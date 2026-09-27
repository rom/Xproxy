package sessionrec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
)

// chained returns a policy that writes a manifest, and the key material
// behind the reference it was given.
func chained(t *testing.T, key string, edit func(*config.RecordingIntegrity)) (*Policy, string) {
	t.Helper()
	dir := t.TempDir()
	i := &config.RecordingIntegrity{SegmentBytes: DefaultSegmentBytes}
	if key != "" {
		path := filepath.Join(dir, "chain.key")
		if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
		i.Key = path
	}
	if edit != nil {
		edit(i)
	}
	c := &config.SessionRecording{
		Directory: dir, FilePrefix: "session",
		MaxFileBytes: 1 << 20, MaxFiles: 10, Integrity: i,
	}
	return New(c, WithSecrets(keysource.New(nil, 0, nil))), dir
}

// record writes one session and returns the file it wrote.
func record(t *testing.T, p *Policy, out ...string) string {
	t.Helper()
	rec, err := p.Open(Header{Width: 80, Height: 24, Title: "t"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range out {
		rec.Out([]byte(s))
	}
	res := rec.Close()
	if res.Err != nil {
		t.Fatalf("close: %v", res.Err)
	}
	if res.Chain != res.File+ChainExt {
		t.Fatalf("result names chain %q for file %q", res.Chain, res.File)
	}
	return res.File
}

// The point of the manifest: the recording the proxy wrote verifies, and
// says how much of it the manifest accounted for.
func TestAManifestCoversTheWholeRecording(t *testing.T) {
	p, _ := chained(t, "", nil)
	name := record(t, p, "one\r\n", "two\r\n")

	v, err := Verify(name, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	st, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if v.Covered != st.Size() {
		t.Errorf("the manifest covers %d bytes and the file is %d", v.Covered, st.Size())
	}
	if v.Records < 3 {
		t.Errorf("%d records; an open, a segment and a close is the least there can be", v.Records)
	}
	if v.Keyed || v.Authentic {
		t.Errorf("no key was configured and the verification claims keyed=%v authentic=%v", v.Keyed, v.Authentic)
	}
}

// A key makes the records unforgeable by somebody who does not hold it,
// which is the whole difference between this and a checksum.
func TestAKeyedManifestVerifiesOnlyUnderItsKey(t *testing.T) {
	p, _ := chained(t, "the key", nil)
	name := record(t, p, "sudo -i\r\n")

	v, err := Verify(name, []byte("the key"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.Keyed || !v.Authentic {
		t.Errorf("keyed=%v authentic=%v; the manifest was written under a key", v.Keyed, v.Authentic)
	}
	if _, err := Verify(name, []byte("another key")); err == nil {
		t.Error("a manifest verified under a key it was not written with")
	}
	// And a caller who has no key learns that the manifest claims more
	// than it can check, rather than being told it is fine.
	if _, err := Verify(name, nil); err == nil {
		t.Error("a keyed manifest verified with no key at all")
	}
}

// Somebody who can write the recording can recompute an unkeyed chain.
// That is stated in the package comment, and it is what the key is for:
// the same rewrite under a key does not verify.
func TestRewritingBothFilesIsCaughtOnlyByTheKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		fails bool
	}{
		{"no key, so the chain can be recomputed", "", false},
		{"a key, so it cannot", "the key", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := chained(t, tc.key, nil)
			name := record(t, p, "rm -rf /var/log\r\n")
			// The edit: the recording says something else, and the manifest
			// is rebuilt from the edited file by somebody with no key.
			edited := strings.Replace(read(t, name), "rm -rf /var/log", "ls /var/log   ", 1)
			write(t, name, edited)
			rebuild(t, name, nil)

			_, err := Verify(name, keyOf(tc.key))
			if tc.fails && err == nil {
				t.Error("a rewritten recording verified under the key it was not rewritten with")
			}
			if !tc.fails && err != nil {
				t.Errorf("the rewrite was expected to pass an unkeyed chain and did not: %v", err)
			}
		})
	}
}

// Every shape of a change to the recording alone.
func TestAnEditedRecordingDoesNotVerify(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(string) string
		want string
	}{
		{"a byte changed in the middle", func(s string) string {
			return strings.Replace(s, "sudo", "ls  ", 1)
		}, "do not match their digest"},
		{"the tail cut off", func(s string) string {
			return s[:len(s)-20]
		}, "covers"},
		{"bytes appended", func(s string) string {
			return s + "[1.0,\"o\",\"nothing to see\"]\n"
		}, "the manifest covers"},
		{"the whole file emptied", func(string) string { return "" }, "covers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := chained(t, "k", nil)
			name := record(t, p, "sudo -i\r\n", "id\r\n")
			write(t, name, tc.edit(read(t, name)))
			_, err := Verify(name, []byte("k"))
			if err == nil {
				t.Fatal("the edited recording verified")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// And every shape of a change to the manifest alone. Each has to be
// named, because "it does not verify" is not enough for somebody who has
// to decide what happened.
func TestATamperedManifestDoesNotVerify(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]ChainRecord) []ChainRecord
		want string
	}{
		{"a record removed from the middle", func(rs []ChainRecord) []ChainRecord {
			return append(rs[:1:1], rs[2:]...)
		}, "out of sequence"},
		{"two records swapped", func(rs []ChainRecord) []ChainRecord {
			rs[0], rs[1] = rs[1], rs[0]
			return rs
		}, "out of sequence"},
		{"a digest replaced", func(rs []ChainRecord) []ChainRecord {
			for i := range rs {
				if rs[i].Kind == ChainSegment {
					rs[i].Digest = strings.Repeat("0", 64)
				}
			}
			return rs
		}, "hash does not cover it"},
		{"a link broken", func(rs []ChainRecord) []ChainRecord {
			rs[len(rs)-1].Prev = strings.Repeat("0", 64)
			return rs
		}, "does not link"},
		{"the close record dropped", func(rs []ChainRecord) []ChainRecord {
			return rs[:len(rs)-1]
		}, "no close record"},
		{"an unknown kind", func(rs []ChainRecord) []ChainRecord {
			rs[1].Kind = "something"
			return rs
		}, "hash does not cover it"},
		{"nothing at all", func([]ChainRecord) []ChainRecord { return nil }, "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := chained(t, "", nil)
			name := record(t, p, "one\r\n")
			rebuild(t, name, tc.edit)
			_, err := Verify(name, nil)
			if err == nil {
				t.Fatal("the tampered manifest verified")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// A long session is more than one segment, which is what localises an
// edit to a part of the file rather than to the file.
func TestSegmentsLocaliseAnEdit(t *testing.T) {
	p, _ := chained(t, "", func(i *config.RecordingIntegrity) { i.SegmentBytes = 4096 })
	rec, err := p.Open(Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	for range 40 {
		rec.Out([]byte(strings.Repeat("x", 1024) + "\r\n"))
	}
	res := rec.Close()
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	rs := manifest(t, res.File)
	segments := 0
	var covered int64
	for _, r := range rs {
		if r.Kind == ChainSegment {
			segments++
			if r.Offset != covered {
				t.Errorf("segment %d starts at %d where %d was expected", r.Seq, r.Offset, covered)
			}
			covered += r.Length
		}
	}
	if segments < 5 {
		t.Errorf("%d segments for a 40KB recording at 4096 bytes each", segments)
	}
	if _, err := Verify(res.File, nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// A session that hit its byte bound is a short recording the proxy
// declared, and a verifier has to be able to tell that from a file
// somebody shortened.
func TestTheManifestCarriesADeclaredTruncation(t *testing.T) {
	dir := t.TempDir()
	c := &config.SessionRecording{
		Directory: dir, FilePrefix: "session",
		MaxFileBytes: 4096, MaxFiles: 10,
		Integrity: &config.RecordingIntegrity{SegmentBytes: DefaultSegmentBytes},
	}
	p := New(c, WithSecrets(keysource.New(nil, 0, nil)))
	rec, err := p.Open(Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte(strings.Repeat("y", 8192)))
	res := rec.Close()
	if !res.Truncated {
		t.Fatal("the recording was not truncated, so there is nothing to carry")
	}
	v, err := Verify(res.File, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.Truncated {
		t.Error("the manifest verified and does not say the proxy stopped the recording early")
	}
}

// A recording with no manifest is not a recording that failed to
// verify, and a caller has to be able to tell the two apart.
func TestARecordingWithNoManifestSaysSo(t *testing.T) {
	p, _ := policy(t, nil)
	name := record2(t, p)
	_, err := Verify(name, nil)
	if !errors.Is(err, ErrNoChain) {
		t.Errorf("verify without a manifest: %v, want ErrNoChain", err)
	}
}

// The manifest goes when the recording it describes is pruned.
func TestPruningTakesTheManifest(t *testing.T) {
	dir := t.TempDir()
	c := &config.SessionRecording{
		Directory: dir, FilePrefix: "session",
		MaxFileBytes: 1 << 20, MaxFiles: 1,
		Integrity: &config.RecordingIntegrity{SegmentBytes: DefaultSegmentBytes},
	}
	p := New(c, WithSecrets(keysource.New(nil, 0, nil)))
	first := record(t, p, "one\r\n")
	_ = record(t, p, "two\r\n")
	for _, name := range []string{first, first + ChainExt} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the prune: %v", filepath.Base(name), err)
		}
	}
	left := files(t, dir)
	if len(left) != 2 {
		t.Errorf("the directory holds %v; one recording and its manifest was the count asked for", left)
	}
}

// Asking for records nobody can forge and getting records anybody can is
// the one outcome that must not happen quietly.
func TestAKeyThatDoesNotResolveRefusesToRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    func(t *testing.T) *Policy
	}{
		{"no resolver at all", func(t *testing.T) *Policy {
			c := &config.SessionRecording{
				Directory: t.TempDir(), FilePrefix: "session",
				MaxFileBytes: 1 << 20, MaxFiles: 10,
				Integrity: &config.RecordingIntegrity{Key: "/nowhere/key"},
			}
			return New(c)
		}},
		{"a reference that resolves to nothing", func(t *testing.T) *Policy {
			c := &config.SessionRecording{
				Directory: t.TempDir(), FilePrefix: "session",
				MaxFileBytes: 1 << 20, MaxFiles: 10,
				Integrity: &config.RecordingIntegrity{Key: filepath.Join(t.TempDir(), "absent")},
			}
			return New(c, WithSecrets(keysource.New(nil, 0, nil)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p(t)
			rec, err := p.Open(Header{Width: 80, Height: 24})
			if err == nil {
				_ = rec.Close()
				t.Fatal("a recording was written with no integrity key where one was configured")
			}
			if !strings.Contains(err.Error(), "integrity key") {
				t.Errorf("error %q does not say what was missing", err)
			}
			if left := files(t, p.cfg.Directory); len(left) != 0 {
				t.Errorf("the failed open left %v behind", left)
			}
		})
	}
}

// Turning the section off leaves no manifest, so an operator who does
// not want one does not get a second file per session.
func TestIntegrityOffWritesNoManifest(t *testing.T) {
	off := false
	p, dir := chained(t, "", func(i *config.RecordingIntegrity) { i.Enabled = &off })
	name := record2(t, p)
	if _, err := os.Stat(name + ChainExt); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a manifest was written where the section was off: %v", err)
	}
	if left := files(t, dir); len(left) != 1 {
		t.Errorf("the directory holds %v, want the recording alone", left)
	}
}

// Test helpers.

// record2 writes one session where the caller does not care about the
// manifest, and tolerates there being none.
func record2(t *testing.T, p *Policy) string {
	t.Helper()
	rec, err := p.Open(Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte("hello\r\n"))
	return rec.Close().File
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func write(t *testing.T, name, s string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func keyOf(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

// manifest reads the records beside a recording.
func manifest(t *testing.T, name string) []ChainRecord {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(read(t, name+ChainExt)), "\n")
	out := make([]ChainRecord, 0, len(lines))
	for _, line := range lines {
		var r ChainRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// rebuild writes the manifest again for the recording as it now is. edit
// changes the existing records, keeping their hashes as they were; a nil
// edit is an honest rebuild by somebody who has the file and not the
// key, which is the case the key exists for.
func rebuild(t *testing.T, name string, edit func([]ChainRecord) []ChainRecord) {
	t.Helper()
	if edit == nil {
		data := []byte(read(t, name))
		forge(t, name, []ChainRecord{
			{Kind: ChainOpen, File: filepath.Base(name)},
			{Kind: ChainSegment, Offset: 0, Length: int64(len(data)), Digest: digestOf(data)},
			{Kind: ChainClose, Offset: int64(len(data)), Digest: digestOf(data)},
		})
		return
	}
	var b strings.Builder
	for _, r := range edit(manifest(t, name)) {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	write(t, name+ChainExt, b.String())
}

// A forged manifest is the interesting case: somebody with the recording
// and no key rebuilds the chain, so every record's own hash is right and
// the links are right, and what is left to catch them is whether the
// records account for the file consistently.
func TestAForgedManifestIsCaughtByWhatItClaims(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(base string, data []byte) []ChainRecord
		want string
	}{
		{"a segment that does not start where the last one ended", func(base string, data []byte) []ChainRecord {
			return []ChainRecord{
				{Kind: ChainOpen, File: base},
				{Kind: ChainSegment, Offset: 1, Length: int64(len(data)) - 1, Digest: digestOf(data[1:])},
				{Kind: ChainClose, Offset: int64(len(data)), Digest: digestOf(data)},
			}
		}, "covers from 1 where 0 was expected"},
		{"a close that does not close where the segments reached", func(base string, data []byte) []ChainRecord {
			return []ChainRecord{
				{Kind: ChainOpen, File: base},
				{Kind: ChainSegment, Offset: 0, Length: int64(len(data)), Digest: digestOf(data)},
				{Kind: ChainClose, Offset: int64(len(data)) - 1, Digest: digestOf(data)},
			}
		}, "closes at"},
		{"a close whose whole-file digest is somebody else's", func(base string, data []byte) []ChainRecord {
			return []ChainRecord{
				{Kind: ChainOpen, File: base},
				{Kind: ChainSegment, Offset: 0, Length: int64(len(data)), Digest: digestOf(data)},
				{Kind: ChainClose, Offset: int64(len(data)), Digest: digestOf([]byte("something else"))},
			}
		}, "whole recording's digest does not match"},
		{"a record of a kind the verifier does not know", func(base string, data []byte) []ChainRecord {
			return []ChainRecord{
				{Kind: ChainOpen, File: base},
				{Kind: "amended", Offset: 0, Length: int64(len(data)), Digest: digestOf(data)},
				{Kind: ChainClose, Offset: int64(len(data)), Digest: digestOf(data)},
			}
		}, "unknown kind"},
		{"more records after the close", func(base string, data []byte) []ChainRecord {
			return []ChainRecord{
				{Kind: ChainOpen, File: base},
				{Kind: ChainSegment, Offset: 0, Length: int64(len(data)), Digest: digestOf(data)},
				{Kind: ChainClose, Offset: int64(len(data)), Digest: digestOf(data)},
				{Kind: ChainSegment, Offset: 0, Length: int64(len(data)), Digest: digestOf(data)},
			}
		}, "after the close record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := chained(t, "", nil)
			name := record(t, p, "one\r\n", "two\r\n")
			data := []byte(read(t, name))
			forge(t, name, tc.make(filepath.Base(name), data))
			_, err := Verify(name, nil)
			if err == nil {
				t.Fatal("the forged manifest verified")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// A keyed manifest and no key is its own answer, not a MAC that happens
// not to match: a caller who forgot the key has to be told that rather
// than shown a mismatch.
func TestAKeyedManifestWithNoKeySaysTheKeyIsMissing(t *testing.T) {
	p, _ := chained(t, "the key", nil)
	name := record(t, p, "one\r\n")
	_, err := Verify(name, nil)
	if err == nil {
		t.Fatal("a keyed manifest verified with no key")
	}
	if !strings.Contains(err.Error(), "no key was given") {
		t.Errorf("error %q does not say the key was missing", err)
	}
}

// The chain covers what reached the file, which is why it sits after the
// buffer. A destination that took only half the bytes must leave a
// manifest for the half that landed.
func TestTheChainDigestsWhatWasWrittenAndNotWhatWasOffered(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "stream")
	f, err := os.Create(name) //nolint:gosec // a temporary directory this test made
	if err != nil {
		t.Fatal(err)
	}
	c, err := newChain(name, "stream", nil, 4096)
	if err != nil {
		t.Fatal(err)
	}
	w := chainWriter{w: half{f}, c: c}
	if n, err := w.Write([]byte("abcdefgh")); n != 4 || err != nil {
		t.Fatalf("write: %d, %v", n, err)
	}
	if err := c.finish(false); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := read(t, name); got != "abcd" {
		t.Fatalf("the file holds %q", got)
	}
	v, err := Verify(name, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Covered != 4 {
		t.Errorf("the manifest covers %d bytes of the 4 that were written", v.Covered)
	}
}

// half writes the first half of what it is given, which is what a full
// disk or a pipe with a small buffer does.
type half struct{ w io.Writer }

func (h half) Write(p []byte) (int, error) { return h.w.Write(p[:len(p)/2]) }

// A recording whose length is an exact multiple of the segment size must
// not leave a record covering nothing: a manifest is read by somebody
// deciding what happened, and a zero-length segment is a question.
func TestNoSegmentRecordCoversNothing(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "exact")
	f, err := os.Create(name) //nolint:gosec // a temporary directory this test made
	if err != nil {
		t.Fatal(err)
	}
	c, err := newChain(name, "exact", nil, 16)
	if err != nil {
		t.Fatal(err)
	}
	w := chainWriter{w: f, c: c}
	for range 3 {
		if _, err := w.Write([]byte(strings.Repeat("z", 16))); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.finish(false); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	segments := 0
	for _, r := range manifest(t, name) {
		if r.Kind != ChainSegment {
			continue
		}
		segments++
		if r.Length == 0 {
			t.Errorf("record %d covers no bytes at all", r.Seq)
		}
	}
	if segments != 3 {
		t.Errorf("%d segment records for 48 bytes at 16 each", segments)
	}
	if _, err := Verify(name, nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// forge writes a manifest whose records are internally consistent -- own
// hashes and links recomputed -- from the records given, which is what
// somebody with the file and no key would produce.
func forge(t *testing.T, name string, rs []ChainRecord) {
	t.Helper()
	var b strings.Builder
	prev := ""
	for i := range rs {
		rs[i].Seq, rs[i].At, rs[i].Prev = int64(i), time.Now().UTC(), prev
		rs[i].Hash = chainHashOf(rs[i])
		prev = rs[i].Hash
		line, err := json.Marshal(rs[i])
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	write(t, name+ChainExt, b.String())
}
