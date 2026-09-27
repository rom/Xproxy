package sessionrec

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/asciicast"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/recenc"
)

// encrypting returns a policy that writes ciphertext under keyFile's
// material, plus the directory and the key.
func encrypting(t *testing.T, key string, edit func(*config.SessionRecording)) (*Policy, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.key")
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &config.SessionRecording{
		Directory: dir, FilePrefix: "session",
		MaxFileBytes: 1 << 20, MaxFiles: 10,
		Encryption: &config.RecordingEncryption{Key: path, ChunkBytes: recenc.MinChunk},
	}
	if edit != nil {
		edit(c)
	}
	return New(c, WithSecrets(keysource.New(nil, 0, nil))), dir
}

// plain reads a recording back through the decryptor.
func plain(t *testing.T, name string, key []byte) string {
	t.Helper()
	f, err := os.Open(name) //nolint:gosec // a temporary directory this test made
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := recenc.NewReader(f, key)
	if err != nil {
		t.Fatalf("open %s: %v", filepath.Base(name), err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(name), err)
	}
	return string(b)
}

// The file on the disk is ciphertext, named for what it is, and holds the
// session when it is opened under the key.
func TestAnEncryptedRecordingIsCiphertextOnTheDisk(t *testing.T) {
	p, _ := encrypting(t, "a key from custody", nil)
	rec, err := p.Open(Header{Width: 80, Height: 24, Title: "alice@db"})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte("psql -c 'select 1'\r\n"))
	rec.Mark("xproxy: a note in the timeline")
	res := rec.Close()
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if !strings.HasSuffix(res.File, ".cast"+recenc.Ext) {
		t.Errorf("the file is called %q, which does not say it is encrypted", filepath.Base(res.File))
	}
	raw, err := os.ReadFile(res.File)
	if err != nil {
		t.Fatal(err)
	}
	if !recenc.Looks(raw) {
		t.Error("the file does not begin with the magic")
	}
	for _, leak := range []string{"select 1", "alice@db", "a note in the timeline", "asciicast", "width"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("%q is in the file in the clear", leak)
		}
	}
	text := plain(t, res.File, []byte("a key from custody"))
	for _, want := range []string{"select 1", "alice@db", "a note in the timeline"} {
		if !strings.Contains(text, want) {
			t.Errorf("the plaintext does not carry %q:\n%s", want, text)
		}
	}
	// And it is a recording, not just bytes: the container survived the
	// round trip.
	rd, err := asciicast.NewReader(strings.NewReader(text))
	if err != nil {
		t.Fatalf("the plaintext is not an asciicast: %v", err)
	}
	if rd.Header.Width != 80 || rd.Header.Height != 24 {
		t.Errorf("header %dx%d", rd.Header.Width, rd.Header.Height)
	}
}

// Encryption and the manifest together: the chain covers the ciphertext,
// which is the layer an auditor can check without being able to read the
// session.
func TestTheManifestCoversTheCiphertext(t *testing.T) {
	p, dir := encrypting(t, "content key", func(c *config.SessionRecording) {
		path := filepath.Join(c.Directory, "chain.key")
		if err := os.WriteFile(path, []byte("manifest key"), 0o600); err != nil {
			t.Fatal(err)
		}
		c.Integrity = &config.RecordingIntegrity{Key: path, SegmentBytes: DefaultSegmentBytes}
	})
	rec, err := p.Open(Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte("id\r\n"))
	res := rec.Close()
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	// The manifest verifies with the manifest key alone. Nothing here
	// knows the content key, which is the point.
	v, err := Verify(res.File, []byte("manifest key"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.Authentic {
		t.Error("the manifest is not keyed")
	}
	st, err := os.Stat(res.File)
	if err != nil {
		t.Fatal(err)
	}
	if v.Covered != st.Size() {
		t.Errorf("the manifest covers %d of %d bytes", v.Covered, st.Size())
	}
	// Both sidecars sit beside the one file.
	names := files(t, dir)
	if len(names) != 4 { // the recording, its manifest, and the two key files
		t.Errorf("the directory holds %v", names)
	}
}

// A key that cannot be resolved writes nothing at all. Falling back to
// plaintext would put on the disk exactly what the section was there to
// keep off it.
func TestNoKeyMeansNoRecordingRatherThanAPlainOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    func(t *testing.T) *Policy
	}{
		{"no resolver at all", func(t *testing.T) *Policy {
			return New(&config.SessionRecording{
				Directory: t.TempDir(), FilePrefix: "session",
				MaxFileBytes: 1 << 20, MaxFiles: 10,
				Encryption: &config.RecordingEncryption{Key: "/nowhere/key", ChunkBytes: recenc.MinChunk},
			})
		}},
		{"a reference that resolves to nothing", func(t *testing.T) *Policy {
			dir := t.TempDir()
			return New(&config.SessionRecording{
				Directory: dir, FilePrefix: "session",
				MaxFileBytes: 1 << 20, MaxFiles: 10,
				Encryption: &config.RecordingEncryption{Key: filepath.Join(dir, "absent"), ChunkBytes: recenc.MinChunk},
			}, WithSecrets(keysource.New(nil, 0, nil)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p(t)
			rec, err := p.Open(Header{Width: 80, Height: 24})
			if err == nil {
				_ = rec.Close()
				t.Fatal("a recording was written where the encryption key could not be resolved")
			}
			if !strings.Contains(err.Error(), "encryption key") {
				t.Errorf("error %q does not say what was missing", err)
			}
			for _, left := range files(t, p.cfg.Directory) {
				if strings.HasSuffix(left, ".cast") || strings.HasSuffix(left, recenc.Ext) {
					t.Errorf("the failed open left %s behind", left)
				}
			}
		})
	}
}

// A chunk size the format refuses is refused at the open rather than
// clamped, and leaves nothing behind -- neither the file nor the manifest
// that was opened beside it a moment earlier.
func TestAChunkTheFormatRefusesLeavesNoFile(t *testing.T) {
	p, dir := encrypting(t, "k", func(c *config.SessionRecording) {
		c.Encryption.ChunkBytes = 7
		c.Integrity = &config.RecordingIntegrity{SegmentBytes: DefaultSegmentBytes}
	})
	if _, err := p.Open(Header{Width: 80, Height: 24}); err == nil {
		t.Fatal("a chunk of 7 octets was accepted")
	}
	for _, left := range files(t, dir) {
		if strings.HasSuffix(left, recenc.Ext) || strings.HasSuffix(left, ChainExt) {
			t.Errorf("the failed open left %s behind", left)
		}
	}
}

// Turning the section off writes the recording in the clear and without
// the extension, so an operator who turns it off gets what they had.
func TestEncryptionOffWritesTheFileAsBefore(t *testing.T) {
	off := false
	p, _ := encrypting(t, "k", func(c *config.SessionRecording) { c.Encryption.Enabled = &off })
	rec, err := p.Open(Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte("hello\r\n"))
	res := rec.Close()
	if strings.HasSuffix(res.File, recenc.Ext) {
		t.Errorf("the file is called %q with encryption off", filepath.Base(res.File))
	}
	body, err := os.ReadFile(res.File)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "hello") {
		t.Error("the recording is not the plain file it was before")
	}
}

// A recording that reached max_file_bytes is sealed and readable up to
// where it stopped: the bound must not cost the whole file.
func TestATruncatedEncryptedRecordingStillOpens(t *testing.T) {
	p, _ := encrypting(t, "k", func(c *config.SessionRecording) { c.MaxFileBytes = 8192 })
	rec, err := p.Open(Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte(strings.Repeat("y", 4096)))
	rec.Out([]byte(strings.Repeat("z", 8192)))
	res := rec.Close()
	if !res.Truncated {
		t.Fatal("the recording was not truncated, so there is nothing to test")
	}
	text := plain(t, res.File, []byte("k"))
	if !strings.Contains(text, "yyy") {
		t.Error("what was recorded before the bound did not come back")
	}
	if !strings.Contains(text, "max_file_bytes") {
		t.Error("the mark saying the recording stopped is missing")
	}
}

// The prune takes the encrypted recording and its manifest, under their
// own names.
func TestPruningTakesAnEncryptedRecording(t *testing.T) {
	p, dir := encrypting(t, "k", func(c *config.SessionRecording) {
		c.MaxFiles = 1
		c.Integrity = &config.RecordingIntegrity{SegmentBytes: DefaultSegmentBytes}
	})
	first := record(t, p, "one\r\n")
	_ = record(t, p, "two\r\n")
	for _, name := range []string{first, first + ChainExt} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the prune: %v", filepath.Base(name), err)
		}
	}
	casts, err := filepath.Glob(filepath.Join(dir, "*"+recenc.Ext))
	if err != nil {
		t.Fatal(err)
	}
	if len(casts) != 1 {
		t.Errorf("%d recordings left, want 1", len(casts))
	}
}
