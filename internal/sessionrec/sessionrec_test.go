package sessionrec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

func policy(t *testing.T, edit func(*config.SessionRecording)) (*Policy, string) {
	t.Helper()
	dir := t.TempDir()
	c := &config.SessionRecording{
		Directory: dir, FilePrefix: "session",
		MaxFileBytes: 1 << 20, MaxFiles: 10,
	}
	if edit != nil {
		edit(c)
	}
	return New(c), dir
}

func files(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// A recording is a file per session, with the header first and the
// events after it. Everything a kind hands over has to come back out,
// or the file is evidence of nothing.
func TestARecordingHoldsWhatWasWritten(t *testing.T) {
	p, dir := policy(t, nil)
	rec, err := p.Open(Header{Width: 80, Height: 24, Title: "alice@host via bastion", Tag: "alice", Env: map[string]string{"TERM": "xterm"}})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte("hello\r\n"))
	rec.In([]byte("whoami\r"))
	rec.Mark("a transfer happened here")
	rec.Resize(120, 40)
	res := rec.Close()

	if res.File == "" || res.Truncated || res.Err != nil {
		t.Fatalf("result %+v, want a file and no trouble", res)
	}
	if res.Bytes != int64(len("hello\r\n")+len("whoami\r")) {
		t.Errorf("bytes %d, want the session's own bytes", res.Bytes)
	}
	if got := files(t, dir); len(got) != 1 || !strings.HasSuffix(got[0], ".cast") || !strings.Contains(got[0], "alice") {
		t.Errorf("files %v, want one session-<time>-alice.cast", got)
	}
	body, err := os.ReadFile(res.File)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var head struct {
		Version int               `json:"version"`
		Width   int               `json:"width"`
		Height  int               `json:"height"`
		Title   string            `json:"title"`
		Env     map[string]string `json:"env"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &head); err != nil {
		t.Fatalf("header: %v", err)
	}
	if head.Version != 2 || head.Width != 80 || head.Title != "alice@host via bastion" || head.Env["TERM"] != "xterm" {
		t.Errorf("header %+v does not describe the session", head)
	}
	rest := strings.Join(lines[1:], "\n")
	for _, want := range []string{"hello", "whoami", "a transfer happened here"} {
		if !strings.Contains(rest, want) {
			t.Errorf("the file does not carry %q:\n%s", want, rest)
		}
	}
	// The mode is the proxy user's alone: the file holds everything the
	// session showed.
	fi, err := os.Stat(res.File)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
}

// One session that prints for an hour must not fill the disk. Past the
// bound the session goes on and the file says it stopped, which is very
// different from a file that silently lost its middle.
func TestTheByteBoundStopsTheFileAndSaysSo(t *testing.T) {
	p, _ := policy(t, func(c *config.SessionRecording) { c.MaxFileBytes = 16 })
	rec, err := p.Open(Header{Tag: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte("0123456789"))
	rec.Out([]byte("0123456789")) // past the bound
	rec.Out([]byte("and more"))   // ignored
	res := rec.Close()
	if !res.Truncated {
		t.Error("the recording did not report itself short")
	}
	if res.Bytes != 10 {
		t.Errorf("bytes %d, want only what fitted", res.Bytes)
	}
	body, _ := os.ReadFile(res.File)
	if !strings.Contains(string(body), "max_file_bytes") {
		t.Errorf("the file does not say why it stopped:\n%s", body)
	}
	if strings.Contains(string(body), "and more") {
		t.Error("bytes past the bound reached the file")
	}
}

// A recorder prunes what it wrote and nothing else: a file another
// process put in the directory is not this one's to delete.
func TestPruningKeepsTheCountAndTouchesNothingElse(t *testing.T) {
	p, dir := policy(t, func(c *config.SessionRecording) { c.MaxFiles = 2 })
	stranger := filepath.Join(dir, "not-ours.cast")
	if err := os.WriteFile(stranger, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		rec, err := p.Open(Header{Tag: "u"})
		if err != nil {
			t.Fatal(err)
		}
		rec.Out([]byte("x"))
		rec.Close()
	}
	got := files(t, dir)
	ours := 0
	for _, n := range got {
		if strings.HasPrefix(n, "session-") {
			ours++
		}
	}
	if ours != 2 {
		t.Errorf("%d of our files kept, want 2: %v", ours, got)
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Errorf("a file this recorder did not write was removed: %v", err)
	}
}

// The tag comes from a name the client chose, so it decides nothing
// about where the proxy writes.
func TestFileTagCannotEscapeTheDirectory(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"alice", "alice"},
		{"../../etc/passwd", "______etc_passwd"},
		{"a/b", "a_b"},
		{"", "unknown"},
		{strings.Repeat("x", 100), strings.Repeat("x", 32)},
	} {
		if got := FileTag(tc.in); got != tc.want {
			t.Errorf("FileTag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	p, dir := policy(t, nil)
	rec, err := p.Open(Header{Tag: "../../escape"})
	if err != nil {
		t.Fatal(err)
	}
	res := rec.Close()
	if filepath.Dir(res.File) != dir {
		t.Errorf("the file landed in %s, outside %s", filepath.Dir(res.File), dir)
	}
}

// A policy that is absent or turned off records nothing, and every
// method stays safe on it, so a kind that records nothing writes no
// conditionals.
func TestNoPolicyRecordsNothingAndNeverPanics(t *testing.T) {
	off := false
	for _, p := range []*Policy{
		New(nil),
		New(&config.SessionRecording{Enabled: &off, Directory: t.TempDir()}),
	} {
		if p.Enabled() {
			t.Error("a policy that records nothing says it is enabled")
		}
		if p.Config() != nil {
			t.Error("a policy that records nothing returned a section")
		}
		rec, err := p.Open(Header{Tag: "x"})
		if err != nil || rec != nil {
			t.Fatalf("Open on no policy: %v, %v", rec, err)
		}
		rec.Out([]byte("x"))
		rec.In([]byte("x"))
		rec.Mark("x")
		rec.Resize(1, 1)
		if res := rec.Close(); res != (Result{}) {
			t.Errorf("Close on no recording: %+v", res)
		}
		if rec.Name() != "" {
			t.Error("a recording that does not exist has a name")
		}
	}
}

// Writer records what the far side actually received, not what the
// proxy meant to send.
func TestWriterRecordsWhatWasDelivered(t *testing.T) {
	p, _ := policy(t, nil)
	rec, err := p.Open(Header{Tag: "u"})
	if err != nil {
		t.Fatal(err)
	}
	var dst shortWriter
	w := Writer{Dst: &dst, Rec: rec}
	if n, err := w.Write([]byte("abcdefgh")); n != 4 || err != nil {
		t.Fatalf("write %d, %v", n, err)
	}
	res := rec.Close()
	if res.Bytes != 4 {
		t.Errorf("recorded %d bytes, want the 4 that were delivered", res.Bytes)
	}
	body, _ := os.ReadFile(res.File)
	if !strings.Contains(string(body), "abcd") || strings.Contains(string(body), "efgh") {
		t.Errorf("the file does not hold exactly what was delivered:\n%s", body)
	}
}

// shortWriter accepts half of what it is given, as a socket does.
type shortWriter struct{ n int }

func (w *shortWriter) Write(p []byte) (int, error) {
	w.n += len(p) / 2
	return len(p) / 2, nil
}

// Two sessions for one user inside the same millisecond is ordinary on
// a busy bastion. The name carries the time only to the millisecond, so
// without a suffix the second O_EXCL fails and that session goes
// unrecorded -- a recording missing exactly when the machine was busy.
func TestSessionsInTheSameMillisecondBothRecord(t *testing.T) {
	// Keep every file: what is under test is the naming, not the prune.
	const n = 25
	p, dir := policy(t, func(c *config.SessionRecording) { c.MaxFiles = n })
	recs := make([]*Recording, 0, n)
	for i := 0; i < n; i++ {
		rec, err := p.Open(Header{Tag: "sameuser"})
		if err != nil {
			t.Fatalf("session %d could not be recorded: %v", i, err)
		}
		rec.Out([]byte("x"))
		recs = append(recs, rec)
	}
	seen := map[string]bool{}
	for i, rec := range recs {
		res := rec.Close()
		if res.File == "" {
			t.Fatalf("session %d wrote no file", i)
		}
		if seen[res.File] {
			t.Errorf("two sessions wrote to %s", res.File)
		}
		seen[res.File] = true
	}
	if got := len(files(t, dir)); got != n {
		t.Errorf("%d files for %d sessions", got, n)
	}
}
