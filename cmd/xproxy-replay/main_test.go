package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/sessionrec"
)

// The program is the other half of the recording promise, so the tests
// drive it the way an operator does: a file in, a page or a frame or a
// timeline out, and a refusal that names what to use instead.

var pf32 = [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}

// rfbFile writes a recording of one red pixel, the way the gateway does.
func rfbFile(t *testing.T, dir string) string {
	t.Helper()
	head, err := json.Marshal(map[string]any{
		"version": 2, "width": 4, "height": 4, "title": "alice@hmi via desks",
		"env": map[string]string{
			"XPROXY_PROTOCOL": "rfb", "XPROXY_ENCODING": "base64",
			"XPROXY_PIXEL_FORMAT": hex.EncodeToString(pf32[:]),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rect := make([]byte, 12)
	binary.BigEndian.PutUint16(rect[4:6], 1)
	binary.BigEndian.PutUint16(rect[6:8], 1)
	body := append([]byte{0, 0, 0, 1}, rect...)
	body = append(body, 0, 0, 255, 0) // one red pixel, little endian
	var b bytes.Buffer
	b.Write(head)
	b.WriteByte('\n')
	ev, err := json.Marshal([]any{0.25, "o", base64.StdEncoding.EncodeToString(body)})
	if err != nil {
		t.Fatal(err)
	}
	b.Write(ev)
	b.WriteByte('\n')
	mark, err := json.Marshal([]any{0.3, "m", "xproxy: refused client message key-event: view_only"})
	if err != nil {
		t.Fatal(err)
	}
	b.Write(mark)
	b.WriteByte('\n')
	path := filepath.Join(dir, "s.rfb.cast")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func textFile(t *testing.T, dir string) string {
	t.Helper()
	head, _ := json.Marshal(map[string]any{"version": 2, "width": 80, "height": 24})
	ev, _ := json.Marshal([]any{0.0, "o", "hello\r\n"})
	in, _ := json.Marshal([]any{0.1, "i", "secret\r"})
	var b bytes.Buffer
	b.Write(head)
	b.WriteByte('\n')
	b.Write(ev)
	b.WriteByte('\n')
	b.Write(in)
	b.WriteByte('\n')
	path := filepath.Join(dir, "s.cast")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheTimelineSaysWhatTheStreamDid(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"-summary", rfbFile(t, dir)}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	text := out.String()
	for _, want := range []string{"rfb", "alice@hmi via desks", "raw", "1 updates", "view_only"} {
		if !strings.Contains(text, want) {
			t.Errorf("the timeline does not say %q:\n%s", want, text)
		}
	}
}

func TestAPageAndFramesAreWritten(t *testing.T) {
	dir := t.TempDir()
	rec := rfbFile(t, dir)
	page := filepath.Join(dir, "out.html")
	var out, errOut bytes.Buffer
	if code := run([]string{"-html", page, "-png", dir, rec}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	body, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("data:image/png;base64")) {
		t.Error("the page carries no frame")
	}
	frames, _ := filepath.Glob(filepath.Join(dir, "frame-*.png"))
	if len(frames) != 1 {
		t.Fatalf("%d frames written", len(frames))
	}
	// The frame is the picture: one red pixel at the origin.
	if b, err := os.ReadFile(frames[0]); err != nil || !bytes.HasPrefix(b, []byte("\x89PNG")) {
		t.Errorf("the frame is not a PNG: %v", err)
	}
}

func TestATerminalRecordingIsReplayedAndFiltered(t *testing.T) {
	dir := t.TempDir()
	path := textFile(t, dir)
	var out, errOut bytes.Buffer
	if code := run([]string{"-speed", "1000", path}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "hello") {
		t.Errorf("the session was not replayed: %q", out.String())
	}
	if strings.Contains(out.String(), "secret") {
		t.Error("what was typed was replayed without -input")
	}
	out.Reset()
	if code := run([]string{"-speed", "1000", "-input", path}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "secret") {
		t.Error("-input did not include what was typed")
	}
}

func TestAGraphicalRecordingIsNotWrittenToATerminal(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{rfbFile(t, dir)}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errOut.String(), "-html") {
		t.Errorf("the refusal does not say what to use: %q", errOut.String())
	}
	if strings.Contains(out.String(), "\x00") {
		t.Error("protocol bytes were written to the terminal")
	}
}

func TestTheUsageAndVersionAreAnswered(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-version"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "xproxy-replay") {
		t.Errorf("version: %d %q", code, out.String())
	}
	if code := run(nil, &out, &errOut); code != 2 {
		t.Errorf("no argument: %d", code)
	}
	if code := run([]string{"/nonexistent/recording.cast"}, &out, &errOut); code != 1 {
		t.Errorf("a file that is not there: %d", code)
	}
	// An RDP recording's pixels are not decoded, and -png says so
	// rather than writing an empty frame.
	dir := t.TempDir()
	head, _ := json.Marshal(map[string]any{"version": 2, "width": 8, "height": 8,
		"env": map[string]string{"XPROXY_PROTOCOL": "rdp", "XPROXY_ENCODING": "base64"}})
	ev, _ := json.Marshal([]any{0.1, "o", base64.StdEncoding.EncodeToString([]byte{3, 0, 0, 8, 1, 2, 3, 4})})
	path := filepath.Join(dir, "s.rdp.cast")
	if err := os.WriteFile(path, append(append(head, '\n'), append(ev, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := run([]string{"-png", dir, path}, &out, &errOut); code != 1 {
		t.Errorf("an rdp recording rendered as pixels: %d", code)
	}
	if !strings.Contains(errOut.String(), "does not decode") {
		t.Errorf("the refusal does not say why: %q", errOut.String())
	}
	// Its timeline still works, because the framing and the marks are
	// readable even where the graphics are not.
	out.Reset()
	if code := run([]string{"-summary", path}, &out, &errOut); code != 0 {
		t.Errorf("summary of an rdp recording: %d", code)
	}
	if !strings.Contains(out.String(), "rdp") || !strings.Contains(out.String(), "8 bytes") {
		t.Errorf("the summary says nothing useful: %q", out.String())
	}
}

// chainedFile writes a recording and the manifest the gateway writes
// beside it, under the key given (empty for an unkeyed manifest).
func chainedFile(t *testing.T, dir, key string) string {
	t.Helper()
	c := &config.SessionRecording{
		Directory: dir, FilePrefix: "session", MaxFileBytes: 1 << 20, MaxFiles: 10,
		Integrity: &config.RecordingIntegrity{SegmentBytes: sessionrec.DefaultSegmentBytes},
	}
	if key != "" {
		path := filepath.Join(dir, "chain.key")
		if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
		c.Integrity.Key = path
	}
	p := sessionrec.New(c, sessionrec.WithSecrets(keysource.New(nil, 0, nil)))
	rec, err := p.Open(sessionrec.Header{Width: 80, Height: 24, Title: "alice@db"})
	if err != nil {
		t.Fatal(err)
	}
	rec.Out([]byte("psql -c 'select 1'\r\n"))
	res := rec.Close()
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	return res.File
}

// A reviewer asks the question directly, and the answer says what the
// manifest is worth as well as whether it matched.
func TestVerifyAnswersWhatTheManifestIsWorth(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		key  string
		args func(rec, keyFile string) []string
		want string
	}{
		{"unkeyed", "", func(rec, _ string) []string { return []string{"-verify", rec} },
			"carries no MACs"},
		{"keyed, with the key", "the key", func(rec, keyFile string) []string {
			return []string{"-verify", "-key", keyFile, rec}
		}, "verify under the key given"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := filepath.Join(dir, tc.name)
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			rec := chainedFile(t, d, tc.key)
			var out, errOut bytes.Buffer
			if code := run(tc.args(rec, filepath.Join(d, "chain.key")), &out, &errOut); code != 0 {
				t.Fatalf("exit %d: %s", code, errOut.String())
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Errorf("the answer %q does not say %q", out.String(), tc.want)
			}
			// -verify answers the question and stops. A reviewer who asked
			// whether a recording is intact did not ask to be shown it,
			// and on a graphical recording showing it would be protocol
			// bytes on their terminal.
			if strings.Contains(out.String(), "psql") {
				t.Errorf("-verify replayed the session as well:\n%s", out.String())
			}
		})
	}
}

// The promise the program makes: a recording that does not match its
// manifest is not shown, because a reviewer must not describe a session
// from a file somebody else edited.
func TestAnEditedRecordingIsNotReplayed(t *testing.T) {
	dir := t.TempDir()
	rec := chainedFile(t, dir, "")
	body, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(body, []byte("select 1"), []byte("select 2"), 1)
	if bytes.Equal(body, edited) {
		t.Fatal("the test did not edit the recording")
	}
	if err := os.WriteFile(rec, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := run([]string{rec}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("the session was replayed anyway: %q", out.String())
	}
	for _, want := range []string{"not the recording its manifest describes", "-force"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("the refusal does not say %q:\n%s", want, errOut.String())
		}
	}

	// And -force shows it, having said what it is showing.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"-speed", "0", "-force", rec}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "select 2") {
		t.Errorf("-force did not replay the file: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "-force was given") {
		t.Errorf("-force did not say it was showing an unverified recording:\n%s", errOut.String())
	}
}

// A recording with no manifest still replays: most have none, and this
// is a viewer. Asked to verify one, it says there is nothing to check.
func TestARecordingWithNoManifestStillPlays(t *testing.T) {
	dir := t.TempDir()
	rec := textFile(t, dir)
	var out, errOut bytes.Buffer
	if code := run([]string{"-speed", "0", rec}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "hello") {
		t.Errorf("the recording did not replay: %q", out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"-verify", rec}, &out, &errOut); code != 1 {
		t.Errorf("-verify on a recording with no manifest: exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "no integrity manifest") {
		t.Errorf("the answer %q does not say the manifest is missing", out.String())
	}
}

// A key the program cannot read is an error before anything is shown,
// and a vault reference says why rather than failing as a missing file.
func TestTheKeyReferenceIsAnsweredBeforeAnythingIsShown(t *testing.T) {
	dir := t.TempDir()
	rec := chainedFile(t, dir, "the key")
	for _, tc := range []struct{ name, ref, want string }{
		{"a vault reference", "vault:secret/rec#key", "reads no vault"},
		{"a file that is not there", filepath.Join(dir, "absent"), "keysource"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run([]string{"-verify", "-key", tc.ref, rec}, &out, &errOut); code != 1 {
				t.Fatalf("exit %d, want 1", code)
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("the error does not say %q:\n%s", tc.want, errOut.String())
			}
		})
	}
}
