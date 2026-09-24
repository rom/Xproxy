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
