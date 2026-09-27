package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/recenc"
)

// hostileCast is a recording of a session that is attacking whoever
// reads it: the title retitles the reviewer's window, the output writes
// their clipboard, asks their terminal to report its cursor position
// (which a terminal answers on its own input, and a shell reads as a
// command line), and hides a word behind a bidirectional override.
const hostileCast = `{"version":2,"width":80,"height":24,"timestamp":1758000000,"title":"lab-console\u001b]0;pwned\u0007"}
[0.0,"o","$ whoami\r\n"]
[0.1,"o","\u001b[32moperator\u001b[0m\r\n"]
[0.2,"o","\u001b]52;c;cHduZWQ=\u0007"]
[0.3,"o","\u001b[6n"]
[0.4,"o","rm -rf \u202esafe\r\n"]
[0.5,"i","whoami\r"]
[0.6,"m","factor verified"]
`

func writeCast(t *testing.T, body string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "session.rfb.cast")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

// The property the whole command exists for: the file keeps what
// happened, and reading it does not run it. Nothing that reaches outside
// the window the replay is drawn in may survive in a form a terminal
// acts on -- the clipboard, the title, a device report -- and the views
// that are for reading rather than replaying carry no escape at all.
func TestSessionReadingNeverForwardsWhatReachesOutside(t *testing.T) {
	dir, path := writeCast(t, hostileCast)
	for _, c := range []struct {
		args      []string
		anyEscape bool // whether the view may contain an escape at all
	}{
		{[]string{"session", "list", dir}, false},
		{[]string{"session", "show", path}, false},
		{[]string{"session", "show", "-input", path}, false},
		{[]string{"session", "play", "-speed", "1000", "-plain", path}, false},
		{[]string{"session", "show", "-safe", path}, true},
		{[]string{"session", "play", "-speed", "1000", path}, true},
	} {
		var out, errOut bytes.Buffer
		if code := run(c.args, &out, &errOut); code != 0 {
			t.Fatalf("%v: exit %d: %s", c.args, code, errOut.String())
		}
		got := out.String()
		if !c.anyEscape && strings.ContainsRune(got, 0x1b) {
			t.Errorf("%v put an escape in a view that is for reading: %q", c.args, got)
		}
		// The sequences that reach outside the window, whatever the view.
		for _, bad := range []string{
			"\x1b]", "\x1bP", "\x1b_", "\x1b^", "\x1bX", // OSC, DCS, APC, PM, SOS
			"\x1b[6n", "\x1b[c", "\x1b[t", // the reports a terminal answers
			"\x07", "\u202e", "\u009b", // a bell, an override, an 8 bit CSI
		} {
			if strings.Contains(got, bad) {
				t.Errorf("%v put %q in the output: %q", c.args, bad, got)
			}
		}
	}
}

// The text of the session still arrives, because this is a filter and
// not a refusal: a reviewer has to be able to read what was done.
func TestSessionShowKeepsTheText(t *testing.T) {
	_, path := writeCast(t, hostileCast)
	var out, errOut bytes.Buffer
	if code := run([]string{"session", "show", path}, &out, &errOut); code != 0 {
		t.Fatalf("exit: %s", errOut.String())
	}
	got := out.String()
	for _, want := range []string{"$ whoami", "operator", "rm -rf safe", "factor verified"} {
		if !strings.Contains(got, want) {
			t.Errorf("the output does not carry %q:\n%s", want, got)
		}
	}
	// The plain view is for reading, so it carries no transcript of the
	// sequences either.
	if strings.Contains(got, `\e`) {
		t.Errorf("the plain view carries an encoded sequence:\n%s", got)
	}
	// What was typed is left out unless it is asked for: a session's
	// input stream carries what the screen never showed.
	if strings.Contains(got, "whoami\r") {
		t.Error("the input stream was included without -input")
	}
}

// The safe view keeps the colours, because a replay without them is not
// a replay, and says where a sequence it would not forward was.
func TestSessionSafeKeepsColourAndNamesTheRest(t *testing.T) {
	_, path := writeCast(t, hostileCast)
	var out, errOut bytes.Buffer
	if code := run([]string{"session", "show", "-safe", path}, &out, &errOut); code != 0 {
		t.Fatalf("exit: %s", errOut.String())
	}
	got := out.String()
	// The tool's own stripper would have removed the colour, so seeing
	// it proves the replay writes past it.
	if !strings.Contains(got, `\e[32m`) && !strings.Contains(got, "\x1b[32m") {
		t.Errorf("the safe view lost the colour:\n%q", got)
	}
	for _, want := range []string{`]52;c;cHduZWQ=`, `[6n`, `\u202e`} {
		if !strings.Contains(got, want) {
			t.Errorf("the safe view does not say %q was there:\n%q", want, got)
		}
	}
}

// The listing names the files and filters the titles, which came from
// the session as much as the output did.
func TestSessionListFiltersTheTitle(t *testing.T) {
	dir, _ := writeCast(t, hostileCast)
	var out, errOut bytes.Buffer
	if code := run([]string{"session", "list", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit: %s", errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "session.rfb.cast") || !strings.Contains(got, "80x24") {
		t.Errorf("the listing is missing the file or its size:\n%s", got)
	}
	if !strings.Contains(got, "lab-console") {
		t.Errorf("the listing lost the title:\n%s", got)
	}
	if strings.Contains(got, "pwned") {
		t.Errorf("the listing carried the title's escape sequence payload:\n%s", got)
	}
	// The JSON form is the same filtering, since a dashboard renders it.
	out.Reset()
	if code := run([]string{"-json", "session", "list", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit: %s", errOut.String())
	}
	var list []recording
	if err := json.Unmarshal(out.Bytes(), &list); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if len(list) != 1 || list[0].Title != "lab-console" {
		t.Errorf("JSON listing %+v", list)
	}
}

// A file that is not a recording, or is not there, fails with a word
// about it rather than a panic or an empty success.
func TestSessionRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.cast")
	if err := os.WriteFile(bad, []byte("not a recording\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"session", "show", bad},
		{"session", "play", bad},
		{"session", "show", filepath.Join(dir, "missing.cast")},
		{"session"},
		{"session", "nonsense"},
		{"session", "play", "-speed", "0", bad},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code == 0 {
			t.Errorf("%v succeeded: %q", args, out.String())
		}
	}
	// A directory with an unreadable file in it still lists, saying so.
	var out, errOut bytes.Buffer
	if code := run([]string{"session", "list", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit: %s", errOut.String())
	}
	if !strings.Contains(out.String(), "unreadable") {
		t.Errorf("the listing did not say the file is unreadable:\n%s", out.String())
	}
}

// sealedCast writes an encrypted recording of the body given, the way the
// gateways do, and returns the directory, the file and the key file.
func sealedCast(t *testing.T, body string) (dir, path, keyFile string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "session.cast"+recenc.Ext)
	keyFile = filepath.Join(dir, "rec.key")
	if err := os.WriteFile(keyFile, []byte("a content key"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path) //nolint:gosec // a temporary directory this test made
	if err != nil {
		t.Fatal(err)
	}
	w, err := recenc.NewWriter(f, []byte("a content key"), recenc.MinChunk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, path, keyFile
}

// A terminal recording encrypted at rest: unreadable without the key,
// and read through the same filter with it.
func TestSessionReadsAnEncryptedRecording(t *testing.T) {
	const body = `{"version":2,"width":80,"height":24,"timestamp":1758000000,"title":"lab-console"}
[0.0,"o","$ whoami\r\n"]
[0.1,"o","operator\r\n"]
`
	dir, path, keyFile := sealedCast(t, body)

	// Without the key: a refusal that names the flag, and nothing shown.
	var out, errOut bytes.Buffer
	if code := run([]string{"session", "show", path}, &out, &errOut); code != 1 {
		t.Fatalf("no key: exit %d, want 1", code)
	}
	if strings.Contains(out.String(), "operator") {
		t.Error("the session was shown without the key")
	}
	if !strings.Contains(errOut.String(), "-key") {
		t.Errorf("the refusal does not name the flag:\n%s", errOut.String())
	}

	// With it, the ordinary view.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"session", "show", "-key", keyFile, path}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "whoami") {
		t.Errorf("the session did not come out: %q", out.String())
	}

	// And play, which is the same reader with the timing.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"session", "play", "-speed", "100", "-key", keyFile, path}, &out, &errOut); code != 0 {
		t.Fatalf("play: exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "operator") {
		t.Errorf("play did not replay it: %q", out.String())
	}

	// The listing shows both kinds and says which is which.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"session", "list", dir}, &out, &errOut); code != 0 {
		t.Fatalf("list: exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "encrypted: pass -key") {
		t.Errorf("the listing does not say the file is encrypted:\n%s", out.String())
	}
	if strings.Contains(out.String(), "unreadable") {
		t.Errorf("the listing calls an encrypted recording unreadable:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"session", "list", "-key", keyFile, dir}, &out, &errOut); code != 0 {
		t.Fatalf("list with the key: exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "lab-console") || !strings.Contains(out.String(), "80x24") {
		t.Errorf("the listing did not look inside with the key:\n%s", out.String())
	}

	// The JSON form says so in a field, for whatever reads it.
	out.Reset()
	if code := run([]string{"-json", "session", "list", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit: %s", errOut.String())
	}
	var list []recording
	if err := json.Unmarshal(out.Bytes(), &list); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if len(list) != 1 || !list[0].Encrypted {
		t.Errorf("JSON listing %+v", list)
	}
}

// The wrong key, and a vault reference this command cannot resolve, are
// both answered rather than shown as an empty session.
func TestSessionAnswersAKeyItCannotUse(t *testing.T) {
	_, path, _ := sealedCast(t, `{"version":2,"width":80,"height":24}`+"\n"+`[0.0,"o","secret\r\n"]`+"\n")
	dir := filepath.Dir(path)
	wrong := filepath.Join(dir, "wrong.key")
	if err := os.WriteFile(wrong, []byte("not the key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, ref, want string }{
		{"the wrong key", wrong, ""},
		{"a vault reference", "vault:secret/rec#key", "reads no vault"},
		{"a file that is not there", filepath.Join(dir, "absent"), "keysource"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run([]string{"session", "show", "-key", tc.ref, path}, &out, &errOut); code != 1 {
				t.Fatalf("exit %d, want 1", code)
			}
			if strings.Contains(out.String(), "secret") {
				t.Error("the session came out anyway")
			}
			if tc.want != "" && !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("the error does not say %q:\n%s", tc.want, errOut.String())
			}
		})
	}
}
