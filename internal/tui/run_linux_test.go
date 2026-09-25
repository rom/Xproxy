//go:build linux

package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/rom/xproxy/internal/ban"
)

// Run takes over a terminal, so the only honest test of it is against a
// real one. This opens a pseudo terminal pair, hands the slave to Run
// and types at it.

func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo terminals here: %v", err)
	}
	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		_ = m.Close()
		t.Skipf("TIOCSPTLCK: %v", errno)
	}
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); errno != 0 {
		_ = m.Close()
		t.Skipf("TIOCGPTN: %v", errno)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = m.Close()
		t.Skipf("opening the slave: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(); _ = m.Close() })
	return m, s
}

// countingSource answers with a view the test can change, and counts the
// fetches.
type countingSource struct {
	mu      sync.Mutex
	fetches int
	data    Data
}

func (f *countingSource) Fetch(context.Context) Data {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	return f.data
}

func (f *countingSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

func (f *countingSource) set(d Data) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data = d
}

// until polls for something the terminal is expected to do, instead of
// assuming one fixed pause covers it. A keystroke goes through a
// pseudo-terminal, a reader goroutine and a redraw, so how long it
// takes depends on what else the machine is running: a pause that is
// generous on an idle machine is not generous beside the rest of the
// suite, and the test then fails on a program that works.
func until(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("%s never happened", what)
}

// waitForTheFirstFrame returns once the alternate screen and one frame
// have been written, and fails if Run gives up before that.
func waitForTheFirstFrame(t *testing.T, out *lockedBuffer, done <-chan error) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-done:
			t.Fatalf("Run returned early: %v", err)
		default:
		}
		if out.frames() >= 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no frame was drawn")
}

func TestRunOverAPseudoTerminal(t *testing.T) {
	master, slave := openPTY(t)
	var out lockedBuffer
	src := &countingSource{data: Data{Bans: []ban.Entry{{Target: "198.51.100.7", Reason: "waf"}, {Target: "203.0.113.9", Reason: "rate"}}}}
	var unbanned []string
	var mu sync.Mutex
	act := Actions{
		Unban: func(target string) error {
			mu.Lock()
			defer mu.Unlock()
			unbanned = append(unbanned, target)
			return nil
		},
		Ban: func(target, dur, reason string) error {
			mu.Lock()
			defer mu.Unlock()
			unbanned = append(unbanned, "ban:"+target+":"+dur+":"+reason)
			return nil
		},
	}
	done := make(chan error, 1)
	go func() {
		// The refresh interval is longer than the test so that nothing
		// but a keystroke draws. Every frame is then one key's frame,
		// which is what lets the test below wait for the key to have
		// been read instead of pausing and hoping. The interval on its
		// own has a test of its own.
		done <- Run(src, act, Options{In: slave, Out: &out, Refresh: time.Hour, Color: true})
	}()

	waitForTheFirstFrame(t, &out, done)
	// The alternate screen is entered and the cursor hidden.
	if !strings.Contains(out.string(), "\x1b[?1049h") || !strings.Contains(out.string(), "\x1b[?25l") {
		t.Errorf("the alternate screen was not entered: %q", out.string()[:min(40, out.len())])
	}

	// press sends one key and waits for the frame it causes.
	//
	// A key is drawn whatever it does, including a key nothing is bound
	// to, so the frame is proof the key was read -- which is the thing a
	// pause between keystrokes can only guess at. It also keeps the
	// keys apart: the next one is not written until the reader has
	// finished with this one, so a cursor key cannot be cut in half by a
	// read that arrived a moment late.
	press := func(name, keys string) {
		t.Helper()
		before := out.frames()
		if _, err := master.WriteString(keys); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		until(t, "the frame after "+name, func() bool { return out.frames() > before })
		select {
		case err := <-done:
			t.Fatalf("Run returned on %s: %v", name, err)
		default:
		}
	}
	type keyPress struct {
		name string
		keys string
	}
	for _, k := range []keyPress{
		{"next view", "\t"},
		{"previous view", "\x1b[Z"},
		{"a numbered view", "5"},
		{"back to the bans", "3"}, // the bans are the third screen
		{"down", "j"},
		{"up", "k"},
		{"down again", "\x1b[B"},
		{"pause", "p"},
		{"resume", "p"},
		{"refresh", "r"},
		{"slower", "+"},
		{"faster", "-"},
		{"a key nobody bound", "Z"},
	} {
		press(k.name, k.keys)
	}
	// The refresh key fetched again. The frame comes after the fetch, so
	// this is settled by now and nothing has to be waited for.
	if n := src.count(); n < 2 {
		t.Errorf("the refresh key did not fetch: %d fetches", n)
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(unbanned)
	}
	// The unban prompt: it asks, and only "y" confirms.
	press("unban", "u")
	if !strings.Contains(out.last(), "unban 203.0.113.9") {
		t.Errorf("the unban prompt did not name the selected ban: %q", out.last())
	}
	press("a refusal", "n")
	press("return", "\r")
	// The submit runs before the frame, so a frame that has arrived is
	// the proof a pause was standing in for.
	if n := count(); n != 0 {
		t.Errorf("an unban happened without confirmation: %d", n)
	}
	press("unban again", "u")
	press("a confirmation", "y")
	press("return", "\r")
	if n := count(); n != 1 {
		t.Errorf("the confirmed unban did not happen: %d actions", n)
	}
	// The ban prompt takes a line, and backspace edits it. The line is
	// pasted rather than typed a key at a time, which is how an address
	// gets into this prompt in real use and is the one thing a single
	// read has to be able to hold.
	press("the ban prompt", "b")
	if !strings.Contains(out.last(), "ban <address") {
		t.Errorf("the ban prompt is not showing: %q", out.last())
	}
	if _, err := master.WriteString("203.0.113.99 1hX\x7f reason\r"); err != nil {
		t.Fatal(err)
	}
	until(t, "the ban", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(unbanned) > 1 && strings.HasPrefix(unbanned[len(unbanned)-1], "ban:203.0.113.99:1h:")
	})
	mu.Lock()
	last := unbanned[len(unbanned)-1]
	mu.Unlock()
	if last != "ban:203.0.113.99:1h:reason" {
		t.Errorf("the pasted line was read as %q", last)
	}
	// Escape cancels a prompt.
	press("the ban prompt again", "b")
	press("escape", "\x1b")
	if !strings.Contains(out.last(), "cancelled") {
		t.Errorf("escape did not cancel the prompt: %q", out.last())
	}

	// q quits, restoring the screen.
	if _, err := master.WriteString("q"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return on q")
	}
	if !strings.Contains(out.string(), "\x1b[?1049l") || !strings.Contains(out.string(), "\x1b[?25h") {
		t.Error("the screen was not restored")
	}
}

// The interval fetches on its own, and it is the one path that can find
// the selection pointing past the end of a list that has shrunk since
// the cursor was put there.
func TestTheIntervalFetchesAndKeepsTheSelectionInRange(t *testing.T) {
	master, slave := openPTY(t)
	var out lockedBuffer
	two := []ban.Entry{{Target: "198.51.100.7", Reason: "waf"}, {Target: "203.0.113.9", Reason: "rate"}}
	src := &countingSource{data: Data{Bans: two}}
	var mu sync.Mutex
	var unbanned []string
	act := Actions{Unban: func(target string) error {
		mu.Lock()
		defer mu.Unlock()
		unbanned = append(unbanned, target)
		return nil
	}}
	done := make(chan error, 1)
	go func() {
		done <- Run(src, act, Options{In: slave, Out: &out, Refresh: 20 * time.Millisecond})
	}()
	waitForTheFirstFrame(t, &out, done)

	// Onto the bans and down to the second one. The frames are not
	// attributable to a key here -- the interval is drawing too -- so
	// each step waits for what it does to show up in the frame.
	if _, err := master.WriteString("3"); err != nil {
		t.Fatal(err)
	}
	until(t, "the bans view", func() bool { return strings.Contains(out.last(), "198.51.100.7") })
	if _, err := master.WriteString("j"); err != nil {
		t.Fatal(err)
	}
	until(t, "the cursor on the second ban", func() bool { return strings.Contains(out.last(), "> 203.0.113.9") })

	// The list shrinks under the cursor. The interval fetches on its own
	// and has to bring the selection back in range: the row it pointed
	// at is gone.
	before := src.count()
	src.set(Data{Bans: two[:1]})
	until(t, "a fetch on the interval", func() bool { return src.count() > before+1 })
	until(t, "the cursor on the remaining ban", func() bool { return strings.Contains(out.last(), "> 198.51.100.7") })

	// And the selection is a row that exists, which is what the prompt
	// proves: a selection left past the end offers nothing to unban.
	if _, err := master.WriteString("u"); err != nil {
		t.Fatal(err)
	}
	until(t, "the unban prompt", func() bool { return strings.Contains(out.last(), "unban 198.51.100.7") })
	if _, err := master.WriteString("y\r"); err != nil {
		t.Fatal(err)
	}
	until(t, "the unban", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(unbanned) == 1 && unbanned[0] == "198.51.100.7"
	})

	if _, err := master.WriteString("q"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return on q")
	}
}

func TestRunRefusesANonTerminal(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out lockedBuffer
	if err := Run(&countingSource{}, Actions{}, Options{In: f, Out: &out}); err == nil {
		t.Error("Run took over something that is not a terminal")
	}
	if out.len() != 0 {
		t.Errorf("it wrote %d bytes to the output first", out.len())
	}
}

// lockedBuffer collects the frames Run draws. Each draw is one write, so
// the writes are the frames: a test can count them and read the last
// one, which is the screen as it stands.
type lockedBuffer struct {
	mu     sync.Mutex
	b      strings.Builder
	writes []string
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writes = append(l.writes, string(p))
	return l.b.Write(p)
}

func (l *lockedBuffer) string() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *lockedBuffer) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Len()
}

// frames is how many times Run has drawn.
func (l *lockedBuffer) frames() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.writes)
}

// last is the frame on the screen now.
func (l *lockedBuffer) last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.writes) == 0 {
		return ""
	}
	return l.writes[len(l.writes)-1]
}
