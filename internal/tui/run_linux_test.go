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

// countingSource answers with a fixed view and counts the fetches.
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
		done <- Run(src, act, Options{In: slave, Out: &out, Refresh: 50 * time.Millisecond, Color: true})
	}()

	// Wait for the first frame.
	deadline := time.After(20 * time.Second)
	for out.len() == 0 {
		select {
		case err := <-done:
			t.Fatalf("Run returned early: %v", err)
		case <-deadline:
			t.Fatal("no frame was drawn")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	// The alternate screen is entered and the cursor hidden.
	if !strings.Contains(out.string(), "\x1b[?1049h") || !strings.Contains(out.string(), "\x1b[?25l") {
		t.Errorf("the alternate screen was not entered: %q", out.string()[:min(40, out.len())])
	}
	// The reader hands one read to handleKey, so a key is one write; a
	// line is typed one key at a time the way a person types it.
	typeLine := func(text string) {
		t.Helper()
		for _, r := range text {
			if _, err := master.WriteString(string(r)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(15 * time.Millisecond)
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
		if _, err := master.WriteString(k.keys); err != nil {
			t.Fatalf("%s: %v", k.name, err)
		}
		time.Sleep(20 * time.Millisecond)
		select {
		case err := <-done:
			t.Fatalf("Run returned on %s: %v", k.name, err)
		default:
		}
	}
	// The refresh key fetched again.
	until(t, "a second fetch", func() bool { return src.count() >= 2 })
	// The unban prompt: it asks, and only "y" confirms.
	if _, err := master.WriteString("u"); err != nil {
		t.Fatal(err)
	}
	until(t, "the unban prompt", func() bool { return strings.Contains(out.string(), "unban") })
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(unbanned)
	}
	typeLine("n\r")
	// A negative is the one thing polling cannot establish, so it keeps
	// its pause: nothing is expected to arrive, and the wait is for it
	// to have had the chance.
	time.Sleep(100 * time.Millisecond)
	if n := count(); n != 0 {
		t.Errorf("an unban happened without confirmation: %d", n)
	}
	typeLine("uy\r")
	until(t, "the confirmed unban", func() bool { return count() == 1 })
	// The ban prompt takes a line, and backspace edits it.
	typeLine("b203.0.113.99 1hX\x7f reason\r")
	until(t, "the ban", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(unbanned) > 1 && strings.HasPrefix(unbanned[len(unbanned)-1], "ban:203.0.113.99:1h:")
	})
	// Escape cancels a prompt.
	typeLine("b\x1b")
	time.Sleep(50 * time.Millisecond)

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

// lockedBuffer collects the frames Run draws.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
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
