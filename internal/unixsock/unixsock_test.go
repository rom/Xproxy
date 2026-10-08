package unixsock_test

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/unixsock"
)

// TestListenMode: the socket ends up with the mode asked for, and never
// exists more open than that. The second half cannot be observed from
// here, so what is checked is the result.
func TestListenMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	ln, err := unixsock.Listen(p, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Fatalf("mode = %o, want 660", got)
	}
}

// TestListenRefusesLiveSocket: a path something is listening on belongs
// to a running process, and taking it would split a daemon in two.
func TestListenRefusesLiveSocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	first, err := unixsock.Listen(p, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	go func() {
		for {
			c, err := first.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if _, err := unixsock.Listen(p, 0o600); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("second bind: %v", err)
	}
}

// TestListenClearsStaleSocket: a socket left by a process that died is
// removed, because refusing would mean the daemon never starts again
// after one unclean stop.
func TestListenClearsStaleSocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	dead, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	// Close without unlinking, which is what a killed process leaves.
	dead.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = dead.Close()
	ln, err := unixsock.Listen(p, 0o600)
	if err != nil {
		t.Fatalf("a stale socket was not cleared: %v", err)
	}
	_ = ln.Close()
}

// TestListenLeavesOtherFiles: a path that is not a socket is a
// configuration pointing somewhere it should not, and deleting it would
// be this process destroying a file on the strength of a typing
// mistake.
func TestListenLeavesOtherFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "important.db")
	if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := unixsock.Listen(p, 0o600); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("binding over a file: %v", err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "data" {
		t.Fatalf("the file was touched: %q %v", b, err)
	}
}

// TestListenUnlinksOnClose keeps the next start clean.
func TestListenUnlinksOnClose(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.sock")
	ln, err := unixsock.Listen(p, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("the socket survived Close: %v", err)
	}
}

// TestListenRefusesNoPath: a daemon configured with no socket path asks for
// one bound nowhere, and a listener on "" would be a management interface
// nobody can reach and nobody can see is missing.
func TestListenRefusesNoPath(t *testing.T) {
	if _, err := unixsock.Listen("", 0o600); err == nil || !strings.Contains(err.Error(), "no path") {
		t.Fatalf("an empty path: %v", err)
	}
}

// TestListenReportsABindThatCannotHappen: the bind's own error is returned
// rather than turned into something of this package's, because what the
// operator needs is the reason the kernel gave -- here a parent directory
// that is not there, which is a path in the configuration that does not exist.
func TestListenReportsABindThatCannotHappen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "no-such-directory", "s.sock")
	ln, err := unixsock.Listen(p, 0o600)
	if err == nil {
		_ = ln.Close()
		t.Fatal("binding under a directory that does not exist succeeded")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error = %v, want one that says the path is not there", err)
	}
}
