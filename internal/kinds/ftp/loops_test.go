package ftp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// What this listener settles before it serves anything, and what its accept
// loop does with something that is not a connection.
//
// Neither is reachable through a real socket: a listener does not fail
// transiently on demand, and the lists below are read once at start, so a
// mistake in one of them has to be refused there or it is never refused at
// all.

// engine is a server to hand the kind as its host. The listeners are never
// started -- nothing here serves anything -- but the kind reads the
// process's secret resolver, access ledger and logs while it is being
// built, so it needs a real one.
func engine(t *testing.T) proxy.Host {
	t.Helper()
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// closedSocket is the error a listener gives after its socket was closed.
// The loop recognises it by shape, so a test that drives it has to produce
// the shape rather than a sentinel.
func closedSocket() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: errors.New("use of closed network connection")}
}

func timedOut() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.ErrDeadlineExceeded}
}

// scriptedAccepts answers each Accept from a script and then reports its
// socket closed, so a loop driven by it always ends.
type scriptedAccepts struct {
	mu    sync.Mutex
	next  []acceptResult
	calls int
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func (l *scriptedAccepts) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if len(l.next) == 0 {
		return nil, closedSocket()
	}
	r := l.next[0]
	l.next = l.next[1:]
	return r.conn, r.err
}

func (l *scriptedAccepts) Close() error   { return nil }
func (l *scriptedAccepts) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 21} }

func (l *scriptedAccepts) seen() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func TestTheAcceptLoopKeepsGoingOnAnErrorAndEndsOnAClosedSocket(t *testing.T) {
	ln := &scriptedAccepts{next: []acceptResult{
		{err: timedOut()},
		{err: errors.New("something the kernel has not explained")},
		{err: closedSocket()},
	}}
	srv := &server{
		cfg:  config.Listener{Name: "files", FTP: &config.FTPListener{MaxConnections: 10}},
		f:    &config.FTPListener{MaxConnections: 10},
		ln:   ln,
		cons: map[net.Conn]struct{}{},
		done: make(chan struct{}),
	}
	start := time.Now()
	finished := make(chan struct{})
	go func() { srv.serve(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the accept loop did not return on a closed socket")
	}
	if n := ln.seen(); n != 3 {
		t.Errorf("the loop called Accept %d times, want all three of the script", n)
	}
	// The unexplained error cost the loop its backoff. Without it a socket
	// that answers an error immediately spins a core until somebody notices.
	if took := time.Since(start); took < 10*time.Millisecond {
		t.Errorf("the loop went round an unexplained error in %v, with no pause at all", took)
	}
}

func TestAConnectionAcceptedAfterTheListenerIsRetiredIsDropped(t *testing.T) {
	client, accepted := net.Pipe()
	srv := &server{
		cfg:  config.Listener{Name: "files", FTP: &config.FTPListener{MaxConnections: 10}},
		f:    &config.FTPListener{MaxConnections: 10},
		ln:   &scriptedAccepts{next: []acceptResult{{conn: accepted}}},
		cons: map[net.Conn]struct{}{},
		done: make(chan struct{}),
	}
	// Retired between the accept and the admission, which is what a reload
	// that removes a listener does to a connection already on the queue.
	close(srv.done)
	srv.serve()

	if n := srv.open.Load(); n != 0 {
		t.Errorf("the listener still counts %d open connections", n)
	}
	if len(srv.cons) != 0 {
		t.Errorf("the connection was tracked by a listener that is going away: %v", srv.cons)
	}
	if _, err := client.Write([]byte("anybody there")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("writing to the dropped connection gave %v, want it closed", err)
	}
}

func TestTheSessionsStillRunningWhenTheGraceEndsAreClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &server{
		cfg:  config.Listener{Name: "files", FTP: &config.FTPListener{MaxConnections: 10}},
		f:    &config.FTPListener{MaxConnections: 10},
		ln:   ln,
		cons: map[net.Conn]struct{}{},
		done: make(chan struct{}),
	}
	client, accepted := net.Pipe()
	if !srv.admit(accepted) {
		t.Fatal("a serving listener did not admit a connection")
	}
	reading := make(chan struct{})
	go func() {
		defer srv.wg.Done()
		defer srv.untrack(accepted)
		close(reading)
		_, _ = accepted.Read(make([]byte, 1))
	}()
	<-reading

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := make(chan struct{})
	go func() { srv.shutdown(ctx); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not return after its grace period ended")
	}
	if _, err := client.Write([]byte("anybody there")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("writing to the session gave %v, want it closed by the shutdown", err)
	}
	_, late := net.Pipe()
	if srv.admit(late) {
		t.Error("a connection was admitted after the listener shut down")
	}
	// Shutting down twice is what a reload racing a signal does.
	srv.shutdown(context.Background())
}

// The lists this listener is built from are read once, so a mistake in one
// of them is a refusal to start rather than a session that quietly carries
// what the operator thought they had excluded.
func TestTheListsAreReadWhenTheListenerIsBuilt(t *testing.T) {
	host := engine(t)
	dir := t.TempDir()
	for _, c := range []struct {
		name string
		f    config.FTPListener
		want string
	}{
		{
			// A bare address is not a prefix, and the difference matters:
			// 10.0.0.1 and 10.0.0.1/32 are the same network, but a typed
			// address with no length is as likely to be a mistake for /24.
			name: "an allowed client that is not a prefix",
			f:    config.FTPListener{UpstreamTLSMode: "none", AllowClients: []string{"10.0.0.1"}},
			want: "ftp allow_clients",
		},
		{
			name: "a certificate authority that is not there",
			f: config.FTPListener{UpstreamTLSMode: "starttls",
				UpstreamTLS: &config.UpstreamTLS{CAFile: filepath.Join(dir, "absent.pem")}},
			want: "ftp upstream_tls",
		},
		{
			// The address a passive reply advertises. A name here would be
			// a reply no client can read: PASV is six octets.
			name: "a data address that is not an address",
			f:    config.FTPListener{UpstreamTLSMode: "none", DataAddress: "ftp.example.invalid"},
			want: "ftp data_address",
		},
		{
			name: "a port range that is not one",
			f:    config.FTPListener{UpstreamTLSMode: "none", DataPorts: "50000-"},
			want: "ftp data_ports",
		},
		{
			name: "an enrolment file that is not there",
			f: config.FTPListener{UpstreamTLSMode: "none",
				MFA: &config.MFAPolicy{File: filepath.Join(dir, "absent.json")}},
			want: "ftp mfa",
		},
		{
			name: "a YARA rule file that is not there",
			f: config.FTPListener{UpstreamTLSMode: "none",
				YARA: &config.YARAPolicy{RulesFile: filepath.Join(dir, "absent.yar")}},
			want: "yara",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := newServer(host, config.Listener{Name: "files", FTP: &c.f}, nil, nil)
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not name %q", err, c.want)
			}
		})
	}

	t.Run("and the lists that are valid are normalised", func(t *testing.T) {
		// Written as an operator writes them: the case of an extension is
		// not significant, and a list in YAML collects stray spaces.
		s, err := newServer(host, config.Listener{Name: "files", FTP: &config.FTPListener{
			UpstreamTLSMode: "none",
			Commands:        []string{" user ", "PASS", "quit"},
			AllowExtensions: []string{".TXT", ".Csv"},
			DenyExtensions:  []string{".EXE"},
			AllowPaths:      []string{"/home/{user}"},
		}}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"USER", "PASS", "QUIT"} {
			if !s.verbs[verb] {
				t.Errorf("%s is not in the verb list", verb)
			}
		}
		if s.verbs["DELE"] {
			t.Error("a verb nobody listed is in the list")
		}
		for _, ext := range []string{".txt", ".csv"} {
			if !s.policy.allowExt[ext] {
				t.Errorf("%s is not allowed", ext)
			}
		}
		if !s.policy.denyExt[".exe"] {
			t.Error(".exe is not denied")
		}
		// A path list that names the user has to be recompiled per session,
		// and the listener has to know that before the first one arrives.
		if !s.policy.templated {
			t.Error("a path template was not noticed")
		}
	})
}
