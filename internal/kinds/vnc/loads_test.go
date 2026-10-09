package vnc

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/rfb"
)

// What this listener settles before it serves anything, and what its
// accept loop does with something that is not a connection.
//
// Neither is reachable through a real socket: a listener does not fail
// transiently on demand, and the secrets below are read once at start,
// so a mistake in one of them has to be refused there or it is never
// refused at all -- a gateway that started with no password is one that
// cannot authenticate anybody and will say so only to the first person
// who tries.

// engine is a server to hand the kind as its host. The listeners are
// never started -- nothing here serves anything -- but the kind reads
// the process's secret resolver, access ledger and logs while it is
// being built, so it needs a real one.
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

// secret writes a password file with the mode a secret has to have.
func secret(t *testing.T, name, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheSecretsAndListsAreReadWhenTheListenerIsBuilt(t *testing.T) {
	host := engine(t)
	good := secret(t, "pw", "desktop-secret\n", 0o600)
	open := secret(t, "open", "desktop-secret\n", 0o644)
	missing := filepath.Join(t.TempDir(), "nothing")

	for _, c := range []struct {
		name string
		v    config.VNCListener
		want string
	}{
		{
			name: "a password file that is not there",
			v:    config.VNCListener{PasswordFile: missing},
			want: "password_file",
		},
		{
			// A VNC password is one shared secret for a whole desktop,
			// so a file anybody on the host can read is the whole
			// gateway's authentication readable by anybody on the host.
			name: "a password file anybody can read",
			v:    config.VNCListener{PasswordFile: open},
			want: "readable by anyone else",
		},
		{
			name: "a VNC-authenticated VeNCrypt subtype with no password to check",
			v: config.VNCListener{
				SecurityTypes: []string{"vencrypt"}, VeNCryptSubtypes: []string{"x509-vnc"},
			},
			want: "non-empty password is required",
		},
		{
			// A directory passes the mode check and then cannot be
			// read, which is the other half of readSecret.
			name: "a password file that is a directory",
			v:    config.VNCListener{PasswordFile: t.TempDir()},
			want: "password_file",
		},
		{
			name: "an upstream password file that is not there",
			v:    config.VNCListener{UpstreamPasswordFile: missing},
			want: "upstream_password_file",
		},
		{
			name: "an allow_clients entry that is not a prefix",
			v:    config.VNCListener{AllowClients: []string{"192.0.2.1"}},
			want: "allow_clients",
		},
		{
			name: "an upstream CA file that is not there",
			v: config.VNCListener{
				UpstreamTLSMode: "vencrypt", UpstreamTLS: &config.UpstreamTLS{CAFile: missing},
			},
			want: "upstream_tls",
		},
		{
			name: "an RSA key file that is not a key",
			v:    config.VNCListener{RSAKeyFile: open},
			want: "rsa_key_file",
		},
		{
			name: "an SSH key file that is not there",
			v: config.VNCListener{
				SSH: &config.VNCOverSSH{Address: "127.0.0.1:22", KeyFile: missing, User: "jump"},
			},
			want: "ssh",
		},
		{
			name: "an MFA file that is not there",
			v:    config.VNCListener{MFA: &config.MFAPolicy{File: missing}},
			want: "mfa",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := c.v
			cfg := config.Listener{Name: "desks", VNC: &v}
			_, err := newServer(host, cfg, nil, nil)
			if err == nil {
				t.Fatalf("the listener was built with %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, which does not name %q", err, c.want)
			}
		})
	}

	// And the lists a working listener does read: the names become the
	// types this gateway will negotiate, in the order the operator put
	// them in, and a name it does not know is left out rather than
	// taken for something else.
	t.Run("what a working listener parsed", func(t *testing.T) {
		v := config.VNCListener{
			PasswordFile:     good,
			SecurityTypes:    []string{"VeNCrypt", " none ", "nonsense"},
			VeNCryptSubtypes: []string{"x509-plain", "also-nonsense"},
			AllowClients:     []string{"192.0.2.0/24", "198.51.100.7/32"},
		}
		srv, err := newServer(host, config.Listener{Name: "desks", VNC: &v}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(srv.offered) != 2 || srv.offered[0] != rfb.SecVeNCrypt || srv.offered[1] != rfb.SecNone {
			t.Errorf("security_types became %v", srv.offered)
		}
		if len(srv.subtypes) != 1 || srv.subtypes[0] != rfb.VeNCryptX509Plain {
			t.Errorf("vencrypt_subtypes became %v", srv.subtypes)
		}
		if len(srv.allow) != 2 {
			t.Errorf("allow_clients became %v", srv.allow)
		}
		if srv.password != "desktop-secret" {
			t.Errorf("the password read as %q; the newline is not part of it", srv.password)
		}
	})
}

// closedSocket is the error a listener gives after its socket was
// closed. The loop recognises nothing about it beyond that it is an
// error, so any will do, but the shape is the real one.
func closedSocket() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: errors.New("use of closed network connection")}
}

// scriptedAccepts answers each Accept from a script and then reports
// its socket closed, so a loop driven by it always ends.
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

func (l *scriptedAccepts) Close() error { return nil }
func (l *scriptedAccepts) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5900}
}

func (l *scriptedAccepts) seen() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// A connection the listener cannot serve -- it is full, or it is
// shutting down -- is closed rather than left open and unattended, and
// the loop ends when the socket does.
func TestTheAcceptLoopDropsWhatItCannotServeAndEndsWithItsSocket(t *testing.T) {
	full, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	ln := &scriptedAccepts{next: []acceptResult{{conn: full}, {err: closedSocket()}}}
	srv := &server{
		engine: engine(t),
		cfg:    config.Listener{Name: "desks"},
		v:      &config.VNCListener{MaxConnections: 0},
		ln:     ln,
		cons:   map[net.Conn]struct{}{},
	}
	finished := make(chan struct{})
	go func() { srv.serve(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the accept loop did not return when its socket was closed")
	}
	if n := ln.seen(); n != 2 {
		t.Errorf("the loop called Accept %d times, want both of the script", n)
	}
	// Dropped, not served: the connection the loop would not take is
	// closed, which the other end of the pipe sees.
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Error("a connection the listener would not serve was left open")
	}

	// A listener that is shutting down refuses the same way, for a
	// different reason: a session started now is one nothing waits for.
	srv.sessions.Close()
	if srv.admit(full) {
		t.Error("a connection was admitted by a listener that is shutting down")
	}
}

// A shutdown waits for the sessions it has, and closes the ones still
// running when the grace runs out. A shutdown that waited again would
// hang the process on one session that will not end.
func TestTheSessionsStillRunningWhenTheGraceEndsAreClosed(t *testing.T) {
	srv := &server{
		engine: engine(t),
		cfg:    config.Listener{Name: "desks"},
		v:      &config.VNCListener{MaxConnections: 10},
		cons:   map[net.Conn]struct{}{},
	}
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	if !srv.admit(client) {
		t.Fatal("a connection was not admitted by a serving listener")
	}
	var reading sync.WaitGroup
	reading.Add(1)
	go func() {
		defer srv.sessions.Leave()
		defer srv.untrack(client)
		reading.Done()
		// Held open until the shutdown closes it under us.
		_, _ = client.Read(make([]byte, 1))
	}()
	reading.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { srv.shutdown(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the shutdown did not return after the grace ran out")
	}
	// The session's own connection was closed, which is what the
	// session reading it notices.
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("a session still running at the end of the grace was left open")
	}
}

// engineWith is engine with upstreams of its own, for the parts of a
// session that need a pool rather than a listener.
func engineWith(t *testing.T, upstreams string) proxy.Host {
	t.Helper()
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
` + upstreams))
	if err != nil {
		t.Fatal(err)
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// What a session says when there is nothing to dial. A pool with no
// endpoint left and one whose endpoint refuses are different sentences
// to an operator reading the log, and neither may look like a session
// that worked.
func TestASessionWithNothingToDialSaysSo(t *testing.T) {
	t.Run("an endpoint that refuses", func(t *testing.T) {
		// A port nothing is listening on, so the dial itself is what
		// fails rather than the handshake after it.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		gone := ln.Addr().String()
		_ = ln.Close()
		host := engineWith(t, `
upstreams:
  - name: screens
    endpoints: [{address: `+gone+`}]
`)
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"},
			v: &config.VNCListener{Upstream: "screens"}}
		se := &session{t: srv, ip: netip.MustParseAddr("192.0.2.9")}
		if err := se.connect(); err == nil {
			t.Fatal("a session connected to a port nothing is listening on")
		}

		// And a grant for another machine is not satisfied by the one
		// the pool would have chosen: the window names a desktop.
		pinned := &session{t: srv, ip: netip.MustParseAddr("192.0.2.9"), pinned: "10.0.0.1:5900"}
		err = pinned.connect()
		if err == nil {
			t.Fatal("a pinned session reached a machine the grant does not name")
		}
		if !strings.Contains(err.Error(), "10.0.0.1:5900") {
			t.Errorf("the error says %q, which does not name the machine the grant is for", err)
		}
	})
}

// The session identifier is what the recording and the capture are
// named by, and a session that was never registered has none rather
// than a made-up one.
func TestASessionThatWasNeverListedHasNoIdentifier(t *testing.T) {
	se := &session{t: &server{v: &config.VNCListener{}}}
	if id := se.sessionID(); id != "" {
		t.Errorf("an unlisted session answered %q", id)
	}
}
