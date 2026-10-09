package smtp

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// What the listener settles before it serves anything, and what it does with
// the sessions still running when the grace period it was given runs out.
//
// Both are worth their own test because neither is reachable from a session.
// The lists below are read once at start, so a mistake in one of them has to
// be refused there or it is never refused at all; and the shutdown path only
// runs when a reload or a signal has already decided this listener is going
// away, which is exactly when a session must not be left behind.

func TestTheListsAreReadWhenTheListenerIsBuilt(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	for _, c := range []struct {
		name string
		m    config.SMTPListener
		want string
	}{
		{
			// A bare address is not a prefix, and the difference matters:
			// 10.0.0.1 and 10.0.0.1/32 are the same network, but a typed
			// address with no length is as likely to be a mistake for /24.
			name: "an allowed client that is not a prefix",
			m:    config.SMTPListener{UpstreamTLSMode: "none", AllowClients: []string{"10.0.0.1"}},
			want: "smtp allow_clients",
		},
		{
			name: "a certificate authority that is not there",
			m:    config.SMTPListener{UpstreamTLSMode: "starttls", UpstreamTLS: &config.UpstreamTLS{CAFile: missing}},
			want: "smtp upstream_tls",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := newServer(nil, config.Listener{Name: "mail", SMTP: &c.m}, nil, nil)
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not name %q", err, c.want)
			}
		})
	}

	t.Run("and the capability list is normalised", func(t *testing.T) {
		// Written as an operator writes it: the case of an EHLO keyword is
		// not significant and a list in YAML collects stray spaces.
		s, err := newServer(nil, config.Listener{Name: "mail", SMTP: &config.SMTPListener{
			UpstreamTLSMode:  "none",
			Commands:         []string{"ehlo", "QUIT"},
			HideCapabilities: []string{" dsn ", "Help"},
			Banner:           "mail.test ESMTP xproxy",
		}}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, kw := range []string{"DSN", "HELP"} {
			if !s.hidden[kw] {
				t.Errorf("%s is not hidden", kw)
			}
		}
		// The ones it always hides are there whether or not they were asked
		// for: STARTTLS because the proxy answers it itself, CHUNKING
		// because BDAT has no terminator for the two ends to agree on.
		for _, kw := range config.SMTPAlwaysHidden {
			if !s.hidden[kw] {
				t.Errorf("%s is not hidden", kw)
			}
		}
		if !s.verbs["EHLO"] || !s.verbs["QUIT"] || s.verbs["DATA"] {
			t.Errorf("verbs: %v", s.verbs)
		}
		// The name the proxy gives as its own: the banner's first word,
		// because that is the name the client was already greeted with.
		if s.host != "mail.test" {
			t.Errorf("host = %q, want mail.test", s.host)
		}
	})
}

func TestTheSessionsStillRunningWhenTheGraceEndsAreClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &server{ln: ln, cons: map[net.Conn]struct{}{}, done: make(chan struct{})}

	// A session that ends when, and only when, its connection is closed:
	// the one shutdown has to decide about.
	client, _ := net.Pipe()
	if !s.admit(client) {
		t.Fatal("a connection was not admitted by a serving listener")
	}
	var reading sync.WaitGroup
	reading.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.untrack(client)
		reading.Done()
		_, _ = client.Read(make([]byte, 1))
	}()
	reading.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { s.shutdown(ctx); close(done) }()
	<-done

	// And once it has shut down the listener admits nothing: a connection
	// accepted after this point would be a session nobody is waiting for.
	other, _ := net.Pipe()
	if s.admit(other) {
		t.Error("a connection was admitted after the listener shut down")
	}
	// Shutting down twice is what a reload racing a signal does.
	s.shutdown(context.Background())
}
