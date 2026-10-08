package ldap

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
)

// Every bound this listener runs with, configured and unset.
//
// Each of these has a default, and the default is the one that applies
// in most deployments -- so a configured value that was read as zero,
// or a default that changed under a release, would be a bound nobody
// noticed moving. The pairs below say what each one is on both sides.
func TestEveryBoundHasAConfiguredValueAndADefault(t *testing.T) {
	set := &server{m: &config.LDAPListener{
		MaxOutstanding:  7,
		MaxConnections:  9,
		MaxMessageBytes: 4096,
		IdleTimeout:     config.Duration(11 * time.Second),
		RequestTimeout:  config.Duration(12 * time.Second),
		ConnectTimeout:  config.Duration(13 * time.Second),
	}}
	unset := &server{m: &config.LDAPListener{}}
	for _, tc := range []struct {
		name        string
		got, want   int
		gotD, wantD time.Duration
		duration    bool
	}{
		{name: "max_outstanding", got: set.maxOutstanding(), want: 7},
		{name: "max_outstanding default", got: unset.maxOutstanding(), want: 32},
		{name: "max_connections", got: set.maxConnections(), want: 9},
		{name: "max_connections default", got: unset.maxConnections(), want: 256},
		{name: "max_message_bytes", got: set.maxMessage(), want: 4096},
		{name: "max_message_bytes default", got: unset.maxMessage(), want: 1 << 18},
		{name: "idle_timeout", gotD: set.idleTimeout(), wantD: 11 * time.Second, duration: true},
		{name: "idle_timeout default", gotD: unset.idleTimeout(), wantD: 300 * time.Second, duration: true},
		{name: "request_timeout", gotD: set.requestTimeout(), wantD: 12 * time.Second, duration: true},
		{name: "request_timeout default", gotD: unset.requestTimeout(), wantD: 30 * time.Second, duration: true},
		{name: "connect_timeout", gotD: set.connectTimeout(), wantD: 13 * time.Second, duration: true},
		{name: "connect_timeout default", gotD: unset.connectTimeout(), wantD: 5 * time.Second, duration: true},
	} {
		if tc.duration {
			if tc.gotD != tc.wantD {
				t.Errorf("%s = %s, want %s", tc.name, tc.gotD, tc.wantD)
			}
			continue
		}
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// A burst that was not configured is the rate, which is what makes
// `bind_rate_limit: 5` on its own mean five binds and not a limiter
// that refuses everything.
func TestABurstDefaultsToTheRate(t *testing.T) {
	if got := burstOf(0, 5); got != 5 {
		t.Errorf("burstOf(0, 5) = %d, want the rate", got)
	}
	if got := burstOf(9, 5); got != 9 {
		t.Errorf("burstOf(9, 5) = %d, want the burst", got)
	}
}

// The connection bound, which is the one refusal this listener makes
// before it has read a single byte.
//
// A directory in front of an estate is a service everything logs into,
// so the point of the bound is that the relay stops accepting rather
// than passing an unbounded number of sockets through to the directory
// -- and the refusal is counted, because an operator raising the bound
// needs to see that it was reached.
func TestTheConnectionBoundIsEnforcedAtAccept(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        require_tls: false
        max_connections: 1`, d.addr())

	// The first connection is accepted and held: the bind is refused for
	// travelling in the clear, which is a decision about the credential
	// and not about the socket, so the connection is counted either way.
	first := dialLDAP(t, addr)
	first.send(bind(1, "cn=app1,ou=services,dc=example,dc=com", "s3cret"))
	if got := first.next(3 * time.Second); got == nil {
		t.Fatal("the first connection was never answered")
	}

	// The second is refused at accept, whatever it sends.
	second := dialLDAP(t, addr)
	_ = second.trySend(bind(1, "cn=app2,ou=services,dc=example,dc=com", "s3cret"))
	if got := second.next(2 * time.Second); got != nil {
		t.Errorf("a connection past the bound was answered: %+v", got)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.LDAPRejected >= 1 && sn.Refusals["ldap"]["max_connections"] >= 1
	}, "the refused connection was not counted")
}
