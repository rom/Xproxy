package ldap

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/testutil"
)

// The directory's leg, which this relay upgrades on its own behalf rather
// than relaying: a bind carries a password, and the hop from this relay to
// the directory is a second network with its own answer to whether that
// password crosses it in clear.
//
// Both transports a directory offers are here -- LDAPS from the first octet
// and StartTLS in band -- and so are the three ways the in-band one fails: a
// directory that refuses the upgrade, one that answers it with something
// else, and one that cannot be reached at all. None of them may end with the
// bind going past.

// directoryCert writes a CA and the certificate a fake directory serves.
func directoryCert(t *testing.T, name string) (*testutil.CA, *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, name)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return ca, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
}

// boundClient dials the relay over TLS and binds. The client leg is TLS
// because a password in the clear is refused before any of this is reached,
// which is a different test.
func boundClient(t *testing.T, s *proxy.Server, addr string, ca *testutil.CA) *client {
	t.Helper()
	cl := dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=app1,ou=services,dc=example,dc=com", "s3cret"))
	return cl
}

// TestTheDirectoryLegIsUpgradedByThisRelay: each transport, driven to a bind
// the directory answered -- which it can only have done inside TLS, because
// that is the only way it would read the request at all.
func TestTheDirectoryLegIsUpgradedByThisRelay(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		// inBand says the directory is in clear until the relay asks.
		inBand bool
	}{
		{name: "LDAPS from the first octet", mode: "implicit"},
		{name: "StartTLS in band", mode: "starttls", inBand: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dirCA, dirCfg := directoryCert(t, "directories.test")
			d := &directory{}
			if tc.inBand {
				d.startTLS, d.startTLSCfg = true, dirCfg
			} else {
				d.serverTLS = dirCfg
			}
			startDirectory(t, d)
			ca, cert, key := certs(t)
			s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        default_action: allow
        upstream_tls_mode: `+tc.mode+`
        upstream_tls: {ca_file: `+dirCA.Path+`, server_name: directories.test, min_version: "1.2"}`+
				tlsSection(cert, key), d.addr())

			cl := boundClient(t, s, addr, ca)
			got := cl.next(10 * time.Second)
			if got == nil {
				t.Fatal("the bind was never answered")
			}
			if got.Op != wire.OpBindResponse || got.Result.Code != wire.ResultSuccess {
				t.Fatalf("the bind was answered %s %+v", got.Op, got.Result)
			}
			// The directory answered, so it read the request, so the
			// handshake happened: a directory expecting TLS reads nothing
			// from a relay that did not upgrade.
			seen := d.await(t, 1, "the bind")
			if tc.inBand && seen[0].Op != wire.OpExtendedRequest {
				t.Errorf("the first thing the directory saw was %s, want the StartTLS request", seen[0].Op)
			}
		})
	}
}

// TestTheServerNameDefaultsToTheEndpointItDialled: a trust store with no name
// in it still verifies, against the address the endpoint was configured as --
// not skipped, which is the failure mode that makes a verified upstream leg
// worthless.
func TestTheServerNameDefaultsToTheEndpointItDialled(t *testing.T) {
	// The certificate carries 127.0.0.1, and nothing else about it matches
	// the endpoint, so a handshake that succeeds here is one that checked
	// the address.
	dirCA, dirCfg := directoryCert(t, "nothing-like-the-address.test")
	d := startDirectory(t, &directory{serverTLS: dirCfg})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        default_action: allow
        upstream_tls_mode: implicit
        upstream_tls: {ca_file: `+dirCA.Path+`, min_version: "1.2"}`+tlsSection(cert, key), d.addr())

	cl := boundClient(t, s, addr, ca)
	if got := cl.next(10 * time.Second); got == nil || got.Result.Code != wire.ResultSuccess {
		t.Fatalf("the bind was answered %+v", got)
	}
	d.await(t, 1, "the bind")
}

// TestADirectoryThatWillNotUpgradeIsNotTalkedToInClear: the fallback that
// must not exist. A directory that refuses StartTLS, or answers it with
// something that is not an answer to it, is one this relay stops talking to
// -- the password it was about to forward stays on this side.
func TestADirectoryThatWillNotUpgradeIsNotTalkedToInClear(t *testing.T) {
	for _, tc := range []struct {
		name string
		dir  *directory
	}{
		{"it refuses the upgrade", &directory{startTLS: false}},
		{"it answers the upgrade with a bind response", &directory{
			reply: func(m *wire.Message) []byte { return bindResult(m.ID, wire.ResultSuccess) },
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := startDirectory(t, tc.dir)
			dirCA, _ := directoryCert(t, "directories.test")
			ca, cert, key := certs(t)
			s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        default_action: allow
        upstream_tls_mode: starttls
        upstream_tls: {ca_file: `+dirCA.Path+`, server_name: directories.test, min_version: "1.2"}`+
				tlsSection(cert, key), d.addr())

			cl := boundClient(t, s, addr, ca)
			if got := cl.next(3 * time.Second); got != nil {
				t.Errorf("the client was answered %s %+v", got.Op, got.Result)
			}
			for _, m := range d.seen() {
				if m.Op == wire.OpBindRequest {
					t.Errorf("the bind reached the directory anyway")
				}
			}
			awaitCounter(t, s, func(sn proxy.Snapshot) bool {
				return sn.LDAPUpstreamFail >= 1
			}, "the refused upgrade was not counted")
		})
	}
}

// TestADirectoryThatCannotBeReachedIsCounted: no endpoint answered. The
// session ends without a bind response rather than with a success the client
// would take for an authenticated session.
func TestADirectoryThatCannotBeReachedIsCounted(t *testing.T) {
	// A port that was bound and released: nothing is listening on it, and
	// nothing else in this test suite is using it either.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := ln.Addr().String()
	_ = ln.Close()

	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        default_action: allow`+tlsSection(cert, key), gone)

	cl := boundClient(t, s, addr, ca)
	if got := cl.next(3 * time.Second); got != nil {
		t.Errorf("the client was answered %s %+v", got.Op, got.Result)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.LDAPUpstreamFail >= 1
	}, "the unreachable directory was not counted")
}

// TestShutdownClosesTheSessionsItWasNotGivenTimeFor: a shutdown whose context
// is already past does not wait for an idle client to go away on its own. The
// sessions are closed, and the call still returns rather than hanging on a
// wait group nothing will finish.
func TestShutdownClosesTheSessionsItWasNotGivenTimeFor(t *testing.T) {
	d := startDirectory(t, &directory{})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        default_action: allow`+tlsSection(cert, key), d.addr())

	cl := boundClient(t, s, addr, ca)
	if got := cl.next(10 * time.Second); got == nil || got.Result.Code != wire.ResultSuccess {
		t.Fatalf("the bind was answered %+v", got)
	}

	// Already past: the grace is spent before the shutdown begins.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		_ = s.Shutdown(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the shutdown never returned with a session still open")
	}
	// And the session is gone, which is what the closing was for.
	if got := cl.next(5 * time.Second); got != nil {
		t.Errorf("the session outlived the shutdown: %s", got.Op)
	}
}
