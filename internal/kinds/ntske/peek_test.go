package ntske_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/ntp"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// Everything the ClientHello reader can decide before a handshake exists.
//
// These are the paths a scan takes, and until this file they were covered
// only by accident: two runs of the same suite over the same code disagreed
// about them by six statements, because whether a hello arrives in one read
// or two decided whether the loop went round again. Driven deliberately they
// are both covered and stable -- and the behaviour is worth pinning on its
// own account, because this is the only thing between port 4460 and anything
// that is not an NTS client.
//
// The record header is what each case turns on. handshakeBytes wants
// `16 03 xx` and a record length in [1, 16640]; short of `5 + recLen` octets
// it asks for more, which is this loop's signal to keep reading.
func TestWhatTheHelloReaderDecidesWithoutAHandshake(t *testing.T) {
	// A record promising 512 octets, which these cases never complete.
	header := []byte{0x16, 0x03, 0x01, 0x02, 0x00}

	for _, tc := range []struct {
		name   string
		write  []byte
		reason string
	}{
		// Nothing at all. A connection opened and dropped is the shape of a
		// port scan, and it is refused by its own name rather than as a
		// malformed hello: there was no hello.
		{name: "a connection that says nothing", reason: "no_hello"},
		// A record header and less than it promised. This is the ordinary
		// end of a recording that was cut, and the shape of a client that
		// died mid-handshake.
		{name: "a record header and nothing after it",
			write: header, reason: "incomplete_hello"},
		{name: "a hello cut off part way",
			write:  append(append([]byte{}, header...), 0x01, 0x00, 0x01, 0xFC, 0x03, 0x03),
			reason: "incomplete_hello"},
		// A record that promises the most a TLS record may carry and then
		// dribbles out more than the reader will hold. Without the bound the
		// loop would keep appending for as long as the peer kept writing.
		{name: "a hello larger than the reader will hold",
			write: append([]byte{0x16, 0x03, 0x01, 0x41, 0x00},
				make([]byte, 16<<10+120)...),
			reason: "hello_too_large"},
		// And the case that is not a length at all: bytes that cannot be a
		// handshake record. This port carries one protocol and it starts
		// with a ClientHello, so anything else is a scan rather than a
		// client that took a wrong turn.
		{name: "bytes that are not a handshake record",
			write: []byte("GET / HTTP/1.1\r\nHost: ke.test\r\n\r\n"), reason: "not_tls"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := testutil.WriteCert(t, t.TempDir(), "ke.test")
			up := startKEServer(t, cert, key)
			s, addr := ntskeServer(t, `        upstream: ke_servers
        handshake_timeout: 1s`, up)

			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.write) > 0 {
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Write(tc.write); err != nil {
					// A peer that refused the whole write is still a peer
					// that wrote some of it, which is what the case needs.
					t.Logf("write: %v", err)
				}
			}
			// Closing is what turns "not here yet" into "not coming": the
			// reader's next read fails and it decides.
			_ = c.Close()

			refused(t, s, tc.reason, 1)
			// And nothing reached the key establishment server: a connection
			// refused on its handshake is one the relay never dialled out for.
			if n := s.Stats().NTSKERelayed; n != 0 {
				t.Errorf("ntske_relayed is %d, want 0", n)
			}
		})
	}
}

// The decisions this gateway makes about a connection before, and instead
// of, reading a handshake: the client lists, the two bounds, and a key
// establishment server that is not there.
//
// These are the rest of what made this package's figure move between runs:
// its own tests reached none of them, so whether they were covered at all
// depended on another package's tests happening to walk through here.

// A client outside allow_clients is refused without the handshake being
// read, which is the point of asking first: a scan from an address that has
// no business on 4460 costs this relay one accept and no TLS.
func TestAClientOutsideTheListIsRefusedBeforeTheHandshake(t *testing.T) {
	cert, key := testutil.WriteCert(t, t.TempDir(), "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers
        allow_clients: ["10.0.0.0/8"]`, up)

	c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", wire.ALPN))
	if err == nil {
		_ = c.Close()
	}
	refused(t, s, "client_not_allowed", 1)
	if n := s.Stats().NTSKERelayed; n != 0 {
		t.Errorf("ntske_relayed is %d, want 0", n)
	}
}

// A key establishment server that cannot be reached is reported as the
// relay's own failure rather than as something the client did. The
// distinction matters on this protocol: a client refused for its own
// handshake should fix its handshake, and a client told the upstream is
// unavailable should wait.
func TestAKeyEstablishmentServerThatIsNotThere(t *testing.T) {
	cert, _ := testutil.WriteCert(t, t.TempDir(), "ke.test")
	// A listener whose pool points at a port nothing is listening on: the
	// address is taken and released so that it is a port that answers
	// nothing rather than one that might belong to somebody else.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()

	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: ke
      address: "127.0.0.1:0"
      kind: ntske
      ntske:
        upstream: ke_servers
logging: {access: {enabled: false}}
upstreams:
  - {name: ke_servers, endpoints: [{address: %q}]}
`, dead))
	addr := proxytest.Addr(t, s, "ke")

	c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", wire.ALPN))
	if err == nil {
		_ = c.Close()
	}
	// Counted on its own gauge rather than in the refusal-reason table: an
	// upstream that is down is this relay's problem, not a client's, and
	// ntske_upstream_failed is the series an operator pages on. (The sibling
	// kinds put an upstream failure in the reason table as well; this one
	// does not, which is worth knowing when reading across them.)
	for deadline := time.Now().Add(10 * time.Second); ; {
		if s.Stats().NTSKEUpstreamFailed >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ntske_upstream_failed stayed at 0; refusals %v",
				s.Stats().Refusals["ntske"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := s.Stats().NTSKERelayed; n != 0 {
		t.Errorf("ntske_relayed is %d, want 0", n)
	}
}

// The two bounds, each driven with a bound of one and a connection held
// open. They are separate knobs and separate refusals: max_connections is
// about sockets this listener is holding, max_concurrent_handshakes about
// the ones still negotiating, and an estate that confused them would size
// one of them wrongly.
func TestTheConnectionBoundsAreCountedSeparately(t *testing.T) {
	for _, tc := range []struct {
		name, section, reason string
	}{
		{"the connection bound", "        max_connections: 1\n", "max_connections"},
		{"the handshake bound", "        max_concurrent_handshakes: 1\n", "handshake_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := testutil.WriteCert(t, t.TempDir(), "ke.test")
			up := startKEServer(t, cert, key)
			s, addr := ntskeServer(t, "        upstream: ke_servers\n"+tc.section, up)

			// The first connection is opened and held without completing a
			// handshake, so it occupies the slot rather than passing through.
			held, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Close() }()
			if _, err := held.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00}); err != nil {
				t.Fatal(err)
			}
			// Wait for the relay to be holding it before the second arrives,
			// so the bound is reached rather than raced.
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				if s.Stats().NTSKESessions >= 1 || s.Stats().NTSKEHandshakes >= 1 {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}

			second, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = second.Close() }()
			refused(t, s, tc.reason, 1)
		})
	}
}

// A shutdown whose grace period runs out closes what is still open.
//
// A gateway that could not be stopped while a client held a connection
// would be one an operator cannot restart, which on this protocol means a
// fleet that cannot get fresh cookies. So the grace period is a bound and
// not a hope: when it expires the sockets are closed and the wait returns.
func TestAShutdownThatRunsOutOfGraceClosesWhatIsOpen(t *testing.T) {
	cert, key := testutil.WriteCert(t, t.TempDir(), "ke.test")
	up := startKEServer(t, cert, key)
	s, addr := ntskeServer(t, `        upstream: ke_servers
        handshake_timeout: 30s`, up)

	// A connection that has started a handshake and will not finish it, so
	// it is still being held when the shutdown begins.
	held, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if _, err := held.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if s.Stats().NTSKESessions >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A grace period that has already expired: the shutdown must not wait
	// for the client to decide to finish.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(ctx) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the shutdown did not return: a held connection kept the gateway up")
	}

	// And the held connection was closed rather than left to the client.
	_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil {
		t.Error("the held connection is still open after the shutdown")
	}
}
