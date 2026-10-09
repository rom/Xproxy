package postgres

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/pgwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/testutil"
)

// The database's own leg, and the messages a client can send that are not
// messages.
//
// Both halves of the same question: this relay reads what crosses it, so what
// it does with something unreadable is policy rather than plumbing. A message
// whose declared length does not match its contents is the shape every
// length-prefixed injection takes -- the relay reads it one way, the server
// another -- and a server leg left in clear is a password on the wire.

// serverCert writes a CA and the certificate a fake database serves.
func serverCert(t *testing.T, name string) (*testutil.CA, *tls.Config) {
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

func waitRefused(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().Refusals["postgres"][reason] == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s was not counted: %v", reason, s.Stats().Refusals["postgres"])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTheDatabaseLegIsUpgradedByThisRelay: the relay asks the server for TLS
// on its own behalf and verifies what it gets, with the name taken from the
// configuration or, where none was given, from the address it dialled -- not
// skipped, which is the failure that makes a verified leg worthless.
func TestTheDatabaseLegIsUpgradedByThisRelay(t *testing.T) {
	for _, tc := range []struct{ name, serverName, certName string }{
		{"the name it was configured with", ", server_name: db.test", "db.test"},
		// Nothing about this certificate's name matches the endpoint, so a
		// handshake that succeeds is one that verified the address instead.
		{"the address it dialled", "", "nothing-like-the-address.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, cfg := serverCert(t, tc.certName)
			fake := startFake(t, &fakeServer{sslAnswer: wire.AllowTLS, sslCfg: cfg})
			s, addr := relayFor(t, "        upstream: pg\n"+
				"        require_tls: false\n"+
				"        default_action: allow\n"+
				"        upstream_tls_mode: require\n"+
				"        upstream_tls: {ca_file: "+ca.Path+tc.serverName+", min_version: \"1.2\"}\n",
				fake.addr())

			cl := dial(t, addr, "user", "alice", "database", "sales")
			if e := cl.waitReady(t); e != "" {
				t.Fatalf("the session over an upgraded server leg: %s", e)
			}
			fake.mu.Lock()
			asked := fake.sslAsked
			fake.mu.Unlock()
			if asked != 1 {
				t.Errorf("the relay made %d ssl requests", asked)
			}
			// The startup crossed after the handshake, so the fake read it
			// inside TLS -- it reads nothing from a relay that did not upgrade.
			if ss := fake.sawStartups(); len(ss) != 1 || ss[0]["user"] != "alice" {
				t.Fatalf("the server saw %+v", ss)
			}
			if r := s.Stats().Refusals["postgres"]; len(r) != 0 {
				t.Errorf("an upgraded leg refused something: %v", r)
			}
		})
	}
}

// TestADatabaseThatAnswersTheSSLRequestWithNonsenseIsNotTalkedTo: the answer
// to an SSL request is one octet and there are two of them. Anything else is
// not a PostgreSQL server, and the startup packet -- which carries the user
// name, and is followed by the password -- is not sent to it.
func TestADatabaseThatAnswersTheSSLRequestWithNonsenseIsNotTalkedTo(t *testing.T) {
	ca, _ := serverCert(t, "db.test")
	fake := startFake(t, &fakeServer{sslAnswer: 'Z'})
	_, addr := relayFor(t, "        upstream: pg\n"+
		"        require_tls: false\n"+
		"        default_action: allow\n"+
		"        upstream_tls_mode: require\n"+
		"        upstream_tls: {ca_file: "+ca.Path+", server_name: db.test, min_version: \"1.2\"}\n",
		fake.addr())

	cl := dial(t, addr, "user", "alice")
	if e := cl.waitReady(t); e == "" {
		t.Error("the client was told the session was ready")
	}
	if ss := fake.sawStartups(); len(ss) != 0 {
		t.Errorf("the startup reached the server anyway: %+v", ss)
	}
}

// TestAMessageThisRelayCannotReadEndsTheSession: a declared length that does
// not match the contents. Forwarding it would hand the server a message this
// relay read differently from the way the server will -- which is a policy
// that decided about a statement other than the one that runs.
func TestAMessageThisRelayCannotReadEndsTheSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		// A statement with no terminator: the string runs off the end.
		{"a query that does not end", frame(wire.MsgQuery, []byte("select 1"))},
		// A Parse declaring two parameter types and carrying none.
		{"a parse that lies about its parameters", frame(wire.MsgParse,
			append([]byte("st\x00select $1, $2\x00"), 0, 2))},
		// A Bind with nothing after the portal name.
		{"a bind with nothing in it", frame(wire.MsgBind, []byte("p\x00"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := startFake(t, &fakeServer{})
			s, addr := relayFor(t, base, fake.addr())
			cl := dial(t, addr, "user", "alice")
			if e := cl.waitReady(t); e != "" {
				t.Fatalf("the session: %s", e)
			}
			if _, err := cl.c.Write(tc.raw); err != nil {
				t.Fatal(err)
			}
			waitRefused(t, s, "unreadable_message")
			for _, st := range fake.got() {
				if st != "" {
					t.Errorf("the server was sent %q", st)
				}
			}
		})
	}
}

// TestTheFastPathFunctionInterfaceIsRefused: the legacy fast-path call names a
// function by object identifier and takes its arguments as raw octets, so
// there is no statement for a policy to read -- it is a way to call anything
// the role can call without saying so in SQL. Off unless an operator turned it
// on, and refused whatever the enforcement mode, because by the time it is on
// the wire there is nothing left to inspect.
func TestTheFastPathFunctionInterfaceIsRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := relayFor(t, base+"      policy: {mode: shadow}\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("the session: %s", e)
	}
	// Function 2345 with no arguments: enough to be the message, and the
	// relay refuses it on what it is rather than on what it says.
	body := binary.BigEndian.AppendUint32(nil, 2345)
	body = append(body, 0, 0, 0, 0)
	if _, err := cl.c.Write(frame(wire.MsgFunctionCall, body)); err != nil {
		t.Fatal(err)
	}
	waitRefused(t, s, "function_call")
	for _, st := range fake.got() {
		if st != "" {
			t.Errorf("the server was sent %q", st)
		}
	}
}

// TestAStartupThisRelayCannotReadIsRefused: the first four octets after the
// length are a code, and a code this relay does not know is not something to
// guess about -- a client that is not a PostgreSQL client gets nothing.
func TestAStartupThisRelayCannotReadIsRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s, addr := relayFor(t, base, fake.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	// A protocol version nothing speaks: not 3.0, not one of the three
	// request codes.
	if _, err := c.Write(prelude(0x00070000)); err != nil {
		t.Fatal(err)
	}
	waitRefused(t, s, "unreadable_startup")
	if ss := fake.sawStartups(); len(ss) != 0 {
		t.Errorf("it reached the server: %+v", ss)
	}
}
