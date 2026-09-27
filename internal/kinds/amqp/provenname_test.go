package amqp

import (
	"fmt"
	"testing"

	wire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/proxytest"
)

// provenYAML is a listener with the estate's authorisation policy over it. The
// section is a sibling of server:, so it needs its own fixture.
//
// Two rules, two actions, and that is the shape this kind needs: the connection
// is the connect action, asked before the SASL exchange has named anybody, so an
// estate covers it with networks; the authenticated session is the session
// action, and that is where a rule about people belongs.
const provenYAML = `
version: 1
server:
  listeners:
    - name: broker
      address: "127.0.0.1:0"
      kind: amqp
      amqp:
        upstream: br
        require_tls: false
        default_action: allow
logging: {access: {enabled: false}}
upstreams:
  - {name: br, endpoints: [{address: %q}]}
authorization:
  rules:
    - {name: staff, allow: true, users: [orders], actions: [session]}
    - {name: door, allow: true, networks: ["127.0.0.0/8"], actions: [connect]}
`

// startOk sends the PLAIN response naming a user, which is the only place a
// 0-9-1 client says who it is.
func (cl *client091) startOk(user string) {
	cl.t.Helper()
	cl.expect("connection.start")
	cl.send(wire.ClassConnection, 11, 0, emptyTable(), sstr("PLAIN"),
		lstr([]byte("\x00"+user+"\x00secret")), sstr("en_US"))
}

// The estate's policy is asked about the name the *broker* accepted.
//
// A 0-9-1 broker that refuses a credential closes the connection instead of
// tuning, so connection.tune is the broker's way of saying the password was
// right -- which this relay already reads, because "has this connection
// authenticated" cannot be answered from the client's side. The same answer
// proves the name, so an allow rule keyed on users here is an authenticated
// grant rather than a filter on a claim, which is not true of the database
// relays.
//
// What it costs is where the refusal lands, and the test says so: the credential
// does reach the broker, because it is what proves the name, and what the
// refusal keeps off the broker is every method after it. The tune frame is never
// forwarded, so the client is never told it has a connection it may not use.
func TestThePolicyIsAskedAboutTheNameTheBrokerAccepted(t *testing.T) {
	b := startBroker(t, &fakeBroker{})
	s := proxytest.Start(t, fmt.Sprintf(provenYAML, b.addr()))
	addr := proxytest.Addr(t, s, "broker")

	// A name no rule covers. The broker tunes, the estate refuses, and the tune is
	// never forwarded -- which is the assertion that matters, because a test that
	// only checked the connection ended could not tell a refusal from a client
	// that simply had nothing more to read.
	cl := dial091(t, addr)
	cl.startOk("intruder")
	for {
		name, _ := cl.next()
		if name == "" {
			break // the connection ended, which is the refusal
		}
		if name == "connection.tune" {
			t.Fatal("the broker's acceptance was forwarded to a client the " +
				"estate refused, so the client believes it has a connection")
		}
	}
	if n := s.Stats().Refusals["amqp"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["amqp"])
	}
	// The start-ok reached the broker -- it had to, it carries the credential --
	// and nothing of this client's followed it.
	if !b.got("connection.start-ok") {
		t.Errorf("the broker never saw the credential that proves the name (saw %v)", b.saw)
	}
	if b.got("connection.tune-ok") {
		t.Errorf("a refused client tuned the connection anyway (saw %v)", b.saw)
	}

	// And the name the policy does allow completes its handshake.
	cl2 := dial091(t, addr)
	cl2.handshake("orders", "/")
	if n := s.Stats().Refusals["amqp"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d after an allowed login, want still 1", n)
	}
}
