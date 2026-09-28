package opcua

import (
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/opcua"
)

// The channel, which is where most of this listener's value is.
//
// The policy and the mode are in the clear by construction, so these decisions hold
// on every channel whatever it then does to its bodies — and they are the decisions
// that exclude most of what goes wrong.

func TestASecurityPolicyTheListenerDoesNotNameIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, "        upstream: servers\n"+
		"        default_action: allow\n"+
		"        require_client_certificate: false\n"+
		"        security_policies: [Aes256_Sha256_RsaPss]\n"+services, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")

	ch := cl.channel(wire.PolicyBasic256Sha256, wire.ModeSignAndEncrypt)
	if ch.Type != wire.Error {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	until(t, s, refused("security_policy_not_allowed"), "the refusal")
	if up.sawService(wire.SvcOpenChannel) {
		t.Errorf("the server saw the channel: %v", up.seen())
	}
}

// A withdrawn policy is refused for its own reason, so the log says what is wrong
// with it rather than only that it was not named.
func TestADeprecatedSecurityPolicyIsRefusedForBeingDeprecated(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, "        upstream: servers\n"+
		"        default_action: allow\n"+services, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")

	if ch := cl.channel(wire.PolicyBasic256, wire.ModeSign); ch.Type != wire.Error {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	until(t, s, refused("security_policy_deprecated"), "the refusal")
	if up.sawService(wire.SvcOpenChannel) {
		t.Errorf("the server saw the channel: %v", up.seen())
	}
}

// And carried where the knob says so, because one old client is why it is switched
// on and the estate decided that.
func TestADeprecatedPolicyIsCarriedWhenTheKnobSaysSo(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, "        upstream: servers\n"+
		"        default_action: allow\n"+
		"        allow_deprecated_policies: true\n"+
		"        security_policies: [Basic256, Basic256Sha256]\n"+services, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	if ch := cl.channel(wire.PolicyBasic256, wire.ModeSign); ch.Type != wire.Message {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	up.await(t, 1, "the channel")
}

// Mode none is refused by default, which is the difference between a channel with a
// strong cipher suite and a channel that encrypts nothing.
func TestModeNoneIsRefusedByDefault(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, "        upstream: servers\n"+
		"        default_action: allow\n"+
		"        security_policies: [None, Basic256Sha256]\n"+services, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")

	if ch := cl.channel(wire.PolicyBasic256Sha256, wire.ModeNone); ch.Type != wire.Error {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	until(t, s, refused("security_mode_not_allowed"), "the refusal")
}

// require_readable_bodies refuses sign_and_encrypt, which is the honest outcome for
// a listener whose service rules must apply: the alternative is carrying a channel
// while enforcing none of what it was configured to enforce.
func TestRequireReadableBodiesRefusesAnEncryptedChannel(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        require_readable_bodies: true\n", up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")

	if ch := cl.channel(wire.PolicyBasic256Sha256, wire.ModeSignAndEncrypt); ch.Type != wire.Error {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	until(t, s, refused("body_not_readable"), "the refusal")
	// And mode sign is carried, which is the trade the knob makes: every message
	// still authenticated, and the body readable.
	cl2 := dial(t, addr)
	cl2.handshake("opc.tcp://127.0.0.1:4840")
	if ch := cl2.channel(wire.PolicyBasic256Sha256, wire.ModeSign); ch.Type != wire.Message {
		t.Fatalf("mode sign answered %s", ch.Type)
	}
}

// A token lifetime past the bound is refused: a client asking for a very long one is
// asking not to rotate its keys.
func TestATokenLifetimePastTheBoundIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        max_token_lifetime: 1h\n", up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")

	cl.send(openChannel(wire.PolicyBasic256Sha256, wire.ModeSign, 24*3600*1000))
	if ch, err := cl.next(); err != nil || ch.Type != wire.Error {
		t.Fatalf("the relay answered %v %v", ch, err)
	}
	until(t, s, refused("token_lifetime"), "the refusal")
}

// An encrypted body is carried and counted, and the service rules do not see it.
// That is a property of the channel rather than a gap, and the counter is how an
// operator finds out it is happening.
func TestAnEncryptedBodyIsCarriedAndCounted(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        nodes: [\"ns=3;i=1001\"]\n", up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSignAndEncrypt)

	// A Read of a node the policy does not name. Over this channel the relay
	// cannot see the node, so the message goes through — which is exactly what
	// the warning at load says will happen.
	if ch := cl.service(wire.SvcRead, readBody(op(n(9, 99), wire.AttrValue))); ch.Type != wire.Message {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	up.await(t, 2, "the channel and the read")
	if got := s.Stats().OPCUAOpaque; got == 0 {
		t.Error("the opaque body was not counted")
	}
}

// The identity: the application and then the user.

func TestAnApplicationTheListenerDoesNotNameIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        application_uris: [\"urn:scada:*\"]\n", up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)

	ch := cl.service(wire.SvcCreateSession,
		createSessionBody("urn:laptop:tool", "session-1", nil))
	if ch.Type != wire.Message {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	if svc := serviceOfAnswer(t, ch); svc != wire.SvcFault {
		t.Errorf("the answer was %s, want a service fault", svc)
	}
	until(t, s, refused("application_not_allowed"), "the refusal")
	if up.sawService(wire.SvcCreateSession) {
		t.Errorf("the server saw the session: %v", up.seen())
	}
}

// A session with no certificate is refused by default: a session with no
// certificate has no application identity, whatever user it then activates as.
func TestASessionWithNoCertificateIsRefusedByDefault(t *testing.T) {
	up := startServer(t, &fakeServer{})
	// Not `base`, which turns the certificate rules off so that the other tests
	// are about something else. This one is about the default.
	s, addr := relayFor(t, "        upstream: servers\n"+
		"        default_action: allow\n"+
		"        security_policies: [Basic256Sha256]\n"+services, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)

	cl.service(wire.SvcCreateSession, createSessionBody("urn:scada:client", "s", nil))
	until(t, s, refused("no_client_certificate"), "the refusal")
	if up.sawService(wire.SvcCreateSession) {
		t.Errorf("the server saw the session: %v", up.seen())
	}
}

// An anonymous token is refused by default, and named it is carried.
func TestAnAnonymousTokenIsRefusedByDefault(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, "        upstream: servers\n"+
		"        default_action: allow\n"+
		"        security_policies: [Basic256Sha256]\n"+
		"        require_client_certificate: false\n"+services, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:scada:client", "s", nil))

	cl.service(wire.SvcActivateSession, activateBody(wire.TokenAnonymous, "", "", ""))
	until(t, s, refused("token_kind_not_allowed"), "the refusal")
	if up.sawService(wire.SvcActivateSession) {
		t.Errorf("the server saw the activation: %v", up.seen())
	}
}

// A plaintext password is refused by default. Under mode none it is on the wire as
// the operator typed it; under sign it is readable by anything on the path, this
// relay included — which is why the default does not depend on the mode.
func TestAPlaintextPasswordIsRefusedByDefault(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:scada:client", "s", nil))

	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "operator", "hunter2", ""))
	until(t, s, refused("plaintext_password"), "the refusal")
	if up.sawService(wire.SvcActivateSession) {
		t.Errorf("the server saw the activation: %v", up.seen())
	}
}

// An encrypted one is carried, and the user list then decides.
func TestAUserTheListenerDoesNotNameIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        users: [operator, engineer]\n", up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:scada:client", "s", nil))

	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "contractor", "secret", rsaOaep))
	until(t, s, refused("user_not_allowed"), "the refusal")
	if up.sawService(wire.SvcActivateSession) {
		t.Errorf("the server saw the activation: %v", up.seen())
	}

	// And a named user is carried.
	cl2 := dial(t, addr)
	cl2.handshake("opc.tcp://127.0.0.1:4840")
	cl2.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl2.service(wire.SvcCreateSession, createSessionBody("urn:scada:client", "s", nil))
	cl2.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "operator", "secret", rsaOaep))
	up.await(t, 4, "the second session's activation")
	if !up.sawService(wire.SvcActivateSession) {
		t.Errorf("the server did not see the activation: %v", up.seen())
	}
	if got := s.Stats().OPCUASessions; got == 0 {
		t.Error("the activation was not counted")
	}
}

// The service level: what may be called, on which nodes, on which attributes.

func TestAServiceTheListenerDoesNotNameIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, baseServices+
		"        services: [open_secure_channel, read, browse]\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcWrite, writeBody(wr(n(3, 1001), wire.AttrValue, 72.5)))
	until(t, s, refused("service_not_allowed"), "the refusal")
	if up.sawService(wire.SvcWrite) {
		t.Errorf("the server saw the write: %v", up.seen())
	}
	// And a named one reaches the server.
	cl.service(wire.SvcRead, readBody(op(n(3, 1001), wire.AttrValue)))
	up.await(t, 2, "the read")
	if !up.sawService(wire.SvcRead) {
		t.Errorf("the server did not see the read: %v", up.seen())
	}
}

// read_only refuses every service that changes anything, and no rule can override
// it.
func TestReadOnlyRefusesAWriteEvenWithARuleAllowingIt(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        read_only: true\n"+
		"        rules:\n"+
		"          - name: engineers\n"+
		"            action: allow\n"+
		"            services: [write, call]\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcWrite, writeBody(wr(n(3, 1001), wire.AttrValue, 72.5)))
	until(t, s, refused("read_only"), "the refusal")
	if up.sawService(wire.SvcWrite) {
		t.Errorf("the server saw the write: %v", up.seen())
	}
	// A Call is control and is refused too.
	cl.service(wire.SvcCall, callBody(n(4, 100), n(4, 200), 1))
	if up.sawService(wire.SvcCall) {
		t.Errorf("the server saw the call: %v", up.seen())
	}
	// And a subscription is *not* on that list, because a read-only listener no
	// HMI can subscribe through is a listener no HMI can use.
	cl.service(wire.SvcCreateSubscription, subscriptionBody(1000))
	up.await(t, 2, "the subscription")
	if !up.sawService(wire.SvcCreateSubscription) {
		t.Errorf("the server did not see the subscription: %v", up.seen())
	}
}

func TestANodeTheListenerDoesNotNameIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        nodes: [\"ns=3;i=*\", \"ns=4;s=Motor/*\"]\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcRead, readBody(op(n(9, 1), wire.AttrValue)))
	until(t, s, refused("node_not_allowed"), "the refusal")
	if up.sawService(wire.SvcRead) {
		t.Errorf("the server saw the read: %v", up.seen())
	}
	// Both patterns match what they should.
	cl.service(wire.SvcRead, readBody(op(n(3, 1001), wire.AttrValue)))
	cl.service(wire.SvcRead, readBody(op("ns=4;s=Motor/Speed", wire.AttrValue)))
	up.await(t, 3, "the two allowed reads")
}

// A node identifier with brackets in it is an ordinary one, and a pattern naming it
// has to match: path.Match reads "[" as a character class, so a relay that did not
// make them literal would have a rule that silently matched nothing.
func TestANodeIdentifierWithBracketsMatchesItsPattern(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+
		"        nodes: [\"ns=4;s=Tank[1]/Level\"]\n", up.addr())
	cl := session(t, addr)
	cl.service(wire.SvcRead, readBody(op("ns=4;s=Tank[1]/Level", wire.AttrValue)))
	up.await(t, 2, "the read of the bracketed node")
	if !up.sawService(wire.SvcRead) {
		t.Errorf("the server did not see the read: %v", up.seen())
	}
}

// write_nodes narrows the writes without narrowing the reads, which is how "read the
// whole plant, write two setpoints" is written.
func TestWriteNodesNarrowTheWritesAndNotTheReads(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        nodes: [\"ns=3;i=*\"]\n"+
		"        write_nodes: [\"ns=3;i=2000\"]\n", up.addr())
	cl := session(t, addr)

	// A read of a node outside write_nodes is allowed.
	cl.service(wire.SvcRead, readBody(op(n(3, 1001), wire.AttrValue)))
	up.await(t, 2, "the read")
	// A write of the same node is not.
	cl.service(wire.SvcWrite, writeBody(wr(n(3, 1001), wire.AttrValue, 1)))
	until(t, s, refused("node_not_allowed"), "the refusal")
	if up.sawService(wire.SvcWrite) {
		t.Errorf("the server saw the write: %v", up.seen())
	}
	// And the one node write_nodes names is written.
	cl.service(wire.SvcWrite, writeBody(wr(n(3, 2000), wire.AttrValue, 1)))
	up.await(t, 3, "the allowed write")
	if !up.sawService(wire.SvcWrite) {
		t.Errorf("the server did not see the allowed write: %v", up.seen())
	}
}

// The attribute is the line between moving an actuator and changing who may move it,
// and both arrive as an ordinary Write.
func TestAWriteToAPermissionAttributeIsRefusedByDefault(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        nodes: [\"ns=3;i=*\"]\n", up.addr())
	cl := session(t, addr)

	// The value is written.
	cl.service(wire.SvcWrite, writeBody(wr(n(3, 1001), wire.AttrValue, 72.5)))
	up.await(t, 2, "the value write")
	// The access level is not, and the refusal says what it was rather than only
	// that an attribute was not allowed.
	cl.service(wire.SvcWrite, writeBody(wr(n(3, 1001), wire.AttrAccessLevel, 3)))
	until(t, s, refused("permission_write"), "the refusal")
	if got := countOf(up, wire.SvcWrite); got != 1 {
		t.Errorf("the server saw %d writes, want 1", got)
	}
}

// A method names two nodes and both are checked: allowing Reset on one pump is not
// allowing it on every pump of that model.
func TestAMethodIsCheckedSeparatelyFromItsObject(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        nodes: [\"ns=4;i=*\"]\n"+
		"        methods: [\"ns=4;i=200\"]\n", up.addr())
	cl := session(t, addr)

	// The allowed method on an allowed object.
	cl.service(wire.SvcCall, callBody(n(4, 100), n(4, 200), 1))
	up.await(t, 2, "the allowed call")
	// A different method on the same object.
	cl.service(wire.SvcCall, callBody(n(4, 100), n(4, 999), 1))
	until(t, s, refused("method_not_allowed"), "the refusal")
	if got := countOf(up, wire.SvcCall); got != 1 {
		t.Errorf("the server saw %d calls, want 1", got)
	}
}

// The deny lists win over a rule that allows.
func TestADenyListIsNotOverriddenByARule(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        deny_nodes: [\"ns=4;s=Safety/*\"]\n"+
		"        rules:\n"+
		"          - name: everything\n"+
		"            action: allow\n"+
		"            nodes: [\"ns=4;s=*\"]\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcRead, readBody(op("ns=4;s=Safety/Interlock", wire.AttrValue)))
	until(t, s, refused("node_denied"), "the refusal")
	if up.sawService(wire.SvcRead) {
		t.Errorf("the server saw the read: %v", up.seen())
	}
}

// The bounds.

func TestTooManyOperationsInOneRequestIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        max_operations: 4\n", up.addr())
	cl := session(t, addr)

	ops := make([][2]any, 0, 5)
	for i := 0; i < 5; i++ {
		ops = append(ops, op(n(3, uint32(1000+i)), wire.AttrValue))
	}
	cl.service(wire.SvcRead, readBody(ops...))
	until(t, s, refused("too_many_operations"), "the refusal")
	if up.sawService(wire.SvcRead) {
		t.Errorf("the server saw the read: %v", up.seen())
	}
	// Four is inside the bound.
	cl.service(wire.SvcRead, readBody(ops[:4]...))
	up.await(t, 2, "the read inside the bound")
}

// A publishing interval under the bound is refused, which is the bound that matters
// most on this protocol: the amplification is arithmetic rather than accidental.
func TestAPublishingIntervalUnderTheBoundIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        min_publishing_interval: 200ms\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcCreateSubscription, subscriptionBody(1))
	until(t, s, refused("publishing_interval"), "the refusal")
	if up.sawService(wire.SvcCreateSubscription) {
		t.Errorf("the server saw the subscription: %v", up.seen())
	}
	// Zero means "as fast as the server can", which is faster than any bound, so
	// it is refused wherever a bound exists rather than read as unset.
	cl.service(wire.SvcCreateSubscription, subscriptionBody(0))
	if up.sawService(wire.SvcCreateSubscription) {
		t.Errorf("a zero interval reached the server: %v", up.seen())
	}
	// And one inside the bound is carried.
	cl.service(wire.SvcCreateSubscription, subscriptionBody(1000))
	up.await(t, 2, "the subscription inside the bound")
}

func TestTooManyMonitoredItemsIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        max_monitored_items: 2\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcCreateMonitored, monitoredBody(1000, n(3, 1), n(3, 2), n(3, 3)))
	until(t, s, refused("too_many_monitored_items"), "the refusal")
	if up.sawService(wire.SvcCreateMonitored) {
		t.Errorf("the server saw the items: %v", up.seen())
	}
}

func TestASamplingIntervalUnderTheBoundIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        min_sampling_interval: 100ms\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcCreateMonitored, monitoredBody(10, n(3, 1)))
	until(t, s, refused("sampling_interval"), "the refusal")
	// Minus one means the subscription's own publishing interval, which is
	// already bounded, so it is not refused here.
	cl.service(wire.SvcCreateMonitored, monitoredBody(-1, n(3, 1)))
	up.await(t, 2, "the item taking the subscription's interval")
}

// The rules.

func TestARuleSelectsOnTheUserAndDecidesForIt(t *testing.T) {
	up := startServer(t, &fakeServer{})
	const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
	s, addr := relayFor(t, baseDefault+
		"        default_action: deny\n"+
		"        rules:\n"+
		"          - name: handshake\n"+
		"            action: allow\n"+
		"            services: [open_secure_channel, create_session, activate_session]\n"+
		"          - name: engineer-writes\n"+
		"            action: allow\n"+
		"            users: [engineer]\n"+
		"            services: [write]\n"+
		"            comment: change window only\n"+
		"          - name: everyone-reads\n"+
		"            action: allow\n"+
		"            services: [read]\n", up.addr())

	// An operator may read and not write.
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcCreateSession, createSessionBody("urn:scada:client", "s", nil))
	cl.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "operator", "p", rsaOaep))
	cl.service(wire.SvcRead, readBody(op(n(3, 1), wire.AttrValue)))
	up.await(t, 4, "the operator's read")
	cl.service(wire.SvcWrite, writeBody(wr(n(3, 1), wire.AttrValue, 1)))
	until(t, s, refused("no_rule"), "the operator's write")
	if up.sawService(wire.SvcWrite) {
		t.Errorf("the operator's write reached the server: %v", up.seen())
	}

	// An engineer may write.
	cl2 := dial(t, addr)
	cl2.handshake("opc.tcp://127.0.0.1:4840")
	cl2.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl2.service(wire.SvcCreateSession, createSessionBody("urn:scada:client", "s", nil))
	cl2.service(wire.SvcActivateSession,
		activateBody(wire.TokenUserName, "engineer", "p", rsaOaep))
	cl2.service(wire.SvcWrite, writeBody(wr(n(3, 1), wire.AttrValue, 1)))
	up.await(t, 8, "the engineer's write")
	if !up.sawService(wire.SvcWrite) {
		t.Errorf("the engineer's write did not reach the server: %v", up.seen())
	}
}

// A rule naming a user does not match a session that has not activated one, because
// before ActivateSession there is no user to name.
func TestARuleAboutUsersDoesNotMatchABareChannel(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, baseDefault+
		"        default_action: deny\n"+
		"        rules:\n"+
		"          - name: anyone-with-a-user\n"+
		"            action: allow\n"+
		"            users: [\"*\"]\n"+
		"            services: [read]\n"+
		"          - name: handshake\n"+
		"            action: allow\n"+
		"            services: [open_secure_channel]\n", up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)

	// A Read before any session exists. The user rule cannot match it.
	cl.service(wire.SvcRead, readBody(op(n(3, 1), wire.AttrValue)))
	until(t, s, refused("no_rule"), "the refusal")
	if up.sawService(wire.SvcRead) {
		t.Errorf("the server saw the read: %v", up.seen())
	}
}

// A rule selecting on the mode is how "this client may write, but only over an
// encrypted channel" is written.
func TestARuleSelectsOnTheSecurityMode(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, baseDefault+
		"        default_action: deny\n"+
		"        rules:\n"+
		"          - name: encrypted-writes\n"+
		"            action: allow\n"+
		"            security_modes: [sign_and_encrypt]\n"+
		"            services: [write]\n"+
		"          - name: everything-else\n"+
		"            action: allow\n"+
		"            services: [open_secure_channel, read]\n", up.addr())

	// Over mode sign the write matches no rule.
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)
	cl.service(wire.SvcWrite, writeBody(wr(n(3, 1), wire.AttrValue, 1)))
	until(t, s, refused("no_rule"), "the refusal")
	if up.sawService(wire.SvcWrite) {
		t.Errorf("the server saw the write: %v", up.seen())
	}
}

// Shadow mode records and forwards, except for the hard decisions.
func TestShadowModeRecordsAndForwards(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        nodes: [\"ns=3;i=*\"]\n"+
		"        monitor_only: true\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcRead, readBody(op(n(9, 1), wire.AttrValue)))
	until(t, s, wouldRefuse("node_not_allowed"), "the would-be refusal")
	up.await(t, 2, "the forwarded read")
	if !up.sawService(wire.SvcRead) {
		t.Errorf("a shadow listener did not forward the read: %v", up.seen())
	}
	if got := s.Stats().Refusals["opcua"]["node_not_allowed"]; got != 0 {
		t.Errorf("a shadow listener counted %d real refusals", got)
	}
}

// A hard decision is enforced even in monitor mode, because a message the relay
// could not read is not an opinion.
func TestAHardRefusalStandsInMonitorMode(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        monitor_only: true\n", up.addr())
	cl := dial(t, addr)

	cl.send(build().u32(0).chunk(wire.Message, wire.Final))
	if ch, err := cl.next(); err == nil && ch.Type != wire.Error {
		t.Fatalf("a monitor-mode listener answered %s", ch.Type)
	}
	until(t, s, refused("no_hello"), "the refusal")
	if len(up.seen()) != 0 {
		t.Errorf("the server was reached: %v", up.seen())
	}
}

// The server's own refusal is read and reported: it is where the two policies
// disagree, and on this protocol it usually means a user the server does not grant
// what the listener does.
func TestTheServersOwnRefusalIsReported(t *testing.T) {
	up := startServer(t, &fakeServer{fault: wire.StatusBadUserAccessDenied})
	s, addr := relayFor(t, base, up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcRead, readBody(op(n(3, 1), wire.AttrValue)))
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().OPCUAServerFaults > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the server's fault was not counted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An ERR from the server is carried and counted: it is the one place a server's own
// words reach this relay's log.
func TestAnErrorFromTheServerIsCounted(t *testing.T) {
	up := startServer(t, &fakeServer{errorAfterHello: wire.StatusBadTCPEndpointURLInvalid})
	s, addr := relayFor(t, base, up.addr())
	cl := dial(t, addr)
	cl.send(hello("opc.tcp://127.0.0.1:4840"))
	ch, err := cl.next()
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if ch.Type != wire.Error {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().OPCUAServerErrors > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the server's error was not counted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A refusal answers with a ServiceFault by default, which is what a server does: the
// client's library reports the refusal against the handle it sent, and the poll loop
// carries on.
func TestARefusalIsAnsweredWithAServiceFaultAndTheSessionCarriesOn(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+"        nodes: [\"ns=3;i=*\"]\n", up.addr())
	cl := session(t, addr)

	ch := cl.service(wire.SvcRead, readBody(op(n(9, 1), wire.AttrValue)))
	if svc := serviceOfAnswer(t, ch); svc != wire.SvcFault {
		t.Fatalf("the answer was %s, want a service fault", svc)
	}
	// And the session is still usable, which is the point of answering rather than
	// closing: a plant connection is a poll loop.
	if ch := cl.service(wire.SvcRead, readBody(op(n(3, 1), wire.AttrValue))); ch.Type != wire.Message {
		t.Fatalf("after the refusal the session answered %s", ch.Type)
	}
	up.await(t, 2, "the allowed read after the refusal")
}

// deny_response: close ends the connection instead, for an estate that would rather
// a refusal be loud.
func TestDenyResponseCloseEndsTheConnection(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+
		"        nodes: [\"ns=3;i=*\"]\n"+
		"        deny_response: close\n", up.addr())
	cl := session(t, addr)

	if _, err := cl.serviceQuiet(wire.SvcRead, readBody(op(n(9, 1), wire.AttrValue))); err == nil {
		t.Error("the connection was not closed")
	} else if !connEnded(err) {
		t.Errorf("the connection ended with %v", err)
	}
}

// session opens a connection, a channel and gets as far as a service call, which is
// what most of the tests above need before they say anything.
func session(t *testing.T, addr string) *client {
	t.Helper()
	cl := dial(t, addr)
	if ch := cl.handshake("opc.tcp://127.0.0.1:4840"); ch.Type != wire.Acknowledge {
		t.Fatalf("the handshake answered %s", ch.Type)
	}
	if ch := cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign); ch.Type != wire.Message {
		t.Fatalf("the channel answered %s", ch.Type)
	}
	return cl
}

// serviceOfAnswer reads the service out of a MSG chunk the relay sent back, which is
// how "the client was told" is asserted.
func serviceOfAnswer(t *testing.T, ch *wire.Chunk) wire.Service {
	t.Helper()
	if ch.Type != wire.Message {
		t.Fatalf("the answer was %s rather than a message", ch.Type)
	}
	_, off, err := wire.ParseSymmetric(ch.Body)
	if err != nil {
		t.Fatal(err)
	}
	_, off, err = wire.ParseSequence(ch.Raw, off)
	if err != nil {
		t.Fatal(err)
	}
	call, err := wire.ParseCall(ch.Raw[off:], false)
	if err != nil {
		t.Fatal(err)
	}
	return call.Service
}

// countOf is how many of one service reached the server, which is what separates
// "the second write was refused" from "no write ever arrived".
func countOf(up *fakeServer, svc wire.Service) int {
	n := 0
	for _, got := range up.seen() {
		if got == svc {
			n++
		}
	}
	return n
}

// A Browse is a read, and it is the read that turns "I can reach this server" into
// "I know everything on it". So the node lists apply to where a browse starts, which
// is what bounds enumeration.
func TestABrowseIsBoundedByTheNodeList(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        nodes: [\"ns=3;i=*\"]\n", up.addr())
	cl := session(t, addr)

	// The Objects folder, ns=0;i=85, is where every scanner starts.
	cl.service(wire.SvcBrowse, browseBody(n(0, 85)))
	until(t, s, refused("node_not_allowed"), "the refusal")
	if up.sawService(wire.SvcBrowse) {
		t.Errorf("the server saw the browse: %v", up.seen())
	}
	// And a browse inside the allowed namespace is carried.
	cl.service(wire.SvcBrowse, browseBody(n(3, 1)))
	up.await(t, 2, "the allowed browse")
	if !up.sawService(wire.SvcBrowse) {
		t.Errorf("the server did not see the allowed browse: %v", up.seen())
	}
}

// A namespace URI cannot be named, and that is the protocol's doing: the node a Read
// names is a plain NodeId, which carries an index and no URI. The validator refuses
// the URI form with the reason, which is tested in the config package; here the
// index form is what decides.

// The namespace list decides on the index, which is the only form a request carries.
func TestANamespaceIndexListDecidesOnTheIndex(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        namespaces: [\"3-4\"]\n", up.addr())
	cl := session(t, addr)

	cl.service(wire.SvcRead, readBody(op(n(4, 1), wire.AttrValue)))
	up.await(t, 2, "the read in namespace four")
	cl.service(wire.SvcRead, readBody(op(n(5, 1), wire.AttrValue)))
	until(t, s, refused("namespace_not_allowed"), "the refusal")
	if got := countOf(up, wire.SvcRead); got != 1 {
		t.Errorf("the server saw %d reads, want 1", got)
	}
}

// A message whose service body does not parse ends the connection, because the body
// is what the decision rests on and the octets after it are at a position nothing
// agrees on.
func TestAServiceBodyThatDoesNotParseEndsTheConnection(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	cl := session(t, addr)

	// A Read whose node array claims two nodes and carries one.
	body := build().f64(0).u32(0).array(2).node(3, 1).u32(uint32(wire.AttrValue)).null().u16(0).null()
	ch, err := cl.serviceQuiet(wire.SvcRead, body)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	// An ERR carrying the reason, and then the connection: a client whose log
	// says "connection reset" gives the operator nothing to correlate against
	// this relay's refusal.
	if ch.Type != wire.Error {
		t.Errorf("the relay answered %s", ch.Type)
	}
	if _, err := cl.next(); err == nil {
		t.Error("the connection was not ended after the error")
	}
	until(t, s, refused("unreadable_service"), "the refusal")
	if up.sawService(wire.SvcRead) {
		t.Errorf("the server saw the read: %v", up.seen())
	}
}

// A service this relay does not classify is refused, because a service with no name
// is a service with no policy.
func TestAServiceTheRelayCannotNameIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	cl := session(t, addr)

	if _, err := cl.serviceQuiet(wire.Service(31337), nil); err == nil {
		t.Log("the relay answered rather than closing, which the response policy allows")
	}
	until(t, s, refused("service_unknown"), "the refusal")
	if len(up.seen()) > 1 {
		t.Errorf("the server saw %v", up.seen())
	}
}

// Too many requests on one connection ends it, for a client that is not a plant
// client.
func TestTooManyRequestsEndsTheConnection(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        max_requests: 2\n", up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")
	cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign)

	// The channel was the first request; the second is a read; the third is past
	// the bound.
	cl.service(wire.SvcRead, readBody(op(n(3, 1), wire.AttrValue)))
	ch, err := cl.serviceQuiet(wire.SvcRead, readBody(op(n(3, 1), wire.AttrValue)))
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if ch.Type != wire.Error {
		t.Errorf("the relay answered %s", ch.Type)
	}
	if _, err := cl.next(); err == nil {
		t.Error("the connection was not ended after the error")
	}
	until(t, s, refused("too_many_requests"), "the refusal")
}

// A second Hello on an established connection is refused: the sizes are already
// negotiated, so this is either a peer that lost track of its own state or one
// renegotiating them underneath the relay's bounds.
func TestASecondHelloIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")

	cl.send(hello("opc.tcp://127.0.0.1:4840"))
	if ch, err := cl.next(); err == nil && ch.Type != wire.Error {
		t.Errorf("the relay answered %s", ch.Type)
	}
	until(t, s, refused("unexpected_message"), "the refusal")
	_ = up
}

// A server's own message arriving from the client's side is refused: the server
// answers, and a client that answers is not a client.
func TestAServerMessageFromTheClientIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	cl := dial(t, addr)
	cl.handshake("opc.tcp://127.0.0.1:4840")

	cl.send(ack())
	if ch, err := cl.next(); err == nil && ch.Type != wire.Error {
		t.Errorf("the relay answered %s", ch.Type)
	}
	until(t, s, refused("unexpected_message"), "the refusal")
	_ = up
}
