package opcua

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/opcua"
)

// The policy on its own, at each of the four layers it decides at: the
// connection, the channel, the session and the service call.
//
// The end-to-end tests next door drive encoded chunks through the relay, which
// is what proves the reader and the policy agree. What a unit test reaches
// cheaply is the shape of each decision -- which refusals are hard, which status
// code a client's own library will report, and the pairs that have to be decided
// together. On this protocol the last of those is the substance: a listener that
// checked only the security policy would admit Basic256Sha256 with mode none,
// which is a strong cipher suite with nothing encrypted.

func compiled(t *testing.T, c *config.OPCUAListener) *policy {
	t.Helper()
	p, err := compile(c, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func host(s string) netip.Addr { return netip.MustParseAddr(s) }

func off() *bool { b := false; return &b }

var at = time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

// sessionAs is a session that reached the end of the handshake with a readable
// channel, which is the state every service decision is made in.
func sessionAs(user string) Session {
	return Session{IP: host("10.0.0.5"), Endpoint: "opc.tcp://plc1:4840/UA/Server",
		Hello: true, Policy: wire.PolicyBasic256Sha256, Mode: wire.ModeSign, Secured: true,
		Channel: 1, Token: 1, ApplicationURI: "urn:hmi:client", SessionName: "hmi",
		HasCert: true, Created: true, User: user, TokenKind: wire.TokenUserName,
		Activated: true, At: at}
}

// node is one operation on a node, as the relay builds one from a parsed id.
func node(ns uint16, id string, attr wire.Attribute, write bool) Operation {
	return Operation{Node: NodeRef{Key: "ns=" + itoa(ns) + ";s=" + id, Namespace: ns},
		Attr: attr, Write: write}
}

func itoa(n uint16) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A body this relay can read is the premise of every service-level rule, and
// which modes leave one is a property of the channel rather than a gap in the
// policy.
func TestAReadableBodyIsAPropertyOfTheChannel(t *testing.T) {
	for _, c := range []struct {
		mode     wire.MessageSecurityMode
		secured  bool
		readable bool
	}{
		{wire.ModeNone, true, true},
		{wire.ModeSign, true, true},
		{wire.ModeSignAndEncrypt, true, false},
		// Before an OpenSecureChannel the mode is invalid rather than none,
		// which is the distinction between "no protection" and "not agreed".
		{wire.ModeInvalid, false, false},
		{wire.ModeSign, false, false},
	} {
		s := sessionAs("op")
		s.Mode, s.Secured = c.mode, c.secured
		if got := s.Readable(); got != c.readable {
			t.Errorf("mode %v secured=%v is readable=%v, want %v",
				c.mode, c.secured, got, c.readable)
		}
	}
}

// The address lists, answered before anything has been read.
func TestTheClientListsDecideBeforeTheHello(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs",
		AllowClients: []string{"10.0.0.0/24"}, DenyClients: []string{"10.0.0.9/32"}})
	for _, c := range []struct {
		addr   string
		allow  bool
		reason string
	}{
		{"10.0.0.5", true, ""},
		{"10.0.0.9", false, "client_denied"},
		{"10.9.9.9", false, "client_not_allowed"},
	} {
		d := p.Connect(Session{IP: host(c.addr)})
		if d.Allow != c.allow {
			t.Errorf("%s decided %+v, want allow=%v", c.addr, d, c.allow)
		}
		if !c.allow && (d.Reason != c.reason || !d.Hard ||
			d.Status != wire.StatusBadSecurityChecksFailed) {
			t.Errorf("%s decided %+v, want a hard %s", c.addr, d, c.reason)
		}
	}
}

// The transport handshake: the sizes, which are checked where refusing costs
// nothing, and the endpoint the client named.
func TestTheHelloIsCheckedForItsSizesAndItsEndpoint(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs",
		Endpoints: []string{"opc.tcp://plc1:4840/UA/*"}})

	ok := &wire.HelloBody{ReceiveBufferSize: 65536, SendBufferSize: 65536,
		MaxMessageSize: 1 << 20, MaxChunkCount: 16,
		EndpointURL: "opc.tcp://plc1:4840/UA/Server"}
	if d := p.Hello(sessionAs("op"), ok); !d.Allow {
		t.Fatalf("an ordinary Hello was refused: %+v", d)
	}
	// A proposal the transport cannot honour is refused hard: the answer to the
	// negotiation is the minimum of the two proposals, so a relay that carried
	// both unchanged would find the ends had agreed on a chunk larger than its
	// own buffer.
	small := *ok
	small.ReceiveBufferSize = 16
	d := p.Hello(sessionAs("op"), &small)
	if d.Allow || d.Reason != "hello_unacceptable" || !d.Hard ||
		d.Status != wire.StatusBadTCPMessageTooLarge {
		t.Fatalf("a Hello under the buffer floor decided %+v", d)
	}
	// An endpoint off the list is a refusal with the status a server would have
	// given, so the client's own library says something true.
	other := *ok
	other.EndpointURL = "opc.tcp://plc9:4840/UA/Server"
	d = p.Hello(sessionAs("op"), &other)
	if d.Allow || d.Reason != "endpoint_not_allowed" ||
		d.Status != wire.StatusBadTCPEndpointURLInvalid {
		t.Fatalf("an endpoint off the list decided %+v", d)
	}
	// A server dialling outward is refused unless the listener asked for it,
	// and then it is measured against the same endpoint list.
	rh := &wire.ReverseHelloBody{ServerURI: "urn:plc1", EndpointURL: ok.EndpointURL}
	d = p.ReverseHello(rh)
	if d.Allow || d.Reason != "reverse_hello" || !d.Hard {
		t.Fatalf("a reverse Hello decided %+v", d)
	}
	rev := compiled(t, &config.OPCUAListener{Upstream: "plcs", AllowReverseHello: true,
		Endpoints: []string{"opc.tcp://plc1:4840/UA/*"}})
	if d := rev.ReverseHello(rh); !d.Allow {
		t.Fatalf("an allowed reverse Hello was refused: %+v", d)
	}
	bad := &wire.ReverseHelloBody{ServerURI: "urn:plc9",
		EndpointURL: "opc.tcp://plc9:4840/UA/Server"}
	if d := rev.ReverseHello(bad); d.Allow || d.Reason != "endpoint_not_allowed" {
		t.Fatalf("a reverse Hello to another endpoint decided %+v", d)
	}
	// And the rendering of a proposal for the log line.
	if got := describeSizes(ok); got != "recv=65536 send=65536 max=1048576 chunks=16" {
		t.Errorf("describeSizes rendered %q", got)
	}
}

// The channel: the policy from the header and the mode from the body, decided
// together because neither is enough on its own.
func TestTheChannelDecidesThePolicyAndTheModeTogether(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs"})
	open := func(mode wire.MessageSecurityMode) *wire.OpenChannelRequest {
		return &wire.OpenChannelRequest{Mode: mode, Lifetime: 600000}
	}
	// The defaults: the current policies, and sign or sign_and_encrypt. Mode
	// none is what a listener has to be told to accept.
	if d := p.Channel(sessionAs("op"), wire.PolicyBasic256Sha256, open(wire.ModeSign)); !d.Allow {
		t.Fatalf("Basic256Sha256 with sign was refused by the defaults: %+v", d)
	}
	for _, c := range []struct {
		name   string
		pol    wire.SecurityPolicy
		mode   wire.MessageSecurityMode
		reason string
		hard   bool
	}{
		{"a policy this build does not name", wire.SecurityPolicy("#Rot13"), wire.ModeSign,
			"security_policy_unknown", true},
		{"a withdrawn SHA-1 policy", wire.PolicyBasic256, wire.ModeSign,
			"security_policy_deprecated", false},
		{"mode none", wire.PolicyBasic256Sha256, wire.ModeNone,
			"security_mode_not_allowed", false},
		{"a mode that is not one", wire.PolicyBasic256Sha256, wire.MessageSecurityMode(9),
			"security_mode_unknown", true},
	} {
		d := p.Channel(sessionAs("op"), c.pol, open(c.mode))
		if d.Allow || d.Reason != c.reason || d.Hard != c.hard {
			t.Errorf("%s decided %+v, want %s hard=%v", c.name, d, c.reason, c.hard)
		}
	}
	// The deprecated policies are named separately from the allow list so the
	// log says what is wrong with them, and a listener may still take them.
	old := compiled(t, &config.OPCUAListener{Upstream: "plcs", AllowDeprecatedPolicies: true,
		SecurityPolicies: []string{"Basic256", "Basic256Sha256"}})
	if d := old.Channel(sessionAs("op"), wire.PolicyBasic256, open(wire.ModeSign)); !d.Allow {
		t.Fatalf("a listener that allows the old policies refused one: %+v", d)
	}
	// A deny list no allow list overrides.
	deny := compiled(t, &config.OPCUAListener{Upstream: "plcs",
		SecurityPolicies:     []string{"Basic256Sha256"},
		DenySecurityPolicies: []string{"Basic256Sha256"}})
	d := deny.Channel(sessionAs("op"), wire.PolicyBasic256Sha256, open(wire.ModeSign))
	if d.Allow || d.Reason != "security_policy_denied" || !d.Hard {
		t.Fatalf("a policy on both lists decided %+v", d)
	}
	// require_readable_bodies is the honest answer to a listener whose service
	// rules would otherwise be inert.
	readable := compiled(t, &config.OPCUAListener{Upstream: "plcs", RequireReadableBodies: true,
		SecurityModes: []string{"none", "sign", "sign_and_encrypt"}})
	d = readable.Channel(sessionAs("op"), wire.PolicyBasic256Sha256, open(wire.ModeSignAndEncrypt))
	if d.Allow || d.Reason != "body_not_readable" {
		t.Fatalf("sign_and_encrypt against require_readable_bodies decided %+v", d)
	}
	// A nonce under policy None is a client that believes it is securing
	// something, which is worth refusing rather than passing.
	none := compiled(t, &config.OPCUAListener{Upstream: "plcs",
		SecurityPolicies: []string{"None"}, SecurityModes: []string{"none"}})
	withNonce := open(wire.ModeNone)
	withNonce.Nonce = []byte("0123456789abcdef")
	d = none.Channel(sessionAs("op"), wire.PolicyNone, withNonce)
	if d.Allow || d.Reason != "nonce_without_policy" || d.Detail != "16 octets" {
		t.Fatalf("a nonce under policy None decided %+v", d)
	}
	// And the token lifetime, which is how long the key material stands.
	short := compiled(t, &config.OPCUAListener{Upstream: "plcs",
		MaxTokenLifetime: config.Duration(10 * time.Minute)})
	long := open(wire.ModeSign)
	long.Lifetime = 3600000
	d = short.Channel(sessionAs("op"), wire.PolicyBasic256Sha256, long)
	if d.Allow || d.Reason != "token_lifetime" ||
		!strings.Contains(d.Detail, "past 10m0s") {
		t.Fatalf("a channel asking for an hour of key material decided %+v", d)
	}
}

// The session: the application on the other end, and then the user.
func TestTheSessionIsDecidedOnTheApplicationAndThenTheUser(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs",
		ApplicationURIs: []string{"urn:hmi:*", "urn:scada:1"},
		Users:           []string{"op*", "engineer"}, DenyUsers: []string{"op-test"}})

	create := func(uri string, cert []byte, typ uint32) *wire.CreateSessionRequest {
		return &wire.CreateSessionRequest{ApplicationURI: uri, Certificate: cert,
			ApplicationType: typ}
	}
	cert := []byte("a certificate")
	if d := p.CreateSession(sessionAs("op1"), create("urn:hmi:client", cert, 1)); !d.Allow {
		t.Fatalf("an ordinary CreateSession was refused: %+v", d)
	}
	for _, c := range []struct {
		name   string
		req    *wire.CreateSessionRequest
		reason string
	}{
		{"no certificate", create("urn:hmi:client", nil, 1), "no_client_certificate"},
		{"an application off the list", create("urn:laptop", cert, 1), "application_not_allowed"},
		// A CreateSession from something calling itself a server is a peer
		// describing itself as the thing on the other side of this relay.
		{"an application that says it is a server", create("urn:hmi:client", cert, 0),
			"application_type"},
	} {
		d := p.CreateSession(sessionAs("op1"), c.req)
		if d.Allow || d.Reason != c.reason {
			t.Errorf("%s decided %+v, want %s", c.name, d, c.reason)
		}
	}
	// The certificate check: the application URI has to be one the certificate
	// carried, which is the cheapest identity check the protocol has.
	s := sessionAs("op1")
	s.CertURIs = []string{"urn:hmi:other"}
	d := p.CertificateURI(s)
	if d.Allow || d.Reason != "certificate_uri_mismatch" ||
		d.Status != wire.StatusBadCertificateUseNotAllowed {
		t.Fatalf("a certificate naming another application decided %+v", d)
	}
	s.CertURIs = []string{"urn:other", "urn:hmi:client"}
	if d := p.CertificateURI(s); !d.Allow {
		t.Fatalf("a certificate carrying the application URI was refused: %+v", d)
	}
	// With no certificate, or with the check off, there is nothing to compare.
	s.HasCert = false
	if d := p.CertificateURI(s); !d.Allow {
		t.Fatalf("a session with no certificate was refused by the URI check: %+v", d)
	}
	lax := compiled(t, &config.OPCUAListener{Upstream: "plcs", RequireCertificateURI: off()})
	bad := sessionAs("op1")
	bad.CertURIs = []string{"urn:somebody-else"}
	if d := lax.CertificateURI(bad); !d.Allow {
		t.Fatalf("require_certificate_uri: false still compared them: %+v", d)
	}

	// The user, on ActivateSession.
	// A password is kept only as its length and the algorithm it was encrypted
	// with, because a relay that held the value would be a relay whose memory
	// is worth stealing.
	activate := func(kind wire.TokenKind, user, alg string) *wire.ActivateSessionRequest {
		a := &wire.ActivateSessionRequest{Kind: kind, User: user, PolicyID: "policy",
			PasswordAlgorithm: alg}
		if kind == wire.TokenUserName {
			a.PasswordLen = 12
		}
		return a
	}
	if d := p.ActivateSession(sessionAs("op1"),
		activate(wire.TokenUserName, "op1", "rsa-oaep")); !d.Allow {
		t.Fatalf("an ordinary ActivateSession was refused: %+v", d)
	}
	for _, c := range []struct {
		name   string
		req    *wire.ActivateSessionRequest
		reason string
		hard   bool
	}{
		{"a token kind this build does not name", activate(wire.TokenKind(999), "", ""),
			"token_kind_unknown", true},
		{"an anonymous token where the list names three", activate(wire.TokenAnonymous, "", ""),
			"token_kind_not_allowed", false},
		// Under mode none this password is on the wire as typed; under sign it
		// is readable by anything on the path, this relay included.
		{"a password with no encryption algorithm", activate(wire.TokenUserName, "op1", ""),
			"plaintext_password", false},
		{"a denied user", activate(wire.TokenUserName, "op-test", "rsa-oaep"),
			"user_denied", true},
		{"a user off the list", activate(wire.TokenUserName, "visitor", "rsa-oaep"),
			"user_not_allowed", false},
	} {
		d := p.ActivateSession(sessionAs("op1"), c.req)
		if d.Allow || d.Reason != c.reason || d.Hard != c.hard {
			t.Errorf("%s decided %+v, want %s hard=%v", c.name, d, c.reason, c.hard)
		}
		if d.Status != wire.StatusBadUserAccessDenied {
			t.Errorf("%s answers with status %#x", c.name, d.Status)
		}
	}
	// A username token with no name at all is a client authenticating as
	// nobody, which is not the same as an anonymous token.
	open := compiled(t, &config.OPCUAListener{Upstream: "plcs", RefusePlaintextPasswords: off()})
	d = open.ActivateSession(sessionAs(""), activate(wire.TokenUserName, "", ""))
	if d.Allow || d.Reason != "empty_user" {
		t.Fatalf("a username token with no name decided %+v", d)
	}
}

// The service call: the deny lists and read_only first, which no rule can
// override, and then the lists.
func TestTheServiceOrderIsWhatMakesReadOnlyMeanWhatItSays(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs", ReadOnly: true,
		DenyServices: []string{"call"},
		Rules: []config.OPCUARule{{Name: "engineers", Users: []string{"engineer"},
			Services: []string{"read", "write", "browse", "call"}}}})

	call := func(svc wire.Service) *wire.ServiceCall {
		return &wire.ServiceCall{Service: svc,
			TypeID: wire.NodeId{Namespace: 0, Kind: wire.FourByte, Numeric: uint32(svc)}}
	}
	eng := sessionAs("engineer")
	// A rule that names a service cannot write through read_only, and cannot
	// override a deny list: both are refused for the rule's own user.
	d := p.Request(eng, call(wire.SvcWrite))
	if d.Allow || d.Reason != "read_only" || !d.Hard {
		t.Fatalf("a write on a read-only listener decided %+v", d)
	}
	d = p.Request(eng, call(wire.SvcCall))
	if d.Allow || d.Reason != "service_denied" || !d.Hard {
		t.Fatalf("a denied service decided %+v", d)
	}
	// A service this build has not classified is refused with the identifier
	// from the message, so the refusal can name it.
	unknown := &wire.ServiceCall{Service: wire.Service(9999),
		TypeID: wire.NodeId{Namespace: 3, Kind: wire.FourByte, Numeric: 9999}}
	d = p.Request(eng, unknown)
	if d.Allow || d.Reason != "service_unknown" || !d.Hard ||
		!strings.Contains(d.Detail, "9999") {
		t.Fatalf("an unclassified service decided %+v", d)
	}
	// A read is carried, and names the rule that decided it.
	if d := p.Request(eng, call(wire.SvcRead)); !d.Allow || d.Rule != "engineers" {
		t.Fatalf("a read was refused: %+v", d)
	}
	// On a deny-by-default listener a session no rule selects is refused as
	// that rather than as a service off a list.
	other := sessionAs("visitor")
	d = p.Request(other, call(wire.SvcRead))
	if d.Allow || d.Reason != "no_rule" {
		t.Fatalf("a session no rule selects decided %+v", d)
	}
	// The listener's own service list, and a rule's narrower one.
	lists := compiled(t, &config.OPCUAListener{Upstream: "plcs", DefaultAction: "allow",
		Services: []string{"read", "browse", "write"},
		Rules: []config.OPCUARule{{Name: "readers", Users: []string{"op*"},
			Services: []string{"read", "browse"}, DenyServices: []string{"browse"}}}})
	if d := lists.Request(sessionAs("op1"), call(wire.SvcRead)); !d.Allow {
		t.Fatalf("a read on both lists was refused: %+v", d)
	}
	d = lists.Request(sessionAs("op1"), call(wire.SvcBrowse))
	if d.Allow || d.Reason != "service_denied" || d.Rule != "readers" || !d.Hard {
		t.Fatalf("a service on the rule's deny list decided %+v", d)
	}
	// A service the listener allows and the rule does not name: the rule that
	// names services selects only those, so this one falls to the default.
	d = lists.Request(sessionAs("op1"), call(wire.SvcWrite))
	if !d.Allow || d.Rule != "" {
		t.Fatalf("a service outside the rule's list decided %+v", d)
	}
	// And one the listener's list does not name at all.
	d = lists.Request(sessionAs("op1"), call(wire.SvcCreateSubscription))
	if d.Allow || d.Reason != "service_not_allowed" {
		t.Fatalf("a service off the listener's list decided %+v", d)
	}
}

// The nodes, the attributes and the methods, which is where reading a process
// value parts company with changing who may write it.
func TestTheNodeAndAttributeListsAreReadInOrder(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs", DefaultAction: "allow",
		// The patterns are path.Match, where a `*` does not cross a `/`, so a
		// node identifier's own slashes are segment boundaries and a pattern
		// covering a subtree ends in `/*`.
		Nodes:       []string{"ns=4;s=Tank1/*", "ns=4;s=Pump1/*", "ns=4;s=Pump1"},
		WriteNodes:  []string{"ns=4;s=Pump1/*"},
		DenyNodes:   []string{"ns=4;s=Tank1/Secret"},
		Methods:     []string{"ns=4;s=Pump1/Start"},
		DenyMethods: []string{"ns=4;s=Pump1/Reset"},
		Namespaces:  []string{"4"},
		Attributes:  []string{"value", "browse_name", "display_name", "access_level"}})

	for _, c := range []struct {
		name   string
		op     Operation
		reason string
		hard   bool
	}{
		{"a denied node", node(4, "Tank1/Secret", wire.AttrValue, false),
			"node_denied", true},
		{"a namespace off the list", node(5, "Tank1/Level", wire.AttrValue, false),
			"namespace_not_allowed", false},
		{"a node off the list", node(4, "Valve1/Position", wire.AttrValue, false),
			"node_not_allowed", false},
		// Hard, because the service writes. A read refused by the same list may
		// be shadowed -- monitor_only is for learning what a policy would do --
		// but a write may not: forwarding one so that it could be written down
		// is a moved actuator, which is what the mode's documented contract
		// says it still refuses.
		{"a write outside the write list", node(4, "Tank1/Level", wire.AttrValue, true),
			"node_not_allowed", true},
		{"an attribute off the list", node(4, "Tank1/Level", wire.AttrDataType, false),
			"attribute_not_allowed", false},
		{"an attribute this build does not name", node(4, "Tank1/Level", wire.Attribute(99), false),
			"attribute_unknown", true},
	} {
		svc := wire.SvcRead
		if c.op.Write {
			svc = wire.SvcWrite
		}
		d := p.Operations(sessionAs("op1"), svc, []Operation{c.op})
		if d.Allow || d.Reason != c.reason || d.Hard != c.hard {
			t.Errorf("%s decided %+v, want %s hard=%v", c.name, d, c.reason, c.hard)
		}
	}
	// A write to a permission attribute is named for what it is: a privilege
	// change however ordinary the node looks.
	perm := node(4, "Pump1/Speed", wire.AttrAccessLevel, true)
	d := p.Operations(sessionAs("op1"), wire.SvcWrite, []Operation{perm})
	if d.Allow || d.Reason != "permission_write" {
		t.Fatalf("a write to access_level decided %+v", d)
	}
	// What the lists admit: a read of a listed node, and the one node the
	// write list names.
	if d := p.Operations(sessionAs("op1"), wire.SvcRead,
		[]Operation{node(4, "Tank1/Level", wire.AttrValue, false)}); !d.Allow {
		t.Fatalf("a listed read was refused: %+v", d)
	}
	if d := p.Operations(sessionAs("op1"), wire.SvcWrite,
		[]Operation{node(4, "Pump1/Speed", wire.AttrValue, true)}); !d.Allow {
		t.Fatalf("the one writable node was refused: %+v", d)
	}
	// The method on a Call is checked separately from the object it is on.
	obj := node(4, "Pump1", 0, false)
	start := NodeRef{Key: "ns=4;s=Pump1/Start", Namespace: 4}
	reset := NodeRef{Key: "ns=4;s=Pump1/Reset", Namespace: 4}
	stop := NodeRef{Key: "ns=4;s=Pump1/Stop", Namespace: 4}
	obj.Method = &start
	if d := p.Operations(sessionAs("op1"), wire.SvcCall, []Operation{obj}); !d.Allow {
		t.Fatalf("the one allowed method was refused: %+v", d)
	}
	obj.Method = &reset
	d = p.Operations(sessionAs("op1"), wire.SvcCall, []Operation{obj})
	if d.Allow || d.Reason != "method_denied" || !d.Hard {
		t.Fatalf("a denied method decided %+v", d)
	}
	obj.Method = &stop
	d = p.Operations(sessionAs("op1"), wire.SvcCall, []Operation{obj})
	if d.Allow || d.Reason != "method_not_allowed" {
		t.Fatalf("a method off the list decided %+v", d)
	}
	// An operation with no attribute at all -- which is what a Call is -- is
	// not an attribute decision.
	plain := node(4, "Pump1", 0, false)
	if d := p.Operations(sessionAs("op1"), wire.SvcCall, []Operation{plain}); !d.Allow {
		t.Fatalf("an operation naming no attribute was refused: %+v", d)
	}
	// And RefOf, which is how the relay turns a parsed id into what the lists
	// compare against.
	ref := RefOf(wire.NodeId{Namespace: 4, Kind: wire.String, Text: "Tank1/Level"})
	if ref.Key != "ns=4;s=Tank1/Level" || ref.Namespace != 4 {
		t.Errorf("RefOf produced %+v", ref)
	}
}

// The operation bound, which is part of the same decision as the operations: a
// Read naming ten thousand nodes is one request and ten thousand operations.
func TestTheOperationBoundIsPartOfTheSameDecision(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs", DefaultAction: "allow",
		MaxOperations: 4, MaxWriteOperations: 2,
		Rules: []config.OPCUARule{{Name: "bulk", Users: []string{"loader"}, MaxOperations: 10}}})

	ops := func(n int, write bool) []Operation {
		out := make([]Operation, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, node(4, "Tank1/Level", wire.AttrValue, write))
		}
		return out
	}
	if d := p.Operations(sessionAs("op1"), wire.SvcRead, ops(4, false)); !d.Allow {
		t.Fatalf("a read at the bound was refused: %+v", d)
	}
	d := p.Operations(sessionAs("op1"), wire.SvcRead, ops(5, false))
	if d.Allow || d.Reason != "too_many_operations" || !d.Hard ||
		d.Status != wire.StatusBadTooManyOperations {
		t.Fatalf("a read over the bound decided %+v", d)
	}
	// A write has its own, tighter bound.
	if d := p.Operations(sessionAs("op1"), wire.SvcWrite, ops(3, true)); d.Allow {
		t.Fatalf("a write over the write bound was allowed: %+v", d)
	}
	// And a rule's own bound stands in for both.
	if d := p.Operations(sessionAs("loader"), wire.SvcWrite, ops(8, true)); !d.Allow {
		t.Fatalf("the rule's own bound did not apply: %+v", d)
	}
}

// A rule selects on the session it was written for, and the guards that make a
// rule about users not decide the messages sent before any session existed.
func TestARuleSelectsOnTheSessionItWasWrittenFor(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs", DefaultAction: "allow",
		Rules: []config.OPCUARule{{Name: "narrow", Action: "deny",
			Clients: []string{"10.0.0.0/24"}, ApplicationURIs: []string{"urn:hmi:*"},
			Users: []string{"op*"}, TokenKinds: []string{"username"},
			SecurityPolicies: []string{"Basic256Sha256"}, SecurityModes: []string{"sign"},
			Services: []string{"read"}}}})

	call := &wire.ServiceCall{Service: wire.SvcRead}
	if d := p.Request(sessionAs("op1"), call); d.Allow {
		t.Fatalf("the rule did not cover the session every selector names: %+v", d)
	}
	for _, c := range []struct {
		name string
		edit func(*Session)
	}{
		{"client", func(s *Session) { s.IP = host("10.9.9.9") }},
		{"application URI", func(s *Session) { s.ApplicationURI = "urn:laptop" }},
		{"user", func(s *Session) { s.User = "engineer" }},
		{"token kind", func(s *Session) { s.TokenKind = wire.TokenX509 }},
		{"security policy", func(s *Session) { s.Policy = wire.PolicyAes256Sha256RsaPss }},
		{"security mode", func(s *Session) { s.Mode = wire.ModeSignAndEncrypt }},
		// A rule written about users must not decide about a message sent
		// before any session existed: a `users: ["*"]` rule matches an empty
		// name, so the guard is what keeps it off the handshake.
		{"not activated", func(s *Session) { s.Activated = false }},
		{"not secured", func(s *Session) { s.Secured = false }},
	} {
		s := sessionAs("op1")
		c.edit(&s)
		if d := p.Request(s, call); !d.Allow {
			t.Errorf("the rule still covered a session whose %s does not match: %+v", c.name, d)
		}
	}
	// A rule about one service does not decide another.
	if d := p.Request(sessionAs("op1"), &wire.ServiceCall{Service: wire.SvcBrowse}); !d.Allow {
		t.Errorf("a rule naming read decided a browse: %+v", d)
	}
}

// An observe rule logs and counts and then the search keeps looking.
func TestAnObserveRuleIsReportedAndDecidesNothingHere(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs", DefaultAction: "allow",
		Rules: []config.OPCUARule{
			{Name: "watch-writes", Action: "observe", Comment: "trial", Services: []string{"write"}},
			{Name: "no-writes", Action: "deny", Services: []string{"write"}},
		}})
	call := &wire.ServiceCall{Service: wire.SvcWrite}
	d := p.Request(sessionAs("op1"), call)
	if d.Allow || d.Reason != "rule_denied" || d.Rule != "no-writes" {
		t.Fatalf("the observe rule shadowed the deny rule below it: %+v", d)
	}
	r := p.ObserveRule(sessionAs("op1"), wire.SvcWrite)
	if r == nil || r.Name() != "watch-writes" || r.Comment() != "trial" {
		t.Fatalf("the observe rule reported is %v", r)
	}
	if r := p.ObserveRule(sessionAs("op1"), wire.SvcRead); r != nil {
		t.Fatalf("a read reported the write rule: %v", r.Name())
	}
}

// A rule's schedule, read against the clock the policy was compiled with --
// which is why compile takes one.
func TestARulesScheduleIsReadAgainstThePolicysOwnClock(t *testing.T) {
	cfg := &config.OPCUAListener{Upstream: "plcs", DefaultAction: "allow",
		Rules: []config.OPCUARule{{Name: "office", Action: "deny",
			Schedule: &config.ModbusSchedule{Days: []string{"wed"}, From: "09:00", To: "17:00"}}}}
	call := &wire.ServiceCall{Service: wire.SvcRead}

	// at is a Wednesday noon.
	inside := compiled(t, cfg)
	if d := inside.Request(sessionAs("op1"), call); d.Allow {
		t.Fatalf("the rule did not decide inside its window: %+v", d)
	}
	night, err := compile(cfg, func() time.Time { return at.Add(11 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	if d := night.Request(sessionAs("op1"), call); !d.Allow {
		t.Fatalf("the rule still decided outside its window: %+v", d)
	}
}

// The two bounds on a subscription, where the amplification is arithmetic
// rather than accidental.
func TestTheSubscriptionBoundsAreArithmetic(t *testing.T) {
	p := compiled(t, &config.OPCUAListener{Upstream: "plcs", DefaultAction: "allow",
		MaxSubscriptions: 2, MinPublishingInterval: config.Duration(100 * time.Millisecond),
		MaxMonitoredItems: 3, MinSamplingInterval: config.Duration(50 * time.Millisecond)})

	s := sessionAs("op1")
	if d := p.Subscription(s, &wire.SubscriptionRequest{Interval: 500}); !d.Allow {
		t.Fatalf("an ordinary subscription was refused: %+v", d)
	}
	s.Subscriptions = 2
	d := p.Subscription(s, &wire.SubscriptionRequest{Interval: 500})
	if d.Allow || d.Reason != "too_many_subscriptions" || !d.Hard {
		t.Fatalf("a third subscription decided %+v", d)
	}
	s.Subscriptions = 0
	// Zero means "as fast as the server can", which needs no case of its own:
	// it is under every positive bound.
	for _, interval := range []float64{0, 1, 99} {
		d := p.Subscription(s, &wire.SubscriptionRequest{Interval: interval})
		if d.Allow || d.Reason != "publishing_interval" {
			t.Errorf("an interval of %.0fms decided %+v", interval, d)
		}
	}
	// The monitored items: a count and a sampling interval.
	items := func(sampling ...float64) *wire.MonitoredItemsRequest {
		m := &wire.MonitoredItemsRequest{Subscription: 1}
		for _, s := range sampling {
			m.Items = append(m.Items, wire.MonitoredItem{Sampling: s})
		}
		return m
	}
	if d := p.MonitoredItems(s, items(100, 200, 50)); !d.Allow {
		t.Fatalf("three items at or above the bound were refused: %+v", d)
	}
	d = p.MonitoredItems(s, items(100, 100, 100, 100))
	if d.Allow || d.Reason != "too_many_monitored_items" || !d.Hard {
		t.Fatalf("a fourth item decided %+v", d)
	}
	d = p.MonitoredItems(s, items(100, 10))
	if d.Allow || d.Reason != "sampling_interval" {
		t.Fatalf("an item under the sampling bound decided %+v", d)
	}
	// Minus one means the subscription's own publishing interval, which is
	// already bounded, so it is not measured again here.
	if d := p.MonitoredItems(s, items(-1, -1)); !d.Allow {
		t.Fatalf("items deferring to the publishing interval were refused: %+v", d)
	}
}

// The compile-time refusals, and the glob that every node list is matched with.
func TestCompileRefusesWhatCannotBeAPolicyAndTheGlobsReadBrackets(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*config.OPCUAListener)
		want string
	}{
		{"security_policies", func(m *config.OPCUAListener) {
			m.SecurityPolicies = []string{"Basic512"}
		}, "security_policies:"},
		{"deny_security_policies", func(m *config.OPCUAListener) {
			m.DenySecurityPolicies = []string{"Rot13"}
		}, "deny_security_policies:"},
		{"security_modes", func(m *config.OPCUAListener) {
			m.SecurityModes = []string{"encrypt"}
		}, "security_modes:"},
		{"token_kinds", func(m *config.OPCUAListener) { m.TokenKinds = []string{"kerberos"} },
			"token_kinds:"},
		{"services", func(m *config.OPCUAListener) { m.Services = []string{"teleport"} },
			"services:"},
		{"deny_services", func(m *config.OPCUAListener) { m.DenyServices = []string{"teleport"} },
			"deny_services:"},
		{"namespaces", func(m *config.OPCUAListener) { m.Namespaces = []string{"four"} },
			"namespaces:"},
		{"attributes", func(m *config.OPCUAListener) { m.Attributes = []string{"colour"} },
			"attributes:"},
		{"write_attributes", func(m *config.OPCUAListener) {
			m.WriteAttributes = []string{"colour"}
		}, "write_attributes:"},
		{"a rule's own list", func(m *config.OPCUAListener) {
			m.Rules = []config.OPCUARule{{Name: "r", Services: []string{"teleport"}}}
		}, "rules[0]:"},
		{"a rule's schedule", func(m *config.OPCUAListener) {
			m.Rules = []config.OPCUARule{{Name: "r",
				Schedule: &config.ModbusSchedule{From: "noon"}}}
		}, "rules[0]:"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &config.OPCUAListener{Upstream: "plcs"}
			c.edit(m)
			if _, err := compile(m, nil); err == nil ||
				!strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// An allow list with no entries means everything, and a deny list with
	// none means nothing -- the asymmetry every list in this file relies on.
	if !matchGlob(nil, "ns=4;s=Tank1") {
		t.Error("an empty allow list refused a node")
	}
	if matchedGlob(nil, "ns=4;s=Tank1") {
		t.Error("an empty deny list matched a node")
	}
	// A node identifier with brackets in it is an ordinary one, and the
	// brackets are made literal so that it matches rather than quietly not.
	if !matchGlob([]string{"ns=4;s=Tank[1]/Level"}, "ns=4;s=Tank[1]/Level") {
		t.Error("a bracketed node identifier did not match itself")
	}
	if !matchGlob([]string{"ns=4;s=Tank[1]/*"}, "ns=4;s=Tank[1]/Level") {
		t.Error("a bracketed prefix pattern did not match")
	}
	// And the property every node list in a configuration has to be written
	// for: a `*` does not cross a `/`, so `ns=4;s=Tank*` covers `Tank1` and not
	// `Tank1/Level`.
	if matchGlob([]string{"ns=4;s=Tank*"}, "ns=4;s=Tank1/Level") {
		t.Error("a * crossed a / in a node identifier")
	}
	if !matchGlob([]string{"ns=4;s=Tank*"}, "ns=4;s=Tank1") {
		t.Error("a * did not match inside one segment")
	}
	if matchGlob([]string{"ns=4;s=Tank[1]/*"}, "ns=4;s=Tank2/Level") {
		t.Error("a bracketed pattern matched another node")
	}
	if got := literalBrackets("ns=4;s=Plain"); got != "ns=4;s=Plain" {
		t.Errorf("literalBrackets rewrote a pattern with no brackets: %q", got)
	}
	// And how a refusal is expressed, which defaults to the protocol's own
	// fault rather than a dropped connection.
	if got := compiled(t, &config.OPCUAListener{Upstream: "plcs"}).respondWith(); got != "fault" {
		t.Errorf("deny_response defaulted to %q", got)
	}
	if got := compiled(t, &config.OPCUAListener{Upstream: "plcs",
		DenyResponse: "close"}).respondWith(); got != "close" {
		t.Errorf("deny_response: close compiled to %q", got)
	}
}
