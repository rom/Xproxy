package radius

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // the fake server computes the digests the standard specifies
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/radius"
)

// End to end: a client, this relay, and a RADIUS server that signs its
// answers the way a real one does.
//
// The fake server matters more here than on most kinds. Half of what this
// listener does is verify digests, and a test whose server produced wrong
// ones would pass for the wrong reason -- so the server below computes a
// correct Response Authenticator and, when asked, a correct
// Message-Authenticator, and the tests that expect a refusal break one of
// them deliberately.

const theSecret = "s3cret-and-then-some"

const radiusYAML = `
version: 1
server:
  listeners:
    - name: auth
      address: "127.0.0.1:0"
      kind: radius
%[2]s
      radius:
        upstream: servers
        secret_file: %[3]q
%[1]s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %[4]q}]}
`

// secretFile writes a shared secret somewhere only its owner can read,
// which is what the validator requires and what an operator would do.
func secretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "radius.secret")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func relay(t *testing.T, section, extra, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(radiusYAML, section, extra, secretFile(t, theSecret), serverAddr))
	return s, proxytest.Addr(t, s, "auth")
}

// fakeServer answers Access-Requests.
type fakeServer struct {
	pc net.PacketConn
	// reply builds the answer. It is given the parsed request and returns
	// the code and the attributes to send back.
	reply func(*wire.Packet) (wire.Code, [][]byte)
	// signMAC adds a Message-Authenticator to the answer.
	signMAC bool

	mu   sync.Mutex
	seen []*wire.Packet
}

func startServer(t *testing.T, f *fakeServer) *fakeServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.pc = pc
	t.Cleanup(func() { _ = pc.Close() })
	go f.serve()
	return f
}

func (f *fakeServer) addr() string { return f.pc.LocalAddr().String() }

func (f *fakeServer) serve() {
	buf := make([]byte, 4096)
	for {
		n, from, err := f.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		p, err := wire.Parse(raw)
		if err != nil {
			continue
		}
		f.mu.Lock()
		f.seen = append(f.seen, p)
		f.mu.Unlock()
		code, attrs := wire.CodeAccessAccept, [][]byte(nil)
		if f.reply != nil {
			code, attrs = f.reply(p)
		}
		_, _ = f.pc.WriteTo(f.answer(p, code, attrs), from)
	}
}

// answer builds a correctly signed reply.
func (f *fakeServer) answer(req *wire.Packet, code wire.Code, attrs [][]byte) []byte {
	if f.signMAC {
		attrs = append(attrs, attr(wire.AttrMessageAuthenticator, make([]byte, 16)...))
	}
	out := packetWith(code, req.ID, req.Authenticator, attrs...)
	if f.signMAC {
		at := len(out) - 16
		buf := make([]byte, len(out))
		copy(buf, out)
		for i := 0; i < 16; i++ {
			buf[at+i] = 0
		}
		h := hmac.New(md5.New, []byte(theSecret)) //nolint:gosec // RFC 3579 specifies HMAC-MD5
		h.Write(buf)
		copy(out[at:], h.Sum(nil))
	}
	sum := md5.New() //nolint:gosec // RFC 2865 specifies MD5
	sum.Write(out[:4])
	sum.Write(req.Authenticator[:])
	sum.Write(out[wire.HeaderBytes:])
	sum.Write([]byte(theSecret))
	copy(out[4:wire.HeaderBytes], sum.Sum(nil))
	return out
}

func (f *fakeServer) requests() []*wire.Packet {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*wire.Packet, len(f.seen))
	copy(out, f.seen)
	return out
}

// attr renders one attribute, and vsa a Vendor-Specific one in RFC 2865
// §5.26's recommended encoding. They are the same two lines the wire
// package's own tests use, written again here because a test in one package
// cannot borrow a helper from another's.
func attr(t wire.AttrType, value ...byte) []byte {
	return append([]byte{byte(t), byte(len(value) + 2)}, value...)
}

func vsa(vendor uint32, vendorType uint8, value ...byte) []byte {
	inner := append([]byte{vendorType, byte(len(value) + 2)}, value...)
	v := make([]byte, 4, 4+len(inner))
	binary.BigEndian.PutUint32(v, vendor)
	return attr(wire.AttrVendorSpecific, append(v, inner...)...)
}

// auth16 is a request authenticator a test can recompute, so the answer's
// digests can be verified against the value the client sent.
func auth16(fill byte) [16]byte {
	var a [16]byte
	for i := range a {
		a[i] = fill
	}
	return a
}

// packetWith builds a packet with the length filled in. It is the test
// builder from radius_test.go under a name the server can use for a reply.
func packetWith(code wire.Code, id uint8, auth [16]byte, attrs ...[]byte) []byte {
	var body []byte
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := make([]byte, wire.HeaderBytes, wire.HeaderBytes+len(body))
	b[0], b[1] = byte(code), id
	copy(b[4:], auth[:])
	b = append(b, body...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

// client is a NAS.
type client struct {
	t     *testing.T
	pc    net.PacketConn
	relay *net.UDPAddr
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, pc: pc, relay: ra}
}

// send writes a request and returns the answer, or nil when none came.
func (c *client) send(raw []byte) *wire.Packet {
	c.t.Helper()
	if _, err := c.pc.WriteTo(raw, c.relay); err != nil {
		c.t.Fatal(err)
	}
	_ = c.pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := c.pc.ReadFrom(buf)
	if err != nil {
		return nil
	}
	p, err := wire.Parse(buf[:n])
	if err != nil {
		c.t.Fatalf("the relay's answer did not parse: %v", err)
	}
	return p
}

// request builds a signed Access-Request: a user name, and a correct
// Message-Authenticator unless withMAC is false.
func request(id uint8, user string, withMAC bool, extra ...[]byte) []byte {
	auth := auth16(id ^ 0x5a)
	attrs := append([][]byte{attr(wire.AttrUserName, []byte(user)...)}, extra...)
	if !withMAC {
		return packetWith(wire.CodeAccessRequest, id, auth, attrs...)
	}
	attrs = append(attrs, attr(wire.AttrMessageAuthenticator, make([]byte, 16)...))
	out := packetWith(wire.CodeAccessRequest, id, auth, attrs...)
	at := len(out) - 16
	h := hmac.New(md5.New, []byte(theSecret)) //nolint:gosec // RFC 3579 specifies HMAC-MD5
	h.Write(out)
	copy(out[at:], h.Sum(nil))
	return out
}

// signedComputed builds a packet for one of the codes whose authenticator is
// computed rather than drawn: an Accounting-Request, a Disconnect-Request, a
// CoA-Request. The order is the standard's and is not interchangeable -- the
// HMAC is written first, because the MD5 covers it.
func signedComputed(code wire.Code, id uint8, attrs ...[]byte) []byte {
	all := make([][]byte, 0, len(attrs)+1)
	all = append(all, attrs...)
	all = append(all, attr(wire.AttrMessageAuthenticator, make([]byte, 16)...))
	out := packetWith(code, id, [16]byte{}, all...)
	at := len(out) - 16
	h := hmac.New(md5.New, []byte(theSecret)) //nolint:gosec // RFC 3579 specifies HMAC-MD5
	h.Write(out)
	copy(out[at:], h.Sum(nil))
	sum := md5.New() //nolint:gosec // RFC 2866 specifies MD5
	sum.Write(out)
	sum.Write([]byte(theSecret))
	copy(out[4:wire.HeaderBytes], sum.Sum(nil))
	return out
}

func refusals(s *proxy.Server, reason string) uint64 {
	return s.Stats().Refusals["radius"][reason]
}

func TestARequestReachesTheServerAndItsAnswerComesBack(t *testing.T) {
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relay(t, "        default_action: allow\n", "", srv.addr())

	got := dial(t, addr).send(request(7, "alice@corp.example", true))
	if got == nil {
		t.Fatal("no answer")
	}
	if got.Code != wire.CodeAccessAccept {
		t.Fatalf("code = %v, want access-accept", got.Code)
	}
	// The client's own identifier comes back, whatever this relay used
	// towards the server.
	if got.ID != 7 {
		t.Fatalf("identifier = %d, want the client's 7", got.ID)
	}
	// And the answer verifies under the client's secret and the client's
	// own request authenticator, which is what proves the relay re-signed
	// it rather than forwarding the server's digest over a changed packet.
	if !got.VerifyResponseAuthenticator([]byte(theSecret), auth16(7^0x5a)) {
		t.Fatal("the answer's Response Authenticator does not verify")
	}
	if err := got.VerifyMessageAuthenticator([]byte(theSecret), auth16(7^0x5a)); err != nil {
		t.Fatalf("the answer's Message-Authenticator does not verify: %v", err)
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("the server saw %d requests", len(reqs))
	}
	if reqs[0].UserName() != "alice@corp.example" {
		t.Fatalf("the server saw user %q", reqs[0].UserName())
	}
	// The relay renumbered, which it has to: eight bits of identifier are
	// not enough to multiplex two switches.
	if err := reqs[0].VerifyMessageAuthenticator([]byte(theSecret), reqs[0].Authenticator); err != nil {
		t.Fatalf("the forwarded request's digest does not verify: %v", err)
	}
	if st := s.Stats(); st.RADIUSRequests != 1 {
		t.Fatalf("radius_requests = %d, want 1", st.RADIUSRequests)
	}
}

func TestAPacketWithNoDigestIsRefusedAndOneWithABadDigestIsToo(t *testing.T) {
	t.Parallel()
	t.Run("no Message-Authenticator at all", func(t *testing.T) {
		srv := startServer(t, &fakeServer{signMAC: true})
		s, addr := relay(t, "        default_action: allow\n", "", srv.addr())
		if got := dial(t, addr).send(request(1, "bob", false)); got != nil {
			t.Fatalf("a request with no digest was answered: %v", got.Code)
		}
		if len(srv.requests()) != 0 {
			t.Fatal("it reached the server")
		}
		if refusals(s, "missing_message_authenticator") == 0 {
			t.Fatalf("refusals: %v", s.Stats().Refusals["radius"])
		}
	})
	t.Run("a digest over different octets", func(t *testing.T) {
		srv := startServer(t, &fakeServer{signMAC: true})
		s, addr := relay(t, "        default_action: allow\n", "", srv.addr())
		raw := request(2, "bob", true)
		// bob -> bOb, after the digest was computed. This is the shape of
		// the attack the digest exists for: the packet is well formed and
		// says something else.
		raw[wire.HeaderBytes+3] ^= 0x20
		if got := dial(t, addr).send(raw); got != nil {
			t.Fatalf("a forged request was answered: %v", got.Code)
		}
		if refusals(s, "bad_message_authenticator") == 0 {
			t.Fatalf("refusals: %v", s.Stats().Refusals["radius"])
		}
		if s.Stats().RADIUSBadDigest == 0 {
			t.Fatal("radius_bad_digest was not counted")
		}
	})
	t.Run("the check can be turned off for one piece of equipment", func(t *testing.T) {
		// Which is the point of the per-rule setting: the one switch too
		// old to send a digest is written down, and the estate keeps the
		// mitigation.
		srv := startServer(t, &fakeServer{})
		section := "        default_action: deny\n" +
			"        rules:\n" +
			"          - {name: old-switch, action: allow, clients: [127.0.0.1/32], require_message_authenticator: false}\n"
		_, addr := relay(t, section, "", srv.addr())
		got := dial(t, addr).send(request(3, "bob", false))
		if got == nil || got.Code != wire.CodeAccessAccept {
			t.Fatalf("answer = %v, want an accept", got)
		}
	})
}

func TestAReplyThatGrantsTooMuchPrivilegeIsRefused(t *testing.T) {
	t.Parallel()
	// The grant is in the reply, which is the half an estate usually has no
	// control over: one compromised server would otherwise hand out enable
	// on every router behind this relay.
	srv := startServer(t, &fakeServer{
		signMAC: true,
		reply: func(*wire.Packet) (wire.Code, [][]byte) {
			return wire.CodeAccessAccept, [][]byte{
				vsa(wire.VendorCisco, 1, []byte("shell:priv-lvl=15")...),
			}
		},
	})
	s, addr := relay(t, "        default_action: allow\n        max_privilege_level: 1\n", "", srv.addr())
	got := dial(t, addr).send(request(9, "bob", true))
	if got == nil {
		t.Fatal("no answer: the client should get a rejection rather than silence")
	}
	if got.Code != wire.CodeAccessReject {
		t.Fatalf("code = %v, want access-reject", got.Code)
	}
	if refusals(s, "privilege_too_high") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["radius"])
	}
	if s.Stats().RADIUSPrivilegeGrants == 0 {
		t.Fatal("radius_privilege_grants was not counted")
	}
	// And the rejection is one the client can verify, because a client that
	// cannot treats it as noise and retries.
	if !got.VerifyResponseAuthenticator([]byte(theSecret), auth16(9^0x5a)) {
		t.Fatal("the rejection's Response Authenticator does not verify")
	}
}

func TestADowngradeToEAPMD5IsRefusedWhicheverWayItIsAsked(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relay(t, "        default_action: allow\n", "", srv.addr())
	c := dial(t, addr)

	// Asked for directly.
	eap := []byte{byte(wire.EAPResponse), 1, 0, 6, byte(wire.EAPTypeMD5Challenge), 0}
	if got := c.send(request(11, "bob", true, attr(wire.AttrEAPMessage, eap...))); got != nil &&
		got.Code == wire.CodeAccessAccept {
		t.Fatal("an EAP-MD5 response was carried")
	}
	if refusals(s, "weak_eap_type") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["radius"])
	}

	// And offered in a Nak, which is the way a downgrade actually happens:
	// the packet's own type is Nak, which is not a method, so a reader that
	// looked only there would carry it.
	before := refusals(s, "weak_eap_type")
	nak := []byte{byte(wire.EAPResponse), 2, 0, 6, byte(wire.EAPTypeNak), byte(wire.EAPTypeMD5Challenge)}
	if got := c.send(request(12, "bob", true, attr(wire.AttrEAPMessage, nak...))); got != nil &&
		got.Code == wire.CodeAccessAccept {
		t.Fatal("a Nak offering EAP-MD5 was carried")
	}
	if refusals(s, "weak_eap_type") <= before {
		t.Fatalf("the Nak's offer was not read: %v", s.Stats().Refusals["radius"])
	}

	// A method that is not weak goes through, so the refusal above is about
	// the method rather than about EAP.
	peap := []byte{byte(wire.EAPResponse), 3, 0, 6, byte(wire.EAPTypePEAP), 0x20}
	if got := c.send(request(13, "bob", true, attr(wire.AttrEAPMessage, peap...))); got == nil ||
		got.Code != wire.CodeAccessAccept {
		t.Fatalf("a PEAP response was refused: %v", got)
	}
}

func TestTwoClientsUsingOneIdentifierEachGetTheirOwnAnswer(t *testing.T) {
	t.Parallel()
	// The protocol's identifier is eight bits and shared between every
	// client, so a relay that forwarded it unchanged would deliver one
	// switch's Access-Accept to the other. The user name in each answer is
	// what proves the pairing: the fake server echoes it back.
	srv := startServer(t, &fakeServer{
		signMAC: true,
		reply: func(p *wire.Packet) (wire.Code, [][]byte) {
			return wire.CodeAccessAccept, [][]byte{
				attr(wire.AttrReplyMessage, []byte(p.UserName())...),
			}
		},
	})
	_, addr := relay(t, "        default_action: allow\n", "", srv.addr())

	// Both clients use identifier 42, from different sockets.
	type result struct {
		user string
		p    *wire.Packet
	}
	out := make(chan result, 2)
	for _, user := range []string{"first", "second"} {
		go func(user string) {
			out <- result{user, dial(t, addr).send(request(42, user, true))}
		}(user)
	}
	for i := 0; i < 2; i++ {
		r := <-out
		if r.p == nil {
			t.Fatalf("%s got no answer", r.user)
		}
		a, ok := r.p.First(wire.AttrReplyMessage)
		if !ok {
			t.Fatalf("%s got an answer with no reply message", r.user)
		}
		if got, _ := a.Text(); got != r.user {
			t.Fatalf("%s got %q's answer", r.user, got)
		}
	}
}

func TestShadowModeCarriesWhatItWouldRefuseAndStillVerifies(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relay(t, "        default_action: deny\n", "      policy: {mode: shadow}\n", srv.addr())
	c := dial(t, addr)

	// The policy would refuse this -- nothing matched and the default is
	// deny -- and in shadow mode it is carried and written down.
	got := c.send(request(5, "bob", true))
	if got == nil || got.Code != wire.CodeAccessAccept {
		t.Fatalf("shadow mode refused a request: %v", got)
	}
	if s.Stats().WouldRefusals["radius"]["no_rule_matched"] == 0 {
		t.Fatalf("would-refusals: %v", s.Stats().WouldRefusals["radius"])
	}
	if n := len(s.Stats().Refusals["radius"]); n != 0 {
		t.Fatalf("shadow mode refused something: %v", s.Stats().Refusals["radius"])
	}

	// The digest is not policy, so it is still checked: a relay that
	// forwarded an unverifiable packet because its policy was in shadow
	// mode would have no authentication at all.
	if got := c.send(request(6, "bob", false)); got != nil {
		t.Fatalf("shadow mode carried a packet with no digest: %v", got.Code)
	}
	if refusals(s, "missing_message_authenticator") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["radius"])
	}
}

func TestADynamicAuthorizationRequestIsNotCarried(t *testing.T) {
	t.Parallel()
	// A Disconnect-Request ends a live user's session from one datagram, and
	// it runs from a server towards the equipment rather than the other way.
	// The refusal is hard: shadow mode does not carry one to find out what
	// would have happened.
	srv := startServer(t, &fakeServer{signMAC: true})
	s, addr := relay(t, "        default_action: allow\n", "      policy: {mode: shadow}\n", srv.addr())
	raw := signedComputed(wire.CodeDisconnectRequest, 1,
		attr(wire.AttrUserName, 'b', 'o', 'b'))
	if got := dial(t, addr).send(raw); got != nil {
		t.Fatalf("a Disconnect-Request was answered: %v", got.Code)
	}
	if len(srv.requests()) != 0 {
		t.Fatal("it reached the server")
	}
	if refusals(s, "dynamic_authorization_not_allowed") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["radius"])
	}
}

func TestAnAccountingRequestIsVerifiedAgainstItsComputedAuthenticator(t *testing.T) {
	t.Parallel()
	// An Accounting-Request's authenticator field is MD5 over the packet with
	// sixteen zeroes in its place and the secret appended -- not a nonce. A
	// verifier that used the field as though it were one would reject every
	// accounting packet in the estate, and one that skipped the check
	// altogether would carry a packet whose only integrity value is wrong.
	srv := startServer(t, &fakeServer{
		signMAC: true,
		reply: func(*wire.Packet) (wire.Code, [][]byte) {
			return wire.CodeAccountingResponse, nil
		},
	})
	s, addr := relay(t, "        default_action: allow\n", "", srv.addr())
	c := dial(t, addr)

	good := signedComputed(wire.CodeAccountingRequest, 21,
		attr(wire.AttrUserName, 'b', 'o', 'b'),
		attr(wire.AttrAcctStatusType, 0, 0, 0, 1))
	if got := c.send(good); got == nil || got.Code != wire.CodeAccountingResponse {
		t.Fatalf("a correctly signed accounting request was not carried: %v", got)
	}
	if len(srv.requests()) != 1 {
		t.Fatalf("the server saw %d requests", len(srv.requests()))
	}

	bad := signedComputed(wire.CodeAccountingRequest, 22,
		attr(wire.AttrUserName, 'b', 'o', 'b'))
	bad[4] ^= 0xff
	if got := c.send(bad); got != nil {
		t.Fatalf("a packet with a wrong authenticator was answered: %v", got.Code)
	}
	if refusals(s, "bad_request_authenticator") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["radius"])
	}
	if len(srv.requests()) != 1 {
		t.Fatal("it reached the server")
	}
}
