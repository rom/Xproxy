package radius

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/netutil"
	wire "github.com/rom/xproxy/internal/radius"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

// The datagram path.
//
// RADIUS is request and answer over UDP with no session and nothing to
// close, so the relay keeps one socket towards the servers and pairs
// answers to questions by the identifier it chose -- which it has to
// choose, because the protocol's own is eight bits wide and shared between
// every client.
//
// The order of the checks on the way in is the order they are cheapest and
// most decisive in: the address lists, the imported lists and the estate's
// authorisation policy, the rate limit, the size bound, the parse, the
// integrity check, and only then the policy. The integrity check sits
// before the policy deliberately. Everything the policy decides on -- the
// user name, the realm, the method -- is an attribute inside the packet,
// and an attribute inside a packet whose digest has not been verified is
// whatever the last host on the path chose to put there.

// serve runs the listener until it is shut down.
func (t *server) serve() {
	if !t.running.Enter() {
		// Shut down before it started, which a reload can do.
		return
	}
	defer t.running.Leave()
	up, err := t.serverSocket()
	if err != nil {
		t.host.Logs().Error.Error("radius upstream socket could not be opened",
			"listener", t.name, "error", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	if t.running.Enter() {
		go func() {
			defer t.running.Leave()
			defer safe.Guard("radius upstream reader")
			t.readServer(up)
		}()
	}
	buf := make([]byte, wire.MaxMessage+1)
	for {
		if t.running.Closing() {
			return
		}
		_ = t.pc.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := t.pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if n > t.maxMessage() {
			// Refused unread. Reading it to find out what it asked for is
			// the work the bound exists to avoid.
			t.deny(netutil.AddrOf(from.String()), "message_too_large", strconv.Itoa(n))
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		t.fromClient(up, raw, from)
	}
}

// serverSocket opens the socket this relay speaks to the servers from.
func (t *server) serverSocket() (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), "udp", ":0")
}

// admitClient is the two questions this relay asks about a client that has
// no name of its own: do the imported lists know this address, and does the
// estate's authorisation policy allow it here.
//
// It is asked per datagram, because RADIUS has no session to hang the
// answer on. A refusal goes through deny, so a client that keeps sending
// earns a ban the same way one refused by the address lists does -- which
// is what stops the record from being written at packet rate.
//
// The subject names the address and nothing else. The user name is inside
// the packet, which has not been verified yet, and a policy rule keyed on
// an unverified claim is a rule keyed on whatever the sender wrote.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists:       h.ThreatIntel(),
		Quarantined: h.Packs().Quarantined,
		Policy:      h.Authorization(),
		Logs:        h.Logs(),
		Matched:     func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.name,
		Kind:     "radius",
		Client:   ip,
		Target:   t.r.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("radius", reason)
			h.Shadow().Record("radius", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// fromClient decides about one datagram from a client and, when it is
// allowed, forwards it to a server.
func (t *server) fromClient(up net.PacketConn, raw []byte, from net.Addr) {
	ip := netutil.AddrOf(from.String())
	if !t.policy.Client(ip) {
		t.deny(ip, "client_not_allowed", "")
		return
	}
	if t.admitClient(ip) != "" {
		return
	}
	// The rate limit is a bound rather than policy, so it is never
	// shadowed: a relay that let a flood through because its policy was in
	// shadow mode would be a relay with no bound at all. Here it is also
	// the only thing between a credential-stuffing run and a RADIUS server
	// doing a key derivation per attempt.
	if t.limiter != nil && !t.limiter.Allow(ip.String()) {
		t.host.Counters().Refuse("radius", "rate_limited")
		return
	}
	p, err := wire.Parse(raw)
	if err != nil {
		t.deny(ip, "malformed", err.Error())
		return
	}
	if len(p.Attrs) > t.policy.maxAttrs {
		t.deny(ip, "too_many_attributes", strconv.Itoa(len(p.Attrs)))
		return
	}
	if !p.Code.Request() && !p.Code.Dynamic() {
		// A reply arriving on the listener's own socket. It is not an
		// answer to anything -- answers come back on the upstream socket --
		// so it is either a client that is confused about which way this
		// relay runs or something injecting replies.
		t.deny(ip, "wrong_direction", p.Code.String())
		return
	}
	if !t.verifyRequest(ip, p) {
		return
	}
	req := t.request(ip, p)
	d := t.policy.Decide(req)
	if !d.Allow {
		t.refused(ip, p, d)
		if t.enforcing() || d.Hard {
			t.answerRefusal(p, from)
			return
		}
	}
	// Behavioural detection, after the policy and on what is going on to
	// the server: the models learn from what reached it, and a request the
	// policy refused never got there.
	if reason := t.decideAnomaly(req); reason != "" {
		t.answerRefusal(p, from)
		return
	}
	t.forward(up, p, req, from, d)
}

// verifyRequest runs the integrity checks, which are not policy and are
// never shadowed.
//
// A listener with no secret cannot run them, which is the whole of what it
// gives up: it reports that, once per packet, as a counter rather than a
// refusal -- refusing every packet for want of a configuration file would
// be a listener that does not work rather than one that is strict.
func (t *server) verifyRequest(ip netip.Addr, p *wire.Packet) bool {
	if !t.reading() {
		t.host.Counters().RADIUSNoDigest.Add(1)
		return true
	}
	auth := requestAuth(p)
	// An Accounting-Request and the dynamic authorization codes carry a
	// *computed* authenticator rather than a nonce: MD5 over the packet with
	// sixteen zeroes in its place and the secret appended. That is a real
	// integrity check on a packet that would otherwise have none, and it is
	// the only one those codes have when they carry no digest attribute.
	if !isNonceCode(p.Code) && !p.VerifyResponseAuthenticator(t.secret, auth) {
		t.host.Counters().RADIUSBadDigest.Add(1)
		t.deny(ip, "bad_request_authenticator", p.Code.String())
		return false
	}
	err := p.VerifyMessageAuthenticator(t.secret, auth)
	switch {
	case err == nil:
		return true
	case errors.Is(err, wire.ErrNoDigest):
		if !t.policy.NeedMAC(ip) {
			return true
		}
		t.host.Counters().RADIUSNoDigest.Add(1)
		t.deny(ip, "missing_message_authenticator", p.Code.String())
		return false
	default:
		// A digest that does not verify is a mismatched secret or a forged
		// packet, and a relay cannot tell which. Neither is forwarded, in
		// any mode.
		t.host.Counters().RADIUSBadDigest.Add(1)
		t.deny(ip, "bad_message_authenticator", p.Code.String())
		return false
	}
}

// isNonceCode says whether a code's authenticator field is a nonce the
// client drew rather than a digest it computed.
//
// It decides what the two verifications are run against, and getting it
// wrong is silent: the digest of an Accounting-Request computed over its own
// authenticator field verifies against nothing, so every accounting packet
// in the estate would be refused with no indication why.
func isNonceCode(c wire.Code) bool {
	switch c {
	case wire.CodeAccessRequest, wire.CodeStatusServer, wire.CodeStatusClient:
		return true
	}
	return false
}

// requestAuth is the value RFC 3579 §3.2 calls the Request Authenticator for
// this packet: the field itself where the client drew a nonce, and sixteen
// zeroes where the field holds a computed digest.
func requestAuth(p *wire.Packet) [wire.AuthenticatorBytes]byte {
	if isNonceCode(p.Code) {
		return p.Authenticator
	}
	return [wire.AuthenticatorBytes]byte{}
}

// request builds the policy's view of one packet.
func (t *server) request(ip netip.Addr, p *wire.Packet) Request {
	user := p.UserName()
	local, realm := wire.Realm(user)
	req := Request{Client: ip, Code: p.Code, ID: p.ID, User: user, Local: local,
		Realm: realm, AuthType: p.AuthType(), At: time.Now()}
	if a, ok := p.First(wire.AttrNASIdentifier); ok {
		if s, ok := a.Text(); ok {
			req.NASID = s
		}
	}
	for _, a := range p.Attrs {
		req.Attrs = append(req.Attrs, a.Type)
	}
	if _, ok := p.PasswordBytes(); ok {
		req.Password = true
	}
	if p.Has(wire.AttrUserPassword) {
		t.host.Counters().RADIUSPlaintextPasswords.Add(1)
	}
	if e, err := p.EAP(); err == nil {
		req.HasEAP, req.EAPType, req.EAPOffers = e.HasType, e.Type, e.NakTypes
		if e.Identity != "" && req.User == "" {
			// A NAS that sent no User-Name but did send an EAP identity:
			// the outer identity is what the server will route on, so it is
			// what the policy decides on too.
			req.User = e.Identity
			req.Local, req.Realm = wire.Realm(e.Identity)
		}
	}
	return req
}

// forward sends a decided request to a server and records what it needs to
// pair the answer.
func (t *server) forward(up net.PacketConn, p *wire.Packet, req Request, from net.Addr, d Decision) {
	pool := t.r.Upstream
	if p.Code == wire.CodeAccountingRequest && t.r.AccountingUpstream != "" {
		pool = t.r.AccountingUpstream
	}
	addr := t.serverAddr(pool, req.Client)
	if addr == nil {
		t.host.Counters().Refuse("radius", "no_upstream")
		return
	}
	e := &exchange{client: req.Client, from: from, server: addr.String(),
		clientID: p.ID, clientAuth: p.Authenticator, code: p.Code,
		user: req.User, rule: d.Rule}
	id, ok := t.pend.add(e, time.Now())
	if !ok {
		if t.reading() {
			t.deny(req.Client, "too_many_pending", strconv.Itoa(t.pend.outstanding()))
		} else {
			// Without a secret the relay cannot renumber, so a collision on
			// the client's own identifier is a collision it refuses. Naming
			// it as its own reason rather than as a full table is the
			// difference between an operator reading "the servers are not
			// answering" and "this listener has no secret".
			t.deny(req.Client, "identifier_in_use", strconv.Itoa(int(p.ID)))
		}
		return
	}
	out := p.Raw
	if t.reading() {
		signed, auth, err := forward(p, id, t.secret, t.upSecret)
		if err != nil {
			t.pend.drop(id)
			t.deny(req.Client, "cannot_resign", err.Error())
			return
		}
		out, e.mineAuth = signed, auth
	} else {
		e.mineAuth = p.Authenticator
	}
	if _, err := up.WriteTo(out, addr); err != nil {
		t.host.Counters().Refuse("radius", "upstream_failed")
		t.host.Logs().Error.Warn("radius forward to server failed", "listener", t.name,
			"server", addr.String(), "error", err.Error())
		// The request never left, so no answer is coming and there is no
		// reason to hold its identifier until the timeout.
		t.pend.drop(id)
		return
	}
	t.host.Counters().RADIUSRequests.Add(1)
	t.logRequest(req, d)
}

// serverAddr picks the server a request goes to.
func (t *server) serverAddr(pool string, client netip.Addr) net.Addr {
	p := t.host.Pool(pool)
	if p == nil {
		return nil
	}
	e, _ := p.Pick(client.String(), "", nil, upstream.CanaryAny)
	if e == nil {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", e.Address)
	if err != nil {
		return nil
	}
	return addr
}

// readServer reads what the servers send back.
func (t *server) readServer(up net.PacketConn) {
	buf := make([]byte, wire.MaxMessage+1)
	for {
		if t.running.Closing() {
			return
		}
		_ = up.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := up.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if n > t.maxMessage() {
			t.deny(netutil.AddrOf(from.String()), "reply_too_large", strconv.Itoa(n))
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		t.fromServer(raw, from)
	}
}

// fromServer decides about one reply and delivers it to the client it
// belongs to.
func (t *server) fromServer(raw []byte, from net.Addr) {
	ip := netutil.AddrOf(from.String())
	p, err := wire.Parse(raw)
	if err != nil {
		t.deny(ip, "malformed_reply", err.Error())
		return
	}
	if !p.Code.Response() && !p.Code.Dynamic() {
		// A request arriving on the socket this relay sends from. Forwarding
		// it would make this relay the way into the equipment's network
		// rather than out of it.
		t.deny(ip, "wrong_direction", p.Code.String())
		return
	}
	e, expired := t.pend.take(p.ID, from.String(), time.Now())
	if e == nil {
		// An answer nobody asked for. On a datagram protocol that is the
		// shape of answer spoofing: a reply to a question the client did
		// ask, from somewhere else or with the wrong identifier, arriving
		// first.
		t.host.Counters().RADIUSUnsolicited.Add(1)
		t.deny(ip, "unsolicited_reply", p.Code.String())
		return
	}
	if expired {
		t.host.Counters().Refuse("radius", "reply_after_timeout")
		return
	}
	if t.reading() && t.policy.verifyResp {
		if !p.VerifyResponseAuthenticator(t.upSecret, e.mineAuth) {
			t.host.Counters().RADIUSBadDigest.Add(1)
			t.deny(ip, "bad_response_authenticator", p.Code.String())
			return
		}
	}
	if t.reading() && t.policy.NeedMAC(e.client) {
		switch err := p.VerifyMessageAuthenticator(t.upSecret, e.mineAuth); {
		case err == nil:
		case errors.Is(err, wire.ErrNoDigest):
			t.host.Counters().RADIUSNoDigest.Add(1)
			t.deny(ip, "missing_message_authenticator", p.Code.String())
			return
		default:
			t.host.Counters().RADIUSBadDigest.Add(1)
			t.deny(ip, "bad_message_authenticator", p.Code.String())
			return
		}
	}
	rep := t.reply(e, p)
	if d := t.policy.Reply(rep); !d.Allow {
		t.refusedReply(e, p, d)
		if t.enforcing() {
			// The client gets an Access-Reject rather than silence, so the
			// person logging in sees a refused login rather than a dead
			// server -- and the privileged answer the server sent does not
			// reach the equipment.
			t.answerRefusalTo(e, from)
			return
		}
	}
	out := p.Raw
	if t.reading() {
		signed, err := backward(p, e, t.secret)
		if err != nil {
			t.deny(ip, "cannot_resign", err.Error())
			return
		}
		out = signed
	}
	if _, err := t.pc.WriteTo(out, e.from); err != nil {
		t.host.Counters().Refuse("radius", "client_write_failed")
		return
	}
	t.logReply(e, rep)
}

// reply builds the policy's view of one answer.
func (t *server) reply(e *exchange, p *wire.Packet) Reply {
	rep := Reply{Client: e.client, Code: p.Code, Rule: e.rule, At: time.Now(),
		Administrative: p.Administrative()}
	if n, ok := p.PrivilegeLevel(); ok {
		rep.Privilege, rep.HasPrivilege = n, true
	}
	if rep.HasPrivilege || rep.Administrative {
		t.host.Counters().RADIUSPrivilegeGrants.Add(1)
	}
	for _, a := range p.Attrs {
		rep.Attrs = append(rep.Attrs, a.Type)
	}
	return rep
}

// answerRefusal tells a refused client no, in the protocol's own terms.
//
// Only an Access-Request has anything useful to answer: an
// Accounting-Response means "recorded", so sending one for a refused
// accounting packet would be a lie, and a refused dynamic authorization
// request is not this relay's to answer at all. Those are silent whatever
// deny_response says, which is what the protocol gives a relay to work
// with.
func (t *server) answerRefusal(p *wire.Packet, to net.Addr) {
	if !t.reject || p.Code != wire.CodeAccessRequest {
		return
	}
	t.writeReject(p.ID, p.Authenticator, to)
}

// answerRefusalTo is the same for a reply this relay refused: the client is
// still waiting for an answer to its own request, so it gets a rejection
// rather than a timeout.
func (t *server) answerRefusalTo(e *exchange, _ net.Addr) {
	if !t.reject || e.code != wire.CodeAccessRequest {
		return
	}
	t.writeReject(e.clientID, e.clientAuth, e.from)
}

// writeReject builds and sends an Access-Reject.
//
// It carries a Reply-Message saying which proxy refused it, because the
// string reaches the person at the keyboard on a lot of equipment -- and a
// correct Response Authenticator, because a client that cannot verify the
// rejection treats it as noise and retries.
func (t *server) writeReject(id uint8, auth [wire.AuthenticatorBytes]byte, to net.Addr) {
	const msg = "refused by xproxy"
	body := append([]byte{byte(wire.AttrReplyMessage), byte(len(msg) + 2)}, msg...)
	out := make([]byte, wire.HeaderBytes, wire.HeaderBytes+len(body))
	out[0], out[1] = byte(wire.CodeAccessReject), id
	out = append(out, body...)
	out[2], out[3] = byte(len(out)>>8), byte(len(out))
	if t.reading() {
		p, err := wire.Parse(out)
		if err != nil {
			return
		}
		sum := p.ResponseAuthenticator(t.secret, auth)
		copy(out[4:wire.HeaderBytes], sum[:])
	}
	if _, err := t.pc.WriteTo(out, to); err != nil {
		t.host.Counters().Refuse("radius", "client_write_failed")
	}
}
