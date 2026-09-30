package coap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/netutil"
)

// serve runs the two loops: the segment side and the device side.
func (s *server) serve() {
	// started is closed however this function leaves, because a shutdown waits on
	// it before waiting on the loops: a listener whose device socket could not be
	// opened must not make a shutdown wait out its whole context for goroutines
	// that were never registered.
	launched := false
	defer func() {
		if !launched {
			close(s.started)
		}
	}()
	up, err := s.deviceSocket()
	if err != nil {
		s.host.Logs().Error.Error("coap could not open its device socket",
			"listener", s.cfg.Name, "error", err.Error())
		return
	}
	s.up.Store(&deviceSocket{up})
	s.wg.Add(2)
	go func() { defer s.wg.Done(); s.fromDevices() }()
	go func() { defer s.wg.Done(); s.sweep() }()
	// The segment side is either the socket read straight, or a DTLS session per
	// peer over the same socket. One listener is one address, so it is one or the
	// other: RFC 7252 s9 puts the two on different ports for exactly this reason.
	//
	// A pre-shared key table turns DTLS on by itself, with no tls section and no
	// certificate. That is not a convenience: a segment that speaks PSK is a
	// segment whose devices have no certificate machinery, and an estate that
	// has none for them usually has no authority of its own either. Requiring a
	// server certificate to serve the mode that exists because certificates are
	// too expensive would be requiring the thing the mode replaces.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if s.secured() {
			s.serveDTLS(s.tls)
			return
		}
		s.fromClients()
	}()
	// Every Add is done, so a shutdown may now wait on them.
	launched = true
	close(s.started)
	<-s.done
}

// deviceSocket opens the socket this relay speaks to devices on.
//
// The family is left unspecified rather than pinned, so the listener works over
// whichever the configured devices are on -- and so the relay can be exercised on
// a host that has only one of the two.
func (s *server) deviceSocket() (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), "udp", ":0")
}

// replier is how an answer gets back to the client it is for.
//
// In NoSec that is the listener's own socket and the address the request came
// from. Inside DTLS it is the session the request arrived in, because an answer
// written to the socket instead would be cleartext sent to a peer that
// established a session precisely so that it would not be -- and would be
// discarded by the peer's DTLS stack, so the failure would look like a timeout
// rather than like a mistake.
type replier interface {
	send(b []byte) error
	// remote is where the answer goes, for the pending table and the logs.
	remote() net.Addr
	// secure says the request arrived inside a session, which is the only
	// identity this protocol offers.
	secure() bool
	// peer is who the session's far end turned out to be: the security name
	// its pre-shared key identity or its pinned public key maps to. The zero
	// identity is a NoSec client, which is nobody.
	peer() identity
}

// plain writes onto the listener's own socket.
type plain struct {
	pc net.PacketConn
	to net.Addr
}

func (p plain) send(b []byte) error { _, err := p.pc.WriteTo(b, p.to); return err }
func (p plain) remote() net.Addr    { return p.to }
func (p plain) peer() identity      { return identity{} }
func (p plain) secure() bool        { return false }

func (s *server) fromClients() {
	// One octet more than the bound, so a message over it is seen to be over it
	// rather than silently truncated into a shorter valid one.
	buf := make([]byte, s.maxMessage()+1)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			if s.stopping() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		s.fromClient(raw, plain{pc: s.pc, to: from})
	}
}

func (s *server) fromDevices() {
	// The socket is read once into a local, because serve() has already stored it
	// and this loop is the only thing reading it: a load per datagram would be a
	// load per sensor reading for a value that cannot change.
	up := s.device()
	if up == nil {
		return
	}
	buf := make([]byte, wire.MaxMessage+1)
	for {
		n, from, err := up.ReadFrom(buf)
		if err != nil {
			if s.stopping() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		s.fromDevice(raw, from)
	}
}

func (s *server) sweep() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.pend.sweep(now)
			c := s.host.Counters()
			c.CoAPPending.Store(int64(s.pend.len()))
			c.CoAPObservers.Store(int64(s.obs.len()))
			if m := s.mux(); m != nil {
				c.CoAPDatagramsDropped.Store(m.Dropped())
			}
		}
	}
}

func (s *server) stopping() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// fromClient decides about one message from the segment and relays it.
//
// to is how the answer gets back: the listener's socket in NoSec, the DTLS session
// otherwise. It carries whether the request was secure, which in NoSec is false for
// everything -- the honest answer, because there is no identity to report.
func (s *server) fromClient(raw []byte, to replier) {
	c := s.host.Counters()
	from := to.remote()
	secure := to.secure()
	ip := netutil.AddrOf(from.String())
	c.CoAPMessages.Add(1)
	if !s.policy.Client(ip) {
		c.CoAPRejected.Add(1)
		c.Refuse("coap", "client_not_allowed")
		s.deny(ip, "client_not_allowed", "")
		return
	}
	if reason := s.admitClient(ip); reason != "" {
		c.CoAPRejected.Add(1)
		c.Refuse("coap", reason)
		return
	}
	if len(raw) > s.maxMessage() {
		// A bound, so it is refused before anything reads it, and never
		// shadowed. There is nothing to answer with either: a message this relay
		// would not parse is one whose token it has not read.
		c.CoAPOversize.Add(1)
		c.Refuse("coap", "message_too_large")
		s.deny(ip, "message_too_large", byteCount(len(raw)))
		return
	}
	m, err := wire.Parse(raw)
	if err != nil {
		c.CoAPMalformed.Add(1)
		c.Refuse("coap", "malformed")
		s.deny(ip, "malformed", err.Error())
		return
	}
	if s.limiter != nil && !s.limiter.Allow(ip.String()) {
		c.CoAPRateLimited.Add(1)
		c.Refuse("coap", "rate_limited")
		return
	}
	switch {
	case m.Code.IsRequest():
		c.CoAPRequests.Add(1)
	case m.Code.IsEmpty():
		c.CoAPEmpty.Add(1)
	}

	who := to.peer()
	req := request{from: ip, msg: m, secure: secure, at: time.Now(),
		identity: who.name, named: who.name != ""}
	d := s.policy.Decide(req)
	s.observeRequest(m, ip, secure)
	if !d.Allow {
		if d.Reason == "no_security_name" {
			c.CoAPUnnamed.Add(1)
		}
		s.refused(ip, m, d, "client", who)
		if s.enforcing() || d.Hard {
			s.answer(m, d, to)
			return
		}
	}
	// Behavioural detection, after the policy and on the requests that are
	// going on to the device: the models learn from what reached it, and a
	// request the policy refused never got there.
	if reason := s.decideAnomaly(req); reason != "" {
		s.answer(m, hard(reason, m.Path(), wire.Forbidden), to)
		return
	}
	// An Observe registration is a flow with no end, so it takes a slot in a
	// table of its own. The bound is never shadowed: "how many open-ended flows
	// may exist" would otherwise be answered by whoever asked for the most.
	addr := s.deviceAddr(ip)
	if addr == nil {
		c.CoAPUpstreamFail.Add(1)
		return
	}
	e := &exchange{client: addrPort(from), device: addrPort(addr), reply: to,
		token: string(m.Token), size: len(raw),
		rule: d.Rule, path: m.Path(), code: m.Code, observing: m.Registering()}
	if e.observing {
		if !s.obs.add(e.key()) {
			c.CoAPRefusedObserve.Add(1)
			c.Refuse("coap", "too_many_observers")
			s.deny(ip, "too_many_observers", m.Path())
			s.answer(m, hard("too_many_observers", "", wire.ServiceUnavailable), to)
			return
		}
	}
	if m.Deregistering() {
		s.obs.remove(e.key())
	}
	if !s.pend.add(e, time.Now()) {
		c.Refuse("coap", "too_many_pending")
		s.deny(ip, "too_many_pending", "")
		s.answer(m, hard("too_many_pending", "", wire.ServiceUnavailable), to)
		return
	}
	s.logMessage(ip, m, d, "client", "allow", secure, who)
	up := s.device()
	if up == nil {
		// The listener has not finished starting, or has stopped. Either way
		// there is nowhere to send this, and the exchange is forgotten rather
		// than left in the pending table waiting for an answer nothing asked for.
		s.forget(e)
		return
	}
	if _, err := up.WriteTo(raw, addr); err != nil {
		c.CoAPUpstreamFail.Add(1)
		s.host.Logs().Error.Warn("coap relay to device failed", "listener", s.cfg.Name,
			"device", addr.String(), "error", err.Error())
		s.forget(e)
		return
	}
	c.CoAPRelayed.Add(1)
}

// fromDevice decides about one message coming back and delivers it to the client
// that asked.
func (s *server) fromDevice(raw []byte, from net.Addr) {
	c := s.host.Counters()
	ip := netutil.AddrOf(from.String())
	c.CoAPResponses.Add(1)
	if !s.policy.Server(ip) {
		// The one refusal that is never shadowed on this side: a listener that
		// evaluated the device list without enforcing it would carry an answer
		// from whatever reached the socket first and write it down.
		c.CoAPRogueDevice.Add(1)
		c.Refuse("coap", "device_not_allowed")
		s.deny(ip, "device_not_allowed", "")
		return
	}
	m, err := wire.Parse(raw)
	if err != nil {
		c.CoAPMalformed.Add(1)
		c.Refuse("coap", "malformed_response")
		s.deny(ip, "malformed_response", err.Error())
		return
	}
	// The token is the pairing, together with the device that answered. A
	// response's message identifier is its own when the response is separate, so
	// pairing on that would deliver a separate response to nobody.
	e, ok := s.pend.take(key{device: addrPort(from), token: string(m.Token)}, time.Now())
	if !ok {
		c.CoAPUnsolicited.Add(1)
		c.Refuse("coap", "unsolicited")
		s.deny(ip, "unsolicited", m.Code.String())
		return
	}
	d := s.policy.Answer(m, e.size, e.rule)
	if !d.Allow {
		// A device's answer carries the client's identity, because the line an
		// operator reads is about the exchange rather than about one datagram
		// of it: an answer refused for a device that a named client asked is a
		// different finding from the same answer to an anonymous one.
		s.refused(ip, m, d, "device", e.reply.peer())
		if s.enforcing() || d.Hard {
			s.pend.drop(e.key())
			s.obs.remove(e.key())
			return
		}
	}
	s.observeReply(m, e, ip)
	if err := e.reply.send(raw); err != nil {
		c.CoAPSendFailed.Add(1)
		s.host.Logs().Error.Warn("coap reply to client failed", "listener", s.cfg.Name,
			"client", e.client.String(), "error", err.Error())
		return
	}
	c.CoAPAnswered.Add(1)
	if e.observing {
		c.CoAPNotifications.Add(1)
	}
	s.logReply(ip, m, e, d)
}

// answer sends the response the standard gives for a refusal, rather than
// dropping the datagram.
//
// Silence is the wrong answer on this protocol. A Confirmable request is
// retransmitted until something answers, so a dropped refusal becomes four or five
// more requests and leaves the device's own logs showing a timeout where a refusal
// happened. Where the refusal is about a message whose token could not be read,
// the answer is a bare Reset, which carries nothing and pretends nothing.
func (s *server) answer(m *wire.Message, d Decision, to replier) {
	if !s.answering() || d.Answer == 0 {
		return
	}
	var out *wire.Message
	switch {
	case m.Code.IsEmpty():
		// Nothing to answer: an empty message is already an answer.
		return
	case m.Type == wire.Confirmable || m.Type == wire.NonConfirmable:
		out = wire.Answer(m, d.Answer, s.nextMID())
	default:
		out = wire.ResetFor(m.MessageID)
	}
	raw, err := wire.Encode(out)
	if err != nil {
		return
	}
	if err := to.send(raw); err != nil {
		s.host.Counters().CoAPSendFailed.Add(1)
		return
	}
	s.host.Counters().CoAPRefusalsAnswered.Add(1)
}

// admitClient is the two questions asked about a client that has no identity: do
// the imported lists know this address, and does the estate's authorisation policy
// allow it here.
//
// In NoSec the address is all there is, and it is worth being plain that on a
// constrained network it is often a device's only name -- which makes the lists
// more useful here than on DHCPv6, where a client picks its own link-local
// address, and less useful than on a protocol with a login.
func (s *server) admitClient(ip netip.Addr) string {
	h := s.host
	return admit.Client(admit.Deps{
		Lists: h.ThreatIntel(),
		// A behaviour pack holding this address out, where one is.
		Quarantined: h.Packs().Quarantined,
		Policy:      h.Authorization(),
		Logs:        h.Logs(),
		Matched:     func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: s.cfg.Name,
		Kind:     "coap",
		Client:   ip,
		Target:   s.m.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !s.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("coap", reason)
			h.Shadow().Record("coap", s.cfg.Name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { s.deny(ip, reason, detail) },
	})
}

// deviceAddr picks the device to relay to.
func (s *server) deviceAddr(client netip.Addr) net.Addr {
	pool := s.host.Pool(s.m.Upstream)
	if pool == nil {
		return nil
	}
	e, _ := pool.Pick(client.String(), "", nil, 0)
	if e == nil {
		return nil
	}
	if ap, err := netip.ParseAddrPort(e.Address); err == nil {
		return net.UDPAddrFromAddrPort(ap)
	}
	ua, err := net.ResolveUDPAddr("udp", e.Address)
	if err != nil {
		return nil
	}
	return ua
}

func (s *server) forget(e *exchange) {
	s.pend.drop(e.key())
	s.obs.remove(e.key())
}

func addrPort(a net.Addr) netip.AddrPort {
	if ua, ok := a.(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func byteCount(n int) string {
	return itoa(n) + " octets"
}
