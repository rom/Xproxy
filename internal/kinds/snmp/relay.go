package snmp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/dtlsx"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessions"
	wire "github.com/rom/xproxy/internal/snmp"
	"github.com/rom/xproxy/internal/upstream"
)

// The datagram path. SNMP is a datagram protocol in practice: a request, an
// answer, no session, and nothing to close. So the relay keeps one socket
// towards the agents and matches answers to questions by request identifier,
// which is the only thing in the protocol that pairs them.

// peer is where a datagram came from and how an answer gets back to it.
//
// A plain datagram listener needs only the address: the answer goes to whatever
// the datagram claimed as its source, which is also why an unsolicited response
// on this protocol is an attack on the manager rather than a curiosity. Inside
// DTLS the answer goes into the session instead, and the session is also where
// the sender's identity came from -- so the two facts travel together, because
// a relay that knew who asked but answered somewhere else, or answered the
// right session under the wrong name, would be worse than one that knew
// neither.
type peer struct {
	ip   netip.Addr
	from net.Addr
	// transport is what a rule names, and what decides whether the message's
	// own claim of authPriv is a claim or a fact.
	transport Transport
	// name is RFC 6353 s5.3's tmSecurityName, derived from the session's
	// certificate; nameWhy is why there is none, as a stable label for a
	// counter and a refusal.
	name, nameWhy string
	// sess is the DTLS session to answer into, nil on a plain datagram.
	sess *dtlsx.Session
}

// write sends one message back to this peer: into its session where it has one,
// and to its address where it does not.
func (p *peer) write(t *server, b []byte) error {
	if p.sess != nil {
		_, err := p.sess.Write(b)
		return err
	}
	_, err := t.pc.WriteTo(b, p.from)
	return err
}

func (t *server) serveDatagrams() {
	agent, err := t.agentSocket()
	if err != nil {
		t.host.Logs().Error.Error("snmp agent socket could not be opened",
			"listener", t.cfg.Name, "error", err.Error())
		return
	}
	defer func() { _ = agent.Close() }()
	if t.running.Enter() {
		go func() {
			defer t.running.Leave()
			defer safe.Guard("snmp agent reader")
			t.readAgent(agent)
		}()
	}
	buf := make([]byte, t.maxMessage()+1)
	for {
		select {
		case <-t.done:
			return
		default:
		}
		_ = t.pc.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := t.pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			select {
			case <-t.done:
				return
			default:
			}
			return
		}
		if n > t.maxMessage() {
			// A datagram past the bound is refused unread: reading it to
			// find out what it asked for is the work the bound exists to
			// avoid.
			t.host.Counters().SNMPMalformed.Add(1)
			t.host.Counters().Refuse("snmp", "message_too_large")
			t.deny(netutil.AddrOf(from.String()), "snmp_message_too_large", "")
			continue
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		t.fromManager(agent, msg, t.plainPeer(from))
	}
}

// agentSocket opens the socket this relay speaks to agents on. One socket
// for the whole listener, because the request identifier is what pairs an
// answer with its question and a socket per exchange would be a file
// descriptor per poll.
func (t *server) agentSocket() (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), "udp", ":0")
}

// admitClient is the two questions this relay asks about a client that has no
// identity: do the imported lists know this address, and does the estate's
// authorisation policy allow it here.
//
// SNMP names a community or a USM user, and neither is an identity the estate
// can carry into a rule: a v1 or v2c community is a shared word travelling in
// clear, and a USM user is the agent's own account rather than a person's. So
// the policy decides on the address, the listener, the pool and the hour. Which
// operations and which subtrees that manager may touch is the `snmp` policy's own
// business, because it is the thing that can say what a set on sysName means.
//
// It is asked once per datagram, like this relay's own address lists, because a
// datagram relay has no session to hang the answer on. A refusal goes through
// deny, so a client that keeps sending earns a ban the same way one refused by
// the address lists does -- which is what stops the record from being written at
// packet rate.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists: h.ThreatIntel(),
		// A behaviour pack holding this address out, where one is.
		Quarantined: h.Packs().Quarantined,
		Policy:      h.Authorization(),
		Logs:        h.Logs(),
		Matched:     func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.cfg.Name,
		Kind:     "snmp",
		Client:   ip,
		Target:   t.m.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("snmp", reason)
			h.Shadow().Record("snmp", t.cfg.Name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// fromManager decides about one datagram from a manager and, when it is
// allowed, forwards it to an agent.
func (t *server) fromManager(agent net.PacketConn, raw []byte, p *peer) {
	s := t.host
	ip := p.ip
	s.Counters().SNMPMessages.Add(1)
	if !t.policy.Client(ip) {
		s.Counters().SNMPRejected.Add(1)
		s.Counters().Refuse("snmp", "client_not_allowed")
		t.deny(ip, "client_not_allowed", "")
		return
	}
	// The imported lists and the estate's authorisation policy, after this
	// listener's own address lists -- those are local policy about local
	// clients, and a feed must not overrule an allow rule an operator wrote --
	// and before the agent is spoken to.
	if reason := t.admitClient(ip); reason != "" {
		s.Counters().SNMPRejected.Add(1)
		s.Counters().Refuse("snmp", reason)
		return
	}
	// The rate limit is a bound rather than policy, so it is never shadowed:
	// a relay that let a flood through because its policy was in shadow mode
	// would be a relay with no bound at all.
	if t.limiter != nil && !t.limiter.Allow(ip.String()) {
		s.Counters().SNMPRateLimited.Add(1)
		s.Counters().Refuse("snmp", "rate_limited")
		return
	}
	m, err := wire.Parse(raw)
	if err != nil {
		s.Counters().SNMPMalformed.Add(1)
		s.Counters().Refuse("snmp", "malformed")
		t.deny(ip, "snmp_malformed", err.Error())
		return
	}
	// Version 3, with the user's keys: verified, decrypted where it can be,
	// and thereafter decided about like any other message. Before the
	// fabrication, because a forged digest is not a request to answer -- and
	// before count, because a decrypted payload is a read or a write and an
	// opaque one is neither.
	if v := t.inspect(m); !v.Allow {
		t.refused(ip, m, v)
		if t.enforcing() {
			if !t.deceive(m, p, v.Reason) {
				t.answerRefusal(m, p)
			}
			return
		}
	}
	// The transport model's own two checks, before the rules: a message whose
	// certificate maps to no name, and one whose flags disagree with the
	// session it arrived in. Both are about whether there is an identity to
	// decide about at all, which is a question that comes before what the
	// identity may do.
	if v := t.inspectTransport(m, p); !v.Allow {
		t.refused(ip, m, v)
		if t.enforcing() {
			t.answerRefusal(m, p)
			return
		}
	}
	t.count(m)
	// A listener that is nothing but a fabricated agent answers here, and
	// nothing is forwarded: there is no agent behind it to reach. The
	// client has already passed this listener's own address lists, the
	// imported feeds and the rate limit above.
	if dec := t.decoy; dec != nil && dec.whole && dec.admits(ip) {
		if t.deceive(m, p, "decoy") {
			return
		}
		// A message the fabrication has no answer for -- a version 3
		// message, or a notification -- is dropped, which is what an
		// address with nothing on it does.
		return
	}
	d := t.policy.Decide(t.request(ip, m, p))
	if !d.Allow {
		t.refused(ip, m, d)
		if t.enforcing() {
			// The fabrication answers instead, for the clients it covers,
			// and only here: this is the path where the request has
			// already been kept from the agent.
			if !t.deceive(m, p, d.Reason) {
				t.answerRefusal(m, p)
			}
			return
		}
	}
	// Engineering: a SET is a configuration change on this protocol. Reported
	// whatever the policy said, and refused where this listener requires an
	// approved grant for it.
	if reason := t.decideEngineering(t.request(ip, m, p)); reason != "" {
		if !t.deceive(m, p, reason) {
			t.answerRefusal(m, p)
		}
		return
	}
	// Behavioural detection, after the policy and on the messages that are
	// going on to the agent: the models learn from what reached it, and a
	// message the policy refused never got there.
	if reason := t.decideAnomaly(t.request(ip, m, p)); reason != "" {
		if !t.deceive(m, p, reason) {
			t.answerRefusal(m, p)
		}
		return
	}
	out := raw
	// The GETBULK bound is applied by *lowering* the repetition count rather
	// than by refusing the request. A poller asking for more than it should
	// get still gets an answer, which is what keeps this deployable -- and
	// the amplification is gone either way, which is what the bound is for.
	// The one shape that cannot be lowered is refused instead: see
	// lowerRepetitions.
	trimmed, lowered, refuse := t.lowerRepetitions(m, d)
	switch {
	case refuse:
		bound := Decision{Rule: d.Rule, Reason: "snmp_max_repetitions",
			Detail: itoa(int(m.PDU.MaxRepetitions))}
		s.Counters().SNMPAmplified.Add(1)
		t.refused(ip, m, bound)
		// Not shadowable: an amplification bound in shadow mode is a
		// working amplifier.
		t.answerRefusal(m, p)
		return
	case lowered:
		out = trimmed
		s.Counters().SNMPTruncated.Add(1)
	}
	// The agent is chosen before the slot is taken, so the slot records which
	// agent the question went to: on a datagram protocol the identifier alone
	// does not say whose answer this is.
	addr := t.agentAddr(ip)
	if addr == nil {
		s.Counters().SNMPUpstreamFail.Add(1)
		return
	}
	agentIP := netutil.AddrOf(addr.String())
	upgraded, changed, err := t.applyUpgrade(out, m)
	switch {
	case errors.Is(err, errOriginate):
		// The upgrade is to v3, which is originated rather than re-enveloped.
		// The pending slot is taken first, because a discovery's report has to
		// find this request waiting: it is the manager's question that the
		// relay will ask properly once it knows the agent's engine.
		if !t.hold(m, p, d, len(raw), agentIP) {
			return
		}
		t.originateUpstream(agent, m, ip, d)
		return
	case err != nil:
		s.Counters().Refuse("snmp", "upgrade_failed")
		t.deny(ip, "snmp_upgrade_failed", err.Error())
		return
	case changed:
		out = upgraded
		s.Counters().SNMPUpgraded.Add(1)
	}
	if !t.hold(m, p, d, len(raw), agentIP) {
		return
	}
	t.logMessage(ip, m, d, "manager")
	t.observeManager(ip, m)
	// One agent per message: SNMP has no fan-out, and a manager that asked
	// once expects one answer.
	if _, err := agent.WriteTo(out, addr); err != nil {
		s.Counters().SNMPUpstreamFail.Add(1)
		s.Logs().Error.Warn("snmp forward to agent failed", "listener", t.cfg.Name,
			"agent", addr.String(), "error", err.Error())
		// The request never left, so there is no answer coming and no
		// reason to hold its slot until the timeout: an operator reading
		// the outstanding count should see the requests that are actually
		// outstanding.
		t.forget(m)
	}
}

// forget releases the slot of a request this relay did not manage to send.
func (t *server) forget(m *wire.Message) {
	if m.PDU != nil && !m.PDU.Type.Notification() {
		t.pend.drop(m.PDU.RequestID)
	}
}

// agentAddr picks the agent a request goes to.
func (t *server) agentAddr(client netip.Addr) net.Addr {
	pool := t.host.Pool(t.m.Upstream)
	if pool == nil {
		return nil
	}
	e, _ := pool.Pick(client.String(), "", nil, upstream.CanaryAny)
	if e == nil {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", e.Address)
	if err != nil {
		return nil
	}
	return addr
}

// readAgent reads answers from agents and forwards them to the manager that
// asked, when one did.
func (t *server) readAgent(agent net.PacketConn) {
	buf := make([]byte, wire.MaxMessage)
	for {
		select {
		case <-t.done:
			return
		default:
		}
		_ = agent.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := agent.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		t.fromAgent(agent, raw, from)
	}
}

// fromAgent decides about one datagram from an agent.
func (t *server) fromAgent(agent net.PacketConn, raw []byte, from net.Addr) {
	s := t.host
	ip := netutil.AddrOf(from.String())
	m, err := wire.Parse(raw)
	if err != nil {
		s.Counters().SNMPMalformed.Add(1)
		s.Counters().Refuse("snmp", "malformed_response")
		t.deny(ip, "snmp_malformed_response", err.Error())
		return
	}
	// Version 3, with the keys, before the pairing below: an answer this relay
	// can decrypt is an answer it can pair, and an answer whose digest does not
	// check out is the response-spoofing attack the pairing exists to catch,
	// arriving with a forged credential.
	//
	// Which keys depends on who asked. Where this relay originated the request
	// as itself, the answer belongs to *its* USM session and is read with its
	// own keys; the manager's keys have nothing to do with it and would not
	// verify it. Where the request was forwarded, the answer is the manager's
	// and usm_users is what reads it.
	if t.orig != nil && m.Version == wire.V3 {
		if why, detail := t.orig.readAgentV3(m, from.String(), time.Now()); why != "" {
			s.Counters().Refuse("snmp", why)
			t.deny(ip, why, detail)
			if t.enforcing() {
				return
			}
		}
	} else if v := t.inspect(m); !v.Allow {
		t.refused(ip, m, v)
		if t.enforcing() {
			return
		}
	}
	if m.PDU == nil {
		// An encrypted v3 answer this listener holds no key for. There is no
		// request identifier to match it by, so there is nothing to forward
		// it to: a relay cannot pair an answer it cannot read. Configuring
		// the user's keys -- usm_users -- is what makes such an exchange work
		// end to end.
		s.Counters().SNMPUnsolicited.Add(1)
		s.Counters().Refuse("snmp", "encrypted_response")
		return
	}
	if m.PDU.Type != wire.Response && m.PDU.Type != wire.ReportPDU {
		// The upstream side of this relay answers questions; it does not
		// ask them. A request arriving from there is a datagram sent in the
		// wrong direction at best.
		s.Counters().SNMPUnsolicited.Add(1)
		s.Counters().Refuse("snmp", "wrong_direction")
		t.deny(ip, "snmp_wrong_direction", m.PDU.Type.String())
		return
	}
	if t.orig != nil && m.PDU.Type == wire.ReportPDU {
		// The answer to a discovery. The engine has been learned above, so the
		// manager's question -- still waiting in the table -- is now askable.
		// The report itself goes no further: the manager asked for data, not
		// for a statement about engine identifiers.
		if e, ok := t.pend.take(m.PDU.RequestID, ip, time.Now()); ok && len(e.pdu) > 0 {
			if t.resendAfterDiscovery(agent, e) {
				// Put the slot back: the same question is outstanding again,
				// and the answer that comes next is the one the manager gets.
				if !t.pend.add(e, time.Now()) {
					s.Counters().Refuse("snmp", "too_many_pending")
				}
			}
			return
		}
		s.Counters().SNMPUnsolicited.Add(1)
		s.Counters().Refuse("snmp", "unsolicited_response")
		return
	}
	e, ok := t.pend.take(m.PDU.RequestID, ip, time.Now())
	if !ok {
		// A response nobody asked for, or one that arrived after the manager
		// stopped waiting. On a datagram protocol the first is the shape of
		// a response-spoofing attack on the manager: an answer to a question
		// it did ask, from somewhere else, arriving first.
		s.Counters().SNMPUnsolicited.Add(1)
		s.Counters().Refuse("snmp", "unsolicited_response")
		if e == nil {
			t.deny(ip, "snmp_unsolicited_response", m.PDU.Type.String())
		} else {
			s.Counters().SNMPTimedOut.Add(1)
		}
		return
	}
	// The amplification bounds, on the way back. These are bounds rather
	// than policy and are never shadowed: a relay whose policy was in
	// shadow mode would otherwise be a working amplifier.
	if len(raw) > t.maxResponse() {
		s.Counters().SNMPAmplified.Add(1)
		s.Counters().Refuse("snmp", "response_too_large")
		t.deny(e.client, "snmp_response_too_large", itoa(len(raw)))
		return
	}
	if r := t.maxRatio(); r > 0 && e.asked > 0 && len(raw) > e.asked*r {
		// The bound that is about *reflection* rather than about size: a
		// large answer to a large question is a walk, and a large answer to
		// a tiny question is an amplifier.
		s.Counters().SNMPAmplified.Add(1)
		s.Counters().Refuse("snmp", "response_ratio")
		t.deny(e.client, "snmp_response_ratio", itoa(len(raw))+" for "+itoa(e.asked))
		return
	}
	out, restored := t.restore(raw, m, e)
	if restored {
		s.Counters().SNMPUpgraded.Add(1)
	}
	if err := e.answer(t, out); err != nil {
		s.Logs().Error.Warn("snmp answer to manager failed", "listener", t.cfg.Name,
			"client", e.client.String(), "error", err.Error())
	}
	t.logMessage(e.client, m, Decision{Allow: true, Rule: e.rule}, "agent")
	t.observeAgent(ip, m)
}

// The stream path. RFC 3430 puts SNMP on TCP with a length-delimited framing
// of its own -- which is to say none: a message is a BER SEQUENCE and its own
// length field delimits it. RFC 6353 wraps that in TLS on port 10161, which
// is the half of the secure upgrade that faces a management station.

func (t *server) handleStream(client net.Conn) {
	s := t.host
	start := time.Now()
	s.Counters().SNMPSessions.Add(1)
	s.Counters().SNMPSessionsOpen.Add(1)
	defer s.Counters().SNMPSessionsOpen.Add(-1)
	ip := netutil.AddrOf(client.RemoteAddr().String())
	// Opened before anything can refuse the session, because a refused session is
	// the one an operator most often wants and it never dials: after that point
	// there is nothing left to record. A nil tap wraps nothing and writes nothing.
	tap := t.host.Capture().Open("snmp", t.cfg.Name, "", client.RemoteAddr())
	defer tap.Close()
	var up net.Conn
	var pool *upstream.Pool
	var ep *upstream.Endpoint
	defer func() {
		if up != nil {
			_ = up.Close()
		}
		if ep != nil && pool != nil {
			pool.End(ep, false, 0)
		}
		_ = client.Close()
	}()
	if !t.policy.Client(ip) {
		s.Counters().SNMPRejected.Add(1)
		s.Counters().Refuse("snmp", "client_not_allowed")
		t.deny(ip, "client_not_allowed", "")
		tap.Deny("client_not_allowed")
		t.logSession(ip, start, false, "client_not_allowed")
		return
	}
	if reason := t.admitClient(ip); reason != "" {
		s.Counters().SNMPRejected.Add(1)
		s.Counters().Refuse("snmp", reason)
		tap.Deny(reason)
		t.logSession(ip, start, false, reason)
		return
	}
	live := s.Sessions().Register(sessions.Info{
		Kind: "snmp", Listener: t.cfg.Name, Client: client.RemoteAddr().String(),
	}, func() { _ = client.Close() })
	defer live.Done()
	tap.Name(live.ID)
	secure := false
	if t.m.TLSMode == "implicit" || (t.tlsCfg != nil && t.m.TLSMode == "") {
		tc := tls.Server(client, t.tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			s.Counters().Refuse("snmp", "tls_handshake")
			t.deny(ip, "tls_handshake", err.Error())
			tap.Deny("tls_handshake")
			t.logSession(ip, start, false, "tls_handshake")
			return
		}
		_ = tc.SetDeadline(time.Time{})
		client, secure = tc, true
	}
	// Wrapped after the handshake, so the capture holds SNMP rather than the TLS
	// records carrying it; on a listener with no certificate this is the socket.
	client = tap.Client(client)
	var err error
	up, pool, ep, err = t.dialAgent(ip)
	up = tap.Upstream(up)
	if err != nil {
		s.Counters().SNMPUpstreamFail.Add(1)
		tap.Deny("upstream_unavailable")
		t.logSession(ip, start, secure, "upstream_unavailable")
		return
	}
	if t.m.ProxyProtocol {
		if _, err := up.Write(netutil.ProxyV2Header(client.RemoteAddr(), client.LocalAddr())); err != nil {
			tap.Deny("proxy_header")
			t.logSession(ip, start, secure, "proxy_header")
			return
		}
	}
	if t.upTLS != nil {
		c := t.upTLS.Clone()
		if c.ServerName == "" && !c.InsecureSkipVerify {
			host, _, err := net.SplitHostPort(ep.Address)
			if err != nil {
				host = ep.Address
			}
			c.ServerName = host
		}
		tc := tls.Client(up, c)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			s.Counters().Refuse("snmp", "upstream_tls")
			tap.Deny("upstream_tls")
			t.logSession(ip, start, secure, "upstream_tls")
			return
		}
		up = tc
	}
	if ep != nil {
		live.Annotate("", ep.Address, "")
	}
	// Not tap.Deny: this reason is how the stream ended, and a session that ran
	// and then closed was not turned away. The refusals this kind makes about
	// individual messages reach the tap through deny, as everywhere else.
	reason := t.pumpStream(client, up, t.streamPeer(client, secure))
	t.logSession(ip, start, secure, reason)
}

// pumpStream relays a stream session in both directions, deciding about
// every message.
func (t *server) pumpStream(client, up net.Conn, p *peer) string {
	var wg sync.WaitGroup
	reasons := make(chan string, 2)
	stop := func() {
		_ = client.Close()
		_ = up.Close()
	}
	// The session's own table of outstanding requests. A stream cannot be
	// spoofed the way a datagram can, but the pairing is still what says an
	// answer belongs to a question -- and it is what carries the version
	// the manager asked in back to the answer it gets.
	pend := newPending(t.maxPending(), t.requestTimeout())
	pend.onChange = t.publishPending
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("snmp manager reader")
		reasons <- t.pumpOne(client, up, p, true, pend)
		stop()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("snmp agent reader")
		reasons <- t.pumpOne(up, client, p, false, pend)
		stop()
	}()
	wg.Wait()
	close(reasons)
	first := ""
	for r := range reasons {
		if r != "" && (first == "" || first == "closed") {
			first = r
		}
	}
	return first
}

// pumpOne reads messages from one side and writes what is allowed to the
// other.
func (t *server) pumpOne(src, dst net.Conn, p *peer, fromManager bool, pend *pending) string {
	s := t.host
	ip := p.ip
	rd := newStreamReader(src, t.maxMessage())
	for {
		_ = src.SetReadDeadline(time.Now().Add(t.idleTimeout()))
		raw, err := rd.next()
		if err != nil {
			if reason := t.readError(err, ip, fromManager); reason != "" {
				return reason
			}
			return "closed"
		}
		s.Counters().SNMPMessages.Add(1)
		m, perr := wire.Parse(raw)
		if perr != nil {
			s.Counters().SNMPMalformed.Add(1)
			s.Counters().Refuse("snmp", "malformed")
			t.deny(ip, "snmp_malformed", perr.Error())
			return "snmp_malformed"
		}
		if v := t.inspect(m); !v.Allow {
			t.refused(ip, m, v)
			if t.enforcing() {
				if fromManager && t.m.DenyResponse == "close" {
					return v.Reason
				}
				if fromManager && (t.m.DenyResponse == "" || t.m.DenyResponse == "error") {
					if answer := refusalFor(m); answer != nil {
						_, _ = src.Write(answer)
					}
				}
				if !fromManager {
					// A forged or replayed answer from the upstream side ends
					// the session: on a stream there is one peer, and a peer
					// that sent one is not a peer to carry on reading from.
					return v.Reason
				}
				continue
			}
		}
		if fromManager {
			// The transport model's own checks, on the stream side too: RFC
			// 6353 is TLS over TCP as much as DTLS over UDP, and a listener
			// that checked the identity on one transport and not the other
			// would be a listener with a door in it.
			if v := t.inspectTransport(m, p); !v.Allow {
				t.refused(ip, m, v)
				if t.enforcing() {
					if t.m.DenyResponse == "close" {
						return v.Reason
					}
					if answer := refusalFor(m); answer != nil {
						_, _ = src.Write(answer)
					}
					continue
				}
			}
		}
		t.count(m)
		out := raw
		if fromManager {
			if t.limiter != nil && !t.limiter.Allow(ip.String()) {
				s.Counters().SNMPRateLimited.Add(1)
				s.Counters().Refuse("snmp", "rate_limited")
				continue
			}
			d := t.policy.Decide(t.request(ip, m, p))
			if !d.Allow {
				t.refused(ip, m, d)
				if t.enforcing() {
					if t.m.DenyResponse == "close" {
						return d.Reason
					}
					if t.m.DenyResponse == "" || t.m.DenyResponse == "error" {
						if answer := refusalFor(m); answer != nil {
							_, _ = src.Write(answer)
						}
					}
					continue
				}
			}
			trimmed, lowered, refuse := t.lowerRepetitions(m, d)
			switch {
			case refuse:
				bound := Decision{Rule: d.Rule, Reason: "snmp_max_repetitions",
					Detail: itoa(int(m.PDU.MaxRepetitions))}
				s.Counters().SNMPAmplified.Add(1)
				t.refused(ip, m, bound)
				if answer := refusalFor(m); answer != nil {
					_, _ = src.Write(answer)
				}
				continue
			case lowered:
				out = trimmed
				s.Counters().SNMPTruncated.Add(1)
			}
			if upgraded, changed, err := t.applyUpgrade(out, m); err != nil {
				s.Counters().Refuse("snmp", "upgrade_failed")
				t.deny(ip, "snmp_upgrade_failed", err.Error())
				continue
			} else if changed {
				out = upgraded
				s.Counters().SNMPUpgraded.Add(1)
			}
			if !m.PDU.Type.Notification() {
				e := &exchange{client: ip, requestID: m.PDU.RequestID, asked: len(raw),
					rule: d.Rule, version: m.Version, community: m.Community,
					tsm: echoOf(m)}
				if !pend.add(e, time.Now()) {
					s.Counters().Refuse("snmp", "too_many_pending")
					t.deny(ip, "snmp_too_many_pending", "")
					continue
				}
			}
			t.logMessage(ip, m, d, "manager")
			t.observeManager(ip, m)
		} else {
			if len(raw) > t.maxResponse() {
				// On a stream there is no reflection -- the connection was
				// established -- but the size bound is still what stops one
				// answer filling a manager's buffer.
				s.Counters().SNMPAmplified.Add(1)
				s.Counters().Refuse("snmp", "response_too_large")
				t.deny(ip, "snmp_response_too_large", itoa(len(raw)))
				return "snmp_response_too_large"
			}
			if m.PDU.Type != wire.Response && m.PDU.Type != wire.ReportPDU {
				// The upstream side answers questions; it does not ask
				// them.
				s.Counters().SNMPUnsolicited.Add(1)
				s.Counters().Refuse("snmp", "wrong_direction")
				t.deny(ip, "snmp_wrong_direction", m.PDU.Type.String())
				return "snmp_wrong_direction"
			}
			// No address to match on a stream: the connection was established,
			// so an answer arriving on it came from the agent it was asked of.
			e, ok := pend.take(m.PDU.RequestID, netip.Addr{}, time.Now())
			if !ok {
				s.Counters().SNMPUnsolicited.Add(1)
				if e == nil {
					s.Counters().Refuse("snmp", "unsolicited_response")
					t.deny(ip, "snmp_unsolicited_response", m.PDU.Type.String())
					return "snmp_unsolicited_response"
				}
				s.Counters().SNMPTimedOut.Add(1)
				s.Counters().Refuse("snmp", "response_too_late")
				continue
			}
			var restored bool
			if out, restored = t.restore(raw, m, e); restored {
				s.Counters().SNMPUpgraded.Add(1)
			}
			t.logMessage(ip, m, Decision{Allow: true, Rule: e.rule}, "agent")
		}
		if _, err := dst.Write(out); err != nil {
			return "closed"
		}
	}
}

// readError turns a reader failure into a reason, or the empty string for an
// ordinary end of connection.
func (t *server) readError(err error, ip netip.Addr, fromManager bool) string {
	switch {
	case errors.Is(err, errTooLong):
		t.host.Counters().SNMPMalformed.Add(1)
		t.host.Counters().Refuse("snmp", "message_too_large")
		t.deny(ip, "snmp_message_too_large", "")
		return "snmp_message_too_large"
	case errors.Is(err, errFraming):
		from := "manager"
		if !fromManager {
			from = "agent"
		}
		t.host.Counters().SNMPMalformed.Add(1)
		t.host.Counters().Refuse("snmp", "framing")
		t.deny(ip, "snmp_framing", from)
		return "snmp_framing"
	}
	return ""
}

// itoa formats a small non-negative number without a strconv import in the
// hot path.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 && i > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
