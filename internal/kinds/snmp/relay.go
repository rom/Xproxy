package snmp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

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
		t.fromManager(agent, msg, from)
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

// fromManager decides about one datagram from a manager and, when it is
// allowed, forwards it to an agent.
func (t *server) fromManager(agent net.PacketConn, raw []byte, from net.Addr) {
	s := t.host
	ip := netutil.AddrOf(from.String())
	s.Counters().SNMPMessages.Add(1)
	if !t.policy.Client(ip) {
		s.Counters().SNMPRejected.Add(1)
		s.Counters().Refuse("snmp", "client_not_allowed")
		t.deny(ip, "client_not_allowed", "")
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
	t.count(m)
	d := t.policy.Decide(request{client: ip, msg: m})
	if !d.Allow {
		t.refused(ip, m, d)
		if t.enforcing() {
			t.answerRefusal(m, from)
			return
		}
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
		t.answerRefusal(m, from)
		return
	case lowered:
		out = trimmed
		s.Counters().SNMPTruncated.Add(1)
	}
	if upgraded, changed, err := t.applyUpgrade(out, m); err != nil {
		s.Counters().Refuse("snmp", "upgrade_failed")
		t.deny(ip, "snmp_upgrade_failed", err.Error())
		return
	} else if changed {
		out = upgraded
		s.Counters().SNMPUpgraded.Add(1)
	}
	if m.PDU != nil && !m.PDU.Type.Notification() {
		e := &exchange{client: ip, from: from, requestID: m.PDU.RequestID,
			asked: len(raw), rule: d.Rule, version: m.Version, community: m.Community}
		if !t.pend.add(e, time.Now()) {
			// The table is full of requests nobody answered. Refusing here
			// keeps the answer matching reliable, and that matching is the
			// check that finds an unsolicited response rather than a
			// convenience.
			s.Counters().Refuse("snmp", "too_many_pending")
			t.deny(ip, "snmp_too_many_pending", "")
			return
		}
	}
	t.logMessage(ip, m, d, "manager")
	t.observeManager(ip, m)
	// One agent per message: SNMP has no fan-out, and a manager that asked
	// once expects one answer.
	addr := t.agentAddr(ip)
	if addr == nil {
		s.Counters().SNMPUpstreamFail.Add(1)
		t.forget(m)
		return
	}
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
		t.fromAgent(raw, from)
	}
}

// fromAgent decides about one datagram from an agent.
func (t *server) fromAgent(raw []byte, from net.Addr) {
	s := t.host
	ip := netutil.AddrOf(from.String())
	m, err := wire.Parse(raw)
	if err != nil {
		s.Counters().SNMPMalformed.Add(1)
		s.Counters().Refuse("snmp", "malformed_response")
		t.deny(ip, "snmp_malformed_response", err.Error())
		return
	}
	if m.PDU == nil {
		// An encrypted v3 answer. There is no request identifier to match
		// it by, so there is nothing to forward it to: a relay cannot pair
		// an answer it cannot read.
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
	e, ok := t.pend.take(m.PDU.RequestID, time.Now())
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
	if _, err := t.pc.WriteTo(out, e.from); err != nil {
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
		t.logSession(ip, start, false, "client_not_allowed")
		return
	}
	live := s.Sessions().Register(sessions.Info{
		Kind: "snmp", Listener: t.cfg.Name, Client: client.RemoteAddr().String(),
	}, func() { _ = client.Close() })
	defer live.Done()
	secure := false
	if t.m.TLSMode == "implicit" || (t.tlsCfg != nil && t.m.TLSMode == "") {
		tc := tls.Server(client, t.tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			s.Counters().Refuse("snmp", "tls_handshake")
			t.deny(ip, "tls_handshake", err.Error())
			t.logSession(ip, start, false, "tls_handshake")
			return
		}
		_ = tc.SetDeadline(time.Time{})
		client, secure = tc, true
	}
	var err error
	up, pool, ep, err = t.dialAgent(ip)
	if err != nil {
		s.Counters().SNMPUpstreamFail.Add(1)
		t.logSession(ip, start, secure, "upstream_unavailable")
		return
	}
	if t.m.ProxyProtocol {
		if _, err := up.Write(netutil.ProxyV2Header(client.RemoteAddr(), client.LocalAddr())); err != nil {
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
			t.logSession(ip, start, secure, "upstream_tls")
			return
		}
		up = tc
	}
	if ep != nil {
		live.Annotate("", ep.Address, "")
	}
	reason := t.pumpStream(client, up, ip)
	t.logSession(ip, start, secure, reason)
}

// pumpStream relays a stream session in both directions, deciding about
// every message.
func (t *server) pumpStream(client, up net.Conn, ip netip.Addr) string {
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
		reasons <- t.pumpOne(client, up, ip, true, pend)
		stop()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("snmp agent reader")
		reasons <- t.pumpOne(up, client, ip, false, pend)
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
func (t *server) pumpOne(src, dst net.Conn, ip netip.Addr, fromManager bool, pend *pending) string {
	s := t.host
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
		t.count(m)
		out := raw
		if fromManager {
			if t.limiter != nil && !t.limiter.Allow(ip.String()) {
				s.Counters().SNMPRateLimited.Add(1)
				s.Counters().Refuse("snmp", "rate_limited")
				continue
			}
			d := t.policy.Decide(request{client: ip, msg: m})
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
					rule: d.Rule, version: m.Version, community: m.Community}
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
			e, ok := pend.take(m.PDU.RequestID, time.Now())
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
