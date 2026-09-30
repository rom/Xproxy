package dhcp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	wire "github.com/rom/xproxy/internal/dhcp"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

// The data path. Two sockets: the one the engine bound on port 67, which faces
// the segment, and one of this relay's own facing the servers. A reply is
// matched to the request that asked for it by transaction identifier and
// hardware address together, which on a protocol with no session is the only
// thing that makes a reply deliverable at all.

func (s *server) serveMessages() {
	up, err := s.serverSocket()
	if err != nil {
		s.host.Logs().Error.Error("dhcp server socket could not be opened",
			"listener", s.cfg.Name, "error", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	if !s.running.Enter() {
		// Shut down before it started, which a reload can do.
		return
	}
	defer s.running.Leave()
	if s.running.Enter() {
		go func() {
			defer s.running.Leave()
			defer safe.Guard("dhcp server reader")
			s.readServers(up)
		}()
	}
	if s.running.Enter() {
		go func() {
			defer s.running.Leave()
			defer safe.Guard("dhcp pending sweep")
			s.sweepPending()
		}()
	}
	buf := make([]byte, wire.MaxPacket+1)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		_ = s.pc.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if n > s.maxMessage() {
			// Past the bound, so it is refused unread: reading it to find out
			// what it asked for is the work the bound exists to avoid.
			s.host.Counters().DHCPMalformed.Add(1)
			s.host.Counters().Refuse("dhcp", "message_too_large")
			s.deny(netutil.AddrOf(from.String()), "message_too_large", itoa(n))
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		s.fromClient(up, raw, from)
	}
}

// sweepPending expires the requests nobody answered, so the gauge an operator
// reads does not sit at whatever the last busy moment said.
func (s *server) sweepPending() {
	every := s.requestTimeout() / 2
	if every < 250*time.Millisecond {
		every = 250 * time.Millisecond
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.pend.sweep(now)
		}
	}
}

// serverSocket opens the socket this relay speaks to servers on. One socket for
// the listener, because the transaction identifier and hardware address are
// what pair a reply with its request and a socket per exchange would be a file
// descriptor per boot.
func (s *server) serverSocket() (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), "udp4", ":0")
}

// admitClient is the two questions this relay asks about a client that has no
// identity: do the imported lists know this address, and does the estate's
// authorisation policy allow it here.
//
// It is worth being plain about how little the address is worth on this one. A
// client that has no lease yet sends from 0.0.0.0 -- that is what DHCP is for --
// so a rule naming networks decides nothing about exactly the clients an operator
// most wants to think about, and the imported lists have nothing to match. What
// does decide here is the listener, the pool, the action and the hour: "this
// segment is not relayed outside working hours" is a real rule, and it is the
// shape a rule on this kind should take. What a client may ask for once it is
// through is the `dhcp` policy's own business, which decides on the hardware
// address and the message type -- the fields that actually name a device.
//
// It is asked once per message from the segment, like this relay's own address
// lists, because DHCP has no session to hang the answer on.
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
		Kind:     "dhcp",
		Client:   ip,
		Target:   s.m.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !s.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("dhcp", reason)
			h.Shadow().Record("dhcp", s.cfg.Name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { s.deny(ip, reason, detail) },
	})
}

// fromClient decides about one message from the segment and, when it is
// allowed, relays it to a server.
func (s *server) fromClient(up net.PacketConn, raw []byte, from net.Addr) {
	c := s.host.Counters()
	ip := netutil.AddrOf(from.String())
	c.DHCPMessages.Add(1)
	if !s.policy.Client(ip) {
		c.DHCPRejected.Add(1)
		c.Refuse("dhcp", "client_not_allowed")
		s.deny(ip, "client_not_allowed", "")
		return
	}
	// The imported lists and the estate's authorisation policy, after this
	// listener's own address lists -- those are local policy about local
	// clients, and a feed must not overrule an allow rule an operator wrote --
	// and before anything reaches a server.
	if reason := s.admitClient(ip); reason != "" {
		c.DHCPRejected.Add(1)
		c.Refuse("dhcp", reason)
		return
	}
	m, err := wire.Parse(raw)
	if err != nil {
		c.DHCPMalformed.Add(1)
		c.Refuse("dhcp", "malformed")
		s.deny(ip, "malformed", err.Error())
		return
	}
	if m.Op != wire.BootRequest || !m.Type.FromClient() {
		// A reply arriving on the segment side. This is what a rogue server
		// on the same segment as the relay looks like from here, and it is
		// worth its own counter: the relay is not the only thing the clients
		// can hear.
		c.DHCPUnsolicited.Add(1)
		c.Refuse("dhcp", "reply_from_client_side")
		s.deny(ip, "reply_from_client_side", m.Type.String())
		return
	}
	switch m.Type {
	case wire.Discover:
		c.DHCPDiscovers.Add(1)
	case wire.Request:
		c.DHCPRequests.Add(1)
	case wire.Release:
		c.DHCPReleases.Add(1)
	}
	// The starvation bound, keyed on the hardware address rather than the
	// source address: exhaustion is one host sending thousands of discovers
	// with a made-up address in each. It is a bound, so it is never shadowed.
	if s.limiter != nil && !s.limiter.Allow(wire.HardwareAddr(m.CHAddr)) {
		c.DHCPRateLimited.Add(1)
		c.Refuse("dhcp", "rate_limited")
		return
	}
	c.DHCPClients.Store(int64(s.pend.len()))
	if m.Hops >= s.maxHops() {
		// A bound: the hop count says how many relay agents this message has
		// crossed, and a message arriving with a large one has been somewhere.
		c.Refuse("dhcp", "too_many_hops")
		s.deny(ip, "too_many_hops", itoa(int(m.Hops)))
		return
	}
	req := request{from: ip, msg: m, at: time.Now()}
	d := s.policy.Decide(req)
	if !d.Allow {
		s.refused(ip, m, d, "client")
		if s.enforcing() || d.Hard {
			s.nak(m, from)
			return
		}
	}
	out, err := s.rewrite(m, d, ip)
	if err != nil {
		c.Refuse("dhcp", "unencodable")
		s.deny(ip, "unencodable", err.Error())
		return
	}
	// RELEASE and DECLINE are told to the server and answered by nobody, so
	// there is nothing to pair them with and no slot to spend.
	if m.Type != wire.Release && m.Type != wire.Decline {
		e := &exchange{client: addrPort(from), hw: m.CHAddr, xid: m.XID,
			rule: d.Rule, broadcast: broadcastReply(m, ip)}
		if v, ok := m.Get(wire.OptParameterList); ok {
			e.asked = append([]byte(nil), v...)
		}
		if !s.pend.add(e, time.Now()) {
			// The table is full of requests nobody answered. Refusing keeps
			// the pairing reliable, and the pairing is what makes a reply
			// deliverable to the client that asked rather than to whichever
			// one is guessed.
			c.Refuse("dhcp", "too_many_pending")
			s.deny(ip, "too_many_pending", "")
			return
		}
	}
	s.logMessage(ip, m, d, "client", "allow")
	s.observeRequest(m, ip)
	addr := s.serverAddr(ip)
	if addr == nil {
		c.DHCPUpstreamFail.Add(1)
		s.forget(m)
		return
	}
	if _, err := up.WriteTo(out, addr); err != nil {
		c.DHCPUpstreamFail.Add(1)
		s.host.Logs().Error.Warn("dhcp relay to server failed", "listener", s.cfg.Name,
			"server", addr.String(), "error", err.Error())
		s.forget(m)
	}
}

// rewrite is the relay agent's own work: RFC 2131 §4.1.1 fills in giaddr and
// increments hops, and RFC 3046 §2.1 discards a client's agent information and
// adds the relay's own.
//
// A client has no business asserting which circuit it is on, because that
// assertion is exactly what the option exists to make on its behalf -- so what
// arrives from a client is removed whatever it said, and what leaves says what
// this relay knows.
func (s *server) rewrite(m *wire.Message, d Decision, ip netip.Addr) ([]byte, error) {
	out := m.Clone()
	if out.Hops < 255 {
		out.Hops++
	}
	if relay, err := netip.ParseAddr(s.m.RelayAddress); err == nil && relay.Is4() {
		if out.GIAddr.IsUnspecified() {
			// Only when it is empty: a downstream relay agent's own address is
			// where the reply has to go back to, and overwriting it would
			// strand every client behind it.
			out.GIAddr = relay
		}
	}
	if out.Remove(wire.OptRelayAgent) {
		s.host.Counters().DHCPStripped.Add(1)
		s.host.Counters().Refuse("dhcp", "client_agent_option")
		s.deny(ip, "client_agent_option", wire.HardwareAddr(m.CHAddr))
	}
	circuit := s.policy.CircuitFor(d.Rule, s.m.CircuitID)
	if circuit != "" || s.m.RemoteID != "" {
		v, err := wire.AgentInfo(circuit, s.m.RemoteID)
		if err != nil {
			return nil, err
		}
		out.Set(wire.OptRelayAgent, v)
	}
	// The client's own parameter list: an option it may not ask for is removed
	// from the ask rather than the message refused, because a client that
	// asked for a proxy and is not told about one is a client that works.
	if v, ok := out.Get(wire.OptParameterList); ok {
		trimmed, removed := s.policy.AskDenied(v)
		if len(removed) > 0 {
			out.Set(wire.OptParameterList, trimmed)
			s.host.Counters().DHCPStripped.Add(1)
			s.logAsk(ip, m, removed)
		}
	}
	return wire.Encode(out)
}

// readServers reads replies and forwards them to the client that asked.
func (s *server) readServers(up net.PacketConn) {
	buf := make([]byte, wire.MaxPacket+1)
	for {
		select {
		case <-s.done:
			return
		default:
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
		if n > s.maxMessage() {
			s.host.Counters().DHCPMalformed.Add(1)
			s.host.Counters().Refuse("dhcp", "reply_too_large")
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		s.fromServer(raw, from)
	}
}

// fromServer decides about one reply.
func (s *server) fromServer(raw []byte, from net.Addr) {
	c := s.host.Counters()
	ip := netutil.AddrOf(from.String())
	// The rogue-server check, before anything is read. Every switch vendor
	// sells this as DHCP snooping with a trusted port; here it is an address
	// list, and it is never shadowed: a listener that evaluated the list
	// without enforcing it would be a listener that relays a rogue server's
	// answer and writes it down.
	if !s.policy.Server(ip) {
		c.DHCPRogue.Add(1)
		c.Refuse("dhcp", "rogue_server")
		s.deny(ip, "rogue_server", "")
		return
	}
	m, err := wire.Parse(raw)
	if err != nil {
		c.DHCPMalformed.Add(1)
		c.Refuse("dhcp", "malformed_reply")
		s.deny(ip, "malformed_reply", err.Error())
		return
	}
	c.DHCPReplies.Add(1)
	e, ok := s.pend.take(key{xid: m.XID, hw: string(m.CHAddr)}, time.Now())
	if !ok {
		// A reply nobody asked for, or one that arrived after the client
		// stopped waiting. On a protocol with no session the first is the
		// shape of an answer aimed at a client this relay is not serving.
		c.DHCPUnsolicited.Add(1)
		c.Refuse("dhcp", "unsolicited_reply")
		s.deny(ip, "unsolicited_reply", m.Type.String())
		return
	}
	d := s.policy.Answer(request{from: ip, msg: m, at: time.Now()}, e.rule)
	if !d.Allow {
		s.refused(ip, m, d, "server")
		if s.enforcing() || d.Hard {
			return
		}
	}
	out := m.Clone()
	if len(d.Strip) > 0 {
		if !s.policy.StripDenied() {
			// on_denied_option: deny. The whole reply goes, which leaves the
			// client with no address -- which is why it is not the default.
			s.refused(ip, m, Decision{Rule: d.Rule, Reason: "option_denied",
				Detail: stripDetail(d)}, "server")
			if s.enforcing() {
				return
			}
		} else {
			for _, code := range d.Strip {
				if out.Remove(code) {
					c.DHCPStripped.Add(1)
				}
			}
			s.logStripped(e, m, d)
		}
	}
	if d.Bounded {
		out.Set(wire.OptLeaseTime, seconds(d.Lease))
	}
	// The relay's own agent option does not travel on to the client: RFC 3046
	// §2.2 says the relay removes what it added before forwarding the reply,
	// because it is a note between the relay and the server.
	out.Remove(wire.OptRelayAgent)
	// giaddr is the relay's own address and means nothing to the client.
	out.GIAddr = netip.AddrFrom4([4]byte{})
	out.Hops = 0
	raw2, err := wire.Encode(out)
	if err != nil {
		c.Refuse("dhcp", "unencodable_reply")
		s.deny(ip, "unencodable_reply", err.Error())
		return
	}
	if m.Type.Assigns() {
		c.DHCPLeases.Add(1)
		s.logLease(e, m, d, ip)
		s.observeLease(m, ip)
	}
	if m.Type == wire.Ack || m.Type == wire.Nak {
		// The exchange is over. A NAK ends it as surely as an ACK, and the
		// slot should not wait for the timeout.
		s.pend.drop(key{xid: m.XID, hw: string(m.CHAddr)})
	}
	to := net.UDPAddrFromAddrPort(e.client)
	if e.broadcast {
		// The client has no address yet, so there is nowhere to unicast to:
		// RFC 2131 §4.1 says the reply goes to the broadcast address on the
		// client's port. This needs a route for 255.255.255.255 on the
		// listener's own interface, which is a deployment matter the
		// documentation says plainly.
		to = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	}
	if _, err := s.pc.WriteTo(raw2, to); err != nil {
		s.host.Logs().Error.Warn("dhcp reply to client failed", "listener", s.cfg.Name,
			"client", to.String(), "error", err.Error())
	}
}

// broadcastReply says whether a reply has to go to the segment rather than to
// the address the request came from.
//
// Both conditions matter. A client that sent from 0.0.0.0 has no address to
// unicast to, whatever its flags say; a client that set the broadcast flag has
// asked for one, and RFC 2131 §4.1 says to honour it. A request relayed from
// another agent, or a renewal from a client that already has an address, is
// answered where it came from.
func broadcastReply(m *wire.Message, from netip.Addr) bool {
	if m.Relayed() {
		return false
	}
	return from.IsUnspecified() || (m.Broadcast() && m.CIAddr.IsUnspecified())
}

// forget releases the slot of a request this relay did not manage to send.
func (s *server) forget(m *wire.Message) {
	s.pend.drop(key{xid: m.XID, hw: string(m.CHAddr)})
}

// serverAddr picks the server a message goes to.
func (s *server) serverAddr(client netip.Addr) net.Addr {
	pool := s.host.Pool(s.m.Upstream)
	if pool == nil {
		return nil
	}
	e, _ := pool.Pick(client.String(), "", nil, upstream.CanaryAny)
	if e == nil {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp4", e.Address)
	if err != nil {
		return nil
	}
	return addr
}

// nak answers a refused request, when the listener is configured to.
//
// The default is to say nothing: a client that hears no answer retries, which
// is what it does anyway when no server is listening, and a NAK is a way to
// stop a client dead. An operator who wants the honest answer asks for it.
func (s *server) nak(m *wire.Message, to net.Addr) {
	if !s.naking() || m.Type != wire.Request {
		// Only a REQUEST has an answer that means no. A DISCOVER's refusal is
		// silence, because DHCPNAK is defined as the answer to a request for a
		// particular address.
		return
	}
	out := &wire.Message{Op: wire.BootReply, HType: m.HType, XID: m.XID,
		Flags: m.Flags, CHAddr: m.CHAddr, Type: wire.Nak,
		GIAddr: netip.AddrFrom4([4]byte{})}
	out.Set(wire.OptMessage, []byte("refused by policy"))
	raw, err := wire.Encode(out)
	if err != nil {
		return
	}
	_, _ = s.pc.WriteTo(raw, to)
}

func addrPort(a net.Addr) netip.AddrPort {
	if u, ok := a.(*net.UDPAddr); ok {
		if ap := u.AddrPort(); ap.IsValid() {
			return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		}
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

func seconds(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
