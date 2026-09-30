package dhcp6

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	wire "github.com/rom/xproxy/internal/dhcp6"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
)

// The two paths: from the segment towards a server, and from a server back to
// the client that asked.
//
// The second is the interesting one, and it is the one with the server list, the
// option policy, the prefix bound and the lifetime bound on it. A DHCPv6 reply is
// a configuration, and this is where an estate says which configurations its
// machines may be given.

func (s *server) serveMessages() {
	up, err := s.serverSocket()
	if err != nil {
		s.host.Logs().Error.Error("dhcp6 server socket could not be opened",
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
			defer safe.Guard("dhcp6 server reader")
			s.readServers(up)
		}()
	}
	if s.running.Enter() {
		go func() {
			defer s.running.Leave()
			defer safe.Guard("dhcp6 pending sweep")
			s.sweepPending()
		}()
	}
	buf := make([]byte, wire.MaxMessage+1)
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
			s.host.Counters().DHCP6Malformed.Add(1)
			s.host.Counters().Refuse("dhcp6", "message_too_large")
			s.deny(netutil.AddrOf(from.String()), "message_too_large", strconv.Itoa(n))
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

// serverSocket opens the socket this relay speaks to servers on.
//
// One socket for the listener, because the transaction identifier and the client
// identifier are what pair a reply with its request, and a socket per exchange
// would be a file descriptor per boot.
// The family is left unspecified rather than pinned to udp6, which on a
// dual-stack host is the same socket -- a wildcard listen gives an AF_INET6
// socket that is not v6-only -- and on a host without IPv6 is a socket that
// exists. That matters because it is what lets this relay be exercised end to
// end where there is no IPv6 to exercise it over, and a check that cannot be
// tested is a check that stops being true without anybody noticing.
func (s *server) serverSocket() (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), "udp", ":0")
}

// admitClient is the two questions this relay asks about a client that has no
// identity yet: do the imported lists know this address, and does the estate's
// authorisation policy allow it here.
//
// It is worth being plain about how little the address is worth. A DHCPv6 client
// sends from a link-local address it chose for itself, so a rule naming networks
// decides very little about the clients an operator most wants to think about,
// and the imported lists have nothing useful to match: a link-local address is
// not in anybody's threat feed. What does decide here is the listener, the pool,
// the action and the hour. What a client may ask for once it is through is this
// kind's own policy, which decides on the DUID and the message type -- the
// fields that name a device.
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
		Kind:     "dhcp6",
		Client:   ip,
		Target:   s.m.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !s.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("dhcp6", reason)
			h.Shadow().Record("dhcp6", s.cfg.Name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { s.deny(ip, reason, detail) },
	})
}

// fromClient decides about one message from the segment and, when it is allowed,
// wraps it and relays it to a server.
func (s *server) fromClient(up net.PacketConn, raw []byte, from net.Addr) {
	c := s.host.Counters()
	ip := netutil.AddrOf(from.String())
	c.DHCP6Messages.Add(1)
	if !s.policy.Client(ip) {
		c.DHCP6Rejected.Add(1)
		c.Refuse("dhcp6", "client_not_allowed")
		s.deny(ip, "client_not_allowed", "")
		return
	}
	// The imported lists and the estate's authorisation policy, after this
	// listener's own address lists -- those are local policy about local
	// clients, and a feed must not overrule an allow rule an operator wrote --
	// and before anything reaches a server.
	if reason := s.admitClient(ip); reason != "" {
		c.DHCP6Rejected.Add(1)
		c.Refuse("dhcp6", reason)
		return
	}
	m, err := wire.Parse(raw)
	if err != nil {
		c.DHCP6Malformed.Add(1)
		c.Refuse("dhcp6", "malformed")
		s.deny(ip, "malformed", err.Error())
		return
	}
	if hops := relayDepth(m); hops >= s.maxHops() {
		// A bound. The hop count says how many relay agents the message has
		// crossed, and one arriving already wrapped several times has been
		// somewhere.
		c.Refuse("dhcp6", "too_many_hops")
		s.deny(ip, "too_many_hops", strconv.Itoa(int(hops)))
		return
	}
	in := m.Innermost()
	switch in.Type {
	case wire.Solicit:
		c.DHCP6Solicits.Add(1)
	case wire.Request:
		c.DHCP6Requests.Add(1)
	case wire.Release, wire.Decline:
		c.DHCP6Releases.Add(1)
	}
	// The starvation bound, keyed on the identifier rather than the source
	// address: exhaustion is one host sending thousands of solicits with a
	// made-up identifier in each. It is a bound, so it is never shadowed.
	if s.limiter != nil && !s.limiter.Allow(duidOf(m)) {
		c.DHCP6RateLimited.Add(1)
		c.Refuse("dhcp6", "rate_limited")
		return
	}
	c.DHCP6Clients.Store(int64(s.pend.len()))
	req := request{from: ip, msg: m, at: time.Now()}
	d := s.policy.Decide(req)
	if !d.Allow {
		s.refused(ip, m, d, "client")
		if s.enforcing() || d.Hard {
			return
		}
	}
	out, err := s.wrap(m, d, ip)
	if err != nil {
		c.Refuse("dhcp6", "unencodable")
		s.deny(ip, "unencodable", err.Error())
		return
	}
	// RELEASE and DECLINE are told to the server and answered by a REPLY that
	// carries a status rather than a lease; they are still paired, because that
	// reply still has to reach the client that asked.
	e := &exchange{client: addrPort(from), duid: duidOf(m), xid: in.TransactionID, rule: d.Rule}
	if v, ok := in.Get(wire.OptionORO); ok {
		e.asked = append([]byte(nil), v...)
	}
	if !s.pend.add(e, time.Now()) {
		// The table is full of requests nobody answered. Refusing keeps the
		// pairing reliable, and the pairing is what makes a reply deliverable
		// to the client that asked rather than to whichever one is guessed.
		c.Refuse("dhcp6", "too_many_pending")
		s.deny(ip, "too_many_pending", "")
		return
	}
	s.logMessage(ip, m, d, "client", "allow")
	s.observeRequest(m, ip)
	addr := s.serverAddr(ip)
	if addr == nil {
		c.DHCP6UpstreamFail.Add(1)
		s.forget(e)
		return
	}
	if _, err := up.WriteTo(out, addr); err != nil {
		c.DHCP6UpstreamFail.Add(1)
		s.host.Logs().Error.Warn("dhcp6 relay to server failed", "listener", s.cfg.Name,
			"server", addr.String(), "error", err.Error())
		s.forget(e)
		return
	}
	c.DHCP6Relayed.Add(1)
}

// relayDepth is how many relay agents a message has already crossed.
func relayDepth(m *wire.Message) uint8 {
	n := 0
	for p := m; p != nil; p = p.Inner {
		if p.Type.IsRelay() {
			n++
		}
	}
	if n > 255 {
		n = 255
	}
	return uint8(n) //nolint:gosec // bounded above
}

// wrap is the relay agent's own work: RFC 8415 s19.1.1 puts the client's message
// inside a RELAY-FORW carrying the link address the server allocates from and the
// peer address the message came from, and this relay adds its own identifying
// options.
//
// A client's own Interface-ID, Remote-ID or Subscriber-ID is removed first,
// whatever it said, because that assertion is exactly what the option exists to
// make on the client's behalf.
func (s *server) wrap(m *wire.Message, d Decision, ip netip.Addr) ([]byte, error) {
	inner := m.Clone()
	target := inner.Innermost()
	for _, code := range d.Strip {
		target.Remove(code)
	}
	if s.policy.StripClientRelayOptions() {
		for _, code := range wire.RelayOptions {
			target.Remove(code)
		}
	}
	// The options a client may not ask for, taken out of its request list
	// rather than the message refused.
	if v, ok := target.Get(wire.OptionORO); ok {
		kept, gone := s.policy.AskDenied(v)
		if len(gone) > 0 {
			if len(kept) == 0 {
				target.Remove(wire.OptionORO)
			} else {
				target.Set(wire.OptionORO, kept)
			}
			s.logAsks(ip, gone)
		}
	}
	var opts []wire.Option
	if id := s.policy.InterfaceFor(d.Rule, s.m.InterfaceID); id != "" {
		opts = append(opts, wire.Option{Code: wire.OptionInterfaceID, Value: []byte(id)})
	}
	if s.m.RemoteID != "" {
		// RFC 4649: four octets of enterprise number, then the identifier.
		v := make([]byte, 4, 4+len(s.m.RemoteID))
		n := uint32(s.m.RemoteIDEnterprise) //nolint:gosec // validation bounds it
		v[0], v[1], v[2], v[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
		v = append(v, s.m.RemoteID...)
		opts = append(opts, wire.Option{Code: wire.OptionRemoteID, Value: v})
	}
	if s.m.SubscriberID != "" {
		opts = append(opts, wire.Option{Code: wire.OptionSubscriberID, Value: []byte(s.m.SubscriberID)})
	}
	fwd, err := wire.Wrap(inner, s.link, ip, opts...)
	if err != nil {
		return nil, err
	}
	return wire.Encode(fwd)
}

// readServers reads the socket the servers answer on.
func (s *server) readServers(up net.PacketConn) {
	buf := make([]byte, wire.MaxMessage+1)
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
			s.host.Counters().DHCP6Malformed.Add(1)
			s.host.Counters().Refuse("dhcp6", "message_too_large")
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		s.fromServer(raw, from)
	}
}

// fromServer decides about one reply and, when it is allowed, unwraps it and
// sends it to the client that asked.
func (s *server) fromServer(raw []byte, from net.Addr) {
	c := s.host.Counters()
	ip := netutil.AddrOf(from.String())
	c.DHCP6Replies.Add(1)
	if !s.policy.Server(ip) {
		// The whole attack, and the one refusal that is never shadowed: a
		// listener that evaluated the server list without enforcing it would
		// relay a rogue server's answer and write it down.
		c.DHCP6RogueServer.Add(1)
		c.Refuse("dhcp6", "server_not_allowed")
		s.deny(ip, "server_not_allowed", "")
		return
	}
	m, err := wire.Parse(raw)
	if err != nil {
		c.DHCP6Malformed.Add(1)
		c.Refuse("dhcp6", "malformed_reply")
		s.deny(ip, "malformed_reply", err.Error())
		return
	}
	in := m.Innermost()
	k := key{xid: in.TransactionID, duid: duidOf(m)}
	e, ok := s.pend.take(k, time.Now())
	if !ok {
		// Nobody asked. On this protocol that is either a server answering a
		// request that has already expired or something aiming replies at the
		// relay, and the two look the same from here.
		c.DHCP6Unsolicited.Add(1)
		c.Refuse("dhcp6", "unsolicited")
		s.deny(ip, "unsolicited", in.Type.String())
		return
	}
	req := request{from: ip, msg: m, at: time.Now()}
	d := s.policy.Answer(req, e.rule)
	if !d.Allow {
		s.refused(ip, m, d, "server")
		if s.enforcing() || d.Hard {
			s.pend.drop(k)
			return
		}
	}
	out, err := s.rewriteReply(m, d)
	if err != nil {
		c.Refuse("dhcp6", "unencodable")
		s.deny(ip, "unencodable", err.Error())
		s.pend.drop(k)
		return
	}
	if len(d.Strip) > 0 {
		c.DHCP6OptionsStripped.Add(uint64(len(d.Strip)))
	}
	if d.Bounded {
		c.DHCP6LeaseBounded.Add(1)
	}
	if _, err := s.pc.WriteTo(out, net.UDPAddrFromAddrPort(e.client)); err != nil {
		c.DHCP6SendFailed.Add(1)
		s.host.Logs().Error.Warn("dhcp6 reply to client failed", "listener", s.cfg.Name,
			"client", e.client.String(), "error", err.Error())
		return
	}
	c.DHCP6Answered.Add(1)
	s.logMessage(ip, m, d, "server", "allow")
	s.logLease(e, m, ip)
	s.observeReply(m, e)
}

// rewriteReply takes the options the policy refused out of the client's own
// message, bounds the lifetimes, and renders what goes back.
//
// The client's message is what comes out of the wrapper: a RELAY-REPL is the
// server's answer to *this relay*, and RFC 8415 s19.3 says what goes to the
// client is the message inside it. So the wrapper is dropped rather than
// forwarded, which is also what stops the relay's own Interface-ID reaching the
// client.
func (s *server) rewriteReply(m *wire.Message, d Decision) ([]byte, error) {
	out, err := wire.Unwrap(m.Clone())
	if err != nil {
		return nil, err
	}
	for _, code := range d.Strip {
		out.Remove(code)
	}
	if d.Bounded {
		boundLifetimes(out, d.Lease)
	}
	// The relay's own options never go to a client: they are this relay's
	// statement to the server about where the message came from.
	for _, code := range wire.RelayOptions {
		out.Remove(code)
	}
	return wire.Encode(out)
}

// boundLifetimes writes a valid lifetime over the ones a server sent.
//
// It edits the identity associations in place, which means re-rendering them:
// the lifetimes are inside the IA_ADDR and IA_PREFIX options, so there is no way
// to change one without rebuilding the option that holds it. A valid lifetime of
// zero is left alone, because zero is how a server withdraws an address and
// rewriting it would turn a withdrawal into a lease.
//
// The preferred lifetime is brought down with it where it would otherwise exceed
// it: RFC 8415 s21.6 says a preferred lifetime longer than the valid one makes
// the option invalid, and a relay that bounded one and not the other would be
// sending exactly that.
func boundLifetimes(m *wire.Message, valid uint32) {
	for i, o := range m.Options {
		switch o.Code {
		case wire.OptionIANA, wire.OptionIAPD:
			m.Options[i].Value = boundIA(o.Value, 12, valid)
		case wire.OptionIATA:
			m.Options[i].Value = boundIA(o.Value, 4, valid)
		}
	}
}

// boundIA rewrites the lifetimes inside one identity association. head is the
// length of its own header, before the inner options.
func boundIA(v []byte, head int, valid uint32) []byte {
	if len(v) < head {
		return v
	}
	out := append([]byte(nil), v[:head]...)
	rest := v[head:]
	for len(rest) >= 4 {
		code := uint16(rest[0])<<8 | uint16(rest[1])
		n := int(rest[2])<<8 | int(rest[3])
		if len(rest) < 4+n {
			// Unreadable, so it is left exactly as it arrived: the policy has
			// already refused a message whose options do not add up, and
			// rewriting one that does not would be inventing a message.
			return append(out, rest...)
		}
		field := append([]byte(nil), rest[:4+n]...)
		body := field[4:]
		switch {
		case code == wire.OptionIAAddr && n >= 24:
			putLifetimes(body[16:24], valid)
		case code == wire.OptionIAPrefix && n >= 25:
			putLifetimes(body[0:8], valid)
		}
		out = append(out, field...)
		rest = rest[4+n:]
	}
	return append(out, rest...)
}

// putLifetimes writes the preferred and valid lifetimes into an eight-octet
// field, keeping the preferred one no longer than the valid one.
func putLifetimes(b []byte, valid uint32) {
	pref := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if cur := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7]); cur == 0 {
		return
	}
	if pref > valid {
		pref = valid
	}
	b[0], b[1], b[2], b[3] = byte(pref>>24), byte(pref>>16), byte(pref>>8), byte(pref)
	b[4], b[5], b[6], b[7] = byte(valid>>24), byte(valid>>16), byte(valid>>8), byte(valid)
}

func (s *server) forget(e *exchange) {
	s.pend.drop(key{xid: e.xid, duid: e.duid})
}

// serverAddr picks the server to relay to.
func (s *server) serverAddr(client netip.Addr) net.Addr {
	pool := s.host.Pool(s.m.Upstream)
	if pool == nil {
		return nil
	}
	e, _ := pool.Pick(client.String(), "", nil, 0)
	if e == nil {
		return nil
	}
	ap, err := netip.ParseAddrPort(e.Address)
	if err != nil {
		ua, err := net.ResolveUDPAddr("udp", e.Address)
		if err != nil {
			return nil
		}
		return ua
	}
	return net.UDPAddrFromAddrPort(ap)
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
