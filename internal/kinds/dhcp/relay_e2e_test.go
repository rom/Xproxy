package dhcp

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/dhcp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// fakeServer is a DHCP server. It records every message that reached it, which
// is the assertion that matters on a security relay: not what the client was
// told, but what got through.
type fakeServer struct {
	pc net.PacketConn

	mu  sync.Mutex
	got []*wire.Message
	// reply is the answer it sends, built from the request. Nil answers with an
	// ordinary ACK carrying an address, a mask, a router and a lease.
	reply func(*wire.Message) *wire.Message
	// silent answers nothing at all.
	silent bool
}

func startServer(t *testing.T, s *fakeServer) *fakeServer {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.pc = pc
	t.Cleanup(func() { _ = pc.Close() })
	go s.serve()
	return s
}

func (s *fakeServer) addr() string { return s.pc.LocalAddr().String() }

func (s *fakeServer) serve() {
	buf := make([]byte, wire.MaxPacket+1)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		m, err := wire.Parse(buf[:n])
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.got = append(s.got, m)
		silent, reply := s.silent, s.reply
		s.mu.Unlock()
		if silent {
			continue
		}
		out := ack(m)
		if reply != nil {
			out = reply(m)
		}
		if out == nil {
			continue
		}
		raw, err := wire.Encode(out)
		if err != nil {
			continue
		}
		_, _ = s.pc.WriteTo(raw, from)
	}
}

func (s *fakeServer) seen() []*wire.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*wire.Message, len(s.got))
	copy(out, s.got)
	return out
}

func (s *fakeServer) await(t *testing.T, n int, what string) []*wire.Message {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.seen(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the server saw %d messages", what, len(s.seen()))
	return nil
}

// reply builds a server's answer to a request, which the tests then add
// dangerous options to.
func reply(m *wire.Message, typ wire.MessageType) *wire.Message {
	out := &wire.Message{Op: wire.BootReply, HType: m.HType, XID: m.XID,
		Flags: m.Flags, CHAddr: m.CHAddr, Type: typ,
		YIAddr: netip.MustParseAddr("10.20.0.55"),
		SIAddr: netip.MustParseAddr("0.0.0.0"),
		GIAddr: m.GIAddr, CIAddr: netip.MustParseAddr("0.0.0.0")}
	out.Set(wire.OptServerID, []byte{10, 20, 0, 1})
	if v, ok := m.Get(wire.OptRelayAgent); ok {
		// RFC 3046 §2.2: a server returns the agent option unchanged, and the
		// relay is the thing that has to take it off again before the client
		// sees it. A fake server that dropped it would leave that untested.
		out.Set(wire.OptRelayAgent, v)
	}
	out.Set(wire.OptSubnetMask, []byte{255, 255, 255, 0})
	out.Set(wire.OptLeaseTime, []byte{0, 0, 14, 16}) // 3600 seconds
	out.Set(wire.OptRouter, []byte{10, 20, 0, 1})
	out.Set(wire.OptDNS, []byte{10, 20, 0, 2})
	return out
}

func ack(m *wire.Message) *wire.Message {
	if m.Type == wire.Discover {
		return reply(m, wire.Offer)
	}
	return reply(m, wire.Ack)
}

const dhcpYAML = `
version: 1
server:
  listeners:
    - name: segment
      address: "127.0.0.1:0"
      kind: dhcp
%s
      dhcp:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`

func relayFor(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	return relayWith(t, section, "", serverAddr)
}

func relayWith(t *testing.T, section, extra, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(dhcpYAML, extra, section, serverAddr))
	return s, proxytest.Addr(t, s, "segment")
}

// base is the section every test starts from: a relay address, the server pool,
// and the estate's own gateway and resolver.
const base = "        upstream: servers\n" +
	"        relay_address: 10.20.0.1\n" +
	"        allow_gateways: [10.20.0.1]\n" +
	"        allow_resolvers: [10.20.0.2]\n"

// client is a device on the segment.
type client struct {
	t  *testing.T
	pc net.PacketConn
	to *net.UDPAddr
	hw []byte
}

func dial(t *testing.T, addr string, hw ...byte) *client {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(hw) == 0 {
		hw = []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	}
	return &client{t: t, pc: pc, to: ua, hw: hw}
}

// send writes a message of a type, with any extra options.
func (c *client) send(typ wire.MessageType, xid uint32, set func(*wire.Message)) {
	c.t.Helper()
	m := &wire.Message{Op: wire.BootRequest, HType: wire.HTypeEthernet,
		XID: xid, CHAddr: c.hw,
		CIAddr: netip.MustParseAddr("0.0.0.0"),
		YIAddr: netip.MustParseAddr("0.0.0.0"),
		SIAddr: netip.MustParseAddr("0.0.0.0"),
		GIAddr: netip.MustParseAddr("0.0.0.0"),
		Type:   typ}
	m.Set(wire.OptParameterList, []byte{wire.OptSubnetMask, wire.OptRouter, wire.OptDNS})
	if set != nil {
		set(m)
	}
	raw, err := wire.Encode(m)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.pc.WriteTo(raw, c.to); err != nil {
		c.t.Fatal(err)
	}
}

// recv reads one reply, or reports that nothing came.
func (c *client) recv() (*wire.Message, bool) {
	c.t.Helper()
	buf := make([]byte, wire.MaxPacket+1)
	_ = c.pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := c.pc.ReadFrom(buf)
	if err != nil {
		return nil, false
	}
	m, err := wire.Parse(buf[:n])
	if err != nil {
		c.t.Fatalf("the relay sent something unreadable: %v", err)
	}
	return m, true
}

func awaitCounter(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: the counters never said so: %+v", what, s.Stats().Refusals["dhcp"])
}

// TestTheOrdinaryLeaseCycleGoesThrough is the base case, and it asserts the
// relay agent's own work on the way out: giaddr filled in, hops incremented,
// and the agent option added.
func TestTheOrdinaryLeaseCycleGoesThrough(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+"        circuit_id: vlan20\n        remote_id: relay-1\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0x1234, nil)
	m, ok := c.recv()
	if !ok {
		t.Fatal("no offer came back")
	}
	if m.Type != wire.Offer || m.YIAddr != netip.MustParseAddr("10.20.0.55") {
		t.Fatalf("got %v offering %v", m.Type, m.YIAddr)
	}
	// The relay's own note to the server does not travel on to the client, and
	// neither does giaddr: both are between the relay and the server.
	if m.Has(wire.OptRelayAgent) {
		t.Error("the agent option reached the client")
	}
	if !m.GIAddr.IsUnspecified() || m.Hops != 0 {
		t.Errorf("giaddr %v hops %d reached the client", m.GIAddr, m.Hops)
	}
	seen := fs.await(t, 1, "the discover")
	if seen[0].GIAddr != netip.MustParseAddr("10.20.0.1") {
		t.Errorf("the server saw giaddr %v", seen[0].GIAddr)
	}
	if seen[0].Hops != 1 {
		t.Errorf("the server saw %d hops", seen[0].Hops)
	}
	v, ok := seen[0].Get(wire.OptRelayAgent)
	if !ok {
		t.Fatal("the server was not told which circuit")
	}
	subs, err := wire.SubOptions(v)
	if err != nil || len(subs) != 2 || string(subs[0].Value) != "vlan20" {
		t.Fatalf("agent option %v err %v", subs, err)
	}
	// And the second half of the cycle.
	c.send(wire.Request, 0x1234, nil)
	m, ok = c.recv()
	if !ok || m.Type != wire.Ack {
		t.Fatalf("got %v, want an ack", m)
	}
}

// TestAReplyFromAnAddressThatIsNotAServerIsDropped is the rogue-server check,
// which is what every switch vendor sells as DHCP snooping.
func TestAReplyFromAnAddressThatIsNotAServerIsDropped(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        allow_servers: [10.99.0.0/16]\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0x2222, nil)
	if m, ok := c.recv(); ok {
		t.Fatalf("a reply from an address that is not a server reached the client: %v", m.Type)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.DHCPRogue > 0 },
		"the rogue reply was counted")
}

// TestAnOfferArrivingOnTheSegmentIsNotRelayed: a rogue server on the same
// segment as the relay is not something the server list can see, because it
// speaks to the clients directly -- but what it sends to the relay's own port
// is a reply on the request side, and that has a name.
func TestAnOfferArrivingOnTheSegmentIsNotRelayed(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, fs.addr())
	c := dial(t, addr)
	m := &wire.Message{Op: wire.BootReply, HType: wire.HTypeEthernet, XID: 3,
		CHAddr: c.hw, Type: wire.Offer,
		YIAddr: netip.MustParseAddr("10.20.0.99")}
	raw, err := wire.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.pc.WriteTo(raw, c.to); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["reply_from_client_side"] > 0
	}, "the offer on the segment was counted")
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
}

// TestTheDangerousOptionsAreStrippedByDefault is the answer policy: a route, a
// proxy and a boot file are removed and the client still gets its address.
func TestTheDangerousOptionsAreStrippedByDefault(t *testing.T) {
	fs := startServer(t, &fakeServer{reply: func(m *wire.Message) *wire.Message {
		out := ack(m)
		out.Set(wire.OptClasslessRoute, []byte{0, 10, 20, 0, 9})
		out.Set(wire.OptWPAD, []byte("http://attacker/wpad.dat"))
		out.Set(wire.OptBootFile, []byte("evil.efi"))
		return out
	}})
	s, addr := relayFor(t, base, fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0x3333, nil)
	m, ok := c.recv()
	if !ok {
		t.Fatal("no offer came back")
	}
	for _, code := range []uint8{wire.OptClasslessRoute, wire.OptWPAD, wire.OptBootFile} {
		if m.Has(code) {
			t.Errorf("%s reached the client", wire.OptionName(code))
		}
	}
	// And the address, the mask and the lease did.
	if m.YIAddr != netip.MustParseAddr("10.20.0.55") || !m.Has(wire.OptSubnetMask) || !m.Has(wire.OptLeaseTime) {
		t.Error("stripping the dangerous options broke the reply")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.DHCPStripped >= 3 },
		"three options were stripped")
}

// TestAGatewayTheEstateDoesNotHaveIsRemoved is the check that catches a
// compromised *real* server as well as a rogue one: the source address was on
// the server list and the answer was still wrong.
func TestAGatewayTheEstateDoesNotHaveIsRemoved(t *testing.T) {
	fs := startServer(t, &fakeServer{reply: func(m *wire.Message) *wire.Message {
		out := ack(m)
		out.Set(wire.OptRouter, []byte{10, 20, 0, 66})
		return out
	}})
	s, addr := relayFor(t, base, fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0x4444, nil)
	m, ok := c.recv()
	if !ok {
		t.Fatal("no offer came back")
	}
	if m.Has(wire.OptRouter) {
		v, _ := m.Get(wire.OptRouter)
		t.Fatalf("a router the estate does not have reached the client: %v", v)
	}
	if !m.Has(wire.OptDNS) {
		t.Error("the resolver, which is on the list, was removed too")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["option_stripped"] > 0
	}, "the wrong gateway was reported as a finding")
}

// TestAnAllowedRouteGoesThroughAndAnotherDoesNot, for the estate that really
// does use classless routes.
func TestAnAllowedRouteGoesThroughAndAnotherDoesNot(t *testing.T) {
	inside := []byte{16, 10, 20, 10, 20, 0, 1} // 10.20.0.0/16 via 10.20.0.1
	outside := []byte{0, 10, 20, 0, 9}         // 0.0.0.0/0 via 10.20.0.9
	for _, c := range []struct {
		what  string
		route []byte
		want  bool
	}{
		{what: "a route inside the list", route: inside, want: true},
		{what: "a default route", route: outside, want: false},
	} {
		route := c.route
		fs := startServer(t, &fakeServer{reply: func(m *wire.Message) *wire.Message {
			out := ack(m)
			out.Set(wire.OptClasslessRoute, route)
			return out
		}})
		section := base + "        deny_options: [wpad_url, tftp_server, boot_file, vendor_specific, ms_classless_static_route, static_route]\n" +
			"        allow_routes: [10.20.0.0/16]\n"
		_, addr := relayFor(t, section, fs.addr())
		cl := dial(t, addr)
		cl.send(wire.Discover, 0x5555, nil)
		m, ok := cl.recv()
		if !ok {
			t.Fatalf("%s: no offer came back", c.what)
		}
		if got := m.Has(wire.OptClasslessRoute); got != c.want {
			t.Errorf("%s: carried=%v, want %v", c.what, got, c.want)
		}
	}
}

// TestAClientsOwnAgentOptionIsStripped is RFC 3046 §2.1: a client has no
// business asserting which circuit it is on, because that assertion is exactly
// what the option exists to make on its behalf.
func TestAClientsOwnAgentOptionIsStripped(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        circuit_id: vlan20\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0x6666, func(m *wire.Message) {
		v, _ := wire.AgentInfo("vlan-i-am-not-on", "")
		m.Set(wire.OptRelayAgent, v)
	})
	seen := fs.await(t, 1, "the discover")
	v, ok := seen[0].Get(wire.OptRelayAgent)
	if !ok {
		t.Fatal("the relay's own agent option is missing")
	}
	subs, err := wire.SubOptions(v)
	if err != nil || string(subs[0].Value) != "vlan20" {
		t.Fatalf("the server was told %v", subs)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["client_agent_option"] > 0
	}, "the client's agent option was counted")
}

// TestAnOptionAClientMayNotAskForIsRemovedFromTheAsk: a client that asked for a
// proxy and is not told about one is a client that works.
func TestAnOptionAClientMayNotAskForIsRemovedFromTheAsk(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+"        deny_requested_options: [wpad_url, classless_static_route]\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0x7777, func(m *wire.Message) {
		m.Set(wire.OptParameterList, []byte{wire.OptSubnetMask, wire.OptWPAD,
			wire.OptRouter, wire.OptClasslessRoute})
	})
	seen := fs.await(t, 1, "the discover")
	v, _ := seen[0].Get(wire.OptParameterList)
	if bytes.Contains(v, []byte{wire.OptWPAD}) || bytes.Contains(v, []byte{wire.OptClasslessRoute}) {
		t.Fatalf("the ask still carries what the policy removed: %v", v)
	}
	if !bytes.Contains(v, []byte{wire.OptRouter}) {
		t.Errorf("trimming the ask removed what was allowed: %v", v)
	}
}

// TestALeasePastTheBoundIsShortenedRatherThanRefused: a client that would have
// held an address for a year holds it for a day instead, and still boots.
func TestALeasePastTheBoundIsShortenedRatherThanRefused(t *testing.T) {
	fs := startServer(t, &fakeServer{reply: func(m *wire.Message) *wire.Message {
		out := ack(m)
		out.Set(wire.OptLeaseTime, []byte{0x01, 0xe1, 0x33, 0x80}) // a year
		return out
	}})
	_, addr := relayFor(t, base+"        max_lease_time: 24h\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0x8888, nil)
	m, ok := c.recv()
	if !ok {
		t.Fatal("no offer came back")
	}
	v, ok := m.Get(wire.OptLeaseTime)
	if !ok {
		t.Fatal("the lease time was removed")
	}
	secs, err := wire.Seconds(v)
	if err != nil || secs != 86400 {
		t.Fatalf("lease %d seconds, want 86400", secs)
	}
}

// TestAHiddenOptionIsRefusedEvenInShadowMode is the split this kind draws: an
// option in the boot filename field is a message two parsers read differently,
// and there is nothing for a policy to be evaluated against.
func TestAHiddenOptionIsRefusedEvenInShadowMode(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	s, addr := relayWith(t, base+"        message_types: [request]\n",
		"      policy: {mode: shadow}", fs.addr())
	c := dial(t, addr)
	// A discover is outside the message-type list, which is policy: shadow
	// mode records it and forwards it.
	c.send(wire.Discover, 0x9999, nil)
	if _, ok := c.recv(); !ok {
		t.Error("shadow mode refused a policy decision")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.DHCPWouldDeny > 0 },
		"the message type was recorded rather than enforced")
	// An option split across instances is not policy.
	c2 := dial(t, addr, 0x02, 0x11, 0x22, 0x33, 0x44, 0x66)
	raw := splitOption(t, c2.hw)
	if _, err := c2.pc.WriteTo(raw, c2.to); err != nil {
		t.Fatal(err)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["hidden_options"] > 0
	}, "the split option was refused")
	if _, ok := c2.recv(); ok {
		t.Error("shadow mode forwarded a message with a split option")
	}
}

// splitOption builds a discover whose vendor class arrives in two instances,
// which RFC 3396 says are one option.
func splitOption(t *testing.T, hw []byte) []byte {
	t.Helper()
	out := make([]byte, wire.FixedLen)
	out[0] = uint8(wire.BootRequest)
	out[1] = wire.HTypeEthernet
	out[2] = uint8(len(hw))
	copy(out[28:44], hw)
	out = append(out, wire.Cookie[:]...)
	out = append(out, wire.OptMessageType, 1, uint8(wire.Discover))
	out = append(out, wire.OptVendorClass, 3, 'a', 'b', 'c')
	out = append(out, wire.OptVendorClass, 3, 'd', 'e', 'f')
	out = append(out, wire.OptEnd)
	for len(out) < 300 {
		out = append(out, wire.OptPad)
	}
	return out
}

// TestARuleNarrowsByHardwareAddressAndVendorClass, which is how a PXE segment
// is written down: those machines may be told a boot server and nothing else
// may.
func TestARuleNarrowsByHardwareAddressAndVendorClass(t *testing.T) {
	fs := startServer(t, &fakeServer{reply: func(m *wire.Message) *wire.Message {
		out := ack(m)
		out.Set(wire.OptBootFile, []byte("pxelinux.0"))
		out.Set(wire.OptTFTPServer, []byte{10, 20, 0, 3})
		return out
	}})
	section := base +
		"        rules:\n" +
		"          - name: pxe\n" +
		"            action: allow\n" +
		"            hardware_addresses: [\"02:11:22\"]\n" +
		"            vendor_classes: [\"PXEClient*\"]\n" +
		"            deny_options: [wpad_url]\n" +
		"            allow_boot_servers: [10.20.0.3]\n" +
		"            boot_files: [\"pxelinux.0\"]\n"
	_, addr := relayFor(t, section, fs.addr())
	// A machine that matches the rule is told its boot server.
	c := dial(t, addr)
	c.send(wire.Discover, 0xaaaa, func(m *wire.Message) {
		m.Set(wire.OptVendorClass, []byte("PXEClient:Arch:00007"))
	})
	m, ok := c.recv()
	if !ok {
		t.Fatal("no offer came back")
	}
	if !m.Has(wire.OptBootFile) || !m.Has(wire.OptTFTPServer) {
		t.Error("the rule's own traffic was not told its boot server")
	}
	// A machine that does not match takes the listener's default lists, where
	// the boot options are on the built-in deny list.
	c2 := dial(t, addr, 0x02, 0x99, 0x99, 1, 2, 3)
	c2.send(wire.Discover, 0xbbbb, nil)
	m2, ok := c2.recv()
	if !ok {
		t.Fatal("no offer came back for the second client")
	}
	if m2.Has(wire.OptBootFile) || m2.Has(wire.OptTFTPServer) {
		t.Error("a machine outside the rule was told a boot server")
	}
	// A machine whose hardware address is in the rule's vendor range and whose
	// vendor class is not: the rule needs *both*, so this one is outside it.
	// Without this case a rule that ignored its vendor class entirely would
	// behave identically on every client the test sent.
	c3 := dial(t, addr, 0x02, 0x11, 0x22, 0x77, 0x88, 0x99)
	c3.send(wire.Discover, 0xbbcc, func(m *wire.Message) {
		m.Set(wire.OptVendorClass, []byte("MSFT 5.0"))
	})
	m3, ok := c3.recv()
	if !ok {
		t.Fatal("no offer came back for the third client")
	}
	if m3.Has(wire.OptBootFile) || m3.Has(wire.OptTFTPServer) {
		t.Error("a machine matching the rule's addresses but not its vendor class was told a boot server")
	}
}

// TestADownstreamAgentsGiaddrIsNotOverwritten: giaddr is where the reply has to
// go back to, so overwriting another agent's would strand every client behind it.
func TestADownstreamAgentsGiaddrIsNotOverwritten(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+"        allow_clients: [\"127.0.0.0/8\"]\n        max_hops: 4\n", fs.addr())
	c := dial(t, addr)
	downstream := netip.MustParseAddr("10.30.0.1")
	c.send(wire.Request, 0xdd01, func(m *wire.Message) {
		m.Hops = 1
		m.GIAddr = downstream
	})
	seen := fs.await(t, 1, "the relayed request")
	if seen[0].GIAddr != downstream {
		t.Fatalf("the server saw giaddr %v, want the downstream agent's %v",
			seen[0].GIAddr, downstream)
	}
	if seen[0].Hops != 2 {
		t.Errorf("hops %d, want the downstream agent's one plus this relay's", seen[0].Hops)
	}
	// And the reply goes back to where the request came from, not to a
	// broadcast: a relayed request has somewhere to unicast to.
	if m, ok := c.recv(); !ok || m.Type != wire.Ack {
		t.Fatalf("got %v, want an ack back", m)
	}
}

// TestABootFileOutsideTheListIsRefused, because the boot file is what the
// machine runs.
func TestABootFileOutsideTheListIsRefused(t *testing.T) {
	fs := startServer(t, &fakeServer{reply: func(m *wire.Message) *wire.Message {
		out := ack(m)
		out.File = "../../evil.efi"
		return out
	}})
	s, addr := relayFor(t, base+
		"        deny_options: [wpad_url, classless_static_route, ms_classless_static_route, static_route, vendor_specific]\n"+
		"        boot_files: [\"pxelinux.0\", \"images/*.efi\"]\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0xcccc, nil)
	if m, ok := c.recv(); ok {
		t.Fatalf("a reply naming an unlisted boot file reached the client: %q", m.File)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["boot_file_not_allowed"] > 0
	}, "the boot file was refused")
}

// TestTheStarvationBoundIsKeyedOnTheHardwareAddress: exhaustion is one host
// sending thousands of discovers with a made-up address in each, and a limit
// keyed on the source address would see one sender doing nothing unusual.
func TestTheStarvationBoundIsKeyedOnTheHardwareAddress(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        rate_limit: 1\n        rate_burst: 1\n", fs.addr())
	c := dial(t, addr)
	for i := 0; i < 6; i++ {
		c.send(wire.Discover, uint32(0xd000+i), nil)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.DHCPRateLimited > 0 },
		"the rate limit refused a message")
	// A different hardware address is a different key, so it is not affected.
	c2 := dial(t, addr, 0x02, 0x11, 0x22, 0x33, 0x44, 0x77)
	c2.send(wire.Discover, 0xd999, nil)
	if _, ok := c2.recv(); !ok {
		t.Error("a second hardware address was caught by the first one's limit")
	}
}

// TestAReplyNobodyAskedForIsDropped: on a protocol with no session, the pairing
// is the only thing that makes a reply deliverable at all.
func TestAReplyNobodyAskedForIsDropped(t *testing.T) {
	// The fake server answers with a transaction identifier of its own, which
	// is an answer to a question nobody asked.
	fs := startServer(t, &fakeServer{reply: func(m *wire.Message) *wire.Message {
		out := ack(m)
		out.XID = m.XID ^ 0xffff
		return out
	}})
	s, addr := relayFor(t, base, fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0xeeee, nil)
	if _, ok := c.recv(); ok {
		t.Fatal("a reply that matched no request reached the client")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["unsolicited_reply"] > 0
	}, "the unsolicited reply was counted")
}

// TestTooManyHopsIsRefused: the hop count says how many relay agents a message
// has crossed, and a message arriving with a large one has been somewhere.
func TestTooManyHopsIsRefused(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        max_hops: 2\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0xf111, func(m *wire.Message) {
		m.Hops = 2
		m.GIAddr = netip.MustParseAddr("10.30.0.1")
	})
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["too_many_hops"] > 0
	}, "the hop bound refused the message")
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
}

// TestAClientIdentifierThatNamesAnotherAddressIsRefused, when the listener asks
// for the check.
func TestAClientIdentifierThatNamesAnotherAddressIsRefused(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        require_client_id_match: true\n", fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0xf222, func(m *wire.Message) {
		m.Set(wire.OptClientID, append([]byte{wire.HTypeEthernet}, 0xde, 0xad, 0xbe, 0xef, 0, 1))
	})
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["client_id_mismatch"] > 0
	}, "the mismatched identifier was refused")
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
	// The matching form goes through, and so does an opaque identifier that is
	// not the hardware form at all.
	c2 := dial(t, addr, 0x02, 0x11, 0x22, 0x33, 0x44, 0x88)
	c2.send(wire.Discover, 0xf333, func(m *wire.Message) {
		m.Set(wire.OptClientID, append([]byte{wire.HTypeEthernet}, c2.hw...))
	})
	if _, ok := c2.recv(); !ok {
		t.Error("a matching client identifier was refused")
	}
	c3 := dial(t, addr, 0x02, 0x11, 0x22, 0x33, 0x44, 0x99)
	c3.send(wire.Discover, 0xf444, func(m *wire.Message) {
		m.Set(wire.OptClientID, []byte{0xff, 'o', 'p', 'a', 'q', 'u', 'e'})
	})
	if _, ok := c3.recv(); !ok {
		t.Error("an opaque client identifier was refused")
	}
}

// TestADenyRuleRefusesAndNakAnswersWhenAsked.
func TestADenyRuleRefusesAndNakAnswersWhenAsked(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	section := base + "        deny_response: nak\n" +
		"        rules:\n" +
		"          - {name: block, action: deny, hardware_addresses: [\"02:11:22:33:44:55\"]}\n"
	_, addr := relayFor(t, section, fs.addr())
	c := dial(t, addr)
	// A discover's refusal is silence: DHCPNAK is defined as the answer to a
	// request for a particular address.
	c.send(wire.Discover, 0xf555, nil)
	if m, ok := c.recv(); ok {
		t.Errorf("a refused discover was answered with %v", m.Type)
	}
	c.send(wire.Request, 0xf556, nil)
	m, ok := c.recv()
	if !ok || m.Type != wire.Nak {
		t.Fatalf("got %v, want a nak", m)
	}
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
}

// TestDropIsTheDefaultRefusal, because a client that hears nothing retries and
// a nak stops it dead.
func TestDropIsTheDefaultRefusal(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	section := base + "        rules:\n" +
		"          - {name: block, action: deny}\n"
	_, addr := relayFor(t, section, fs.addr())
	c := dial(t, addr)
	c.send(wire.Request, 0xf666, nil)
	if m, ok := c.recv(); ok {
		t.Fatalf("the default refusal answered with %v", m.Type)
	}
	if seen := fs.seen(); len(seen) != 0 {
		t.Fatalf("the server saw %v", seen)
	}
}

// TestAReplyIsBroadcastOnlyWhenThereIsNowhereToUnicast pins the rule, which is
// read from the message rather than from a switch: both conditions matter, and
// a relayed request or a renewal is answered where it came from.
func TestAReplyIsBroadcastOnlyWhenThereIsNowhereToUnicast(t *testing.T) {
	zero := netip.MustParseAddr("0.0.0.0")
	for _, c := range []struct {
		what string
		msg  *wire.Message
		from netip.Addr
		want bool
	}{
		{what: "a client with no address, sending from none",
			msg:  &wire.Message{CIAddr: zero, GIAddr: zero},
			from: zero, want: true},
		{what: "a client that set the broadcast flag",
			msg:  &wire.Message{CIAddr: zero, GIAddr: zero, Flags: 0x8000},
			from: netip.MustParseAddr("127.0.0.1"), want: true},
		{what: "a renewal from a client that has an address",
			msg:  &wire.Message{CIAddr: netip.MustParseAddr("10.20.0.55"), GIAddr: zero, Flags: 0x8000},
			from: netip.MustParseAddr("10.20.0.55"), want: false},
		{what: "a request relayed by another agent",
			msg:  &wire.Message{CIAddr: zero, GIAddr: netip.MustParseAddr("10.30.0.1"), Flags: 0x8000},
			from: netip.MustParseAddr("10.30.0.1"), want: false},
	} {
		if got := broadcastReply(c.msg, c.from); got != c.want {
			t.Errorf("%s: broadcast=%v, want %v", c.what, got, c.want)
		}
	}
}

// TestASilentServerLeavesNothingBehind: the pending table expires, because the
// entries come off a broadcast segment and nothing has to wait for the answer.
func TestASilentServerLeavesNothingBehind(t *testing.T) {
	fs := startServer(t, &fakeServer{silent: true})
	s, addr := relayFor(t, base+"        request_timeout: 1s\n        max_pending: 2\n", fs.addr())
	for i := 0; i < 2; i++ {
		c := dial(t, addr, 0x02, 0x11, 0x22, 0x33, 0x44, byte(i))
		c.send(wire.Discover, uint32(0xf700+i), nil)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.DHCPPending >= 2 },
		"the table filled up")
	// A third request finds the table full and is refused rather than
	// forgetting one of the two.
	c := dial(t, addr, 0x02, 0x11, 0x22, 0x33, 0x44, 0xfe)
	c.send(wire.Discover, 0xf7ff, nil)
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["dhcp"]["too_many_pending"] > 0
	}, "the full table refused the third request")
	// And the entries expire.
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.DHCPPending == 0 },
		"the table emptied on the timeout")
}
