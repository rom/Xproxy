package dhcp6

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/dhcp6"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// fakeServer is a DHCPv6 server. It records every message that reached it, which
// is the assertion that matters on a security relay: not what the client was
// told, but what got through.
type fakeServer struct {
	pc net.PacketConn

	mu  sync.Mutex
	got []*wire.Message
	// relay is the address the relay speaks to servers from. A rogue server
	// cannot guess this ephemeral port, but the test can: it is the source of
	// every RELAY-FORW that arrives here, and aiming at it is what lets the
	// server list be tested rather than assumed.
	relay net.Addr
	// reply builds the answer from the RELAY-FORW it received. Nil answers with
	// an ordinary REPLY carrying an address, a lifetime and a resolver.
	reply func(*wire.Message) *wire.Message
	// silent answers nothing at all.
	silent bool
}

// The loopback these tests run over.
//
// DHCPv6 is IPv6, and in a deployment every one of these sockets is an IPv6
// socket. The transport the test uses is not the thing under test, though: what
// is under test is what the relay reads out of a message, what it refuses, and
// what it writes back -- and every address inside those messages is an IPv6
// address whichever family carried it. A build host without IPv6 is common
// enough (this one has none), and a suite that skipped itself there would be a
// suite that said nothing on the machine where it most needs to speak up.
var loopback = sync.OnceValues(func() (string, string) {
	if pc, err := net.ListenPacket("udp6", "[::1]:0"); err == nil {
		_ = pc.Close()
		return "udp6", "[::1]"
	}
	return "udp4", "127.0.0.1"
})

func startServer(t *testing.T, s *fakeServer) *fakeServer {
	t.Helper()
	network, host := loopback()
	return startServerOn(t, s, network, host)
}

func startServerOn(t *testing.T, s *fakeServer, network, host string) *fakeServer {
	t.Helper()
	pc, err := net.ListenPacket(network, host+":0")
	if err != nil {
		t.Fatalf("no loopback at %s: %v", host, err)
	}
	s.pc = pc
	t.Cleanup(func() { _ = pc.Close() })
	go s.serve()
	return s
}

func (s *fakeServer) addr() string { return s.pc.LocalAddr().String() }

func (s *fakeServer) serve() {
	buf := make([]byte, wire.MaxMessage+1)
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
		s.relay = from
		silent, build := s.silent, s.reply
		s.mu.Unlock()
		if silent {
			continue
		}
		out := answer(m)
		if build != nil {
			out = build(m)
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

// relayAddr is where the relay speaks to servers from, known once it has.
func (s *fakeServer) relayAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.relay
}

func (s *fakeServer) await(t *testing.T, n int, what string) []*wire.Message {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.seen(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the server saw %d messages", what, len(s.seen()))
	return nil
}

// iaNA is an address association as a server sends one.
func iaNA(iaid uint32, addr string, preferred, valid uint32) wire.Option {
	v := binary.BigEndian.AppendUint32(nil, iaid)
	v = binary.BigEndian.AppendUint32(v, 1800)
	v = binary.BigEndian.AppendUint32(v, 2880)
	inner := netip.MustParseAddr(addr).AsSlice()
	inner = binary.BigEndian.AppendUint32(inner, preferred)
	inner = binary.BigEndian.AppendUint32(inner, valid)
	v = append(v, opt(wire.OptionIAAddr, inner)...)
	return wire.Option{Code: wire.OptionIANA, Value: v}
}

// iaPD is a prefix delegation as a server sends one.
func iaPD(iaid uint32, prefix string, preferred, valid uint32) wire.Option {
	pfx := netip.MustParsePrefix(prefix)
	v := binary.BigEndian.AppendUint32(nil, iaid)
	v = binary.BigEndian.AppendUint32(v, 1800)
	v = binary.BigEndian.AppendUint32(v, 2880)
	inner := binary.BigEndian.AppendUint32(nil, preferred)
	inner = binary.BigEndian.AppendUint32(inner, valid)
	inner = append(inner, byte(pfx.Bits()))
	inner = append(inner, pfx.Addr().AsSlice()...)
	v = append(v, opt(wire.OptionIAPrefix, inner)...)
	return wire.Option{Code: wire.OptionIAPD, Value: v}
}

func opt(code uint16, value []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, code)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	return append(out, value...)
}

func duidLL(mac ...byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, 3) // link layer
	out = binary.BigEndian.AppendUint16(out, 1)  // ethernet
	return append(out, mac...)
}

// answer builds a RELAY-REPL around a REPLY, the way a server behind a relay
// answers: RFC 8415 s19.2 says the server copies the link and peer addresses and
// the relay's own options back, and the relay is the thing that has to take those
// off again before the client sees them.
func answer(fwd *wire.Message) *wire.Message {
	in := fwd.Innermost()
	out := &wire.Message{Type: wire.Reply, TransactionID: in.TransactionID}
	if v, ok := in.Get(wire.OptionClientID); ok {
		out.Set(wire.OptionClientID, v)
	}
	out.Set(wire.OptionServerID, duidLL(2, 0, 0, 0, 0, 1))
	out.Options = append(out.Options, iaNA(1, "2001:db8:1::55", 3600, 7200))
	out.Set(wire.OptionDNSServers, netip.MustParseAddr("2001:db8:1::2").AsSlice())
	repl := &wire.Message{Type: wire.RelayReply, HopCount: fwd.HopCount,
		LinkAddress: fwd.LinkAddress, PeerAddress: fwd.PeerAddress, Inner: out}
	for _, code := range wire.RelayOptions {
		if v, ok := fwd.Get(code); ok {
			repl.Set(code, v)
		}
	}
	return repl
}

const dhcp6YAML = `
version: 1
server:
  listeners:
    - name: segment
      address: %q
      kind: dhcp6
%s
      dhcp6:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`

// base is the section every test starts from: the pool, the link address the
// server allocates from, and the estate's own resolver.
const base = "        upstream: servers\n" +
	"        link_address: 2001:db8:1::1\n" +
	"        allow_resolvers: [\"2001:db8:1::2\"]\n"

func relayFor(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	return relayWith(t, section, "", serverAddr)
}

func relayWith(t *testing.T, section, extra, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	_, host := loopback()
	return relayOn(t, host, section, extra, serverAddr)
}

func relayOn(t *testing.T, host, section, extra, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(dhcp6YAML, host+":0", extra, section, serverAddr))
	return s, proxytest.Addr(t, s, "segment")
}

// client is a device on the segment.
type client struct {
	t    *testing.T
	conn *net.UDPConn
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	network, _ := loopback()
	return dialOn(t, network, addr)
}

func dialOn(t *testing.T, network, addr string) *client {
	t.Helper()
	ua, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP(network, nil, ua)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &client{t: t, conn: c}
}

func (c *client) send(m *wire.Message) {
	c.t.Helper()
	raw, err := wire.Encode(m)
	if err != nil {
		c.t.Fatal(err)
	}
	c.raw(raw)
}

func (c *client) raw(b []byte) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *client) read(d time.Duration) (*wire.Message, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return wire.Parse(buf[:n])
}

func (c *client) ask(m *wire.Message) *wire.Message {
	c.t.Helper()
	c.send(m)
	got, err := c.read(5 * time.Second)
	if err != nil {
		c.t.Fatalf("no answer: %v", err)
	}
	return got
}

func (c *client) expectSilence(what string) {
	c.t.Helper()
	if m, err := c.read(400 * time.Millisecond); err == nil {
		c.t.Fatalf("%s: answered with %s", what, m.Type)
	}
}

// solicit is what a client sends: an identifier, an elapsed time, and an
// association it wants filled in.
func solicit(xid uint32, mac byte) *wire.Message {
	m := &wire.Message{Type: wire.Solicit, TransactionID: xid}
	m.Set(wire.OptionClientID, duidLL(2, 0, 0, 0, 0, mac))
	m.Set(wire.OptionElapsedTime, []byte{0, 10})
	// IAID, then the two renewal times, which a client sends as zeros to say it
	// has no preference (RFC 8415 s21.4). They are not optional: the option is
	// twelve octets before the first address goes in it.
	v := binary.BigEndian.AppendUint32(nil, 1)
	v = binary.BigEndian.AppendUint32(v, 0)
	v = binary.BigEndian.AppendUint32(v, 0)
	m.Options = append(m.Options, wire.Option{Code: wire.OptionIANA, Value: v})
	return m
}

// The floor: a client asks, the relay wraps it, the server answers, and the
// client gets the server's own message with the wrapper taken off.
func TestTheRelayWrapsAndUnwraps(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        interface_id: seg-1\n", up.addr())

	c := dial(t, addr)
	got := c.ask(solicit(0x010203, 1))

	// What the server saw: a RELAY-FORW with this relay's link address, the
	// client's message inside it, and the relay's own interface identifier.
	seen := up.await(t, 1, "the request")
	fwd := seen[0]
	if fwd.Type != wire.RelayForward {
		t.Fatalf("the server saw a %s", fwd.Type)
	}
	if fwd.LinkAddress != netip.MustParseAddr("2001:db8:1::1") {
		t.Errorf("link address %s", fwd.LinkAddress)
	}
	if v, ok := fwd.Get(wire.OptionInterfaceID); !ok || string(v) != "seg-1" {
		t.Errorf("interface identifier %q", v)
	}
	if fwd.Innermost().Type != wire.Solicit {
		t.Fatalf("the inner message is a %s", fwd.Innermost().Type)
	}

	// What the client got: the server's own message, with the wrapper and the
	// relay's own options off it.
	if got.Type != wire.Reply {
		t.Fatalf("the client got a %s", got.Type)
	}
	if got.Inner != nil {
		t.Error("the client got the wrapper too")
	}
	for _, code := range wire.RelayOptions {
		if got.Has(code) {
			t.Errorf("the client got the relay's own %s", wire.OptionName(code))
		}
	}
	ias, err := got.IAs()
	if err != nil || len(ias) != 1 || len(ias[0].Addresses) != 1 {
		t.Fatalf("associations %+v %v", ias, err)
	}
	if ias[0].Addresses[0].Addr != netip.MustParseAddr("2001:db8:1::55") {
		t.Errorf("address %s", ias[0].Addresses[0].Addr)
	}
	sn := s.Stats()
	if sn.DHCP6Messages != 1 || sn.DHCP6Relayed != 1 || sn.DHCP6Answered != 1 {
		t.Errorf("counters: messages %d relayed %d answered %d",
			sn.DHCP6Messages, sn.DHCP6Relayed, sn.DHCP6Answered)
	}
}

// The whole attack, and the one refusal a shadow-mode listener still enforces: a
// reply from an address that is not one of the servers.
func TestAReplyFromSomewhereElseIsDropped(t *testing.T) {
	// Pinned to IPv4 loopback, and this is the one test whose transport matters.
	// allow_servers is a list of networks, so it decides on the sender's
	// *address* -- which is right in a deployment, where a rogue at a real
	// server's address is the real server, and which means the two servers in
	// this test have to be at different addresses to be told apart. 127.0.0.2 is
	// a second loopback address; ::1 is the only IPv6 one there is.
	rogue := &fakeServer{silent: true}
	if pc, err := net.ListenPacket("udp4", "127.0.0.2:0"); err != nil {
		t.Skipf("no second loopback address here: %v", err)
	} else {
		_ = pc.Close()
	}
	up := startServerOn(t, &fakeServer{silent: true}, "udp4", "127.0.0.1")
	startServerOn(t, rogue, "udp4", "127.0.0.2")
	// Shadow mode, because this refusal is one a listener being trialled still
	// enforces: relaying a rogue server's answer and writing it down is not a
	// trial of anything.
	s, addr := relayOn(t, "127.0.0.1", base, "      policy: {mode: shadow}\n", up.addr())

	c := dialOn(t, "udp4", addr)
	c.send(solicit(0x111111, 1))
	fwd := up.await(t, 1, "the request")[0]

	// The real server stays silent, so the only answer that could reach the
	// client is the rogue's -- and it is aimed straight at the socket the relay
	// is waiting on, which is the strongest thing a rogue server can do.
	raw, err := wire.Encode(answer(fwd))
	if err != nil {
		t.Fatal(err)
	}
	target := up.relayAddr()
	if target == nil {
		t.Fatal("the relay's server socket is not known")
	}
	if _, err := rogue.pc.WriteTo(raw, target); err != nil {
		t.Fatal(err)
	}

	c.expectSilence("a reply from an address that is not a server")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().DHCP6RogueServer > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rogue reply was not counted: refusals %+v",
				s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Never shadowed, so it is a refusal and not a would-be one.
	if s.Stats().DHCP6WouldDeny > 0 {
		t.Error("the rogue reply was only recorded as a would-be refusal")
	}
}

// The option policy: what a server sends that configures something other than
// the client's own address is taken out, and the rest is forwarded.
func TestTheDangerousOptionsAreStripped(t *testing.T) {
	up := startServer(t, &fakeServer{reply: func(fwd *wire.Message) *wire.Message {
		repl := answer(fwd)
		in := repl.Inner
		// A resolver the estate does not own, a search domain, a boot URL, a
		// captive portal, an S46 container and the option that turns the relay
		// off altogether.
		in.Set(wire.OptionDNSServers, netip.MustParseAddr("2001:db8:66::66").AsSlice())
		in.Set(wire.OptionDomainList, []byte{4, 'e', 'v', 'i', 'l', 0})
		in.Set(wire.OptionBootFileURL, []byte("tftp://[2001:db8:66::66]/boot"))
		in.Set(wire.OptionCaptivePortal, []byte("http://portal.example/"))
		in.Set(wire.OptionS46ContMAPE, []byte{0, 0})
		in.Set(wire.OptionUnicast, netip.MustParseAddr("2001:db8:66::66").AsSlice())
		return repl
	}})
	// Three mechanisms, and which one catches which option is the point. The
	// boot URL, the captive portal, the S46 container and the Server Unicast
	// option are on the built-in deny list, because there is no list of
	// acceptable values for them to be on. The resolver and the search domain
	// are not on that list and are caught by naming what this estate's own are,
	// which is the check a compromised real server fails too.
	s, addr := relayFor(t, base+"        allow_domains: [\"*.plant.example\"]\n", up.addr())
	c := dial(t, addr)
	got := c.ask(solicit(0x222222, 2))

	for _, code := range []uint16{wire.OptionDNSServers, wire.OptionDomainList,
		wire.OptionBootFileURL, wire.OptionCaptivePortal, wire.OptionS46ContMAPE,
		wire.OptionUnicast} {
		if got.Has(code) {
			t.Errorf("the client was told %s", wire.OptionName(code))
		}
	}
	// And the rest of the answer survived: a client that still gets its address
	// is a client that works.
	if !got.Has(wire.OptionServerID) || !got.Has(wire.OptionIANA) {
		t.Fatalf("the answer lost what it needed: %v", got.Codes())
	}
	if s.Stats().DHCP6OptionsStripped == 0 {
		t.Error("nothing was counted as stripped")
	}
}

// A resolver the estate does own is carried. The positive list is the useful half
// of the answer policy: it catches a compromised real server as well as a rogue
// one.
func TestAResolverTheEstateOwnsIsCarried(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)
	got := c.ask(solicit(0x333333, 3))
	v, ok := got.Get(wire.OptionDNSServers)
	if !ok {
		// Handing out resolvers is what stateless DHCPv6 exists for on a network
		// that addresses itself by router advertisement, so a listener that
		// stripped this one by default would be a listener nobody could deploy.
		t.Fatal("the resolver the estate owns was stripped")
	}
	addrs, err := wire.Addresses(v)
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("2001:db8:1::2") {
		t.Fatalf("resolvers %v %v", addrs, err)
	}
}

// Prefix delegation, the part with no DHCPv4 equivalent. A prefix outside the
// estate's is a refusal rather than a strip: there is no useful half of a
// delegation to keep.
func TestADelegationOutsideTheEstateIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{reply: func(fwd *wire.Message) *wire.Message {
		repl := answer(fwd)
		repl.Inner.Options = append(repl.Inner.Options, iaPD(7, "2001:db8:ffff::/48", 3600, 7200))
		return repl
	}})
	s, addr := relayFor(t, base+`        prefix_delegation:
          prefixes: ["2001:db8:100::/40"]
          min_length: 56
          max_length: 56
`, up.addr())
	c := dial(t, addr)
	c.send(solicit(0x444444, 4))
	c.expectSilence("a delegation outside the estate's prefixes")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["bad_identity_association"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A delegation the estate does make is carried, with the length it delegates.
func TestADelegationTheEstateMakesIsCarried(t *testing.T) {
	up := startServer(t, &fakeServer{reply: func(fwd *wire.Message) *wire.Message {
		repl := answer(fwd)
		repl.Inner.Options = append(repl.Inner.Options, iaPD(7, "2001:db8:100:aa00::/56", 3600, 7200))
		return repl
	}})
	_, addr := relayFor(t, base+`        prefix_delegation:
          prefixes: ["2001:db8:100::/40"]
          min_length: 56
          max_length: 56
`, up.addr())
	c := dial(t, addr)
	got := c.ask(solicit(0x454545, 5))
	ias, err := got.IAs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ia := range ias {
		if ia.Code == wire.OptionIAPD && len(ia.Prefixes) == 1 {
			found = true
			if ia.Prefixes[0].Prefix != netip.MustParsePrefix("2001:db8:100:aa00::/56") {
				t.Errorf("prefix %s", ia.Prefixes[0].Prefix)
			}
		}
	}
	if !found {
		t.Fatalf("the delegation did not reach the client: %v", got.Codes())
	}
}

// A client asking for a prefix the estate does not delegate is asking a real
// server to give a segment away, and it is refused here rather than left to the
// server's own configuration -- which is not what this estate reads.
func TestAClientAskingForTheWrongPrefixIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+`        prefix_delegation:
          prefixes: ["2001:db8:100::/40"]
          max_length: 56
`, up.addr())
	m := solicit(0x464646, 6)
	m.Options = append(m.Options, iaPD(9, "2001:db8:ffff::/48", 0, 0))
	c := dial(t, addr)
	c.send(m)
	c.expectSilence("a client asking for a prefix outside the estate's")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["request_not_allowed"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up.seen()) != 0 {
		t.Fatal("the request reached the server")
	}
}

// A hint of ::/0 is a client saying "any", which RFC 8415 s21.22 allows. Refusing
// it would refuse every client that does not already know its prefix.
func TestAPrefixHintOfAnythingIsAllowed(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+`        prefix_delegation:
          prefixes: ["2001:db8:100::/40"]
`, up.addr())
	m := solicit(0x474747, 7)
	m.Options = append(m.Options, iaPD(9, "::/0", 0, 0))
	c := dial(t, addr)
	if got := c.ask(m); got.Type != wire.Reply {
		t.Fatalf("the client got a %s", got.Type)
	}
	up.await(t, 1, "the request")
}

// The client's own relay options are the client claiming to be somewhere it is
// not, and RFC 4649 and RFC 4580 both say those are a relay's statement.
func TestAClientsOwnRelayOptionsAreStripped(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+"        interface_id: seg-1\n", up.addr())
	m := solicit(0x555555, 5)
	m.Set(wire.OptionInterfaceID, []byte("somewhere-else"))
	m.Set(wire.OptionRemoteID, []byte("claimed"))
	c := dial(t, addr)
	c.send(m)
	seen := up.await(t, 1, "the request")
	in := seen[0].Innermost()
	for _, code := range wire.RelayOptions {
		if in.Has(code) {
			t.Errorf("the client's own %s reached the server", wire.OptionName(code))
		}
	}
	// And the relay's own is on the wrapper, where a server reads it.
	if v, ok := seen[0].Get(wire.OptionInterfaceID); !ok || string(v) != "seg-1" {
		t.Errorf("the relay's own interface identifier is %q", v)
	}
}

// The valid lifetime is bounded, and the preferred one comes down with it: a
// preferred lifetime longer than the valid one makes the option invalid.
func TestTheLifetimeIsBounded(t *testing.T) {
	up := startServer(t, &fakeServer{reply: func(fwd *wire.Message) *wire.Message {
		repl := answer(fwd)
		repl.Inner.Options = []wire.Option{
			{Code: wire.OptionServerID, Value: duidLL(2, 0, 0, 0, 0, 1)},
			iaNA(1, "2001:db8:1::55", 86400, 172800),
			iaPD(2, "2001:db8:100:bb00::/56", 86400, 172800),
		}
		if v, ok := fwd.Innermost().Get(wire.OptionClientID); ok {
			repl.Inner.Set(wire.OptionClientID, v)
		}
		return repl
	}})
	s, addr := relayFor(t, base+"        max_lease_time: 1h\n"+`        prefix_delegation:
          prefixes: ["2001:db8:100::/40"]
`, up.addr())
	c := dial(t, addr)
	got := c.ask(solicit(0x666666, 6))
	ias, err := got.IAs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ias) != 2 {
		t.Fatalf("%d associations", len(ias))
	}
	for _, ia := range ias {
		for _, a := range ia.Addresses {
			if a.Valid != 3600 || a.Preferred != 3600 {
				t.Errorf("address lifetimes %d/%d", a.Preferred, a.Valid)
			}
		}
		for _, p := range ia.Prefixes {
			if p.Valid != 3600 || p.Preferred != 3600 {
				t.Errorf("prefix lifetimes %d/%d", p.Preferred, p.Valid)
			}
		}
	}
	if s.Stats().DHCP6LeaseBounded == 0 {
		t.Error("nothing was counted as bounded")
	}
}

// A valid lifetime of zero is how a server withdraws an address. Bounding it up
// to a minimum would turn a withdrawal into a lease.
func TestAWithdrawalIsNotTurnedIntoALease(t *testing.T) {
	up := startServer(t, &fakeServer{reply: func(fwd *wire.Message) *wire.Message {
		repl := answer(fwd)
		repl.Inner.Options = []wire.Option{
			{Code: wire.OptionServerID, Value: duidLL(2, 0, 0, 0, 0, 1)},
			iaNA(1, "2001:db8:1::55", 0, 0),
		}
		if v, ok := fwd.Innermost().Get(wire.OptionClientID); ok {
			repl.Inner.Set(wire.OptionClientID, v)
		}
		return repl
	}})
	_, addr := relayFor(t, base+"        min_lease_time: 10m\n", up.addr())
	c := dial(t, addr)
	got := c.ask(solicit(0x676767, 7))
	ias, err := got.IAs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ias) != 1 || len(ias[0].Addresses) != 1 {
		t.Fatalf("associations %+v", ias)
	}
	if v := ias[0].Addresses[0].Valid; v != 0 {
		t.Fatalf("a withdrawal came out as a lease of %d seconds", v)
	}
}

// RECONFIGURE is refused by name: a message to a client that answers nothing,
// which the standard requires to be authenticated with a key nobody deploys.
func TestReconfigureIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{reply: func(fwd *wire.Message) *wire.Message {
		repl := answer(fwd)
		repl.Inner.Type = wire.Reconfigure
		return repl
	}})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)
	c.send(solicit(0x777777, 7))
	c.expectSilence("a reconfigure from a server")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["reconfigure_not_allowed"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A message type the estate does not carry, and one nobody defined.
func TestAMessageTypeIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)

	// The lease query family, which the default list leaves out: a relay agent's
	// own diagnostic, and an inventory of every lease to anything else.
	q := &wire.Message{Type: wire.LeaseQuery, TransactionID: 0x888888}
	q.Set(wire.OptionClientID, duidLL(2, 0, 0, 0, 0, 8))
	c.send(q)
	c.expectSilence("a lease query")

	// A type nobody defined, which is not forwarded on a guess.
	c.raw([]byte{200, 0, 0, 1})
	c.expectSilence("a message type nobody defined")

	for deadline := time.Now().Add(5 * time.Second); ; {
		r := s.Stats().Refusals["dhcp6"]
		if r["message_type_not_allowed"] > 0 && r["unknown_message_type"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up.seen()) != 0 {
		t.Fatal("something reached the server")
	}
}

// An option twice is a message two implementations read differently, and the
// identity associations are the exception because a client sends several.
func TestARepeatedOptionIsRefusedAndAssociationsAreNot(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)

	m := solicit(0x999999, 9)
	m.Options = append(m.Options, wire.Option{Code: wire.OptionClientID,
		Value: duidLL(2, 0, 0, 0, 0, 10)})
	c.send(m)
	c.expectSilence("a client identifier twice")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["repeated_option"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Two associations are ordinary.
	two := solicit(0x9a9a9a, 11)
	second := binary.BigEndian.AppendUint32(nil, 2)
	second = binary.BigEndian.AppendUint32(second, 0)
	second = binary.BigEndian.AppendUint32(second, 0)
	two.Options = append(two.Options, wire.Option{Code: wire.OptionIANA, Value: second})
	if got := c.ask(two); got.Type != wire.Reply {
		t.Fatalf("the client got a %s", got.Type)
	}
}

// The options a client may not ask for come out of its request list, and the
// message is still relayed: a client that asked for a captive portal still gets
// an address.
func TestADeniedAskIsRemovedFromTheRequest(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+"        deny_requested_options: [captive_portal, boot_file_url]\n",
		up.addr())
	m := solicit(0xaaaaaa, 12)
	oro := binary.BigEndian.AppendUint16(nil, wire.OptionDNSServers)
	oro = binary.BigEndian.AppendUint16(oro, wire.OptionCaptivePortal)
	oro = binary.BigEndian.AppendUint16(oro, wire.OptionBootFileURL)
	m.Set(wire.OptionORO, oro)
	c := dial(t, addr)
	if got := c.ask(m); got.Type != wire.Reply {
		t.Fatalf("the client got a %s", got.Type)
	}
	seen := up.await(t, 1, "the request")
	v, ok := seen[0].Innermost().Get(wire.OptionORO)
	if !ok {
		t.Fatal("the request list went altogether")
	}
	if !bytes.Equal(v, binary.BigEndian.AppendUint16(nil, wire.OptionDNSServers)) {
		t.Fatalf("the request list is %x", v)
	}
}

// A relay chain deeper than the estate's topology has been somewhere.
func TestADeepChainIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        max_relay_hops: 2\n", up.addr())
	inner := solicit(0xbbbbbb, 13)
	m := inner
	for i := 0; i < 3; i++ {
		m = &wire.Message{Type: wire.RelayForward, HopCount: uint8(i),
			LinkAddress: netip.MustParseAddr("2001:db8:2::1"),
			PeerAddress: netip.MustParseAddr("fe80::1"), Inner: m}
	}
	c := dial(t, addr)
	c.send(m)
	c.expectSilence("a chain of three relays")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["too_many_hops"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up.seen()) != 0 {
		t.Fatal("the deep chain reached the server")
	}
}

// The hop bound at its exact boundary, which is what says max_relay_hops means
// what the reference says it means.
//
// The bound is on the chain this relay would send, so a message already at the
// bound is refused and one a single layer short goes through and comes out at
// the bound. Off by one here would either refuse a site that is within its
// budget or admit one a layer past it, and neither shows up in a test that
// sends a chain of ten.
func TestTheHopBoundHoldsAtItsBoundary(t *testing.T) {
	chain := func(depth int) *wire.Message {
		m := solicit(uint32(0xbc0000+depth), byte(depth))
		for i := 0; i < depth; i++ {
			m = &wire.Message{Type: wire.RelayForward, HopCount: uint8(i), //nolint:gosec // i < 4
				LinkAddress: netip.MustParseAddr("2001:db8:2::1"),
				PeerAddress: netip.MustParseAddr("fe80::1"), Inner: m}
		}
		return m
	}

	// One layer short of the bound: relayed, and the chain the server sees is
	// exactly max_relay_hops deep, because this relay added the last one.
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base+"        max_relay_hops: 3\n", up.addr())
	dial(t, addr).send(chain(2))
	fwd := up.await(t, 1, "a chain one layer short of the bound")[0]
	if got := relayDepth(fwd); got != 3 {
		t.Errorf("the server saw a chain %d deep", got)
	}

	// At the bound: refused, because relaying it would put it past.
	up2 := startServer(t, &fakeServer{})
	s2, addr2 := relayFor(t, base+"        max_relay_hops: 3\n", up2.addr())
	c2 := dial(t, addr2)
	c2.send(chain(3))
	c2.expectSilence("a chain already at the bound")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s2.Stats().Refusals["dhcp6"]["too_many_hops"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s2.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up2.seen()) != 0 {
		t.Fatal("a chain at the bound reached the server")
	}
}

// Shadow mode carries what the policy would have refused, and does not carry a
// hard refusal. That distinction is the whole point of the flag: a bound and a
// message two parsers would read differently are not opinions an operator can
// try out, because carrying one is the harm rather than a note about it.
func TestShadowModeStillRefusesAHardRefusal(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayWith(t, base, "      policy: {mode: shadow}\n", up.addr())
	c := dial(t, addr)

	// A client identifier twice: a message the relay would decide about from
	// the first value while a server acted on the last.
	m := solicit(0xbdbdbd, 0xbd)
	m.Options = append(m.Options, wire.Option{Code: wire.OptionClientID,
		Value: duidLL(2, 0, 0, 0, 0, 0xbe)})
	c.send(m)
	c.expectSilence("a repeated identifier in shadow mode")

	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["repeated_option"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals %+v would-deny %d", s.Stats().Refusals["dhcp6"],
				s.Stats().DHCP6WouldDeny)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up.seen()) != 0 {
		t.Fatal("a hard refusal was carried in shadow mode")
	}

	// And the soft half of the same listener still carries, so the mode is on.
	ok := solicit(0xbfbfbf, 0xbf)
	if got := c.ask(ok); got.Type != wire.Reply {
		t.Fatalf("shadow mode did not carry an ordinary request: %s", got.Type)
	}
}

// The pending table is the thing that pairs a reply with the client that asked,
// so when it is full the request is refused rather than the pairing made
// unreliable: a reply delivered to whichever client is guessed is worse than a
// client that retries.
func TestAFullPendingTableRefusesTheRequest(t *testing.T) {
	up := startServer(t, &fakeServer{silent: true})
	s, addr := relayFor(t, base+"        max_pending: 1\n        request_timeout: 30s\n",
		up.addr())

	first := dial(t, addr)
	first.send(solicit(0xc00001, 1))
	up.await(t, 1, "the first request")

	second := dial(t, addr)
	second.send(solicit(0xc00002, 2))
	second.expectSilence("a request with the table full")

	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["too_many_pending"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(up.seen()); n != 1 {
		t.Errorf("the server saw %d requests", n)
	}
}

// The client address list, which on this protocol says less than it looks --
// a DHCPv6 client sends from a link-local address it chose for itself -- and
// still decides for the one deployment where every sender is known: a listener
// fronting downstream relay agents.
func TestAClientOutsideTheListIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, host := loopback()
	s, addr := relayFor(t, base+"        deny_clients: [\""+denyAll(host)+"\"]\n", up.addr())
	c := dial(t, addr)
	c.send(solicit(0xc10001, 1))
	c.expectSilence("a client on a denied network")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["client_not_allowed"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up.seen()) != 0 {
		t.Fatal("a denied client reached the server")
	}
}

// denyAll is the loopback in use, as a network that covers it.
func denyAll(host string) string {
	if strings.HasPrefix(host, "[") {
		return "::1/128"
	}
	return "127.0.0.0/8"
}

// A pool whose only server is drained has nowhere to relay to, which is counted
// rather than guessed at: a relay that picked a drained endpoint anyway would
// undo the reason somebody drained it.
func TestNoServerToRelayToIsCounted(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, host := loopback()
	s := proxytest.Start(t, fmt.Sprintf(drainedYAML, host+":0", base, up.addr()))
	addr := proxytest.Addr(t, s, "segment")

	c := dial(t, addr)
	c.send(solicit(0xc20001, 1))
	c.expectSilence("a request with every server drained")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().DHCP6UpstreamFail > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing was counted as an upstream failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up.seen()) != 0 {
		t.Fatal("a drained server was relayed to")
	}
}

// drainedYAML is the same listener with its one server taken out of rotation.
// allow_servers is written out because it cannot be derived from a pool with
// nothing pickable in it.
const drainedYAML = `
version: 1
server:
  listeners:
    - name: segment
      address: %q
      kind: dhcp6
      dhcp6:
%s        allow_servers: ["::1/128", "127.0.0.0/8"]
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q, drain: true}]}
`

// A message from one relay agent is wrapped again by this one, and the hop count
// says how deep the chain is. That is the shape a relay in front of another
// relay has.
func TestARelayedMessageIsWrappedAgain(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base, up.addr())
	inner := solicit(0xbcbcbc, 14)
	one := &wire.Message{Type: wire.RelayForward, HopCount: 0,
		LinkAddress: netip.MustParseAddr("2001:db8:2::1"),
		PeerAddress: netip.MustParseAddr("fe80::1"), Inner: inner}
	c := dial(t, addr)
	c.send(one)
	seen := up.await(t, 1, "the request")
	if seen[0].HopCount != 1 {
		t.Fatalf("the outer hop count is %d", seen[0].HopCount)
	}
	chain := seen[0].Chain()
	if len(chain) != 3 || chain[2].Type != wire.Solicit {
		t.Fatalf("chain of %d", len(chain))
	}
	// The downstream relay's own link address is still on its own wrapper: it is
	// its statement about its segment and not this relay's to edit.
	if chain[1].LinkAddress != netip.MustParseAddr("2001:db8:2::1") {
		t.Errorf("the inner wrapper's link address is %s", chain[1].LinkAddress)
	}
}

// A message past the bound is refused unread: reading it to find out what it
// asked for is the work the bound exists to avoid.
func TestAnOversizeMessageIsRefusedUnread(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        max_message_bytes: 256\n", up.addr())
	c := dial(t, addr)
	m := solicit(0xcccccc, 15)
	m.Set(wire.OptionUserClass, make([]byte, 400))
	c.send(m)
	c.expectSilence("an oversize message")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["message_too_large"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The starvation bound is keyed on the identifier, not the source address: a
// thousand solicits from one host with a made-up identifier in each is what
// exhausts a pool, and a limit on the address would see one sender doing nothing
// unusual.
func TestTheRateLimitIsKeyedOnTheIdentifier(t *testing.T) {
	up := startServer(t, &fakeServer{silent: true})
	s, addr := relayFor(t, base+"        rate_limit: 2\n        rate_burst: 2\n", up.addr())
	c := dial(t, addr)
	// One identifier, many messages: the limit bites.
	for i := 0; i < 10; i++ {
		c.send(solicit(uint32(0xd00000+i), 16))
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().DHCP6RateLimited > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing was rate limited: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A different identifier from the same address still gets through, which is
	// what makes the key the identifier rather than the address.
	before := len(up.seen())
	c.send(solicit(0xd10000, 99))
	for deadline := time.Now().Add(5 * time.Second); ; {
		if len(up.seen()) > before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a fresh identifier was caught by another identifier's limit")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Shadow mode records what it would have refused and carries the traffic -- and
// the reply from an address that is not a server is still refused, because that
// one is never shadowed.
func TestShadowModeRecordsAndCarries(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayWith(t, base+"        message_types: [request]\n",
		"      policy: {mode: shadow}\n", up.addr())
	c := dial(t, addr)
	if got := c.ask(solicit(0xeeeeee, 17)); got.Type != wire.Reply {
		t.Fatalf("shadow mode refused: %s", got.Type)
	}
	up.await(t, 1, "the request")
	if s.Stats().DHCP6WouldDeny == 0 {
		t.Error("nothing was recorded as a would-be refusal")
	}
	if s.Stats().DHCP6Denied != 0 {
		t.Error("a shadow-mode listener counted a refusal it did not make")
	}
	if got := s.Stats().WouldRefusals["dhcp6"]["message_type_not_allowed"]; got == 0 {
		t.Errorf("would-refusals: %+v", s.Stats().WouldRefusals["dhcp6"])
	}
}

// An answer nobody asked for is not delivered to whichever client is guessed.
func TestAnUnsolicitedReplyIsDropped(t *testing.T) {
	up := startServer(t, &fakeServer{reply: func(fwd *wire.Message) *wire.Message {
		repl := answer(fwd)
		// A transaction identifier nobody used.
		repl.Inner.TransactionID = 0x0f0f0f
		return repl
	}})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)
	c.send(solicit(0xf1f1f1, 18))
	c.expectSilence("a reply to a transaction nobody started")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().DHCP6Unsolicited > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A rule about one fleet, by the identifier's rendering. A DUID pattern is how a
// rule about "the vendor's handsets" is written, because nobody lists every one.
func TestARuleMatchesOnTheIdentifier(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+`        rules:
          - name: nothing-from-this-fleet
            action: deny
            duids: ["ll:00030001020000000063*"]
`, up.addr())
	c := dial(t, addr)
	c.send(solicit(0x121212, 0x63))
	c.expectSilence("a client in the refused fleet")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["rule"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Another client is not the fleet.
	if got := c.ask(solicit(0x131313, 0x64)); got.Type != wire.Reply {
		t.Fatalf("a client outside the rule got a %s", got.Type)
	}
}

// A server renewing one address and withdrawing another in the same identity
// association, where the lease bound applies.
//
// This is the case where the guard in putLifetimes earns its place. The
// decision to rewrite is made per reply, so once one address in the association
// is over the ceiling every lifetime in it is walked -- and the withdrawn one
// must still come out as a withdrawal. A relay that wrote the ceiling over it
// would leave the device holding an address the estate has given to somebody
// else.
func TestAWithdrawalSurvivesABoundOnItsNeighbour(t *testing.T) {
	up := startServer(t, &fakeServer{reply: func(fwd *wire.Message) *wire.Message {
		repl := answer(fwd)
		in := repl.Inner
		in.Remove(wire.OptionIANA)
		// One address well over the ceiling, and one withdrawn, in one option.
		v := binary.BigEndian.AppendUint32(nil, 1)
		v = binary.BigEndian.AppendUint32(v, 1800)
		v = binary.BigEndian.AppendUint32(v, 2880)
		v = append(v, opt(wire.OptionIAAddr, addrBody("2001:db8:1::10", 40000, 80000))...)
		v = append(v, opt(wire.OptionIAAddr, addrBody("2001:db8:1::11", 0, 0))...)
		in.Options = append(in.Options, wire.Option{Code: wire.OptionIANA, Value: v})
		return repl
	}})
	s, addr := relayFor(t, base+"        max_lease_time: 1h\n", up.addr())
	c := dial(t, addr)
	got := c.ask(solicit(0x5a5a5a, 0x5a))

	ias, err := got.IAs()
	if err != nil {
		t.Fatalf("the reply's associations: %v", err)
	}
	if len(ias) != 1 || len(ias[0].Addresses) != 2 {
		t.Fatalf("the association came back as %+v", ias)
	}
	kept, withdrawn := ias[0].Addresses[0], ias[0].Addresses[1]
	if kept.Valid != 3600 {
		t.Errorf("the lease over the ceiling came back with %d seconds", kept.Valid)
	}
	if kept.Preferred != 3600 {
		// A preferred lifetime longer than the valid one makes the option
		// invalid, so it comes down with it.
		t.Errorf("the preferred lifetime came back as %d", kept.Preferred)
	}
	if withdrawn.Valid != 0 || withdrawn.Preferred != 0 {
		t.Errorf("the withdrawal became a lease of %d seconds (preferred %d)",
			withdrawn.Valid, withdrawn.Preferred)
	}
	if s.Stats().DHCP6LeaseBounded == 0 {
		t.Error("nothing was counted as bounded")
	}
}

// on_client_relay_option: deny refuses the message rather than trimming it,
// which is what an estate writes when a client claiming to be on a circuit is
// worth knowing about rather than quietly correcting.
func TestAClientsRelayOptionCanRefuseTheMessage(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        on_client_relay_option: deny\n", up.addr())
	m := solicit(0x5b5b5b, 0x5b)
	m.Set(wire.OptionSubscriberID, []byte("somebody-else"))
	c := dial(t, addr)
	c.send(m)
	c.expectSilence("a client claiming a subscriber identifier")
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["client_relay_option"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up.seen()) != 0 {
		t.Fatal("the message reached the server")
	}
}

// A server's own message arriving on the segment side, which is what a rogue
// server on the relay's own segment looks like from here. It gets its own
// reason, because the relay is not the only thing the clients can hear.
func TestAServersMessageOnTheSegmentIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	c := dial(t, addr)

	adv := &wire.Message{Type: wire.Advertise, TransactionID: 0x5c5c5c}
	adv.Set(wire.OptionServerID, duidLL(9, 9, 9, 9, 9, 9))
	adv.Set(wire.OptionDNSServers, netip.MustParseAddr("2001:db8:66::66").AsSlice())
	c.send(adv)
	c.expectSilence("an advertise from the segment")

	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["dhcp6"]["server_message_from_client_side"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["dhcp6"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(up.seen()) != 0 {
		t.Fatal("a server's message was relayed to a server")
	}
}

// addrBody is an IAADDR's value: the address and its two lifetimes.
func addrBody(addr string, preferred, valid uint32) []byte {
	out := netip.MustParseAddr(addr).AsSlice()
	out = binary.BigEndian.AppendUint32(out, preferred)
	return binary.BigEndian.AppendUint32(out, valid)
}
