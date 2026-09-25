package dhcp

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// build assembles a message the way a client does, so a test says what it means
// rather than what it looks like.
type build struct {
	op       Op
	hlen     uint8
	hops     uint8
	xid      uint32
	flags    uint16
	ciaddr   string
	giaddr   string
	chaddr   []byte
	sname    string
	file     string
	cookie   *[4]byte
	opts     []byte
	trailing []byte
}

func (b build) bytes() []byte {
	out := make([]byte, FixedLen)
	if b.op == 0 {
		b.op = BootRequest
	}
	out[0] = uint8(b.op)
	out[1] = HTypeEthernet
	if b.chaddr == nil {
		b.chaddr = []byte{0x02, 0, 0, 0, 0, 1}
	}
	out[2] = b.hlen
	if out[2] == 0 {
		out[2] = uint8(len(b.chaddr))
	}
	out[3] = b.hops
	out[4] = byte(b.xid >> 24)
	out[5] = byte(b.xid >> 16)
	out[6] = byte(b.xid >> 8)
	out[7] = byte(b.xid)
	out[10] = byte(b.flags >> 8)
	out[11] = byte(b.flags)
	if b.ciaddr != "" {
		a := netip.MustParseAddr(b.ciaddr).As4()
		copy(out[12:16], a[:])
	}
	if b.giaddr != "" {
		a := netip.MustParseAddr(b.giaddr).As4()
		copy(out[24:28], a[:])
	}
	copy(out[28:44], b.chaddr)
	copy(out[44:108], b.sname)
	copy(out[108:236], b.file)
	c := Cookie
	if b.cookie != nil {
		c = *b.cookie
	}
	out = append(out, c[:]...)
	out = append(out, b.opts...)
	out = append(out, OptEnd)
	out = append(out, b.trailing...)
	for len(out) < 300 {
		out = append(out, OptPad)
	}
	return out
}

// opt is one option as it appears on the wire.
func opt(code uint8, value ...byte) []byte {
	return append([]byte{code, uint8(len(value))}, value...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func discover(extra ...[]byte) []byte {
	return build{opts: cat(append([][]byte{opt(OptMessageType, uint8(Discover))}, extra...)...)}.bytes()
}

func TestAMessageIsReadHeaderThenOptions(t *testing.T) {
	raw := build{
		xid:    0xdeadbeef,
		flags:  0x8000,
		ciaddr: "10.0.0.7",
		giaddr: "10.0.0.1",
		chaddr: []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
		file:   "pxelinux.0",
		sname:  "boot.example.com",
		opts: cat(opt(OptMessageType, uint8(Request)),
			opt(OptRequestedIP, 10, 0, 0, 7),
			opt(OptParameterList, OptRouter, OptDNS, OptWPAD)),
	}.bytes()
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Op != BootRequest || m.Type != Request || m.XID != 0xdeadbeef {
		t.Fatalf("got %v %v xid %#x", m.Op, m.Type, m.XID)
	}
	if !m.Broadcast() {
		t.Error("the broadcast flag was not read")
	}
	if !m.Relayed() {
		t.Error("a message with a giaddr reads as un-relayed")
	}
	if m.CIAddr != netip.MustParseAddr("10.0.0.7") || m.GIAddr != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("addresses %v %v", m.CIAddr, m.GIAddr)
	}
	if got := HardwareAddr(m.CHAddr); got != "02:11:22:33:44:55" {
		t.Errorf("hardware address %q", got)
	}
	if m.File != "pxelinux.0" || m.SName != "boot.example.com" {
		t.Errorf("file %q sname %q", m.File, m.SName)
	}
	if v, ok := m.Get(OptParameterList); !ok || !bytes.Equal(v, []byte{OptRouter, OptDNS, OptWPAD}) {
		t.Errorf("parameter list %v present=%v", v, ok)
	}
	if !m.Has(OptRequestedIP) || m.Has(OptWPAD) {
		t.Error("an option that was sent is missing, or one that was not is present")
	}
}

// TestTheHardwareAddressIsHlenOctetsAndNotSix is why hlen is read: Infiniband
// addresses are twenty octets, and the padding after a six-octet one is
// whatever the client left there.
func TestTheHardwareAddressIsHlenOctetsAndNotSix(t *testing.T) {
	raw := build{chaddr: []byte{1, 2, 3}, hlen: 3,
		opts: opt(OptMessageType, uint8(Discover))}.bytes()
	// Leave rubbish in the rest of the field, as a real client's stack does.
	for i := 31; i < 44; i++ {
		raw[i] = 0xff
	}
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := HardwareAddr(m.CHAddr); got != "01:02:03" {
		t.Fatalf("hardware address %q, want the three octets hlen claims", got)
	}
}

// TestOptionOverloadIsReadFromTheHeaderFields is the first of the two
// encodings that make one message say different things to different parsers.
func TestOptionOverloadIsReadFromTheHeaderFields(t *testing.T) {
	// The dangerous option is hidden in the boot filename field, where a
	// reader that only walked the options field would never see it -- and a
	// server reads it, because RFC 2132 §9.3 says to.
	hidden := cat(opt(OptWPAD, 'h', 't', 't', 'p', ':', '/', '/', 'x'), []byte{OptEnd})
	raw := build{
		op:    BootReply,
		opts:  cat(opt(OptMessageType, uint8(Ack)), opt(OptOverload, 1)),
		file:  string(hidden),
		sname: "ignored",
	}.bytes()
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Overload != 1 {
		t.Fatalf("overload %d", m.Overload)
	}
	v, ok := m.Get(OptWPAD)
	if !ok || string(v) != "http://x" {
		t.Fatalf("the hidden option was not read: %q present=%v", v, ok)
	}
	// The file field held options, so it is not a filename.
	if m.File != "" {
		t.Errorf("file %q, want empty when it carried options", m.File)
	}
	// And sname was not overloaded, so it is still a string.
	if m.SName != "ignored" {
		t.Errorf("sname %q", m.SName)
	}
	if !m.Hidden() {
		t.Error("a message with an overloaded field does not report it")
	}
	for _, o := range m.Options {
		if o.Code == OptWPAD && o.Where != InFile {
			t.Errorf("the hidden option says it came from %v", o.Where)
		}
	}
}

// TestSeveralInstancesOfOneOptionAreOneOption is RFC 3396, the second such
// encoding: a reader that took the first instance and a server that joins them
// are reading different values.
func TestSeveralInstancesOfOneOptionAreOneOption(t *testing.T) {
	raw := build{op: BootReply,
		opts: cat(opt(OptMessageType, uint8(Ack)),
			opt(OptBootFile, 'p', 'a', 'r', 't', '1'),
			opt(OptDNS, 10, 0, 0, 1),
			opt(OptBootFile, 'p', 'a', 'r', 't', '2'))}.bytes()
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := m.Get(OptBootFile)
	if !ok || string(v) != "part1part2" {
		t.Fatalf("joined value %q present=%v", v, ok)
	}
	// The order is the order the codes first appeared, which is what a relay
	// has to write back.
	want := []uint8{OptMessageType, OptBootFile, OptDNS}
	if got := m.Codes(); len(got) != len(want) {
		t.Fatalf("codes %v, want %v", got, want)
	}
	for _, o := range m.Options {
		if o.Code == OptBootFile && !o.Split {
			t.Error("the joined option does not say it was split")
		}
	}
	if !m.Hidden() {
		t.Error("a message using the long-option encoding does not report it")
	}
}

func TestTheMessagesThatAreNotMessages(t *testing.T) {
	for what, raw := range map[string][]byte{
		"nothing":                {},
		"a header and no cookie": make([]byte, FixedLen),
		"the wrong cookie": build{cookie: &[4]byte{1, 2, 3, 4},
			opts: opt(OptMessageType, uint8(Discover))}.bytes(),
		"an op nobody defined": build{op: Op(7),
			opts: opt(OptMessageType, uint8(Discover))}.bytes(),
		"no message type":          build{opts: opt(OptRequestedIP, 10, 0, 0, 1)}.bytes(),
		"a message past the bound": make([]byte, MaxPacket+1),
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s parsed", what)
		}
	}
	// An option claiming more octets than the field has left. It has to be
	// built without the padding a real client sends, because padding *is*
	// part of the options field: an option that runs into it is readable, and
	// only one that runs past the end of the message is not.
	head := build{opts: opt(OptMessageType, uint8(Discover))}.bytes()[:MinPacket]
	over := cat(head, opt(OptMessageType, uint8(Discover)), []byte{OptRouter, 40, 1, 2})
	if _, err := Parse(over); err == nil {
		t.Error("an option claiming more than is there parsed")
	}
	if _, err := Parse(cat(head, opt(OptMessageType, uint8(Discover)), []byte{OptRouter})); err == nil {
		t.Error("an option with no length octet parsed")
	}

	// A message type of zero: option 53 present, one octet, and a value no
	// standard defines. The fuzzer found this one -- it is the absent value
	// wearing a length, and a relay cannot decide about a message whose type
	// the two ends may read differently.
	if _, err := Parse(build{opts: opt(OptMessageType, 0)}.bytes()); err == nil {
		t.Error("a message type of zero parsed")
	}
	// A type nobody has defined but which is not zero is carried, because the
	// policy's type list is where a later RFC's type belongs rather than a
	// code change in the reader.
	m, err := Parse(build{opts: opt(OptMessageType, 200)}.bytes())
	if err != nil {
		t.Errorf("an undefined message type was refused by the reader: %v", err)
	} else if m.Type.Known() || m.Type != MessageType(200) {
		t.Errorf("type %v", m.Type)
	}

	// An hlen longer than the field that holds it: one reader takes sixteen
	// octets and another reads past them, and the address is what a lease is
	// keyed on.
	raw := build{hlen: 200, opts: opt(OptMessageType, uint8(Discover))}.bytes()
	if _, err := Parse(raw); err == nil {
		t.Error("an hlen of 200 parsed")
	}
}

// TestWhatIsAfterTheTerminatorIsNotRead: everything past option 255 is padding
// by definition, and a reader that kept going would be reading a field two
// parsers disagree about.
func TestWhatIsAfterTheTerminatorIsNotRead(t *testing.T) {
	raw := build{opts: opt(OptMessageType, uint8(Discover)),
		trailing: opt(OptWPAD, 'x')}.bytes()
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Has(OptWPAD) {
		t.Fatal("an option after the terminator was read")
	}
}

func TestTooManyOptionsIsRefused(t *testing.T) {
	var many []byte
	for i := 0; i <= MaxOptions; i++ {
		many = append(many, opt(uint8(100+i%100), 1)...)
	}
	if _, err := Parse(build{opts: cat(opt(OptMessageType, uint8(Discover)), many)}.bytes()); err == nil {
		t.Fatal("a message with more options than the bound parsed")
	}
}

func TestAMessageTypeIsNamedTheWayARuleWritesIt(t *testing.T) {
	for _, c := range []struct {
		in   string
		want MessageType
	}{
		{"discover", Discover}, {"DHCPDISCOVER", Discover}, {" offer ", Offer},
		{"ack", Ack}, {"nak", Nak}, {"force_renew", ForceRenew},
		{"forcerenew", ForceRenew}, {"lease_query", LeaseQuery},
	} {
		got, ok := TypeOf(c.in)
		if !ok || got != c.want {
			t.Errorf("%q read as %v ok=%v", c.in, got, ok)
		}
	}
	if _, ok := TypeOf("renew"); ok {
		t.Error("a message type nobody defines was named")
	}
	if !strings.Contains(MessageType(99).String(), "99") {
		t.Errorf("an unknown type hides its number: %q", MessageType(99))
	}
	// The direction a type belongs to is read from the type, because the type
	// and the direction disagreeing is itself the finding.
	if !Discover.FromClient() || Discover.FromServer() {
		t.Error("a discover is a client's")
	}
	if !Offer.FromServer() || Offer.FromClient() {
		t.Error("an offer is a server's")
	}
	if !Ack.Assigns() || Discover.Assigns() {
		t.Error("the assigning types are the offer and the ack")
	}
	if BootRequest.String() != "request" || BootReply.String() != "reply" {
		t.Error("the two operations are not named")
	}
	if !strings.Contains(Op(7).String(), "7") {
		t.Errorf("an unknown op hides its number: %q", Op(7))
	}
}

func TestAnOptionIsNamedByNameOrByNumber(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint8
	}{
		{"router", OptRouter}, {"WPAD_URL", OptWPAD}, {" 121 ", OptClasslessRoute},
		{"0", OptPad}, {"255", OptEnd}, {"classless_static_route", OptClasslessRoute},
	} {
		got, ok := OptionOf(c.in)
		if !ok || got != c.want {
			t.Errorf("%q read as %d ok=%v", c.in, got, ok)
		}
	}
	for _, bad := range []string{"", "256", "-1", "not_an_option"} {
		if _, ok := OptionOf(bad); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
	if OptionName(OptWPAD) != "wpad_url" {
		t.Errorf("name %q", OptionName(OptWPAD))
	}
	if got := OptionName(200); got != "option_200" {
		t.Errorf("an unnamed option hides its number: %q", got)
	}
}

func TestTheTypedOptionReaders(t *testing.T) {
	as, err := Addresses([]byte{10, 0, 0, 1, 10, 0, 0, 2})
	if err != nil || len(as) != 2 || as[1] != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("addresses %v err %v", as, err)
	}
	for _, bad := range [][]byte{{}, {10, 0, 0}, {10, 0, 0, 1, 2}} {
		if _, err := Addresses(bad); err == nil {
			t.Errorf("%v read as an address list", bad)
		}
	}
	if _, err := Address([]byte{10, 0, 0}); err == nil {
		t.Error("three octets read as an address")
	}
	if n, err := Seconds([]byte{0, 0, 1, 0}); err != nil || n != 256 {
		t.Errorf("seconds %d err %v", n, err)
	}
	if _, err := Seconds([]byte{0, 1}); err == nil {
		t.Error("two octets read as a duration")
	}
}

// TestAClasslessRouteIsDecodedSoTheRefusalCanSayWhich: an operator who sees a
// route injection refused deserves to be told which route.
func TestAClasslessRouteIsDecodedSoTheRefusalCanSayWhich(t *testing.T) {
	// 0.0.0.0/0 via 10.0.0.9 -- a default route in a broadcast reply -- and
	// 192.168.1.0/24 via 10.0.0.9, whose destination is three significant
	// octets rather than four.
	v := []byte{0, 10, 0, 0, 9, 24, 192, 168, 1, 10, 0, 0, 9}
	rs, err := Routes(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("routes %v", rs)
	}
	if rs[0].String() != "0.0.0.0/0 via 10.0.0.9" {
		t.Errorf("first route %q", rs[0])
	}
	if rs[1].String() != "192.168.1.0/24 via 10.0.0.9" {
		t.Errorf("second route %q", rs[1])
	}
	for _, bad := range [][]byte{{}, {33, 1, 2, 3, 4, 5}, {24, 192, 168}, {0, 10, 0}} {
		if _, err := Routes(bad); err == nil {
			t.Errorf("%v read as routes", bad)
		}
	}
}

func TestAHardwareAddressRoundTrips(t *testing.T) {
	for _, s := range []string{"02:11:22:33:44:55", "02-11-22-33-44-55", "02.11.22.33.44.55"} {
		b, err := ParseHardwareAddr(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got := HardwareAddr(b); got != "02:11:22:33:44:55" {
			t.Errorf("%q became %q", s, got)
		}
		if got := OUI(b); got != "02:11:22" {
			t.Errorf("OUI %q", got)
		}
	}
	for _, bad := range []string{"", "zz:11", "02:11:2", "02:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"} {
		if _, err := ParseHardwareAddr(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if OUI([]byte{1, 2}) != "" {
		t.Error("an address too short to have a vendor reported one")
	}
}

func TestTheAgentOptionIsBuiltAndRead(t *testing.T) {
	v, err := AgentInfo("eth0:vlan10", "relay-1")
	if err != nil {
		t.Fatal(err)
	}
	subs, err := SubOptions(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 || subs[0].Code != 1 || string(subs[0].Value) != "eth0:vlan10" {
		t.Fatalf("suboptions %v", subs)
	}
	if string(subs[1].Value) != "relay-1" {
		t.Errorf("remote id %q", subs[1].Value)
	}
	if _, err := AgentInfo("", ""); err == nil {
		t.Error("an agent option with no suboptions was built")
	}
	if _, err := AgentInfo(strings.Repeat("x", 256), ""); err == nil {
		t.Error("a suboption longer than its length octet was built")
	}
	for _, bad := range [][]byte{{}, {1}, {1, 40, 2}} {
		if _, err := SubOptions(bad); err == nil {
			t.Errorf("%v read as suboptions", bad)
		}
	}
}

// FuzzParse feeds arbitrary datagrams to the reader. Every one of them arrives
// on a broadcast segment before anything has authenticated anything, because
// there is nothing in this protocol to authenticate with.
func FuzzParse(f *testing.F) {
	f.Add(discover())
	f.Add(build{op: BootReply, opts: cat(opt(OptMessageType, uint8(Ack)),
		opt(OptRouter, 10, 0, 0, 1))}.bytes())
	f.Add([]byte{})
	f.Add(make([]byte, MinPacket))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			if m != nil {
				t.Fatal("an error came with a message")
			}
			return
		}
		if m == nil {
			t.Fatal("no error and no message")
		}
		if m.Op != BootRequest && m.Op != BootReply {
			t.Fatalf("op %v was accepted", m.Op)
		}
		if len(m.CHAddr) > MaxHWLen {
			t.Fatalf("a hardware address of %d octets", len(m.CHAddr))
		}
		if len(m.Options) > MaxOptions {
			t.Fatalf("%d options", len(m.Options))
		}
		if m.Type == 0 {
			t.Fatal("a message with no type was accepted")
		}
	})
}
