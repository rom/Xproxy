package dhcp6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// opt builds one option as it appears on the wire.
func opt(code uint16, value ...byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, code)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	return append(out, value...)
}

// msg builds a client or server message.
func msg(t MessageType, xid uint32, opts ...[]byte) []byte {
	out := []byte{byte(t), byte(xid >> 16), byte(xid >> 8), byte(xid)}
	for _, o := range opts {
		out = append(out, o...)
	}
	return out
}

// relay builds a RELAY-FORW around a message.
func relay(hops uint8, link, peer string, inner []byte, opts ...[]byte) []byte {
	out := []byte{byte(RelayForward), hops}
	out = appendAddr(out, netip.MustParseAddr(link))
	out = appendAddr(out, netip.MustParseAddr(peer))
	out = append(out, opt(OptionRelayMsg, inner...)...)
	for _, o := range opts {
		out = append(out, o...)
	}
	return out
}

func duidLL(mac ...byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(DUIDLL))
	out = binary.BigEndian.AppendUint16(out, 1) // ethernet
	return append(out, mac...)
}

func TestAMessageIsReadFromItsOctets(t *testing.T) {
	raw := msg(Solicit, 0x0a0b0c,
		opt(OptionClientID, duidLL(0x02, 0, 0, 0, 0, 1)...),
		opt(OptionElapsedTime, 0x00, 0x64),
		opt(OptionORO, 0x00, byte(OptionDNSServers), 0x00, byte(OptionDomainList)),
	)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != Solicit {
		t.Errorf("type %s", m.Type)
	}
	if m.TransactionID != 0x0a0b0c {
		t.Errorf("transaction identifier %#x", m.TransactionID)
	}
	if len(m.Options) != 3 {
		t.Fatalf("%d options", len(m.Options))
	}
	if m.Depth != 0 || m.Inner != nil {
		t.Errorf("an unrelayed message reports depth %d", m.Depth)
	}
	if !m.Has(OptionClientID) || m.Has(OptionServerID) {
		t.Errorf("codes %v", m.Codes())
	}
	d, ok := m.ClientDUID()
	if !ok {
		t.Fatal("the client identifier did not read")
	}
	if d.Type != DUIDLL || d.HardwareAddr() != "02:00:00:00:00:01" {
		t.Errorf("DUID %+v hardware %q", d, d.HardwareAddr())
	}
	// The raw octets are kept, because a decision is made about the message
	// that arrived rather than about a re-rendering of it.
	if !bytes.Equal(m.Raw, raw) {
		t.Error("the message does not carry its own octets")
	}
}

// A message with no options is legal: an empty INFORMATION-REQUEST is a client
// asking for whatever a server will tell it.
func TestAMessageWithNoOptions(t *testing.T) {
	m, err := Parse(msg(InformationRequest, 1))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Options) != 0 || len(m.Codes()) != 0 {
		t.Fatalf("%d options", len(m.Options))
	}
}

func TestAMalformedMessageIsRefused(t *testing.T) {
	long := make([]byte, MaxMessage+1)
	long[0] = byte(Solicit)
	var many []byte
	many = append(many, msg(Solicit, 1)...)
	for i := 0; i <= MaxOptions; i++ {
		many = append(many, opt(OptionRapidCommit)...)
	}
	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"nothing at all", nil, ErrShort},
		{"a header cut short", []byte{byte(Solicit), 1, 2}, ErrShort},
		{"an option header cut short", append(msg(Solicit, 1), 0x00, 0x01, 0x00), ErrOption},
		{"an option longer than what is there",
			append(msg(Solicit, 1), 0x00, 0x01, 0x00, 0x20, 0x01), ErrOption},
		{"a message past the bound", long, ErrTooLong},
		{"more options than the bound", many, ErrTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// The relay chain: the client's own message is at the bottom, and what a policy
// decides about is that one rather than the wrapper.
func TestTheRelayChainIsFollowedToTheClientsOwnMessage(t *testing.T) {
	inner := msg(Solicit, 0x112233, opt(OptionClientID, duidLL(2, 0, 0, 0, 0, 9)...))
	one := relay(0, "2001:db8::1", "fe80::1", inner, opt(OptionInterfaceID, 'e', 't', 'h', '0'))
	two := relay(1, "2001:db8::2", "fe80::2", one)

	m, err := Parse(two)
	if err != nil {
		t.Fatal(err)
	}
	chain := m.Chain()
	if len(chain) != 3 {
		t.Fatalf("%d messages in the chain", len(chain))
	}
	if chain[0].Type != RelayForward || chain[1].Type != RelayForward || chain[2].Type != Solicit {
		t.Fatalf("chain %s, %s, %s", chain[0].Type, chain[1].Type, chain[2].Type)
	}
	if chain[0].HopCount != 1 || chain[1].HopCount != 0 {
		t.Errorf("hop counts %d and %d", chain[0].HopCount, chain[1].HopCount)
	}
	if chain[0].LinkAddress != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("outer link address %s", chain[0].LinkAddress)
	}
	if chain[1].PeerAddress != netip.MustParseAddr("fe80::1") {
		t.Errorf("inner peer address %s", chain[1].PeerAddress)
	}
	for i, want := range []int{0, 1, 2} {
		if chain[i].Depth != want {
			t.Errorf("message %d reports depth %d", i, chain[i].Depth)
		}
	}
	in := m.Innermost()
	if in.Type != Solicit || in.TransactionID != 0x112233 {
		t.Fatalf("innermost %s %#x", in.Type, in.TransactionID)
	}
	// The identifiers come from the innermost message, because that is the
	// client's own; the wrapper is this relay's and its neighbours'.
	if d, ok := m.ClientDUID(); !ok || d.HardwareAddr() != "02:00:00:00:00:09" {
		t.Errorf("client DUID %+v", d)
	}
	// And the relay's own option in the middle wrapper is where it belongs.
	if _, ok := chain[1].Get(OptionInterfaceID); !ok {
		t.Error("the interface identifier is not on the wrapper that added it")
	}
}

func TestAMalformedRelayMessageIsRefused(t *testing.T) {
	inner := msg(Solicit, 1)
	deep := inner
	for i := 0; i <= MaxNesting; i++ {
		deep = relay(0, "2001:db8::1", "fe80::1", deep)
	}
	noInside := []byte{byte(RelayForward), 0}
	noInside = appendAddr(noInside, netip.MustParseAddr("2001:db8::1"))
	noInside = appendAddr(noInside, netip.MustParseAddr("fe80::1"))

	hopped := relay(MaxHopCount+1, "2001:db8::1", "fe80::1", inner)

	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"a relay header cut short", []byte{byte(RelayForward), 0, 1, 2}, ErrShort},
		{"a relay message with nothing inside", noInside, ErrRelay},
		{"a hop count past the standard's", hopped, ErrRelay},
		{"a chain deeper than the bound", deep, ErrRelay},
		{"an inner message that is not one",
			relay(0, "2001:db8::1", "fe80::1", []byte{byte(Solicit), 1}), ErrShort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A chain exactly at the bound is a topology, not an attack: the bound refuses
// what is past it and nothing else.
func TestAChainAtTheBoundIsRead(t *testing.T) {
	deep := msg(Solicit, 1)
	for i := 0; i < MaxNesting-1; i++ {
		deep = relay(uint8(i), "2001:db8::1", "fe80::1", deep) //nolint:gosec // below the bound
	}
	m, err := Parse(deep)
	if err != nil {
		t.Fatalf("a chain of %d was refused: %v", MaxNesting-1, err)
	}
	if got := len(m.Chain()); got != MaxNesting {
		t.Fatalf("%d messages in the chain", got)
	}
}

// An option appearing twice is a message two implementations will read
// differently, unless it is one of the ones that may repeat -- and the
// identity associations may, because a client asks for several.
func TestARepeatedOptionIsReported(t *testing.T) {
	m, err := Parse(msg(Solicit, 1,
		opt(OptionClientID, duidLL(2, 0, 0, 0, 0, 1)...),
		opt(OptionClientID, duidLL(2, 0, 0, 0, 0, 2)...),
		opt(OptionElapsedTime, 0, 1),
	))
	if err != nil {
		t.Fatal(err)
	}
	rep := m.Repeated()
	if len(rep) != 1 || rep[0] != OptionClientID {
		t.Fatalf("repeated %v", rep)
	}
	// Get takes the first, All takes both: a caller that has to decide can see
	// that there was something to decide.
	v, _ := m.Get(OptionClientID)
	if !bytes.Equal(v, duidLL(2, 0, 0, 0, 0, 1)) {
		t.Error("Get did not take the first value")
	}
	if len(m.All(OptionClientID)) != 2 {
		t.Error("All did not see both")
	}

	// Several identity associations are ordinary.
	ok, err := Parse(msg(Solicit, 1,
		opt(OptionIANA, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
		opt(OptionIANA, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0),
	))
	if err != nil {
		t.Fatal(err)
	}
	if got := ok.Repeated(); len(got) != 0 {
		t.Fatalf("two identity associations reported as repeated: %v", got)
	}
}

func TestTheMessageTypesSaySoWhoSendsThem(t *testing.T) {
	for _, tc := range []struct {
		t                MessageType
		client, server   bool
		isRelay, assigns bool
	}{
		{Solicit, true, false, false, false},
		{Advertise, false, true, false, true},
		{Request, true, false, false, false},
		{Reply, false, true, false, true},
		{Release, true, false, false, false},
		{Decline, true, false, false, false},
		{Reconfigure, false, true, false, false},
		{InformationRequest, true, false, false, false},
		{RelayForward, false, false, true, false},
		{RelayReply, false, false, true, false},
		// A requestor's message: towards a server, so the client's direction.
		{LeaseQuery, true, false, false, false},
		{LeaseQueryReply, false, true, false, false},
		{LeaseQueryDone, false, true, false, false},
		{LeaseQueryData, false, true, false, false},
	} {
		t.Run(tc.t.String(), func(t *testing.T) {
			if tc.t.FromClient() != tc.client || tc.t.FromServer() != tc.server {
				t.Errorf("client %v server %v", tc.t.FromClient(), tc.t.FromServer())
			}
			if tc.t.IsRelay() != tc.isRelay || tc.t.Assigns() != tc.assigns {
				t.Errorf("relay %v assigns %v", tc.t.IsRelay(), tc.t.Assigns())
			}
			if !tc.t.Known() {
				t.Error("not known")
			}
			got, ok := TypeOf(tc.t.String())
			if !ok || got != tc.t {
				t.Errorf("the name %q did not read back", tc.t.String())
			}
		})
	}
	if MessageType(200).Known() {
		t.Error("a type nobody defined is known")
	}
	if _, ok := TypeOf("nonsense"); ok {
		t.Error("a name nobody uses read back")
	}
	// A type this relay does not know is neither a client's nor a server's, so
	// nothing forwards it on a guess.
	unknown := MessageType(200)
	if unknown.FromClient() || unknown.FromServer() || unknown.IsRelay() {
		t.Error("an undefined type was attributed to somebody")
	}
}

func TestADUIDIsReadAndNamed(t *testing.T) {
	llt := binary.BigEndian.AppendUint16(nil, uint16(DUIDLLT))
	llt = binary.BigEndian.AppendUint16(llt, 1)
	llt = binary.BigEndian.AppendUint32(llt, 0x2a2a2a2a)
	llt = append(llt, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55)

	en := binary.BigEndian.AppendUint16(nil, uint16(DUIDEN))
	en = binary.BigEndian.AppendUint32(en, 9)
	en = append(en, 'a', 'b', 'c')

	uuid := binary.BigEndian.AppendUint16(nil, uint16(DUIDUUID))
	uuid = append(uuid, make([]byte, 16)...)

	for _, tc := range []struct {
		name string
		in   []byte
		want DUIDType
		mac  string
	}{
		{"link layer and time", llt, DUIDLLT, "02:11:22:33:44:55"},
		{"link layer", duidLL(0x02, 0, 0, 0, 0, 1), DUIDLL, "02:00:00:00:00:01"},
		{"enterprise", en, DUIDEN, ""},
		{"uuid", uuid, DUIDUUID, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseDUID(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if d.Type != tc.want {
				t.Errorf("type %s", d.Type)
			}
			if d.HardwareAddr() != tc.mac {
				t.Errorf("hardware address %q, want %q", d.HardwareAddr(), tc.mac)
			}
			// The rendering is stable and carries the whole identifier, because
			// it is what a lease table is keyed on.
			if got := d.String(); !bytes.Contains([]byte(got), []byte(d.Type.String())) {
				t.Errorf("rendering %q", got)
			}
			again, err := ParseDUID(tc.in)
			if err != nil || again.String() != d.String() {
				t.Error("the rendering is not stable")
			}
		})
	}
	// A form this relay does not know is kept opaque rather than refused: RFC
	// 8415 s11.1 says a receiver must treat an unknown type as an identifier.
	unknown := binary.BigEndian.AppendUint16(nil, 9)
	unknown = append(unknown, 1, 2, 3)
	d, err := ParseDUID(unknown)
	if err != nil {
		t.Fatalf("an unknown DUID form was refused: %v", err)
	}
	if !bytes.Equal(d.Raw, unknown) || d.HardwareAddr() != "" {
		t.Errorf("unknown form %+v", d)
	}
}

func TestAMalformedDUIDIsRefused(t *testing.T) {
	long := make([]byte, MaxDUID+1)
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"nothing", nil},
		{"one octet", []byte{1}},
		{"a link-layer-and-time form with no time", []byte{0, 1, 0, 1}},
		{"a link-layer form with no hardware type", []byte{0, 3, 1}},
		{"an enterprise form with no number", []byte{0, 2, 0, 0}},
		{"a UUID that is not sixteen octets", append([]byte{0, 4}, make([]byte, 15)...)},
		{"past the bound of RFC 8415", long},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDUID(tc.in); !errors.Is(err, ErrDUID) {
				t.Fatalf("got %v, want %v", err, ErrDUID)
			}
		})
	}
	if got := (DUID{}).String(); got != "duid:none" {
		t.Errorf("an empty DUID renders as %q", got)
	}
}

// FuzzParse holds the parser to what it promises whatever the octets are: every
// bound honoured, every message it accepts re-encodable, and never a panic on a
// length somebody else wrote.
func FuzzParse(f *testing.F) {
	f.Add(msg(Solicit, 1, opt(OptionClientID, duidLL(2, 0, 0, 0, 0, 1)...)))
	f.Add(relay(0, "2001:db8::1", "fe80::1", msg(Solicit, 1)))
	f.Add(msg(Reply, 2, opt(OptionIANA, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0)))
	f.Add([]byte{})
	f.Add([]byte{byte(RelayForward)})
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
		depth := 0
		for p := m; p != nil; p = p.Inner {
			depth++
			if depth > MaxNesting+1 {
				t.Fatalf("a chain of %d was accepted", depth)
			}
			if len(p.Options) > MaxOptions {
				t.Fatalf("%d options were accepted", len(p.Options))
			}
			if p.Type.IsRelay() {
				if p.HopCount > MaxHopCount {
					t.Fatalf("a hop count of %d was accepted", p.HopCount)
				}
				if p.Inner == nil {
					t.Fatal("a relay message with nothing inside was accepted")
				}
			}
			// Every accessor has to hold on whatever was accepted.
			_ = p.Codes()
			_ = p.Repeated()
			_, _ = p.ClientDUID()
			_, _ = p.ServerDUID()
			if ias, err := p.IAs(); err == nil {
				for _, ia := range ias {
					for _, pfx := range ia.Prefixes {
						if pfx.Prefix.Bits() > 128 || pfx.Prefix.Bits() < 0 {
							t.Fatalf("a prefix of %d bits was accepted", pfx.Prefix.Bits())
						}
					}
				}
			}
		}
		// A message this parser accepted has to be one it can render again: a
		// relay builds what it forwards, so a message it could read and not
		// write would be one it had to drop for a reason nobody could see.
		if _, err := Encode(m); err != nil {
			t.Fatalf("a message that parsed did not encode: %v", err)
		}
	})
}

// A truncated option value is refused rather than read off the end.
//
// Each of these is a length a peer chose, and the value is shorter than the
// fields the standard says are in it. There is nothing to do with such an option
// but refuse the message: a parser that read what it could would be inventing
// the rest, and one that indexed past the value would take the daemon down with
// a datagram anybody on the segment can send.
func TestATruncatedOptionValueIsRefused(t *testing.T) {
	// An IAADDR is sixteen octets of address and two lifetimes: twenty-four.
	for n := 0; n < 24; n++ {
		inner := optionBytes(OptionIAAddr, make([]byte, n))
		v := append(iaHead(1), inner...)
		m := &Message{Type: Reply, TransactionID: 1}
		m.Options = append(m.Options, Option{Code: OptionIANA, Value: v})
		raw, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("an address option of %d octets did not even parse: %v", n, err)
		}
		if _, err := got.IAs(); err == nil {
			t.Errorf("an address option of %d octets was accepted", n)
		}
	}
	// An IAPREFIX is two lifetimes, a length octet and sixteen of prefix:
	// twenty-five. The one extra octet over an address is the length, and it is
	// the octet a reader most easily forgets.
	for n := 0; n < 25; n++ {
		inner := optionBytes(OptionIAPrefix, make([]byte, n))
		v := append(iaHead(1), inner...)
		m := &Message{Type: Reply, TransactionID: 1}
		m.Options = append(m.Options, Option{Code: OptionIAPD, Value: v})
		raw, err := Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("a prefix option of %d octets did not even parse: %v", n, err)
		}
		if _, err := got.IAs(); err == nil {
			t.Errorf("a prefix option of %d octets was accepted", n)
		}
	}
}

// A relay message shorter than its own header is refused at every length, and
// the header is thirty-four octets because it carries two addresses.
func TestARelayMessageShorterThanItsHeaderIsRefused(t *testing.T) {
	for n := 1; n < RelayHeaderLen; n++ {
		raw := make([]byte, n)
		raw[0] = byte(RelayForward)
		if _, err := Parse(raw); err == nil {
			t.Errorf("a relay message of %d octets was accepted", n)
		}
	}
	// And thirty-four exactly is a relay message with no options, which is
	// malformed for another reason -- there is no Relay-Message inside it -- but
	// not a truncated header.
	raw := make([]byte, RelayHeaderLen)
	raw[0] = byte(RelayForward)
	if _, err := Parse(raw); err != nil && !errors.Is(err, ErrRelay) {
		t.Errorf("a bare relay header: %v", err)
	}
}

// The message bound, with a message that is otherwise entirely valid: the
// refusal has to be about the length rather than about anything else, or the
// test would pass with the bound gone.
//
// The oversize one is assembled as octets rather than through Encode, because
// Encode refuses the bound too -- which is the right thing for a message this
// daemon sends, and no help at all against one it receives.
func TestAMessageOverTheBoundIsRefused(t *testing.T) {
	build := func(n int) []byte {
		raw := []byte{byte(Reply), 0, 0, 1}
		raw = append(raw, optionBytes(OptionClientID, []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6})...)
		for i := 0; i < n; i++ {
			raw = append(raw, optionBytes(OptionVendorOpts, make([]byte, 1000))...)
		}
		return raw
	}
	// Just under the bound: it parses, and every option is there, so the
	// refusal below cannot be about the shape of the message.
	under := build(8)
	if len(under) > MaxMessage {
		t.Fatalf("the under-bound message is %d octets", len(under))
	}
	m, err := Parse(under)
	if err != nil {
		t.Fatalf("a message of %d octets was refused: %v", len(under), err)
	}
	if len(m.Options) != 9 {
		t.Fatalf("the under-bound message parsed to %d options", len(m.Options))
	}
	// One more option takes it over, and nothing else about it changed.
	over := build(9)
	if len(over) <= MaxMessage {
		t.Fatalf("the over-bound message is only %d octets", len(over))
	}
	if _, err := Parse(over); !errors.Is(err, ErrTooLong) {
		t.Errorf("a message of %d octets: %v", len(over), err)
	}
}

// iaHead is an identity association's own fields: the IAID and the two renewal
// times.
func iaHead(iaid uint32) []byte {
	v := binary.BigEndian.AppendUint32(nil, iaid)
	v = binary.BigEndian.AppendUint32(v, 1800)
	return binary.BigEndian.AppendUint32(v, 2880)
}

func optionBytes(code uint16, value []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, code)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	return append(out, value...)
}
