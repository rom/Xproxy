package dhcp6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// What a relay builds has to be what a server reads, so the round trip is the
// test: encode, parse, and compare.
func TestAMessageRoundTrips(t *testing.T) {
	m := &Message{Type: Solicit, TransactionID: 0xabcdef, Options: []Option{
		{Code: OptionClientID, Value: duidLL(2, 0, 0, 0, 0, 1)},
		{Code: OptionElapsedTime, Value: []byte{0, 100}},
		{Code: OptionRapidCommit},
	}}
	raw, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != m.Type || got.TransactionID != m.TransactionID {
		t.Fatalf("type %s transaction %#x", got.Type, got.TransactionID)
	}
	if len(got.Options) != 3 {
		t.Fatalf("%d options", len(got.Options))
	}
	for i, o := range m.Options {
		if got.Options[i].Code != o.Code || !bytes.Equal(got.Options[i].Value, o.Value) {
			t.Errorf("option %d: %+v", i, got.Options[i])
		}
	}
}

// The wrapper a relay builds, and the client's message recovered from the
// answer. This is the whole of the relay mechanism.
func TestWrappingAndUnwrapping(t *testing.T) {
	inner, err := Parse(msg(Solicit, 0x010203, opt(OptionClientID, duidLL(2, 0, 0, 0, 0, 7)...)))
	if err != nil {
		t.Fatal(err)
	}
	link := netip.MustParseAddr("2001:db8:1::1")
	peer := netip.MustParseAddr("fe80::a")
	fwd, err := Wrap(inner, link, peer, Option{Code: OptionInterfaceID, Value: []byte("eth0")})
	if err != nil {
		t.Fatal(err)
	}
	if fwd.Type != RelayForward || fwd.HopCount != 0 {
		t.Fatalf("wrapper %s hops %d", fwd.Type, fwd.HopCount)
	}
	raw, err := Encode(fwd)
	if err != nil {
		t.Fatal(err)
	}
	// What a server sees.
	seen, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if seen.LinkAddress != link || seen.PeerAddress != peer {
		t.Errorf("link %s peer %s", seen.LinkAddress, seen.PeerAddress)
	}
	if _, ok := seen.Get(OptionInterfaceID); !ok {
		t.Error("the relay's own option did not survive")
	}
	in := seen.Innermost()
	if in.Type != Solicit || in.TransactionID != 0x010203 {
		t.Fatalf("innermost %s %#x", in.Type, in.TransactionID)
	}
	if !bytes.Equal(in.Raw, inner.Raw) {
		t.Error("the client's own octets did not survive the wrapper")
	}

	// And the way back: a RELAY-REPL carrying the answer.
	answer := &Message{Type: Reply, TransactionID: 0x010203, Options: []Option{
		{Code: OptionServerID, Value: duidLL(2, 0, 0, 0, 0, 1)},
	}}
	repl := &Message{Type: RelayReply, LinkAddress: link, PeerAddress: peer, Inner: answer}
	rraw, err := Encode(repl)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(rraw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Unwrap(back)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != Reply || out.TransactionID != 0x010203 {
		t.Fatalf("unwrapped %s %#x", out.Type, out.TransactionID)
	}
	// An answer that was not relayed is its own message: a server answering an
	// unrelayed request answers the client directly.
	if got, err := Unwrap(answer); err != nil || got != answer {
		t.Errorf("unwrapping an unrelayed reply: %v %v", got, err)
	}
}

// The hop count is the chain's depth and it is the relay's to set, not the
// sender's: wrapping a relay message adds one, wrapping a client's starts at
// zero, and a chain already at the standard's bound is refused rather than
// extended.
func TestWrappingCountsTheHops(t *testing.T) {
	inner, err := Parse(msg(Solicit, 1))
	if err != nil {
		t.Fatal(err)
	}
	first, err := Wrap(inner, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1"))
	if err != nil {
		t.Fatal(err)
	}
	if first.HopCount != 0 {
		t.Fatalf("a client's message wrapped to hop count %d", first.HopCount)
	}
	second, err := Wrap(first, netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("fe80::2"))
	if err != nil {
		t.Fatal(err)
	}
	if second.HopCount != 1 {
		t.Fatalf("a relay message wrapped to hop count %d", second.HopCount)
	}
	// At the bound, a further relay is refused: the standard's own limit is
	// what stops a loop between two relays becoming a packet that never dies.
	atBound := &Message{Type: RelayForward, HopCount: MaxHopCount, Inner: inner}
	if _, err := Wrap(atBound, netip.MustParseAddr("2001:db8::3"), netip.MustParseAddr("fe80::3")); err == nil {
		t.Fatal("a chain already at the hop bound was extended")
	}
	if _, err := Wrap(nil, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fe80::1")); err == nil {
		t.Fatal("nothing was wrapped")
	}
	if _, err := Unwrap(nil); err == nil {
		t.Fatal("nothing was unwrapped")
	}
	if _, err := Unwrap(&Message{Type: RelayReply}); !errors.Is(err, ErrRelay) {
		t.Error("a relay reply with nothing inside unwrapped")
	}
}

// Editing the inside of a chain is what a relay does on the way back, and the
// Relay-Message option has to follow: an encoder that wrote the old octets would
// be sending the message the relay decided to change.
func TestEncodingFollowsTheEditedInside(t *testing.T) {
	inner, err := Parse(msg(Reply, 5,
		opt(OptionServerID, duidLL(2, 0, 0, 0, 0, 1)...),
		opt(OptionDNSServers, netip.MustParseAddr("2001:db8::53").AsSlice()...),
	))
	if err != nil {
		t.Fatal(err)
	}
	outer := &Message{Type: RelayReply, LinkAddress: netip.MustParseAddr("2001:db8::1"),
		PeerAddress: netip.MustParseAddr("fe80::1"), Inner: inner,
		Options: []Option{{Code: OptionRelayMsg, Value: []byte("stale")}}}
	// The resolver the relay decided to strip.
	if !inner.Remove(OptionDNSServers) {
		t.Fatal("the option was not there to remove")
	}
	raw, err := Encode(outer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Innermost().Has(OptionDNSServers) {
		t.Fatal("the stripped option came back: the encoder wrote the stale octets")
	}
	if !got.Innermost().Has(OptionServerID) {
		t.Error("the rest of the message did not survive")
	}
}

func TestEncodingRefusesWhatCannotBeSent(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   *Message
	}{
		{"nothing", nil},
		{"a transaction identifier that does not fit", &Message{Type: Solicit, TransactionID: 1 << 24}},
		{"a relay message with nothing inside", &Message{Type: RelayForward}},
		{"a hop count past the standard's", &Message{Type: RelayForward,
			HopCount: MaxHopCount + 1, Inner: &Message{Type: Solicit}}},
		{"an option past what a length field holds", &Message{Type: Solicit,
			Options: []Option{{Code: 1, Value: make([]byte, 0x10000)}}}},
		{"a message past the bound", &Message{Type: Solicit, Options: func() []Option {
			out := make([]Option, 0, 4)
			for i := 0; i < 4; i++ {
				out = append(out, Option{Code: 1, Value: make([]byte, 4000)})
			}
			return out
		}()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Encode(tc.in); err == nil {
				t.Fatal("encoded")
			}
		})
	}
}

// Set replaces and does not duplicate, because a message this relay edited must
// not come out with two of an option that may not repeat.
func TestSetAndRemove(t *testing.T) {
	m := &Message{Type: Reply, Options: []Option{
		{Code: OptionServerID, Value: []byte("a")},
		{Code: OptionDNSServers, Value: []byte("x")},
		{Code: OptionServerID, Value: []byte("b")},
	}}
	m.Set(OptionServerID, []byte("c"))
	if got := m.All(OptionServerID); len(got) != 1 || string(got[0]) != "c" {
		t.Fatalf("server identifiers %q", got)
	}
	if !m.Has(OptionDNSServers) {
		t.Error("the other options were disturbed")
	}
	m.Set(OptionPreference, []byte{7})
	if v, ok := m.Get(OptionPreference); !ok || v[0] != 7 {
		t.Error("an option that was not there was not added")
	}
	if !m.Remove(OptionDNSServers) || m.Has(OptionDNSServers) {
		t.Error("the option was not removed")
	}
	if m.Remove(OptionDNSServers) {
		t.Error("removing what is not there reported success")
	}
}

// A clone is deep, including the chain: editing a message for forwarding must
// not edit the one a decision was made about or the one a log line describes.
func TestACloneIsDeep(t *testing.T) {
	raw := relay(0, "2001:db8::1", "fe80::1",
		msg(Solicit, 1, opt(OptionClientID, duidLL(2, 0, 0, 0, 0, 1)...)))
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := m.Clone()
	c.Innermost().Set(OptionClientID, []byte("edited"))
	c.Innermost().Options[0].Value[0] = 'X'
	c.Options[0].Value = []byte("edited")
	c.Raw[0] = 0xff

	if v, _ := m.Innermost().Get(OptionClientID); !bytes.Equal(v, duidLL(2, 0, 0, 0, 0, 1)) {
		t.Error("editing the clone changed the original's inner option")
	}
	if m.Raw[0] != byte(RelayForward) {
		t.Error("editing the clone changed the original's octets")
	}
	if (*Message)(nil).Clone() != nil {
		t.Error("cloning nothing produced something")
	}
}

// A link address that is not an IPv6 address is written as the unspecified
// address rather than as whatever its octets are: the field is sixteen octets,
// and a v4 address there would be fifteen octets of somebody else's.
func TestAnAddressFieldIsAlwaysSixteenOctets(t *testing.T) {
	m := &Message{Type: RelayForward, LinkAddress: netip.MustParseAddr("192.0.2.1"),
		Inner: &Message{Type: Solicit}}
	raw, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LinkAddress.IsUnspecified() {
		t.Fatalf("link address %s", got.LinkAddress)
	}
}

func TestIdentityAssociationsAreRead(t *testing.T) {
	iaaddr := func(a string, pref, valid uint32) []byte {
		v := netip.MustParseAddr(a).AsSlice()
		v = binary.BigEndian.AppendUint32(v, pref)
		v = binary.BigEndian.AppendUint32(v, valid)
		return opt(OptionIAAddr, v...)
	}
	iaprefix := func(p string, pref, valid uint32) []byte {
		pfx := netip.MustParsePrefix(p)
		v := binary.BigEndian.AppendUint32(nil, pref)
		v = binary.BigEndian.AppendUint32(v, valid)
		v = append(v, byte(pfx.Bits()))
		v = append(v, pfx.Addr().AsSlice()...)
		return opt(OptionIAPrefix, v...)
	}
	na := binary.BigEndian.AppendUint32(nil, 0x11223344) // IAID
	na = binary.BigEndian.AppendUint32(na, 1800)         // T1
	na = binary.BigEndian.AppendUint32(na, 2880)         // T2
	na = append(na, iaaddr("2001:db8::10", 3600, 7200)...)

	pd := binary.BigEndian.AppendUint32(nil, 0x55667788)
	pd = binary.BigEndian.AppendUint32(pd, 1800)
	pd = binary.BigEndian.AppendUint32(pd, 2880)
	pd = append(pd, iaprefix("2001:db8:100::/56", 3600, 7200)...)

	ta := binary.BigEndian.AppendUint32(nil, 0x99aabbcc)
	ta = append(ta, iaaddr("2001:db8::20", 600, 1200)...)

	failed := binary.BigEndian.AppendUint32(nil, 1)
	failed = binary.BigEndian.AppendUint32(failed, 0)
	failed = binary.BigEndian.AppendUint32(failed, 0)
	failed = append(failed, opt(OptionStatusCode, 0, byte(StatusNoPrefixAvail), 'n', 'o')...)

	m, err := Parse(msg(Reply, 1,
		opt(OptionIANA, na...), opt(OptionIAPD, pd...),
		opt(OptionIATA, ta...), opt(OptionIAPD, failed...)))
	if err != nil {
		t.Fatal(err)
	}
	ias, err := m.IAs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ias) != 4 {
		t.Fatalf("%d identity associations", len(ias))
	}
	if ias[0].Code != OptionIANA || ias[0].IAID != 0x11223344 || ias[0].T1 != 1800 || ias[0].T2 != 2880 {
		t.Errorf("address association %+v", ias[0])
	}
	if len(ias[0].Addresses) != 1 || ias[0].Addresses[0].Addr != netip.MustParseAddr("2001:db8::10") {
		t.Errorf("addresses %+v", ias[0].Addresses)
	}
	if ias[0].Addresses[0].Preferred != 3600 || ias[0].Addresses[0].Valid != 7200 {
		t.Errorf("lifetimes %+v", ias[0].Addresses[0])
	}
	if ias[1].Code != OptionIAPD || len(ias[1].Prefixes) != 1 {
		t.Fatalf("prefix delegation %+v", ias[1])
	}
	if got := ias[1].Prefixes[0].Prefix; got != netip.MustParsePrefix("2001:db8:100::/56") {
		t.Errorf("delegated prefix %s", got)
	}
	// A temporary association has no renew and rebind times, so they are zero
	// rather than read out of the first address.
	if ias[2].Code != OptionIATA || ias[2].T1 != 0 || ias[2].T2 != 0 {
		t.Errorf("temporary association %+v", ias[2])
	}
	if len(ias[2].Addresses) != 1 {
		t.Errorf("temporary addresses %+v", ias[2].Addresses)
	}
	if ias[3].Status == nil || ias[3].Status.Code != StatusNoPrefixAvail || ias[3].Status.Message != "no" {
		t.Errorf("status %+v", ias[3].Status)
	}
	if got := StatusName(StatusNoPrefixAvail); got != "no_prefix_available" {
		t.Errorf("status name %q", got)
	}
}

func TestAMalformedIdentityAssociationIsRefused(t *testing.T) {
	short := binary.BigEndian.AppendUint32(nil, 1)
	badInner := binary.BigEndian.AppendUint32(nil, 1)
	badInner = binary.BigEndian.AppendUint32(badInner, 0)
	badInner = binary.BigEndian.AppendUint32(badInner, 0)
	badInner = append(badInner, 0x00, byte(OptionIAAddr), 0x00, 0x40) // a length nothing follows

	shortAddr := binary.BigEndian.AppendUint32(nil, 1)
	shortAddr = binary.BigEndian.AppendUint32(shortAddr, 0)
	shortAddr = binary.BigEndian.AppendUint32(shortAddr, 0)
	shortAddr = append(shortAddr, opt(OptionIAAddr, make([]byte, 20)...)...)

	longPrefix := binary.BigEndian.AppendUint32(nil, 1)
	longPrefix = binary.BigEndian.AppendUint32(longPrefix, 0)
	longPrefix = binary.BigEndian.AppendUint32(longPrefix, 0)
	pv := make([]byte, 25)
	pv[8] = 200 // a prefix length of 200 bits
	longPrefix = append(longPrefix, opt(OptionIAPrefix, pv...)...)

	for _, tc := range []struct {
		name string
		opts []byte
	}{
		{"an association with no times", opt(OptionIANA, short...)},
		{"an association with nothing in it at all", opt(OptionIANA)},
		{"a temporary association with no identifier", opt(OptionIATA, 1, 2)},
		{"an inner option longer than what is there", opt(OptionIANA, badInner...)},
		{"an address option cut short", opt(OptionIANA, shortAddr...)},
		{"a prefix longer than an address", opt(OptionIAPD, longPrefix...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse(msg(Reply, 1, tc.opts))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.IAs(); !errors.Is(err, ErrOption) {
				t.Fatalf("got %v, want %v", err, ErrOption)
			}
		})
	}
}

func TestTheTypedOptionReaders(t *testing.T) {
	two := append(netip.MustParseAddr("2001:db8::53").AsSlice(),
		netip.MustParseAddr("2001:db8::54").AsSlice()...)
	got, err := Addresses(two)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1] != netip.MustParseAddr("2001:db8::54") {
		t.Fatalf("addresses %v", got)
	}
	if _, err := Addresses(two[:17]); !errors.Is(err, ErrOption) {
		t.Error("a list that is not a whole number of addresses was read")
	}
	if n, err := Seconds([]byte{0, 0, 0x07, 0x08}); err != nil || n != 0x708 {
		t.Errorf("seconds %d %v", n, err)
	}
	if _, err := Seconds([]byte{0, 0, 1}); !errors.Is(err, ErrOption) {
		t.Error("three octets read as four")
	}
	if _, err := ParseStatus([]byte{0}); !errors.Is(err, ErrOption) {
		t.Error("a status code of one octet was read")
	}
}

func TestDomainNamesAreReadAndRefused(t *testing.T) {
	// "plant.example." and "office.example."
	wire := []byte{5, 'p', 'l', 'a', 'n', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0,
		6, 'o', 'f', 'f', 'i', 'c', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}
	got, err := DomainNames(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "plant.example" || got[1] != "office.example" {
		t.Fatalf("names %q", got)
	}
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"a name that does not end", []byte{5, 'p', 'l', 'a', 'n', 't'}},
		{"a label longer than what is there", []byte{9, 'p', 'l', 'a', 'n', 't', 0}},
		// A compression pointer has nowhere to point in an option, so a reader
		// that followed one would be reading something the client did not send.
		{"a compressed name", []byte{0xc0, 0x0c}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DomainNames(tc.in); !errors.Is(err, ErrOption) {
				t.Fatalf("got %v, want %v", err, ErrOption)
			}
		})
	}
	if got, err := DomainNames(nil); err != nil || len(got) != 0 {
		t.Errorf("an empty list: %q %v", got, err)
	}
}

func TestTheOptionTableNamesWhatMatters(t *testing.T) {
	for _, code := range DangerousOptions {
		if OptionName(code) == "" {
			t.Errorf("option %d has no name", code)
		}
		got, ok := OptionOf(OptionName(code))
		if !ok || got != code {
			t.Errorf("option %d (%s) did not read back", code, OptionName(code))
		}
	}
	// The ones worth spelling out, because they are the reason the list is
	// longer than DHCPv4's.
	for _, code := range []uint16{OptionS46ContMAPE, OptionS46ContMAPT, OptionS46ContLW,
		OptionCaptivePortal, OptionBootFileURL, OptionUnicast, OptionSZTPRedirect} {
		found := false
		for _, d := range DangerousOptions {
			if d == code {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not in the dangerous list", OptionName(code))
		}
	}
	// The relay's own options, which a client has no business sending.
	for _, code := range RelayOptions {
		if !MayRepeat(code) && OptionName(code) == "" {
			t.Errorf("relay option %d has no name", code)
		}
	}
	if got := OptionName(60000); got != "option_60000" {
		t.Errorf("an unnamed option renders as %q", got)
	}
	if got, ok := OptionOf("60000"); !ok || got != 60000 {
		t.Errorf("a bare number did not read as an option: %d %v", got, ok)
	}
	if _, ok := OptionOf("not an option"); ok {
		t.Error("a name nobody uses read back")
	}
	if _, ok := OptionOf("70000"); ok {
		t.Error("a number past the field read back")
	}
	if MayRepeat(OptionClientID) || !MayRepeat(OptionIAPD) {
		t.Error("the repeat table is wrong about the identity associations")
	}
}
