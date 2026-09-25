package dhcp

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// TestAMessageRoundTripsThroughTheEncoder is the pair that has to agree: the
// reader and the writer are the two halves of every rewrite this relay makes,
// and an option that survived the policy has to survive the encoding too.
func TestAMessageRoundTripsThroughTheEncoder(t *testing.T) {
	raw := build{
		op:     BootReply,
		xid:    0x01020304,
		flags:  0x8000,
		giaddr: "10.0.0.1",
		chaddr: []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
		file:   "pxelinux.0",
		sname:  "boot.example.com",
		opts: cat(opt(OptMessageType, uint8(Ack)),
			opt(OptSubnetMask, 255, 255, 255, 0),
			opt(OptRouter, 10, 0, 0, 1),
			opt(OptDNS, 10, 0, 0, 2, 10, 0, 0, 3),
			opt(OptLeaseTime, 0, 0, 14, 16)),
	}.bytes()
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil {
		t.Fatalf("what the encoder wrote does not parse: %v", err)
	}
	if back.Op != m.Op || back.Type != m.Type || back.XID != m.XID || back.Flags != m.Flags {
		t.Fatalf("header changed: %+v", back)
	}
	if !bytes.Equal(back.CHAddr, m.CHAddr) || back.GIAddr != m.GIAddr {
		t.Errorf("hardware address or giaddr changed")
	}
	if back.File != m.File || back.SName != m.SName {
		t.Errorf("file %q sname %q", back.File, back.SName)
	}
	for _, code := range m.Codes() {
		want, _ := m.Get(code)
		got, ok := back.Get(code)
		if !ok || !bytes.Equal(got, want) {
			t.Errorf("option %s: %v, want %v", OptionName(code), got, want)
		}
	}
	// The message type is written first whatever order it was read in.
	if back.Codes()[0] != OptMessageType {
		t.Errorf("the first option written is %s", OptionName(back.Codes()[0]))
	}
	// And the message is padded to the BOOTP minimum, because there are
	// relay agents and clients in the world that drop anything shorter.
	if len(out) < 300 {
		t.Errorf("%d octets, shorter than the 300 RFC 2131 pads to", len(out))
	}
}

// TestAnOptionRemovedIsAnOptionGone is what an option policy means: the message
// that leaves does not carry it, rather than carrying it with a note.
func TestAnOptionRemovedIsAnOptionGone(t *testing.T) {
	m, err := Parse(build{op: BootReply,
		opts: cat(opt(OptMessageType, uint8(Ack)),
			opt(OptRouter, 10, 0, 0, 1),
			opt(OptWPAD, 'h', 't', 't', 'p'),
			opt(OptClasslessRoute, 0, 10, 0, 0, 9))}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	c := m.Clone()
	if !c.Remove(OptWPAD) || !c.Remove(OptClasslessRoute) {
		t.Fatal("an option that was there did not report being removed")
	}
	if c.Remove(OptWPAD) {
		t.Error("an option that was already gone reported being removed")
	}
	out, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.Has(OptWPAD) || back.Has(OptClasslessRoute) {
		t.Fatal("a removed option was written anyway")
	}
	if !back.Has(OptRouter) {
		t.Error("removing two options removed a third")
	}
	// The clone is what was edited: the original still carries everything, so
	// the log line can say what was refused.
	if !m.Has(OptWPAD) {
		t.Error("editing the clone changed the original")
	}
}

// TestASetOptionKeepsItsPlace, because an operator comparing a capture with a
// log should see the same sequence in both.
func TestASetOptionKeepsItsPlace(t *testing.T) {
	m, err := Parse(build{op: BootReply,
		opts: cat(opt(OptMessageType, uint8(Ack)),
			opt(OptRouter, 10, 0, 0, 1),
			opt(OptDNS, 10, 0, 0, 2))}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	m.Set(OptRouter, []byte{10, 0, 0, 254})
	m.Set(OptRelayAgent, []byte{1, 1, 'x'})
	if got := m.Codes(); got[1] != OptRouter || got[len(got)-1] != OptRelayAgent {
		t.Fatalf("codes %v: a replaced option moved, or a new one did not go last", got)
	}
	v, _ := m.Get(OptRouter)
	if !bytes.Equal(v, []byte{10, 0, 0, 254}) {
		t.Errorf("router %v", v)
	}
}

// TestALongOptionIsWrittenTheWayItIsRead is RFC 3396 in both directions: a
// relay that could read the encoding and not write it would be a relay that
// could not carry what it had just decided to allow.
func TestALongOptionIsWrittenTheWayItIsRead(t *testing.T) {
	long := bytes.Repeat([]byte{'a'}, 600)
	m := &Message{Op: BootReply, HType: HTypeEthernet, Type: Ack,
		CHAddr: []byte{1, 2, 3, 4, 5, 6}}
	m.Set(OptBootFile, long)
	out, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := back.Get(OptBootFile)
	if !ok || !bytes.Equal(v, long) {
		t.Fatalf("a 600-octet option came back as %d octets", len(v))
	}
	for _, o := range back.Options {
		if o.Code == OptBootFile && !o.Split {
			t.Error("the option came back in one instance, which cannot hold 600 octets")
		}
	}
}

// TestTheOverloadEncodingIsReadAndNotWritten: a relay whose own output hid
// options in the boot filename field would be making its output harder to read
// than its input, for no gain.
func TestTheOverloadEncodingIsReadAndNotWritten(t *testing.T) {
	hidden := cat(opt(OptWPAD, 'x'), []byte{OptEnd})
	m, err := Parse(build{op: BootReply,
		opts: cat(opt(OptMessageType, uint8(Ack)), opt(OptOverload, 1)),
		file: string(hidden)}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	out, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.Overload != 0 {
		t.Errorf("overload %d was written", back.Overload)
	}
	// The option that was hidden is still carried -- in the options field,
	// where a reader finds it.
	v, ok := back.Get(OptWPAD)
	if !ok || string(v) != "x" {
		t.Fatalf("the hidden option was lost: %q present=%v", v, ok)
	}
	for _, o := range back.Options {
		if o.Where != InOptions {
			t.Errorf("option %s came back from %v", OptionName(o.Code), o.Where)
		}
	}
}

func TestWhatTheEncoderRefusesToWrite(t *testing.T) {
	base := func() *Message {
		return &Message{Op: BootReply, HType: HTypeEthernet, Type: Ack,
			CHAddr: []byte{1, 2, 3, 4, 5, 6}}
	}
	m := base()
	m.Op = Op(9)
	if _, err := Encode(m); err == nil {
		t.Error("an op nobody defined was written")
	}
	m = base()
	m.CHAddr = make([]byte, MaxHWLen+1)
	if _, err := Encode(m); err == nil {
		t.Error("a hardware address longer than its field was written")
	}
	m = base()
	m.File = strings.Repeat("x", MaxFileLen+1)
	if _, err := Encode(m); err == nil {
		t.Error("a filename longer than its field was written")
	}
	m = base()
	m.SName = strings.Repeat("x", MaxSNameLen+1)
	if _, err := Encode(m); err == nil {
		t.Error("an sname longer than its field was written")
	}
	// The framing codes are not options and cannot be set as ones.
	m = base()
	m.Options = []Option{{Code: OptPad, Value: []byte{1}}}
	if out, err := Encode(m); err != nil || Has(out, OptPad) {
		t.Error("the padding code was written as an option")
	}
	// A message whose options do not fit.
	m = base()
	m.Set(OptBootFile, bytes.Repeat([]byte{'a'}, MaxPacket))
	if _, err := Encode(m); err == nil {
		t.Error("a message past the packet bound was written")
	}
	if _, err := appendOption(nil, OptEnd, []byte{1}); err == nil {
		t.Error("the terminator was written as an option")
	}
}

// Has says whether an encoded message carries an option code at all, for the
// one case a test needs to look at the bytes rather than the parse.
func Has(raw []byte, code uint8) bool {
	m, err := Parse(raw)
	if err != nil {
		return false
	}
	return m.Has(code)
}

// TestAZeroLengthOptionSurvives: several options are present-or-absent flags,
// and an encoder that dropped them would be changing what the message says.
func TestAZeroLengthOptionSurvives(t *testing.T) {
	m := &Message{Op: BootRequest, HType: HTypeEthernet, Type: Discover,
		CHAddr: []byte{1, 2, 3, 4, 5, 6}}
	m.Set(OptRapidCommit, nil)
	out, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Has(OptRapidCommit) {
		t.Fatal("a zero-length option was dropped")
	}
	v, _ := back.Get(OptRapidCommit)
	if len(v) != 0 {
		t.Errorf("value %v", v)
	}
}

// TestTheAddressFieldsAreWrittenAsFourOctets, including the unspecified one a
// client with no address yet sends.
func TestTheAddressFieldsAreWrittenAsFourOctets(t *testing.T) {
	m := &Message{Op: BootRequest, HType: HTypeEthernet, Type: Discover,
		CHAddr: []byte{1, 2, 3, 4, 5, 6},
		CIAddr: netip.MustParseAddr("0.0.0.0"),
		GIAddr: netip.MustParseAddr("10.0.0.1"),
		// An address that is not IPv4 cannot go in a four-octet field; it is
		// written as the unspecified address rather than refused, because the
		// parser never produces one and this guards a caller's own mistake.
		YIAddr: netip.MustParseAddr("2001:db8::1"),
	}
	out, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !back.CIAddr.IsUnspecified() || back.GIAddr != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("ciaddr %v giaddr %v", back.CIAddr, back.GIAddr)
	}
	if !back.YIAddr.IsUnspecified() {
		t.Errorf("yiaddr %v, want the unspecified address", back.YIAddr)
	}
}
