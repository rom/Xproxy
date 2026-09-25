package bacnet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// The ordinary case, end to end: a read of a zone temperature.
func TestAReadOfAPropertyIsReadRight(t *testing.T) {
	want := ObjectID{Type: AnalogInput, Instance: 12}
	v, n, a, err := parse(readRequest(want, PropPresentValue))
	if err != nil {
		t.Fatal(err)
	}
	if v.Function != FuncOriginalUnicast {
		t.Fatalf("function %s", v.Function)
	}
	if n.ExpectingReply != true || n.Priority != 0 {
		t.Fatalf("npdu %+v", n)
	}
	if a.Type != PDUConfirmedRequest || a.Service.Name() != "readProperty" {
		t.Fatalf("apdu %+v", a)
	}
	if a.MaxAPDU != 1476 || a.InvokeID != 1 {
		t.Fatalf("max apdu %d invoke %d", a.MaxAPDU, a.InvokeID)
	}
	got, ok := Targets(a)
	if !ok || len(got) != 1 {
		t.Fatalf("targets %v %v", got, ok)
	}
	if got[0].Object != want || !got[0].HasProperty || got[0].Property != PropPresentValue {
		t.Fatalf("target %+v, want %s present-value", got[0], want)
	}
}

// A datagram whose declared length is not the datagram's length is
// refused both ways round. The short case is the one that matters: the
// octets past the declared end are octets this relay would not inspect
// and a device might read.
func TestALengthThatIsNotTheDatagramsIsRefused(t *testing.T) {
	good := readRequest(ObjectID{Type: AnalogInput, Instance: 1}, PropPresentValue)
	t.Run("declares less", func(t *testing.T) {
		b := append([]byte(nil), good...)
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-2))
		_, err := ParseBVLC(b)
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("err %v, want malformed", err)
		}
		if !strings.Contains(err.Error(), "unread") {
			t.Fatalf("err %q does not say what is wrong", err)
		}
	})
	t.Run("declares more", func(t *testing.T) {
		b := append([]byte(nil), good...)
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)+4))
		if _, err := ParseBVLC(b); !errors.Is(err, ErrTruncated) {
			t.Fatalf("err %v, want truncated", err)
		}
	})
	t.Run("declares less than the header", func(t *testing.T) {
		b := append([]byte(nil), good...)
		binary.BigEndian.PutUint16(b[2:4], 3)
		if _, err := ParseBVLC(b); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err %v, want malformed", err)
		}
	})
}

// Something else entirely on port 47808 is not a broken BACnet message,
// and the two are different events: one is a stray datagram and the other
// is a peer worth a log line.
func TestADatagramThatIsNotBACnetSaysSo(t *testing.T) {
	if _, err := ParseBVLC([]byte{0x16, 0x03, 0x01, 0x00}); !errors.Is(err, ErrNotBACnet) {
		t.Fatalf("a TLS record was read as BACnet")
	}
	if _, err := ParseBVLC(nil); !errors.Is(err, ErrTruncated) {
		t.Fatal("an empty datagram")
	}
	if _, err := ParseBVLC([]byte{0x81, 0x0A, 0x00}); !errors.Is(err, ErrTruncated) {
		t.Fatal("a datagram shorter than the header")
	}
	if _, err := ParseBVLC(append([]byte{0x81, 0x0A, 0x06, 0x00}, make([]byte, MaxMessage)...)); !errors.Is(err, ErrMalformed) {
		t.Fatal("a datagram past the Annex J maximum")
	}
}

// An undefined function code is refused rather than forwarded. A relay
// that passed one on would be forwarding a link layer operation it has no
// name for, to a device that might.
func TestAnUndefinedFunctionIsRefused(t *testing.T) {
	_, err := ParseBVLC([]byte{0x81, 0x7F, 0x00, 0x04})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err %v, want unsupported", err)
	}
	if Function(0x7F).Known() {
		t.Fatal("0x7f is not a function of Annex J")
	}
	if !strings.Contains(Function(0x7F).String(), "0x7f") {
		t.Fatalf("an unnamed function renders as %q", Function(0x7F))
	}
}

// The originating address in a Forwarded-NPDU is inside the payload,
// where whoever sent the datagram chose it. The parser reports it and
// says it is there; it does not vouch for it.
func TestAForwardedNPDUCarriesTheAddressItsSenderChose(t *testing.T) {
	origin := []byte{192, 0, 2, 7, 0xBA, 0xC0}
	b := bvlc(FuncForwardedNPDU, origin, npdu(0x00), unconfirmed(WhoIs))
	v, _, a, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !v.HasOrigin {
		t.Fatal("no originating address")
	}
	if want := netip.MustParseAddrPort("192.0.2.7:47808"); v.Origin != want {
		t.Fatalf("origin %v, want %v", v.Origin, want)
	}
	if a.Service.Name() != "who-Is" {
		t.Fatalf("service %s", a.Service)
	}
	// And without room for it the message is truncated rather than read
	// as one whose payload starts six octets early.
	if _, err := ParseBVLC(bvlc(FuncForwardedNPDU, []byte{1, 2, 3})); !errors.Is(err, ErrTruncated) {
		t.Fatal("a forwarded-npdu with a short originating address")
	}
}

// The BBMD functions are named as a group because two of them are an
// attack on their own: registering as a foreign device subscribes an
// address to every broadcast on a network, and reading the distribution
// table hands over the estate's BACnet routing.
func TestTheBBMDFunctionsAreNamedAsAGroup(t *testing.T) {
	for _, f := range []Function{FuncWriteBDT, FuncReadBDT, FuncReadBDTAck,
		FuncRegisterForeignDevice, FuncReadFDT, FuncReadFDTAck, FuncDeleteFDTEntry} {
		if !f.BBMD() {
			t.Errorf("%s is not counted as broadcast management", f)
		}
		if f.CarriesNPDU() {
			t.Errorf("%s was read as carrying a network message", f)
		}
	}
	for _, f := range []Function{FuncOriginalUnicast, FuncOriginalBroadcast, FuncForwardedNPDU, FuncDistributeBroadcast} {
		if f.BBMD() {
			t.Errorf("%s was counted as broadcast management", f)
		}
		if !f.CarriesNPDU() {
			t.Errorf("%s does not carry a network message", f)
		}
	}
	for _, f := range []Function{FuncOriginalBroadcast, FuncDistributeBroadcast, FuncForwardedNPDU} {
		if !f.Broadcast() {
			t.Errorf("%s is not counted as a broadcast", f)
		}
	}
	if FuncOriginalUnicast.Broadcast() {
		t.Error("a unicast was counted as a broadcast")
	}
}

// The reserved bits of the network header are checked. A sender that sets
// one is arranging for two readers to disagree, and a relay whose reading
// differs from the device's is a relay that can be talked past.
func TestTheNetworkHeadersReservedBitsAreRefused(t *testing.T) {
	for _, c := range []byte{0x40, 0x10, 0x50} {
		_, err := ParseNPDU(npdu(c, unconfirmed(WhoIs)))
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("control 0x%02x: err %v, want malformed", c, err)
		}
	}
	if _, err := ParseNPDU([]byte{2, 0x00, 0x10, 0x08}); !errors.Is(err, ErrMalformed) {
		t.Error("version 2 was read as version 1")
	}
	if _, err := ParseNPDU([]byte{1}); !errors.Is(err, ErrTruncated) {
		t.Error("a one octet network header")
	}
}

// The addressing fields, and the hop count that only comes with a
// destination. Getting the order wrong is the classic BACnet parser bug:
// the hop count follows the source address, not the destination's.
func TestTheAddressingFieldsAreReadInTheStandardsOrder(t *testing.T) {
	dest := []byte{0x00, 0x05, 0x01, 0x22}      // DNET 5, DLEN 1, DADR 0x22
	src := []byte{0x00, 0x09, 0x02, 0x01, 0x02} // SNET 9, SLEN 2, SADR 0102
	n, err := ParseNPDU(npdu(0x20|0x08, dest, src, []byte{0xFE}, unconfirmed(IAm)))
	if err != nil {
		t.Fatal(err)
	}
	if !n.HasDest || n.DNET != 5 || len(n.DADR) != 1 || n.DADR[0] != 0x22 {
		t.Fatalf("destination %+v", n)
	}
	if !n.HasSource || n.SNET != 9 || len(n.SADR) != 2 {
		t.Fatalf("source %+v", n)
	}
	if n.Hop != 0xFE {
		t.Fatalf("hop %d, want 254", n.Hop)
	}
	if n.BroadcastDest() {
		t.Fatal("a one octet destination address was read as a broadcast")
	}
	// DLEN zero is a broadcast on the destination network, which is the
	// one thing a length of zero means in this header.
	n2, err := ParseNPDU(npdu(0x20, []byte{0x00, 0x05, 0x00, 0xFE}, unconfirmed(WhoIs)))
	if err != nil {
		t.Fatal(err)
	}
	if !n2.BroadcastDest() {
		t.Fatal("DLEN 0 is a broadcast on the destination network")
	}
	// SLEN zero is not a source. It is a field written to be skipped.
	if _, err := ParseNPDU(npdu(0x08, []byte{0x00, 0x09, 0x00}, unconfirmed(WhoIs))); !errors.Is(err, ErrMalformed) {
		t.Fatal("a source network with no address")
	}
	// And a length that runs off the end is truncated rather than read
	// as the octets that happen to follow.
	if _, err := ParseNPDU(npdu(0x20, []byte{0x00, 0x05, 0x40, 0x01})); !errors.Is(err, ErrTruncated) {
		t.Fatal("a destination address longer than the message")
	}
}

// A network layer message is not an application message, and its
// proprietary range carries a vendor identifier the standard range does
// not.
func TestANetworkLayerMessageIsReadAsOne(t *testing.T) {
	n, err := ParseNPDU(npdu(0x80, []byte{byte(NetInitializeRoutingTable)}))
	if err != nil {
		t.Fatal(err)
	}
	if !n.NetworkMessage || n.MessageType != NetInitializeRoutingTable {
		t.Fatalf("npdu %+v", n)
	}
	if len(n.APDU) != 0 {
		t.Fatal("a network message carried an application PDU")
	}
	if !n.MessageType.Routing() {
		t.Fatal("initialize-routing-table does not change routing?")
	}
	v, err := ParseNPDU(npdu(0x80, []byte{0x90, 0x01, 0x2C}))
	if err != nil {
		t.Fatal(err)
	}
	if !v.HasVendor || v.VendorID != 300 {
		t.Fatalf("vendor %d, present %v", v.VendorID, v.HasVendor)
	}
	if !v.MessageType.Proprietary() || v.MessageType.Known() {
		t.Fatalf("0x90 read as %s", v.MessageType)
	}
	if _, err := ParseNPDU(npdu(0x80, []byte{0x90, 0x01})); !errors.Is(err, ErrTruncated) {
		t.Fatal("a proprietary message with half a vendor identifier")
	}
	if _, err := ParseNPDU(npdu(0x80)); !errors.Is(err, ErrTruncated) {
		t.Fatal("a network message with no type")
	}
	// The security messages are named as a group: a relay cannot read
	// inside a Security-Payload, which is the point of it.
	for _, m := range []NetworkMessageType{NetChallengeRequest, NetSecurityPayload, NetSecurityResponse,
		NetRequestKeyUpdate, NetUpdateKeySet, NetUpdateDistributionKey, NetRequestMasterKey, NetSetMasterKey} {
		if !m.Security() {
			t.Errorf("%s is not counted as a security message", m)
		}
	}
	if NetWhoIsRouterToNetwork.Security() {
		t.Error("who-is-router-to-network was counted as a security message")
	}
}

// An NPDU that says it carries an application message and then carries
// nothing is truncated. Reading it as a request with no service choice
// would be a request a policy has nothing to decide about.
func TestANetworkHeaderWithNoApplicationMessageIsTruncated(t *testing.T) {
	if _, err := ParseNPDU(npdu(0x00)); !errors.Is(err, ErrTruncated) {
		t.Fatal("a network header with nothing after it")
	}
}

// Every field of a confirmed request, including the two that say how much
// the client will take back -- which is what a relay needs to bound a
// reply it forwards.
func TestAConfirmedRequestsFieldsAreRead(t *testing.T) {
	a, err := ParseAPDU([]byte{0x02, 0x34, 0x2A, ReadProperty})
	if err != nil {
		t.Fatal(err)
	}
	if !a.SegmentedAccepted || a.Segmented {
		t.Fatalf("segmentation %+v", a)
	}
	if a.MaxSegments != 8 || a.MaxAPDU != 1024 {
		t.Fatalf("max segments %d max apdu %d, want 8 and 1024", a.MaxSegments, a.MaxAPDU)
	}
	if a.InvokeID != 0x2A {
		t.Fatalf("invoke %d", a.InvokeID)
	}
	// Segmented: the sequence number and the window follow the invoke
	// identifier and come before the service choice.
	s, err := ParseAPDU([]byte{0x0C, 0x05, 0x01, 0x03, 0x10, WriteProperty})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Segmented || !s.MoreFollows || s.Sequence != 3 || s.Window != 0x10 {
		t.Fatalf("segmented request %+v", s)
	}
	if s.Service.Name() != "writeProperty" {
		t.Fatalf("service %s", s.Service)
	}
}

// The malformed application headers, each of which is a way to make a
// parser read a different message from the one a device reads.
func TestTheApplicationHeadersContradictionsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want error
	}{
		{"a reserved bit in a confirmed request", []byte{0x01, 0x05, 0x01, ReadProperty}, ErrMalformed},
		{"more-follows without segmentation", []byte{0x04, 0x05, 0x01, ReadProperty}, ErrMalformed},
		{"a reserved bit in the size octet", []byte{0x00, 0x85, 0x01, ReadProperty}, ErrMalformed},
		{"a reserved maximum APDU length", []byte{0x00, 0x0F, 0x01, ReadProperty}, ErrMalformed},
		{"a proposed window of zero", []byte{0x08, 0x05, 0x01, 0x00, 0x00, ReadProperty}, ErrMalformed},
		{"a reserved bit in an unconfirmed request", []byte{0x11, WhoIs}, ErrMalformed},
		{"a reserved bit in a simple ack", []byte{0x22, 0x01, WriteProperty}, ErrMalformed},
		{"a reserved bit in a complex ack", []byte{0x31, 0x01, ReadProperty}, ErrMalformed},
		{"a reserved bit in an error", []byte{0x52, 0x01, ReadProperty}, ErrMalformed},
		{"a reserved bit in a reject", []byte{0x61, 0x01, 0x09}, ErrMalformed},
		{"a reserved bit in an abort", []byte{0x72, 0x01, 0x04}, ErrMalformed},
		{"an empty application message", nil, ErrTruncated},
		{"a confirmed request that stops at the size octet", []byte{0x00, 0x05}, ErrTruncated},
		{"an unconfirmed request with no service choice", []byte{0x10}, ErrTruncated},
		{"a segment ack that stops early", []byte{0x40, 0x01, 0x00}, ErrTruncated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseAPDU(c.b); !errors.Is(err, c.want) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
		})
	}
}

// The reply shapes, because a relay decides about a reply too: a complex
// ack carries the service it is answering, and an abort or a reject
// carries a reason instead.
func TestTheReplyShapesAreRead(t *testing.T) {
	ack, err := ParseAPDU([]byte{0x30, 0x2A, ReadProperty, 0x0C, 0, 0, 0, 12})
	if err != nil {
		t.Fatal(err)
	}
	if ack.Type != PDUComplexACK || ack.Service.Name() != "readProperty" || ack.InvokeID != 0x2A {
		t.Fatalf("complex ack %+v", ack)
	}
	if len(ack.Params) != 5 {
		t.Fatalf("params %v", ack.Params)
	}
	simple, err := ParseAPDU([]byte{0x20, 0x01, WriteProperty})
	if err != nil {
		t.Fatal(err)
	}
	if simple.Type != PDUSimpleACK || !simple.Service.Confirmed {
		t.Fatalf("simple ack %+v", simple)
	}
	ab, err := ParseAPDU([]byte{0x71, 0x01, 0x04})
	if err != nil {
		t.Fatal(err)
	}
	if ab.Type != PDUAbort || !ab.Server || !ab.HasReason || ab.Reason != 4 {
		t.Fatalf("abort %+v", ab)
	}
	if ab.HasService {
		t.Fatal("an abort carries no service choice")
	}
	seg, err := ParseAPDU([]byte{0x41, 0x01, 0x02, 0x10})
	if err != nil {
		t.Fatal(err)
	}
	if seg.Type != PDUSegmentACK || !seg.Server || seg.Sequence != 2 || seg.Window != 0x10 {
		t.Fatalf("segment ack %+v", seg)
	}
	if PDUConfirmedRequest.Request() != true || PDUComplexACK.Request() {
		t.Fatal("Request does not separate a request from a reply")
	}
	if PDUType(9).String() != "pdu-type-9" {
		t.Fatalf("an out of range pdu type renders as %q", PDUType(9))
	}
}

// Clip cuts on a rune boundary. A name out of a device is attacker
// controlled in an estate somebody else can reach, and a log line cut
// through a character is a log line a reader cannot trust.
func TestClipCutsOnARuneBoundary(t *testing.T) {
	if got := Clip("short", 32); got != "short" {
		t.Fatalf("%q", got)
	}
	// Three-octet runes across the cut.
	s := strings.Repeat("å", 10)
	got := Clip(s, 7)
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("%q was not marked as clipped", got)
	}
	body := strings.TrimSuffix(got, "...")
	if len(body) > 7 {
		t.Fatalf("%q is longer than the bound", body)
	}
	for _, r := range body {
		if r == '�' {
			t.Fatalf("%q was cut inside a character", body)
		}
	}
}
