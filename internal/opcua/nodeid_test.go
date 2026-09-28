package opcua

import (
	"bytes"
	"errors"
	"testing"
)

func TestEveryNodeIdEncodingReadsToTheSameKey(t *testing.T) {
	// The four numeric encodings are four ways to write one identifier, and a
	// server is free to pick any that fits. A rule written against one of them
	// would be a rule that stops working when the server's stack changes.
	for _, tc := range []struct {
		name string
		wire []byte
		key  string
	}{
		{"two byte", []byte{0x00, 0x20}, "ns=0;i=32"},
		{"four byte", []byte{0x01, 0x00, 0x20, 0x00}, "ns=0;i=32"},
		{"numeric", []byte{0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00}, "ns=0;i=32"},
	} {
		r := &reader{b: tc.wire}
		n := r.nodeID(false)
		if err := r.done(); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := n.Key(); got != tc.key {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.key)
		}
	}
}

func TestANodeIdsNamespaceAndIdentifierAreBothRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		key  string
		kind IDKind
	}{
		{"a four byte in namespace three", []byte{0x01, 0x03, 0xE9, 0x03}, "ns=3;i=1001", FourByte},
		{"a numeric in namespace 65535",
			[]byte{0x02, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00}, "ns=65535;i=1", Numeric},
		{"a string identifier",
			append([]byte{0x03, 0x04, 0x00, 0x0B, 0x00, 0x00, 0x00}, []byte("Motor/Speed")...),
			"ns=4;s=Motor/Speed", String},
	} {
		r := &reader{b: tc.wire}
		n := r.nodeID(false)
		if err := r.done(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := n.Key(); got != tc.key {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.key)
		}
		if n.Kind != tc.kind {
			t.Errorf("%s: kind %s, want %s", tc.name, n.Kind, tc.kind)
		}
	}
}

func TestAGuidIdentifierRendersInTheStandardsOwnMixedEndianness(t *testing.T) {
	// The first three fields are little-endian on the wire and big-endian in the
	// canonical text. Getting it wrong yields an identifier that matches no
	// allow-list anyone wrote from a server's documentation.
	g := []byte{
		0x91, 0x2B, 0x96, 0x72, // Data1, little-endian
		0x75, 0xFA, // Data2
		0xE6, 0x45, // Data3
		0x93, 0x2B, 0xF5, 0x65, 0xB0, 0x4B, 0x4D, 0x10, // Data4, in order
	}
	wire := append([]byte{0x04, 0x01, 0x00}, g...)
	r := &reader{b: wire}
	n := r.nodeID(false)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	want := "ns=1;g=72962B91-FA75-45E6-932B-F565B04B4D10"
	if got := n.Key(); got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

func TestAnOpaqueIdentifierRendersAsHex(t *testing.T) {
	wire := build().byte(byte(Opaque)).u16(2).bstr([]byte{0xDE, 0xAD, 0xBE, 0xEF}).b
	r := &reader{b: wire}
	n := r.nodeID(false)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	if got := n.Key(); got != "ns=2;b=deadbeef" {
		t.Errorf("%q", got)
	}
}

func TestAnExpandedNodeIdCarriesTheNamespaceURIAndTheServerIndex(t *testing.T) {
	// A namespace URI is the portable form: an index only means something against
	// the server's own namespace table, so an allow-list written with indices
	// silently changes meaning when a server's table does.
	wire := build().byte(byte(Numeric) | flagNamespaceURI | flagServerIndex).
		u16(3).u32(1001).str("urn:plant:ns:motors").u32(2).b
	r := &reader{b: wire}
	n := r.nodeID(true)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	if n.NamespaceURI != "urn:plant:ns:motors" {
		t.Errorf("uri %q", n.NamespaceURI)
	}
	if n.ServerIndex != 2 {
		t.Errorf("server index %d", n.ServerIndex)
	}
	if got := n.Key(); got != "svr=2;nsu=urn:plant:ns:motors;i=1001" {
		t.Errorf("key %q", got)
	}
}

func TestAPlainNodeIdWithTheExpandedFlagsIsRefused(t *testing.T) {
	// The two types are distinguished by position in the structure, not by
	// content, so a plain node id carrying the flags is a message whose following
	// fields are at positions nothing agrees on.
	for _, flag := range []byte{flagNamespaceURI, flagServerIndex} {
		wire := build().byte(byte(Numeric) | flag).u16(0).u32(1).str("x").u32(1).b
		r := &reader{b: wire}
		r.nodeID(false)
		if err := r.done(); !errors.Is(err, ErrEncoding) {
			t.Errorf("flag %#x: err %v, want ErrEncoding", flag, err)
		}
	}
}

func TestANodeIdEncodingNobodyDefinedIsRefused(t *testing.T) {
	for _, kind := range []byte{0x06, 0x07, 0x3F} {
		r := &reader{b: []byte{kind, 0, 0, 0, 0, 0, 0, 0}}
		r.nodeID(true)
		if err := r.done(); !errors.Is(err, ErrEncoding) {
			t.Errorf("encoding %#x: err %v, want ErrEncoding", kind, err)
		}
	}
}

func TestATruncatedNodeIdIsReportedRatherThanReadAsZero(t *testing.T) {
	for _, wire := range [][]byte{
		{},
		{0x00},                   // a two byte with no identifier
		{0x01, 0x00},             // a four byte with half an identifier
		{0x02, 0x00, 0x00, 0x00}, // a numeric with half an identifier
		{0x04, 0x00, 0x00, 0x01}, // a guid with one of sixteen octets
	} {
		r := &reader{b: wire}
		r.nodeID(false)
		if err := r.done(); !errors.Is(err, ErrShort) {
			t.Errorf("%x: err %v, want ErrShort", wire, err)
		}
	}
}

func TestTheNullNodeIdIsRecognisedHoweverItWasWritten(t *testing.T) {
	for _, wire := range [][]byte{
		{0x00, 0x00},
		{0x01, 0x00, 0x00, 0x00},
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	} {
		r := &reader{b: wire}
		n := r.nodeID(false)
		if err := r.done(); err != nil {
			t.Fatal(err)
		}
		if !n.Zero() {
			t.Errorf("%x is not reported as the null node id", wire)
		}
	}
	// A string node id with an empty string is also null, which is what an
	// unactivated session's authentication token looks like.
	wire := build().byte(byte(String)).u16(0).str("").b
	r := &reader{b: wire}
	if n := r.nodeID(false); !n.Zero() {
		t.Error("an empty string identifier is not null")
	}
	wire = build().byte(byte(String)).u16(0).str("x").b
	r = &reader{b: wire}
	if n := r.nodeID(false); n.Zero() {
		t.Error("a non-empty identifier is reported as null")
	}
}

func TestParseNodeIdReadsTheTextFormAConfigurationFileHolds(t *testing.T) {
	for _, tc := range []struct {
		in  string
		key string
	}{
		{"ns=3;i=1001", "ns=3;i=1001"},
		{"i=2253", "ns=0;i=2253"},
		{"ns=4;s=Motor/Speed", "ns=4;s=Motor/Speed"},
		{"nsu=urn:plant:motors;i=7", "nsu=urn:plant:motors;i=7"},
		{"svr=1;ns=2;i=9", "svr=1;ns=2;i=9"},
		{"ns=1;g=72962b91-fa75-45e6-932b-f565b04b4d10",
			"ns=1;g=72962B91-FA75-45E6-932B-F565B04B4D10"},
		{"ns=2;b=DEADBEEF", "ns=2;b=deadbeef"},
	} {
		n, err := ParseNodeId(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got := n.Key(); got != tc.key {
			t.Errorf("%q: %q, want %q", tc.in, got, tc.key)
		}
	}
}

func TestParseNodeIdRefusesWhatAnOperatorGotWrong(t *testing.T) {
	for _, in := range []string{
		"",                   // nothing
		"ns=3",               // a namespace and no identifier
		"1001",               // an identifier with no key
		"ns=abc;i=1",         // a namespace that is not a number
		"ns=70000;i=1",       // a namespace past sixteen bits
		"ns=0;i=99999999999", // an identifier past thirty-two bits
		"ns=0;x=1",           // a part nobody defined
		"svr=abc;ns=0;i=1",   // a server index that is not a number
	} {
		if _, err := ParseNodeId(in); err == nil {
			t.Errorf("ParseNodeId(%q) was accepted", in)
		}
	}
}

func TestANodeIdRoundTripsThroughItsTextForm(t *testing.T) {
	// The wire form and the text form have to agree, because a rule is written in
	// one and matched against the other.
	for _, wire := range [][]byte{
		{0x00, 0x20},
		{0x01, 0x03, 0xE9, 0x03},
		{0x02, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00},
		append([]byte{0x03, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00}, []byte("abc")...),
		append([]byte{0x04, 0x01, 0x00}, bytes.Repeat([]byte{0x11}, 16)...),
		{0x05, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0xAB, 0xCD},
	} {
		r := &reader{b: wire}
		n := r.nodeID(false)
		if err := r.done(); err != nil {
			t.Fatalf("%x: %v", wire, err)
		}
		back, err := ParseNodeId(n.Key())
		if err != nil {
			t.Errorf("%q: %v", n.Key(), err)
			continue
		}
		if back.Key() != n.Key() {
			t.Errorf("%q round tripped to %q", n.Key(), back.Key())
		}
	}
}

func TestTheIDKindsRender(t *testing.T) {
	for k, want := range map[IDKind]string{
		TwoByte: "two_byte", FourByte: "four_byte", Numeric: "numeric",
		String: "string", Guid: "guid", Opaque: "opaque", IDKind(9): "kind(9)",
	} {
		if got := k.String(); got != want {
			t.Errorf("%d: %q, want %q", byte(k), got, want)
		}
	}
	// A node id whose kind is none of the six still renders something a log line
	// can carry, rather than an empty identifier that reads as the null node.
	n := NodeId{Kind: IDKind(9), Text: "?"}
	if got := n.String(); got != "ns=0;?=?" {
		t.Errorf("%q", got)
	}
}
