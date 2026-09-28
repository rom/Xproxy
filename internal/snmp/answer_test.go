package snmp

import (
	"strings"
	"testing"
)

// An encoded OID has to read back as the one that went in. Everything a
// fabricated agent answers is named by one, and a name a manager cannot
// read is an answer it discards.
func TestOIDsRoundTrip(t *testing.T) {
	for _, s := range []string{
		"1.3.6.1.2.1.1.1.0",
		"1.3.6.1.2.1.2.2.1.10.1",
		"1.3.6.1.4.1.9.1.1208",       // an enterprise number above 127
		"1.3.6.1.4.1.8072.3.2.10",    // and one above 16383
		"1.3.6.1.2.1.2.2.1.10.65535", // an index that needs three octets
		"0.0",
		"2.16843009.1", // a subidentifier needing five octets
		"1.3.6.1.4.1.4294967295.1",
	} {
		o, err := ParseOID(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		enc := EncodeOID(o)
		if len(enc) == 0 {
			t.Fatalf("%s: encoded to nothing", s)
		}
		back, err := readOID(element{tag: TagOID, body: enc})
		if err != nil {
			t.Fatalf("%s: reading back: %v", s, err)
		}
		if got := back.String(); got != s {
			t.Errorf("%s came back as %s", s, got)
		}
	}
	// An OID of one arc has no first octet group, so there is nothing to
	// encode and nothing that would read back.
	if enc := EncodeOID(OID{1}); enc != nil {
		t.Errorf("a one-arc OID encoded to %x", enc)
	}
}

// The unsigned values: the fewest octets that hold the number, and a leading
// zero where the top bit would otherwise make it negative. Every agent
// writes them this way, and a response that wrote them differently would be
// this proxy's fingerprint.
func TestUnsignedValuesAreEncodedTheWayAnAgentDoes(t *testing.T) {
	for _, tc := range []struct {
		in   uint64
		want string
	}{
		{0, "00"},
		{1, "01"},
		{127, "7f"},
		{128, "0080"},
		{255, "00ff"},
		{256, "0100"},
		{0x7fffffff, "7fffffff"},
		{0x80000000, "0080000000"},
		{0xffffffff, "00ffffffff"},
		{0xffffffffffffffff, "00ffffffffffffffff"},
	} {
		if got := hexOf(encodeUint(tc.in)); got != tc.want {
			t.Errorf("%d encoded as %s, want %s", tc.in, got, tc.want)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(digits[c>>4])
		sb.WriteByte(digits[c&0x0f])
	}
	return sb.String()
}

// A built answer has to parse as the response it claims to be, with the
// request identifier the manager is waiting on and the values that were put
// in it. This is the round trip the fabrication depends on.
func TestAnAnswerParsesAsAResponse(t *testing.T) {
	req, err := Envelope(V2c, "public", requestPDU(t, GetRequest, 4242, "1.3.6.1.2.1.1.1.0"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(req)
	if err != nil {
		t.Fatal(err)
	}
	sysDescr, _ := ParseOID("1.3.6.1.2.1.1.1.0")
	upTime, _ := ParseOID("1.3.6.1.2.1.1.3.0")
	out, err := Answer(m, [][]byte{
		Varbind(sysDescr, TagOctetStr, []byte("a switch")),
		Varbind(upTime, TagTimeTicks, Ticks(123456)),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(out)
	if err != nil {
		t.Fatalf("the answer did not parse: %v", err)
	}
	if got.PDU.Type != Response {
		t.Errorf("the answer is a %s", got.PDU.Type)
	}
	if got.PDU.RequestID != 4242 {
		t.Errorf("the answer carries request %d", got.PDU.RequestID)
	}
	if got.PDU.ErrorStatus != 0 {
		t.Errorf("the answer carries error status %d", got.PDU.ErrorStatus)
	}
	if got.Community != "public" {
		t.Errorf("the answer carries community %q", got.Community)
	}
	if len(got.PDU.VarBinds) != 2 {
		t.Fatalf("the answer carries %d bindings", len(got.PDU.VarBinds))
	}
	if got.PDU.VarBinds[0].OID.String() != "1.3.6.1.2.1.1.1.0" || got.PDU.VarBinds[0].Tag != TagOctetStr {
		t.Errorf("binding 0 is %s %#x", got.PDU.VarBinds[0].OID, got.PDU.VarBinds[0].Tag)
	}
	if got.PDU.VarBinds[1].Tag != TagTimeTicks {
		t.Errorf("binding 1 is tagged %#x, and a manager that asked for uptime wants ticks",
			got.PDU.VarBinds[1].Tag)
	}

	// And an error answer, which carries the bindings back as they arrived.
	bad, err := AnswerError(m, StatusNoSuchName, 1)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(bad)
	if err != nil {
		t.Fatalf("the error answer did not parse: %v", err)
	}
	if e.PDU.ErrorStatus != StatusNoSuchName || e.PDU.ErrorIndex != 1 {
		t.Errorf("the error answer says status %d index %d", e.PDU.ErrorStatus, e.PDU.ErrorIndex)
	}
	if len(e.PDU.VarBinds) != 1 || e.PDU.VarBinds[0].OID.String() != "1.3.6.1.2.1.1.1.0" {
		t.Errorf("the error answer did not carry the request's binding back: %+v", e.PDU.VarBinds)
	}
}

// requestPDU builds a request with one binding, which is what the tests
// above answer.
func requestPDU(t *testing.T, typ PDUType, id int64, oid string) []byte {
	t.Helper()
	o, err := ParseOID(oid)
	if err != nil {
		t.Fatal(err)
	}
	body := encodeTLV(TagInteger, encodeInt(id))
	body = append(body, encodeTLV(TagInteger, encodeInt(0))...)
	body = append(body, encodeTLV(TagInteger, encodeInt(0))...)
	body = append(body, encodeTLV(TagSequence, Varbind(o, TagNull, NullValue()))...)
	return encodeTLV(Tag(typ), body)
}

// The ordering a walk depends on: subidentifier by subidentifier, a prefix
// before what extends it, and 2 before 10 rather than after it -- the
// mistake a comparison written on the dotted string makes, which turns a
// walk of an interface table into a walk that skips most of it.
func TestOIDsCompareTheWayAWalkNeeds(t *testing.T) {
	oid := func(s string) OID {
		t.Helper()
		o, err := ParseOID(s)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.1.0", 0},
		{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", -1},
		{"1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.1.0", 1},
		// A prefix comes first.
		{"1.3.6.1.2.1.2.2.1", "1.3.6.1.2.1.2.2.1.1", -1},
		// And the one every string comparison gets wrong.
		{"1.3.6.1.2.1.2.2.1.1.2", "1.3.6.1.2.1.2.2.1.1.10", -1},
		{"1.3.6.1.2.1.2.2.1.10.1", "1.3.6.1.2.1.2.2.1.2.1", 1},
	} {
		if got := Compare(oid(tc.a), oid(tc.b)); got != tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
