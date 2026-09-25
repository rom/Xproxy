package snmp

import (
	"errors"
	"testing"
)

// The builders. Every test message is assembled from these rather than from
// a captured hexdump, so that a test says what shape it is about.

// tlv wraps contents in a tag and a length, using the long form when it has
// to -- which is the encoding an agent emits for anything past 127 octets
// and therefore the one a reader has to get right.
func tlv(t Tag, body ...byte) []byte {
	out := []byte{byte(t)}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}

func integer(v int64) []byte {
	if v == 0 {
		return tlv(TagInteger, 0)
	}
	var b []byte
	neg := v < 0
	for v != 0 && v != -1 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	if len(b) == 0 || (!neg && b[0]&0x80 != 0) {
		b = append([]byte{0}, b...)
	}
	return tlv(TagInteger, b...)
}

func octets(t Tag, s string) []byte { return tlv(t, []byte(s)...) }

// oid encodes an object identifier, packing the first two sub-identifiers
// the way BER does and writing the rest base-128.
//
// The packed value is itself base-128, not one octet: 2.999 packs to 1079
// and needs two. Writing it as a single octet is the encoder's half of the
// reader bug this test found.
func oid(vals ...uint32) []byte {
	if len(vals) < 2 {
		panic("an oid needs two sub-identifiers")
	}
	body := base128(vals[0]*40 + vals[1])
	for _, v := range vals[2:] {
		body = append(body, base128(v)...)
	}
	return tlv(TagOID, body...)
}

func base128(v uint32) []byte {
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0x7f)}, out...)
		v >>= 7
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// varbind is one binding: a name and a value.
func varbind(name []byte, value []byte) []byte {
	return tlv(TagSequence, join(name, value)...)
}

// pdu builds an ordinary PDU (everything but the v1 trap).
func pdu(t Tag, reqID int64, a, c int64, binds ...[]byte) []byte {
	return tlv(t, join(integer(reqID), integer(a), integer(c),
		tlv(TagSequence, join(binds...)...))...)
}

// v2c builds a version 2c message.
func v2c(community string, p []byte) []byte {
	return tlv(TagSequence, join(integer(int64(V2c)), octets(TagOctetStr, community), p)...)
}

// v1 builds a version 1 message.
func v1msg(community string, p []byte) []byte {
	return tlv(TagSequence, join(integer(int64(V1)), octets(TagOctetStr, community), p)...)
}

// The version, the credential and the operation: the three fields every
// SNMP policy is written about, read from the three places the protocol
// puts them.
func TestTheVersionAndTheCredentialAreReadFromTheirOwnPlaces(t *testing.T) {
	get := pdu(TagGetRequest, 42, 0, 0, varbind(oid(1, 3, 6, 1, 2, 1, 1, 1, 0), tlv(TagNull)))
	m, err := Parse(v2c("public", get))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != V2c || m.Community != "public" {
		t.Fatalf("version %s community %q", m.Version, m.Community)
	}
	if m.PDU == nil || m.PDU.Type != GetRequest || m.PDU.RequestID != 42 {
		t.Fatalf("pdu %+v", m.PDU)
	}
	if len(m.PDU.VarBinds) != 1 || m.PDU.VarBinds[0].OID.String() != "1.3.6.1.2.1.1.1.0" {
		t.Fatalf("varbinds %+v", m.PDU.VarBinds)
	}
	// The version field is off by one from the name, which is the mistake
	// this test exists to make impossible: a v1 message carries 0.
	m, err = Parse(v1msg("public", get))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != V1 {
		t.Fatalf("a version field of 0 read as %s", m.Version)
	}
	if got := V1.String(); got != "v1" {
		t.Errorf("V1 names itself %q", got)
	}
	// And the names an operator writes.
	for name, want := range map[string]Version{"1": V1, "v1": V1, "2c": V2c, "v2c": V2c, "2": V2c, "3": V3, "v3": V3} {
		got, ok := VersionOf(name)
		if !ok || got != want {
			t.Errorf("version %q: %v %v", name, got, ok)
		}
	}
	if _, ok := VersionOf("2u"); ok {
		t.Error("a version that does not exist was accepted")
	}
	// A version field the protocol does not define is refused rather than
	// forwarded: the credential is in a different place in each version, so
	// a relay that did not know the version could not find it.
	bad := tlv(TagSequence, join(integer(7), octets(TagOctetStr, "public"), get)...)
	if _, err := Parse(bad); !errors.Is(err, ErrVersion) {
		t.Errorf("version 7: %v", err)
	}
}

// What a PDU type says about what is being done. "Read only" is a one-line
// policy on this protocol because there is exactly one writing operation,
// and getting that boundary wrong is how a read-only listener writes.
func TestPDUTypesSayWhatIsBeingDone(t *testing.T) {
	for _, tc := range []struct {
		t                           PDUType
		writes, reads, notification bool
	}{
		{GetRequest, false, true, false},
		{GetNextRequest, false, true, false},
		{GetBulkRequest, false, true, false},
		{SetRequest, true, false, false},
		{Response, false, false, false},
		{TrapV1, false, false, true},
		{TrapV2, false, false, true},
		{InformRequest, false, false, true},
		{ReportPDU, false, false, false},
	} {
		if got := tc.t.Writes(); got != tc.writes {
			t.Errorf("%s writes %v", tc.t, got)
		}
		if got := tc.t.Reads(); got != tc.reads {
			t.Errorf("%s reads %v", tc.t, got)
		}
		if got := tc.t.Notification(); got != tc.notification {
			t.Errorf("%s notification %v", tc.t, got)
		}
		if !tc.t.Known() {
			t.Errorf("%s is not known", tc.t)
		}
	}
	for name, want := range map[string]PDUType{
		"get": GetRequest, "get_next": GetNextRequest, "set": SetRequest,
		"get_bulk": GetBulkRequest, "trap": TrapV2, "trap_v1": TrapV1,
		"inform": InformRequest, "response": Response, "report": ReportPDU,
	} {
		got, ok := PDUTypeOf(name)
		if !ok || got != want {
			t.Errorf("pdu %q: %v %v", name, got, ok)
		}
	}
	if _, ok := PDUTypeOf("walk"); ok {
		t.Error("a pdu type that does not exist was accepted")
	}
	if got := PDUType(0xaa).String(); got != "pdu_0xaa" {
		t.Errorf("an undefined pdu reads as %q", got)
	}
	// A PDU tag the protocol does not define is refused, not forwarded.
	bad := v2c("public", tlv(Tag(0xaa), join(integer(1), integer(0), integer(0), tlv(TagSequence))...))
	if _, err := Parse(bad); !errors.Is(err, ErrTag) {
		t.Errorf("an undefined pdu tag: %v", err)
	}
}

// GETBULK puts non-repeaters and max-repetitions where every other PDU puts
// the error status and index. Reading them in the wrong place would make the
// amplification factor invisible -- which is the whole reason this protocol
// is a reflection vector.
func TestGetBulkCarriesItsAmplificationFactorWhereTheErrorFieldsGo(t *testing.T) {
	bulk := pdu(TagGetBulkRequest, 7, 0, 10000, varbind(oid(1, 3, 6, 1, 2, 1), tlv(TagNull)))
	m, err := Parse(v2c("public", bulk))
	if err != nil {
		t.Fatal(err)
	}
	if m.PDU.MaxRepetitions != 10000 || m.PDU.NonRepeaters != 0 {
		t.Fatalf("non-repeaters %d max-repetitions %d", m.PDU.NonRepeaters, m.PDU.MaxRepetitions)
	}
	if m.PDU.ErrorStatus != 0 || m.PDU.ErrorIndex != 0 {
		t.Errorf("a getbulk reported an error status: %+v", m.PDU)
	}
	// And a response puts them back: the same two positions mean the other
	// thing, so a relay reading a response must not report an error status
	// of ten thousand as a repetition count.
	resp := pdu(TagResponse, 7, 2, 1, varbind(oid(1, 3, 6, 1, 2, 1), tlv(TagNull)))
	m, err = Parse(v2c("public", resp))
	if err != nil {
		t.Fatal(err)
	}
	if m.PDU.ErrorStatus != 2 || m.PDU.ErrorIndex != 1 {
		t.Fatalf("error status %d index %d", m.PDU.ErrorStatus, m.PDU.ErrorIndex)
	}
	if m.PDU.MaxRepetitions != 0 {
		t.Errorf("a response reported max-repetitions %d", m.PDU.MaxRepetitions)
	}
}

// Object identifiers, in the encoding BER actually uses: the first two
// sub-identifiers packed into one octet and the rest base-128.
func TestObjectIdentifiersAreReadAndComparedPerSubIdentifier(t *testing.T) {
	for _, tc := range []struct {
		vals []uint32
		text string
	}{
		{[]uint32{1, 3, 6, 1, 2, 1, 1, 1, 0}, "1.3.6.1.2.1.1.1.0"},
		{[]uint32{0, 0}, "0.0"},
		{[]uint32{2, 999}, "2.999"},
		// A sub-identifier past 127 needs two base-128 octets, and one past
		// 16383 needs three: the boundaries an encoder gets wrong.
		{[]uint32{1, 3, 128}, "1.3.128"},
		{[]uint32{1, 3, 16384}, "1.3.16384"},
		{[]uint32{1, 3, 4294967295}, "1.3.4294967295"},
		// The packed first value spanning two octets, which a reader that
		// took only the first octet would read as 2.56.55 -- a different
		// object under a different subtree.
		{[]uint32{2, 1000}, "2.1000"},
	} {
		m, err := Parse(v2c("c", pdu(TagGetRequest, 1, 0, 0, varbind(oid(tc.vals...), tlv(TagNull)))))
		if err != nil {
			t.Fatalf("%v: %v", tc.vals, err)
		}
		if got := m.PDU.VarBinds[0].OID.String(); got != tc.text {
			t.Errorf("%v read as %q, want %q", tc.vals, got, tc.text)
		}
	}
	// The subtree test is per sub-identifier, which is the point of keeping
	// an OID as numbers: the *string* "1.3.6.1.2.1" is a prefix of the
	// string "1.3.6.1.2.11", and the object is not under the subtree. A
	// policy written with string prefixes allows a subtree nobody named.
	mib2 := OID{1, 3, 6, 1, 2, 1}
	for _, tc := range []struct {
		o    OID
		want bool
	}{
		{OID{1, 3, 6, 1, 2, 1}, true},
		{OID{1, 3, 6, 1, 2, 1, 1, 1, 0}, true},
		{OID{1, 3, 6, 1, 2, 11}, false},
		{OID{1, 3, 6, 1, 2, 11, 1}, false},
		{OID{1, 3, 6, 1, 2}, false},
		{OID{1, 3, 6, 1, 4, 1}, false},
	} {
		if got := tc.o.Under(mib2); got != tc.want {
			t.Errorf("%s under %s = %v", tc.o, mib2, got)
		}
	}
	if !(OID{1, 2}).Equal(OID{1, 2}) || (OID{1, 2}).Equal(OID{1, 2, 3}) || (OID{1, 2}).Equal(OID{1, 3}) {
		t.Error("OID equality")
	}
	if got := OID(nil).String(); got != "" {
		t.Errorf("an empty oid reads as %q", got)
	}
	// The names an operator writes, with and without the leading dot.
	for _, s := range []string{"1.3.6.1.2.1", ".1.3.6.1.2.1", " 1.3.6.1.2.1 "} {
		got, err := ParseOID(s)
		if err != nil || !got.Equal(mib2) {
			t.Errorf("ParseOID(%q) = %v %v", s, got, err)
		}
	}
	for _, s := range []string{"", ".", "1.3.x", "1.3.-1", "1.3.4294967296", "1..3"} {
		if _, err := ParseOID(s); err == nil {
			t.Errorf("ParseOID(%q) was accepted", s)
		}
	}
}

// What is not a message. Every one of these would otherwise reach an agent
// that will read the octets somehow.
func TestMessagesThatAreNotMessages(t *testing.T) {
	good := v2c("public", pdu(TagGetRequest, 1, 0, 0, varbind(oid(1, 3, 6, 1), tlv(TagNull))))
	for what, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"nothing at all":        {nil, ErrTruncated},
		"one octet":             {[]byte{0x30}, ErrTruncated},
		"not a sequence":        {tlv(TagInteger, 1), ErrTag},
		"a length that lies":    {append([]byte{0x30, 0x7f}, good[2:]...), ErrTruncated},
		"the indefinite form":   {[]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}, ErrIndefinite},
		"a length past 32 bits": {[]byte{0x30, 0x85, 1, 1, 1, 1, 1}, ErrLongLength},
		"a second message":      {append(append([]byte{}, good...), good...), ErrTrailing},
		"no community":          {tlv(TagSequence, integer(1)...), ErrTruncated},
		"no pdu":                {tlv(TagSequence, join(integer(1), octets(TagOctetStr, "c"))...), ErrTruncated},
	} {
		_, err := Parse(tc.raw)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", what, err, tc.want)
		}
	}
	// A community string longer than any agent accepts.
	long := make([]byte, MaxCommunity+1)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := Parse(v2c(string(long), pdu(TagGetRequest, 1, 0, 0))); !errors.Is(err, ErrCommunity) {
		t.Error("an over-long community string was accepted")
	}
	// A message past what this reads at all.
	huge := make([]byte, MaxMessage+1)
	if _, err := Parse(huge); !errors.Is(err, ErrTruncated) {
		t.Error("a message past MaxMessage was read")
	}
}

// Object identifiers that are not ones. Each of these is a way to make two
// implementations disagree about whether an object is inside a subtree,
// which is a way past a policy.
func TestObjectIdentifiersThatAreNotOnes(t *testing.T) {
	for what, body := range map[string][]byte{
		"empty":                         {},
		"a truncated sub-identifier":    {0x2b, 0x81},
		"a non-minimal sub-identifier":  {0x2b, 0x80, 0x01},
		"a sub-identifier past 32 bits": {0x2b, 0x90, 0x80, 0x80, 0x80, 0x00},
	} {
		raw := v2c("c", pdu(TagGetRequest, 1, 0, 0, varbind(tlv(TagOID, body...), tlv(TagNull))))
		if _, err := Parse(raw); !errors.Is(err, ErrOID) {
			t.Errorf("%s: %v", what, err)
		}
	}
	// And one past the sub-identifier bound, which is a way to spend a
	// relay's time rather than to name an object.
	body := []byte{0x2b}
	for i := 0; i <= MaxOIDLength; i++ {
		body = append(body, 0x01)
	}
	raw := v2c("c", pdu(TagGetRequest, 1, 0, 0, varbind(tlv(TagOID, body...), tlv(TagNull))))
	if _, err := Parse(raw); !errors.Is(err, ErrOID) {
		t.Errorf("an oid past the bound: %v", err)
	}
}

// The variable binding list, including the value types this reads for their
// extent and does not interpret.
func TestVarBindsCarryTheirTypeAndExtent(t *testing.T) {
	binds := []([]byte){
		varbind(oid(1, 3, 6, 1, 2, 1, 1, 3, 0), tlv(TagTimeTicks, 0x00, 0x01, 0x02, 0x03)),
		varbind(oid(1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1), tlv(TagCounter32, 0xff, 0xff, 0xff, 0xff)),
		varbind(oid(1, 3, 6, 1, 2, 1, 4, 20, 1, 1), tlv(TagIPAddress, 10, 0, 0, 1)),
		varbind(oid(1, 3, 6, 1, 2, 1, 1, 1, 0), octets(TagOctetStr, "a switch")),
		varbind(oid(1, 3, 6, 1, 2, 1, 99), tlv(TagNoSuchObject)),
		varbind(oid(1, 3, 6, 1, 2, 1, 98), tlv(TagEndOfMibView)),
	}
	m, err := Parse(v2c("public", pdu(TagResponse, 1, 0, 0, binds...)))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.PDU.VarBinds) != 6 {
		t.Fatalf("varbinds %d", len(m.PDU.VarBinds))
	}
	if got := m.PDU.VarBinds[0]; got.Tag != TagTimeTicks || got.Len != 4 {
		t.Errorf("timeticks %+v", got)
	}
	if got := m.PDU.VarBinds[3]; got.Tag != TagOctetStr || got.Len != len("a switch") {
		t.Errorf("octet string %+v", got)
	}
	// The three exception values are not errors: an agent ending a walk
	// says end-of-MIB-view with one, and a relay that treated them as
	// failures would break every walk.
	if !m.PDU.VarBinds[4].Exception() || !m.PDU.VarBinds[5].Exception() {
		t.Error("the exception values were not recognised")
	}
	if m.PDU.VarBinds[0].Exception() {
		t.Error("a timeticks value was read as an exception")
	}
	// An unsigned application value with the high bit set is encoded with a
	// leading zero octet, and read as signed it would be negative: a
	// counter that has simply grown past two billion.
	m, err = Parse(v2c("c", pdu(TagResponse, 1, 0, 0,
		varbind(oid(1, 3, 6, 1), tlv(TagCounter64, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)))))
	if err != nil {
		t.Fatalf("a full counter64: %v", err)
	}
	if b := m.PDU.VarBinds[0]; b.Tag != TagCounter64 || b.Len != 9 {
		// Nine octets: eight of value and the leading zero that keeps it
		// unsigned. A reader that refused the ninth would refuse every
		// counter past 2^63.
		t.Errorf("a full counter64 read as tag %#02x, %d octets", byte(b.Tag), b.Len)
	}
	// A binding with two values, or none, is not a binding.
	for what, bind := range map[string][]byte{
		"two values": tlv(TagSequence, join(oid(1, 3, 6, 1), tlv(TagNull), tlv(TagNull))...),
		"no value":   tlv(TagSequence, oid(1, 3, 6, 1)...),
		"no name":    tlv(TagSequence, tlv(TagNull)...),
	} {
		if _, err := Parse(v2c("c", pdu(TagGetRequest, 1, 0, 0, bind))); err == nil {
			t.Errorf("%s was accepted as a binding", what)
		}
	}
}

// The version 1 trap, whose header is its own shape: version 2 replaced it
// with two varbinds, so a relay that bridges the two has to read both.
func TestTheVersionOneTrapHasItsOwnHeader(t *testing.T) {
	trap := tlv(TagTrapV1, join(
		oid(1, 3, 6, 1, 4, 1, 9),
		tlv(TagIPAddress, 192, 0, 2, 7),
		integer(6), // enterpriseSpecific
		integer(42),
		tlv(TagTimeTicks, 0x00, 0x00, 0x30, 0x39),
		tlv(TagSequence, varbind(oid(1, 3, 6, 1, 4, 1, 9, 1), octets(TagOctetStr, "link down"))...),
	)...)
	m, err := Parse(v1msg("public", trap))
	if err != nil {
		t.Fatal(err)
	}
	p := m.PDU
	if p.Type != TrapV1 || !p.Type.Notification() {
		t.Fatalf("type %s", p.Type)
	}
	if p.Enterprise.String() != "1.3.6.1.4.1.9" {
		t.Errorf("enterprise %s", p.Enterprise)
	}
	if p.Agent != [4]byte{192, 0, 2, 7} {
		t.Errorf("agent %v", p.Agent)
	}
	if p.GenericTrap != 6 || p.SpecificTrap != 42 || p.Timestamp != 12345 {
		t.Errorf("trap %d/%d at %d", p.GenericTrap, p.SpecificTrap, p.Timestamp)
	}
	if len(p.VarBinds) != 1 {
		t.Errorf("varbinds %+v", p.VarBinds)
	}
	// A v1 trap whose agent address is not four octets is not one: the
	// field is an IpAddress and a relay must not read three octets as an
	// address with a zero on the end.
	bad := tlv(TagTrapV1, join(oid(1, 3, 6, 1), tlv(TagIPAddress, 1, 2, 3), integer(6), integer(0),
		tlv(TagTimeTicks, 0), tlv(TagSequence))...)
	if _, err := Parse(v1msg("public", bad)); err == nil {
		t.Error("a three-octet agent address was accepted")
	}
}

// usm builds the user security model's parameters, which travel inside an
// OCTET STRING rather than beside the other fields: a SEQUENCE wrapped in a
// string, which is the shape a reader has to descend into twice.
func usm(engineID string, boots, tm int64, user string, auth, priv string) []byte {
	inner := tlv(TagSequence, join(
		octets(TagOctetStr, engineID),
		integer(boots),
		integer(tm),
		octets(TagOctetStr, user),
		octets(TagOctetStr, auth),
		octets(TagOctetStr, priv),
	)...)
	return tlv(TagOctetStr, inner...)
}

// v3msg builds a version 3 message. flags is the msgFlags octet and scoped
// is whatever follows the security parameters.
func v3msg(msgID int64, flags byte, model int64, sec []byte, scoped []byte) []byte {
	global := tlv(TagSequence, join(
		integer(msgID), integer(65507), tlv(TagOctetStr, flags), integer(model),
	)...)
	return tlv(TagSequence, join(integer(int64(V3)), global, sec, scoped)...)
}

// scopedPDU wraps a PDU with its context.
func scopedPDU(engineID, contextName string, p []byte) []byte {
	return tlv(TagSequence, join(
		octets(TagOctetStr, engineID), octets(TagOctetStr, contextName), p,
	)...)
}

// The version 3 header, field by field. Each of these is something a policy
// names, and the security level is the one that matters most: noAuthNoPriv
// is v2c with more fields, and a great many estates enable v3 and leave it
// there.
func TestTheVersionThreeHeaderIsReadFieldByField(t *testing.T) {
	get := pdu(TagGetRequest, 99, 0, 0, varbind(oid(1, 3, 6, 1, 2, 1, 1, 1, 0), tlv(TagNull)))
	// authNoPriv: the authentication bit and the reportable bit.
	raw := v3msg(7, 0x05, 3, usm("engine-a", 3, 12345, "monitor", "0123456789ab", ""),
		scopedPDU("engine-a", "", get))
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != V3 || m.V3 == nil {
		t.Fatalf("version %s header %v", m.Version, m.V3)
	}
	h := m.V3
	if h.MessageID != 7 || h.MaxSize != 65507 || h.SecurityModel != 3 {
		t.Errorf("global data %+v", h)
	}
	if h.Level != AuthNoPriv || !h.Reportable {
		t.Errorf("level %s reportable %v", h.Level, h.Reportable)
	}
	if string(h.EngineID) != "engine-a" || h.EngineBoots != 3 || h.EngineTime != 12345 {
		t.Errorf("engine %q boots %d time %d", h.EngineID, h.EngineBoots, h.EngineTime)
	}
	if h.User != "monitor" {
		t.Errorf("user %q", h.User)
	}
	if h.ScopedPDUEncrypted {
		t.Error("a plain scoped pdu read as encrypted")
	}
	if m.PDU == nil || m.PDU.Type != GetRequest || m.PDU.RequestID != 99 {
		t.Fatalf("pdu %+v", m.PDU)
	}
	// The v3 credential is the user name, not a community string, and the
	// community field must stay empty so a policy cannot confuse them.
	if m.Community != "" {
		t.Errorf("a v3 message reported community %q", m.Community)
	}

	// The three levels, from the two flag bits.
	for flags, want := range map[byte]SecurityLevel{
		0x00: NoAuthNoPriv, 0x04: NoAuthNoPriv,
		0x01: AuthNoPriv, 0x05: AuthNoPriv,
		0x03: AuthPriv, 0x07: AuthPriv,
		// The privacy bit without the authentication bit is not a level the
		// standard defines -- encryption nobody can attribute -- and reads
		// as the lowest level so a listener refuses it by name rather than
		// treating it as authenticated.
		0x02: NoAuthNoPriv,
	} {
		scoped := scopedPDU("e", "", get)
		if want.Encrypted() {
			scoped = octets(TagOctetStr, "ciphertext")
		}
		m, err := Parse(v3msg(1, flags, 3, usm("e", 1, 1, "u", "", ""), scoped))
		if err != nil {
			t.Fatalf("flags %#02x: %v", flags, err)
		}
		if m.V3.Level != want {
			t.Errorf("flags %#02x read as %s, want %s", flags, m.V3.Level, want)
		}
	}
	for name, want := range map[string]SecurityLevel{
		"noAuthNoPriv": NoAuthNoPriv, "noauthnopriv": NoAuthNoPriv,
		"authNoPriv": AuthNoPriv, "AUTHPRIV": AuthPriv,
	} {
		got, ok := LevelOf(name)
		if !ok || got != want {
			t.Errorf("level %q: %v %v", name, got, ok)
		}
	}
	if _, ok := LevelOf("authOnly"); ok {
		t.Error("a level that does not exist was accepted")
	}
	if !AuthPriv.Authenticated() || !AuthNoPriv.Authenticated() || NoAuthNoPriv.Authenticated() {
		t.Error("Authenticated")
	}
	if !AuthPriv.Encrypted() || AuthNoPriv.Encrypted() {
		t.Error("Encrypted")
	}
	// The names the RFC uses, which is how they appear in every vendor's
	// configuration guide and therefore in every log an operator compares
	// against one.
	for l, want := range map[SecurityLevel]string{
		NoAuthNoPriv: "noAuthNoPriv", AuthNoPriv: "authNoPriv", AuthPriv: "authPriv",
		SecurityLevel(9): "noAuthNoPriv",
	} {
		if got := l.String(); got != want {
			t.Errorf("level %d names itself %q, want %q", int(l), got, want)
		}
	}
}

// An encrypted scoped PDU is the case a relay cannot inspect, and saying so
// is the honest answer: the header is readable, the payload is not, and a
// policy about object identifiers has nothing to work with.
func TestAnEncryptedScopedPDUIsReadableAsAHeaderAndNoFurther(t *testing.T) {
	raw := v3msg(11, 0x03, 3, usm("engine-b", 1, 2, "operator", "0123456789ab", "12345678"),
		octets(TagOctetStr, "this is ciphertext"))
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.V3.Level != AuthPriv || !m.V3.ScopedPDUEncrypted {
		t.Fatalf("header %+v", m.V3)
	}
	if m.PDU != nil {
		t.Fatalf("an encrypted payload was decoded as %+v", m.PDU)
	}
	// The user name is still there, which is what a policy can decide on.
	if m.V3.User != "operator" {
		t.Errorf("user %q", m.V3.User)
	}
}

// The context, which is where a v3 message says which agent it is for when
// one engine fronts several -- a proxy's own case.
func TestTheScopedPDUCarriesItsContext(t *testing.T) {
	get := pdu(TagGetRequest, 1, 0, 0)
	m, err := Parse(v3msg(1, 0x01, 3, usm("e", 1, 1, "u", "", ""),
		scopedPDU("switch-7", "vlan-200", get)))
	if err != nil {
		t.Fatal(err)
	}
	if string(m.V3.ContextEngineID) != "switch-7" || m.V3.ContextName != "vlan-200" {
		t.Errorf("context %q %q", m.V3.ContextEngineID, m.V3.ContextName)
	}
}

// A security model this does not read. The security parameters are that
// model's own octets, so nothing in them is interpreted -- and a relay must
// not report a user name it did not read.
func TestAnUnknownSecurityModelLeavesItsParametersUnread(t *testing.T) {
	m, err := Parse(v3msg(1, 0x01, 99, octets(TagOctetStr, "some other model's bytes"),
		scopedPDU("e", "", pdu(TagGetRequest, 1, 0, 0))))
	if err != nil {
		t.Fatal(err)
	}
	if m.V3.SecurityModel != 99 {
		t.Errorf("model %d", m.V3.SecurityModel)
	}
	if m.V3.User != "" || len(m.V3.EngineID) != 0 {
		t.Errorf("a model this does not read reported user %q engine %q", m.V3.User, m.V3.EngineID)
	}
}

// Version 3 messages that are not messages.
func TestVersionThreeMessagesThatAreNotMessages(t *testing.T) {
	get := pdu(TagGetRequest, 1, 0, 0)
	sec := usm("e", 1, 1, "u", "", "")
	for what, raw := range map[string][]byte{
		"no global data": tlv(TagSequence, join(integer(3), sec, scopedPDU("e", "", get))...),
		"msgFlags of two octets": tlv(TagSequence, join(integer(3),
			tlv(TagSequence, join(integer(1), integer(1), tlv(TagOctetStr, 0x01, 0x00), integer(3))...),
			sec, scopedPDU("e", "", get))...),
		"msgFlags of none": tlv(TagSequence, join(integer(3),
			tlv(TagSequence, join(integer(1), integer(1), tlv(TagOctetStr), integer(3))...),
			sec, scopedPDU("e", "", get))...),
		"no security parameters": tlv(TagSequence, join(integer(3),
			tlv(TagSequence, join(integer(1), integer(1), tlv(TagOctetStr, 0x01), integer(3))...))...),
		"usm that is not a sequence": v3msg(1, 0x01, 3, octets(TagOctetStr, "not a sequence"),
			scopedPDU("e", "", get)),
		"no scoped pdu": v3msg(1, 0x01, 3, sec, nil),
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	// An engine identifier past the 32 octets RFC 3411 allows.
	long := ""
	for i := 0; i < 33; i++ {
		long += "e"
	}
	if _, err := Parse(v3msg(1, 0x01, 3, usm(long, 1, 1, "u", "", ""), scopedPDU("e", "", get))); err == nil {
		t.Error("a 33-octet engine identifier was accepted")
	}
	// A user name past what is compared against a configured list.
	longUser := make([]byte, MaxCommunity+1)
	for i := range longUser {
		longUser[i] = 'u'
	}
	if _, err := Parse(v3msg(1, 0x01, 3, usm("e", 1, 1, string(longUser), "", ""),
		scopedPDU("e", "", get))); !errors.Is(err, ErrCommunity) {
		t.Error("an over-long user name was accepted")
	}
}

// A message nested deeper than this reader descends, which is a message
// shaped to make a parser recurse rather than to ask an agent anything.
func TestAMessageCannotNestForever(t *testing.T) {
	body := tlv(TagNull)
	for i := 0; i < MaxNesting+4; i++ {
		body = tlv(TagSequence, body...)
	}
	if _, err := Parse(body); err == nil {
		t.Error("a deeply nested message was accepted")
	}
}
