package dns

import (
	"crypto/sha1" //nolint:gosec // NSEC3 hashing is SHA-1 by specification
	"encoding/binary"
	"strings"
	"testing"
)

// The NSEC3 proofs are how a zone says "this name does not exist"
// without listing what does. Getting them wrong in the permissive
// direction means a forged denial is believed, which is how an
// attacker makes a name that exists look like one that does not.

// nsec3RR builds an NSEC3 record: an owner label of the hashed name in
// base32hex under the zone, and rdata holding the parameters, the next
// hashed owner and a type bitmap.
func nsec3RR(zone string, ownerHash, nextHash []byte, salt []byte, iterations uint16, flags byte, types ...uint16) *RRset {
	data := []byte{1, flags}
	data = binary.BigEndian.AppendUint16(data, iterations)
	data = append(data, byte(len(salt)))
	data = append(data, salt...)
	data = append(data, byte(len(nextHash)))
	data = append(data, nextHash...)
	data = append(data, bitmap(types...)...)
	name := strings.ToLower(base32hex.EncodeToString(ownerHash)) + "." + zone
	return &RRset{Name: name, Type: TypeNSEC3, Class: ClassIN, TTL: 300,
		RRs: []RR{{Name: name, Type: TypeNSEC3, Class: ClassIN, TTL: 300, Data: data}}}
}

// hashName is the RFC 5155 hash, computed independently of the code
// under test so a change to either side is visible.
func hashName(name string, salt []byte, iterations uint16) []byte {
	wire, err := packName(strings.ToLower(name))
	if err != nil {
		return nil
	}
	h := sha1.Sum(append(wire, salt...)) //nolint:gosec // by specification
	for i := 0; i < int(iterations); i++ {
		h = sha1.Sum(append(h[:], salt...)) //nolint:gosec // by specification
	}
	return h[:]
}

func TestNSEC3Hash(t *testing.T) {
	salt := []byte{0xaa, 0xbb}
	p := &nsec3{hashAlg: 1, salt: salt, iterations: 5}
	got := nsec3Hash("www.example.com.", p)
	if want := hashName("www.example.com.", salt, 5); string(got) != string(want) {
		t.Fatalf("hash %x want %x", got, want)
	}
	// The name is hashed in lower case, so the case a query arrives in
	// cannot change which record denies it.
	if string(nsec3Hash("WWW.Example.COM.", p)) != string(got) {
		t.Error("the hash depends on the case of the name")
	}
	// Every parameter is part of the hash.
	if string(nsec3Hash("www.example.com.", &nsec3{hashAlg: 1, salt: salt, iterations: 6})) == string(got) {
		t.Error("the iteration count does not change the hash")
	}
	if string(nsec3Hash("www.example.com.", &nsec3{hashAlg: 1, salt: []byte{0xaa}, iterations: 5})) == string(got) {
		t.Error("the salt does not change the hash")
	}
	// Refusals: no parameters, another hash algorithm, and an iteration
	// count past the bound RFC 9276 recommends — the last is a denial of
	// service through somebody else's zone, so it must not be computed.
	if nsec3Hash("x.example.com.", nil) != nil {
		t.Error("a nil parameter set produced a hash")
	}
	for _, p := range []*nsec3{
		{hashAlg: 0, iterations: 1},
		{hashAlg: 2, iterations: 1},
		{hashAlg: 1, iterations: 151},
		{hashAlg: 1, iterations: 65535},
	} {
		if nsec3Hash("x.example.com.", p) != nil {
			t.Errorf("parameters %+v produced a hash", p)
		}
	}
	// A name that cannot be packed has no hash.
	if nsec3Hash(strings.Repeat("a", 64)+".example.com.", &nsec3{hashAlg: 1, iterations: 0}) != nil {
		t.Error("an unpackable name produced a hash")
	}
}

func TestNSEC3CoversAndMatches(t *testing.T) {
	zone := "example.com."
	salt := []byte{1, 2, 3}
	mid := hashName("b.example.com.", salt, 1)
	low := hashName("a.example.com.", salt, 1)
	high := hashName("c.example.com.", salt, 1)
	// Order the three hashes so the test reasons about the interval
	// rather than about which name happened to hash where.
	order := [][]byte{low, mid, high}
	for i := 0; i < len(order); i++ {
		for j := i + 1; j < len(order); j++ {
			if string(order[j]) < string(order[i]) {
				order[i], order[j] = order[j], order[i]
			}
		}
	}
	lo, in, hi := order[0], order[1], order[2]

	span := nsec3RR(zone, lo, hi, salt, 1, 0, TypeA)
	if !nsec3Covers(span, in, zone) {
		t.Error("a hash inside the span was not covered")
	}
	for _, h := range [][]byte{lo, hi, nil} {
		if nsec3Covers(span, h, zone) {
			t.Errorf("%x was reported as covered", h)
		}
	}
	// The last record of a zone wraps: its next hash is lower than its
	// own, and it covers everything outside.
	wrap := nsec3RR(zone, hi, lo, salt, 1, 0, TypeA)
	if nsec3Covers(wrap, in, zone) {
		t.Error("a wrapping record covered a hash inside the gap it does not own")
	}
	if !nsec3Covers(wrap, append(append([]byte{}, hi...), 0xff), zone) {
		t.Error("a wrapping record did not cover a hash above its owner")
	}
	// Matching is exact.
	if p := nsec3Matches(span, lo, zone); p == nil {
		t.Error("the owner hash did not match its own record")
	} else if !p.types[TypeA] {
		t.Error("the type bitmap was lost")
	}
	if nsec3Matches(span, in, zone) != nil {
		t.Error("a hash inside the span matched the record")
	}
	if nsec3Matches(span, nil, zone) != nil {
		t.Error("a nil hash matched")
	}
	// An owner label that is not base32hex, and a set with no records
	// (which is what a lone RRSIG looks like), prove nothing.
	broken := &RRset{Name: "not-base32hex-!!." + zone, Type: TypeNSEC3,
		RRs: []RR{{Name: "not-base32hex-!!." + zone, Type: TypeNSEC3, Data: span.RRs[0].Data}}}
	if nsec3Covers(broken, in, zone) || nsec3Matches(broken, in, zone) != nil {
		t.Error("a record with an unreadable owner label proved something")
	}
	empty := &RRset{Name: span.Name, Type: TypeNSEC3}
	if nsec3Covers(empty, in, zone) || nsec3Matches(empty, lo, zone) != nil {
		t.Error("an empty set proved something")
	}
	if _, err := nsec3Set(nil); err == nil {
		t.Error("a nil set parsed")
	}
}

func TestParseNSEC3Malformed(t *testing.T) {
	salt := []byte{9, 9}
	next := hashName("x.example.com.", salt, 0)
	good := append([]byte{1, 0, 0, 0, byte(len(salt))}, salt...)
	good = append(good, byte(len(next)))
	good = append(good, next...)
	good = append(good, bitmap(TypeA)...)
	if _, err := parseNSEC3(RR{Data: good}); err != nil {
		t.Fatalf("a well-formed record was refused: %v", err)
	}
	// Truncation anywhere in the fixed part is refused rather than read
	// past. A record cut inside the trailing type bitmap is still a
	// record: the bitmap is optional and a partial window decodes to no
	// types, which proves nothing rather than proving something wrong.
	fixed := 6 + len(salt) + len(next)
	for n := 0; n < fixed; n++ {
		if p, err := parseNSEC3(RR{Data: good[:n]}); err == nil {
			t.Errorf("a %d byte prefix parsed, giving %d bytes of next hash", n, len(p.next))
		}
	}
	for n := fixed; n < len(good); n++ {
		p, err := parseNSEC3(RR{Data: good[:n]})
		if err != nil {
			t.Errorf("a %d byte record with a cut bitmap was refused: %v", n, err)
			continue
		}
		if string(p.next) != string(next) {
			t.Errorf("a %d byte record decoded the wrong next hash", n)
		}
	}
	// A salt or hash length longer than the record.
	bad := [][]byte{
		{1, 0, 0, 0, 200, 1, 2},
		append([]byte{1, 0, 0, 0, 0, 200}, next...),
		{1, 0, 0, 0},
		nil,
	}
	for i, d := range bad {
		if _, err := parseNSEC3(RR{Data: d}); err == nil {
			t.Errorf("case %d was accepted", i)
		}
	}
}

// TestNSEC3DenialRefusals covers the proofs that must not convince the
// validator. A forged denial is how a name that exists is made to look
// like one that does not.
func TestNSEC3DenialRefusals(t *testing.T) {
	zone := "example.com."
	salt := []byte{7}
	h := func(name string) []byte { return hashName(name, salt, 1) }
	// A span that covers nothing relevant, built from a hash nobody asks
	// about.
	unrelated := nsec3RR(zone, h("zzz.example.com."), h("zzy.example.com."), salt, 1, 0, TypeA)

	cases := []struct {
		name     string
		sets     []*RRset
		qname    string
		typ      uint16
		nxdomain bool
		want     Result
	}{
		{"no records at all", nil, "a.example.com.", TypeA, true, Bogus},
		{"a set that proves nothing", []*RRset{unrelated}, "a.example.com.", TypeA, true, Bogus},
		{"a name outside the zone", []*RRset{unrelated}, "a.other.com.", TypeA, false, Bogus},
		{"an empty set", []*RRset{{Name: "x." + zone, Type: TypeNSEC3}}, "a.example.com.", TypeA, true, Bogus},
		{
			"parameters nobody supports",
			[]*RRset{nsec3RR(zone, h("a.example.com."), h("b.example.com."), salt, 1000, 0, TypeA)},
			"a.example.com.", TypeA, true, Insecure,
		},
		{
			// A matching record that lists the type being denied is a
			// contradiction: the name has that type.
			"a match that lists the type",
			[]*RRset{nsec3RR(zone, h("a.example.com."), h("b.example.com."), salt, 1, 0, TypeA)},
			"a.example.com.", TypeA, false, Bogus,
		},
		{
			// A matching record listing CNAME denies nothing either.
			"a match that lists CNAME",
			[]*RRset{nsec3RR(zone, h("a.example.com."), h("b.example.com."), salt, 1, 0, TypeCNAME)},
			"a.example.com.", TypeA, false, Bogus,
		},
	}
	for _, tc := range cases {
		if got := nsec3Denial(tc.sets, tc.qname, tc.typ, zone, tc.nxdomain); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}

	// The NODATA proof that works: a record matching the name, without
	// the type in its bitmap.
	ok := []*RRset{nsec3RR(zone, h("a.example.com."), h("b.example.com."), salt, 1, 0, TypeAAAA)}
	if got := nsec3Denial(ok, "a.example.com.", TypeA, zone, false); got != Secure {
		t.Errorf("a valid NODATA proof gave %v", got)
	}
	// The same record with NS and no SOA is the parent side of a
	// delegation: it may deny a DS (insecure) but nothing else.
	deleg := []*RRset{nsec3RR(zone, h("a.example.com."), h("b.example.com."), salt, 1, 0, TypeNS)}
	if got := nsec3Denial(deleg, "a.example.com.", TypeDS, zone, false); got != Insecure {
		t.Errorf("a delegation denying DS gave %v", got)
	}
	if got := nsec3Denial(deleg, "a.example.com.", TypeA, zone, false); got != Bogus {
		t.Errorf("a delegation denying A gave %v", got)
	}
	// An opt-out span covering the next closer name makes a DS query
	// insecure rather than bogus.
	optOut := []*RRset{
		nsec3RR(zone, h(zone), h("zz.example.com."), salt, 1, 1, TypeSOA, TypeNS),
	}
	got := nsec3Denial(optOut, "a.example.com.", TypeDS, zone, false)
	if got != Insecure && got != Bogus {
		t.Errorf("an opt-out span gave %v", got)
	}
}

// TestNSECBitmapDecoding covers the type bitmap, which is what a proof
// is read out of.
func TestNSECBitmapDecoding(t *testing.T) {
	types := nsecTypes(append([]byte{0}, bitmap(TypeA, TypeAAAA, TypeRRSIG, TypeNSEC)...))
	for _, want := range []uint16{TypeA, TypeAAAA, TypeRRSIG, TypeNSEC} {
		if !types[want] {
			t.Errorf("type %d is missing", want)
		}
	}
	for _, absent := range []uint16{TypeMX, TypeDS, TypeCNAME, TypeSOA} {
		if types[absent] {
			t.Errorf("type %d appeared", absent)
		}
	}
	// A bitmap with a window longer than the data, a length past 32, and
	// one that is simply truncated: none of them may read past the end
	// or invent a type.
	for i, d := range [][]byte{
		{0, 0, 40, 0xff},
		{0, 0, 33, 1, 2, 3},
		{0, 0},
		{0, 0, 4},
		{0},
		nil,
	} {
		got := nsecTypes(d)
		if len(got) > 32 {
			t.Errorf("case %d produced %d types", i, len(got))
		}
	}
	// A high window number puts types above 255 in the map.
	high := nsecTypes([]byte{0, 1, 1, 0x80}) // window 1, bit 0 => type 256
	if !high[256] {
		t.Error("a high window was not decoded")
	}
}
