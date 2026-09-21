package dns

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// Name compression is the oldest hostile input in DNS: a pointer that
// goes forwards, a pointer that points at itself, a chain that never
// ends, a name that expands to more than a name can hold. These tests
// drive the decoder directly, because a message that gets past it is a
// message the rest of the resolver trusts.

// msgWith builds a message body with a header in front, so offsets in
// the test line up with the ones the decoder sees.
func msgWith(body ...byte) []byte {
	return append(make([]byte, headerLen), body...)
}

func TestReadNameCompression(t *testing.T) {
	// "www.example.test." written out, then a pointer back to it.
	plain := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0}
	b := msgWith(plain...)
	ptr := len(b)
	b = binary.BigEndian.AppendUint16(b, 0xc000|uint16(headerLen)) //nolint:gosec // test offset

	name, n, err := readName(b, headerLen)
	if err != nil || name != "www.example.test" || n != headerLen+len(plain) {
		t.Fatalf("plain name: %q %d %v", name, n, err)
	}
	name, n, err = readName(b, ptr)
	if err != nil || name != "www.example.test" || n != ptr+2 {
		t.Fatalf("compressed name: %q %d %v", name, n, err)
	}
	// The case-preserving reader agrees on the value and the offset.
	for _, keep := range []bool{false, true} {
		got, gn, err := readNameCase(b, ptr, keep)
		if err != nil || got != name || gn != n {
			t.Errorf("readNameCase(keepCase=%v): %q %d %v", keep, got, gn, err)
		}
	}
	// Case is preserved only when asked for, and folded otherwise: one
	// spelling per name is what keeps a cache from holding two entries
	// for one record.
	mixed := msgWith(3, 'W', 'W', 'w', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'E', 's', 't', 0)
	lower, _, err := readNameCase(mixed, headerLen, false)
	if err != nil {
		t.Fatal(err)
	}
	upper, _, err := readNameCase(mixed, headerLen, true)
	if err != nil {
		t.Fatal(err)
	}
	if lower != "www.example.test" {
		t.Errorf("folded name %q", lower)
	}
	if upper != "WWw.Example.tEst" {
		t.Errorf("preserved name %q", upper)
	}
}

func TestReadNameRefusals(t *testing.T) {
	// A pointer to itself, a pointer forwards, a pointer into the
	// header, a chain of pointers, a label with the reserved bits set,
	// a label longer than 63, a name longer than 255 and a truncated
	// name. None may loop, and none may return a name.
	selfPtr := msgWith(0xc0, byte(headerLen))
	forward := msgWith(0xc0, byte(headerLen+4), 0, 0, 1, 'a', 0)
	intoHeader := msgWith(0xc0, 0x00)
	reserved := msgWith(0x80, 1, 'a', 0)
	truncated := msgWith(3, 'w', 'w')
	noRoot := msgWith(1, 'a')
	// A chain of pointers, each naming the one before it, longer than
	// the hop bound: following it costs nothing per hop, so only the
	// bound stops it.
	chain := msgWith(1, 'a', 0) // a real name to land on at the end
	prev := headerLen
	for i := 0; i < 40; i++ {
		at := len(chain)
		chain = binary.BigEndian.AppendUint16(chain, 0xc000|uint16(prev)) //nolint:gosec // test offset
		prev = at
	}
	// A name of 300 bytes in labels of 60.
	var long []byte
	for i := 0; i < 6; i++ {
		long = append(long, 60)
		long = append(long, bytes.Repeat([]byte{'a'}, 60)...)
	}
	long = append(long, 0)
	tooLong := msgWith(long...)
	// A label of 64 bytes, one past the maximum.
	bigLabel := msgWith(append(append([]byte{64}, bytes.Repeat([]byte{'a'}, 64)...), 0)...)

	cases := map[string][]byte{
		"a pointer to itself":       selfPtr,
		"a pointer forwards":        forward,
		"a pointer into the header": intoHeader,
		"reserved label bits":       reserved,
		"a truncated label":         truncated,
		"a name with no root":       noRoot,
		"a chain of pointers":       chain,
		"a name of 300 bytes":       tooLong,
		"a label of 64 bytes":       bigLabel,
		"nothing at all":            nil,
	}
	for name, b := range cases {
		off := headerLen
		if len(b) <= headerLen {
			off = 0
		}
		if name == "a chain of pointers" {
			off = len(b) - 2 // the last pointer of the chain
		}
		for _, keep := range []bool{false, true} {
			got, _, err := readNameCase(b, off, keep)
			if err == nil {
				t.Errorf("%s (keepCase=%v) parsed as %q", name, keep, got)
			}
		}
	}
	// A pointer at the very end of the buffer has no second byte.
	if _, _, err := readNameCase(append(msgWith(), 0xc0), headerLen, true); err == nil {
		t.Error("a pointer with one byte was read")
	}
	// An offset past the buffer.
	if _, _, err := readNameCase(msgWith(0), 1000, true); err == nil {
		t.Error("an offset past the buffer was read")
	}
}

// TestDecompressRData covers the types whose rdata carries names,
// because a name inside rdata is a name an attacker chooses the
// encoding of.
func TestDecompressRData(t *testing.T) {
	// A message holding "target.test." at a known offset, then records
	// whose rdata points at it.
	target := []byte{6, 't', 'a', 'r', 'g', 'e', 't', 4, 't', 'e', 's', 't', 0}
	base := msgWith(target...)
	ptr := func() []byte {
		return binary.BigEndian.AppendUint16(nil, 0xc000|uint16(headerLen)) //nolint:gosec // test offset
	}
	cases := []struct {
		name  string
		typ   uint16
		rdata []byte
	}{
		{"CNAME", TypeCNAME, ptr()},
		{"NS", TypeNS, ptr()},
		{"PTR", TypePTR, ptr()},
		{"DNAME", TypeDNAME, ptr()},
		{"MX", TypeMX, append([]byte{0, 10}, ptr()...)},
		{"SRV", TypeSRV, append([]byte{0, 1, 0, 2, 0, 80}, ptr()...)},
	}
	for _, tc := range cases {
		b := append(append([]byte{}, base...), tc.rdata...)
		got, err := decompressRData(b, len(base), len(tc.rdata), tc.typ)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !bytes.Contains(got, target) {
			t.Errorf("%s: the name was not expanded: %x", tc.name, got)
		}
		// The expansion is longer than the pointer, so a decoder that
		// kept the compressed form would be caught here.
		if len(got) <= len(tc.rdata) {
			t.Errorf("%s: rdata did not grow: %d bytes", tc.name, len(got))
		}
		// Truncated rdata of the same type is refused.
		if _, err := decompressRData(b, len(base), len(tc.rdata)-1, tc.typ); err == nil {
			t.Errorf("%s: truncated rdata was accepted", tc.name)
		}
		// A pointer naming itself is refused: a decoder that follows it
		// never returns.
		at := len(base) + len(tc.rdata) - 2
		loop := append(append([]byte{}, tc.rdata[:len(tc.rdata)-2]...), 0xc0, byte(at))
		lb := append(append([]byte{}, base...), loop...)
		if _, err := decompressRData(lb, len(base), len(loop), tc.typ); err == nil {
			t.Errorf("%s: a self-referential pointer was accepted", tc.name)
		}
	}

	// SOA: two names and twenty bytes of counters.
	soaRData := append(append(ptr(), ptr()...), make([]byte, 20)...)
	b := append(append([]byte{}, base...), soaRData...)
	got, err := decompressRData(b, len(base), len(soaRData), TypeSOA)
	if err != nil {
		t.Fatalf("SOA: %v", err)
	}
	if bytes.Count(got, target) != 2 || len(got) != 2*len(target)+20 {
		t.Fatalf("SOA rdata: %d bytes, %d names", len(got), bytes.Count(got, target))
	}
	// One byte fewer of counters is malformed, not a shorter SOA.
	if _, err := decompressRData(b, len(base), len(soaRData)-1, TypeSOA); err == nil {
		t.Error("a SOA with nineteen bytes of counters was accepted")
	}

	// A type with no names in its rdata is copied as it stands, pointer
	// bytes and all: expanding them would change data the zone signed.
	raw := []byte{0xc0, byte(headerLen), 1, 2, 3}
	b = append(append([]byte{}, base...), raw...)
	got, err = decompressRData(b, len(base), len(raw), TypeTXT)
	if err != nil || !bytes.Equal(got, raw) {
		t.Errorf("TXT rdata: %x (%v)", got, err)
	}
	// The copy is a copy: writing to it must not reach the message.
	got[0] = 0xff
	if b[len(base)] != 0xc0 {
		t.Error("the decoder returned a slice of the message")
	}
}

// TestCanonicalRDataExact covers the lower casing that goes into a
// signature: too little and a valid signature fails, too much and a
// counter changes underneath it.
func TestCanonicalRDataExact(t *testing.T) {
	name := []byte{6, 'T', 'a', 'R', 'g', 'E', 't', 4, 'T', 'e', 's', 'T', 0}
	lower := []byte{6, 't', 'a', 'r', 'g', 'e', 't', 4, 't', 'e', 's', 't', 0}
	for _, typ := range []uint16{TypeNS, TypeCNAME, TypePTR, TypeDNAME} {
		if got := canonicalRDataExact(typ, name); !bytes.Equal(got, lower) {
			t.Errorf("type %d: %x", typ, got)
		}
	}
	// MX and SRV keep their counters. 0x41 and 0x5a inside a counter are
	// 'A' and 'Z': lowering them would change the number.
	mx := append([]byte{0x41, 0x5a}, name...)
	got := canonicalRDataExact(TypeMX, mx)
	if !bytes.Equal(got[:2], []byte{0x41, 0x5a}) {
		t.Errorf("MX preference was changed: %x", got[:2])
	}
	if !bytes.Equal(got[2:], lower) {
		t.Errorf("MX name: %x", got[2:])
	}
	srv := append([]byte{0x41, 0x5a, 0x41, 0x5a, 0x41, 0x5a}, name...)
	got = canonicalRDataExact(TypeSRV, srv)
	if !bytes.Equal(got[:6], srv[:6]) {
		t.Errorf("SRV counters were changed: %x", got[:6])
	}
	// SOA: both names are lowered, the twenty bytes of counters are not.
	counters := bytes.Repeat([]byte{0x41}, 20)
	soa := append(append(append([]byte{}, name...), name...), counters...)
	got = canonicalRDataExact(TypeSOA, soa)
	if !bytes.Equal(got[len(got)-20:], counters) {
		t.Errorf("SOA counters were changed: %x", got[len(got)-20:])
	}
	if bytes.Count(got, lower) != 2 {
		t.Errorf("SOA names were not lowered: %x", got)
	}
	// A type with no names is returned unchanged, including one that
	// looks like a name.
	txt := append([]byte{}, name...)
	if got := canonicalRDataExact(TypeTXT, txt); !bytes.Equal(got, name) {
		t.Errorf("TXT rdata was changed: %x", got)
	}
	// Rdata shorter than the fixed part of its type must not panic.
	for _, typ := range []uint16{TypeMX, TypeSRV, TypeSOA, TypeNS} {
		for n := 0; n <= 6; n++ {
			_ = canonicalRDataExact(typ, make([]byte, n))
		}
		_ = canonicalRDataExact(typ, nil)
	}
}

// TestLabelsOf covers the split the denial proofs walk.
func TestLabelsOf(t *testing.T) {
	cases := map[string]int{
		"":                     0,
		".":                    2, // the root: an empty label either side of the dot
		"example.com.":         3,
		"a.b.c.d.example.com.": 7,
	}
	for name, want := range cases {
		if got := labelsOf(name); len(got) != want {
			t.Errorf("labelsOf(%q) = %v", name, got)
		}
	}
	// The join of the tail of the labels is the parent name, which is
	// what the closest encloser proof relies on.
	labels := labelsOf("a.b.example.com.")
	if got := strings.Join(labels[1:], "."); got != "b.example.com." {
		t.Errorf("parent %q", got)
	}
	if got := strings.Join(labels[len(labels)-1:], "."); got != "" {
		t.Errorf("root %q", got)
	}
}

// TestSkipName covers the walker that steps over a name without
// decoding it, which is what the section parser uses to find the next
// record.
func TestSkipName(t *testing.T) {
	plain := []byte{3, 'w', 'w', 'w', 4, 't', 'e', 's', 't', 0}
	b := msgWith(plain...)
	if n, err := skipName(b, headerLen); err != nil || n != headerLen+len(plain) {
		t.Fatalf("plain: %d %v", n, err)
	}
	// A pointer takes two bytes however long the name it names is.
	withPtr := binary.BigEndian.AppendUint16(append([]byte{}, b...), 0xc000|uint16(headerLen)) //nolint:gosec // test offset
	if n, err := skipName(withPtr, len(b)); err != nil || n != len(b)+2 {
		t.Fatalf("pointer: %d %v", n, err)
	}
	for name, in := range map[string][]byte{
		"empty":                   nil,
		"a truncated label":       msgWith(3, 'w'),
		"no root":                 msgWith(1, 'a'),
		"reserved bits":           msgWith(0x40, 1),
		"a pointer with one byte": append(msgWith(), 0xc0),
	} {
		off := headerLen
		if len(in) <= headerLen {
			off = 0
		}
		if _, err := skipName(in, off); err == nil {
			t.Errorf("%s was skipped without an error", name)
		}
	}
}
