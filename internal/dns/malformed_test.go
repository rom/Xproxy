package dns

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// A malformed record must be an error, never a panic: ParseMessage runs on
// the listener's own goroutine, where a panic ends the process rather than
// the query.

// TestNSECRdataShorterThanItsName: RDLENGTH says one byte, the encoded
// next-domain name is three. readNameCase is bounded by the message, not
// by the record, so the name ends past the record and the rdata slice ran
// backwards. One 31-byte UDP datagram used to panic the process.
func TestNSECRdataShorterThanItsName(t *testing.T) {
	raw, err := hex.DecodeString("00000000000100010000000000002f000100002f0001000000000001016100")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMessage(raw); err == nil {
		t.Fatal("a record whose name runs past its rdata was accepted")
	}
}

// TestRRSIGRdataShorterThanItsSigner is the same shape for RRSIG, whose
// signer name sits after 18 fixed bytes.
func TestRRSIGRdataShorterThanItsSigner(t *testing.T) {
	var m []byte
	m = binary.BigEndian.AppendUint16(nil, 0)     // id
	m = binary.BigEndian.AppendUint16(m, 0)       // flags
	m = binary.BigEndian.AppendUint16(m, 1)       // qdcount
	m = binary.BigEndian.AppendUint16(m, 1)       // ancount
	m = binary.BigEndian.AppendUint16(m, 0)       // nscount
	m = binary.BigEndian.AppendUint16(m, 0)       // arcount
	m = append(m, 0)                              // question: root
	m = binary.BigEndian.AppendUint16(m, TypeA)   // qtype
	m = binary.BigEndian.AppendUint16(m, ClassIN) // qclass
	m = append(m, 0)                              // owner: root
	m = binary.BigEndian.AppendUint16(m, TypeRRSIG)
	m = binary.BigEndian.AppendUint16(m, ClassIN)
	m = binary.BigEndian.AppendUint32(m, 0)    // ttl
	m = binary.BigEndian.AppendUint16(m, 19)   // rdlength: 18 fixed + 1
	m = append(m, make([]byte, 18)...)         // fixed part
	m = append(m, 1, 'a', 1, 'b', 0)           // a signer name of 5 bytes
	if _, err := ParseMessage(m); err == nil { //nolint:gofmt // table above
		t.Fatal("an RRSIG whose signer runs past its rdata was accepted")
	}
}

// TestSOANameTooLongToRepack: a name that decompresses beyond the wire
// limit cannot be packed again. The packing error used to be discarded,
// leaving rdata whose name lengths disagreed with its contents, which
// panicked later when the canonical form was built for verification.
func TestSOANameTooLongToRepack(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)
	if len(long) <= 253 {
		t.Fatalf("test name is only %d characters", len(long))
	}
	packed, err := packName(long)
	if err != nil {
		// Too long to pack at all: build it by hand instead, which is what
		// a compressed message can express.
		packed = nil
		for _, label := range strings.Split(long, ".") {
			packed = append(packed, byte(len(label)))
			packed = append(packed, label...)
		}
		packed = append(packed, 0)
	}
	var m []byte
	m = binary.BigEndian.AppendUint16(nil, 0)
	m = binary.BigEndian.AppendUint16(m, 0)
	m = binary.BigEndian.AppendUint16(m, 1)
	m = binary.BigEndian.AppendUint16(m, 1)
	m = binary.BigEndian.AppendUint16(m, 0)
	m = binary.BigEndian.AppendUint16(m, 0)
	m = append(m, 0)
	m = binary.BigEndian.AppendUint16(m, TypeSOA)
	m = binary.BigEndian.AppendUint16(m, ClassIN)
	m = append(m, 0)
	m = binary.BigEndian.AppendUint16(m, TypeSOA)
	m = binary.BigEndian.AppendUint16(m, ClassIN)
	m = binary.BigEndian.AppendUint32(m, 0)
	rdata := append(append([]byte(nil), packed...), packed...)
	rdata = append(rdata, make([]byte, 20)...)
	m = binary.BigEndian.AppendUint16(m, uint16(len(rdata))) //nolint:gosec // bounded by construction
	m = append(m, rdata...)
	// Either a clean parse or a clean error; never a panic, and never
	// rdata that cannot be canonicalised.
	if msg, err := ParseMessage(m); err == nil {
		for _, set := range groupRRsets(msg.Answer) {
			_ = sortedCanonical(set.RRs)
		}
	}
}

// TestEmptyNSEC3SetIsNotIndexed: a lone RRSIG covering NSEC3 groups into
// an RRset with signatures and no records; the NSEC3 helpers must not
// index the missing record.
func TestEmptyNSEC3SetIsNotIndexed(t *testing.T) {
	set := &RRset{Name: "example.test", Type: TypeNSEC3, Class: ClassIN}
	if p, err := nsec3Set(set); err == nil || p != nil {
		t.Fatalf("an empty NSEC3 set parsed: %v %v", p, err)
	}
	if wildcardProven([]*RRset{set}, "www.example.test", "example.test") {
		t.Fatal("an empty NSEC3 set proved a wildcard")
	}
	if got := nsec3Denial([]*RRset{set}, "www.example.test", TypeA, "example.test", true); got != Bogus {
		t.Fatalf("an empty NSEC3 set yielded %v", got)
	}
}
