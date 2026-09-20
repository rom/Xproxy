package dns

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// A client that sets CD is asking to see an answer this node would
// refuse: "give me the data, I will check it myself". The shared cache
// keys on (name, type, class) alone — nothing about CD, DO or the
// validation result — and the hit path never re-validates, so storing
// that answer handed every later client of the listener a record with no
// DNSSEC behind it, for the whole TTL, from one query and one bit.
func TestCheckingDisabledDoesNotPoisonTheSharedCache(t *testing.T) {
	u, v, _ := buildHierarchy(t)
	policy := &Policy{
		Resolver: u.v.resolver, DNSSEC: v,
		MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
	}
	s, addr := startServer(t, policy, Hooks{})

	// bad.test carries a signature that does not verify.
	honest := udpQuery(t, addr, mustQuery(t, 1, "bad.test", TypeA))
	if h, _ := ParseHeader(honest); h.Rcode() != RcodeServFail {
		t.Fatalf("an answer that does not verify was served: %+v", h)
	}
	if n := s.cache.Len(); n != 0 {
		t.Fatalf("a bogus answer was cached: %d entries", n)
	}
	// The attacker's own query, with CD set, gets the data — and must
	// leave nothing behind.
	q := mustQuery(t, 2, "bad.test", TypeA)
	binary.BigEndian.PutUint16(q[2:], binary.BigEndian.Uint16(q[2:])|flagCD)
	_ = udpQuery(t, addr, q)
	if n := s.cache.Len(); n != 0 {
		t.Fatalf("a query with CD installed %d cache entries for everybody else", n)
	}
	// The next honest client still gets SERVFAIL, from the upstream.
	before := s.Hits.Load()
	again := udpQuery(t, addr, mustQuery(t, 3, "bad.test", TypeA))
	if h, _ := ParseHeader(again); h.Rcode() != RcodeServFail || s.Hits.Load() != before {
		t.Fatalf("a later client was served the unvalidated answer: %+v hits %d", h, s.Hits.Load()-before)
	}
}

// A message of compression pointers weighs a few bytes per record on the
// wire and expands to a 255-byte name plus a decompressed rdata name.
// With validation on, both ParseMessage and Pack run on the client's own
// query, so a 4 KB datagram turned into megabytes of allocation.
func TestMessageExpansionIsBounded(t *testing.T) {
	// A 255-byte question name, then records of [ptr to it] CNAME with a
	// two-byte rdata pointer: fourteen wire bytes for 510 expanded.
	q := mustQuery(t, 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddd", TypeA)
	msg := append([]byte(nil), q...)
	n := 0
	for len(msg) < 4000 {
		msg = append(msg, 0xc0, 0x0c)
		msg = binary.BigEndian.AppendUint16(msg, TypeCNAME)
		msg = binary.BigEndian.AppendUint16(msg, ClassIN)
		msg = binary.BigEndian.AppendUint32(msg, 0)
		msg = binary.BigEndian.AppendUint16(msg, 2)
		msg = append(msg, 0xc0, 0x0c)
		n++
	}
	binary.BigEndian.PutUint16(msg[6:], uint16(n)) //nolint:gosec // bounded by the loop
	if _, err := ParseMessage(msg); !errors.Is(err, errExpansion) {
		t.Fatalf("a %d-byte message of pointers parsed with %v", len(msg), err)
	}
	// withDO falls back to the query it was given rather than packing the
	// expansion, and the result is still a message the upstream can read.
	out := withDO(msg)
	if len(out) != len(msg) {
		t.Fatalf("withDO packed the expansion: %d bytes from %d", len(out), len(msg))
	}
}

// Pack has a ceiling: a message that would pass MaxMessage is refused
// rather than built, because no transport here could send it.
func TestPackRefusesAMessagePastTheWireLimit(t *testing.T) {
	m := &Message{Header: Header{ID: 1}, Question: Question{Name: "a.test", Type: TypeA, Class: ClassIN}}
	for i := 0; i < 200; i++ {
		m.Answer = append(m.Answer, RR{Name: "a.test", Type: TypeTXT, Class: ClassIN, Data: make([]byte, 255)})
	}
	if _, ok := m.Pack(); !ok {
		t.Fatal("a message well inside the limit was refused")
	}
	for i := 0; i < 1000; i++ {
		m.Answer = append(m.Answer, RR{Name: "a.test", Type: TypeTXT, Class: ClassIN, Data: make([]byte, 255)})
	}
	if _, ok := m.Pack(); ok {
		t.Fatal("a message past MaxMessage was packed")
	}
}

// A FORMERR reply carries no question, so it must not claim one: a
// message that says QDCount=1 and stops after the header is one this
// package's own parser refuses.
func TestFormErrReplyHasNoQuestionCount(t *testing.T) {
	q := mustQuery(t, 7, "a.test", TypeA)
	h, _ := ParseHeader(q)
	out := Reply(q[:headerLen], headerLen, h, RcodeFormErr)
	if got := binary.BigEndian.Uint16(out[4:]); got != 0 {
		t.Fatalf("question count %d in a reply with no question", got)
	}
	full := Reply(q, len(q), h, RcodeNoError)
	if got := binary.BigEndian.Uint16(full[4:]); got != 1 {
		t.Fatalf("question count %d in a reply that echoes the question", got)
	}
}

// The forwarded query carries the client's own OPT record, so without a
// clamp the client decides how large an answer the upstream may send
// while exchangeUDP can only read one buffer; the kernel then chops the
// datagram with no error at all.
func TestForwardedEDNSSizeIsClamped(t *testing.T) {
	q := withDO(mustQuery(t, 1, "a.test", TypeA))
	binary.BigEndian.PutUint16(q[len(q)-8:], 65535) // the OPT class field is the payload size
	h, _ := ParseHeader(q)
	_, qEnd, err := ParseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	ClampEDNSSize(q, qEnd, h, udpReadBuffer-1)
	if got := binary.BigEndian.Uint16(q[len(q)-8:]); got != udpReadBuffer-1 {
		t.Fatalf("advertised payload size %d", got)
	}
	// A size already below the clamp is left alone.
	binary.BigEndian.PutUint16(q[len(q)-8:], 1232)
	ClampEDNSSize(q, qEnd, h, udpReadBuffer-1)
	if got := binary.BigEndian.Uint16(q[len(q)-8:]); got != 1232 {
		t.Fatalf("a small advertised size was raised to %d", got)
	}
}
