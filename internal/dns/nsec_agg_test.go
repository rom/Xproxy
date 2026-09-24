package dns

import (
	"testing"
	"time"
)

// nsecWithTTL is the package's own NSEC builder with a TTL this test
// chooses, since the lifetime of a proof is part of what is being checked.
func nsecWithTTL(owner, next string, ttl uint32) RR {
	rr := nsecRR(owner, next, TypeA)
	rr.TTL = ttl
	return rr
}

// denialOf builds a validated NXDOMAIN message for a name, proved by the
// gaps given as owner/next pairs.
func denialOf(t *testing.T, name string, ttl uint32, pairs ...[2]string) (Question, *Message) {
	t.Helper()
	q := Question{Name: name, Type: TypeA, Class: ClassIN}
	m := &Message{Question: q}
	h := Header{}
	h.Flags = 0x8000 | uint16(RcodeNXDomain) // a response, NXDOMAIN
	m.Header = h
	for _, p := range pairs {
		m.Authority = append(m.Authority, nsecWithTTL(p[0], p[1], ttl))
	}
	return q, m
}

// The feature: one validated proof answers every sibling in its gap, which
// is exactly the shape of a random-subdomain flood.
func TestOneProofAnswersEverySiblingInTheGap(t *testing.T) {
	now := time.Now()
	d := NewDenials(16)
	q, m := denialOf(t, "aaa.example.test", 300, [2]string{"a.example.test", "b.example.test"})
	d.Learn(q, m, now, time.Hour)
	if d.Len() != 1 {
		t.Fatalf("%d proofs held", d.Len())
	}
	for _, name := range []string{"aaa.example.test", "ab.example.test", "annn.example.test"} {
		if !d.Covers(Question{Name: name, Type: TypeA, Class: ClassIN}, now) {
			t.Errorf("%q is in the gap and was not covered", name)
		}
	}
	// A different type of the same name is covered too: NXDOMAIN is about
	// the name, not the type.
	if !d.Covers(Question{Name: "ab.example.test", Type: TypeMX, Class: ClassIN}, now) {
		t.Error("another type of a name in the gap was not covered")
	}
	if d.Hits == 0 {
		t.Error("no hits counted")
	}
}

// And everything it must not answer.
func TestAProofIsNotStretchedPastWhatItProves(t *testing.T) {
	now := time.Now()
	d := NewDenials(16)
	q, m := denialOf(t, "aaa.example.test", 300, [2]string{"a.example.test", "b.example.test"})
	d.Learn(q, m, now, time.Hour)
	for _, tc := range []struct{ name, why string }{
		{"a.example.test", "the gap's own owner exists"},
		{"b.example.test", "the gap's next name exists"},
		{"c.example.test", "outside the gap"},
		{"aaa.other.test", "another parent, so another closest encloser and another wildcard"},
		{"deep.aaa.example.test", "a child, whose parent is not the one the proof covers"},
		{"example.test", "the parent itself"},
	} {
		if d.Covers(Question{Name: tc.name, Type: TypeA, Class: ClassIN}, now) {
			t.Errorf("%q was covered, though %s", tc.name, tc.why)
		}
	}
	// And nothing at all once the proof has expired.
	if d.Covers(Question{Name: "ab.example.test", Type: TypeA, Class: ClassIN}, now.Add(301*time.Second)) {
		t.Error("an expired proof still answered")
	}
	if d.Len() != 0 {
		t.Errorf("the expired proof is still held: %d", d.Len())
	}
}

// The wrapping gap: the last NSEC of a zone names the apex as its next
// name, so it sorts before the owner and covers everything after it.
func TestTheWrappingGapCoversTheEndOfTheZone(t *testing.T) {
	now := time.Now()
	d := NewDenials(16)
	q, m := denialOf(t, "zzz.example.test", 300, [2]string{"z.example.test", "example.test"})
	d.Learn(q, m, now, time.Hour)
	for _, name := range []string{"zzz.example.test", "zz9.example.test"} {
		if !d.Covers(Question{Name: name, Type: TypeA, Class: ClassIN}, now) {
			t.Errorf("%q after the last owner was not covered", name)
		}
	}
	if d.Covers(Question{Name: "m.example.test", Type: TypeA, Class: ClassIN}, now) {
		t.Error("a name before the last owner was covered by the wrapping gap")
	}
}

// Canonical order is by label from the right, which is not string order:
// the store has to use the DNSSEC comparison or it covers the wrong names.
func TestTheGapIsComparedInCanonicalOrder(t *testing.T) {
	now := time.Now()
	d := NewDenials(16)
	// In canonical order the labels of one parent sort as plain octets, so
	// "z" > "b"; in string order "b.example.test" < "z.example.test" too.
	// The case that separates them is upper case, which canonical order
	// folds: "B" must sort where "b" does.
	q, m := denialOf(t, "c.example.test", 300, [2]string{"B.example.test", "d.example.test"})
	d.Learn(q, m, now, time.Hour)
	if !d.Covers(Question{Name: "c.example.test", Type: TypeA, Class: ClassIN}, now) {
		t.Error("a name inside a gap whose owner is upper case was not covered")
	}
	if d.Covers(Question{Name: "a.example.test", Type: TypeA, Class: ClassIN}, now) {
		t.Error("a name before the folded owner was covered")
	}
}

// Nothing is learned from an answer this resolver has not validated, or
// from one that is not a denial at all.
func TestOnlyAValidatedDenialIsLearned(t *testing.T) {
	now := time.Now()
	d := NewDenials(16)
	// A NOERROR answer proves nothing about other names.
	q := Question{Name: "aaa.example.test", Type: TypeA, Class: ClassIN}
	m := &Message{Question: q, Header: Header{Flags: 0x8000}}
	m.Authority = append(m.Authority, nsecWithTTL("a.example.test", "b.example.test", 300))
	d.Learn(q, m, now, time.Hour)
	if d.Len() != 0 {
		t.Error("a NOERROR answer was learned as a denial")
	}
	// An NXDOMAIN with no NSEC records is an unsigned zone's denial: true
	// for the name asked and nothing more.
	q2, m2 := denialOf(t, "aaa.example.test", 300)
	d.Learn(q2, m2, now, time.Hour)
	if d.Len() != 0 {
		t.Error("a denial with no NSEC records was learned")
	}
	// A TTL of zero says do not remember this.
	q3, m3 := denialOf(t, "aaa.example.test", 0, [2]string{"a.example.test", "b.example.test"})
	d.Learn(q3, m3, now, time.Hour)
	if d.Len() != 0 {
		t.Error("a proof with a zero TTL was learned")
	}
	// Another class is another namespace.
	q4, m4 := denialOf(t, "aaa.example.test", 300, [2]string{"a.example.test", "b.example.test"})
	q4.Class = 3
	d.Learn(q4, m4, now, time.Hour)
	if d.Len() != 0 {
		t.Error("a denial in another class was learned")
	}
}

// Only the NSEC records of the authority section are gaps. The authority
// of a real denial also carries the SOA and the signatures over
// everything, and reading an RRSIG's rdata as a name produces a gap that
// covers whatever it happens to compare against.
func TestOnlyNSECRecordsBecomeGaps(t *testing.T) {
	now := time.Now()
	d := NewDenials(4)
	q := Question{Name: "aaa.example.test", Type: TypeA, Class: ClassIN}
	m := &Message{Question: q, Header: Header{Flags: 0x8000 | uint16(RcodeNXDomain)}}
	m.Authority = append(m.Authority,
		soaRR("example.test"),
		nsecWithTTL("a.example.test", "b.example.test", 300),
		RR{Name: "example.test", Type: TypeRRSIG, Class: ClassIN, TTL: 300, Data: make([]byte, 40)},
	)
	d.Learn(q, m, now, time.Hour)
	e := d.byParent["example.test"]
	if e == nil {
		t.Fatal("nothing learned")
	}
	if len(e.gaps) != 1 {
		t.Fatalf("%d gaps learned from one NSEC record: %+v", len(e.gaps), e.gaps)
	}
	if e.gaps[0].owner != "a.example.test" || e.gaps[0].next != "b.example.test" {
		t.Errorf("gap %+v", e.gaps[0])
	}
}

// The store is bounded, and the bound drops the least recently useful
// proof rather than refusing to learn.
func TestTheDenialStoreIsBounded(t *testing.T) {
	now := time.Now()
	d := NewDenials(4)
	for i := range 20 {
		name := string(rune('a'+i)) + ".zone" + string(rune('a'+i)) + ".test"
		q, m := denialOf(t, name, 300, [2]string{"a.zone" + string(rune('a'+i)) + ".test", "z.zone" + string(rune('a'+i)) + ".test"})
		d.Learn(q, m, now, time.Hour)
	}
	if d.Len() > 4 {
		t.Errorf("%d proofs held, over the bound of 4", d.Len())
	}
	// The most recent is still there.
	if !d.Covers(Question{Name: "b.zonet.test", Type: TypeA, Class: ClassIN}, now) {
		t.Error("the most recently learned proof was evicted")
	}
}

// The TTL is capped by the resolver's own maximum, so a signer cannot make
// this resolver hold a denial for a week.
func TestTheProofLifetimeIsCapped(t *testing.T) {
	now := time.Now()
	d := NewDenials(4)
	q, m := denialOf(t, "aaa.example.test", 604800, [2]string{"a.example.test", "b.example.test"})
	d.Learn(q, m, now, time.Minute)
	if !d.Covers(Question{Name: "ab.example.test", Type: TypeA, Class: ClassIN}, now.Add(30*time.Second)) {
		t.Error("inside the cap and not covered")
	}
	if d.Covers(Question{Name: "ab.example.test", Type: TypeA, Class: ClassIN}, now.Add(2*time.Minute)) {
		t.Error("a week-long NSEC TTL outlived the resolver's own maximum")
	}
}

// A nil store answers nothing and holds nothing, which is what the feature
// being off has to mean.
func TestOffMeansNothingIsRememberedOrAnswered(t *testing.T) {
	var d *Denials
	q, m := denialOf(t, "aaa.example.test", 300, [2]string{"a.example.test", "b.example.test"})
	d.Learn(q, m, time.Now(), time.Hour)
	if d.Covers(q, time.Now()) || d.Len() != 0 {
		t.Error("a store that is off answered or held something")
	}
}

// And the name it was asked about is not special: the root's children are
// siblings of each other, which is the junk-top-level-query case.
func TestJunkTopLevelNamesShareOneProof(t *testing.T) {
	now := time.Now()
	d := NewDenials(4)
	q, m := denialOf(t, "qwertyx", 300, [2]string{"qw", "r"})
	d.Learn(q, m, now, time.Hour)
	if !d.Covers(Question{Name: "qwertyz", Type: TypeA, Class: ClassIN}, now) {
		t.Error("another junk top-level name was not covered")
	}
	if d.Covers(Question{Name: "example.test", Type: TypeA, Class: ClassIN}, now) {
		t.Error("a two-label name was covered by a root proof")
	}
}

func TestTheNextNameMustBeReadable(t *testing.T) {
	now := time.Now()
	d := NewDenials(4)
	q := Question{Name: "aaa.example.test", Type: TypeA, Class: ClassIN}
	h := Header{Flags: 0x8000 | uint16(RcodeNXDomain)}
	m := &Message{Question: q, Header: h}
	// A length byte promising more than the rdata holds.
	m.Authority = append(m.Authority, RR{Name: "a.example.test", Type: TypeNSEC, Class: ClassIN, TTL: 300,
		Data: []byte{40, 'x'}})
	d.Learn(q, m, now, time.Hour)
	if d.Len() != 0 {
		t.Error("a proof whose next name does not parse was learned")
	}
}

// End to end: a validated NXDOMAIN answers the next query for a sibling
// without an upstream lookup, which is the whole point of RFC 8198. This
// is driven through the signed hierarchy the DNSSEC tests use, so the
// proof is a real one that a real validator accepted.
func TestASiblingIsAnsweredWithoutAskingAgain(t *testing.T) {
	up, v, _ := buildHierarchy(t)
	p := &Policy{
		Resolver: NewResolver([]string{up.udp.LocalAddr().String()}, 2*time.Second),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		DNSSEC: v, Denials: NewDenials(16),
	}
	s, _ := startServer(t, p, Hooks{})
	client := addr("198.51.100.9")

	// nope.test does not exist, and the upstream proves it with the NSEC
	// covering the gap from n3.test to *.wild.test.
	resp := s.Handle(mustQuery(t, 1, "nope.test", TypeA), client, true)
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.Rcode() != RcodeNXDomain {
		t.Fatalf("rcode %d, want NXDOMAIN", h.Rcode())
	}
	if p.Denials.Len() != 1 {
		t.Fatalf("%d proofs learned from a validated denial", p.Denials.Len())
	}
	// A sibling in the same gap: answered from the proof, with nothing
	// asked upstream. Without the store this name would reach the
	// upstream, which answers an unsigned NXDOMAIN the validator calls
	// bogus -- so a SERVFAIL here is the feature not working.
	before := up.queries.Load()
	resp = s.Handle(mustQuery(t, 2, "nothere.test", TypeA), client, true)
	h, err = ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.Rcode() != RcodeNXDomain {
		t.Fatalf("the sibling got rcode %d, want NXDOMAIN", h.Rcode())
	}
	if after := up.queries.Load(); after != before {
		t.Errorf("%d upstream queries for a name the proof already covered", after-before)
	}
	if s.NSECDenied.Load() != 1 {
		t.Errorf("%d answers counted as taken from a proof", s.NSECDenied.Load())
	}
	// An insecure zone's denial is not a proof: the names in it were
	// never signed, so nothing about other names follows from it.
	up.set("gone.insecure.test/A", answer{rcode: RcodeNXDomain,
		authority: []RR{nsecWithTTL("a.insecure.test", "z.insecure.test", 300)}})
	held := p.Denials.Len()
	if resp := s.Handle(mustQuery(t, 4, "gone.insecure.test", TypeA), client, true); len(resp) == 0 {
		t.Fatal("no answer from the insecure zone")
	}
	if p.Denials.Len() != held {
		t.Error("an unvalidated denial was learned as a proof")
	}
	// A client that asked for signatures gets the upstream lookup, since
	// a synthesised NXDOMAIN carries none.
	before = up.queries.Load()
	if resp := s.Handle(withDO(mustQuery(t, 3, "nothing.test", TypeA)), client, true); len(resp) == 0 {
		t.Fatal("no answer for a DO query")
	}
	if after := up.queries.Load(); after == before {
		t.Error("a client that set DO was answered from a proof with no signatures in it")
	}
}

// A purge means every answer: a gap left behind would deny a name the
// cache no longer has anything to say about.
func TestAPurgeDropsTheHeldProofs(t *testing.T) {
	now := time.Now()
	p := &Policy{Denials: NewDenials(16)}
	s, _ := startServer(t, p, Hooks{})
	q, m := denialOf(t, "aaa.example.test", 300, [2]string{"a.example.test", "b.example.test"})
	p.Denials.Learn(q, m, now, time.Hour)
	if p.Denials.Len() != 1 {
		t.Fatalf("the proof was not learned: %d", p.Denials.Len())
	}
	if n := s.Purge(); n != 1 {
		t.Errorf("purge reported %d entries, want the one proof", n)
	}
	if p.Denials.Len() != 0 {
		t.Error("a proof survived the purge")
	}
	if s.Status().DenialsHeld != 0 {
		t.Error("the status still reports a held proof")
	}
}
