package dns

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// RFC 6052 section 2.2 is a table, and the way to be sure this reads it
// right is the RFC's own worked example: section 2.4 lists 192.0.2.33
// embedded at every defined length, and these are those values, copied
// from it rather than from this implementation.
func TestTheAddressGoesWhereRFC6052Says(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.33")
	for _, tc := range []struct{ prefix, want string }{
		{"64:ff9b::/96", "64:ff9b::c000:221"},
		{"2001:db8::/32", "2001:db8:c000:221::"},
		{"2001:db8:100::/40", "2001:db8:1c0:2:21::"},
		{"2001:db8:122::/48", "2001:db8:122:c000:2:2100::"},
		{"2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"},
		{"2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"},
		{"2001:db8:122:344::/96", "2001:db8:122:344::c000:221"},
	} {
		got, ok := Embed(prefix(tc.prefix), v4)
		if !ok {
			t.Fatalf("%s: refused", tc.prefix)
		}
		if got != netip.MustParseAddr(tc.want) {
			t.Errorf("%s: %s, want %s", tc.prefix, got, tc.want)
		}
		// Octet 8 -- the "u" octet -- must be zero at every length.
		if b := got.As16(); b[8] != 0 {
			t.Errorf("%s: octet 8 is %#x, and RFC 6052 requires zero", tc.prefix, b[8])
		}
	}
	for _, bad := range []struct {
		prefix string
		addr   string
	}{
		{"64:ff9b::/97", "192.0.2.1"},
		{"64:ff9b::/64", "2001:db8::1"},
		{"192.0.2.0/24", "192.0.2.1"},
		{"64:ff9b::/48", ""},
	} {
		addr := netip.Addr{}
		if bad.addr != "" {
			addr = netip.MustParseAddr(bad.addr)
		}
		if _, ok := Embed(prefix(bad.prefix), addr); ok {
			t.Errorf("%s with %q was accepted", bad.prefix, bad.addr)
		}
	}
	// A prefix with bits set past its length cannot smuggle them in. These
	// are in octets 10 and 11, well past a /32, and a /32 writes the
	// address into octets 4 to 7 -- so they would survive into the answer
	// if the prefix were used as given rather than masked.
	got, ok := Embed(netip.PrefixFrom(netip.MustParseAddr("64:ff9b::ff00:0:0"), 32), v4)
	if !ok || got != netip.MustParseAddr("64:ff9b:c000:221::") {
		t.Errorf("a prefix with bits past its length gave %s, want 64:ff9b:c000:221::", got)
	}
	for _, bits := range []int{0, 8, 33, 65, 97, 128} {
		if PrefixLengthOK(bits) {
			t.Errorf("/%d is not a length RFC 6052 defines", bits)
		}
	}
}

// aaaaOf reads the AAAA records of an answer.
func aaaaOf(t *testing.T, resp []byte) []netip.Addr {
	t.Helper()
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	_, qEnd, err := ParseQuestion(resp)
	if err != nil {
		t.Fatal(err)
	}
	var out []netip.Addr
	_ = rrWalk(resp, qEnd, h, func(ttlOff int, typ uint16, _ uint32) {
		if typ != TypeAAAA {
			return
		}
		l := int(binary.BigEndian.Uint16(resp[ttlOff+4:]))
		if l != 16 {
			return
		}
		out = append(out, netip.AddrFrom16([16]byte(resp[ttlOff+6:ttlOff+22])))
	})
	return out
}

func dns64Server(t *testing.T, d *DNS64, answers *AnswerPolicy) *Server {
	t.Helper()
	up := newFakeUpstream(t)
	p := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		DNS64: d, Answers: answers,
	}
	s, _ := startServer(t, p, Hooks{})
	return s
}

// The feature: an IPv6-only client asks for AAAA, the name has only an A
// record, and it gets an address that routes through the translator.
func TestAnIPv4OnlyNameGetsASynthesisedAnswer(t *testing.T) {
	s := dns64Server(t, &DNS64{Prefix: prefix("64:ff9b::/96")}, nil)
	resp := s.Handle(mustQuery(t, 1, "a.example.test", TypeAAAA), addr("2001:db8::1"), true)
	got := aaaaOf(t, resp)
	if len(got) != 1 {
		t.Fatalf("%d AAAA records: %v", len(got), got)
	}
	// The fake upstream answers A with 10.0.0.<len(name)>.
	want, _ := Embed(prefix("64:ff9b::/96"), netip.AddrFrom4([4]byte{10, 0, 0, byte(len("a.example.test"))}))
	if got[0] != want {
		t.Errorf("synthesised %s, want %s", got[0], want)
	}
	h, _ := ParseHeader(resp)
	if h.Rcode() != RcodeNoError {
		t.Errorf("rcode %d", h.Rcode())
	}
	// Nothing about a synthesised answer is signed, so it must not claim
	// to be (RFC 6147 section 5.5).
	if h.Flags&flagAD != 0 {
		t.Error("a synthesised answer carries the AD bit")
	}
	if s.Synthesised.Load() != 1 {
		t.Errorf("%d synthesised", s.Synthesised.Load())
	}
}

// And the three answers it must leave alone.
func TestDNS64LeavesTheRealAnswersAlone(t *testing.T) {
	s := dns64Server(t, &DNS64{Prefix: prefix("64:ff9b::/96")}, nil)
	t.Run("a name that does not exist", func(t *testing.T) {
		resp := s.Handle(mustQuery(t, 2, "nx.example.test", TypeAAAA), addr("2001:db8::1"), true)
		h, _ := ParseHeader(resp)
		if h.Rcode() != RcodeNXDomain {
			t.Errorf("rcode %d, want NXDOMAIN", h.Rcode())
		}
		if got := aaaaOf(t, resp); len(got) != 0 {
			t.Errorf("synthesised %v for a name that does not exist", got)
		}
	})
	t.Run("an A query", func(t *testing.T) {
		resp := s.Handle(mustQuery(t, 3, "a.example.test", TypeA), addr("2001:db8::1"), true)
		_, _, ip := answerIP(t, resp)
		if len(ip) != 4 {
			t.Errorf("an A query got %v", ip)
		}
	})
	t.Run("a name with no addresses at all", func(t *testing.T) {
		// The fake upstream answers other names with an empty NOERROR,
		// so there is no A record to synthesise from.
		resp := s.Handle(mustQuery(t, 4, "empty.test", TypeAAAA), addr("2001:db8::1"), true)
		if got := aaaaOf(t, resp); len(got) != 0 {
			t.Errorf("synthesised %v out of nothing", got)
		}
	})
}

// Only the clients that need it: a dual-stack client handed a synthesised
// address would reach the service the long way round.
func TestOnlyTheNamedClientsGetSynthesis(t *testing.T) {
	s := dns64Server(t, &DNS64{Prefix: prefix("64:ff9b::/96"),
		Clients: []netip.Prefix{prefix("2001:db8:6::/48")}}, nil)
	if got := aaaaOf(t, s.Handle(mustQuery(t, 5, "a.example.test", TypeAAAA), addr("2001:db8:6::1"), true)); len(got) != 1 {
		t.Errorf("a client in the list got %v", got)
	}
	if got := aaaaOf(t, s.Handle(mustQuery(t, 6, "a.example.test", TypeAAAA), addr("2001:db8:9::1"), true)); len(got) != 0 {
		t.Errorf("a client outside the list got %v", got)
	}
}

// The check that makes DNS64 safe to have: the address policy sees the
// IPv4 address before it disappears into a prefix no list would catch.
func TestASynthesisedAddressIsScreenedAsTheIPv4ItIs(t *testing.T) {
	// The fake upstream answers a.example.test with 10.0.0.14, which the
	// policy denies as private. Without screening the *IPv4* address, the
	// answer would come back as 64:ff9b::a00:e -- which is not inside any
	// private range and would sail past a prefix list.
	pol := &AnswerPolicy{Deny: PrivateRanges(), Action: AnswerNXDomain}
	s := dns64Server(t, &DNS64{Prefix: prefix("64:ff9b::/96")}, pol)
	resp := s.Handle(mustQuery(t, 7, "a.example.test", TypeAAAA), addr("2001:db8::1"), true)
	if got := aaaaOf(t, resp); len(got) != 0 {
		t.Fatalf("a private address was synthesised into %v, where no prefix list would find it", got)
	}
	if s.Synthesised.Load() != 0 {
		t.Errorf("%d synthesised", s.Synthesised.Load())
	}
}

// A cached A record is screened too. The main path re-screens a cache hit
// on the way out, because a reload may deny a range an entry was stored
// under; the address this synthesises from has to be screened for the same
// reason, and it is the IPv4 address that is checked -- 64:ff9b::a00:e is
// not inside any private range.
func TestACachedAddressIsScreenedBeforeItIsEmbedded(t *testing.T) {
	up := newFakeUpstream(t)
	open := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Minute, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		DNS64: &DNS64{Prefix: prefix("64:ff9b::/96")},
	}
	s, _ := startServer(t, open, Hooks{})
	// The A record enters the cache while nothing objects to it.
	if _, _, ip := answerIP(t, s.Handle(mustQuery(t, 30, "a.example.test", TypeA), addr("2001:db8::1"), true)); len(ip) != 4 {
		t.Fatalf("the A lookup did not answer: %v", ip)
	}
	// Then the policy narrows, as a reload can.
	narrowed := *open
	narrowed.Answers = &AnswerPolicy{Deny: PrivateRanges(), Action: AnswerNXDomain}
	s.Apply(&narrowed, 100)
	resp := s.Handle(mustQuery(t, 31, "a.example.test", TypeAAAA), addr("2001:db8::1"), true)
	if got := aaaaOf(t, resp); len(got) != 0 {
		t.Fatalf("a cached private address was embedded as %v", got)
	}
}

// The A lookup goes through the cache, so a name already held costs
// nothing upstream, and the answer it stores is the one an A query gets.
func TestTheALookupSharesTheCache(t *testing.T) {
	up := newFakeUpstream(t)
	p := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		DNS64: &DNS64{Prefix: prefix("64:ff9b::/96")},
	}
	s, _ := startServer(t, p, Hooks{})
	// An A query first, which fills the cache.
	s.Handle(mustQuery(t, 8, "a.example.test", TypeA), addr("2001:db8::1"), true)
	before := up.queries.Load()
	// Then the AAAA query: the empty AAAA answer is one upstream query,
	// and the A record it needs comes from the cache rather than a second.
	if got := aaaaOf(t, s.Handle(mustQuery(t, 9, "a.example.test", TypeAAAA), addr("2001:db8::1"), true)); len(got) != 1 {
		t.Fatalf("synthesis: %v", got)
	}
	if after := up.queries.Load(); after-before > 1 {
		t.Errorf("%d upstream queries for the synthesis, want at most 1 (the AAAA)", after-before)
	}
	// And a second AAAA query is answered from the cached empty answer,
	// synthesised again rather than forwarded.
	before = up.queries.Load()
	if got := aaaaOf(t, s.Handle(mustQuery(t, 10, "a.example.test", TypeAAAA), addr("2001:db8::1"), true)); len(got) != 1 {
		t.Errorf("the second time round: %v", got)
	}
	if after := up.queries.Load(); after != before {
		t.Errorf("%d upstream queries for a cached synthesis", after-before)
	}
}

// Only the A records of the answer section are addresses, and the reader
// has to say so by type rather than by the shape of the data: a TXT
// record holding a three-character string has four bytes of rdata, which
// is exactly the length of an address.
func TestOnlyARecordsAreReadAsAddresses(t *testing.T) {
	query := mustQuery(t, 20, "mixed.test", TypeA)
	h, err := ParseHeader(query)
	if err != nil {
		t.Fatal(err)
	}
	_, qEnd, err := ParseQuestion(query)
	if err != nil {
		t.Fatal(err)
	}
	resp := Reply(query, qEnd, h, RcodeNoError)
	rr := func(typ uint16, class uint16, rdata []byte) []byte {
		out := []byte{0xc0, headerLen}
		out = binary.BigEndian.AppendUint16(out, typ)
		out = binary.BigEndian.AppendUint16(out, class)
		out = binary.BigEndian.AppendUint32(out, 60)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
		return append(out, rdata...)
	}
	resp = append(resp, rr(TypeTXT, ClassIN, []byte{3, 'a', 'b', 'c'})...) // four bytes of rdata
	resp = append(resp, rr(TypeA, 3, []byte{10, 0, 0, 1})...)              // class CHAOS, not IN
	resp = append(resp, rr(TypeA, ClassIN, []byte{192, 0, 2, 7})...)       // the only address here
	binary.BigEndian.PutUint16(resp[6:], 3)
	rh, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	got := addressesOf(resp, qEnd, rh)
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("addresses %v, want just 192.0.2.7", got)
	}
}

func TestTheTTLCanBeOverridden(t *testing.T) {
	s := dns64Server(t, &DNS64{Prefix: prefix("64:ff9b::/96"), TTL: 42}, nil)
	resp := s.Handle(mustQuery(t, 11, "a.example.test", TypeAAAA), addr("2001:db8::1"), true)
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	_, qEnd, err := ParseQuestion(resp)
	if err != nil {
		t.Fatal(err)
	}
	var ttls []uint32
	_ = rrWalk(resp, qEnd, h, func(_ int, typ uint16, ttl uint32) {
		if typ == TypeAAAA {
			ttls = append(ttls, ttl)
		}
	})
	if len(ttls) != 1 || ttls[0] != 42 {
		t.Errorf("ttls %v, want [42]", ttls)
	}
}
