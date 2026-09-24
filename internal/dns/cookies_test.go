package dns

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// cookieQuery is a query carrying a COOKIE option with the given value.
func cookieQuery(t *testing.T, id uint16, name string, value []byte) []byte {
	t.Helper()
	q := mustQuery(t, id, name, TypeA)
	m, err := ParseMessage(q)
	if err != nil {
		t.Fatal(err)
	}
	rdata := binary.BigEndian.AppendUint16(nil, ednsCookie)
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(value)))
	rdata = append(rdata, value...)
	m.Additional = append(m.Additional, RR{Type: TypeOPT, Class: 4096, Data: rdata})
	out, ok := m.Pack()
	if !ok {
		t.Fatal("pack")
	}
	return out
}

// answerCookie reads the COOKIE option out of a response.
func answerCookie(t *testing.T, resp []byte) []byte {
	t.Helper()
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	_, qEnd, err := ParseQuestion(resp)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	if err := optWalk(resp, qEnd, h, func(code uint16, data []byte) {
		if code == ednsCookie {
			out = data
		}
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func cookiePolicy(up *fakeUpstream, mode string) *Policy {
	return &Policy{Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute,
		Cookies: mode, CookieLifetime: time.Hour}
}

// A client that sends eight bytes of its own gets them back with a
// server cookie behind them, and the query is answered: respond never
// refuses anybody.
func TestAClientThatAsksForACookieGetsOne(t *testing.T) {
	up := newFakeUpstream(t)
	s, addr := startServer(t, cookiePolicy(up, CookiesRespond), Hooks{})
	mine := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	resp := udpQuery(t, addr, cookieQuery(t, 1, "a.example.test", mine))
	if resp == nil {
		t.Fatal("no answer")
	}
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNoError {
		t.Fatalf("rcode %d, want NOERROR: respond must not refuse", h.Rcode())
	}
	got := answerCookie(t, resp)
	if len(got) != 8+serverCookieLen {
		t.Fatalf("cookie is %d bytes, want %d", len(got), 8+serverCookieLen)
	}
	if string(got[:8]) != string(mine) {
		t.Fatalf("client cookie echoed as %x, want %x", got[:8], mine)
	}
	if s.CookiesIssued.Load() != 1 {
		t.Fatalf("issued %d, want 1", s.CookiesIssued.Load())
	}
	// And the answer is still an answer.
	if _, _, ip := answerIP(t, resp); len(ip) != 4 {
		t.Fatalf("no address in the answer: %v", ip)
	}
}

// The cookie the client was handed verifies on the next query, and that
// is what makes a UDP query's source worth believing.
func TestACookieComesBackAndVerifiesTheAddress(t *testing.T) {
	up := newFakeUpstream(t)
	block, err := NewBlockList([]string{"ads.test"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	verified, unverified := 0, 0
	hooks := Hooks{Event: func(_ netip.Addr, reason string, v bool, _ ...any) {
		if reason != "dns_blocked" {
			return
		}
		mu.Lock()
		if v {
			verified++
		} else {
			unverified++
		}
		mu.Unlock()
	}}
	p := cookiePolicy(up, CookiesRespond)
	p.Block = block
	s, addr := startServer(t, p, hooks)

	// A blocked name from a bare datagram is attributed to nobody: the
	// source has proved nothing, and counting it towards a ban would let
	// anybody have a third party banned.
	_ = udpQuery(t, addr, mustQuery(t, 1, "ads.test", TypeA))
	mu.Lock()
	v0, u0 := verified, unverified
	mu.Unlock()
	if v0 != 0 || u0 != 1 {
		t.Fatalf("bare datagram: verified %d unverified %d, want 0 and 1", v0, u0)
	}

	// Collect a cookie, then send it back with the same blocked name.
	resp := udpQuery(t, addr, cookieQuery(t, 2, "a.example.test", []byte{9, 9, 9, 9, 9, 9, 9, 9}))
	cookie := answerCookie(t, resp)
	if len(cookie) != 8+serverCookieLen {
		t.Fatalf("no usable cookie: %x", cookie)
	}
	_ = udpQuery(t, addr, cookieQuery(t, 3, "ads.test", cookie))
	mu.Lock()
	v1, u1 := verified, unverified
	mu.Unlock()
	if v1 != 1 || u1 != 1 {
		t.Fatalf("with a cookie: verified %d unverified %d, want 1 and 1", v1, u1)
	}
	if s.CookiesVerified.Load() != 1 {
		t.Fatalf("verified count %d, want 1", s.CookiesVerified.Load())
	}
}

// A cookie is proof that the holder can receive at the address it was
// issued to, so one replayed from somewhere else must not verify. The
// address is in the hash for exactly this.
func TestACookieDoesNotVerifyAnotherAddress(t *testing.T) {
	jar, err := newCookieJar(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mine := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	now := time.Now()
	issued := jar.issue(netip.MustParseAddr("192.0.2.1"), mine, now)
	if ok, _ := jar.verify(netip.MustParseAddr("192.0.2.1"), issued, now); !ok {
		t.Fatal("a cookie did not verify for the address it was issued to")
	}
	if ok, _ := jar.verify(netip.MustParseAddr("192.0.2.2"), issued, now); ok {
		t.Fatal("a cookie verified for an address it was not issued to")
	}
	// A cookie past its lifetime, and one from the future.
	if ok, _ := jar.verify(netip.MustParseAddr("192.0.2.1"), issued, now.Add(2*time.Hour)); ok {
		t.Fatal("an expired cookie verified")
	}
	if ok, _ := jar.verify(netip.MustParseAddr("192.0.2.1"), issued, now.Add(-time.Hour)); ok {
		t.Fatal("a cookie from the future verified")
	}
	// Half way through its life it still verifies and asks to be renewed.
	ok, old := jar.verify(netip.MustParseAddr("192.0.2.1"), issued, now.Add(40*time.Minute))
	if !ok || !old {
		t.Fatalf("at 40 minutes: ok=%v old=%v, want true and true", ok, old)
	}
	// Any byte changed and it stops verifying.
	for i := range issued {
		bad := append([]byte(nil), issued...)
		bad[i] ^= 0x80
		if ok, _ := jar.verify(netip.MustParseAddr("192.0.2.1"), bad, now); ok {
			t.Fatalf("a cookie with byte %d altered still verified", i)
		}
	}
	// Another server's cookie, of a length this one does not issue, is
	// not an error: the client is simply unverified.
	if ok, _ := jar.verify(netip.MustParseAddr("192.0.2.1"), append(mine, make([]byte, 32)...), now); ok {
		t.Fatal("a 40 byte cookie of unknown layout verified")
	}
	// A secret of its own per jar: one listener's cookie is not
	// another's.
	other, err := newCookieJar(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := other.verify(netip.MustParseAddr("192.0.2.1"), issued, now); ok {
		t.Fatal("a cookie issued by one listener verified at another")
	}
}

// require is the amplification defence: the first datagram buys nothing
// but the cookie to come back with, and the retry works.
func TestRequireAnswersBadcookieAndThenTheQuery(t *testing.T) {
	up := newFakeUpstream(t)
	s, addr := startServer(t, cookiePolicy(up, CookiesRequire), Hooks{})
	before := up.queries.Load()
	resp := udpQuery(t, addr, cookieQuery(t, 1, "a.example.test", []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	if resp == nil {
		t.Fatal("no answer")
	}
	// Rcode 23 does not fit in the header: RFC 6891 keeps the low four
	// bits there and the high eight in the OPT record, so both halves are
	// asserted. A client that does not understand extended rcodes sees
	// the nibble and one that does reassembles 23.
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeBadCookie&0xf {
		t.Fatalf("header rcode %d, want %d", h.Rcode(), RcodeBadCookie&0xf)
	}
	if got := ExtendedRcode(resp); got != RcodeBadCookie {
		t.Fatalf("extended rcode %d, want BADCOOKIE (%d)", got, RcodeBadCookie)
	}
	if up.queries.Load() != before {
		t.Fatal("the upstream was asked for a query that had proved nothing")
	}
	cookie := answerCookie(t, resp)
	if len(cookie) != 8+serverCookieLen {
		t.Fatalf("BADCOOKIE carried no cookie to retry with: %x", cookie)
	}
	// The retry, with what it was given.
	resp = udpQuery(t, addr, cookieQuery(t, 2, "a.example.test", cookie))
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNoError {
		t.Fatalf("retry rcode %d, want NOERROR", h.Rcode())
	}
	if _, _, ip := answerIP(t, resp); len(ip) != 4 {
		t.Fatal("the retry was not answered")
	}
	if s.CookiesRefused.Load() != 1 {
		t.Fatalf("refused %d, want 1", s.CookiesRefused.Load())
	}
}

// A client with no cookie at all has nothing to echo, so there is no
// retry to invite: it is refused, and that is the cost of require.
func TestRequireRefusesAClientWithNoCookieAtAll(t *testing.T) {
	up := newFakeUpstream(t)
	s, addr := startServer(t, cookiePolicy(up, CookiesRequire), Hooks{})
	resp := udpQuery(t, addr, mustQuery(t, 1, "a.example.test", TypeA))
	if resp == nil {
		t.Fatal("no answer")
	}
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeRefused {
		t.Fatalf("rcode %d, want REFUSED", h.Rcode())
	}
	if s.CookiesRefused.Load() != 1 {
		t.Fatalf("refused %d, want 1", s.CookiesRefused.Load())
	}
	// The same client over TCP is answered: the handshake is the proof a
	// cookie exists to provide (RFC 7873 section 5.2.3).
	resp = tcpQuery(t, addr, mustQuery(t, 2, "a.example.test", TypeA))
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNoError {
		t.Fatalf("tcp rcode %d, want NOERROR: a stream needs no cookie", h.Rcode())
	}
}

// RFC 7873 section 5.2.2: a COOKIE option of a length the protocol does
// not allow is a format error, not something to guess at.
func TestACookieOfTheWrongLengthIsAFormatError(t *testing.T) {
	up := newFakeUpstream(t)
	_, addr := startServer(t, cookiePolicy(up, CookiesRespond), Hooks{})
	for _, n := range []int{1, 7, 9, 15, 41, 64} {
		resp := udpQuery(t, addr, cookieQuery(t, uint16(n), "a.example.test", make([]byte, n)))
		if resp == nil {
			t.Fatalf("%d bytes: no answer", n)
		}
		if h, _ := ParseHeader(resp); h.Rcode() != RcodeFormErr {
			t.Errorf("%d bytes: rcode %d, want FORMERR", n, h.Rcode())
		}
	}
	// And the lengths the protocol does allow are answered.
	for _, n := range []int{8, 16, 24, 40} {
		resp := udpQuery(t, addr, cookieQuery(t, uint16(100+n), "a.example.test", make([]byte, n)))
		if resp == nil {
			t.Fatalf("%d bytes: no answer", n)
		}
		if h, _ := ParseHeader(resp); h.Rcode() != RcodeNoError {
			t.Errorf("%d bytes: rcode %d, want NOERROR", n, h.Rcode())
		}
	}
}

// off means off: no cookie in the answer, and no refusals.
func TestCookiesOffLeavesTheAnswerAlone(t *testing.T) {
	up := newFakeUpstream(t)
	s, addr := startServer(t, cookiePolicy(up, CookiesOff), Hooks{})
	resp := udpQuery(t, addr, cookieQuery(t, 1, "a.example.test", []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	if resp == nil {
		t.Fatal("no answer")
	}
	if got := answerCookie(t, resp); got != nil {
		t.Fatalf("a cookie was returned with cookies off: %x", got)
	}
	if s.CookiesIssued.Load() != 0 {
		t.Fatal("a cookie was issued with cookies off")
	}
}

// The cookie goes into the response's own OPT record rather than beside
// it, and the options that were already there survive.
func TestAddingACookieKeepsTheRestOfTheOptRecord(t *testing.T) {
	q := mustQuery(t, 1, "a.test", TypeA)
	m, err := ParseMessage(q)
	if err != nil {
		t.Fatal(err)
	}
	var rdata []byte
	add := func(code uint16, data []byte) {
		rdata = binary.BigEndian.AppendUint16(rdata, code)
		rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(data)))
		rdata = append(rdata, data...)
	}
	add(12, make([]byte, 4))                       // padding
	add(ednsCookie, make([]byte, 8))               // an old cookie, to be replaced
	add(ednsECS, []byte{0, 1, 24, 0, 203, 0, 113}) // a client subnet
	m.Additional = append(m.Additional, RR{Type: TypeOPT, Class: 4096, Data: rdata})
	full, ok := m.Pack()
	if !ok {
		t.Fatal("pack")
	}
	fresh := make([]byte, 24)
	for i := range fresh {
		fresh[i] = byte(i + 1)
	}
	out := AddCookie(full, fresh)
	h := mustHeader(out)
	seen := map[uint16]int{}
	var cookie []byte
	if err := optWalk(out, questionEnd(t, out), h, func(code uint16, data []byte) {
		seen[code]++
		if code == ednsCookie {
			cookie = data
		}
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	if seen[ednsCookie] != 1 {
		t.Fatalf("cookie options in the answer: %d, want exactly one", seen[ednsCookie])
	}
	if string(cookie) != string(fresh) {
		t.Fatalf("cookie %x, want %x", cookie, fresh)
	}
	if seen[12] != 1 || seen[ednsECS] != 1 {
		t.Errorf("other options lost: %v", seen)
	}
	// A response with no OPT record at all gets one, since RFC 6891 says
	// a response to an EDNS query must carry it.
	bare := Reply(q, questionEnd(t, q), mustHeader(q), RcodeNXDomain)
	out = AddCookie(bare, fresh)
	seen = map[uint16]int{}
	if err := optWalk(out, questionEnd(t, out), mustHeader(out), func(code uint16, _ []byte) { seen[code]++ }); err != nil {
		t.Fatalf("walk: %v", err)
	}
	if seen[ednsCookie] != 1 {
		t.Fatalf("a bare reply did not gain an OPT record with the cookie: %v", seen)
	}
}
