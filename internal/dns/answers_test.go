package dns

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// scripted is an upstream that answers the addresses a test names, so
// the screen can be pointed at an answer rather than at a name.
type scripted struct {
	udp net.PacketConn
	mu  sync.Mutex
	// answers maps a query name to the addresses it resolves to.
	answers map[string][]string
	// seen counts queries and subnet records whether any carried a
	// client subnet option.
	seen   int
	subnet bool
}

func newScripted(t *testing.T, answers map[string][]string) *scripted {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &scripted{udp: udp, answers: answers}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := u.answer(buf[:n]); resp != nil {
				_, _ = udp.WriteTo(resp, from)
			}
		}
	}()
	t.Cleanup(func() { _ = udp.Close() })
	return u
}

func (u *scripted) addr() string { return u.udp.LocalAddr().String() }

func (u *scripted) counts() (queries int, sawECS bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.seen, u.subnet
}

func (u *scripted) answer(query []byte) []byte {
	h, err := ParseHeader(query)
	if err != nil {
		return nil
	}
	q, qEnd, err := ParseQuestion(query)
	if err != nil {
		return nil
	}
	u.mu.Lock()
	u.seen++
	if HasECS(query, qEnd, h) {
		u.subnet = true
	}
	list := u.answers[q.Name]
	u.mu.Unlock()
	if len(list) == 0 {
		return Reply(query, qEnd, h, RcodeNXDomain)
	}
	m := &Message{Header: Header{ID: h.ID, Flags: flagQR | flagRD | flagRA}, Question: q}
	for _, a := range list {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		rr := RR{Name: q.Name, Class: ClassIN, TTL: 300}
		if addr.Is4() {
			b := addr.As4()
			rr.Type, rr.Data = TypeA, b[:]
		} else {
			b := addr.As16()
			rr.Type, rr.Data = TypeAAAA, b[:]
		}
		m.Answer = append(m.Answer, rr)
	}
	out, ok := m.Pack()
	if !ok {
		return Reply(query, qEnd, h, RcodeServFail)
	}
	return out
}

// screenPolicy is a listener with an answer policy and nothing else.
func screenPolicy(up *scripted, a *AnswerPolicy) *Policy {
	return &Policy{Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Minute, Answers: a}
}

// answered reads the addresses out of a response.
func answered(t *testing.T, resp []byte) []netip.Addr {
	t.Helper()
	m, err := ParseMessage(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	var out []netip.Addr
	for _, rr := range m.Answer {
		if a, ok := rdataAddr(rr.Type, rr.Class, rr.Data); ok {
			out = append(out, a)
		}
	}
	return out
}

// A name is what an attacker picks last. The block list cannot express
// "this name may not resolve to my loopback interface", because there is
// nothing wrong with the name: rebinding is a good name answering
// 127.0.0.1 one query after answering a public address, and the browser
// keeps calling the two one origin.
//
// The companion assertion matters as much as the refusal: a screen that
// refuses everything is not a screen. A public address is answered.
func TestAnAnswerIntoLoopbackIsRefused(t *testing.T) {
	up := newScripted(t, map[string][]string{
		"rebind.test": {"127.0.0.1"},
		"honest.test": {"93.184.216.34"},
	})
	var mu sync.Mutex
	reasons := map[string]int{}
	events := 0
	hooks := Hooks{
		Refuse: func(r string) { mu.Lock(); reasons[r]++; mu.Unlock() },
		Event: func(_ netip.Addr, reason string, _ bool, _ ...any) {
			mu.Lock()
			if reason == "dns_answer_denied" {
				events++
			}
			mu.Unlock()
		},
	}
	s, addr := startServer(t, screenPolicy(up, &AnswerPolicy{Deny: PrivateRanges()}), hooks)

	resp := udpQuery(t, addr, mustQuery(t, 1, "rebind.test", TypeA))
	if resp == nil {
		t.Fatal("no answer")
	}
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNXDomain {
		t.Fatalf("rcode %d, want NXDOMAIN", h.Rcode())
	}
	if got := answered(t, resp); len(got) != 0 {
		t.Fatalf("the loopback address was still handed over: %v", got)
	}
	if s.AnswerDenied.Load() != 1 {
		t.Fatalf("answer_denied counted %d, want 1", s.AnswerDenied.Load())
	}
	mu.Lock()
	r, e := reasons["answer_denied"], events
	mu.Unlock()
	if r != 1 {
		t.Errorf("refusal reason counted %d, want 1 (have %v)", r, reasons)
	}
	if e != 1 {
		t.Errorf("security events %d, want 1", e)
	}

	// The same policy, a public address: answered.
	resp = udpQuery(t, addr, mustQuery(t, 2, "honest.test", TypeA))
	got := answered(t, resp)
	if len(got) != 1 || got[0].String() != "93.184.216.34" {
		t.Fatalf("a public address was not answered: %v", got)
	}
}

// 169.254.169.254 serves instance credentials to any process that can
// make an HTTP request, so a name resolving there turns "fetch this URL
// for me" into "read my keys". It is inside the link-local range
// deny_private stands for, and refuse says so to the client rather than
// pretending the name does not exist.
func TestTheMetadataEndpointIsNotAName(t *testing.T) {
	up := newScripted(t, map[string][]string{"metadata.test": {"169.254.169.254"}})
	s, addr := startServer(t, screenPolicy(up, &AnswerPolicy{Deny: PrivateRanges(), Action: AnswerRefuse}), Hooks{})
	resp := udpQuery(t, addr, mustQuery(t, 1, "metadata.test", TypeA))
	if resp == nil {
		t.Fatal("no answer")
	}
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeRefused {
		t.Fatalf("rcode %d, want REFUSED", h.Rcode())
	}
	if s.AnswerDenied.Load() != 1 {
		t.Fatalf("answer_denied counted %d", s.AnswerDenied.Load())
	}
}

// ::ffff:127.0.0.1 is 127.0.0.1 to every socket API and is not inside
// ::1/128, so a v6 deny list that names loopback the obvious way misses
// it. Screening unmaps first.
func TestAMappedAddressIsTheAddressItMaps(t *testing.T) {
	up := newScripted(t, map[string][]string{"mapped.test": {"::ffff:127.0.0.1"}})
	s, addr := startServer(t, screenPolicy(up, &AnswerPolicy{Deny: PrivateRanges()}), Hooks{})
	resp := udpQuery(t, addr, mustQuery(t, 1, "mapped.test", TypeAAAA))
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNXDomain {
		t.Fatalf("rcode %d, want NXDOMAIN", h.Rcode())
	}
	if s.AnswerDenied.Load() != 1 {
		t.Fatal("a mapped loopback address passed the screen")
	}
}

// A name may legitimately have a public address and an internal one --
// a split-horizon zone seen from the wrong side, an appliance that
// publishes its management address beside its service address. Refusing
// the whole answer takes away the address that works; strip takes away
// the one that does not.
func TestStripKeepsTheAddressThatWorks(t *testing.T) {
	up := newScripted(t, map[string][]string{"both.test": {"93.184.216.34", "10.1.2.3"}})
	s, addr := startServer(t, screenPolicy(up, &AnswerPolicy{Deny: PrivateRanges(), Action: AnswerStrip}), Hooks{})
	resp := udpQuery(t, addr, mustQuery(t, 1, "both.test", TypeA))
	if resp == nil {
		t.Fatal("no answer")
	}
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNoError {
		t.Fatalf("rcode %d, want NOERROR", h.Rcode())
	}
	got := answered(t, resp)
	if len(got) != 1 || got[0].String() != "93.184.216.34" {
		t.Fatalf("addresses %v, want only the public one", got)
	}
	if s.AnswerStripped.Load() != 1 || s.AnswerDenied.Load() != 0 {
		t.Fatalf("stripped %d denied %d, want 1 and 0", s.AnswerStripped.Load(), s.AnswerDenied.Load())
	}
	// And the cache keeps what the client was given, not what the
	// upstream said: a second query must not produce the address the
	// first one had removed.
	resp = udpQuery(t, addr, mustQuery(t, 2, "both.test", TypeA))
	if got := answered(t, resp); len(got) != 1 || got[0].String() != "93.184.216.34" {
		t.Fatalf("second answer %v, want only the public address", got)
	}
	if s.Hits.Load() != 1 {
		t.Fatalf("cache hits %d, want 1 (the stripped answer should be the cached one)", s.Hits.Load())
	}
}

// An internal zone really does resolve into private space, and a proxy
// that could not say so would be a proxy nobody turns this on in.
func TestAnExemptedNameMayPointInside(t *testing.T) {
	up := newScripted(t, map[string][]string{
		"db.internal.test":  {"10.1.2.3"},
		"other.public.test": {"10.1.2.4"},
	})
	exempt, err := NewBlockList([]string{"internal.test"})
	if err != nil {
		t.Fatal(err)
	}
	s, addr := startServer(t, screenPolicy(up, &AnswerPolicy{Deny: PrivateRanges(), Exempt: exempt}), Hooks{})
	if got := answered(t, udpQuery(t, addr, mustQuery(t, 1, "db.internal.test", TypeA))); len(got) != 1 {
		t.Fatalf("an exempted name was screened: %v", got)
	}
	if got := answered(t, udpQuery(t, addr, mustQuery(t, 2, "other.public.test", TypeA))); len(got) != 0 {
		t.Fatalf("a name outside the exemption was answered: %v", got)
	}
	if s.AnswerDenied.Load() != 1 {
		t.Fatalf("answer_denied counted %d, want 1", s.AnswerDenied.Load())
	}
}

// deny_private is a starting point, not a verdict: the network running
// this proxy has its own ranges, and naming them in allow is how an
// operator says so without enumerating what is left of RFC 6890.
func TestAllowCarvesOutOfTheDeniedSet(t *testing.T) {
	up := newScripted(t, map[string][]string{"ours.test": {"10.1.2.3"}, "theirs.test": {"10.9.9.9"}})
	a := &AnswerPolicy{Deny: PrivateRanges(), Allow: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}}
	_, addr := startServer(t, screenPolicy(up, a), Hooks{})
	if got := answered(t, udpQuery(t, addr, mustQuery(t, 1, "ours.test", TypeA))); len(got) != 1 {
		t.Fatalf("an allowed range was screened: %v", got)
	}
	if got := answered(t, udpQuery(t, addr, mustQuery(t, 2, "theirs.test", TypeA))); len(got) != 0 {
		t.Fatalf("a denied range was answered: %v", got)
	}
}

// A refused answer must not become a cached one. The cache is shared by
// every client of the listener, so an answer this listener will not
// serve is an answer it must not store: otherwise the screen is a thing
// that happens once and the next thousand clients get the address.
func TestADeniedAnswerIsNotCached(t *testing.T) {
	up := newScripted(t, map[string][]string{"rebind.test": {"127.0.0.1"}})
	s, addr := startServer(t, screenPolicy(up, &AnswerPolicy{Deny: PrivateRanges()}), Hooks{})
	for i := 0; i < 3; i++ {
		_ = udpQuery(t, addr, mustQuery(t, uint16(i+1), "rebind.test", TypeA))
	}
	if s.cache.Len() != 0 {
		t.Fatalf("cache holds %d entries, want none", s.cache.Len())
	}
	if q, _ := up.counts(); q != 3 {
		t.Fatalf("upstream saw %d queries, want 3 (a denied answer must not be served from the cache)", q)
	}
	if s.Hits.Load() != 0 {
		t.Fatalf("cache hits %d, want 0", s.Hits.Load())
	}
}

// The screen runs on the way out as well as on the way in, because a
// reload can deny a range that an entry already in the cache points
// into. An entry the new policy refuses must not outlive it.
func TestAReloadScreensWhatWasAlreadyCached(t *testing.T) {
	up := newScripted(t, map[string][]string{"late.test": {"10.1.2.3"}})
	open := screenPolicy(up, nil)
	s, addr := startServer(t, open, Hooks{})
	if got := answered(t, udpQuery(t, addr, mustQuery(t, 1, "late.test", TypeA))); len(got) != 1 {
		t.Fatalf("no answer to cache: %v", got)
	}
	if s.cache.Len() != 1 {
		t.Fatal("the answer was not cached")
	}
	closed := *open
	closed.Answers = &AnswerPolicy{Deny: PrivateRanges()}
	s.Apply(&closed, 100)
	resp := udpQuery(t, addr, mustQuery(t, 2, "late.test", TypeA))
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNXDomain {
		t.Fatalf("rcode %d, want NXDOMAIN: the cached answer survived the reload", h.Rcode())
	}
	if s.cache.Len() != 0 {
		t.Fatalf("cache holds %d entries, want none: the refused entry was kept", s.cache.Len())
	}
}

// withECS adds a client subnet option to a query.
func withECS(t *testing.T, query []byte) []byte {
	t.Helper()
	m, err := ParseMessage(query)
	if err != nil {
		t.Fatal(err)
	}
	// family 1 (IPv4), source prefix 24, scope 0, then the prefix bytes.
	opt := []byte{0, 1, 24, 0, 203, 0, 113}
	rdata := []byte{0, ednsECS}
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(opt)))
	rdata = append(rdata, opt...)
	m.Additional = append(m.Additional, RR{Type: TypeOPT, Class: 4096, Data: rdata})
	out, ok := m.Pack()
	if !ok {
		t.Fatal("pack")
	}
	return out
}

// The cache here is keyed by the question and nothing else, as it is in
// every forwarder of this shape. An answer tailored to one client's
// subnet would therefore be stored for every client of the listener, so
// a client that chooses the subnet chooses what the next thousand are
// told -- cache poisoning with no spoofing and no race in it. The option
// does not go upstream unless an operator says it may.
func TestTheClientSubnetDoesNotGoUpstream(t *testing.T) {
	up := newScripted(t, map[string][]string{"ecs.test": {"93.184.216.34"}})
	p := screenPolicy(up, nil)
	s, addr := startServer(t, p, Hooks{})
	q := withECS(t, mustQuery(t, 1, "ecs.test", TypeA))
	if !HasECS(q, questionEnd(t, q), mustHeader(q)) {
		t.Fatal("the test query carries no client subnet")
	}
	if got := answered(t, udpQuery(t, addr, q)); len(got) != 1 {
		t.Fatalf("no answer: %v", got)
	}
	if _, saw := up.counts(); saw {
		t.Fatal("the client's subnet reached the upstream")
	}
	if s.ECSStripped.Load() != 1 {
		t.Fatalf("ecs_stripped counted %d, want 1", s.ECSStripped.Load())
	}

	// forward is for the deployment whose clients are one network, and
	// it means what it says.
	fwd := *p
	fwd.ECS = ECSForward
	s.Apply(&fwd, 100)
	s.Purge()
	if got := answered(t, udpQuery(t, addr, withECS(t, mustQuery(t, 2, "ecs.test", TypeA)))); len(got) != 1 {
		t.Fatalf("no answer with forward: %v", got)
	}
	if _, saw := up.counts(); !saw {
		t.Fatal("forward did not forward the client's subnet")
	}
}

func questionEnd(t *testing.T, b []byte) int {
	t.Helper()
	_, end, err := ParseQuestion(b)
	if err != nil {
		t.Fatal(err)
	}
	return end
}

// The option is removed without disturbing the rest of the OPT record:
// a cookie or a padding option a client sent alongside it still reaches
// the upstream, because dropping the record wholesale would be a
// different query than the one the client asked.
func TestStrippingTheSubnetKeepsTheOtherOptions(t *testing.T) {
	q := mustQuery(t, 1, "keep.test", TypeA)
	m, err := ParseMessage(q)
	if err != nil {
		t.Fatal(err)
	}
	var rdata []byte
	appendOpt := func(code uint16, data []byte) {
		rdata = binary.BigEndian.AppendUint16(rdata, code)
		rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(data)))
		rdata = append(rdata, data...)
	}
	appendOpt(10, []byte{1, 2, 3, 4, 5, 6, 7, 8}) // a cookie
	appendOpt(ednsECS, []byte{0, 1, 24, 0, 203, 0, 113})
	appendOpt(12, make([]byte, 4)) // padding
	m.Additional = append(m.Additional, RR{Type: TypeOPT, Class: 4096, Data: rdata})
	full, ok := m.Pack()
	if !ok {
		t.Fatal("pack")
	}
	out := StripECS(full)
	h := mustHeader(out)
	seen := map[uint16]int{}
	if err := optWalk(out, questionEnd(t, out), h, func(code uint16, _ []byte) { seen[code]++ }); err != nil {
		t.Fatalf("walk: %v", err)
	}
	if seen[ednsECS] != 0 {
		t.Error("the client subnet survived")
	}
	if seen[10] != 1 || seen[12] != 1 {
		t.Errorf("other options lost: %v", seen)
	}
}

// A malformed OPT record is left alone rather than rebuilt into
// something the client did not send.
func TestAMalformedOptionRecordIsLeftAsItIs(t *testing.T) {
	rdata := []byte{0, ednsECS, 0, 40, 1, 2} // a length past the rdata
	out, dropped := dropOption(rdata, ednsECS)
	if dropped || len(out) != len(rdata) {
		t.Fatalf("dropped=%v len=%d, want the record unchanged", dropped, len(out))
	}
}

// Every range deny_private names must actually parse and actually deny
// the addresses it is there for.
func TestThePrivateRangesCoverWhatTheyClaim(t *testing.T) {
	a := &AnswerPolicy{Deny: PrivateRanges()}
	for _, s := range []string{"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.168.1.1", "198.18.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:10.0.0.1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1"} {
		if !a.Denies(netip.MustParseAddr(s)) {
			t.Errorf("%s is not denied", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111", "2001:4860:4860::8888"} {
		if a.Denies(netip.MustParseAddr(s)) {
			t.Errorf("%s is denied and should not be", s)
		}
	}
	// A policy with nothing in it denies nothing, and a nil one is not
	// a panic.
	var none *AnswerPolicy
	if none.Denies(netip.MustParseAddr("127.0.0.1")) {
		t.Error("a nil policy denied an address")
	}
	if (&AnswerPolicy{}).Denies(netip.MustParseAddr("127.0.0.1")) {
		t.Error("an empty policy denied an address")
	}
}
