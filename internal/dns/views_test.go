package dns

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// firstRR returns the type and data of the first answer record.
func firstRR(t *testing.T, resp []byte) (uint16, []byte) {
	t.Helper()
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	_, qEnd, err := ParseQuestion(resp)
	if err != nil {
		t.Fatal(err)
	}
	var typ uint16
	var data []byte
	first := true
	_ = rrWalk(resp, qEnd, h, func(ttlOff int, ty uint16, _ uint32) {
		if !first {
			return
		}
		first = false
		l := int(binary.BigEndian.Uint16(resp[ttlOff+4:]))
		typ, data = ty, resp[ttlOff+6:ttlOff+6+l]
	})
	return typ, data
}

func answerCount(t *testing.T, resp []byte) int {
	t.Helper()
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	return int(h.ANCount)
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// localSet builds a record set for a name.
func localSet(recs ...LocalRecord) *LocalRecords { return NewLocalRecords(recs) }

// The reason views exist: one name, two answers, decided by who asked.
func TestAViewAnswersItsOwnClientsDifferently(t *testing.T) {
	up := newFakeUpstream(t)
	p := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		Local: localSet(LocalRecord{Name: "app.test", Type: TypeA, TTL: 60, Addr: addr("203.0.113.9")}),
		Views: []*View{{
			Name:    "internal",
			Clients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			Local:   localSet(LocalRecord{Name: "app.test", Type: TypeA, TTL: 60, Addr: addr("10.0.5.10")}),
		}},
	}
	s, _ := startServer(t, p, Hooks{})
	q := mustQuery(t, 1, "app.test", TypeA)

	inside := s.Handle(q, addr("10.1.2.3"), true)
	if _, _, ip := answerIP(t, inside); len(ip) != 4 || ip[0] != 10 || ip[3] != 10 {
		t.Errorf("a client inside the view got %v, want 10.0.5.10", ip)
	}
	outside := s.Handle(q, addr("198.51.100.7"), true)
	if _, _, ip := answerIP(t, outside); len(ip) != 4 || ip[0] != 203 {
		t.Errorf("a client outside the view got %v, want 203.0.113.9", ip)
	}
	// And the cache is not the way one answer reaches the other client:
	// a local answer is never cached, so the order of the two queries
	// cannot matter. Asked again, in the other order.
	if _, _, ip := answerIP(t, s.Handle(q, addr("198.51.100.7"), true)); len(ip) != 4 || ip[0] != 203 {
		t.Errorf("the second time round, the outside client got %v", ip)
	}
	if _, _, ip := answerIP(t, s.Handle(q, addr("10.1.2.3"), true)); len(ip) != 4 || ip[0] != 10 {
		t.Errorf("the second time round, the inside client got %v", ip)
	}
	if got := s.Viewed.Load(); got != 2 {
		t.Errorf("%d queries counted as viewed, want 2", got)
	}
}

func TestAViewsBlockListAppliesToItsClientsOnly(t *testing.T) {
	up := newFakeUpstream(t)
	guest, err := NewBlockList([]string{"social.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		BlockAction: "nxdomain",
		Views: []*View{{
			Name:    "guest",
			Clients: []netip.Prefix{netip.MustParsePrefix("192.168.9.0/24")},
			Block:   guest,
			Action:  "sinkhole", Sinkhole4: []byte{192, 0, 2, 1},
		}},
	}
	s, _ := startServer(t, p, Hooks{})
	q := mustQuery(t, 2, "social.example.test", TypeA)

	// The guest network is sinkholed, with the view's own address.
	resp := s.Handle(q, addr("192.168.9.5"), true)
	h, _, ip := answerIP(t, resp)
	if h.Rcode() != RcodeNoError || len(ip) != 4 || ip[0] != 192 || ip[3] != 1 {
		t.Errorf("a guest got rcode %d ip %v, want the sinkhole 192.0.2.1", h.Rcode(), ip)
	}
	// Staff are not in the view, so the name resolves.
	resp = s.Handle(q, addr("10.0.0.9"), true)
	if h, _, ip := answerIP(t, resp); h.Rcode() != RcodeNoError || len(ip) != 4 || ip[0] != 10 {
		t.Errorf("staff got rcode %d ip %v, want the upstream answer", h.Rcode(), ip)
	}
}

// A view's block action and its addresses belong together: a list from the
// view with the action from the listener is a policy nobody wrote.
func TestAViewTakesTheListenersSinkholeUnlessItNamesItsOwn(t *testing.T) {
	up := newFakeUpstream(t)
	list, _ := NewBlockList([]string{"ads.test"})
	p := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		BlockAction: "nxdomain", Sinkhole4: []byte{0, 0, 0, 0},
		Views: []*View{{
			Name:    "lab",
			Clients: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")},
			Block:   list, Action: "sinkhole",
		}},
	}
	s, _ := startServer(t, p, Hooks{})
	resp := s.Handle(mustQuery(t, 3, "ads.test", TypeA), addr("10.9.1.1"), true)
	h, _, ip := answerIP(t, resp)
	if h.Rcode() != RcodeNoError || len(ip) != 4 || ip[0] != 0 {
		t.Errorf("rcode %d ip %v, want the listener's 0.0.0.0", h.Rcode(), ip)
	}
}

func TestTheFirstMatchingViewWins(t *testing.T) {
	up := newFakeUpstream(t)
	p := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		Views: []*View{
			{Name: "lab", Clients: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")},
				Local: localSet(LocalRecord{Name: "app.test", Type: TypeA, TTL: 60, Addr: addr("10.9.9.9")})},
			{Name: "estate", Clients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
				Local: localSet(LocalRecord{Name: "app.test", Type: TypeA, TTL: 60, Addr: addr("10.0.0.1")})},
		},
	}
	s, _ := startServer(t, p, Hooks{})
	q := mustQuery(t, 4, "app.test", TypeA)
	// A laboratory client is inside both; the first view is the answer.
	if _, _, ip := answerIP(t, s.Handle(q, addr("10.9.1.1"), true)); len(ip) != 4 || ip[1] != 9 {
		t.Errorf("the laboratory client got %v, want 10.9.9.9", ip)
	}
	if _, _, ip := answerIP(t, s.Handle(q, addr("10.1.1.1"), true)); len(ip) != 4 || ip[3] != 1 {
		t.Errorf("an estate client got %v, want 10.0.0.1", ip)
	}
}

func TestTheViewIsInTheAccessLog(t *testing.T) {
	up := newFakeUpstream(t)
	var mu sync.Mutex
	var lines []string
	p := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second, LogQueries: true,
		Views: []*View{{Name: "internal", Clients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			Local: localSet(LocalRecord{Name: "app.test", Type: TypeA, TTL: 60, Addr: addr("10.0.5.10")})}},
	}
	s, _ := startServer(t, p, Hooks{Access: func(attrs ...any) {
		var sb strings.Builder
		for _, a := range attrs {
			sb.WriteString(" ")
			switch v := a.(type) {
			case string:
				sb.WriteString(v)
			default:
				sb.WriteString("?")
			}
		}
		mu.Lock()
		lines = append(lines, sb.String())
		mu.Unlock()
	}})
	s.Handle(mustQuery(t, 5, "app.test", TypeA), addr("10.1.2.3"), true)
	s.Handle(mustQuery(t, 6, "other.test", TypeA), addr("198.51.100.7"), true)
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 2 {
		t.Fatalf("%d access lines", len(lines))
	}
	if !strings.Contains(lines[0], "view internal") {
		t.Errorf("the view is not in the line: %q", lines[0])
	}
	if strings.Contains(lines[1], "view") {
		t.Errorf("a client in no view has one in its line: %q", lines[1])
	}
}

// The record types a view needs, and NODATA for a type a local name does
// not hold -- never a forwarded answer, which would contradict the local
// one.
func TestTheLocalRecordTypesAreAnswered(t *testing.T) {
	up := newFakeUpstream(t)
	p := &Policy{
		Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL:   time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second,
		Local: localSet(
			LocalRecord{Name: "app.test", Type: TypeA, TTL: 60, Addr: addr("10.0.5.10")},
			LocalRecord{Name: "app.test", Type: TypeAAAA, TTL: 60, Addr: addr("2001:db8::5")},
			LocalRecord{Name: "app.test", Type: TypeTXT, TTL: 60, Text: "owner=platform"},
			LocalRecord{Name: "10.5.0.10.in-addr.arpa", Type: TypePTR, TTL: 60, Text: "app.test"},
		),
	}
	s, _ := startServer(t, p, Hooks{})
	t.Run("A", func(t *testing.T) {
		typ, data := firstRR(t, s.Handle(mustQuery(t, 7, "app.test", TypeA), addr("10.1.2.3"), true))
		if typ != TypeA || len(data) != 4 || data[3] != 10 {
			t.Errorf("type %d data %v", typ, data)
		}
	})
	t.Run("AAAA", func(t *testing.T) {
		typ, data := firstRR(t, s.Handle(mustQuery(t, 8, "app.test", TypeAAAA), addr("10.1.2.3"), true))
		if typ != TypeAAAA || len(data) != 16 || data[0] != 0x20 {
			t.Errorf("type %d data %v", typ, data)
		}
	})
	t.Run("TXT", func(t *testing.T) {
		typ, data := firstRR(t, s.Handle(mustQuery(t, 9, "app.test", TypeTXT), addr("10.1.2.3"), true))
		if typ != TypeTXT || len(data) < 2 || int(data[0]) != len("owner=platform") || string(data[1:]) != "owner=platform" {
			t.Errorf("type %d data %q", typ, data)
		}
	})
	t.Run("PTR", func(t *testing.T) {
		resp := s.Handle(mustQuery(t, 10, "10.5.0.10.in-addr.arpa", TypePTR), addr("10.1.2.3"), true)
		typ, data := firstRR(t, resp)
		if typ != TypePTR {
			t.Fatalf("type %d", typ)
		}
		name, _, err := readName(data, 0)
		if err != nil || strings.TrimSuffix(name, ".") != "app.test" {
			t.Errorf("name %q (%v)", name, err)
		}
	})
	t.Run("a type the name does not hold is NODATA", func(t *testing.T) {
		resp := s.Handle(mustQuery(t, 11, "app.test", TypeMX), addr("10.1.2.3"), true)
		h, _, _ := answerIP(t, resp)
		if h.Rcode() != RcodeNoError {
			t.Errorf("rcode %d, want 0", h.Rcode())
		}
		if n := answerCount(t, resp); n != 0 {
			t.Errorf("%d answers, want none", n)
		}
	})
}

// A record whose address does not match its type is refused when it is
// encoded, rather than answered as something no client can read.
func TestARecordThatCannotBeEncodedIsNotAnswered(t *testing.T) {
	for _, r := range []LocalRecord{
		{Name: "x.test", Type: TypeA, Addr: addr("2001:db8::1")},
		{Name: "x.test", Type: TypeAAAA, Addr: addr("10.0.0.1")},
		{Name: "x.test", Type: TypeTXT, Text: strings.Repeat("x", 256)},
		{Name: "x.test", Type: TypePTR, Text: strings.Repeat("label.", 60)},
	} {
		if _, err := r.Rdata(); err == nil {
			t.Errorf("%+v encoded", r)
		}
	}
	for _, r := range []LocalRecord{
		{Name: "x.test", Type: TypeA, Addr: addr("10.0.0.1")},
		{Name: "x.test", Type: TypeAAAA, Addr: addr("2001:db8::1")},
		{Name: "x.test", Type: TypeTXT, Text: "ok"},
		{Name: "x.test", Type: TypePTR, Text: "app.test"},
	} {
		if _, err := r.Rdata(); err != nil {
			t.Errorf("%+v did not encode: %v", r, err)
		}
	}
}
