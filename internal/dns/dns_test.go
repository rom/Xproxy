package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/testutil"
)

// fakeUpstream answers A queries under example.test with 10.0.0.x, TTL
// 300, NXDOMAIN for nx.*, a large TXT answer (truncated over UDP) for
// big.*, and nothing at all for silent.*.
type fakeUpstream struct {
	udp     net.PacketConn
	tcp     net.Listener
	queries atomic.Int64
	tcpQ    atomic.Int64
}

// listenPair binds a UDP socket and a TCP listener on the same loopback
// port, retrying when the port the system picked is taken by the other
// protocol.
func listenPair(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for i := 0; i < 50; i++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err == nil {
			return udp, tcp
		}
		_ = tcp.Close()
	}
	t.Fatal("no free port pair")
	return nil, nil
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	udp, tcp := listenPair(t)
	f := &fakeUpstream{udp: udp, tcp: tcp}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := f.answer(buf[:n], false); resp != nil {
				_, _ = udp.WriteTo(resp, addr)
			}
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					q, err := ReadTCP(c, MaxMessage)
					if err != nil {
						return
					}
					f.tcpQ.Add(1)
					if resp := f.answer(q, true); resp != nil {
						_ = WriteTCP(c, resp)
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	return f
}

func (f *fakeUpstream) addr() string { return f.udp.LocalAddr().String() }

func (f *fakeUpstream) answer(query []byte, tcp bool) []byte {
	f.queries.Add(1)
	h, err := ParseHeader(query)
	if err != nil {
		return nil
	}
	q, qEnd, err := ParseQuestion(query)
	if err != nil {
		return nil
	}
	switch {
	case strings.HasPrefix(q.Name, "silent."):
		return nil
	case strings.HasPrefix(q.Name, "nx."):
		return Reply(query, qEnd, h, RcodeNXDomain)
	case strings.HasPrefix(q.Name, "big."):
		resp := Reply(query, qEnd, h, RcodeNoError)
		if !tcp {
			return Truncate(resp, qEnd)
		}
		binary.BigEndian.PutUint16(resp[6:], 1)
		rr := []byte{0xc0, headerLen, 0, TypeTXT, 0, ClassIN, 0, 0, 0, 60}
		txt := make([]byte, 1000)
		for i := range txt {
			txt[i] = 'x'
		}
		rdata := append([]byte{255}, txt[:255]...)
		rdata = append(rdata, 255)
		rdata = append(rdata, txt[255:510]...)
		rdata = append(rdata, 255)
		rdata = append(rdata, txt[510:765]...)
		rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
		return append(append(resp, rr...), rdata...)
	case q.Type == TypeA && strings.HasSuffix(q.Name, "example.test"):
		return AnswerA(query, qEnd, h, q, []byte{10, 0, 0, byte(len(q.Name))}, 300)
	}
	return Reply(query, qEnd, h, RcodeNoError)
}

// udpQuery sends one query and returns the response or nil on timeout.
func udpQuery(t *testing.T, server string, query []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func tcpQuery(t *testing.T, server string, query []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := WriteTCP(c, query); err != nil {
		t.Fatal(err)
	}
	resp, err := ReadTCP(c, MaxMessage)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func mustQuery(t *testing.T, id uint16, name string, typ uint16) []byte {
	t.Helper()
	q, err := Query(id, name, typ)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func answerIP(t *testing.T, resp []byte) (Header, Question, []byte) {
	t.Helper()
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	q, qEnd, err := ParseQuestion(resp)
	if err != nil {
		t.Fatal(err)
	}
	var ip []byte
	_ = rrWalk(resp, qEnd, h, func(ttlOff int, typ uint16, _ uint32) {
		if typ == TypeA || typ == TypeAAAA {
			l := int(binary.BigEndian.Uint16(resp[ttlOff+4:]))
			ip = resp[ttlOff+6 : ttlOff+6+l]
		}
	})
	return h, q, ip
}

func TestMessages(t *testing.T) {
	q := mustQuery(t, 0x1234, "WWW.Example.TEST.", TypeA)
	h, err := ParseHeader(q)
	if err != nil || h.ID != 0x1234 || !h.RecursionDesired() || h.QDCount != 1 || h.Opcode() != 0 {
		t.Fatalf("header: %+v %v", h, err)
	}
	qu, qEnd, err := ParseQuestion(q)
	if err != nil || qu.Name != "www.example.test" || qu.Type != TypeA || qu.Class != ClassIN || qEnd != len(q) {
		t.Fatalf("question: %+v %d %v", qu, qEnd, err)
	}
	resp := AnswerA(q, qEnd, h, qu, []byte{192, 0, 2, 1}, 300)
	rh, rq, ip := answerIP(t, resp)
	if !rh.Response() || rh.Rcode() != RcodeNoError || rq != qu || string(ip) != string([]byte{192, 0, 2, 1}) {
		t.Fatalf("answer: %+v %+v %v", rh, rq, ip)
	}
	if ttl, ok := MinTTL(resp, qEnd, rh); !ok || ttl != 300 {
		t.Fatalf("min ttl: %d %v", ttl, ok)
	}
	AdjustTTL(resp, qEnd, rh, 100)
	if ttl, _ := MinTTL(resp, qEnd, rh); ttl != 200 {
		t.Fatalf("adjusted ttl: %d", ttl)
	}
	AdjustTTL(resp, qEnd, rh, 1000)
	if ttl, _ := MinTTL(resp, qEnd, rh); ttl != 0 {
		t.Fatalf("floored ttl: %d", ttl)
	}
	tr := Truncate(resp, qEnd)
	if th, _ := ParseHeader(tr); !th.Truncated() || th.ANCount != 0 || len(tr) != qEnd {
		t.Fatalf("truncate: %+v", th)
	}
	if EDNSSize(q, qEnd, h) != 512 {
		t.Fatal("edns default")
	}
	// An OPT record advertising 4096 is honoured only up to the 1232 cap
	// (RFC 9715), so a spoofed-source query cannot draw a large UDP reply.
	withOPT := append(append([]byte{}, q...), 0, 0, TypeOPT, 0x10, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(withOPT[10:], 1)
	oh, _ := ParseHeader(withOPT)
	if EDNSSize(withOPT, qEnd, oh) != maxEDNSUDP {
		t.Fatalf("edns size: %d", EDNSSize(withOPT, qEnd, oh))
	}
	// A size under the cap is used as advertised.
	small := append(append([]byte{}, q...), 0, 0, TypeOPT, 0x04, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(small[10:], 1)
	sh, _ := ParseHeader(small)
	if EDNSSize(small, qEnd, sh) != 1024 {
		t.Fatalf("edns size under cap: %d", EDNSSize(small, qEnd, sh))
	}
	if ttl, ok := MinTTL(withOPT, qEnd, oh); ok || ttl != 0 {
		t.Fatal("OPT counted as a record with TTL")
	}
	// Compression pointers: forward, into the header and loops are refused.
	bad := append(append([]byte{}, q[:headerLen]...), 0xc0, 0x0c)
	if _, _, err := ParseQuestion(bad); err == nil {
		t.Fatal("self pointer accepted")
	}
	bad = append(append([]byte{}, q[:headerLen]...), 0xc0, 0x00)
	if _, _, err := ParseQuestion(bad); err == nil {
		t.Fatal("pointer into the header accepted")
	}
	for _, cut := range []int{0, 5, headerLen, headerLen + 3, len(q) - 1} {
		if _, _, err := ParseQuestion(q[:cut]); err == nil {
			t.Fatalf("truncated at %d accepted", cut)
		}
	}
	if _, err := Query(1, strings.Repeat("a", 64)+".test", TypeA); err == nil {
		t.Fatal("long label accepted")
	}
	if _, err := Query(1, "a..b", TypeA); err == nil {
		t.Fatal("empty label accepted")
	}
	root, _ := Query(1, ".", TypeNS)
	if rq, _, err := ParseQuestion(root); err != nil || rq.Name != "" {
		t.Fatalf("root: %+v %v", rq, err)
	}
	sink := Sinkhole(q, qEnd, h, qu, []byte{0, 0, 0, 0}, 60)
	if _, _, ip := answerIP(t, sink); string(ip) != string([]byte{0, 0, 0, 0}) {
		t.Fatal("sinkhole A")
	}
	txtq := mustQuery(t, 2, "x.test", TypeTXT)
	th, _ := ParseHeader(txtq)
	tq, tEnd, _ := ParseQuestion(txtq)
	if s := Sinkhole(txtq, tEnd, th, tq, []byte{0, 0, 0, 0}, 60); len(s) != tEnd {
		t.Fatal("sinkhole for TXT should be empty")
	}
	if TypeName(TypeAAAA) != "AAAA" || TypeName(999) != "TYPE999" {
		t.Fatal("type names")
	}
}

func TestBlockList(t *testing.T) {
	bl, err := NewBlockList([]string{"Ads.Example.com.", "*.tracker.test", "=exact.test", ""})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"ads.example.com": true, "x.ads.example.com": true, "example.com": false, "ads.example.com.evil": false,
		"tracker.test": false, "a.tracker.test": true, "a.b.tracker.test": true,
		"exact.test": true, "sub.exact.test": false, "other": false,
	} {
		if bl.Match(name) != want {
			t.Errorf("%s: got %v", name, !want)
		}
	}
	if _, err := NewBlockList([]string{"bad name"}); err == nil {
		t.Fatal("bad entry accepted")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "hosts")
	_ = os.WriteFile(file, []byte("# comment\n0.0.0.0 ads.test # trailing\n127.0.0.1 localhost\n::1 ip6-localhost\nplain.test\n\n"), 0o600)
	n, err := bl.LoadBlockFile(file)
	if err != nil || n != 2 || !bl.Match("ads.test") || !bl.Match("www.plain.test") || bl.Match("localhost") {
		t.Fatalf("file: %d %v", n, err)
	}
	var nilList *BlockList
	if nilList.Match("x") {
		t.Fatal("nil list matched")
	}
}

func TestCache(t *testing.T) {
	c := NewCache(2)
	q := mustQuery(t, 7, "a.test", TypeA)
	h, _ := ParseHeader(q)
	qu, qEnd, _ := ParseQuestion(q)
	resp := AnswerA(q, qEnd, h, qu, []byte{1, 2, 3, 4}, 300)
	rh, _ := ParseHeader(resp)
	now := time.Now()
	c.Put(qu, resp, qEnd, rh, 100*time.Second, now)
	got, _ := c.Get(qu, 9, now.Add(40*time.Second))
	if got == nil || binary.BigEndian.Uint16(got) != 9 {
		t.Fatal("hit with new id")
	}
	if ttl, _ := MinTTL(got, qEnd, rh); ttl != 260 {
		t.Fatalf("ttl after 40s: %d", ttl)
	}
	if got, _ := c.Get(qu, 9, now.Add(101*time.Second)); got != nil {
		t.Fatal("expired entry served")
	}
	c.Put(qu, resp, qEnd, h, time.Minute, now)
	q2 := Question{Name: "b.test", Type: TypeA, Class: ClassIN}
	q3 := Question{Name: "c.test", Type: TypeA, Class: ClassIN}
	c.Put(q2, resp, qEnd, h, time.Minute, now)
	c.Put(q3, resp, qEnd, h, time.Minute, now)
	if c.Len() != 2 {
		t.Fatalf("bound: %d", c.Len())
	}
	if got, _ := c.Get(qu, 1, now); got != nil {
		t.Fatal("oldest not evicted")
	}
	c.Resize(1)
	if c.Len() != 1 {
		t.Fatal("resize")
	}
	if c.Purge() != 1 || c.Len() != 0 {
		t.Fatal("purge")
	}
	c.Put(qu, resp, qEnd, h, 0, now)
	if c.Len() != 0 {
		t.Fatal("zero ttl stored")
	}
}

func startServer(t *testing.T, p *Policy, hooks Hooks) (*Server, string) {
	t.Helper()
	udp, tcp := listenPair(t)
	s := New("dns", udp, tcp, 100, 8, p, hooks)
	s.Serve()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s, udp.LocalAddr().String()
}

func TestServer(t *testing.T) {
	up := newFakeUpstream(t)
	block, _ := NewBlockList([]string{"ads.test"})
	var mu sync.Mutex
	var events []string
	var lines int
	hooks := Hooks{
		Access: func(...any) { mu.Lock(); lines++; mu.Unlock() },
		Event: func(c netip.Addr, reason string, verified bool, _ ...any) {
			mu.Lock()
			// A UDP source completed no round trip, so the listener must
			// say so and the caller must not attribute the event to it.
			if verified {
				reason += " (verified)"
			}
			events = append(events, reason)
			mu.Unlock()
		},
		Banned: func(c netip.Addr) bool { return false },
	}
	policy := &Policy{
		Block: block, BlockAction: "nxdomain", Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second, LogQueries: true,
	}
	s, addr := startServer(t, policy, hooks)

	// Forwarded and answered, then served from the cache.
	resp := udpQuery(t, addr, mustQuery(t, 1, "a.example.test", TypeA))
	h, q, ip := answerIP(t, resp)
	if h.ID != 1 || h.Rcode() != RcodeNoError || q.Name != "a.example.test" || len(ip) != 4 || ip[0] != 10 {
		t.Fatalf("forwarded: %+v %+v %v", h, q, ip)
	}
	before := up.queries.Load()
	resp = udpQuery(t, addr, mustQuery(t, 2, "A.EXAMPLE.TEST", TypeA))
	if h, _, _ := answerIP(t, resp); h.ID != 2 || up.queries.Load() != before || s.Hits.Load() != 1 {
		t.Fatalf("cache hit: id %d upstream %d hits %d", h.ID, up.queries.Load()-before, s.Hits.Load())
	}
	// NXDOMAIN is cached negatively.
	resp = udpQuery(t, addr, mustQuery(t, 3, "nx.example.test", TypeA))
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNXDomain {
		t.Fatalf("nx: %+v", h)
	}
	before = up.queries.Load()
	_ = udpQuery(t, addr, mustQuery(t, 4, "nx.example.test", TypeA))
	if up.queries.Load() != before {
		t.Fatal("negative answer not cached")
	}
	// Blocked: NXDOMAIN, event, not forwarded.
	before = up.queries.Load()
	resp = udpQuery(t, addr, mustQuery(t, 5, "www.ads.test", TypeA))
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeNXDomain || up.queries.Load() != before || s.Blocked.Load() != 1 {
		t.Fatalf("blocked: %+v", h)
	}
	mu.Lock()
	if len(events) != 1 || events[0] != "dns_blocked" {
		t.Fatalf("events: %v", events)
	}
	mu.Unlock()
	// Sinkhole action after a policy swap; the cache survives.
	policy2 := *policy
	policy2.BlockAction, policy2.Sinkhole4, policy2.Sinkhole6, policy2.SinkholeTTL = "sinkhole", []byte{0, 0, 0, 0}, net.ParseIP("::1").To16(), 30
	s.Apply(&policy2, 100)
	if _, _, ip := answerIP(t, udpQuery(t, addr, mustQuery(t, 6, "www.ads.test", TypeA))); string(ip) != string([]byte{0, 0, 0, 0}) {
		t.Fatalf("sinkhole A: %v", ip)
	}
	if _, _, ip := answerIP(t, udpQuery(t, addr, mustQuery(t, 7, "www.ads.test", TypeAAAA))); len(ip) != 16 || ip[15] != 1 {
		t.Fatalf("sinkhole AAAA: %v", ip)
	}
	if s.cache.Len() == 0 {
		t.Fatal("cache lost on apply")
	}
	policy3 := policy2
	policy3.BlockAction = "refuse"
	s.Apply(&policy3, 100)
	if h, _ := ParseHeader(udpQuery(t, addr, mustQuery(t, 8, "ads.test", TypeA))); h.Rcode() != RcodeRefused {
		t.Fatal("refuse action")
	}
	// Truncated over UDP: the resolver retries over TCP and the client
	// without EDNS gets a TC answer; over TCP the full answer.
	resp = udpQuery(t, addr, mustQuery(t, 9, "big.example.test", TypeTXT))
	if h, _ := ParseHeader(resp); !h.Truncated() || s.Truncated.Load() != 1 {
		t.Fatalf("udp big: %+v", h)
	}
	resp = tcpQuery(t, addr, mustQuery(t, 10, "big.example.test", TypeTXT))
	if h, _ := ParseHeader(resp); h.Truncated() || h.ANCount != 1 || len(resp) < 700 {
		t.Fatalf("tcp big: %+v len %d", h, len(resp))
	}
	if up.tcpQ.Load() < 1 {
		t.Fatal("no TCP fallback to the upstream")
	}
	// An unresponsive upstream is SERVFAIL.
	resp = udpQuery(t, addr, mustQuery(t, 11, "silent.example.test", TypeA))
	if h, _ := ParseHeader(resp); h.Rcode() != RcodeServFail || s.ServFail.Load() != 1 {
		t.Fatalf("servfail: %+v", h)
	}
	// Malformed queries: FORMERR for a bad question, dropped when the
	// header is short or is itself a response.
	bad := mustQuery(t, 12, "a.test", TypeA)[:headerLen+3]
	if h, _ := ParseHeader(udpQuery(t, addr, bad)); h.Rcode() != RcodeFormErr {
		t.Fatal("formerr")
	}
	if udpQuery(t, addr, []byte{1, 2, 3}) != nil {
		t.Fatal("short packet answered")
	}
	respQ := mustQuery(t, 13, "a.test", TypeA)
	respQ[2] |= 0x80
	if udpQuery(t, addr, respQ) != nil {
		t.Fatal("response packet answered")
	}
	// Opcode other than QUERY: NOTIMP.
	stat := mustQuery(t, 14, "a.test", TypeA)
	stat[2] |= 2 << 3
	if h, _ := ParseHeader(udpQuery(t, addr, stat)); h.Rcode() != RcodeNotImp {
		t.Fatal("notimp")
	}
	// Client ACL and rate limit.
	policy4 := policy3
	policy4.AllowClients = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	s.Apply(&policy4, 100)
	if h, _ := ParseHeader(udpQuery(t, addr, mustQuery(t, 15, "a.example.test", TypeA))); h.Rcode() != RcodeRefused || s.Refused.Load() != 1 {
		t.Fatal("acl")
	}
	policy5 := policy3
	policy5.RateLimit = limits.NewKeyedLimiter(0.001, 2, 16) // no refill within the test
	s.Apply(&policy5, 100)
	answered := 0
	for i := 0; i < 5; i++ {
		if udpQuery(t, addr, mustQuery(t, uint16(20+i), "a.example.test", TypeA)) != nil {
			answered++
		}
	}
	if answered != 2 || s.Dropped.Load() < 3 {
		t.Fatalf("rate limit: answered %d dropped %d", answered, s.Dropped.Load())
	}
	st := s.Status()
	if st.Queries < 15 || st.CacheHits < 1 || st.Blocked != 4 || st.BlockEntries != 1 || st.CacheEntries == 0 || len(st.Upstreams) != 1 {
		t.Fatalf("status: %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if lines < 10 {
		t.Fatalf("access lines: %d", lines)
	}
}

func TestResolverNoUpstream(t *testing.T) {
	r := NewResolver(nil, time.Second)
	q := mustQuery(t, 1, "a.test", TypeA)
	qu, qEnd, _ := ParseQuestion(q)
	if _, err := r.Exchange(context.Background(), q, qEnd, qu, false); err == nil {
		t.Fatal("no upstream")
	}
	r = NewResolver([]string{"127.0.0.1:1"}, 200*time.Millisecond)
	if _, err := r.Exchange(context.Background(), q, qEnd, qu, true); err == nil || r.Failures.Load() != 1 {
		t.Fatalf("dead upstream: %v", err)
	}
}

// serveDoT answers DNS over TLS with the fake upstream's logic.
func serveDoT(t *testing.T, up *fakeUpstream, cert, key string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					q, err := ReadTCP(c, MaxMessage)
					if err != nil {
						return
					}
					up.tcpQ.Add(1)
					if resp := up.answer(q, true); resp != nil {
						_ = WriteTCP(c, resp)
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestEncryptedUpstreams(t *testing.T) {
	up := newFakeUpstream(t)
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "dns.test")
	dot := serveDoT(t, up, cert, key)
	var dohHits atomic.Int64
	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dohHits.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		q, _ := io.ReadAll(r.Body)
		if h, _ := ParseHeader(q); h.ID != 0 {
			http.Error(w, "id must be 0", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(up.answer(q, true))
	}))
	pair, _ := tls.LoadX509KeyPair(cert, key)
	doh.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	doh.StartTLS()
	t.Cleanup(doh.Close)
	_, dotPort, _ := net.SplitHostPort(dot)
	_, dohPort, _ := net.SplitHostPort(strings.TrimPrefix(doh.URL, "https://"))
	// Name resolution of dns.test must reach loopback: dial by address
	// but verify the name, which the resolver does through ServerName.
	r, err := NewResolverTLS([]string{"tls://127.0.0.1:" + dotPort, "https://127.0.0.1:" + dohPort + "/dns-query"}, 2*time.Second, ca.Path)
	if err != nil {
		t.Fatal(err)
	}
	// The certificate names dns.test, not 127.0.0.1: pin the name by
	// rewriting the parsed hosts (what an operator gets from a resolvable
	// upstream name).
	for _, s := range r.servers {
		s.host = "dns.test"
	}
	q := mustQuery(t, 1, "a.example.test", TypeA)
	qu, qEnd, _ := ParseQuestion(q)
	for i := 0; i < 4; i++ { // round robin over both transports
		resp, err := r.Exchange(context.Background(), q, qEnd, qu, false)
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if h, rq, ip := answerIP(t, resp); h.ID != 1 || rq != qu || len(ip) != 4 {
			t.Fatalf("answer %d: %+v %+v %v", i, h, rq, ip)
		}
	}
	if up.tcpQ.Load() < 2 || dohHits.Load() < 2 {
		t.Fatalf("transports used: dot %d doh %d", up.tcpQ.Load(), dohHits.Load())
	}
	if len(r.servers[0].idle) != 1 {
		t.Fatalf("dot connection not reused: %d idle", len(r.servers[0].idle))
	}
	if got := r.Servers(); len(got) != 2 || !strings.HasPrefix(got[0], "tls://") {
		t.Fatalf("servers: %v", got)
	}
	r.Close()
	if len(r.servers[0].idle) != 0 {
		t.Fatal("close left idle connections")
	}
	// The wrong CA refuses both transports.
	other := testutil.WriteCA(t, t.TempDir())
	bad, err := NewResolverTLS([]string{"tls://127.0.0.1:" + dotPort}, time.Second, other.Path)
	if err != nil {
		t.Fatal(err)
	}
	bad.servers[0].host = "dns.test"
	if _, err := bad.Exchange(context.Background(), q, qEnd, qu, false); err == nil {
		t.Fatal("wrong CA accepted")
	}
	for _, s := range []string{"ftp://x:53", "tls://nohost", "https://h.test", "https://h.test/q?x=1", "1.2.3.4"} {
		if _, err := ParseUpstream(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := NewResolverTLS([]string{"9.9.9.9:53"}, time.Second, "/nonexistent.pem"); err == nil {
		t.Fatal("missing ca accepted")
	}
}
