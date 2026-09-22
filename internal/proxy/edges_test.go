package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/originsig"
	"github.com/rom/xproxy/internal/testutil"
	"github.com/rom/xproxy/internal/upstream"
)

// The deciders below need a live server: they read the generation, the
// counters or the logs. Each is still driven directly rather than through
// a request, so the branch under test is the one that runs.

const edgesYAML = `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
trusted_proxies: [127.0.0.0/8]
rate_limits:
  - {name: exact-pol, key: client_ip, rate: 1, burst: 1, distributed: exact}
  - {name: shared-pol, key: client_ip, rate: 1, burst: 1, distributed: approximate}
cluster:
  node_id: edges
  listen: "127.0.0.1:0"
  gossip_interval: 1s
  tls: {cert_file: %s, key_file: %s, ca_file: %s}
upstreams:
  - name: app
    endpoints: [{address: %s}]
routes:
  - name: app
    paths: [/]
    upstream: app
`

func edgesServer(t *testing.T) *Server {
	t.Helper()
	b := newBackend(t, "edge")
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "edges")
	s, _ := startServer(t, fmt.Sprintf(edgesYAML, cert, key, ca.Path, b.addr()))
	return s
}

func newReqState(ip string) *reqState {
	return &reqState{id: "rid", start: time.Now(), clientIP: netip.MustParseAddr(ip), route: "app", path: "/a/1"}
}

func TestRateKeyEveryShape(t *testing.T) {
	s := edgesServer(t)
	st := newReqState("198.51.100.77")
	st.country = "SE"
	st.device = "dev-7"
	ctx, id := filter.WithIdentity(context.Background())
	filter.SetIdentity(ctx, "oidc", "alice@test")
	filter.SetIdentity(ctx, "api_key", "k-1")
	st.identity = id

	r := httptest.NewRequest("GET", "http://shop.test/a/1", nil)
	r.Header.Set("X-Tenant", "acme")
	r.AddCookie(&http.Cookie{Name: "sid", Value: "s-1"})
	// A token with a string, a number and a boolean claim; the payload is
	// read without verification because the value only names a bucket.
	r.Header.Set("Authorization", "Bearer "+testJWT(t, `{"sub":"u-1","n":42,"b":true,"o":{"x":1}}`))

	ip := "198.51.100.77"
	cases := []struct {
		rl   config.RateLimit
		want string
	}{
		{config.RateLimit{Key: "client_ip"}, ip},
		{config.RateLimit{Key: "client_net", NetV4: 24, NetV6: 48}, "net:198.51.100.0/24"},
		{config.RateLimit{Key: "route"}, "app"},
		{config.RateLimit{Key: "endpoint"}, "ep:GET app /a/{n}"},
		{config.RateLimit{Key: "country"}, "c:SE"},
		{config.RateLimit{Key: "identity"}, "id:alice@test"},
		{config.RateLimit{Key: "identity:api_key"}, "id:api_key:k-1"},
		{config.RateLimit{Key: "device"}, "dev:dev-7"},
		{config.RateLimit{Key: "header:X-Tenant"}, "h:acme"},
		{config.RateLimit{Key: "cookie:sid"}, "ck:s-1"},
		{config.RateLimit{Key: "jwt:sub"}, "jwt:u-1"},
		{config.RateLimit{Key: "jwt:n"}, "jwt:42"},
		{config.RateLimit{Key: "jwt:b"}, "jwt:true"},
		{config.RateLimit{Key: ""}, ip},
		{config.RateLimit{Key: "nonsense"}, ip},
	}
	for _, c := range cases {
		got := s.rateKey(&c.rl, r, st)
		if c.rl.Key == "endpoint" {
			// The template depends on the path parser; only the prefix is
			// asserted so a change there does not break this test.
			if !strings.HasPrefix(got, "ep:GET app /") {
				t.Errorf("key %q = %q", c.rl.Key, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("key %q = %q want %q", c.rl.Key, got, c.want)
		}
	}

	// Every key that cannot be answered falls back to the client address
	// rather than to one shared bucket every client would land in.
	bare := newReqState(ip)
	bare.identity = &filter.Identity{}
	plain := httptest.NewRequest("GET", "http://shop.test/a/1", nil)
	for _, key := range []string{
		"country", "identity", "identity:oidc", "device", "ja4",
		"header:X-Absent", "cookie:absent", "jwt:sub",
	} {
		if got := s.rateKey(&config.RateLimit{Key: key}, plain, bare); got != "ip:"+ip {
			t.Errorf("unanswerable key %q = %q, want the client address", key, got)
		}
	}
	// A claim that is an object or an array names no bucket of its own.
	obj := httptest.NewRequest("GET", "http://shop.test/a/1", nil)
	obj.Header.Set("Authorization", "Bearer "+testJWT(t, `{"o":{"x":1},"a":[1]}`))
	for _, key := range []string{"jwt:o", "jwt:a", "jwt:missing"} {
		if got := s.rateKey(&config.RateLimit{Key: key}, obj, bare); got != "ip:"+ip {
			t.Errorf("claim key %q = %q", key, got)
		}
	}
	// ja4 is only consulted for a TLS connection, and an unknown
	// connection still falls back rather than keying on the empty string.
	tlsReq := httptest.NewRequest("GET", "https://shop.test/a/1", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	tlsReq.RemoteAddr = "203.0.113.9:1234"
	if got := s.rateKey(&config.RateLimit{Key: "ja4"}, tlsReq, bare); got != "ip:"+ip {
		t.Errorf("an unknown fingerprint gave %q", got)
	}
	// A very long header or cookie value is cut: one client must not be
	// able to fill the key table with a single megabyte header.
	longReq := httptest.NewRequest("GET", "http://shop.test/a/1", nil)
	longReq.Header.Set("X-Tenant", strings.Repeat("a", 4096))
	if got := s.rateKey(&config.RateLimit{Key: "header:X-Tenant"}, longReq, bare); len(got) > 256+2 {
		t.Errorf("a long header produced a %d byte key", len(got))
	}
	// An IPv6 client is grouped by the configured prefix, not the v4 one.
	v6 := newReqState("2001:db8:1:2::9")
	if got := s.rateKey(&config.RateLimit{Key: "client_net", NetV4: 24, NetV6: 48}, plain, v6); got != "net:2001:db8:1::/48" {
		t.Errorf("IPv6 network key = %q", got)
	}
	// A prefix length no address can have leaves the address itself.
	if got := s.rateKey(&config.RateLimit{Key: "client_net", NetV4: 99, NetV6: 99}, plain, bare); got != "ip:"+ip {
		t.Errorf("an impossible prefix gave %q", got)
	}
}

func TestBanCategoryFolding(t *testing.T) {
	for reason, want := range map[string]string{
		"acl_deny":            "acl",
		"acl_allow":           "acl",
		"rate_limit":          "rate_limit",
		"rate_limit:tiny":     "rate_limit",
		"rate_limitsomething": "rate_limit",
		"waf":                 "waf",
		"":                    "",
		"normalization":       "normalization",
	} {
		if got := banCategory(reason); got != want {
			t.Errorf("banCategory(%q) = %q want %q", reason, got, want)
		}
	}
}

func TestDigestBodyBounds(t *testing.T) {
	s := edgesServer(t)
	call := func(body io.Reader, length int64) (bool, int) {
		rec := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rec}
		r := httptest.NewRequest("POST", "http://shop.test/", body)
		if length >= 0 {
			r.ContentLength = length
		}
		st := newReqState("198.51.100.4")
		ok := s.digestBody(rw, r, st)
		if ok && st.bodyDigest == "" && r.ContentLength > 0 {
			t.Error("a body was accepted without a digest")
		}
		return ok, rec.Code
	}

	// A body the proxy can cover is buffered, digested and replayable.
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec}
	r := httptest.NewRequest("POST", "http://shop.test/", strings.NewReader("payload"))
	st := newReqState("198.51.100.4")
	if !s.digestBody(rw, r, st) {
		t.Fatal("a small body was refused")
	}
	if st.bodyDigest == "" {
		t.Error("no digest was recorded")
	}
	if r.ContentLength != 7 {
		t.Errorf("ContentLength = %d", r.ContentLength)
	}
	// A retry rereads the body through GetBody.
	for i := 0; i < 2; i++ {
		rc, err := r.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		if string(got) != "payload" {
			t.Errorf("replay %d read %q", i, got)
		}
	}
	first, _ := io.ReadAll(r.Body)
	if string(first) != "payload" {
		t.Errorf("the request body reads %q", first)
	}

	// No body at all is fine and records nothing.
	if ok, _ := call(nil, -1); !ok {
		t.Error("a request without a body was refused")
	}
	if ok, _ := call(http.NoBody, 0); !ok {
		t.Error("an explicitly empty body was refused")
	}

	// One byte past what a digest may cover is refused with 413 rather
	// than silently signed over a truncated body.
	big := strings.NewReader(strings.Repeat("x", int(originsig.MaxDigestBody)+1))
	ok, code := call(big, -1)
	if ok || code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversize body gave %v / %d", ok, code)
	}
	// A body that fails mid-read is a 400, not a partial digest.
	ok, code = call(io.MultiReader(strings.NewReader("ab"), &errReader{err: io.ErrUnexpectedEOF}), -1)
	if ok || code != http.StatusBadRequest {
		t.Errorf("an unreadable body gave %v / %d", ok, code)
	}
}

func TestQueueRefusedAnswers(t *testing.T) {
	s := edgesServer(t)
	call := func(err error) (int, string, string) {
		rec := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rec}
		r := httptest.NewRequest("GET", "http://shop.test/", nil)
		st := newReqState("198.51.100.4")
		s.queueRefused(rw, r, st, err)
		return rw.Status(), st.upErr, rec.Header().Get("Retry-After")
	}
	before := s.Stats()
	if code, up, retry := call(upstream.ErrQueueFull); code != http.StatusServiceUnavailable || up != "queue_full" || retry != "1" {
		t.Errorf("a full queue gave %d / %q / %q", code, up, retry)
	}
	if code, up, _ := call(upstream.ErrQueueTimeout); code != http.StatusServiceUnavailable || up != "queue_timeout" {
		t.Errorf("a queue timeout gave %d / %q", code, up)
	}
	// A client that walked away is recorded as 499 and nothing is
	// written back to a connection that is no longer there.
	code, up, retry := call(context.Canceled)
	if code != 499 || up != "" || retry != "" {
		t.Errorf("a client cancel gave %d / %q / %q", code, up, retry)
	}
	after := s.Stats()
	if after.UpstreamQueueFull != before.UpstreamQueueFull+1 ||
		after.UpstreamQueueTimeouts != before.UpstreamQueueTimeouts+1 ||
		after.ClientAborts != before.ClientAborts+1 {
		t.Errorf("counters did not move once each: %+v", after)
	}
}

func TestTarpitHoldsThenDenies(t *testing.T) {
	s := edgesServer(t)
	rl := &config.RateLimit{Name: "pit", TarpitDelay: config.Duration(20 * time.Millisecond)}

	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec}
	r := httptest.NewRequest("GET", "http://shop.test/", nil)
	start := time.Now()
	s.tarpit(rw, r, newReqState("198.51.100.4"), rl)
	if d := time.Since(start); d < 15*time.Millisecond {
		t.Errorf("the hold lasted %s", d)
	}
	if rw.Status() != http.StatusTooManyRequests {
		t.Errorf("status = %d", rw.Status())
	}

	// A client that disconnects does not pin the goroutine for the whole
	// delay: the hold ends with the request.
	slow := &config.RateLimit{Name: "pit", TarpitDelay: config.Duration(30 * time.Second)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec2 := httptest.NewRecorder()
	rw2 := &responseWriter{ResponseWriter: rec2}
	r2 := httptest.NewRequest("GET", "http://shop.test/", nil).WithContext(ctx)
	start = time.Now()
	s.tarpit(rw2, r2, newReqState("198.51.100.4"), slow)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a cancelled request was held for %s", d)
	}
	if rw2.Status() != 499 {
		t.Errorf("a cancelled request recorded %d", rw2.Status())
	}
}

func TestClusterRateSourceDecide(t *testing.T) {
	s := edgesServer(t)
	src := rateSource{s: s}

	// Only the owner of an exact policy answers, and only for a policy
	// that exists: an unknown name must not be treated as "allowed".
	for _, name := range []string{"nosuchpolicy", "shared-pol"} {
		allowed, ok := src.Decide(name, "k", 1)
		if ok || allowed {
			t.Errorf("Decide(%q) = %v, %v", name, allowed, ok)
		}
	}
	allowed, ok := src.Decide("exact-pol", "198.51.100.1", 1)
	if !ok || !allowed {
		t.Errorf("the first request of an exact policy = %v, %v", allowed, ok)
	}
	// The burst is one, so the peer's next request is refused and the
	// refusal is counted on this node.
	allowed, ok = src.Decide("exact-pol", "198.51.100.1", 1)
	if !ok || allowed {
		t.Errorf("the second request = %v, %v", allowed, ok)
	}

	// Flush never gossips an exact policy's consumption: its owner is
	// authoritative and a peer's copy would double count.
	if m := src.Flush(16); m["exact-pol"] != nil {
		t.Errorf("an exact policy was gossiped: %v", m["exact-pol"])
	}
	// A report for an exact policy is likewise ignored.
	src.Report("peer-a", "exact-pol", nil)
	src.Report("peer-a", "nosuchpolicy", nil)
	src.Report("peer-a", "shared-pol", nil)
}

func TestHoneypotAccessorsOnAServer(t *testing.T) {
	s := edgesServer(t)
	if got := s.HoneypotMarksDropped(); got != 0 {
		t.Errorf("a fresh server reports %d dropped marks", got)
	}
	if got := s.HoneypotMarks(); len(got) != 0 {
		t.Errorf("a fresh server reports %d marks", len(got))
	}
	ip := netip.MustParseAddr("198.51.100.5")
	s.marks.add(ip, "trap", time.Minute, time.Now())
	if len(s.HoneypotMarks()) != 1 {
		t.Fatal("the mark was not recorded")
	}
	if !s.UnmarkHoneypot(ip) {
		t.Error("the mark could not be withdrawn")
	}
	if s.UnmarkHoneypot(ip) {
		t.Error("withdrawing an absent mark reported success")
	}
	if s.UnmarkHoneypot(netip.Addr{}) {
		t.Error("the zero address was unmarked")
	}
	// A mark placed for a peer is held for no longer than this node's own
	// honeypots would hold one, whatever deadline the peer chose.
	far := time.Now().Add(365 * 24 * time.Hour)
	s.onClusterEvent(cluster.Event{Kind: eventHoneypotMark, Key: "198.51.100.6", Until: far}, "peer-a")
	marks := s.HoneypotMarks()
	if len(marks) != 1 {
		t.Fatalf("%d marks after a peer's event", len(marks))
	}
	if d := time.Until(marks[0].Expires); d > 2*time.Hour {
		t.Errorf("a peer's mark is held for %s", d)
	}
	// Only the peer that placed a mark may withdraw it, and an address
	// that does not parse is ignored rather than crashing the receiver.
	s.onClusterEvent(cluster.Event{Kind: eventHoneypotUnmark, Key: "198.51.100.6"}, "peer-b")
	if len(s.HoneypotMarks()) != 1 {
		t.Error("another peer withdrew the mark")
	}
	s.onClusterEvent(cluster.Event{Kind: eventHoneypotUnmark, Key: "198.51.100.6"}, "peer-a")
	if len(s.HoneypotMarks()) != 0 {
		t.Error("the placing peer could not withdraw the mark")
	}
	for _, key := range []string{"", "not-an-address", "198.51.100.300", "198.51.100.6:80"} {
		s.onClusterEvent(cluster.Event{Kind: eventHoneypotMark, Key: key, Until: far}, "peer-a")
		s.onClusterEvent(cluster.Event{Kind: eventHoneypotUnmark, Key: key}, "peer-a")
	}
	if got := s.HoneypotMarks(); len(got) != 0 {
		t.Errorf("an unparseable address was marked: %v", got)
	}
	// A deadline already past places nothing.
	s.onClusterEvent(cluster.Event{Kind: eventHoneypotMark, Key: "198.51.100.7", Until: time.Now().Add(-time.Hour)}, "peer-a")
	if got := s.HoneypotMarks(); len(got) != 0 {
		t.Errorf("an expired mark was placed: %v", got)
	}
	// A kind nobody handles is dropped quietly.
	s.onClusterEvent(cluster.Event{Kind: "nosuchkind", Key: "x"}, "peer-a")
	// peerMarkTTL falls back to an hour when no route has a honeypot.
	if d := s.peerMarkTTL(); d != time.Hour {
		t.Errorf("peerMarkTTL = %s", d)
	}
}

func TestInventoryRouteSelectors(t *testing.T) {
	route := func(name string, hosts ...string) *config.Route {
		return &config.Route{Name: name, Hosts: hosts}
	}
	cases := []struct {
		inv  config.APIInventory
		r    *config.Route
		want bool
	}{
		{config.APIInventory{}, route("api", "a.test"), true},
		{config.APIInventory{}, route("api"), true},
		{config.APIInventory{Routes: []string{"api"}}, route("api", "a.test"), true},
		{config.APIInventory{Routes: []string{"other"}}, route("api", "a.test"), false},
		{config.APIInventory{Routes: []string{"x", "api"}}, route("api"), true},
		{config.APIInventory{Hosts: []string{"a.test"}}, route("api", "a.test"), true},
		{config.APIInventory{Hosts: []string{"a.test"}}, route("api", "b.test"), false},
		{config.APIInventory{Hosts: []string{"a.test"}}, route("api", "b.test", "a.test"), true},
		{config.APIInventory{Hosts: []string{"*.test"}}, route("api", "a.test"), true},
		{config.APIInventory{Hosts: []string{"*.test"}}, route("api", "a.b.test"), false},
		{config.APIInventory{Hosts: []string{"a.test"}}, route("api"), false},
		{config.APIInventory{Routes: []string{"api"}, Hosts: []string{"a.test"}}, route("api", "a.test"), true},
		{config.APIInventory{Routes: []string{"api"}, Hosts: []string{"z.test"}}, route("api", "a.test"), false},
		{config.APIInventory{Routes: []string{"other"}, Hosts: []string{"a.test"}}, route("api", "a.test"), false},
	}
	for i, c := range cases {
		inv := c.inv
		if got := inventoryRoute(&inv, c.r); got != c.want {
			t.Errorf("case %d (%v / %v) = %v want %v", i, c.inv, c.r, got, c.want)
		}
	}
}

func TestSplitOrigin(t *testing.T) {
	cases := map[string]struct {
		scheme, host string
		ok           bool
	}{
		"https://a.test":       {"https", "a.test", true},
		"http://a.test:8080":   {"http", "a.test:8080", true},
		"null":                 {"", "", false},
		"":                     {"", "", false},
		"a.test":               {"", "", false},
		"https:/a.test":        {"", "", false},
		"://a.test":            {"", "a.test", true},
		"https://a.test/x":     {"https", "a.test/x", true},
		"https://a://b":        {"https", "a://b", true},
		"HTTPS://a.test":       {"HTTPS", "a.test", true},
		"file://":              {"file", "", true},
		"chrome-extension://i": {"chrome-extension", "i", true},
	}
	for in, want := range cases {
		scheme, host, ok := splitOrigin(in)
		if scheme != want.scheme || host != want.host || ok != want.ok {
			t.Errorf("splitOrigin(%q) = %q, %q, %v want %q, %q, %v", in, scheme, host, ok, want.scheme, want.host, want.ok)
		}
	}
}

func TestHashUpToRespectsTheBound(t *testing.T) {
	buf := []byte("0123456789")
	// Nothing past the bound reaches the hash, so two bodies that differ
	// only after it produce the same digest — which is what makes the
	// shadow comparison bounded work.
	sum := func(chunks [][]byte, max int64) [32]byte {
		h := sha256.New()
		var n int64
		for _, c := range chunks {
			hashUpTo(h, n, int64(len(c)), max, c)
			n += int64(len(c))
		}
		var d [32]byte
		copy(d[:], h.Sum(nil))
		return d
	}
	whole := sum([][]byte{buf}, 4)
	split := sum([][]byte{buf[:2], buf[2:6], buf[6:]}, 4)
	if whole != split {
		t.Error("the digest depends on how the body was chunked")
	}
	if want := sha256.Sum256(buf[:4]); whole != want {
		t.Error("more than the bound was hashed")
	}
	// A bound of zero hashes nothing at all.
	if sum([][]byte{buf}, 0) != sha256.Sum256(nil) {
		t.Error("a zero bound still hashed")
	}
	// A bound past the body hashes the whole body once.
	if sum([][]byte{buf}, 1<<20) != sha256.Sum256(buf) {
		t.Error("a large bound changed the digest")
	}
}

func TestServeCachedConditionalRequests(t *testing.T) {
	s := edgesServer(t)
	cr := &compiledRoute{cfg: &config.Route{Name: "app"}}
	ops, err := compileOps(config.HeaderOps{Add: map[string]string{"X-Req": "${request_id}"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cr.respOps = ops
	lm := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	entry := func() *cache.Entry {
		return &cache.Entry{
			Status: 200,
			Header: http.Header{
				"Etag":          []string{`"v1"`},
				"Last-Modified": []string{lm.Format(http.TimeFormat)},
				"Content-Type":  []string{"text/plain"},
			},
			Body:    []byte("cached body"),
			Stored:  time.Now().Add(-30 * time.Second),
			Expires: time.Now().Add(time.Minute),
		}
	}
	serve := func(method string, hdr ...string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rec}
		r := httptest.NewRequest(method, "http://shop.test/p", nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		st := newReqState("198.51.100.4")
		s.serveCached(rw, r, st, cr, entry())
		if st.cache != "hit" {
			t.Errorf("a served entry was logged as %q", st.cache)
		}
		return rec
	}

	full := serve("GET")
	if full.Code != 200 || full.Body.String() != "cached body" {
		t.Errorf("a plain hit gave %d / %q", full.Code, full.Body.String())
	}
	if full.Header().Get("X-Cache") != "HIT" || full.Header().Get("Age") == "" {
		t.Errorf("headers = %v", full.Header())
	}
	if full.Header().Get("Content-Length") != "11" {
		t.Errorf("Content-Length = %q", full.Header().Get("Content-Length"))
	}

	// HEAD gets the headers, including the length, and no body.
	head := serve("HEAD")
	if head.Body.Len() != 0 || head.Header().Get("Content-Length") != "11" {
		t.Errorf("HEAD gave %d bytes with length %q", head.Body.Len(), head.Header().Get("Content-Length"))
	}

	// A matching validator gets 304 with no body.
	for _, hdr := range [][]string{
		{"If-None-Match", `"v1"`},
		{"If-None-Match", "*"},
		{"If-None-Match", `"v0", "v1"`},
		{"If-Modified-Since", lm.Format(http.TimeFormat)},
		{"If-Modified-Since", lm.Add(time.Minute).Format(http.TimeFormat)},
	} {
		rec := serve("GET", hdr[0], hdr[1])
		if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
			t.Errorf("%s: %s gave %d with %d bytes", hdr[0], hdr[1], rec.Code, rec.Body.Len())
		}
	}
	// A validator that does not match, or one that is not a date at all,
	// gets the body.
	for _, hdr := range [][]string{
		{"If-None-Match", `"v0"`},
		{"If-Modified-Since", lm.Add(-time.Minute).Format(http.TimeFormat)},
		{"If-Modified-Since", "yesterday"},
	} {
		rec := serve("GET", hdr[0], hdr[1])
		if rec.Code != 200 || rec.Body.Len() == 0 {
			t.Errorf("%s: %s gave %d with %d bytes", hdr[0], hdr[1], rec.Code, rec.Body.Len())
		}
	}

	// The entry is shared by every hit, so a per-request template value
	// must never be appended into the entry's own header slice: two hits
	// with different request identifiers must not see each other's.
	e := entry()
	e.Header["X-Req"] = make([]string, 1, 8) // spare capacity: the trap
	e.Header["X-Req"][0] = "from-upstream"
	for i, want := range []string{"a", "b"} {
		rec := httptest.NewRecorder()
		rw := &responseWriter{ResponseWriter: rec}
		r := httptest.NewRequest("GET", "http://shop.test/p", nil)
		st := newReqState("198.51.100.4")
		st.id = want
		s.serveCached(rw, r, st, cr, e)
		got := rec.Header().Values("X-Req")
		if len(got) != 2 || got[0] != "from-upstream" || got[1] != want {
			t.Fatalf("hit %d saw %v", i, got)
		}
	}
	if n := len(e.Header["X-Req"]); n != 1 {
		t.Errorf("the shared entry grew to %d values", n)
	}
}

func TestFilterDeniedError(t *testing.T) {
	e := &filterDenied{v: filter.Verdict{Deny: true, Reason: "waf:942100"}}
	if got := e.Error(); got != "filter denied: waf:942100" {
		t.Errorf("Error() = %q", got)
	}
	// An empty reason still produces a message rather than a bare prefix
	// nobody can act on.
	if got := (&filterDenied{}).Error(); got == "" {
		t.Error("an empty verdict produced no message")
	}
}

// testJWT builds an unsigned token whose payload is the given JSON: the
// rate-limit key reads the payload without verifying it, so the
// signature is irrelevant here.
func testJWT(t *testing.T, payload string) string {
	t.Helper()
	if !json.Valid([]byte(payload)) {
		t.Fatalf("the payload is not JSON: %s", payload)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + ".sig"
}

// ---------------------------------------------------------- socket activation

func TestActivatedListenersRefusesBadEnvironment(t *testing.T) {
	// Without the variables there is no activation and no error: the
	// proxy binds its own sockets.
	t.Setenv("LISTEN_PID", "")
	t.Setenv("LISTEN_FDS", "")
	a, err := activatedListeners()
	if err != nil || len(a.streams) != 0 || len(a.packets) != 0 {
		t.Fatalf("an unactivated process got %v, %v", a, err)
	}
	// A set meant for another process is ignored: inheriting a stranger's
	// descriptors would serve traffic on sockets nobody meant for us.
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()+1))
	t.Setenv("LISTEN_FDS", "2")
	if a, err := activatedListeners(); err != nil || len(a.streams) != 0 {
		t.Errorf("another process's set gave %v, %v", a, err)
	}
	t.Setenv("LISTEN_PID", "not-a-pid")
	if a, err := activatedListeners(); err != nil || len(a.streams) != 0 {
		t.Errorf("an unparseable pid gave %v, %v", a, err)
	}
	// A count that is not a number, negative, or larger than any
	// plausible unit is an error rather than a loop over stray
	// descriptors.
	// Each call that gets as far as reading the count also consumes the
	// variables, so they are set again for every case.
	for _, n := range []string{"many", "-1", "1025", "99999999999999999999"} {
		t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		t.Setenv("LISTEN_FDS", n)
		if _, err := activatedListeners(); err == nil {
			t.Errorf("LISTEN_FDS=%q was accepted", n)
		}
	}
	// A valid set consumes the variables so a child process does not
	// inherit them and try to adopt the same descriptors.
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "0")
	if _, err := activatedListeners(); err != nil {
		t.Fatalf("an empty set: %v", err)
	}
	if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" {
		t.Error("the activation variables were left in the environment")
	}
}

func TestListenerForPrefersActivatedSockets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// Named sockets are matched by name and consumed, so a second
	// listener of the same name binds its own rather than sharing one.
	a := &activated{streams: map[string]net.Listener{"main": ln}, packets: map[string]net.PacketConn{"main-udp": pc}}
	got, adopted, err := listenerFor(a, "main", "127.0.0.1:0")
	if err != nil || !adopted || got != ln {
		t.Fatalf("named listener = %v, %v, %v", got, adopted, err)
	}
	if len(a.streams) != 0 {
		t.Error("the activated listener was not consumed")
	}
	gotPC, act, err := packetFor(a, "main", "127.0.0.1:0")
	if err != nil || !act || gotPC != pc {
		t.Fatalf("named packet socket = %v, %v, %v", gotPC, act, err)
	}
	if len(a.packets) != 0 {
		t.Error("the activated packet socket was not consumed")
	}

	// A socket named by its address is matched by address, and a wildcard
	// bind is the same address as an explicit one on the same port.
	addr := ln.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	a2 := &activated{streams: map[string]net.Listener{"[::]:" + port: ln}, packets: map[string]net.PacketConn{"0.0.0.0:" + port: pc}}
	if got, act, err := listenerFor(a2, "other", ":"+port); err != nil || !act || got != ln {
		t.Errorf("address match = %v, %v, %v", got, act, err)
	}
	if got, act, err := packetFor(a2, "other", "0.0.0.0:"+port); err != nil || !act || got != pc {
		t.Errorf("packet address match = %v, %v, %v", got, act, err)
	}

	// Nothing to adopt: a socket is bound, and the caller is told it is
	// not an activated one so it closes it on shutdown.
	empty := &activated{streams: map[string]net.Listener{}, packets: map[string]net.PacketConn{}}
	fresh, act, err := listenerFor(empty, "main", "127.0.0.1:0")
	if err != nil || act {
		t.Fatalf("a fresh listener = %v, %v", act, err)
	}
	_ = fresh.Close()
	freshPC, act, err := packetFor(empty, "main", "127.0.0.1:0")
	if err != nil || act {
		t.Fatalf("a fresh packet socket = %v, %v", act, err)
	}
	_ = freshPC.Close()
	// An address nothing can bind is an error, not a silent no-listener.
	if _, _, err := listenerFor(empty, "main", "203.0.113.200:80"); err == nil {
		t.Error("an unbindable address was accepted")
	}
	if _, _, err := packetFor(empty, "main", "203.0.113.200:80"); err == nil {
		t.Error("an unbindable datagram address was accepted")
	}
}

// ------------------------------------------------------------- retry rebuild

func TestTCPRetryNeedsAReplayableBody(t *testing.T) {
	tr := &poolTransport{pool: &upstream.Pool{Scheme: "https"}}

	// A body-less request always retries, against the new address.
	r := httptest.NewRequest("GET", "http://old.test/p?q=1", nil)
	r.Body = http.NoBody
	out, ok := tr.tcpRetry(r, "10.0.0.1:8443")
	if !ok || out.URL.Host != "10.0.0.1:8443" || out.URL.Scheme != "https" {
		t.Fatalf("a body-less retry = %v, %v", out.URL, ok)
	}
	// The original is untouched, so a later attempt still sees its own.
	if r.URL.Host != "old.test" {
		t.Errorf("the original request was rewritten to %q", r.URL.Host)
	}

	// A body that can be replayed is replayed.
	body := httptest.NewRequest("POST", "http://old.test/p", strings.NewReader("payload"))
	body.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("payload")), nil }
	out, ok = tr.tcpRetry(body, "10.0.0.1:8443")
	if !ok {
		t.Fatal("a replayable body was refused")
	}
	if got, _ := io.ReadAll(out.Body); string(got) != "payload" {
		t.Errorf("the retry body reads %q", got)
	}

	// A body that cannot be replayed stops the retry rather than sending
	// the upstream a request with an empty or half-consumed body.
	noGet := httptest.NewRequest("POST", "http://old.test/p", strings.NewReader("payload"))
	noGet.GetBody = nil
	if _, ok := tr.tcpRetry(noGet, "10.0.0.1:8443"); ok {
		t.Error("a request without GetBody was retried")
	}
	failing := httptest.NewRequest("POST", "http://old.test/p", strings.NewReader("payload"))
	failing.GetBody = func() (io.ReadCloser, error) { return nil, io.ErrUnexpectedEOF }
	if _, ok := tr.tcpRetry(failing, "10.0.0.1:8443"); ok {
		t.Error("a failing GetBody was retried")
	}
}

// ------------------------------------------------------------ grpc-web bodies

func TestGRPCWebTextBodyRefusesBadInput(t *testing.T) {
	read := func(rc io.ReadCloser) ([]byte, error) {
		return io.ReadAll(&b64Body{rc: rc})
	}
	frame := []byte{0, 0, 0, 0, 3, 'a', 'b', 'c'}
	enc := base64.StdEncoding.EncodeToString(frame)
	got, err := read(io.NopCloser(strings.NewReader(enc)))
	if err != nil {
		t.Fatalf("a valid body: %v", err)
	}
	if string(got) != string(frame) {
		t.Errorf("decoded %q", got)
	}
	// Two padded chunks decode one after the other, which is how clients
	// send several frames in one body.
	two := enc + enc
	got, err = read(io.NopCloser(strings.NewReader(two)))
	if err != nil || len(got) != 2*len(frame) {
		t.Errorf("two chunks gave %d bytes, %v", len(got), err)
	}
	// Rubbish is an error, not a truncated frame the upstream then parses.
	if _, err := read(io.NopCloser(strings.NewReader("not base64 !!"))); err == nil {
		t.Error("an undecodable body was accepted")
	}
	// A body that fails to read reports that error, and the same error
	// on every later read rather than an empty success.
	b := &b64Body{rc: io.NopCloser(&errReader{err: io.ErrUnexpectedEOF})}
	if _, err := b.Read(make([]byte, 4)); err == nil {
		t.Error("an unreadable body reported success")
	}
	if _, err := b.Read(make([]byte, 4)); err == nil {
		t.Error("the second read reported success")
	}
	// A body past the text bound is refused rather than buffered whole.
	huge := io.NopCloser(io.LimitReader(zeroReader{}, grpcWebTextLimit+16))
	if _, err := read(huge); err == nil {
		t.Error("an oversize text body was accepted")
	}
}

// zeroReader is an endless source of a single base64 character.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

// ------------------------------------------------------------ virtual patches

func TestPatchSelectorsNarrowCorrectly(t *testing.T) {
	counters := &patchCounters{}
	patches := compilePatches([]config.VirtualPatch{{
		ID:        "cve",
		Hosts:     []string{"*.shop.test", "exact.test"},
		Routes:    []string{"api"},
		Methods:   []string{"POST"},
		Paths:     []string{"/v1/"},
		PathRegex: []string{"/v1/[a-z]+"},
		Query:     []config.PatchMatch{{Name: "id", Pattern: "^[0-9]+$"}},
		Headers:   []config.PatchMatch{{Name: "X-Trigger"}},
		Cookies:   []config.PatchMatch{{Name: "sid", Pattern: "^s-"}},
	}}, counters)
	cp := patches[0]

	req := func(mangle func(*http.Request)) *http.Request {
		r := httptest.NewRequest("POST", "http://a.shop.test/v1/items?id=7", nil)
		r.Header.Set("X-Trigger", "anything")
		r.AddCookie(&http.Cookie{Name: "sid", Value: "s-1"})
		if mangle != nil {
			mangle(r)
		}
		return r
	}
	if !cp.selects(req(nil), "a.shop.test", "/v1/items", "api") {
		t.Fatal("the matching request was not selected")
	}
	// Every selector on its own must be able to reject.
	cases := map[string]struct {
		mangle            func(*http.Request)
		host, path, route string
	}{
		"another route":              {nil, "a.shop.test", "/v1/items", "web"},
		"another host":               {nil, "a.other.test", "/v1/items", "api"},
		"a deeper subdomain":         {nil, "a.b.shop.test", "/v1/items", "api"},
		"the bare domain":            {nil, "shop.test", "/v1/items", "api"},
		"another method":             {func(r *http.Request) { r.Method = "GET" }, "a.shop.test", "/v1/items", "api"},
		"another prefix":             {nil, "a.shop.test", "/v2/items", "api"},
		"a path the pattern rejects": {nil, "a.shop.test", "/v1/99", "api"},
		"a query value the pattern rejects": {
			func(r *http.Request) { r.URL.RawQuery = "id=abc" }, "a.shop.test", "/v1/items", "api"},
		"a missing query parameter": {
			func(r *http.Request) { r.URL.RawQuery = "" }, "a.shop.test", "/v1/items", "api"},
		"a missing header": {
			func(r *http.Request) { r.Header.Del("X-Trigger") }, "a.shop.test", "/v1/items", "api"},
		"a cookie value the pattern rejects": {
			func(r *http.Request) { r.Header.Set("Cookie", "sid=other") }, "a.shop.test", "/v1/items", "api"},
		"a missing cookie": {
			func(r *http.Request) { r.Header.Del("Cookie") }, "a.shop.test", "/v1/items", "api"},
	}
	for name, c := range cases {
		if cp.selects(req(c.mangle), c.host, c.path, c.route) {
			t.Errorf("%s was still selected", name)
		}
	}
	// The exact host in the list matches too, and a second value of a
	// listed parameter can satisfy the pattern.
	if !cp.selects(req(nil), "exact.test", "/v1/items", "api") {
		t.Error("the exact host was not selected")
	}
	if !cp.selects(req(func(r *http.Request) { r.URL.RawQuery = "id=abc&id=7" }), "a.shop.test", "/v1/items", "api") {
		t.Error("a second matching query value did not satisfy the condition")
	}

	// A patch with no selectors at all matches every request; it is the
	// configuration validator, not this function, that requires one.
	all := compilePatches([]config.VirtualPatch{{ID: "all"}}, counters)[0]
	if !all.selects(req(nil), "anything.test", "/anything", "anyroute") {
		t.Error("an unrestricted patch did not select")
	}
	// An expiry in the past disables the patch whatever the selectors say.
	expired := compilePatches([]config.VirtualPatch{{ID: "old", Paths: []string{"/"}, Expires: "2000-01-01"}}, counters)[0]
	if expired.active(time.Now()) {
		t.Error("an expired patch is still active")
	}
	future := compilePatches([]config.VirtualPatch{{ID: "new", Paths: []string{"/"}, Expires: "2999-01-01"}}, counters)[0]
	if !future.active(time.Now()) {
		t.Error("a patch that has not expired is inactive")
	}
}

// ------------------------------------------------------------- filter naming

func TestFilterNamesAreStable(t *testing.T) {
	cf := &customFilter{cfg: &config.FilterConfig{Name: "my-filter", Kind: "wasm"}}
	if got := cf.Name(); got != "my-filter" {
		t.Errorf("customFilter.Name = %q", got)
	}
	// A denial with no reason of its own is attributed to the instance,
	// and an implausible status becomes a 403 rather than reaching the
	// client as a 200 or a 999.
	ci := &customInstance{c: cf}
	for _, in := range []filter.Verdict{
		{Deny: true},
		{Deny: true, Status: 200},
		{Deny: true, Status: 99},
		{Deny: true, Status: 600},
	} {
		v := ci.fix(in)
		if v.Reason != "my-filter" || v.Status != 403 {
			t.Errorf("fix(%+v) = %+v", in, v)
		}
	}
	// A verdict that already says enough is left alone, and one that does
	// not deny is never given a status.
	v := ci.fix(filter.Verdict{Deny: true, Status: 429, Reason: "quota"})
	if v.Status != 429 || v.Reason != "quota" {
		t.Errorf("a complete verdict was rewritten to %+v", v)
	}
	if v := ci.fix(filter.Verdict{}); v.Deny || v.Status != 0 || v.Reason != "" {
		t.Errorf("an allow verdict was rewritten to %+v", v)
	}
	if got := cf.denied.Load(); got != 5 {
		t.Errorf("%d denials were counted, want 5", got)
	}
}
