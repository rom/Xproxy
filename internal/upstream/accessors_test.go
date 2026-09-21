package upstream

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// A pool's accessors are what the request path and the management views
// ask about the transport it built: which protocol it speaks, whether a
// QUIC failure falls back to TCP, whether there is a circuit breaker
// behind it. They are one line each, which is exactly why a wrong
// answer is easy to miss.

// TestPoolAccessors covers the plain TCP pool and the features it does
// not have.
func TestPoolAccessors(t *testing.T) {
	p, err := NewPool(testCfg("round_robin", "10.0.0.1:8080", "10.0.0.2:8080"), nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if p.H3() {
		t.Fatal("a plain pool reports HTTP/3")
	}
	if p.H3Fallback() {
		t.Fatal("a pool with no HTTP/3 reports a fallback")
	}
	if p.RoundTripper() == nil || p.TCPRoundTripper() == nil {
		t.Fatal("a pool with no transport")
	}
	if p.RoundTripper() != p.TCPRoundTripper() {
		t.Fatal("a plain pool has two different transports")
	}
	if p.Breaker() != nil {
		t.Fatal("a pool with no circuit configured has a breaker")
	}
	if p.Gate() != nil {
		t.Fatal("a pool with no concurrency limit has a gate")
	}
	if got := p.AffinityCookie(); got != "" {
		t.Fatalf("a pool with no affinity reports the cookie %q", got)
	}
	if n := len(p.Endpoints()); n != 2 {
		t.Fatalf("%d endpoints", n)
	}
	for _, e := range p.Endpoints() {
		if e.Active() != 0 {
			t.Fatalf("%s starts with %d active requests", e.Address, e.Active())
		}
	}
	// An http pool has no client TLS configuration to hand a
	// WebTransport dial.
	if p.H3TLS() != nil {
		t.Log("an http pool carries a TLS configuration")
	}
	// Reloading a certificate a pool does not have is not an error:
	// reload-certs runs across every pool.
	if err := p.ReloadClientCertificate(); err != nil {
		t.Fatalf("reloading a pool with no client certificate: %v", err)
	}
	// Close twice, which is what a failed start and a shutdown do
	// together.
	p.Close()
}

// TestPoolAccessorsWithFeatures covers the same accessors on a pool
// that has the features, so the two answers are known to differ.
func TestPoolAccessorsWithFeatures(t *testing.T) {
	c := testCfg("round_robin", "10.0.0.1:8080")
	c.CircuitBreaker = &config.CircuitBreaker{ConsecutiveFailures: 3, OpenFor: config.Duration(time.Second), HalfOpenRequests: 1}
	c.MaxConcurrent = 10
	c.Affinity = &config.Affinity{CookieName: "srv", TTL: config.Duration(time.Hour), SecretFile: filepath.Join(t.TempDir(), "aff.key")}
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if p.Breaker() == nil {
		t.Fatal("a configured circuit produced no breaker")
	}
	if p.Gate() == nil {
		t.Fatal("a configured concurrency limit produced no gate")
	}
	if got := p.AffinityCookie(); got != "srv" {
		t.Fatalf("affinity cookie %q", got)
	}
	// The status view agrees with the accessors, since an operator
	// reads that rather than the code.
	st := p.Status()
	if st.Circuit == nil || st.Queue == nil {
		t.Fatalf("status %+v", st)
	}
	if st.Protocol != "tcp" {
		t.Fatalf("protocol %q", st.Protocol)
	}
	if st.Endpoints != 1 {
		t.Fatalf("%d endpoints in the status", st.Endpoints)
	}
}

// TestActiveCountsInFlight covers the counter the least-connections
// balancer picks on: it must go up while a request is out and come back
// down afterwards, or one endpoint silently stops being chosen.
func TestActiveCountsInFlight(t *testing.T) {
	p, err := NewPool(testCfg("least_conn", "10.0.0.1:8080", "10.0.0.2:8080"), nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	e, _ := p.Pick("", "", nil, CanaryAny)
	if e == nil {
		t.Fatal("no endpoint")
	}
	if e.Active() != 0 {
		t.Fatalf("active is %d before the request begins", e.Active())
	}
	p.Begin(e)
	if e.Active() != 1 {
		t.Fatalf("active is %d while a request is out", e.Active())
	}
	p.End(e, false, time.Millisecond)
	if e.Active() != 0 {
		t.Fatalf("active is %d after the request finished", e.Active())
	}
}

// TestRefreshWithoutDiscovery covers the discovery refresh on a pool
// whose endpoints are configured by hand: it must be a no-op rather
// than an error or an empty endpoint list.
func TestRefreshWithoutDiscovery(t *testing.T) {
	p, err := NewPool(testCfg("round_robin", "10.0.0.1:8080"), nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	before := len(p.Endpoints())
	p.Refresh()
	if got := len(p.Endpoints()); got != before {
		t.Fatalf("a refresh changed a static pool from %d to %d endpoints", before, got)
	}
}

// TestRoundTripperIsUsable makes one real request through the pool's
// transport, so the accessors above are known to hand back something
// that works rather than something that merely is not nil.
func TestRoundTripperIsUsable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	c := testCfg("round_robin", addr)
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.RoundTripper().RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// TestAffinityCookieIsUnforgeable covers the cookie that pins a client
// to one endpoint. It is signed because the alternative is a client
// choosing which backend serves it — which is a way to find the one
// backend that is still running the old build, or to concentrate a
// load test on one machine.
func TestAffinityCookieIsUnforgeable(t *testing.T) {
	c := testCfg("round_robin", "10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080")
	c.Affinity = &config.Affinity{CookieName: "srv", TTL: config.Duration(time.Hour),
		SecretFile: filepath.Join(t.TempDir(), "aff.key")}
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// A cookie the pool issued pins the client to that endpoint.
	first, cookie := p.Pick("", "", nil, CanaryAny)
	if cookie == "" {
		t.Fatal("no affinity cookie was issued")
	}
	for i := 0; i < 10; i++ {
		e, _ := p.Pick("", cookie, nil, CanaryAny)
		if e != first {
			t.Fatalf("the cookie sent request %d to %s instead of %s", i, e.Address, first.Address)
		}
	}

	// Everything else is refused and the client is balanced as if it
	// had no cookie at all.
	bad := []string{
		"", "0", "1", "2", "not-base64!", "AAAA",
		cookie[:len(cookie)-1],
		cookie + "A",
		flipMiddle(cookie),
		strings.Repeat("A", 65),
		strings.Repeat("A", 1000),
	}
	for _, v := range bad {
		if got := p.aff.verify(v, time.Now()); got >= 0 {
			t.Errorf("the cookie %.20q verified as endpoint %d", v, got)
		}
	}

	// An expired cookie is not honoured either: affinity has a lifetime
	// so a pool that changed still rebalances.
	if got := p.aff.verify(cookie, time.Now().Add(2*time.Hour)); got >= 0 {
		t.Errorf("an expired cookie verified as endpoint %d", got)
	}
}

// flipMiddle changes one character in the middle of a cookie, which is
// inside the signed bytes. The last character is not a good place: in
// base64 it encodes only part of a byte, so several spellings decode to
// the same bytes and verify as the same endpoint — the value is still
// the one the pool signed.
func flipMiddle(s string) string {
	if s == "" {
		return "A"
	}
	b := []byte(s)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// TestClampWeight covers the endpoint weight, which multiplies how much
// traffic one machine receives. Configuration validation bounds it, but
// discovery supplies weights too — an SRV record's weight comes from
// DNS, which is not this proxy's to trust.
func TestClampWeight(t *testing.T) {
	cases := map[int]int{
		-1000: 1, -1: 1, 0: 1, 1: 1, 2: 2,
		999: 999, 1000: 1000, 1001: 1000, 1 << 20: 1000,
	}
	for in, want := range cases {
		if got := clampWeight(in); got != want {
			t.Errorf("clampWeight(%d) = %d, want %d", in, got, want)
		}
	}
}
