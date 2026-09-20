package proxy

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// The small helpers of the request path: each one is a line in a log,
// a routing decision or a header the upstream sees, and each is easier
// to get wrong than it looks.

func TestStaticContentType(t *testing.T) {
	cases := map[string]string{
		"index.html": "text/html; charset=utf-8",
		"INDEX.HTM":  "text/html; charset=utf-8",
		"a/b/c.CSS":  "text/css; charset=utf-8",
		"app.js":     "text/javascript; charset=utf-8",
		"app.mjs":    "text/javascript; charset=utf-8",
		"data.json":  "application/json",
		"app.js.map": "application/json",
		"logo.svg":   "image/svg+xml",
		"mod.wasm":   "application/wasm",
		"notes.txt":  "text/plain; charset=utf-8",
		"feed.xml":   "application/xml",
		"a.png":      "image/png",
		"a.jpg":      "image/jpeg",
		"a.JPEG":     "image/jpeg",
		"a.gif":      "image/gif",
	}
	for name, want := range cases {
		if got := staticContentType(name); got != want {
			t.Errorf("staticContentType(%q) = %q want %q", name, got, want)
		}
	}
	// An extension nobody listed falls through to the host's database or
	// to nothing; either way it is never html, which is what would turn
	// an uploaded file into a script the browser runs.
	for _, name := range []string{
		"file", "file.", "file.unknown", "archive.tar.gz", "a.html.txt",
		"a.php", "a.phtml", "a.svgz", "a.htm.png", ".html", "a.HTML.exe",
	} {
		got := staticContentType(name)
		if strings.Contains(got, "text/html") && !strings.HasSuffix(strings.ToLower(name), ".html") && !strings.HasSuffix(strings.ToLower(name), ".htm") {
			t.Errorf("staticContentType(%q) = %q", name, got)
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("staticContentType(%q) needs escaping: %q", name, got)
		}
	}
	// A name that is all extension, and an empty one.
	_ = staticContentType("")
	_ = staticContentType(".")
}

func TestHashKey(t *testing.T) {
	st := &reqState{clientIP: netip.MustParseAddr("198.51.100.4")}
	r := httptest.NewRequest("GET", "http://shop.test/", nil)
	r.Header.Set("X-Tenant", "acme")
	r.AddCookie(&http.Cookie{Name: "sid", Value: "abc"})

	// Only a hash balancer has a key at all.
	for _, b := range []string{"", "round_robin", "least_conn", "random"} {
		if got := hashKey(&config.Upstream{Balancer: b, HashOn: "header:X-Tenant"}, r, st); got != "" {
			t.Errorf("balancer %q produced the key %q", b, got)
		}
	}
	cases := map[string]string{
		"header:X-Tenant": "acme",
		"cookie:sid":      "abc",
		"header:Missing":  "198.51.100.4", // falls back to the client address
		"cookie:missing":  "198.51.100.4",
		"":                "198.51.100.4",
		"client_ip":       "198.51.100.4",
		"header:":         "198.51.100.4",
		"cookie:":         "198.51.100.4",
	}
	for on, want := range cases {
		if got := hashKey(&config.Upstream{Balancer: "hash", HashOn: on}, r, st); got != want {
			t.Errorf("hash_on %q gave %q want %q", on, got, want)
		}
	}
	// A header whose value is empty falls back rather than hashing every
	// such client onto one endpoint.
	r.Header.Set("X-Empty", "")
	if got := hashKey(&config.Upstream{Balancer: "hash", HashOn: "header:X-Empty"}, r, st); got != "198.51.100.4" {
		t.Errorf("an empty header gave %q", got)
	}
	// A client with no address still produces a key rather than an empty
	// one, which would collapse every such request onto one endpoint.
	if got := hashKey(&config.Upstream{Balancer: "hash"}, r, &reqState{}); got == "" {
		t.Error("a request with no client address produced an empty key")
	}
}

func TestSameAddress(t *testing.T) {
	same := [][2]string{
		{"127.0.0.1:8080", "127.0.0.1:8080"},
		{":8080", "0.0.0.0:8080"},
		{"0.0.0.0:8080", "[::]:8080"},
		{":8080", "[::]:8080"},
	}
	for _, p := range same {
		if !sameAddress(p[0], p[1]) || !sameAddress(p[1], p[0]) {
			t.Errorf("%q and %q were not the same address", p[0], p[1])
		}
	}
	differ := [][2]string{
		{"127.0.0.1:8080", "127.0.0.1:8081"},
		{"127.0.0.1:8080", "127.0.0.2:8080"},
		{"127.0.0.1:8080", "[::1]:8080"},
		{":8080", "127.0.0.1:8080"},
		{"not an address", "127.0.0.1:8080"},
		{"127.0.0.1:8080", ""},
		{"", ""},
		{"127.0.0.1", "127.0.0.1"},
	}
	for _, p := range differ {
		if sameAddress(p[0], p[1]) {
			t.Errorf("%q and %q were treated as the same address", p[0], p[1])
		}
	}
}

func TestCertSANs(t *testing.T) {
	u, err := url.Parse("spiffe://cluster/ns/default/sa/web")
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{
		DNSNames:       []string{"a.test", "b.test"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("2001:db8::1")},
		EmailAddresses: []string{"ops@example.test"},
		URIs:           []*url.URL{u},
	}
	got := certSANs(c)
	want := []string{"a.test", "b.test", "10.0.0.1", "2001:db8::1", "ops@example.test", "spiffe://cluster/ns/default/sa/web"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("certSANs = %v", got)
	}
	// A certificate with no names gives an empty list, not nil entries.
	if got := certSANs(&x509.Certificate{}); len(got) != 0 {
		t.Errorf("an empty certificate gave %v", got)
	}
}

func TestEmptyDigest(t *testing.T) {
	want := sha256.Sum256(nil)
	if emptyDigest() != want {
		t.Error("the empty digest is not the digest of nothing")
	}
	// It is a value, not a shared buffer somebody can change.
	d := emptyDigest()
	d[0] ^= 0xff
	if emptyDigest() == d {
		t.Error("the empty digest is shared state")
	}
}

func TestSampledPct(t *testing.T) {
	// The ends are exact: 0 never samples and 100 always does, so an
	// operator turning sampling off gets it off.
	for i := 0; i < 200; i++ {
		if sampledPct(0) || sampledPct(-1) || sampledPct(-100) {
			t.Fatal("a percentage of zero or less sampled an event")
		}
		if !sampledPct(100) || !sampledPct(101) || !sampledPct(1000) {
			t.Fatal("a percentage of a hundred or more dropped an event")
		}
	}
	// In between it is a sample: over many draws both outcomes appear.
	var yes, no int
	for i := 0; i < 2000; i++ {
		if sampledPct(50) {
			yes++
		} else {
			no++
		}
	}
	if yes == 0 || no == 0 {
		t.Fatalf("fifty percent gave %d sampled and %d not", yes, no)
	}
	if yes < 500 || yes > 1500 {
		t.Errorf("fifty percent sampled %d of 2000", yes)
	}
}

func TestSelectHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Request-Id", "abc")
	h.Set("User-Agent", "curl/8")
	if got := selectHeaders(h, nil); got != nil {
		t.Errorf("an empty name list gave %v", got)
	}
	got := selectHeaders(h, []string{"X-Request-Id", "Missing"})
	if len(got) != 2 || got["X-Request-Id"] != "abc" || got["Missing"] != "" {
		t.Errorf("selectHeaders = %v", got)
	}
}

// TestResponseWriterHijack covers the wrapper every response goes
// through: an upgrade hijacks the connection, and the recorded status
// has to say so for the access log.
func TestResponseWriterHijack(t *testing.T) {
	// A writer that cannot be hijacked says so rather than panicking.
	plain := &responseWriter{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := plain.Hijack(); err == nil {
		t.Error("a recorder was hijacked")
	}
	if plain.Unwrap() == nil {
		t.Error("Unwrap returned nothing")
	}
	if plain.Status() != 0 {
		t.Errorf("a writer nobody wrote to reports %d", plain.Status())
	}
	plain.WriteHeader(http.StatusTeapot)
	if plain.Status() != http.StatusTeapot {
		t.Errorf("status %d", plain.Status())
	}

	// A real hijack over a real connection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rw := &responseWriter{ResponseWriter: w}
		c, buf, err := rw.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		if !rw.hijacked || rw.Status() != http.StatusSwitchingProtocols {
			t.Errorf("after a hijack: hijacked=%v status=%d", rw.hijacked, rw.Status())
		}
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n")
		_ = buf.Flush()
		_ = c.Close()
	}))
	defer srv.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		t.Fatalf("the upgrade answered %q (%v)", line, err)
	}
}

// TestManagementAccessors covers the views the management socket reads.
// Each one has to answer on a proxy that has none of the optional
// subsystems configured, because that is the ordinary case.
func TestManagementAccessors(t *testing.T) {
	b := newBackend(t, "app")
	s, _ := startServer(t, `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {directory: /tmp}
upstreams:
  - name: app
    endpoints: [{address: `+b.addr()+`}]
routes:
  - {name: all, paths: ["/"], upstream: app}
`)
	if s.Config() == nil || len(s.Config().Routes) != 1 {
		t.Fatal("the active configuration is missing")
	}
	// The optional subsystems answer nil or an empty view rather than
	// panicking on a proxy that does not run them.
	if s.Tickets() != nil {
		t.Error("session tickets are reported without the section")
	}
	if s.Challenger() != nil {
		t.Error("a challenger is reported without the section")
	}
	if s.Cache() != nil {
		t.Error("a cache is reported without the section")
	}
	if s.GeoIP() != nil {
		t.Error("a geoip database is reported without the section")
	}
	if s.Shedder() != nil {
		t.Error("a shedder is reported without the section")
	}
	if len(s.ICAP()) != 0 {
		t.Error("icap services are reported without the section")
	}
	// The views that always exist.
	if len(s.Upstreams()) != 1 {
		t.Errorf("upstreams: %v", s.Upstreams())
	}
	if got := s.Accounts(5); got.Enabled || len(got.Guards) != 0 {
		t.Errorf("accounts: %+v", got)
	}
	if got := s.BotScore(5); got.Enabled || len(got.Filters) != 0 {
		t.Errorf("bot score: %+v", got)
	}
	if got := s.Filters(); len(got) != 0 {
		t.Errorf("filters: %+v", got)
	}
	if s.Stats().OpenConnections < 0 {
		t.Error("the counters are not readable")
	}
	// Every view is safe to read from several goroutines while requests
	// are being served.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			_ = s.Config()
			_ = s.Stats()
			_ = s.Upstreams()
			_ = s.Filters()
			_ = s.ICAP()
			_ = s.Accounts(3)
			_ = s.BotScore(3)
			_ = s.Tickets()
			_ = s.Challenger()
			_ = s.Cache()
			_ = s.GeoIP()
			_ = s.Shedder()
		}
	}()
	for i := 0; i < 20; i++ {
		resp, _ := get(t, "http://"+s.Addrs()["main"]+"/x")
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
	<-done
}
