package http

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/netutil"
)

// The request path is built from small deciders: which key a response is
// cached under, which variable a template expands to, what a client
// certificate field reads as, whether a body may be stored at all. Each
// one is reached from the network on every request, so each is probed
// here on its own with the inputs a caller chooses rather than through a
// whole proxy where one accident hides another.

// ---------------------------------------------------------------- templates

func TestTemplateVarsResolveEveryName(t *testing.T) {
	// Every name Resolve knows, asked three ways: with nothing to answer
	// from, with a request only, and with the full state. The point is
	// that an unset variable reports "not found" rather than an empty
	// string that a template would silently paste into a header.
	names := []string{
		"client_ip", "request_id", "host", "path", "raw_query", "method",
		"scheme", "route", "upstream", "tenant", "country", "ja4",
		"tls_version", "tls_cipher", "status", "status_text", "reason",
		"header", "cookie", "query", "cert", "nosuchvariable", "0", "",
	}
	empty := &tvars{}
	for _, n := range names {
		if v, ok := empty.Resolve(n, "x"); ok {
			switch n {
			case "time", "date", "hour", "minute", "weekday":
			default:
				t.Errorf("Resolve(%q) on an empty state answered %q", n, v)
			}
		}
	}

	// The clock variables always answer, and answer something shaped like
	// a time: a header built from them must never be empty.
	for _, n := range []string{"time", "date", "hour", "minute", "weekday"} {
		v, ok := empty.Resolve(n, "")
		if !ok || v == "" {
			t.Errorf("Resolve(%q) = %q, %v", n, v, ok)
		}
		if strings.ContainsAny(v, "\r\n") {
			t.Errorf("Resolve(%q) = %q contains a line break", n, v)
		}
	}
	if v, _ := empty.Resolve("weekday", ""); len(v) != 3 {
		t.Errorf("weekday = %q, want three letters", v)
	}

	// A request with no state: host falls back to the Host header with
	// the port cut off, and an unparseable Host is used whole.
	r := httptest.NewRequest("POST", "http://example.test:8443/a/b?q=1&q=2", nil)
	r.Header.Set("X-Team", "blue")
	r.AddCookie(&http.Cookie{Name: "sid", Value: "s3cret"})
	rv := &tvars{r: r}
	for name, want := range map[string]string{
		"host": "example.test", "path": "/a/b", "raw_query": "q=1&q=2",
		"method": "POST", "scheme": "http", "header": "", "query": "1",
	} {
		arg := ""
		if name == "query" {
			arg = "q"
		}
		if got, _ := rv.Resolve(name, arg); got != want {
			t.Errorf("Resolve(%q) = %q want %q", name, got, want)
		}
	}
	if got, ok := rv.Resolve("header", "X-Team"); got != "blue" || !ok {
		t.Errorf("header = %q, %v", got, ok)
	}
	if got, ok := rv.Resolve("header", "X-Absent"); got != "" || ok {
		t.Errorf("a missing header answered %q, %v", got, ok)
	}
	if got, ok := rv.Resolve("cookie", "sid"); got != "s3cret" || !ok {
		t.Errorf("cookie = %q, %v", got, ok)
	}
	if _, ok := rv.Resolve("cookie", "absent"); ok {
		t.Error("a missing cookie reported found")
	}
	if _, ok := rv.Resolve("query", "absent"); ok {
		t.Error("a missing query parameter reported found")
	}
	// An address literal Host has no port to split off.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Host = "[2001:db8::1]"
	if got, _ := (&tvars{r: r2}).Resolve("host", ""); got != "[2001:db8::1]" {
		t.Errorf("host of a bracketed literal = %q", got)
	}

	// TLS variables need a handshake; without one they must not answer.
	if _, ok := rv.Resolve("tls_version", ""); ok {
		t.Error("tls_version answered for a plaintext request")
	}
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}
	for name, want := range map[string]string{
		"scheme": "https", "tls_version": "TLS 1.3", "tls_cipher": "TLS_AES_128_GCM_SHA256",
	} {
		if got, ok := rv.Resolve(name, ""); got != want || !ok {
			t.Errorf("Resolve(%q) = %q, %v want %q", name, got, ok, want)
		}
	}
	if _, ok := rv.Resolve("cert", "cn"); ok {
		t.Error("cert answered without a client certificate")
	}

	// Full state.
	st := &reqState{
		id: "rid", clientIP: netip.MustParseAddr("198.51.100.9"), host: "shop.test",
		route: "api", upstream: "pool-a", country: "SE", ja4: "t13d",
		captures: []string{"whole", "first"}, captureNames: []string{"", "leader"},
		cr: &compiledRoute{cfg: &config.Route{Tenant: "acme"}},
	}
	full := &tvars{r: r, st: st, status: 404, reason: "not_found"}
	if got, ok := full.Resolve("capture", "leader"); got != "first" || !ok {
		t.Errorf("capture(leader) = %q, %v, want first, true", got, ok)
	}
	for name, want := range map[string]string{
		"client_ip": "198.51.100.9", "request_id": "rid", "host": "shop.test",
		"route": "api", "upstream": "pool-a", "tenant": "acme", "country": "SE",
		"ja4": "t13d", "status": "404", "status_text": "Not Found",
		"reason": "not_found", "0": "whole", "1": "first", "leader": "first",
	} {
		got, ok := full.Resolve(name, "")
		if got != want || !ok {
			t.Errorf("Resolve(%q) = %q, %v want %q", name, got, ok, want)
		}
	}
	// A capture index past the end, a negative one and a name no group
	// carries are all "not found", never another group's value.
	for _, name := range []string{"2", "99", "-1", "9999999999999999999999", "unknown"} {
		if v, ok := full.Resolve(name, ""); ok {
			t.Errorf("Resolve(%q) = %q, want not found", name, v)
		}
	}
	// An empty state answers nothing for a capture name either.
	if _, ok := (&tvars{st: &reqState{}}).Resolve("0", ""); ok {
		t.Error("a state without captures answered a capture")
	}
	// A route with no tenant and an unresolved country stay unset.
	bare := &tvars{st: &reqState{cr: &compiledRoute{cfg: &config.Route{}}}}
	if v, ok := bare.Resolve("tenant", ""); v != "" || !ok {
		t.Errorf("an empty tenant = %q, %v", v, ok)
	}
	if _, ok := bare.Resolve("country", ""); ok {
		t.Error("an unresolved country reported found")
	}
	if _, ok := bare.Resolve("ja4", ""); ok {
		t.Error("an unset ja4 reported found")
	}
	// A state with no client address does not answer with the zero one.
	if v, ok := (&tvars{st: &reqState{}}).Resolve("client_ip", ""); ok {
		t.Errorf("client_ip of an invalid address = %q", v)
	}
	// status 0 means "no error page in progress".
	if _, ok := (&tvars{status: 0}).Resolve("status_text", ""); ok {
		t.Error("status_text answered without a status")
	}
}

// makeClientCert builds a certificate carrying one of every subject
// alternative name kind, so certField's joins are exercised in order.
func makeClientCert(t *testing.T, cn string, serial *big.Int, sans bool) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Sysctl AB"}},
		Issuer:       pkix.Name{CommonName: "issuing ca"},
		NotBefore:    time.Unix(1_600_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
	}
	if sans {
		tpl.DNSNames = []string{"a.test", "b.test"}
		tpl.IPAddresses = []net.IP{net.ParseIP("192.0.2.7"), net.ParseIP("2001:db8::7")}
		tpl.EmailAddresses = []string{"ops@test"}
		tpl.URIs = []*url.URL{{Scheme: "spiffe", Host: "test", Path: "/ns/prod/sa/api"}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertFieldEveryField(t *testing.T) {
	c := makeClientCert(t, "worker-1", big.NewInt(0x2a), true)
	sum := sha256.Sum256(c.Raw)

	for field, want := range map[string]string{
		"cn":          "worker-1",
		"serial":      "2a",
		"fingerprint": hex.EncodeToString(sum[:]),
		"sans":        "a.test,b.test,192.0.2.7,2001:db8::7,ops@test,spiffe://test/ns/prod/sa/api",
		"not_after":   time.Unix(1_900_000_000, 0).UTC().Format(time.RFC3339),
	} {
		got, ok := certField(c, field)
		if got != want || !ok {
			t.Errorf("certField(%q) = %q, %v want %q", field, got, ok, want)
		}
	}
	if got, ok := certField(c, "subject"); !ok || !strings.Contains(got, "CN=worker-1") {
		t.Errorf("subject = %q, %v", got, ok)
	}
	// The certificate is self-signed, so the issuer is its own subject;
	// what matters is that the field answers with a distinguished name
	// rather than an empty string.
	if got, ok := certField(c, "issuer"); !ok || !strings.Contains(got, "CN=worker-1") {
		t.Errorf("issuer = %q, %v", got, ok)
	}

	// The PEM is URL encoded: it must survive as one header value, with
	// no line break a client could use to split the response.
	p, ok := certField(c, "pem")
	if !ok || strings.ContainsAny(p, "\r\n") {
		t.Fatalf("pem = %q, %v", p, ok)
	}
	dec, err := url.QueryUnescape(p)
	if err != nil || !strings.HasPrefix(dec, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("pem does not decode to a certificate: %v", err)
	}

	// The Envoy style value quotes the subject, so a comma or a semicolon
	// in a distinguished name cannot end the element early.
	x, ok := certField(c, "xfcc")
	if !ok {
		t.Fatal("xfcc reported not found")
	}
	for _, want := range []string{"Hash=" + hex.EncodeToString(sum[:]), `Subject="`, "URI=spiffe://test/ns/prod/sa/api", "DNS=a.test", "DNS=b.test"} {
		if !strings.Contains(x, want) {
			t.Errorf("xfcc %q is missing %q", x, want)
		}
	}
	if strings.ContainsAny(x, "\r\n") {
		t.Errorf("xfcc = %q contains a line break", x)
	}

	// A certificate with nothing to say answers "not found" rather than
	// an empty value a header operation would still set.
	bare := makeClientCert(t, "", big.NewInt(1), false)
	if v, ok := certField(bare, "cn"); ok {
		t.Errorf("an empty common name answered %q", v)
	}
	if v, ok := certField(bare, "sans"); ok {
		t.Errorf("a certificate without names answered sans %q", v)
	}
	if v, ok := certField(&x509.Certificate{}, "serial"); ok {
		t.Errorf("a nil serial answered %q", v)
	}
	// Unknown fields never answer; a template asking for one leaves the
	// header unset instead of pasting another field's value.
	for _, f := range []string{"", "CN", "password", "sans;DNS=evil", "pem\r\nX: y"} {
		if v, ok := certField(c, f); ok {
			t.Errorf("certField(%q) = %q, want not found", f, v)
		}
	}
}

// A subject with the characters that end an X-Forwarded-Client-Cert
// element must still produce one element.
func TestCertFieldQuotesHostileSubject(t *testing.T) {
	c := makeClientCert(t, `a;b,c="d"`, big.NewInt(7), false)
	x, ok := certField(c, "xfcc")
	if !ok {
		t.Fatal("xfcc reported not found")
	}
	subject, _ := certField(c, "subject")
	if strings.Contains(x, ";Subject="+subject) || !strings.Contains(x, strconv.Quote(subject)) {
		t.Errorf("xfcc %q does not quote the subject", x)
	}
}

func TestCompileOpsRejectsBadTemplates(t *testing.T) {
	for name, h := range map[string]config.HeaderOps{
		"when":  {When: "client_ip == "},
		"set":   {Set: map[string]string{"X-A": "${nosuchvar}"}},
		"add":   {Add: map[string]string{"X-A": "${nosuchvar}"}},
		"group": {Set: map[string]string{"X-A": "${nogroup}"}},
	} {
		if _, err := compileOps(h, []string{"leader"}); err == nil {
			t.Errorf("compileOps accepted a bad %s", name)
		}
	}

	// A template naming a capture the route defines is accepted, and a
	// route without that group is not.
	if _, err := compileOps(config.HeaderOps{Set: map[string]string{"X-L": "${leader}"}}, []string{"leader"}); err != nil {
		t.Fatalf("a declared capture was refused: %v", err)
	}
	if _, err := compileOps(config.HeaderOps{Set: map[string]string{"X-L": "${leader}"}}, nil); err == nil {
		t.Error("compileOps accepted a capture no route defines")
	}
}

func TestCompiledOpsStripClientCertHeaders(t *testing.T) {
	ops, err := compileOps(config.HeaderOps{
		Remove: []string{"X-Secret"},
		Set:    map[string]string{"X-Client-Cn": "${cert:cn}"},
		Add:    map[string]string{"X-Client-Fp": "${cert:fingerprint}"},
		When:   `method == "POST"`,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ops.static {
		t.Error("templates reading a certificate were called static")
	}
	if len(ops.strip) != 2 {
		t.Fatalf("strip = %v, want both certificate headers", ops.strip)
	}

	// A GET fails the condition, so the operations do not run — but the
	// client's own copy of the identity headers is still removed, which
	// is the whole point of the separate strip list.
	h := http.Header{}
	h.Set("X-Client-Cn", "admin")
	h.Set("X-Client-Fp", "deadbeef")
	h.Set("X-Secret", "keep-me-out")
	get := httptest.NewRequest("GET", "/", nil)
	ops.apply(h, &tvars{r: get})
	if h.Get("X-Client-Cn") != "" || h.Get("X-Client-Fp") != "" {
		t.Errorf("a forged identity survived a request the condition rejected: %v", h)
	}
	if h.Get("X-Secret") != "keep-me-out" {
		t.Error("remove ran although the condition rejected the request")
	}

	// A nil resolver renders every variable empty rather than panicking.
	h2 := http.Header{"X-Client-Cn": []string{"forged"}}
	ops.apply(h2, nil)
	if h2.Get("X-Client-Cn") != "" {
		t.Errorf("a nil resolver left %q", h2.Get("X-Client-Cn"))
	}

	// Without a condition, the operations always run.
	always, err := compileOps(config.HeaderOps{Set: map[string]string{"X-Fixed": "1"}, Remove: []string{"X-Drop"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !always.static {
		t.Error("a constant template was not reported static")
	}
	h3 := http.Header{"X-Drop": []string{"x"}}
	always.apply(h3, nil)
	if h3.Get("X-Fixed") != "1" || h3.Get("X-Drop") != "" {
		t.Errorf("unconditional operations did not run: %v", h3)
	}
}

// ------------------------------------------------------------------- cache

func TestCacheKeyRefusesUncacheableRequests(t *testing.T) {
	rc := &config.RouteCache{Methods: []string{"GET", "HEAD"}, Query: "all"}
	base := func() *http.Request { return httptest.NewRequest("GET", "http://shop.test/p", nil) }

	if cacheKey(rc, base(), "shop.test", "/p", false) == "" {
		t.Fatal("a plain GET has no key")
	}
	cases := map[string]func(*http.Request){
		"an unlisted method":   func(r *http.Request) { r.Method = "POST" },
		"an authorization":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") },
		"a range":              func(r *http.Request) { r.Header.Set("Range", "bytes=0-1") },
		"a cookie":             func(r *http.Request) { r.Header.Set("Cookie", "sid=1") },
		"an encoded path":      func(r *http.Request) { r.URL.RawPath = "/%70" },
		"a rewritten path":     func(r *http.Request) { r.URL.Path = "/other" },
		"a traversal spelling": func(r *http.Request) { r.URL.Path = "/a/../p" },
		"a doubled slash":      func(r *http.Request) { r.URL.Path = "//p" },
	}
	for name, mangle := range cases {
		r := base()
		mangle(r)
		if k := cacheKey(rc, r, "shop.test", "/p", false); k != "" {
			t.Errorf("%s still produced the key %q", name, k)
		}
	}

	// Cookies allowed by the policy do key an entry.
	withCookies := &config.RouteCache{Methods: []string{"GET"}, Query: "all", Cookies: true}
	r := base()
	r.Header.Set("Cookie", "sid=1")
	if cacheKey(withCookies, r, "shop.test", "/p", true) == "" {
		t.Error("cookies: true still refused a request with a cookie")
	}

	// Authentication filters can strip their cookie before the cache lookup.
	// The cookie's presence on the original client request must still bypass a
	// shared cache when cookies are disabled.
	r.Header.Del("Cookie")
	if k := cacheKey(rc, r, "shop.test", "/p", true); k != "" {
		t.Errorf("a stripped client cookie still produced the key %q", k)
	}
}

func TestCacheKeySeparatesVariants(t *testing.T) {
	rc := &config.RouteCache{Methods: []string{"GET", "HEAD"}, Query: "all", Headers: []string{"Accept-Language"}}
	key := func(mangle func(*http.Request)) string {
		r := httptest.NewRequest("GET", "http://shop.test/p?a=1", nil)
		if mangle != nil {
			mangle(r)
		}
		return cacheKey(rc, r, "shop.test", "/p", false)
	}
	base := key(nil)

	// HEAD shares GET's entry: the stored body is what a later GET reads.
	if got := key(func(r *http.Request) { r.Method = "HEAD" }); got != base {
		t.Error("HEAD does not share GET's entry")
	}
	// The raw Host, its case and its port are all part of the key, so a
	// poisoned answer for "shop.test:1337" is not served to everyone.
	for _, h := range []string{"shop.test:1337", "SHOP.TEST:443", "evil.test"} {
		if got := key(func(r *http.Request) { r.Host = h }); got == base {
			t.Errorf("Host %q shares the canonical entry", h)
		}
	}
	// Host case alone folds: a cache is not split by capitalisation.
	if key(func(r *http.Request) { r.Host = "SHOP.TEST" }) != key(func(r *http.Request) { r.Host = "shop.test" }) {
		t.Error("the host's case split the entry")
	}
	// A listed header's value separates variants, an unlisted one does not.
	if key(func(r *http.Request) { r.Header.Set("Accept-Language", "sv") }) == base {
		t.Error("a listed header did not separate the variants")
	}
	if key(func(r *http.Request) { r.Header.Set("X-Unlisted", "sv") }) != base {
		t.Error("an unlisted header separated the variants")
	}
	// Several values of a listed header all reach the key.
	if key(func(r *http.Request) { r.Header.Add("Accept-Language", "sv"); r.Header.Add("Accept-Language", "en") }) ==
		key(func(r *http.Request) { r.Header.Add("Accept-Language", "sv") }) {
		t.Error("a second value of a listed header was dropped from the key")
	}
	// query: all keeps the whole string; query: none ignores it; listed
	// keeps the named parameters in a stable order whatever the request's.
	none := &config.RouteCache{Methods: []string{"GET"}, Query: "none"}
	r1 := httptest.NewRequest("GET", "http://shop.test/p?a=1", nil)
	r2 := httptest.NewRequest("GET", "http://shop.test/p?a=2&b=3", nil)
	if cacheKey(none, r1, "shop.test", "/p", false) != cacheKey(none, r2, "shop.test", "/p", false) {
		t.Error("query: none still split the entries")
	}
	listed := &config.RouteCache{Methods: []string{"GET"}, Query: "listed", QueryParams: []string{"b", "a"}}
	r3 := httptest.NewRequest("GET", "http://shop.test/p?b=3&a=2", nil)
	r4 := httptest.NewRequest("GET", "http://shop.test/p?a=2&b=3", nil)
	if cacheKey(listed, r3, "shop.test", "/p", false) != cacheKey(listed, r4, "shop.test", "/p", false) {
		t.Error("query: listed depends on the order the client sent")
	}
	r5 := httptest.NewRequest("GET", "http://shop.test/p?a=2&b=3&utm=track", nil)
	if cacheKey(listed, r5, "shop.test", "/p", false) != cacheKey(listed, r4, "shop.test", "/p", false) {
		t.Error("an unlisted parameter reached the key")
	}
	// A value whose separators would otherwise run together is escaped.
	r6 := httptest.NewRequest("GET", "http://shop.test/p?a=2%26b%3D9", nil)
	if cacheKey(listed, r6, "shop.test", "/p", false) == cacheKey(listed, r4, "shop.test", "/p", false) {
		t.Error("an escaped separator collided with two real parameters")
	}
}

func TestStorableRefusesWhatMustNotBeShared(t *testing.T) {
	rc := &config.RouteCache{Statuses: []int{200, 404}, TTL: config.Duration(60 * time.Second)}
	req := func() *http.Request { return httptest.NewRequest("GET", "http://shop.test/p", nil) }
	resp := func(mangle func(*http.Response)) *http.Response {
		r := &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: 10}
		if mangle != nil {
			mangle(r)
		}
		return r
	}
	if _, ok := storable(rc, req(), resp(nil), 1<<20); !ok {
		t.Fatal("a plain 200 is not storable")
	}

	refusals := map[string]struct {
		r *http.Request
		p *http.Response
	}{
		"an unlisted status":   {req(), resp(func(r *http.Response) { r.StatusCode = 500 })},
		"a set-cookie":         {req(), resp(func(r *http.Response) { r.Header.Set("Set-Cookie", "sid=1") })},
		"an oversize body":     {req(), resp(func(r *http.Response) { r.ContentLength = 1 << 30 })},
		"vary: *":              {req(), resp(func(r *http.Response) { r.Header.Set("Vary", "*") })},
		"vary with a * listed": {req(), resp(func(r *http.Response) { r.Header.Set("Vary", "Accept, *") })},
		"no-store":             {req(), resp(func(r *http.Response) { r.Header.Set("Cache-Control", "no-store") })},
		"no-cache":             {req(), resp(func(r *http.Response) { r.Header.Set("Cache-Control", "no-cache") })},
		"private":              {req(), resp(func(r *http.Response) { r.Header.Set("Cache-Control", "private") })},
		"max-age=0":            {req(), resp(func(r *http.Response) { r.Header.Set("Cache-Control", "max-age=0") })},
		"s-maxage=0":           {req(), resp(func(r *http.Response) { r.Header.Set("Cache-Control", "s-maxage=0, max-age=99") })},
		"an expiry in the past": {req(), resp(func(r *http.Response) {
			r.Header.Set("Expires", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
		})},
	}
	// A response to an authenticated request is private unless the
	// upstream says otherwise.
	authed := req()
	authed.Header.Set("Authorization", "Bearer x")
	refusals["an authenticated request"] = struct {
		r *http.Request
		p *http.Response
	}{authed, resp(nil)}

	for name, c := range refusals {
		if ttl, ok := storable(rc, c.r, c.p, 1<<20); ok {
			t.Errorf("%s was stored for %s", name, ttl)
		}
	}

	// public re-admits the authenticated response.
	if _, ok := storable(rc, authed, resp(func(r *http.Response) { r.Header.Set("Cache-Control", "public") }), 1<<20); !ok {
		t.Error("an explicitly public response to an authenticated request was refused")
	}
	// ignore_cache_control takes the route's lifetime whatever the
	// upstream said, no-store included.
	ign := &config.RouteCache{Statuses: []int{200}, TTL: config.Duration(30 * time.Second), IgnoreCacheControl: true}
	if ttl, ok := storable(ign, req(), resp(func(r *http.Response) { r.Header.Set("Cache-Control", "no-store") }), 1<<20); !ok || ttl != 30*time.Second {
		t.Errorf("ignore_cache_control gave %s, %v", ttl, ok)
	}
	// A lifetime is taken from s-maxage first, then max-age, then Expires.
	for header, want := range map[string]time.Duration{
		"s-maxage=120, max-age=5": 120 * time.Second,
		"max-age=5":               5 * time.Second,
	} {
		ttl, ok := storable(rc, req(), resp(func(r *http.Response) { r.Header.Set("Cache-Control", header) }), 1<<20)
		if !ok || ttl != want {
			t.Errorf("%q gave %s, %v want %s", header, ttl, ok, want)
		}
	}
	// An upstream cannot make an entry immortal: a date in the year 9999
	// and an absurd max-age are both cut to the configured ceiling.
	far := resp(func(r *http.Response) { r.Header.Set("Expires", "Fri, 31 Dec 9999 23:59:59 GMT") })
	if ttl, ok := storable(rc, req(), far, 1<<20); !ok || ttl != maxCacheTTL {
		t.Errorf("a far future Expires gave %s, %v", ttl, ok)
	}
	huge := resp(func(r *http.Response) { r.Header.Set("Cache-Control", "max-age=999999999999") })
	if ttl, ok := storable(rc, req(), huge, 1<<20); !ok || ttl != maxCacheTTL {
		t.Errorf("an absurd max-age gave %s, %v", ttl, ok)
	}
	// An unparseable Expires leaves the route's lifetime in place.
	bad := resp(func(r *http.Response) { r.Header.Set("Expires", "not a date") })
	if ttl, ok := storable(rc, req(), bad, 1<<20); !ok || ttl != 60*time.Second {
		t.Errorf("an unparseable Expires gave %s, %v", ttl, ok)
	}
	// An unknown length (-1) is below every ceiling and stays storable;
	// the body limit is enforced as the body streams instead.
	if _, ok := storable(rc, req(), resp(func(r *http.Response) { r.ContentLength = -1 }), 1<<20); !ok {
		t.Error("a chunked response was refused before its body was read")
	}
	// A named Vary is fine.
	if _, ok := storable(rc, req(), resp(func(r *http.Response) { r.Header.Set("Vary", "Accept-Encoding") }), 1<<20); !ok {
		t.Error("a named Vary was refused")
	}
}

func TestEtagMatchesEdges(t *testing.T) {
	cases := []struct {
		inm, etag string
		want      bool
	}{
		{"", `"a"`, false},
		{"*", `"a"`, true},
		{`"a"`, `"a"`, true},
		{` "a" `, `"a"`, true},
		{`"b", "a"`, `"a"`, true},
		{`"b","c"`, `"a"`, false},
		{`W/"a"`, `"a"`, false},
		{`"a"`, `W/"a"`, false},
		{`"a`, `"a"`, false},
		{",,,", `"a"`, false},
		{strings.Repeat(`"x",`, 1000) + `"a"`, `"a"`, true},
	}
	for _, c := range cases {
		if got := etagMatches(c.inm, c.etag); got != c.want {
			t.Errorf("etagMatches(%q, %q) = %v want %v", c.inm, c.etag, got, c.want)
		}
	}
	// A "*" that is only part of a value is not the wildcard.
	if etagMatches(`"*"`, `"a"`) {
		t.Error(`a quoted star matched every entity tag`)
	}
}

// ---------------------------------------------------------------- compression

func TestAcceptEncodingsParsing(t *testing.T) {
	enc := func(v string) map[string]float64 {
		r := httptest.NewRequest("GET", "/", nil)
		if v != "" {
			r.Header.Set("Accept-Encoding", v)
		}
		return acceptEncodings(r)
	}
	if enc("") != nil {
		t.Error("a missing header produced a map")
	}
	q := enc("GZIP;q=0.5, br, x-gzip;q=0.9, ;q=1, zstd;Q=0.25, identity;q=nonsense, deflate;q=")
	for name, want := range map[string]float64{"gzip": 0.9, "br": 1, "zstd": 0.25, "identity": 1, "deflate": 1} {
		if got := q[name]; got != want {
			t.Errorf("%s = %v want %v", name, got, want)
		}
	}
	if _, ok := q[""]; ok {
		t.Error("an empty element produced an encoding")
	}
	// Quality zero means "not acceptable".
	for _, v := range []string{"gzip;q=0", "gzip;q=0.0", "*;q=0"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", v)
		if wantsGzip(r) {
			t.Errorf("%q was read as accepting gzip", v)
		}
	}
	for _, v := range []string{"gzip", "*", "br, gzip;q=0.1", "x-gzip"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", v)
		if !wantsGzip(r) {
			t.Errorf("%q was read as refusing gzip", v)
		}
	}
	// An explicit gzip;q=0 beats a wildcard that would allow it.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "*, gzip;q=0")
	if wantsGzip(r) {
		t.Error("an explicit refusal lost to the wildcard")
	}
}

func TestEligibleTypeRefusesMalformed(t *testing.T) {
	p := newCompressPolicy(&config.Compression{Encodings: []string{"gzip"}, Level: 5, MinBytes: 8, Types: []string{"text/html", "application/json"}})
	for _, ct := range []string{"text/html", "text/html; charset=utf-8", "TEXT/HTML", "application/json ;x=1"} {
		if !p.eligibleType(ct) {
			t.Errorf("eligibleType(%q) = false", ct)
		}
	}
	for _, ct := range []string{"", "image/png", "text/html/extra", "text/html; charset=", `text/html; charset="`, "/", "text-html"} {
		if p.eligibleType(ct) {
			t.Errorf("eligibleType(%q) = true", ct)
		}
	}
}

// plainWriter is a ResponseWriter that is deliberately not a Hijacker or
// a Flusher, so the wrappers' fallbacks are reached.
type plainWriter struct {
	h      http.Header
	status int
	body   bytes.Buffer
}

func (p *plainWriter) Header() http.Header {
	if p.h == nil {
		p.h = http.Header{}
	}
	return p.h
}
func (p *plainWriter) WriteHeader(code int)        { p.status = code }
func (p *plainWriter) Write(b []byte) (int, error) { return p.body.Write(b) }

// hijackWriter reports a successful hijack without a real connection.
type hijackWriter struct {
	plainWriter
	err error
}

func (h *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.err != nil {
		return nil, nil, h.err
	}
	c1, _ := net.Pipe()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

func TestCompressWriterHijackAndUnwrap(t *testing.T) {
	pol := newCompressPolicy(&config.Compression{Encodings: []string{"gzip"}, Level: 5, MinBytes: 8, Types: []string{"text/plain"}})

	// A writer that cannot be hijacked says so rather than panicking, and
	// the wrapper is not marked hijacked.
	plain := &plainWriter{}
	w := newCompressWriter(plain, pol, "gzip")
	if _, _, err := w.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Errorf("Hijack on a plain writer = %v", err)
	}
	if w.hijacked {
		t.Error("a refused hijack still marked the writer hijacked")
	}
	if w.Unwrap() != http.ResponseWriter(plain) {
		t.Error("Unwrap did not return the wrapped writer")
	}

	// A hijack that fails leaves the writer usable.
	failing := &hijackWriter{err: errors.New("no")}
	w2 := newCompressWriter(failing, pol, "gzip")
	if _, _, err := w2.Hijack(); err == nil {
		t.Error("a failing hijack reported success")
	}
	if w2.hijacked {
		t.Error("a failed hijack marked the writer hijacked")
	}

	// After a successful hijack the wrapper must write nothing more: the
	// connection now belongs to the protocol that took it over, and a
	// gzip trailer appended there would corrupt it.
	hw := &hijackWriter{}
	w3 := newCompressWriter(hw, pol, "gzip")
	w3.Header().Set("Content-Type", "text/plain")
	_, _ = w3.Write([]byte("hello"))
	conn, _, err := w3.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	before := hw.body.Len()
	w3.Close()
	w3.Close() // idempotent
	if hw.body.Len() != before {
		t.Errorf("Close wrote %d bytes after the connection was hijacked", hw.body.Len()-before)
	}
}

func TestCompressWriterUndecidedBodies(t *testing.T) {
	pol := newCompressPolicy(&config.Compression{Encodings: []string{"gzip"}, Level: 5, MinBytes: 64, Types: []string{"text/plain"}})

	// A short body of unknown length is decided at Close: sent as it is,
	// with the length the handler never set.
	p := &plainWriter{}
	w := newCompressWriter(p, pol, "gzip")
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("short"))
	if p.body.Len() != 0 {
		t.Error("an undecided body reached the client before Close")
	}
	w.Close()
	if p.body.String() != "short" {
		t.Errorf("body = %q", p.body.String())
	}
	if got := p.Header().Get("Content-Length"); got != "5" {
		t.Errorf("Content-Length = %q want 5", got)
	}
	if p.Header().Get("Content-Encoding") != "" {
		t.Error("a body below min_bytes was compressed")
	}
	if p.Header().Get("Vary") == "" {
		t.Error("Vary: Accept-Encoding is missing from an eligible response")
	}

	// A flush decides at once, so a stream is compressed rather than held.
	p2 := &plainWriter{}
	w2 := newCompressWriter(p2, pol, "gzip")
	w2.Header().Set("Content-Type", "text/plain")
	_, _ = w2.Write([]byte("tiny"))
	w2.Flush()
	if p2.Header().Get("Content-Encoding") != "gzip" {
		t.Error("a flushed stream was not compressed")
	}
	if p2.Header().Get("Content-Length") != "" {
		t.Error("a compressed stream kept a length")
	}
	w2.Close()

	// A known length below min_bytes commits at once and is never held.
	p3 := &plainWriter{}
	w3 := newCompressWriter(p3, pol, "gzip")
	p3.Header().Set("Content-Type", "text/plain")
	p3.Header().Set("Content-Length", "3")
	w3.WriteHeader(200)
	if w3.pending {
		t.Error("a short known length was held")
	}
	_, _ = w3.Write([]byte("abc"))
	w3.Close()
	if p3.body.String() != "abc" {
		t.Errorf("body = %q", p3.body.String())
	}

	// A response the policy must not touch commits as it is: the status
	// carries no body, the encoding is already set, a range is in flight
	// or the upstream asked for no transformation.
	for name, set := range map[string]func(http.Header){
		"204":              nil,
		"an encoding":      func(h http.Header) { h.Set("Content-Encoding", "br") },
		"a range":          func(h http.Header) { h.Set("Content-Range", "bytes 0-1/9") },
		"no-transform":     func(h http.Header) { h.Set("Cache-Control", "No-Transform") },
		"an unlisted type": func(h http.Header) { h.Set("Content-Type", "image/png") },
	} {
		pw := &plainWriter{}
		cw := newCompressWriter(pw, pol, "gzip")
		code := 200
		if name == "204" {
			code = http.StatusNoContent
		} else {
			cw.Header().Set("Content-Type", "text/plain")
		}
		if set != nil {
			set(cw.Header())
		}
		cw.WriteHeader(code)
		if cw.pending || cw.compress {
			t.Errorf("%s was not committed as it is", name)
		}
		if pw.Header().Get("Vary") != "" {
			t.Errorf("%s gained a Vary although it is never compressed", name)
		}
		cw.Close()
	}

	// A second WriteHeader is ignored, and Close without any write leaves
	// the handler's own status alone.
	p4 := &plainWriter{}
	w4 := newCompressWriter(p4, pol, "gzip")
	w4.WriteHeader(404)
	w4.WriteHeader(500)
	if p4.status != 404 {
		t.Errorf("status = %d, want the first one", p4.status)
	}
	p5 := &plainWriter{}
	w5 := newCompressWriter(p5, pol, "gzip")
	w5.Close()
	if p5.status != 0 {
		t.Errorf("Close on an unused writer sent %d", p5.status)
	}
}

func TestResponseWriterRecordsWhatWasSent(t *testing.T) {
	p := &plainWriter{}
	w := &responseWriter{ResponseWriter: p}
	if w.Status() != 0 {
		t.Errorf("an unused writer reports status %d", w.Status())
	}
	// A body without a status is a 200, counted once.
	n, err := w.Write([]byte("abcd"))
	if n != 4 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if w.Status() != 200 || w.bytes != 4 {
		t.Errorf("status %d, bytes %d", w.Status(), w.bytes)
	}
	// A late status cannot overwrite what the client already got.
	w.WriteHeader(500)
	if w.Status() != 200 || p.status != 200 {
		t.Errorf("a late WriteHeader changed the status to %d/%d", w.Status(), p.status)
	}
	_, _ = w.Write([]byte("ef"))
	if w.bytes != 6 {
		t.Errorf("bytes = %d want 6", w.bytes)
	}
	// Flush on a writer that cannot flush still commits the status.
	w2 := &responseWriter{ResponseWriter: &plainWriter{}}
	w2.Flush()
	if w2.Status() != 200 {
		t.Errorf("Flush left the status at %d", w2.Status())
	}
	// A hijack that succeeds is recorded as 101 so the access log does
	// not claim the request was never answered.
	w3 := &responseWriter{ResponseWriter: &hijackWriter{}}
	c, _, err := w3.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if !w3.hijacked || w3.Status() != http.StatusSwitchingProtocols {
		t.Errorf("hijacked %v, status %d", w3.hijacked, w3.Status())
	}
	// A hijack that fails changes nothing.
	w4 := &responseWriter{ResponseWriter: &hijackWriter{err: errors.New("no")}}
	if _, _, err := w4.Hijack(); err == nil || w4.hijacked || w4.Status() != 0 {
		t.Errorf("a failed hijack left %v / %d", w4.hijacked, w4.Status())
	}
	// A writer that is not a hijacker at all.
	w5 := &responseWriter{ResponseWriter: &plainWriter{}}
	if _, _, err := w5.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Errorf("Hijack on a plain writer = %v", err)
	}
	if w5.Unwrap() == nil {
		t.Error("Unwrap returned nothing")
	}
}

// ------------------------------------------------------------- layer 4 bits

func TestAddrOfEdges(t *testing.T) {
	cases := map[string]string{
		"198.51.100.9:443":      "198.51.100.9",
		"198.51.100.9":          "198.51.100.9",
		"[2001:db8::1]:443":     "2001:db8::1",
		"2001:db8::1":           "2001:db8::1",
		"[::ffff:192.0.2.1]:80": "192.0.2.1", // a mapped address is unmapped
		"::ffff:192.0.2.1":      "192.0.2.1",
	}
	for in, want := range cases {
		if got := netutil.AddrOf(in); got.String() != want {
			t.Errorf("netutil.AddrOf(%q) = %v want %v", in, got, want)
		}
	}
	for _, in := range []string{"", "host.test:443", "host.test", "999.1.1.1:1", ":443", "198.51.100.9:notaport:1", "[2001:db8::1", "\x00"} {
		if got := netutil.AddrOf(in); got.IsValid() {
			t.Errorf("netutil.AddrOf(%q) = %v, want the zero address", in, got)
		}
	}
	// A zone is not silently dropped into a different address.
	if got := netutil.AddrOf("fe80::1%eth0"); got.IsValid() && got.Zone() != "eth0" {
		t.Errorf("addrOf of a zoned address = %v", got)
	}
}

// ------------------------------------------------------------------ framing

func TestFramingProblemDetectsSmuggling(t *testing.T) {
	req := func(mangle func(*http.Request)) *http.Request {
		r := httptest.NewRequest("POST", "http://shop.test/", strings.NewReader("x"))
		mangle(r)
		return r
	}
	cases := map[string]struct {
		mangle func(*http.Request)
		want   string
	}{
		"one length": {func(r *http.Request) { r.Header.Set("Content-Length", "1") }, ""},
		"two equal lengths": {func(r *http.Request) {
			r.Header["Content-Length"] = []string{"1", " 1 "}
		}, ""},
		"two different lengths": {func(r *http.Request) {
			r.Header["Content-Length"] = []string{"1", "9"}
		}, "framing_content_length"},
		"three, the last differing": {func(r *http.Request) {
			r.Header["Content-Length"] = []string{"1", "1", "42"}
		}, "framing_content_length"},
		"a coding and a length": {func(r *http.Request) {
			r.Header.Set("Transfer-Encoding", "chunked")
			r.Header.Set("Content-Length", "1")
		}, "framing_te_cl"},
		"an unknown coding": {func(r *http.Request) {
			r.Header.Set("Transfer-Encoding", "gzip")
		}, "framing_transfer_encoding"},
		"a coding list ending in chunked": {func(r *http.Request) {
			r.Header.Set("Transfer-Encoding", "gzip, chunked")
		}, "framing_transfer_encoding"},
		"identity": {func(r *http.Request) {
			r.Header.Set("Transfer-Encoding", "Identity")
		}, ""},
		"a parsed coding beside a length": {func(r *http.Request) {
			r.TransferEncoding = []string{"chunked"}
			r.Header.Set("Content-Length", "1")
		}, "framing_te_cl"},
		"a parsed coding nobody knows": {func(r *http.Request) {
			r.TransferEncoding = []string{"x-banana"}
		}, "framing_transfer_encoding"},
		"nothing at all": {func(r *http.Request) { r.Header.Del("Content-Length") }, ""},
	}
	for name, c := range cases {
		if got := framingProblem(req(c.mangle)); got != c.want {
			t.Errorf("%s gave %q want %q", name, got, c.want)
		}
	}
}

// ------------------------------------------------------------- error pages

func TestErrorPagesLookupFallsBack(t *testing.T) {
	if (*errorPages)(nil).lookup(404) != nil {
		t.Error("a nil page set answered")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	e, err := loadErrorPages(&config.ErrorPages{Dir: dir, Pages: map[string]string{
		"404":     write("404.html", "exact ${status}"),
		"5xx":     write("5xx.html", "class ${status}"),
		"default": write("default.html", "default ${status}"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for status, want := range map[int]string{404: "exact", 500: "class", 503: "class", 400: "default", 302: "default"} {
		tp := e.lookup(status)
		if tp == nil {
			t.Fatalf("no page for %d", status)
		}
		if got := tp.Expand(&tvars{status: status}); !strings.HasPrefix(got, want) {
			t.Errorf("status %d rendered %q want the %s page", status, got, want)
		}
	}
	// Without a default, an unmatched status has no page at all and the
	// caller falls back to the plain status line.
	e2, err := loadErrorPages(&config.ErrorPages{Dir: dir, Pages: map[string]string{"404": write("only404.html", "x")}})
	if err != nil {
		t.Fatal(err)
	}
	if e2.lookup(500) != nil {
		t.Error("a page set without a default answered for 500")
	}
	// A document that is not there at all is a configuration error, not a
	// silent empty page.
	if _, err := loadErrorPages(&config.ErrorPages{Dir: dir, Pages: map[string]string{"404": filepath.Join(dir, "absent.html")}}); err == nil {
		t.Error("loadErrorPages accepted a missing document")
	}
	// An error page is a document, so a "${...}" that is not a variable
	// stays in the text rather than failing the load or, worse, being
	// dropped: a page explaining shell or CSS syntax still renders.
	e3, err := loadErrorPages(&config.ErrorPages{Dir: dir, Pages: map[string]string{
		"default": write("literal.html", "${nosuchvariable} and ${unterminated"),
	}})
	if err != nil {
		t.Fatalf("a document with a literal placeholder was refused: %v", err)
	}
	if got := e3.lookup(404).Expand(&tvars{}); got != "${nosuchvariable} and ${unterminated" {
		t.Errorf("a literal placeholder rendered as %q", got)
	}
}

func TestWantsJSON(t *testing.T) {
	cases := map[string]bool{
		"":                            false,
		"text/html":                   false,
		"application/json":            true,
		"application/json, text/html": true,
		"text/html, application/json": false,
		"*/*":                         false,
		"application/json;q=0.1, text/html;q=0.9": true, // position, not quality
	}
	for accept, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		if got := wantsJSON(r); got != want {
			t.Errorf("wantsJSON(%q) = %v want %v", accept, got, want)
		}
	}
}

// ------------------------------------------------------------- odds and ends

func TestTrimIsByteBounded(t *testing.T) {
	if got := trim("abcdef", 3); got != "abc" {
		t.Errorf("trim = %q", got)
	}
	if got := trim("ab", 8); got != "ab" {
		t.Errorf("trim = %q", got)
	}
	if got := trim("", 0); got != "" {
		t.Errorf("trim = %q", got)
	}
	// The bound is on bytes, so a multi-byte rune may be cut in half; the
	// result is still at most n bytes, which is what the key table needs.
	if got := trim("äöå", 3); len(got) != 3 {
		t.Errorf("trim of a multi-byte string is %d bytes", len(got))
	}
	long := strings.Repeat("k", 1<<16)
	if got := trim(long, 256); len(got) != 256 {
		t.Errorf("a long value trimmed to %d bytes", len(got))
	}
}

func TestAuthKindNamesTheCredential(t *testing.T) {
	kind := func(mangle func(*http.Request)) string {
		r := httptest.NewRequest("GET", "/", nil)
		mangle(r)
		return authKind(r)
	}
	cases := map[string]struct {
		mangle func(*http.Request)
		want   string
	}{
		"bearer":       {func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") }, "bearer"},
		"BEARER":       {func(r *http.Request) { r.Header.Set("Authorization", "BEARER x") }, "bearer"},
		"basic":        {func(r *http.Request) { r.Header.Set("Authorization", "basic x") }, "basic"},
		"negotiate":    {func(r *http.Request) { r.Header.Set("Authorization", "Negotiate x") }, "other"},
		"no scheme":    {func(r *http.Request) { r.Header.Set("Authorization", "opaque") }, "other"},
		"api key":      {func(r *http.Request) { r.Header.Set("X-Api-Key", "k") }, "api_key"},
		"api key alt":  {func(r *http.Request) { r.Header.Set("Api-Key", "k") }, "api_key"},
		"cookie":       {func(r *http.Request) { r.Header.Set("Cookie", "sid=1") }, "cookie"},
		"nothing":      {func(r *http.Request) {}, "none"},
		"an empty TLS": {func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, "none"},
	}
	for name, c := range cases {
		if got := kind(c.mangle); got != c.want {
			t.Errorf("%s = %q want %q", name, got, c.want)
		}
	}
	// A client certificate is the last thing looked at, so a request that
	// also carries a header is named by the header.
	r := httptest.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{makeClientCert(t, "c", big.NewInt(1), false)}}
	if got := authKind(r); got != "client_cert" {
		t.Errorf("a client certificate = %q", got)
	}
	r.Header.Set("Authorization", "Bearer x")
	if got := authKind(r); got != "bearer" {
		t.Errorf("a bearer token beside a certificate = %q", got)
	}
}

func TestMediaTypeNormalises(t *testing.T) {
	cases := map[string]string{
		"":                            "",
		"application/json":            "application/json",
		"APPLICATION/JSON; charset=x": "application/json",
		"  text/plain  ":              "text/plain",
		";":                           "",
		// Go's own parser tolerates a trailing semicolon with no
		// parameter after it, and normalising it to the bare type is
		// what an inventory wants: every server accepts the header, so
		// refusing to record it would lose an endpoint rather than
		// catching an attack.
		"text/plain;":      "text/plain",
		"not a media type": "",
		"application/" + strings.Repeat("x", apiinv.MaxMediaTypeBytes): "",
	}
	for in, want := range cases {
		if got := mediaType(in); got != want {
			t.Errorf("mediaType(%q) = %q want %q", in, got, want)
		}
	}
}

func TestCoarseKeyCollapsesRotation(t *testing.T) {
	// Every address of a /24 shares one key, so an attacker who rotates
	// the last octet does not buy a fresh bucket.
	a := coarseKey(netip.MustParseAddr("198.51.100.1"))
	b := coarseKey(netip.MustParseAddr("198.51.100.254"))
	if a == "" || a != b {
		t.Errorf("coarse keys %q and %q differ", a, b)
	}
	if c := coarseKey(netip.MustParseAddr("198.51.101.1")); c == a {
		t.Error("a neighbouring network shares the key")
	}
	// IPv6 collapses to a /48, which is the smallest block a site is
	// normally given.
	v6a := coarseKey(netip.MustParseAddr("2001:db8:1::1"))
	v6b := coarseKey(netip.MustParseAddr("2001:db8:1:ffff::ffff"))
	if v6a == "" || v6a != v6b {
		t.Errorf("IPv6 coarse keys %q and %q differ", v6a, v6b)
	}
	if c := coarseKey(netip.MustParseAddr("2001:db8:2::1")); c == v6a {
		t.Error("a neighbouring /48 shares the key")
	}
	// A mapped IPv4 address is treated as the IPv4 address it is.
	if coarseKey(netip.MustParseAddr("::ffff:198.51.100.1")) != a {
		t.Error("a mapped address got its own key")
	}
	// The zero address has no prefix and no key.
	if got := coarseKey(netip.Addr{}); got != "" {
		t.Errorf("the zero address gave %q", got)
	}
}

func TestErrReaderAlwaysFails(t *testing.T) {
	want := errors.New("gone")
	r := &errReader{err: want}
	n, err := r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, want) {
		t.Errorf("Read = %d, %v", n, err)
	}
	// Reading it again gives the same answer; io.ReadAll ends rather than
	// spinning.
	if _, err := io.ReadAll(r); !errors.Is(err, want) {
		t.Errorf("ReadAll = %v", err)
	}
}

func TestMarksDroppedCountsRefusals(t *testing.T) {
	m := newMarks()
	if m.Dropped() != 0 {
		t.Fatalf("a fresh table reports %d drops", m.Dropped())
	}
	now := time.Now()
	// A peer may not fill the table on its own: past its share, new
	// addresses are refused and counted.
	for i := 0; i < maxPeerMarks+16; i++ {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i % 256)})
		if i >= 256 {
			ip = netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)})
		}
		m.addFrom(ip, "r", time.Minute, now, "peer-a")
	}
	if m.Dropped() != 0 {
		t.Errorf("a peer's own share counted against the whole table: %d", m.Dropped())
	}
	if n := len(m.list(now)); n > maxPeerMarks {
		t.Errorf("a single peer placed %d marks, past its share of %d", n, maxPeerMarks)
	}
	// An invalid address is never recorded.
	before := len(m.list(now))
	m.add(netip.Addr{}, "r", time.Minute, now)
	if len(m.list(now)) != before {
		t.Error("the zero address was marked")
	}
}

// ---------------------------------------------------------------- static

func TestStaticOpenRefusesSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	ss := &staticSite{cfg: &config.RouteStatic{Root: dir}, root: root}
	f, info, err := ss.open("ok.txt")
	if err != nil {
		t.Fatalf("a regular file: %v", err)
	}
	if info.Size() != 2 {
		t.Errorf("size = %d", info.Size())
	}
	_ = f.Close()

	// A name that is not there.
	if _, _, err := ss.open("absent.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file gave %v", err)
	}

	// A directory opens (the caller decides about an index), a device or
	// a socket never does: serving one would hand the client whatever the
	// kernel produces, or block the request for ever.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, i, err := ss.open("sub"); err != nil || !i.IsDir() {
		t.Errorf("a directory gave %v", err)
	}
	// A socket is never served: the kernel refuses the open outright,
	// which is the behaviour the caller turns into a 404.
	if l, err := net.Listen("unix", filepath.Join(dir, "sock")); err == nil {
		defer l.Close()
		if f, _, err := ss.open("sock"); err == nil {
			_ = f.Close()
			t.Error("a socket was opened for serving")
		}
	}
}

func TestHasDotSegment(t *testing.T) {
	for _, p := range []string{".git/config", "a/.env", "a/.git/b", ".ssh/id", "a/b/.htaccess", "a/..", "..."} {
		if !hasDotSegment(p) {
			t.Errorf("hasDotSegment(%q) = false", p)
		}
	}
	// A single dot is one byte long, so it is not treated as a hidden
	// name; path cleaning has already removed it by this point.
	for _, p := range []string{"", ".", "a/./b", "a/b.txt", "a/b/c", "x.y/z"} {
		if hasDotSegment(p) {
			t.Errorf("hasDotSegment(%q) = true", p)
		}
	}
}

// ------------------------------------------------------------- cluster events

func TestEventBusDispatch(t *testing.T) {
	b := newEventBus(nil)
	// Nothing subscribed: dispatch reports that the event went nowhere,
	// which is what tells the server to handle the kind itself.
	if b.dispatch(cluster.Event{Kind: "ban", Key: "1.2.3.4"}) {
		t.Error("dispatch reported a subscriber for an unknown kind")
	}
	// An empty kind and a nil function are both refused rather than
	// producing a subscription that can never fire or one that panics.
	b.Subscribe("", func(filter.Event) {})
	b.Subscribe("ban", nil)
	if b.dispatch(cluster.Event{Key: "x"}) {
		t.Error("the empty kind gained a subscriber")
	}
	if b.dispatch(cluster.Event{Kind: "ban", Key: "1.2.3.4"}) {
		t.Error("a nil function was subscribed")
	}
	// Two subscribers of one kind both see the event, with its fields.
	var seen []filter.Event
	for i := 0; i < 2; i++ {
		b.Subscribe("ban", func(e filter.Event) { seen = append(seen, e) })
	}
	until := time.Now().Add(time.Minute).Round(0)
	if !b.dispatch(cluster.Event{Kind: "ban", Key: "1.2.3.4", Until: until}) {
		t.Fatal("dispatch reported no subscriber")
	}
	if len(seen) != 2 {
		t.Fatalf("%d subscribers fired", len(seen))
	}
	for _, e := range seen {
		if e.Kind != "ban" || e.Key != "1.2.3.4" || !e.Until.Equal(until) {
			t.Errorf("event = %+v", e)
		}
	}
	// A publisher without a server does not panic: a generation whose
	// server is gone must not take the process with it.
	b.Publish(filter.Event{Kind: "ban", Key: "1.2.3.4"})
}
