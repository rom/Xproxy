package http

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const rateKeysYAML = `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
trusted_proxies: [127.0.0.0/8]
rate_limits:
  - {name: by-cookie, key: "cookie:sid", algorithm: sliding_window, limit: 1, window: 1m}
  - {name: by-net, key: client_net, net_v4: 16, algorithm: sliding_window, limit: 1, window: 1m}
  - {name: by-endpoint, key: endpoint, algorithm: sliding_window, limit: 1, window: 1m}
  - {name: by-claim, key: "jwt:sub", algorithm: sliding_window, limit: 1, window: 1m}
  - {name: by-ja4, key: ja4, algorithm: sliding_window, limit: 1, window: 1m}
upstreams:
  - name: app
    endpoints: [{address: %s}]
routes:
  - {name: cookie, paths: [/cookie], upstream: app, rate_limits: [by-cookie]}
  - {name: net, paths: [/net], upstream: app, rate_limits: [by-net]}
  - {name: endpoint, paths: [/ep], upstream: app, rate_limits: [by-endpoint]}
  - {name: claim, paths: [/claim], upstream: app, rate_limits: [by-claim]}
  - {name: ja4, paths: [/ja4], upstream: app, rate_limits: [by-ja4]}
`

func TestRateLimitKeys(t *testing.T) {
	a := newBackend(t, "a")
	_, url := startServer(t, fmt.Sprintf(rateKeysYAML, a.addr()))
	status := func(path string, hdr ...string) int {
		t.Helper()
		r, _ := http.NewRequest("GET", url+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Add(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// Cookie key: one bucket per session, the address for cookieless clients.
	if a, b := status("/cookie", "Cookie", "sid=one"), status("/cookie", "Cookie", "sid=one"); a != 200 || b != 429 {
		t.Fatalf("cookie bucket: %d %d", a, b)
	}
	if got := status("/cookie", "Cookie", "sid=two"); got != 200 {
		t.Fatalf("other cookie shares the bucket: %d", got)
	}
	if a, b := status("/cookie"), status("/cookie"); a != 200 || b != 429 {
		t.Fatalf("cookieless fallback: %d %d", a, b)
	}
	// Network key: two addresses in the same /16 share a bucket, another /16 does not.
	if a, b := status("/net", "X-Forwarded-For", "203.0.113.10"), status("/net", "X-Forwarded-For", "203.0.200.7"); a != 200 || b != 429 {
		t.Fatalf("net bucket: %d %d", a, b)
	}
	if got := status("/net", "X-Forwarded-For", "198.51.100.1"); got != 200 {
		t.Fatalf("other network: %d", got)
	}
	if a, b := status("/net", "X-Forwarded-For", "2001:db8:1:2::1"), status("/net", "X-Forwarded-For", "2001:db8:1:ffff::9"); a != 200 || b != 429 {
		t.Fatalf("ipv6 /48 bucket: %d %d", a, b)
	}
	// Endpoint key: identifiers collapse into one template per method and route.
	if a, b := status("/ep/users/1"), status("/ep/users/2"); a != 200 || b != 429 {
		t.Fatalf("endpoint template: %d %d", a, b)
	}
	if got := status("/ep/orders/1"); got != 200 {
		t.Fatalf("other endpoint: %d", got)
	}
	r, _ := http.NewRequest("POST", url+"/ep/users/3", nil)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("other method: %d", resp.StatusCode)
	}
	// JWT claim key without verification: the sub names the bucket.
	tok := func(sub string) string {
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sub + `","n":1}`))
		return "Bearer eyJhbGciOiJub25lIn0." + payload + ".sig"
	}
	if a, b := status("/claim", "Authorization", tok("alice")), status("/claim", "Authorization", tok("alice")); a != 200 || b != 429 {
		t.Fatalf("claim bucket: %d %d", a, b)
	}
	if got := status("/claim", "Authorization", tok("bob")); got != 200 {
		t.Fatalf("other subject: %d", got)
	}
	if a, b := status("/claim", "Authorization", "Bearer garbage"), status("/claim", "Authorization", "Bearer garbage"); a != 200 || b != 429 {
		t.Fatalf("unparseable token falls back to the address: %d %d", a, b)
	}
	// JA4 on a plaintext listener falls back to the address.
	if a, b := status("/ja4"), status("/ja4"); a != 200 || b != 429 {
		t.Fatalf("ja4 fallback: %d %d", a, b)
	}
}

func TestBearerClaim(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1","exp":1700000000,"admin":true,"list":[1]}`))
	tok := "h." + payload + ".s"
	for _, tc := range []struct{ auth, claim, want string }{
		{"Bearer " + tok, "sub", "u1"},
		{"bearer " + tok, "exp", "1700000000"},
		{"Bearer " + tok, "admin", "true"},
		{"Bearer " + tok, "list", ""},
		{"Bearer " + tok, "missing", ""},
		{"Basic abc", "sub", ""},
		{"Bearer a.b", "sub", ""},
		{"Bearer a.!!!.c", "sub", ""},
	} {
		if got := bearerClaim(tc.auth, tc.claim); got != tc.want {
			t.Errorf("bearerClaim(%q,%q)=%q want %q", tc.auth, tc.claim, got, tc.want)
		}
	}
	_ = httptest.NewRecorder()
}
