package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/testutil"
)

// TestBotScoreOverTLS: the TLS fingerprint of the connection reaches the
// filter, the score is forwarded upstream, a scripted client on a browser
// user agent is challenged when a challenge section exists, and a curl
// client above deny_at is refused.
func TestBotScoreOverTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "tls.test")
	backend := newBackend(t, "a")
	yaml := `
version: 1
server:
  listeners:
    - name: tls
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
logging:
  access: {enabled: false}
challenge: {secret_file: %s/challenge.key}
filters:
  - name: bots
    kind: bot_score
    options: {challenge_at: 50, deny_at: 80, header: X-Bot-Score, weights: {ua_bot: 90}}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
routes:
  - name: all
    paths: ["/"]
    filters: [bots]
    upstream: app
`
	s, _ := startServer(t, fmt.Sprintf(yaml, cert, key, dir, backend.addr()))
	addr := s.Addrs()["tls"]
	client := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "tls.test"}}} //nolint:gosec // test
	do := func(ua string, hdr ...string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", "https://"+addr+"/page", nil)
		req.Host = "tls.test"
		req.Header.Set("User-Agent", ua)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(body)
	}
	// Go's client on a browser user agent without browser headers: the
	// hello has ALPN h2 and enough ciphers, so only the headers signal
	// (25) fires: served, with the score forwarded.
	resp, body := do("Mozilla/5.0 Chrome/128.0")
	if resp.StatusCode != 200 || body != "a:/page" {
		t.Fatalf("browser-ish client: %d %q", resp.StatusCode, body)
	}
	last := backend.last.Load()
	if last.Header.Get("X-Bot-Score") != "25" {
		t.Fatalf("score header %q", last.Header.Get("X-Bot-Score"))
	}
	// curl user agent with ua_bot weighted to 90: denied.
	resp, _ = do("curl/8.4.0")
	if resp.StatusCode != 403 {
		t.Fatalf("curl: %d", resp.StatusCode)
	}
	if s.Fingerprints().Len() == 0 {
		t.Fatal("no fingerprint recorded for the open TLS connection")
	}
	if st := s.Stats(); st.DeniedFilter != 1 {
		t.Fatalf("denied_filter %d", st.DeniedFilter)
	}
	// Challenge: a scripted hello (no h2) is not reproducible with the
	// standard client, so drive the challenge path with a low
	// challenge_at through the header signal alone.
	yaml2 := strings.Replace(yaml, "challenge_at: 50", "challenge_at: 20", 1)
	cfg := mustParse(t, fmt.Sprintf(yaml2, cert, key, dir, backend.addr()))
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	resp, body = do("Mozilla/5.0 Chrome/128.0")
	if resp.StatusCode != 503 { // the challenge page answers 503 with Retry-After
		t.Fatalf("challenge page status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "/.xproxy/") {
		t.Fatalf("expected the challenge page, got %q", body[:min(len(body), 80)])
	}
	if s.Stats().ChallengesIssued == 0 {
		t.Fatal("challenge not counted")
	}
	// With browser headers the score is 0 and the page is served.
	resp, body = do("Mozilla/5.0 Chrome/128.0", "Accept", "text/html", "Accept-Language", "sv")
	if resp.StatusCode != 200 || body != "a:/page" {
		t.Fatalf("full browser headers: %d %q", resp.StatusCode, body)
	}
}
