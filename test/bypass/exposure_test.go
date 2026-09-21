package bypass

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// A honeypot is worth running only while the client does not know it
// touched one. These tests look for the tell: a header, a cookie, a
// status, a body that differs between a marked client and a fresh one.

const exposureYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging:
  access: {enabled: false}
trusted_proxies: [127.0.0.0/8]
upstreams:
  - name: app
    endpoints: [{address: "%s"}]
routes:
  - {name: trap-login, hosts: [app.test], paths: [/wp-login.php], honeypot: {decoy: wp-login, mark: 1h}}
  - {name: trap-env, hosts: [app.test], paths: [/.env], honeypot: {decoy: env, mark: 1h}}
  - {name: trap-imds, hosts: [app.test], paths: [/latest/meta-data], honeypot: {decoy: imds, mark: 1h}}
  - {name: trap-key, hosts: [app.test], paths: [/id_rsa], honeypot: {decoy: ssh-key, mark: 1h}}
  - {name: app, hosts: [app.test], upstream: app}
`

func startExposure(t *testing.T) *harness {
	t.Helper()
	b := newBackend(t)
	cfg, err := config.Parse([]byte(fmt.Sprintf(exposureYAML, b.addr())))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return &harness{t: t, s: s, addr: s.Addrs()["main"], backend: b}
}

// fetch returns the status, the headers and the body of one request.
func (h *harness) fetch(r *http.Request) (int, http.Header, string) {
	h.t.Helper()
	resp, err := client.Do(r)
	if err != nil {
		h.t.Fatalf("%s %s: %v", r.Method, r.URL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, string(body)
}

// A decoy is a static page. It must not carry state to the client, and
// it must not reflect anything the client sent: a decoy that echoes the
// query is a cross-site scripting hole on a path an attacker already
// knows how to reach.
func TestDecoysCarryNothingBack(t *testing.T) {
	h := startExposure(t)
	payload := "<script>alert(1)</script>"
	for i, path := range []string{"/wp-login.php", "/.env", "/latest/meta-data", "/id_rsa"} {
		ip := fmt.Sprintf("198.51.100.%d", 120+i)
		target := path + "?next=" + url.QueryEscape(payload) + "&user=" + url.QueryEscape("marker-"+ip)
		status, hdr, body := h.fetch(h.req("GET", target, ip, "", "Referer", "http://evil.example/"+payload, "Cookie", "probe="+payload))
		if status != 200 {
			t.Errorf("%s: status %d, want the decoy to answer plainly", path, status)
		}
		for _, name := range []string{"Set-Cookie", "Location", "WWW-Authenticate", "X-Honeypot", "X-Marked"} {
			if v := hdr.Get(name); v != "" {
				t.Errorf("%s: the decoy answered with %s: %q", path, name, v)
			}
		}
		if strings.Contains(body, payload) || strings.Contains(body, "marker-"+ip) {
			t.Errorf("%s: the decoy reflected what the client sent", path)
		}
		if h.backend.hits.Load() != 0 {
			t.Fatalf("%s: a honeypot route reached the origin", path)
		}
	}
}

// Two different clients get the same decoy, byte for byte. A body that
// varies per client is a side channel that tells a scanner it has been
// singled out.
func TestDecoysAreTheSameForEveryone(t *testing.T) {
	h := startExposure(t)
	_, _, first := h.fetch(h.req("GET", "/.env", "198.51.100.140", ""))
	_, _, second := h.fetch(h.req("GET", "/.env", "203.0.113.140", ""))
	if first != second {
		t.Errorf("the decoy differs between clients:\n%q\n%q", first, second)
	}
	// And the same client asking twice is told nothing new the second
	// time, when it is already marked.
	_, _, third := h.fetch(h.req("GET", "/.env", "198.51.100.140", ""))
	if third != first {
		t.Errorf("the decoy changed once the client was marked:\n%q\n%q", first, third)
	}
}

// The mark is for the operator, not for the client. A marked client's
// ordinary traffic must look exactly like anybody else's: the moment a
// scanner can see the mark, it knows which address to stop using.
func TestAMarkedClientCannotSeeItsMark(t *testing.T) {
	h := startExposure(t)
	const marked, clean = "198.51.100.150", "198.51.100.151"

	// Baseline from a client that has touched nothing.
	beforeStatus, beforeHdr, beforeBody := h.fetch(h.req("GET", "/page", clean, ""))

	// Trip two honeypots, then ask for the same ordinary page.
	for _, p := range []string{"/wp-login.php", "/.env"} {
		if status, _, _ := h.fetch(h.req("GET", p, marked, "")); status != 200 {
			t.Fatalf("%s: status %d", p, status)
		}
	}
	if !h.isMarked(marked) {
		t.Fatal("the honeypot did not mark the client, so this test proves nothing")
	}
	afterStatus, afterHdr, afterBody := h.fetch(h.req("GET", "/page", marked, ""))

	if afterStatus != beforeStatus {
		t.Errorf("a marked client gets status %d where a clean one gets %d", afterStatus, beforeStatus)
	}
	if afterBody != beforeBody {
		t.Errorf("a marked client gets a different body:\n%q\n%q", beforeBody, afterBody)
	}
	// Every header but the ones that differ per request anyway.
	volatile := map[string]bool{"Date": true, "X-Request-Id": true, "Content-Length": true}
	for name, want := range beforeHdr {
		if volatile[name] {
			continue
		}
		if got := afterHdr[name]; strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("header %s: marked client got %v, clean client %v", name, got, want)
		}
	}
	for name := range afterHdr {
		if !volatile[name] && beforeHdr[name] == nil {
			t.Errorf("a marked client gets an extra header %s: %v", name, afterHdr[name])
		}
	}

	// Nor does the mark travel to the origin as a header. It lives in
	// the proxy: the access log line, the filter context and
	// `xproxyctl honeypot`. An origin that reflected such a header —
	// into a page, an error, a debug endpoint — would hand the scanner
	// the answer the proxy is keeping from it.
	markedUpstream := h.backend.last.Load().Header.Clone()
	if _, _, _ = h.fetch(h.req("GET", "/page", clean, "")); true {
		cleanUpstream := h.backend.last.Load().Header.Clone()
		for name := range markedUpstream {
			if cleanUpstream[name] == nil {
				t.Errorf("the origin gets an extra header %s for a marked client: %v", name, markedUpstream[name])
			}
		}
	}
	// The operator does see it, in the proxy's own counters.
	if n := h.s.Stats().HoneypotMarked; n == 0 {
		t.Error("the proxy does not report the mark to the operator either")
	}
}

// isMarked asks the proxy, which is what the operator has and the
// client does not.
func (h *harness) isMarked(ip string) bool {
	h.t.Helper()
	for _, m := range h.s.HoneypotMarks() {
		if m.Address == ip {
			return true
		}
	}
	return false
}

// A refusal must not describe the inside of the deployment: no origin
// address, no upstream name, no internal path.
func TestRefusalsDescribeNothingInternal(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	origin := h.backend.addr()
	host, _, _ := strings.Cut(origin, ":")
	for i, c := range []struct {
		name   string
		method string
		target string
	}{
		{"denied route", "GET", "/admin"},
		{"unknown host route", "GET", "/nothing/here"},
		{"virtual patch", "GET", "/plugins/legacy/?cmd=id"},
		{"policy violation", "GET", "/api/items?id=1&evil=1"},
		{"waf", "GET", "/search?q=" + url.QueryEscape("' OR '1'='1")},
	} {
		ip := fmt.Sprintf("198.51.100.%d", 160+i)
		status, hdr, body := h.fetch(h.req(c.method, c.target, ip, ""))
		if status == 200 {
			continue
		}
		for _, leak := range []string{origin, host, "upstream", "10.0.0.", "/etc/"} {
			if leak == "" {
				continue
			}
			if strings.Contains(body, leak) {
				t.Errorf("%s: the %d body names %q", c.name, status, leak)
			}
		}
		// The proxy does not advertise itself either.
		if v := hdr.Get("Server"); v != "" {
			t.Errorf("%s: the refusal carries Server: %q", c.name, v)
		}
		for _, name := range []string{"X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Host", "X-Upstream"} {
			if v := hdr.Get(name); v != "" {
				t.Errorf("%s: the refusal echoes %s: %q", c.name, name, v)
			}
		}
	}
}
