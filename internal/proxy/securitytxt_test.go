package proxy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const securityTxtYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
logging: {access: {enabled: false}}
security_txt:
  - name: internal
    client_cidrs: ["10.0.0.0/8"]
    contact: ["mailto:appsec@corp.internal"]
  - name: shop
    hosts: ["shop.test", "*.shop.test"]
    contact: ["https://example.com/vdp"]
    policy: ["https://example.com/vdp"]
  - name: default
    contact: ["mailto:security@example.com"]
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: app
    paths: [/]
    upstream: a
`

func TestSecurityTxtServedBeforeRouting(t *testing.T) {
	backend := newBackend(t, "a")
	s, url := startServer(t, fmt.Sprintf(securityTxtYAML, backend.addr()))
	get := func(path, host, clientIP string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", url+path, nil)
		req.Host = host
		if clientIP != "" {
			req.Header.Set("X-Forwarded-For", clientIP)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(b)
	}
	// Both locations, on a host with no route of its own.
	for _, p := range []string{"/.well-known/security.txt", "/security.txt"} {
		resp, body := get(p, "parked.test", "")
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("%s: %d %q", p, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if !strings.Contains(body, "mailto:security@example.com") || !strings.Contains(body, "Expires:") {
			t.Fatalf("%s body:\n%s", p, body)
		}
	}
	// The host selector picks the brand's document.
	if _, body := get("/.well-known/security.txt", "eu.shop.test", ""); !strings.Contains(body, "https://example.com/vdp") {
		t.Fatalf("shop body:\n%s", body)
	}
	// The client selector wins over the host one, because it comes first.
	if _, body := get("/.well-known/security.txt", "shop.test", "10.1.2.3"); !strings.Contains(body, "appsec@corp.internal") {
		t.Fatalf("internal body:\n%s", body)
	}
	// Everything else is routed as before: the document does not shadow
	// the application.
	if resp, body := get("/x", "parked.test", ""); resp.StatusCode != 200 || body == "" || strings.Contains(body, "Contact:") {
		t.Fatalf("ordinary request: %d %q", resp.StatusCode, body)
	}
	if n := s.Stats().SecurityTxt; n != 4 {
		t.Fatalf("security_txt counter %d, want 4", n)
	}
	// A method that is not GET or HEAD is refused.
	req, _ := http.NewRequest("POST", url+"/.well-known/security.txt", strings.NewReader("x"))
	req.Host = "parked.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", resp.StatusCode)
	}
}

// Without a security_txt section nothing changes: the path is routed
// like any other, so an origin serving its own file keeps doing so.
func TestSecurityTxtAbsentFallsThroughToRouting(t *testing.T) {
	backend := newBackend(t, "a")
	_, url := startServer(t, fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: a
    endpoints: [{address: %q}]
routes:
  - name: app
    paths: [/]
    upstream: a
`, backend.addr()))
	resp, err := http.Get(url + "/.well-known/security.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || strings.Contains(string(b), "Contact:") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
}

// A body_file is re-read on reload, so a re-signed document needs no
// restart.
func TestSecurityTxtBodyFileIsRereadOnReload(t *testing.T) {
	backend := newBackend(t, "a")
	dir := t.TempDir()
	path := filepath.Join(dir, "security.txt")
	write := func(contact string) {
		t.Helper()
		body := "Contact: mailto:" + contact + "\nExpires: 2030-01-01T00:00:00Z\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("first@example.com")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
security_txt:
  - name: signed
    body_file: %q
upstreams:
  - name: a
    endpoints: [{address: %q}]
routes:
  - name: app
    paths: [/]
    upstream: a
`, path, backend.addr())
	s, url := startServer(t, yaml)
	body := func() string {
		t.Helper()
		resp, err := http.Get(url + "/.well-known/security.txt")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(b)
	}
	if !strings.Contains(body(), "first@example.com") {
		t.Fatalf("first: %q", body())
	}
	write("second@example.com")
	if err := s.Reload(mustParse(t, yaml)); err != nil {
		t.Fatal(err)
	}
	if got := body(); !strings.Contains(got, "second@example.com") || strings.Contains(got, "first@example.com") {
		t.Fatalf("after the reload: %q", got)
	}
}

// A request whose Host is an address literal is the case a name-based
// selector cannot reach: a scanner that found the address in a range
// scan, with no name to go on. The whole path is exercised here — the
// Host header normalisation, the selector and the served document —
// because the bracketed IPv6 spelling only exists on the wire.
func TestSecurityTxtByHostAddress(t *testing.T) {
	backend := newBackend(t, "a")
	_, url := startServer(t, fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
security_txt:
  - name: parked
    host_cidrs: ["198.51.100.0/24", "2001:db8:1::/48"]
    contact: ["mailto:noc@example.com"]
    comment: "This address is not a service."
  - name: shop
    hosts: ["shop.test"]
    contact: ["https://example.com/vdp"]
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: app
    paths: [/]
    upstream: a
`, backend.addr()))

	get := func(host string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest("GET", url+"/.well-known/security.txt", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(b)
	}

	// Inside the ranges, in both families and with a port, which is what
	// a client actually sends.
	for _, host := range []string{
		"198.51.100.7", "198.51.100.7:443", "[2001:db8:1::9]", "[2001:db8:1::9]:8443",
	} {
		resp, body := get(host)
		if resp.StatusCode != 200 || !strings.Contains(body, "mailto:noc@example.com") {
			t.Errorf("Host %q: %d\n%s", host, resp.StatusCode, body)
		}
	}
	// Outside them, and for a name, there is no document at all here, so
	// the request is routed like any other.
	for _, host := range []string{"198.51.101.7", "[2001:db8:2::9]", "other.test"} {
		resp, body := get(host)
		if resp.StatusCode != 200 || strings.Contains(body, "Contact:") {
			t.Errorf("Host %q reached a document: %d\n%s", host, resp.StatusCode, body)
		}
	}
	// A named host still reaches its own document.
	if _, body := get("shop.test"); !strings.Contains(body, "https://example.com/vdp") {
		t.Errorf("shop.test:\n%s", body)
	}
}
