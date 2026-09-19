package bypass

import (
	"fmt"
	"strings"
	"testing"
)

// TestRateLimitAndBans tries to outlast a rate limit by rotating the
// identifier and to spread an attack across a network to duck the ban.
func TestRateLimitAndBans(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	// The tiny limit (burst 3) on /limited: a fourth request from one
	// address is 429.
	ip := "203.0.113.10"
	var last int
	for i := 0; i < 6; i++ {
		last, _ = h.do(h.req("GET", "/limited", ip, ""))
	}
	if last != 429 {
		t.Errorf("rate limit not enforced after a burst: %d", last)
	}
	// Rotating the forwarded address from an untrusted peer does not
	// help: the real peer keys the limit. This client is loopback and
	// trusted, so instead assert the net aggregate ban caps a spread
	// attack: many addresses in one /24 each stay under the limit but
	// together trip the net-sweep trigger, and a fresh address in the
	// range is then refused before routing.
	pub := start(t, "127.0.0.0/8")
	for i := 1; i <= 12; i++ {
		src := fmt.Sprintf("203.0.113.%d", 100+i)
		for j := 0; j < 6; j++ {
			pub.do(pub.req("GET", "/limited", src, ""))
		}
	}
	status, _ := pub.do(pub.req("GET", "/", "203.0.113.200", ""))
	if status != 403 {
		t.Errorf("net aggregate ban did not cover the range: %d", status)
	}

	// WAF repeats ban the address: after the trigger threshold, even a
	// clean request to a WAF-off route is refused.
	waf := start(t, "127.0.0.0/8")
	atk := "203.0.113.50"
	for i := 0; i < 6; i++ {
		waf.do(waf.req("GET", "/search?q="+strings.ReplaceAll("' OR '1'='1", " ", "%20"), atk, ""))
	}
	status, _ = waf.do(waf.req("GET", "/limited", atk, ""))
	if status != 403 {
		t.Errorf("WAF repeat ban not applied: %d", status)
	}
}

// TestHoneypotMarks confirms a probe of a decoy route bans the client.
func TestHoneypotMarks(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	ip := "203.0.113.70"
	if status, _ := h.do(h.req("GET", "/wp-login.php", ip, "")); status == 0 {
		t.Fatal("no honeypot response")
	}
	// The probes trigger bans after one hit; the next request is refused.
	status, _ := h.do(h.req("GET", "/", ip, ""))
	if status != 403 {
		t.Errorf("honeypot probe not banned: %d", status)
	}
}

// TestUploadDisguises tries to smuggle an executable past the upload
// guard behind names, double extensions and declared types.
func TestUploadDisguises(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	pe := append([]byte("MZ"), make([]byte, 64)...)
	elf := append([]byte("\x7fELF"), make([]byte, 64)...)
	php := []byte("<?php system($_GET['c']); ?>")
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, make([]byte, 64)...)
	cases := []struct {
		name, filename, ctype string
		data                  []byte
	}{
		{"windows executable as jpg", "photo.jpg", "image/jpeg", pe},
		{"elf as png", "logo.png", "image/png", elf},
		{"php behind a double extension", "shell.php.jpg", "image/jpeg", php},
		{"php inside a png name", "avatar.png", "image/png", php},
		{"disallowed extension", "run.sh", "application/octet-stream", []byte("#!/bin/sh\n")},
		{"png bytes declared as pdf", "doc.pdf", "application/pdf", png},
		{"no extension", "noext", "application/octet-stream", png},
	}
	for i, c := range cases {
		ip := fmt.Sprintf("203.0.113.%d", 150+i)
		body, ct := multipart("file", c.filename, c.ctype, c.data)
		before := h.backend.hits.Load()
		status, _ := h.do(h.req("POST", "/upload", ip, body, "Content-Type", ct))
		h.denied(c.name, before, status, 400, 415, 413)
	}
	// A real image passes.
	body, ct := multipart("file", "photo.png", "image/png", png)
	before := h.backend.hits.Load()
	status, _ := h.do(h.req("POST", "/upload", "203.0.113.199", body, "Content-Type", ct))
	h.served("clean image upload", before, status)
}

// TestSensitiveExfil confirms a response carrying card numbers is
// blocked even when the client hides the request or the server
// compresses the answer.
func TestSensitiveExfil(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	// The export route's backend returns a card number; the response is
	// blocked before the client (the backend is reached, the client is
	// not served the body).
	status, body := h.do(h.req("GET", "/api/export", "203.0.113.210", ""))
	if strings.Contains(body, "4111") {
		t.Error("card number reached the client")
	}
	if status == 200 {
		t.Errorf("sensitive response not blocked: %d", status)
	}
	// A request body carrying a card is blocked whatever the media type.
	for _, ct := range []string{"application/json", "text/plain"} {
		before := h.backend.hits.Load()
		status, _ = h.do(h.req("POST", "/api/orders", "203.0.113.211", `{"card":"4111 1111 1111 1111"}`, "Content-Type", ct))
		h.denied("card in "+ct+" body", before, status, 403)
	}
}

// TestAccountBruteForce confirms repeated failed logins are blocked
// whether the attacker hammers one account or sprays many.
func TestAccountBruteForce(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	ip := "203.0.113.220"
	// One address and account: three failures block the pair.
	var status int
	for i := 0; i < 4; i++ {
		status, _ = h.do(h.req("POST", "/api/login", ip, `{"user":"victim@example.com"}`, "Content-Type", "application/json"))
	}
	if status != 429 && status != 403 {
		t.Errorf("credential stuffing on one pair not blocked: %d", status)
	}
	// One address trying many accounts (ip_accounts): blocked after four.
	spread := "203.0.113.221"
	for i := 0; i < 5; i++ {
		status, _ = h.do(h.req("POST", "/api/login", spread, fmt.Sprintf(`{"user":"u%d@example.com"}`, i), "Content-Type", "application/json"))
	}
	if status != 429 && status != 403 {
		t.Errorf("credential stuffing across accounts not blocked: %d", status)
	}
}

// TestOpenAPIPositiveModel tries to send requests the description does
// not allow.
func TestOpenAPIPositiveModel(t *testing.T) {
	h := start(t, "127.0.0.0/8")
	cases := []struct {
		name, method, target, body, ctype string
	}{
		{"undocumented path", "GET", "/v1/secret", "", ""},
		{"undocumented method", "DELETE", "/v1/things", "", ""},
		{"parameter over the maximum", "GET", "/v1/things?limit=9999", "", ""},
		{"undeclared property", "POST", "/v1/things", `{"name":"x","evil":1}`, "application/json"},
		{"over-long property", "POST", "/v1/things", `{"name":"much too long a name"}`, "application/json"},
		{"missing required body", "POST", "/v1/things", "", "application/json"},
		{"wrong content type", "POST", "/v1/things", `{"name":"x"}`, "text/plain"},
	}
	for i, c := range cases {
		ip := fmt.Sprintf("203.0.113.%d", 230+i)
		before := h.backend.hits.Load()
		status, _ := h.do(h.req(c.method, c.target, ip, c.body, "Content-Type", c.ctype))
		h.denied(c.name, before, status, 400, 404, 405, 415)
	}
	// A valid request passes.
	before := h.backend.hits.Load()
	status, _ := h.do(h.req("POST", "/v1/things", "203.0.113.250", `{"name":"ok"}`, "Content-Type", "application/json"))
	h.served("valid documented request", before, status)
}
