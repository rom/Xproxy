package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// TestHoneypot serves decoys, marks and bans the client, honours a delay
// and a body file, and exposes marks to the management plane.
func TestHoneypot(t *testing.T) {
	dir := t.TempDir()
	bodyFile := filepath.Join(dir, "backup.sql")
	if err := os.WriteFile(bodyFile, []byte("-- MySQL dump 10.13\nINSERT INTO users VALUES (1,'admin');\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
bans:
  action: reject
  triggers: [{name: probes, reasons: [honeypot], threshold: 3, window: 1m, duration: 1h}]
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - name: wp
    paths: [/wp-login.php]
    honeypot: {decoy: wp-login}
    response_headers: {set: {Server: "Apache/2.4.41 (Ubuntu)"}}
  - name: dump
    paths: [/backup.sql]
    honeypot: {body_file: %s, content_type: application/sql, status: 200, delay: 300ms}
  - name: custom
    paths: [/admin]
    honeypot: {body: "<html>nope</html>", status: 401}
  - name: app
    paths: [/]
    upstream: app
`
	s, base := startServer(t, fmt.Sprintf(yaml, bodyFile))
	resp, body := get(t, base+"/wp-login.php")
	if resp.StatusCode != 200 || !strings.Contains(body, "loginform") || resp.Header.Get("Server") != "Apache/2.4.41 (Ubuntu)" ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("wp decoy: %d %q %v", resp.StatusCode, body[:40], resp.Header)
	}
	// HEAD carries no body; a custom body keeps its status.
	req, _ := http.NewRequest(http.MethodHead, base+"/admin", nil)
	hr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(hr.Body)
	_ = hr.Body.Close()
	if hr.StatusCode != 401 || len(b) != 0 {
		t.Fatalf("HEAD custom: %d %q", hr.StatusCode, b)
	}
	start := time.Now()
	resp, body = get(t, base+"/backup.sql")
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "-- MySQL dump") || resp.Header.Get("Content-Type") != "application/sql" {
		t.Fatalf("body_file decoy: %d %q %s", resp.StatusCode, body, resp.Header.Get("Content-Type"))
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("delay not applied")
	}
	// The third hit reached the trigger threshold: the client is banned.
	resp, _ = get(t, base+"/")
	if resp.StatusCode != 403 {
		t.Fatalf("after three honeypot hits: %d", resp.StatusCode)
	}
	marks := s.HoneypotMarks()
	if len(marks) != 1 || marks[0].Hits != 3 || marks[0].Route != "dump" || marks[0].Address != "127.0.0.1" {
		t.Fatalf("marks: %+v", marks)
	}
	sn := s.Stats()
	if sn.HoneypotHits != 3 || sn.HoneypotMarked != 1 || sn.BansActive != 1 {
		t.Fatalf("counters: hits %d marked %d bans %d", sn.HoneypotHits, sn.HoneypotMarked, sn.BansActive)
	}
	if !s.UnmarkHoneypot(netip.MustParseAddr("127.0.0.1")) || len(s.HoneypotMarks()) != 0 || s.UnmarkHoneypot(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("unmark")
	}
	// A body file that disappears fails the reload as a whole.
	if err := os.Remove(bodyFile); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(yaml, bodyFile)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), "honeypot body_file") {
		t.Fatalf("reload with a missing body file: %v", err)
	}
}

// TestHoneypotMarks covers the bounded mark table directly.
func TestHoneypotMarks(t *testing.T) {
	m := newMarks()
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	m.add(ip, "r", time.Minute, now)
	m.add(ip, "r2", time.Minute, now.Add(time.Second))
	if !m.marked(ip, now) || m.marked(netip.MustParseAddr("192.0.2.2"), now) || m.marked(netip.Addr{}, now) {
		t.Fatal("marked")
	}
	if l := m.list(now); len(l) != 1 || l[0].Hits != 2 || l[0].Route != "r2" {
		t.Fatalf("list: %+v", l)
	}
	if m.marked(ip, now.Add(2*time.Minute)) {
		t.Fatal("expired mark reported")
	}
	m.add(netip.Addr{}, "r", time.Minute, now)
	if len(m.list(now)) != 0 {
		t.Fatal("invalid address stored")
	}
	for i := 0; i < maxMarks+10; i++ {
		m.add(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), "r", time.Minute, now)
	}
	if len(m.m) != maxMarks {
		t.Fatalf("bound: %d", len(m.m))
	}
	later := now.Add(2 * time.Minute)
	m.add(ip, "r", time.Minute, later) // sweeps the expired ones first
	if len(m.m) != 1 {
		t.Fatalf("after sweep: %d", len(m.m))
	}
	if len(DecoyNames()) != len(decoys) || !config.HoneypotDecoys["wp-login"] || len(config.HoneypotDecoys) != len(decoys) {
		t.Fatal("decoy lists disagree")
	}
	for name := range decoys {
		if !config.HoneypotDecoys[name] {
			t.Fatalf("%s not in the config list", name)
		}
	}
}

// A decoy served honestly marks nobody. robots.txt and sitemap.xml
// name the decoy paths, which is the point: a crawler that reads one
// has done what it is meant to do, and marking it — then banning it
// through the honeypot trigger — punishes the search engine rather
// than the scanner. Asking for what the file names is the part that
// says something, and that is a different route.
func TestHoneypotMarkZeroMarksNobody(t *testing.T) {
	b := newBackend(t, "origin")
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
bans:
  action: reject
  triggers:
    - {name: probes, reasons: [honeypot], threshold: 1, window: 1m, duration: 1h}
upstreams:
  - {name: app, endpoints: [{address: "` + b.addr() + `"}]}
routes:
  - {name: hp-robots, paths: [/robots.txt], honeypot: {decoy: robots, mark: 0s}}
  - {name: hp-env, paths: [/.env], honeypot: {decoy: env}}
  - {name: app, paths: [/], upstream: app}
`
	s, url := startServer(t, yaml)

	// The honestly served file: answered, counted, and nothing else.
	resp, body := get(t, url+"/robots.txt", "X-Forwarded-For", "203.0.113.50")
	if resp.StatusCode != 200 || !strings.Contains(body, "Disallow") {
		t.Fatalf("robots.txt: %d %q", resp.StatusCode, body)
	}
	if n := len(s.HoneypotMarks()); n != 0 {
		t.Errorf("%d marks after reading robots.txt, want none", n)
	}
	// And the crawler is still served everywhere else.
	if resp, _ := get(t, url+"/page", "X-Forwarded-For", "203.0.113.50"); resp.StatusCode != 200 {
		t.Errorf("the crawler was refused afterwards: %d", resp.StatusCode)
	}
	if n := s.Stats().HoneypotHits; n != 1 {
		t.Errorf("honeypot_hits = %d, want the hit still counted", n)
	}

	// A decoy that does mark still marks, so the zero is a choice and
	// not a broken default.
	if resp, _ := get(t, url+"/.env", "X-Forwarded-For", "203.0.113.51"); resp.StatusCode != 200 {
		t.Fatalf("/.env: %d", resp.StatusCode)
	}
	marks := s.HoneypotMarks()
	if len(marks) != 1 || marks[0].Address != "203.0.113.51" {
		t.Fatalf("marks %+v, want the .env reader only", marks)
	}
	if resp, _ := get(t, url+"/page", "X-Forwarded-For", "203.0.113.51"); resp.StatusCode != 403 {
		t.Errorf("the .env reader was not banned: %d", resp.StatusCode)
	}
}
