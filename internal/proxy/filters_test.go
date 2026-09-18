package proxy

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/rom/xproxy/internal/filters" // built-in kinds
	"github.com/rom/xproxy/internal/passwd"
)

const filtersYAML = `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints:
      - {address: %s}
filters:
  - name: staff
    kind: basic_auth
    stage: before_auth
    options: {users_file: %s, realm: staff, forward_user_header: X-Remote-User}
  - name: scanners
    kind: header_guard
    options:
      deny: [{header: User-Agent, pattern: "(?i)sqlmap|nikto"}]
      status: 418
      reason: scanner
routes:
  - name: admin
    paths: [/admin/]
    upstream: app
    filters: [staff, scanners]
  - name: open
    paths: [/]
    upstream: app
    filters: [scanners]
`

func TestFilters(t *testing.T) {
	backend := newBackend(t, "a")
	hash, err := passwd.HashWithIterations("correct-horse-battery", 1000)
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(users, []byte("alice:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, url := startServer(t, fmt.Sprintf(filtersYAML, backend.addr(), users))

	resp, body := get(t, url+"/x", "User-Agent", "curl/8")
	if resp.StatusCode != 200 || body != "a:/x" {
		t.Fatalf("open route: %d %q", resp.StatusCode, body)
	}
	resp, _ = get(t, url+"/x", "User-Agent", "sqlmap/1.7")
	if resp.StatusCode != 418 {
		t.Fatalf("scanner on open route: %d", resp.StatusCode)
	}
	resp, _ = get(t, url+"/admin/x", "User-Agent", "curl/8")
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), `Basic realm="staff"`) {
		t.Fatalf("admin without credentials: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	req, _ := http.NewRequest("GET", url+"/admin/x", nil)
	req.SetBasicAuth("alice", "correct-horse-battery")
	req.Header.Set("User-Agent", "curl/8")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("admin with credentials: %d", r2.StatusCode)
	}
	last := backend.last.Load()
	if last.Header.Get("Authorization") != "" || last.Header.Get("X-Remote-User") != "alice" {
		t.Fatalf("upstream headers: %v", last.Header)
	}
	// Scanner with valid credentials: basic_auth (before_auth) passes,
	// header_guard (after_auth) denies.
	req.Header.Set("User-Agent", "nikto")
	r3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = r3.Body.Close()
	if r3.StatusCode != 418 {
		t.Fatalf("scanner with credentials: %d", r3.StatusCode)
	}

	if got := s.Stats().DeniedFilter; got != 3 {
		t.Fatalf("denied_filter = %d", got)
	}
	st := s.Filters()
	if len(st) != 2 || st[0].Name != "scanners" || st[0].Denied != 2 || st[0].Routes != 2 || st[1].Name != "staff" || st[1].Denied != 1 || st[1].Stage != "before_auth" {
		t.Fatalf("filter status: %+v", st)
	}
	var mb strings.Builder
	if err := s.WriteMetrics(&mb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mb.String(), `xproxy_filter_denied_total{filter="scanners",kind="header_guard"} 2`) {
		t.Fatal("metric missing")
	}
}
