package http

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

func TestAccessLogSamplingAndFields(t *testing.T) {
	backend := newBackend(t, "a")
	dir := t.TempDir()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
logging:
  directory: %s
  access:
    sample_percent: 0
    always_log: true
    fields: [request_id, status, route]
upstreams:
  - {name: a, endpoints: [{address: "%s"}]}
routes:
  - {name: ok, paths: [/ok], upstream: a}
`, dir, backend.addr())
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatal(err)
	}
	s, err := proxy.New(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	url := "http://" + s.Addrs()["main"]
	// sample_percent 0 drops the 200 lines...
	for i := 0; i < 5; i++ {
		getAs(t, url+"/ok", "x", "203.0.113.1")
	}
	// ...but a 404 (no matching path is a route miss -> denied no_route)
	// is always logged.
	getAs(t, url+"/nope", "x", "203.0.113.1")
	_ = s.Shutdown(t.Context())
	logs.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "access.log"))
	lines := []string{}
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("expected only the error line, got %d:\n%s", len(lines), data)
	}
	// The field allowlist trims the line: request_id, status, route only,
	// plus the logger's own time/level/msg keys.
	line := lines[0]
	for _, want := range []string{`"status"`, `"request_id"`} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing %s: %s", want, line)
		}
	}
	for _, absent := range []string{`"client_ip"`, `"user_agent"`, `"path"`, `"method"`} {
		if strings.Contains(line, absent) {
			t.Errorf("line kept %s despite the allowlist: %s", absent, line)
		}
	}
	// Metrics still counted every request.
	if s.Stats().Requests < 6 {
		t.Fatalf("requests counted: %d", s.Stats().Requests)
	}
}
