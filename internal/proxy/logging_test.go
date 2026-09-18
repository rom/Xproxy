package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
)

// TestRedactedAccessLog drives a request through the real pipeline with
// redaction on and checks what reaches the access and audit files.
func TestRedactedAccessLog(t *testing.T) {
	backend := newBackend(t, "a")
	dir := t.TempDir()
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
logging:
  directory: %s
  redaction:
    client_ip: hash
    hash_secret_file: %s
    user_agent: drop
    referer: origin
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - name: r
    upstream: a
`
	cfg, err := config.Parse([]byte(fmt.Sprintf(yaml, dir, filepath.Join(dir, "hash.key"), backend.addr())))
	if err != nil {
		t.Fatal(err)
	}
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	url := "http://" + s.Addrs()["main"]
	getAs(t, url+"/page", "x", "203.0.113.77", "User-Agent", "secret-agent", "Referer", "https://ref.example/private?x=1")
	getAs(t, url+"/page", "x", "203.0.113.77")
	_ = s.Shutdown(t.Context())
	logs.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "access.log"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("access lines: %d", len(lines))
	}
	var first, second map[string]any
	json.Unmarshal([]byte(lines[0]), &first)
	json.Unmarshal([]byte(lines[1]), &second)
	ip, _ := first["client_ip"].(string)
	if !strings.HasPrefix(ip, "h:") || ip != second["client_ip"] {
		t.Fatalf("client_ip not a stable pseudonym: %v %v", first["client_ip"], second["client_ip"])
	}
	if strings.Contains(lines[0], "203.0.113.77") || strings.Contains(lines[0], "secret-agent") || strings.Contains(lines[0], "private") {
		t.Fatalf("personal data leaked: %s", lines[0])
	}
	if first["referer"] != "https://ref.example" || first["path"] != "/page" || first["status"] != float64(200) {
		t.Fatalf("fields: %v", first)
	}
	if s.Stats().LogRedaction != true {
		t.Fatal("stats flag")
	}
}
