package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

func TestManagementAPI(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "m.sock")
	reloads := 0
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{
		Reload:      func() error { reloads++; return nil },
		ReloadCerts: func() error { return errors.New("boom") },
	})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", err, st)
	}
	c := NewClient(sock)
	s, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.Routes != 1 || s.Upstreams != 1 || s.PID != os.Getpid() {
		t.Fatalf("%+v", s)
	}
	if err := c.Post("/v1/reload"); err != nil || reloads != 1 {
		t.Fatalf("reload: %v %d", err, reloads)
	}
	if err := c.Post("/v1/reload-certs"); err == nil || err.Error() != "boom" {
		t.Fatalf("error propagation: %v", err)
	}
	if err := c.Post("/v1/logs/reopen"); err == nil {
		t.Fatal("nil action should be 501")
	}
	b, err := c.Raw("/v1/upstreams")
	if err != nil {
		t.Fatal(err)
	}
	var ups map[string][]any
	if json.Unmarshal(b, &ups) != nil || len(ups["u"]) != 1 {
		t.Fatalf("upstreams: %s", b)
	}
	b, _ = c.Raw("/v1/config")
	if len(b) == 0 {
		t.Fatal("config empty")
	}
	// Second start on the same socket is refused.
	m2 := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m2.Start(); err == nil {
		t.Fatal("in-use socket accepted")
	}
}
