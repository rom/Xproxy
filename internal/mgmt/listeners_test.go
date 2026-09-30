package mgmt

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// The inventory over the socket: the two columns /v1/status could not
// give -- the kind and the mode -- and the bound address beside them, for
// a listener the configuration wrote as port 0.
func TestListenerInventoryOverTheSocket(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
    - name: watching
      address: "127.0.0.1:0"
      policy: {mode: shadow}
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
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Shutdown(context.Background()) }()

	rep, err := NewClient(sock).Listeners()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Listeners) != 2 {
		t.Fatalf("listeners %+v", rep.Listeners)
	}
	if rep.Enforcing != 1 || rep.Shadowing != 1 {
		t.Errorf("enforcing %d shadowing %d", rep.Enforcing, rep.Shadowing)
	}
	if rep.Daemon != "xproxy" || rep.Role != "edge" {
		t.Errorf("daemon %q role %q", rep.Daemon, rep.Role)
	}
	byName := map[string]proxy.ListenerView{}
	for _, l := range rep.Listeners {
		byName[l.Name] = l
	}
	main, ok := byName["main"]
	if !ok {
		t.Fatalf("no main in %+v", rep.Listeners)
	}
	if main.Kind != "http" || main.Mode != "enforce" {
		t.Errorf("main: kind %q mode %q", main.Kind, main.Mode)
	}
	if !main.Bound {
		t.Error("main is serving, so it holds its socket")
	}
	if main.Address == "127.0.0.1:0" || main.Address == "" {
		t.Errorf("address %q: the report gives the port the kernel handed out", main.Address)
	}
	if byName["watching"].Mode != "shadow" {
		t.Errorf("watching: mode %q", byName["watching"].Mode)
	}
	if len(rep.Kinds) != 1 || rep.Kinds[0].Kind != "http" || rep.Kinds[0].Listeners != 2 {
		t.Errorf("kinds %+v: two listeners share one kind's counters", rep.Kinds)
	}
}
