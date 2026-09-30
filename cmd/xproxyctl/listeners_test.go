package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/forward" // the second kind, so the inventory has more than one
	_ "github.com/rom/xproxy/internal/kinds/http"    // the kind the harness listens with
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
)

// listenersHarness is a daemon with three listeners of two kinds, one of
// them only watching, which is the shape the view exists to make legible.
func listenersHarness(t *testing.T) (sock, cfgPath string) {
	t.Helper()
	dir := t.TempDir()
	yaml := `version: 1
server:
  listeners:
    - {name: web, address: "127.0.0.1:0", kind: http}
    - {name: watching, address: "127.0.0.1:0", kind: http, policy: {mode: shadow}}
    - name: egress
      address: "127.0.0.1:0"
      kind: forward
      forward: {allow: ["example.com"]}
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: r, upstream: u}
`
	cfg, err := config.Parse([]byte(yaml))
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
	t.Cleanup(func() {
		if err := p.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	// A refusal so the kind table has a number in it.
	p.Counters().Refuse("http", "waf")
	p.Counters().WouldRefuse("http", "api_schema")

	sock = filepath.Join(dir, "m.sock")
	cfgPath = filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	m := mgmt.New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), mgmt.Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return sock, cfgPath
}

func TestTheListenersViewNamesTheKindAndTheMode(t *testing.T) {
	sock, cfgPath := listenersHarness(t)
	for _, tc := range []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"listeners"}, 0, []string{
			"xproxy, generation", "3 listeners, 2 enforcing, 1 in shadow mode",
			"LISTENER", "web", "forward", "shadow", "KIND", "REFUSED", "WOULD REFUSE"}},
		// The breakdown is what somebody woken by a graph reads next.
		{[]string{"listeners", "-reasons"}, 0, []string{"refused", "waf", "would refuse", "api_schema"}},
		// Narrowing keeps the kind rows in step with the listener rows.
		{[]string{"listeners", "-kind", "forward"}, 0, []string{"egress", "1 listeners, 1 enforcing"}},
		{[]string{"listeners", "-mode", "shadow"}, 0, []string{"watching", "1 in shadow mode"}},
		{[]string{"-json", "listeners"}, 0, []string{`"kind": "forward"`, `"mode": "shadow"`, `"bound": true`}},
		{[]string{"listeners", "-kind", "modbus"}, 0, []string{"no listeners"}},
		{[]string{"listeners", "extra"}, 2, []string{"usage: xproxyctl listeners"}},
	} {
		code, out, errOut := runCmd(t, sock, cfgPath, tc.args...)
		if code != tc.code {
			t.Errorf("%v: code %d want %d (%s%s)", tc.args, code, tc.code, out, errOut)
			continue
		}
		text := out
		if tc.code != 0 {
			text = errOut
		}
		for _, want := range tc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%v: %q not in\n%s", tc.args, want, text)
			}
		}
	}
	// -kind forward must not leave http's counters behind under an empty
	// listener table: a number attributed to the wrong protocol is worse
	// than no number.
	_, out, _ := runCmd(t, sock, cfgPath, "listeners", "-kind", "forward")
	if strings.Contains(out, "http") {
		t.Errorf("-kind forward mentioned http:\n%s", out)
	}
}
