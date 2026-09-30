package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/http" // the kind the harness listens with
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
)

// workorderHarness is a daemon with a ledger, which is what a work order needs.
func workorderHarness(t *testing.T) (sock, cfgPath string) {
	t.Helper()
	dir := t.TempDir()
	yaml := "version: 1\naccess:\n  ledger: " + filepath.Join(dir, "access.jsonl") + "\n" +
		"  approvals: 1\n" +
		"server:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\n" +
		"upstreams:\n  - {name: u, endpoints: [{address: \"127.0.0.1:1\"}]}\n" +
		"routes:\n  - {name: r, upstream: u}\n"
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
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

func TestTheWorkOrderCommand(t *testing.T) {
	sock, cfgPath := workorderHarness(t)
	for _, tc := range []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"workorder"}, 0, []string{"no work orders are on file"}},
		// Filing says what it did and, in the same breath, what it did not do.
		{[]string{"workorder", "file", "WO-2026-0481", "-device", "plc-line1",
			"-duration", "8h", "-note", "die change", "-by", "maintenance"}, 0,
			[]string{"WO-2026-0481", "plc-line1", "open", "permits nothing"}},
		{[]string{"workorder"}, 0, []string{"1 work orders, 1 open", "REFERENCE", "WO-2026-0481", "die change", "any"}},
		{[]string{"workorder", "-state", "open"}, 0, []string{"WO-2026-0481"}},
		{[]string{"workorder", "-device", "somewhere-else"}, 0, []string{"no work orders are on file"}},
		{[]string{"-json", "workorder"}, 0, []string{`"reference": "WO-2026-0481"`, `"state": "open"`}},
		{[]string{"workorder", "close", "WO-2026-0481", "-by", "supervisor"}, 0,
			[]string{"closed", "unfiled again"}},
		{[]string{"workorder", "close", "WO-2026-0481", "-by", "supervisor"}, 1, []string{"already closed"}},
		// The usage text is where the distinction from a grant is stated, so a
		// misuse is a teaching moment rather than only an error.
		{[]string{"workorder", "file", "WO-2"}, 2, []string{"usage: xproxyctl workorder", "permits nothing"}},
		{[]string{"workorder", "file"}, 2, []string{"usage: xproxyctl workorder"}},
		{[]string{"workorder", "close"}, 2, []string{"usage: xproxyctl workorder"}},
		{[]string{"workorder", "extra"}, 2, []string{"usage: xproxyctl workorder"}},
		{[]string{"workorder", "file", "WO-3", "-device", "d", "-duration", "nonsense"}, 1, []string{"duration"}},
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
}
