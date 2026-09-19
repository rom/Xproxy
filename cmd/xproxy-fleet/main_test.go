package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAndUsage(t *testing.T) {
	dir := t.TempDir()
	good := "version: 1\nserver:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\nupstreams:\n  - name: web\n    endpoints: [{address: \"10.0.0.1:8080\"}]\nroutes:\n  - {name: default, upstream: web}\n"
	for id, content := range map[string]string{"edge1": good, "edge2": "version: 1\nroutes: [{name: x}]\n"} {
		if err := os.MkdirAll(filepath.Join(dir, "nodes", id), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "nodes", id, "xproxy.yaml"), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"validate", "-dir", dir}, &out, &errOut); code != 1 {
		t.Fatalf("code %d: %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "edge1: ok") || !strings.Contains(out.String(), "edge2: ") || !strings.Contains(errOut.String(), "1 of 2") {
		t.Fatalf("output %q %q", out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if err := os.RemoveAll(filepath.Join(dir, "nodes", "edge2")); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"validate", "-dir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	if code := run([]string{"validate", "-dir", t.TempDir()}, &out, &errOut); code != 1 {
		t.Fatalf("empty dir code %d", code)
	}
	if code := run(nil, &out, &errOut); code != 2 {
		t.Fatalf("usage code %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("unknown code %d", code)
	}
	if code := run([]string{"node"}, &out, &errOut); code != 2 {
		t.Fatalf("node without id code %d", code)
	}
	out.Reset()
	if code := run([]string{"version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "xproxy-fleet ") {
		t.Fatalf("version %d %q", code, out.String())
	}
	if code := run([]string{"serve", "-dir", dir}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "-cert") {
		t.Fatalf("serve without certificates %d %q", code, errOut.String())
	}
	if code := run([]string{"nodes", "-admin-socket", filepath.Join(dir, "none.sock")}, &out, &errOut); code != 1 {
		t.Fatalf("nodes without controller %d", code)
	}
}
