package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApikeyCommand(t *testing.T) {
	file := filepath.Join(t.TempDir(), "api-keys")
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := apikeyCmd(args, &out, &errOut)
		return code, out.String(), errOut.String()
	}
	code, out, errOut := run("add", "acme", "-file", file, "-scopes", "orders:read,orders:write", "-expires", "90d", "-note", "Acme Corp")
	if code != 0 || !strings.HasPrefix(out, "xpk_acme_") || !strings.Contains(errOut, "shown once") {
		t.Fatalf("add: %d %q %q", code, out, errOut)
	}
	plain := strings.TrimSpace(out)
	if data, _ := os.ReadFile(file); strings.Contains(string(data), plain) || !strings.Contains(string(data), "acme|active|") {
		t.Fatalf("file: %s", data)
	}
	if code, _, _ := run("add", "acme", "-file", file); code != 1 {
		t.Fatal("duplicate accepted")
	}
	if code, _, errOut := run("add", "bad id", "-file", file); code != 1 || !strings.Contains(errOut, "key id") {
		t.Fatalf("bad id: %d %s", code, errOut)
	}
	if code, _, _ := run("add", "x", "-file", file, "-expires", "soon"); code != 1 {
		t.Fatal("bad expiry accepted")
	}
	code, out, _ = run("rotate", "acme", "-file", file, "-grace", "1h")
	if code != 0 || !strings.HasPrefix(out, "xpk_acme_") || strings.TrimSpace(out) == plain {
		t.Fatalf("rotate: %d %q", code, out)
	}
	code, out, _ = run("list", "-file", file)
	if code != 0 || !strings.Contains(out, "acme") || !strings.Contains(out, "orders:read,orders:write") || !strings.Contains(out, "Acme Corp") {
		t.Fatalf("list: %d %s", code, out)
	}
	if code, out, _ := run("revoke", "acme", "-file", file); code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %d %s", code, out)
	}
	if code, out, _ := run("list", "-file", file); code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("list after revoke: %d %s", code, out)
	}
	if code, _, _ := run("remove", "acme", "-file", file); code != 0 {
		t.Fatal("remove")
	}
	if code, _, _ := run("remove", "acme", "-file", file); code != 1 {
		t.Fatal("removing a missing key succeeded")
	}
	for _, args := range [][]string{{}, {"add"}, {"frobnicate", "x"}, {"add", "-file", file}} {
		if code, _, _ := run(args...); code != 2 {
			t.Fatalf("usage error expected for %v", args)
		}
	}
}
