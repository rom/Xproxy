package ldapauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// TestBindPasswordFilePermissions: a world-readable service account
// password file is refused at validation, a private one accepted, and a
// missing one reported.
func TestBindPasswordFilePermissions(t *testing.T) {
	dir := t.TempDir()
	opts := func(p string) filter.Options {
		return filter.Options{"url": "ldaps://x", "bind_dn": "cn=svc,dc=y", "bind_password_file": p,
			"base_dn": "dc=y", "user_filter": "(uid=%s)"}
	}
	world := filepath.Join(dir, "world")
	if err := os.WriteFile(world, []byte("pw"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := filtertest.Build("ldap_auth", "t", opts(world)); err == nil {
		t.Fatal("world-readable password file accepted")
	}
	private := filepath.Join(dir, "private")
	if err := os.WriteFile(private, []byte("pw"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := filtertest.Build("ldap_auth", "t", opts(private)); err != nil {
		t.Fatalf("private password file rejected: %v", err)
	}
	if _, err := filtertest.Build("ldap_auth", "t", opts(filepath.Join(dir, "missing"))); err == nil {
		t.Fatal("missing password file accepted")
	}
}
