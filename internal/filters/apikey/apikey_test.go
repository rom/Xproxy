package apikey

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func TestLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")
	plain, err := Add(path, "acme", []string{"orders:read"}, time.Now().Add(48*time.Hour), "Acme Corp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, "xpk_acme_") || IDOf(plain) != "acme" {
		t.Fatalf("key shape %q", plain)
	}
	if _, err := Add(path, "acme", nil, time.Time{}, ""); err == nil {
		t.Fatal("duplicate id accepted")
	}
	expired, _ := Add(path, "old", nil, time.Now().Add(-time.Hour), "")
	star, _ := Add(path, "root", []string{"*"}, time.Time{}, "")
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), plain) {
		t.Fatal("plaintext stored")
	}
	f, err := filtertest.Build("api_key", "keys", filter.Options{"keys_file": path, "required_scopes": []any{"orders:read"}, "reload": "1s"})
	if err != nil {
		t.Fatal(err)
	}
	req := func(key string) *http.Request {
		r, _ := http.NewRequest("GET", "http://api.test/orders", nil)
		r.Header.Set("X-Api-Key-Id", "spoofed")
		if key != "" {
			r.Header.Set("X-Api-Key", key)
		}
		return r
	}
	r := req(plain)
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("valid key denied: %+v", v)
	}
	if r.Header.Get("X-Api-Key-Id") != "acme" || r.Header.Get("X-Api-Key-Scopes") != "orders:read" || r.Header.Get("X-Api-Key") != "" {
		t.Fatalf("headers after auth: %v", r.Header)
	}
	if v := filtertest.Run(f, req(""), nil).Request; !v.Deny || v.Status != 401 || v.Detail != "missing" {
		t.Fatalf("missing: %+v", v)
	}
	if v := filtertest.Run(f, req("xpk_acme_nope"), nil).Request; !v.Deny || v.Detail != "unknown" {
		t.Fatalf("unknown: %+v", v)
	}
	if v := filtertest.Run(f, req(expired), nil).Request; !v.Deny || v.Detail != "expired" {
		t.Fatalf("expired: %+v", v)
	}
	if v := filtertest.Run(f, req(star), nil).Request; v.Deny {
		t.Fatalf("wildcard scope denied: %+v", v)
	}
	// A key without the scope is forbidden, not unauthorised.
	noScope, _ := Add(path, "guest", []string{"catalog"}, time.Time{}, "")
	time.Sleep(1100 * time.Millisecond) // past the reload interval
	if v := filtertest.Run(f, req(noScope), nil).Request; !v.Deny || v.Status != 403 || v.Detail != "scope:orders:read" {
		t.Fatalf("scope: %+v", v)
	}
	// Rotation: the new secret works, the old one until the grace ends.
	rotated, err := Rotate(path, "acme", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if v := filtertest.Run(f, req(rotated), nil).Request; v.Deny {
		t.Fatalf("rotated key denied: %+v", v)
	}
	if v := filtertest.Run(f, req(plain), nil).Request; v.Deny {
		t.Fatalf("previous secret refused inside the grace: %+v", v)
	}
	rotated2, err := Rotate(path, "acme", 0)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if v := filtertest.Run(f, req(plain), nil).Request; !v.Deny {
		t.Fatal("old secret accepted after a rotation without grace")
	}
	if v := filtertest.Run(f, req(rotated), nil).Request; !v.Deny || v.Detail != "unknown" {
		t.Fatalf("first rotation secret after the second rotation: %+v", v)
	}
	// Revocation.
	if err := Revoke(path, "root"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if v := filtertest.Run(f, req(star), nil).Request; !v.Deny || v.Detail != "revoked" {
		t.Fatalf("revoked: %+v", v)
	}
	if err := Remove(path, "old"); err != nil {
		t.Fatal(err)
	}
	keys, _ := Load(path)
	if len(keys) != 3 {
		t.Fatalf("keys after remove: %d", len(keys))
	}
	// A broken file keeps the previous table.
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if v := filtertest.Run(f, req(rotated2), nil).Request; v.Deny {
		t.Fatalf("previous table not kept: %+v", v)
	}
}

func TestSourcesAndValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")
	plain, _ := Add(path, "k1", nil, time.Time{}, "")
	for _, src := range []string{"bearer", "query:api_key", "header:X-Token"} {
		f, err := filtertest.Build("api_key", "k", filter.Options{"keys_file": path, "source": src, "forward_scopes_header": ""})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := http.NewRequest("GET", "http://api.test/x?api_key="+plain+"&keep=1", nil)
		r.Header.Set("Authorization", "Bearer "+plain)
		r.Header.Set("X-Token", plain)
		if v := filtertest.Run(f, r, nil).Request; v.Deny {
			t.Fatalf("%s: %+v", src, v)
		}
		switch src {
		case "bearer":
			if r.Header.Get("Authorization") != "" {
				t.Fatal("bearer not stripped")
			}
		case "query:api_key":
			if strings.Contains(r.URL.RawQuery, plain) || !strings.Contains(r.URL.RawQuery, "keep=1") {
				t.Fatalf("query after strip: %s", r.URL.RawQuery)
			}
		}
	}
	bad := []filter.Options{
		{},
		{"keys_file": "relative"},
		{"keys_file": path, "source": "cookie:x"},
		{"keys_file": path, "required_scopes": []any{"a b"}},
		{"keys_file": path, "reload": "10ms"},
		{"keys_file": path, "forward_id_header": "Authorization"},
	}
	for i, o := range bad {
		if _, err := filtertest.Build("api_key", "k", o); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := filtertest.Build("api_key", "k", filter.Options{"keys_file": path}); err == nil {
		t.Fatal("world readable keys file accepted")
	}
}
