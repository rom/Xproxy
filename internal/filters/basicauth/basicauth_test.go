package basicauth

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
	"github.com/rom/xproxy/internal/passwd"
)

func usersFile(t *testing.T) string {
	t.Helper()
	h, err := passwd.HashWithIterations("correct-horse-battery", 1000)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(p, []byte("# users\nalice:"+h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBasicAuth(t *testing.T) {
	p := usersFile(t)
	f, err := filtertest.Build("basic_auth", "staff", filter.Options{"users_file": p, "realm": "staff", "forward_user_header": "X-Remote-User"})
	if err != nil {
		t.Fatal(err)
	}
	req := func(user, pass string) *http.Request {
		r, _ := http.NewRequest("GET", "http://h.example.test/x", nil)
		if user != "" {
			r.SetBasicAuth(user, pass)
		}
		return r
	}
	res := filtertest.Run(f, req("", ""), nil)
	if !res.Request.Deny || res.Request.Status != 401 || res.Request.Headers["WWW-Authenticate"] != `Basic realm="staff", charset="UTF-8"` {
		t.Fatalf("no credentials: %+v", res.Request)
	}
	if v := filtertest.Run(f, req("alice", "wrong-password-0"), nil).Request; !v.Deny {
		t.Fatal("wrong password accepted")
	}
	if v := filtertest.Run(f, req("bob", "correct-horse-battery"), nil).Request; !v.Deny {
		t.Fatal("unknown user accepted")
	}
	r := req("alice", "correct-horse-battery")
	res = filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("valid credentials denied: %+v", res.Request)
	}
	if r.Header.Get("Authorization") != "" || r.Header.Get("X-Remote-User") != "alice" {
		t.Fatalf("headers after auth: %v", r.Header)
	}
	if len(res.Attrs) != 2 || res.Attrs[1] != "alice" {
		t.Fatalf("attrs %v", res.Attrs)
	}
	// Cached: a second check does not re-hash (observable only as speed;
	// assert the cache holds the entry).
	a := f.(*auth)
	if len(a.cache) != 2 { // alice right and wrong; unknown users are not cached
		t.Fatalf("cache entries %d", len(a.cache))
	}
}

func TestBasicAuthValidate(t *testing.T) {
	p := usersFile(t)
	bad := []filter.Options{
		{},
		{"users_file": filepath.Join(t.TempDir(), "missing")},
		{"users_file": p, "cache_ttl": "forever"},
		{"users_file": p, "realm": "a\"b"},
		{"users_file": p, "unknown": true},
	}
	for i, o := range bad {
		if _, err := filtertest.Build("basic_auth", "a", o); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	world := filepath.Join(t.TempDir(), "w")
	_ = os.WriteFile(world, []byte("a:x\n"), 0o644)
	if _, err := filtertest.Build("basic_auth", "a", filter.Options{"users_file": world}); err == nil {
		t.Fatal("world readable file accepted")
	}
	malformed := filepath.Join(t.TempDir(), "m")
	_ = os.WriteFile(malformed, []byte("alice:plaintext\n"), 0o600)
	if _, err := filtertest.Build("basic_auth", "a", filter.Options{"users_file": malformed}); err == nil {
		t.Fatal("malformed hash accepted")
	}
}
