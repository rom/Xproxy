package basicauth

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	if len(a.cache) != 3 { // alice right and wrong, and the unknown name: a miss is cached like a wrong password
		t.Fatalf("cache entries %d", len(a.cache))
	}
}

// TestUnknownUserCachedLikeWrongPassword: repeating a wrong pair must cost
// the same whether or not the name exists. A negative entry kept only for
// known names let a client tell them apart by the second attempt's timing
// (a full PBKDF2 for the unknown name against a cache hit for the known).
func TestUnknownUserCachedLikeWrongPassword(t *testing.T) {
	f, err := filtertest.Build("basic_auth", "staff", filter.Options{"users_file": usersFile(t), "cache_ttl": "5m"})
	if err != nil {
		t.Fatal(err)
	}
	a := f.(*auth)
	req := func(user string) *http.Request {
		r, _ := http.NewRequest("GET", "http://h.example.test/x", nil)
		r.SetBasicAuth(user, "wrong-password-0")
		return r
	}
	timed := func(user string) time.Duration {
		start := time.Now()
		filtertest.Run(f, req(user), nil)
		return time.Since(start)
	}
	timed("alice")
	timed("nobody")
	if len(a.cache) != 2 {
		t.Fatalf("both misses cached: %d entries", len(a.cache))
	}
	// Second attempts are cache hits for both: neither pays the hash.
	known, unknown := timed("alice"), timed("nobody")
	if known > 20*time.Millisecond || unknown > 20*time.Millisecond {
		t.Fatalf("second attempt not served from the cache: known %v unknown %v", known, unknown)
	}
}

// TestCheckGivesUpWithContext: a caller whose request ended while queued
// on the verification semaphore is refused at once rather than holding
// its slot for the whole wait.
func TestCheckGivesUpWithContext(t *testing.T) {
	f, err := filtertest.Build("basic_auth", "staff", filter.Options{"users_file": usersFile(t), "cache_ttl": "0"})
	if err != nil {
		t.Fatal(err)
	}
	a := f.(*auth)
	for i := 0; i < cap(a.sem); i++ {
		a.sem <- struct{}{} // every slot busy
	}
	defer func() {
		for i := 0; i < cap(a.sem); i++ {
			<-a.sem
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if a.check(ctx, "alice", "correct-horse-battery") {
		t.Fatal("accepted without verifying")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("blocked on a full semaphore with a dead context")
	}
	// A queue deeper than the bound is refused even with a live context.
	a.waiting.Store(int32(passwd.MaxQueuePerSlot*cap(a.sem) + 1))
	if a.check(context.Background(), "alice", "correct-horse-battery") {
		t.Fatal("accepted past the queue bound")
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
