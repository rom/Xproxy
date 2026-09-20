package basicauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/passwd"
)

// TestInstanceSurface covers the parts of the filter's contract the
// request path does not exercise on its own: the name the security log
// carries, the response phase, and the access log attribute that names
// who was let in.
func TestInstanceSurface(t *testing.T) {
	dir := t.TempDir()
	hash, err := passwd.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(dir, "users")
	if err := os.WriteFile(users, []byte("alice:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, ok := filter.Lookup("basic_auth")
	if !ok {
		t.Fatal("the basic_auth kind is not registered")
	}
	opts := filter.Options{"users_file": users, "realm": "xproxy", "forward_user_header": "X-User"}
	if err := k.Validate(opts); err != nil {
		t.Fatal(err)
	}
	f, err := k.New("admin-auth", opts, filter.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if f.Name() != "admin-auth" {
		t.Fatalf("the filter is named %q; the security log's reason comes from this", f.Name())
	}

	// An anonymous request is refused and logs nothing about a user.
	in := f.Begin(context.Background(), &filter.Info{})
	v := in.Request(httptest.NewRequest("GET", "http://a/x", nil))
	if !v.Deny || v.Status != http.StatusUnauthorized {
		t.Fatalf("anonymous: %+v", v)
	}
	if v.Reason != "admin-auth" {
		t.Fatalf("the deny names %q", v.Reason)
	}
	if attrs := in.End(); attrs != nil {
		t.Fatalf("a refused request logged %v", attrs)
	}

	// An authenticated one passes, forwards the name and is logged.
	in = f.Begin(context.Background(), &filter.Info{})
	r := httptest.NewRequest("GET", "http://a/x", nil)
	r.SetBasicAuth("alice", "correct horse battery staple")
	r.Header.Set("X-User", "root") // a client supplied copy
	if v := in.Request(r); v.Deny {
		t.Fatalf("denied a good credential: %+v", v)
	}
	if got := r.Header.Get("X-User"); got != "alice" {
		t.Fatalf("the forwarded user is %q", got)
	}
	if r.Header.Get("Authorization") != "" {
		t.Fatal("the credential was forwarded upstream")
	}
	attrs := in.End()
	if len(attrs) != 2 || attrs[0] != "auth_user" || attrs[1] != "alice" {
		t.Fatalf("the access log attributes are %v", attrs)
	}
	// The response phase never has an opinion: authentication happened
	// on the way in.
	if v := in.Response(&http.Response{StatusCode: 200, Header: http.Header{}}); v.Deny {
		t.Fatal("the response phase denied")
	}
}
