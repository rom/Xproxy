package headerguard

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func TestGuard(t *testing.T) {
	f, err := filtertest.Build("header_guard", "api", filter.Options{
		"require": []any{map[string]any{"header": "X-API-Key", "pattern": "^[a-f0-9]{8}$"}},
		"deny":    []any{map[string]any{"header": "User-Agent", "pattern": "(?i)sqlmap"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := func(key, ua string) *http.Request {
		r, _ := http.NewRequest("GET", "http://h.example.test/x", nil)
		if key != "" {
			r.Header.Set("X-API-Key", key)
		}
		if ua != "" {
			r.Header.Set("User-Agent", ua)
		}
		return r
	}
	if v := filtertest.Run(f, req("deadbeef", "curl"), nil).Request; v.Deny {
		t.Fatalf("valid request denied: %+v", v)
	}
	v := filtertest.Run(f, req("", "curl"), nil).Request
	if !v.Deny || v.Status != 403 || v.Reason != "api" || !strings.Contains(v.Detail, "X-API-Key") {
		t.Fatalf("missing key: %+v", v)
	}
	v = filtertest.Run(f, req("deadbeef", "sqlmap/1.7"), nil).Request
	if !v.Deny || !strings.Contains(v.Detail, "User-Agent") {
		t.Fatalf("scanner not denied: %+v", v)
	}
	v = filtertest.Run(f, req("nothex!!", "curl"), nil).Request
	if !v.Deny {
		t.Fatal("bad key accepted")
	}
}

func TestValidate(t *testing.T) {
	bad := []filter.Options{
		{},
		{"require": []any{map[string]any{"header": "X", "pattern": "("}}},
		{"deny": []any{map[string]any{"header": "bad name", "pattern": "x"}}},
		{"deny": []any{map[string]any{"header": "X", "pattern": "x"}}, "status": 200},
		{"deny": []any{map[string]any{"header": "X", "pattern": "x"}}, "bogus": 1},
	}
	for i, o := range bad {
		if _, err := filtertest.Build("header_guard", "g", o); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := filtertest.Build("no_such_kind", "g", nil); err == nil {
		t.Fatal("unknown kind accepted")
	}
}
