package headerguard

import (
	"net/http/httptest"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// TestEveryHeaderInstanceIsJudged: a payload hidden behind a benign first
// instance of a header is still caught, and a required pattern must hold
// for every instance.
func TestEveryHeaderInstanceIsJudged(t *testing.T) {
	f, err := filtertest.Build("header_guard", "g", filter.Options{
		"deny":    []any{map[string]any{"header": "User-Agent", "pattern": "(?i)sqlmap"}},
		"require": []any{map[string]any{"header": "X-Tenant", "pattern": "^acme$"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://app.test/", nil)
	r.Header.Add("User-Agent", "Mozilla/5.0")
	r.Header.Add("User-Agent", "sqlmap/1.7")
	r.Header.Set("X-Tenant", "acme")
	if v := filtertest.Run(f, r, nil).Request; !v.Deny {
		t.Fatal("second User-Agent instance not judged")
	}
	r = httptest.NewRequest("GET", "http://app.test/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Add("X-Tenant", "acme")
	r.Header.Add("X-Tenant", "evil")
	if v := filtertest.Run(f, r, nil).Request; !v.Deny {
		t.Fatal("second X-Tenant instance not required to match")
	}
	r = httptest.NewRequest("GET", "http://app.test/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("X-Tenant", "acme")
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("clean request denied: %+v", v)
	}
}
