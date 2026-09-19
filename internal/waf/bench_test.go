package waf

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// BenchmarkRequest measures a clean GET through the CRS in block mode:
// the per request cost of the WAF on the hot path.
func BenchmarkRequest(b *testing.B) {
	e, err := New(wafConfig(nil), Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		b.Fatal(err)
	}
	f, _ := e.Filter("default", ModeBlock)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("GET", "http://example.com/products?page=2&sort=name", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Accept", "text/html")
		in := f.Begin(context.Background(), info())
		if v := in.Request(r); v.Deny {
			b.Fatalf("denied: %+v", v)
		}
		in.End()
	}
}

// BenchmarkRequestWithStats adds the rule statistics and learning cost.
func BenchmarkRequestWithStats(b *testing.B) {
	st := NewStats()
	e, err := New(wafConfig(&config.WAFLearning{Enabled: true, MinHits: 5, MaxEntries: 1000}), Need{"default": {ModeBlock: true}}, st, nolog)
	if err != nil {
		b.Fatal(err)
	}
	f, _ := e.Filter("default", ModeBlock)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("GET", "http://example.com/search?q=<script>alert(1)</script>", nil)
		in := f.Begin(context.Background(), info())
		in.Request(r)
		in.End()
	}
}
