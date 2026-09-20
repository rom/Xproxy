package waf

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// TestBodyLimitPartialPassesRest: with request_body_limit_action partial
// the engine inspects the first limit bytes and the upstream still
// receives the whole body (it used to receive only the inspected prefix,
// which broke every request over the limit).
func TestBodyLimitPartialPassesRest(t *testing.T) {
	cfg := &config.WAF{
		Profiles:               []config.WAFProfile{{Name: "default", CRS: &config.CRS{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}}},
		DefaultMode:            "block",
		DefaultProfile:         "default",
		RequestBodyLimit:       64,
		RequestBodyLimitAction: "partial",
		ResponseBodyLimit:      4096,
		ResponseMIMETypes:      []string{"text/plain"},
	}
	e, err := New(cfg, Need{"default": {ModeBlock: true}}, NewStats(), nolog)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("a=1&", 50) // 200 bytes
	r := httptest.NewRequest("POST", "http://example.com/form", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.RemoteAddr = "203.0.113.1:4444"
	f, _ := e.Filter("default", ModeBlock)
	in := f.Begin(context.Background(), info())
	if v := in.Request(r); v.Deny {
		t.Fatalf("partial mode denied: %+v", v)
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != body {
		t.Fatalf("upstream body %d bytes, want %d", len(got), len(body))
	}
	in.End()
}
