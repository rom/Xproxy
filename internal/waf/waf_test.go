package waf

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

func engine(t *testing.T, inspect bool) *Engine {
	t.Helper()
	cfg := &config.WAF{
		Profiles:               []config.WAFProfile{{Name: "default", CRS: &config.CRS{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}}},
		DefaultMode:            "block",
		DefaultProfile:         "default",
		RequestBodyLimit:       4096,
		RequestBodyLimitAction: "reject",
		InspectResponses:       inspect,
		ResponseBodyLimit:      4096,
		ResponseMIMETypes:      []string{"text/html", "text/plain"},
	}
	e, err := New(cfg, Need{"default": {ModeBlock: true, ModeDetect: true}}, NewStats(), nolog)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func info() *filter.Info {
	return &filter.Info{RequestID: "req1", ClientIP: netip.MustParseAddr("203.0.113.1"), Route: "r", Host: "example.com", Path: "/"}
}

func run(t *testing.T, e *Engine, mode Mode, r *http.Request) (filter.Verdict, []any) {
	t.Helper()
	f, err := e.Filter("default", mode)
	if err != nil {
		t.Fatal(err)
	}
	in := f.Begin(context.Background(), info())
	v := in.Request(r)
	return v, in.End()
}

func TestBlockSQLi(t *testing.T) {
	e := engine(t, false)
	r := httptest.NewRequest("GET", "http://example.com/items?id=1%27%20OR%20%271%27=%271", nil)
	r.RemoteAddr = "203.0.113.1:4444"
	v, attrs := run(t, e, ModeBlock, r)
	if !v.Deny || v.Status != 403 || v.Reason != "waf" {
		t.Fatalf("verdict %+v", v)
	}
	if !hasAttr(attrs, "waf_matched") {
		t.Fatalf("attrs %v", attrs)
	}
}

func TestDetectMode(t *testing.T) {
	e := engine(t, false)
	r := httptest.NewRequest("GET", "http://example.com/?q=<script>alert(1)</script>", nil)
	v, attrs := run(t, e, ModeDetect, r)
	if v.Deny {
		t.Fatal("detect mode must not deny")
	}
	if !hasAttr(attrs, "waf_detected") || !hasAttr(attrs, "waf_matched") {
		t.Fatalf("detect attrs %v", attrs)
	}
}

func TestCleanRequestPasses(t *testing.T) {
	e := engine(t, false)
	r := httptest.NewRequest("GET", "http://example.com/products?page=2&sort=name", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "text/html")
	v, attrs := run(t, e, ModeBlock, r)
	if v.Deny {
		t.Fatalf("clean request denied: %+v %v", v, attrs)
	}
	if attrs != nil {
		t.Fatalf("clean request produced attrs: %v", attrs)
	}
}

func TestBodyInspectionAndReplay(t *testing.T) {
	e := engine(t, false)
	body := "user=admin&pass=x' UNION SELECT password FROM users--"
	r := httptest.NewRequest("POST", "http://example.com/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v, _ := run(t, e, ModeBlock, r)
	if !v.Deny {
		t.Fatal("SQLi in body not blocked")
	}
	// A clean body is still readable by the upstream afterwards.
	r = httptest.NewRequest("POST", "http://example.com/login", strings.NewReader("user=alice&pass=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	f, _ := e.Filter("default", ModeBlock)
	in := f.Begin(context.Background(), info())
	if v := in.Request(r); v.Deny {
		t.Fatalf("clean body denied: %+v", v)
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != "user=alice&pass=secret" {
		t.Fatalf("body not replayed: %q", got)
	}
	in.End()
}

func TestBodyLimitReject(t *testing.T) {
	e := engine(t, false)
	r := httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader(strings.Repeat("a", 5000)))
	r.Header.Set("Content-Type", "text/plain")
	v, _ := run(t, e, ModeBlock, r)
	if !v.Deny || v.Status != 413 {
		t.Fatalf("oversize body: %+v", v)
	}
}

func TestResponseInspection(t *testing.T) {
	e := engine(t, true)
	f, _ := e.Filter("default", ModeBlock)
	in := f.Begin(context.Background(), info())
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	if v := in.Request(r); v.Deny {
		t.Fatalf("request denied: %+v", v)
	}
	// A leaked SQL error message in the response is an outbound anomaly.
	leak := "<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</html>"
	resp := &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(leak)), ContentLength: int64(len(leak))}
	v := in.Response(resp)
	if !v.Deny {
		t.Fatalf("SQL error leak not blocked: %+v", v)
	}
	in.End()

	// Clean response passes and body is intact.
	in = f.Begin(context.Background(), info())
	in.Request(r)
	resp = &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader("<html>hello</html>")), ContentLength: 18}
	if v := in.Response(resp); v.Deny {
		t.Fatalf("clean response denied: %+v", v)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "<html>hello</html>" || resp.ContentLength != 18 {
		t.Fatalf("response body altered: %q %d", b, resp.ContentLength)
	}
	in.End()

	// Oversize response is passed through uninspected.
	in = f.Begin(context.Background(), info())
	in.Request(r)
	big := strings.Repeat("x", 5000)
	resp = &http.Response{StatusCode: 200, Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(big)), ContentLength: -1}
	if v := in.Response(resp); v.Deny {
		t.Fatal("oversize response denied")
	}
	b, _ = io.ReadAll(resp.Body)
	if len(b) != 5000 {
		t.Fatalf("oversize body truncated: %d", len(b))
	}
	in.End()
}

func TestCustomDirectivesAndBadRules(t *testing.T) {
	cfg := &config.WAF{
		Profiles:    []config.WAFProfile{{Name: "custom", Directives: `SecRule REQUEST_HEADERS:X-Evil "@streq yes" "id:100001,phase:1,deny,status:406,msg:'evil header'"`}},
		DefaultMode: "block", DefaultProfile: "custom", RequestBodyLimit: 4096, RequestBodyLimitAction: "reject", ResponseBodyLimit: 4096,
	}
	e, err := New(cfg, Need{"custom": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := e.Filter("custom", ModeBlock)
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("X-Evil", "yes")
	in := f.Begin(context.Background(), info())
	if v := in.Request(r); !v.Deny || v.Status != 406 {
		t.Fatalf("custom rule: %+v", v)
	}
	in.End()
	if _, err := e.Filter("custom", ModeDetect); err == nil {
		t.Fatal("uncompiled mode returned a filter")
	}
	if f, err := e.Filter("custom", ModeOff); f != nil || err != nil {
		t.Fatal("off mode should return nil, nil")
	}
	cfg.Profiles[0].Directives = `SecRule THIS IS NOT VALID`
	if _, err := New(cfg, Need{"custom": {ModeBlock: true}}, nil, nolog); err == nil {
		t.Fatal("invalid rule compiled")
	}
}

func TestOnlyNeededModesCompiled(t *testing.T) {
	cfg := &config.WAF{Profiles: []config.WAFProfile{{Name: "a", CRS: &config.CRS{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}}, {Name: "b", CRS: &config.CRS{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}}},
		DefaultMode: "block", DefaultProfile: "a", RequestBodyLimit: 4096, RequestBodyLimitAction: "reject", ResponseBodyLimit: 4096}
	e, err := New(cfg, Need{"a": {ModeDetect: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.profiles["b"]; ok {
		t.Fatal("unused profile compiled")
	}
	if e.profiles["a"].block != nil || e.profiles["a"].detect == nil {
		t.Fatal("wrong modes compiled")
	}
}

func hasAttr(attrs []any, key string) bool {
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == key {
			return true
		}
	}
	return false
}
