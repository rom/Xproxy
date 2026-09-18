package icap

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/icap/icaptest"
)

func svc(t *testing.T, f *icaptest.Server, preview string) *Service {
	t.Helper()
	s, err := NewService(config.ICAPService{Name: "av", URL: f.URL(), ConnectTimeout: config.Duration(time.Second), Timeout: config.Duration(2 * time.Second), MaxConns: 2, MaxBody: 1 << 20, BodyLimitAction: "reject", Fail: "closed", Preview: preview})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestOptionsAndReqmod(t *testing.T) {
	f := icaptest.New(t, 16)
	s := svc(t, f, "auto")
	st := s.Status()
	if !st.Reachable || st.Preview != 16 || !st.Allow204 || st.ISTag != `"tag-1"` {
		t.Fatalf("options: %+v", st)
	}
	ctx := context.Background()
	req := httptest.NewRequest("POST", "http://example.test/upload", nil)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Connection", "keep-alive") // hop-by-hop, must not be forwarded

	// Clean body larger than the preview: preview then 100 Continue then 204.
	v, err := s.Reqmod(ctx, req, []byte(strings.Repeat("clean data ", 10)))
	if err != nil || v.Kind != Unmodified || v.Status != 204 {
		t.Fatalf("clean: %v %+v", err, v)
	}
	f.Mu.Lock()
	previews, body := f.Previews, f.Bodies[len(f.Bodies)-1]
	f.Mu.Unlock()
	if previews != 1 || body != strings.Repeat("clean data ", 10) {
		t.Fatalf("preview flow: previews=%d body=%q", previews, body)
	}
	// Infected body is blocked on the preview alone.
	v, err = s.Reqmod(ctx, req, []byte("EICAR-TEST-FILE"+strings.Repeat("x", 100)))
	if err != nil || v.Kind != Replaced || v.Response == nil || v.Response.StatusCode != 403 {
		t.Fatalf("blocked: %v %+v", err, v)
	}
	page, _ := io.ReadAll(v.Response.Body)
	if string(page) != "<html>blocked by scanner</html>" || v.Response.Header.Get("X-Virus") != "found" || v.Response.ContentLength != int64(len(page)) {
		t.Fatalf("block page: %q %v", page, v.Response.Header)
	}
	// Small body: no preview, full send.
	v, err = s.Reqmod(ctx, req, []byte("tiny"))
	if err != nil || v.Kind != Unmodified {
		t.Fatalf("tiny: %v %+v", err, v)
	}
	// No body (GET).
	get := httptest.NewRequest("GET", "http://example.test/page", nil)
	if v, err := s.Reqmod(ctx, get, nil); err != nil || v.Kind != Unmodified {
		t.Fatalf("get: %v %+v", err, v)
	}
	// Modified request.
	mod := httptest.NewRequest("POST", "http://example.test/modify", nil)
	v, err = s.Reqmod(ctx, mod, []byte("original"))
	if err != nil || v.Kind != ModifiedRequest || v.Request == nil {
		t.Fatalf("modified: %v %+v", err, v)
	}
	nb, _ := io.ReadAll(v.Request.Body)
	if v.Request.URL.Path != "/modified" || v.Request.Header.Get("X-Scanned") != "yes" || string(nb) != "clean" {
		t.Fatalf("modified request: %s %v %q", v.Request.URL, v.Request.Header, nb)
	}
	// Connection pooling: several requests, few connections.
	f.Mu.Lock()
	n := len(f.Requests)
	f.Mu.Unlock()
	if n < 6 {
		t.Fatalf("requests seen %d", n)
	}
	st = s.Status()
	if st.Requests != 5 || st.Unmodified != 3 || st.Replacements != 1 || st.Modified != 1 || st.Errors != 0 {
		t.Fatalf("counters %+v", st)
	}
}

func TestRespmodAndErrors(t *testing.T) {
	f := icaptest.New(t, 0)
	s := svc(t, f, "off")
	ctx := context.Background()
	req := httptest.NewRequest("GET", "http://example.test/download", nil)
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/octet-stream"}}}
	v, err := s.Respmod(ctx, req, resp, []byte("harmless"))
	if err != nil || v.Kind != Unmodified {
		t.Fatalf("respmod clean: %v %+v", err, v)
	}
	v, err = s.Respmod(ctx, req, resp, []byte("EICAR"))
	if err != nil || v.Kind != ModifiedResponse || v.Response.StatusCode != 403 {
		t.Fatalf("respmod blocked: %v %+v", err, v)
	}
	rw := httptest.NewRequest("GET", "http://example.test/rewrite", nil)
	v, err = s.Respmod(ctx, rw, resp, []byte("payload"))
	if err != nil || v.Kind != ModifiedResponse || v.Response.Header.Get("X-Scanned") != "yes" {
		t.Fatalf("respmod rewrite: %v %+v", err, v)
	}
	b, _ := io.ReadAll(v.Response.Body)
	if string(b) != "rewritten" {
		t.Fatalf("rewrite body %q", b)
	}
	// Server error surfaces as an error and the connection is dropped.
	er := httptest.NewRequest("GET", "http://example.test/error", nil)
	if _, err := s.Reqmod(ctx, er, nil); err == nil {
		t.Fatal("500 accepted")
	}
	// Timeout.
	hang := httptest.NewRequest("GET", "http://example.test/hang", nil)
	tctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.Reqmod(tctx, hang, nil); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("hang: %v after %v", err, time.Since(start))
	}
	st := s.Status()
	if st.Errors != 2 || st.Reachable {
		t.Fatalf("errors %+v", st)
	}
	// Recovers on the next good exchange.
	if v, err := s.Reqmod(ctx, req, nil); err != nil || v.Kind != Unmodified || !s.Status().Reachable {
		t.Fatalf("recovery: %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	s, err := NewService(config.ICAPService{Name: "dead", URL: "icap://127.0.0.1:1/scan", ConnectTimeout: config.Duration(200 * time.Millisecond), Timeout: config.Duration(time.Second), MaxConns: 1, MaxBody: 4096, BodyLimitAction: "bypass", Fail: "open", Preview: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Status().Reachable {
		t.Fatal("dead service reported reachable")
	}
	if _, err := s.Reqmod(context.Background(), httptest.NewRequest("GET", "http://x/", nil), nil); err == nil {
		t.Fatal("no error from dead service")
	}
	if _, err := NewService(config.ICAPService{Name: "bad", URL: "::not a url"}); err == nil {
		t.Fatal("bad url accepted")
	}
}

func TestHeaderBlocks(t *testing.T) {
	req := httptest.NewRequest("POST", "http://h.test/p?q=1", nil)
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("X-Ok", "1")
	req.Header.Set("X-Bad", "a\r\nInjected: x")
	blk := string(requestHeaderBlock(req))
	if !strings.HasPrefix(blk, "POST /p?q=1 HTTP/1.1\r\nHost: h.test\r\n") || strings.Contains(blk, "Transfer-Encoding") || strings.Contains(blk, "Injected") || !strings.Contains(blk, "X-Ok: 1\r\n") || !strings.HasSuffix(blk, "\r\n\r\n") {
		t.Fatalf("request block %q", blk)
	}
	resp := &http.Response{StatusCode: 404, Header: http.Header{"Content-Type": {"text/html"}, "Connection": {"close"}}}
	rb := string(responseHeaderBlock(resp))
	if !strings.HasPrefix(rb, "HTTP/1.1 404 Not Found\r\n") || strings.Contains(rb, "Connection") {
		t.Fatalf("response block %q", rb)
	}
}
