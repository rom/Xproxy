package icap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

// An ICAP service is a third party on the request path, reached over a
// socket the proxy opens and speaking a protocol this package parses by
// hand. A scanner that has been compromised, replaced by something that
// is not an ICAP server, or simply upgraded badly must not be able to
// do more than fail the request: the fail setting decides whether that
// means the request goes through or does not, and nothing the server
// sends may make this process leave that choice.

// rawServer answers every connection with bytes a test chooses.
type rawServer struct {
	ln      net.Listener
	reply   atomic.Value // func(method string, n int) string, or nil to hang
	conns   atomic.Int64
	hangFor time.Duration
}

func newRawServer(t *testing.T, reply func(n int) string) *rawServer {
	t.Helper()
	return newRawServerCounting(t, nil, reply)
}

// newRawServerFor answers the OPTIONS probe every service makes at
// construction with a plain 204 and everything else with reply, so a
// test can aim a malformed answer at the exchange it means to break.
func newRawServerFor(t *testing.T, reply func(n int) string) *rawServer {
	t.Helper()
	return newRawServerMethod(t, nil, func(method string, n int) string {
		if method == "OPTIONS" {
			return "ICAP/1.0 200 OK\r\nISTag: \"x\"\r\nMethods: REQMOD, RESPMOD\r\nAllow: 204\r\nEncapsulated: null-body=0\r\n\r\n"
		}
		return reply(n)
	})
}

// newRawServerCounting is newRawServer with a counter of accepted
// connections, so a test can tell a reused connection from a new one.
func newRawServerCounting(t *testing.T, opened *atomic.Int64, reply func(n int) string) *rawServer {
	t.Helper()
	return newRawServerMethod(t, opened, func(_ string, n int) string { return reply(n) })
}

// newRawServerMethod is the general form: the reply may depend on the
// method of the request it is answering.
func newRawServerMethod(t *testing.T, opened *atomic.Int64, reply func(method string, n int) string) *rawServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &rawServer{ln: ln}
	s.reply.Store(reply)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if opened != nil {
				opened.Add(1)
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *rawServer) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	for {
		// Read one request: the request line, then headers until a
		// blank line.
		method := ""
		for i := 0; ; i++ {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if i == 0 {
				method, _, _ = strings.Cut(line, " ")
			}
			if line == "" {
				break
			}
		}
		n := int(s.conns.Add(1))
		if s.hangFor > 0 {
			time.Sleep(s.hangFor)
		}
		fn, _ := s.reply.Load().(func(method string, n int) string)
		if fn == nil {
			return
		}
		out := fn(method, n)
		if out == "" {
			return // hang up without answering
		}
		if _, err := io.WriteString(c, out); err != nil {
			return
		}
		// Drain whatever body bytes arrived with the request so the
		// next read starts on a request line.
		for br.Buffered() > 0 {
			if _, err := br.Discard(br.Buffered()); err != nil {
				return
			}
		}
	}
}

func (s *rawServer) url() string { return "icap://" + s.ln.Addr().String() + "/scan" }

// hostileService builds a service pointed at a raw server.
func hostileService(t *testing.T, s *rawServer, fail string) *Service {
	t.Helper()
	svc, err := NewService(config.ICAPService{
		Name: "av", URL: s.url(),
		ConnectTimeout: config.Duration(time.Second), Timeout: config.Duration(2 * time.Second),
		MaxConns: 2, MaxBody: 1 << 20, BodyLimitAction: "reject", Fail: fail, Preview: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc
}

// TestMalformedResponses feeds the client every shape of answer an ICAP
// server should not send. Each must be an error rather than a verdict:
// a parser that guessed here would let a scanner's failure look like a
// clean result.
func TestMalformedResponses(t *testing.T) {
	cases := map[string]string{
		"empty":                     "",
		"not icap":                  "HTTP/1.1 200 OK\r\n\r\n",
		"no status":                 "ICAP/1.0\r\n\r\n",
		"status is not a number":    "ICAP/1.0 OK fine\r\n\r\n",
		"status out of range":       "ICAP/1.0 999 What\r\n\r\n",
		"status is negative":        "ICAP/1.0 -1 What\r\n\r\n",
		"header without a colon":    "ICAP/1.0 200 OK\r\nJustAHeader\r\n\r\n",
		"truncated headers":         "ICAP/1.0 200 OK\r\nISTag: \"x\"\r\n",
		"no encapsulated":           "ICAP/1.0 200 OK\r\nISTag: \"x\"\r\n\r\n",
		"encapsulated is nonsense":  "ICAP/1.0 200 OK\r\nEncapsulated: banana\r\n\r\n",
		"encapsulated offset":       "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=-1\r\n\r\n",
		"encapsulated not a number": "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=x\r\n\r\n",
		"encapsulated past the end": "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=99999\r\n\r\n",
		"body without headers":      "ICAP/1.0 200 OK\r\nEncapsulated: res-body=0\r\n\r\n",
		"truncated chunk":           "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=40\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n5\r\nab",
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			raw := newRawServer(t, func(int) string { return reply })
			svc := hostileService(t, raw, "closed")
			req := httptest.NewRequest("POST", "http://example.test/upload", nil)
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}}
			if v, err := svc.Respmod(context.Background(), req, resp, []byte("data")); err == nil {
				t.Fatalf("accepted as the verdict %+v", v)
			}
		})
	}
}

// TestEnormousHeaderIsRefused covers a server that answers with an
// unbounded header block. The client reads it into memory, so the
// ceiling is what stops one scanner from taking the process down.
func TestEnormousHeaderIsRefused(t *testing.T) {
	var b strings.Builder
	b.WriteString("ICAP/1.0 200 OK\r\n")
	for i := 0; b.Len() < 4*maxICAPHeaderBytes; i++ {
		fmt.Fprintf(&b, "X-Pad-%d: %s\r\n", i, strings.Repeat("x", 1000))
	}
	b.WriteString("\r\n")
	raw := newRawServer(t, func(int) string { return b.String() })
	svc := hostileService(t, raw, "closed")
	done := make(chan error, 1)
	go func() {
		req := httptest.NewRequest("POST", "http://example.test/upload", nil)
		_, err := svc.Reqmod(context.Background(), req, []byte("data"))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an unbounded header block was accepted")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("reading an unbounded header block did not finish")
	}
}

// TestServerHangsUp covers the connection that closes at each stage:
// before answering, and between one request and the next. The second is
// the ordinary case for a pooled connection the server timed out, and
// it must not turn into a failed request.
func TestServerHangsUp(t *testing.T) {
	raw := newRawServer(t, func(int) string { return "" })
	svc := hostileService(t, raw, "closed")
	req := httptest.NewRequest("POST", "http://example.test/upload", nil)
	if _, err := svc.Reqmod(context.Background(), req, []byte("data")); err == nil {
		t.Fatal("a server that hung up produced a verdict")
	}

	// Now a server that answers once per connection and then closes:
	// every request still gets its answer, on a fresh connection.
	var served atomic.Int64
	raw2 := newRawServer(t, func(int) string {
		served.Add(1)
		return "ICAP/1.0 204 No Content\r\nISTag: \"x\"\r\nEncapsulated: null-body=0\r\n\r\n"
	})
	svc2 := hostileService(t, raw2, "closed")
	for i := 0; i < 5; i++ {
		v, err := svc2.Reqmod(context.Background(), req, []byte("data"))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if v.Kind != Unmodified {
			t.Fatalf("request %d: %+v", i, v)
		}
	}
	if served.Load() < 5 {
		t.Fatalf("only %d requests reached the server", served.Load())
	}
}

// TestSlowServer covers a scanner that takes longer than the timeout.
// The request must come back with an error while the scanner is still
// thinking, because the alternative is the client's connection held
// open by a third party's problem.
func TestSlowServer(t *testing.T) {
	raw := newRawServer(t, func(int) string {
		return "ICAP/1.0 204 No Content\r\nISTag: \"x\"\r\nEncapsulated: null-body=0\r\n\r\n"
	})
	raw.hangFor = 5 * time.Second
	svc, err := NewService(config.ICAPService{
		Name: "av", URL: raw.url(),
		ConnectTimeout: config.Duration(time.Second), Timeout: config.Duration(300 * time.Millisecond),
		MaxConns: 2, MaxBody: 1 << 20, BodyLimitAction: "reject", Fail: "closed", Preview: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	req := httptest.NewRequest("POST", "http://example.test/upload", nil)
	start := time.Now()
	if _, err := svc.Reqmod(context.Background(), req, []byte("data")); err == nil {
		t.Fatal("a scanner slower than the timeout produced a verdict")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the request waited %v for a 300ms timeout", took)
	}
}

// TestUnreachableService covers the service that is not there at all,
// which is what a scanner being restarted looks like.
func TestUnreachableService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing is listening there now

	svc, err := NewService(config.ICAPService{
		Name: "av", URL: "icap://" + addr + "/scan",
		ConnectTimeout: config.Duration(300 * time.Millisecond), Timeout: config.Duration(time.Second),
		MaxConns: 2, MaxBody: 1 << 20, BodyLimitAction: "reject", Fail: "closed", Preview: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if st := svc.Status(); st.Reachable {
		t.Fatalf("a service with nothing behind it reports reachable: %+v", st)
	}
	req := httptest.NewRequest("POST", "http://example.test/upload", nil)
	if _, err := svc.Reqmod(context.Background(), req, []byte("data")); err == nil {
		t.Fatal("an unreachable service produced a verdict")
	}
	// The status names the service, says it is not reachable and counts
	// the failure, which is what `xproxyctl icap` shows.
	st := svc.Status()
	if st.Name != "av" || st.Reachable || st.Errors == 0 {
		t.Fatalf("status %+v", st)
	}
}

// TestContextCancellation covers the client hanging up while the
// scanner is still thinking: the call must return rather than hold the
// goroutine and the pooled connection.
func TestContextCancellation(t *testing.T) {
	raw := newRawServer(t, func(int) string {
		return "ICAP/1.0 204 No Content\r\nISTag: \"x\"\r\nEncapsulated: null-body=0\r\n\r\n"
	})
	raw.hangFor = 3 * time.Second
	svc := hostileService(t, raw, "closed")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	req := httptest.NewRequest("POST", "http://example.test/upload", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := svc.Reqmod(ctx, req, []byte("data")); err == nil {
			t.Error("a cancelled request produced a verdict")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled request did not return")
	}
}

// TestKindString covers the verdict kinds as the access log spells
// them, which is what an operator greps for.
func TestKindString(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range []Kind{Unmodified, ModifiedRequest, Replaced, ModifiedResponse} {
		s := k.String()
		if s == "" {
			t.Fatalf("kind %d has no name", k)
		}
		if seen[s] {
			t.Fatalf("two kinds render as %q", s)
		}
		seen[s] = true
	}
	if got := Kind(99).String(); got == "" {
		t.Fatal("an unknown kind has no name")
	}
}

// TestConcurrentRequestsSharePooledConnections drives the service from
// more goroutines than the pool holds. max_conns bounds the idle
// connections kept for reuse, not the requests in flight — the proxy's
// own concurrency limit does that — so what matters here is that the
// pool is used rather than grown, and that every request gets its
// answer.
func TestConcurrentRequestsSharePooledConnections(t *testing.T) {
	var opened atomic.Int64
	raw := newRawServerCounting(t, &opened, func(int) string {
		time.Sleep(5 * time.Millisecond)
		return "ICAP/1.0 204 No Content\r\nISTag: \"x\"\r\nEncapsulated: null-body=0\r\n\r\n"
	})
	svc := hostileService(t, raw, "closed")
	req := httptest.NewRequest("POST", "http://example.test/upload", nil)

	// Serially, the pool means one connection serves every request.
	before := opened.Load()
	for i := 0; i < 20; i++ {
		if _, err := svc.Reqmod(context.Background(), req, []byte("data")); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if n := opened.Load() - before; n > 2 {
		t.Fatalf("20 serial requests opened %d connections; the pool is not being reused", n)
	}

	// Concurrently, every request still gets its answer.
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			_, err := svc.Reqmod(context.Background(), req, []byte("data"))
			done <- err
		}()
	}
	for i := 0; i < 16; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent request %d: %v", i, err)
		}
	}
}

// TestFilterFailOpenAndClosed is the decision that matters most in this
// package: what happens to a request when the scanner cannot answer.
// Closed means the request does not go through; open means it does, and
// the access log has to say so, because a bypass is the one case where
// traffic reached the origin unscanned.
func TestFilterFailOpenAndClosed(t *testing.T) {
	raw := newRawServer(t, func(int) string { return "" }) // always hangs up
	yes := true
	both := &config.RouteICAP{Request: &yes, Response: &yes}

	t.Run("closed", func(t *testing.T) {
		svc := hostileService(t, raw, "closed")
		f := svc.Filter(both)
		if f.Name() != "icap:av" {
			t.Fatalf("filter name %q", f.Name())
		}
		in := f.Begin(context.Background(), &filter.Info{})
		r := httptest.NewRequest("POST", "http://example.test/upload", strings.NewReader("data"))
		v := in.Request(r)
		if !v.Deny || v.Status != http.StatusBadGateway || v.Detail != "reqmod_unavailable" {
			t.Fatalf("verdict %+v", v)
		}
		if v.Headers["Retry-After"] == "" {
			t.Fatal("no Retry-After on an unavailable scanner")
		}
		attrs := fmt.Sprint(in.End())
		if !strings.Contains(attrs, "icap_error") || !strings.Contains(attrs, "icap_service") {
			t.Fatalf("the access log says nothing about why: %s", attrs)
		}
	})

	t.Run("open", func(t *testing.T) {
		svc := hostileService(t, raw, "open")
		f := svc.Filter(both)
		in := f.Begin(context.Background(), &filter.Info{})
		r := httptest.NewRequest("POST", "http://example.test/upload", strings.NewReader("data"))
		if v := in.Request(r); v.Deny {
			t.Fatalf("fail open denied: %+v", v)
		}
		attrs := fmt.Sprint(in.End())
		if !strings.Contains(attrs, "icap_bypassed") {
			t.Fatalf("a bypass was not recorded: %s", attrs)
		}
		if svc.Status().Bypassed == 0 {
			t.Fatal("the bypass was not counted")
		}
		// The body is still there for the origin: a bypass that ate it
		// would send a truncated request.
		got, err := io.ReadAll(r.Body)
		if err != nil || string(got) != "data" {
			t.Fatalf("the body after a bypass is %q (%v)", got, err)
		}
	})

	t.Run("response phase", func(t *testing.T) {
		svc := hostileService(t, raw, "open")
		f := svc.Filter(both)
		in := f.Begin(context.Background(), &filter.Info{})
		in.Request(httptest.NewRequest("GET", "http://example.test/x", nil))
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}},
			Body: io.NopCloser(strings.NewReader("hello")), ContentLength: 5}
		if v := in.Response(resp); v.Deny {
			t.Fatalf("fail open denied a response: %+v", v)
		}
		got, err := io.ReadAll(resp.Body)
		if err != nil || string(got) != "hello" {
			t.Fatalf("the response body after a bypass is %q (%v)", got, err)
		}
	})
}

// TestFilterBodyLimit covers a body larger than the scanner will take.
// Rejecting is one answer and bypassing is the other; what must not
// happen either way is a body that reaches the origin starting in the
// middle, because the filter read part of it first.
func TestFilterBodyLimit(t *testing.T) {
	yes, no := true, false
	raw := newRawServer(t, func(int) string {
		return "ICAP/1.0 204 No Content\r\nISTag: \"x\"\r\nEncapsulated: null-body=0\r\n\r\n"
	})
	build := func(action string) *Service {
		t.Helper()
		svc, err := NewService(config.ICAPService{
			Name: "av", URL: raw.url(),
			ConnectTimeout: config.Duration(time.Second), Timeout: config.Duration(2 * time.Second),
			MaxConns: 2, MaxBody: 16, BodyLimitAction: action, Fail: "closed", Preview: "off",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(svc.Close)
		return svc
	}
	big := strings.Repeat("x", 1000)

	t.Run("reject with a declared length", func(t *testing.T) {
		in := build("reject").Filter(&config.RouteICAP{Request: &yes, Response: &no}).Begin(context.Background(), &filter.Info{})
		r := httptest.NewRequest("POST", "http://example.test/upload", strings.NewReader(big))
		v := in.Request(r)
		if !v.Deny || v.Status != http.StatusRequestEntityTooLarge || v.Detail != "request_body_too_large" {
			t.Fatalf("verdict %+v", v)
		}
	})

	t.Run("bypass keeps the whole body", func(t *testing.T) {
		in := build("bypass").Filter(&config.RouteICAP{Request: &yes, Response: &no}).Begin(context.Background(), &filter.Info{})
		r := httptest.NewRequest("POST", "http://example.test/upload", strings.NewReader(big))
		r.ContentLength = -1 // chunked: the filter reads until the limit
		if v := in.Request(r); v.Deny {
			t.Fatalf("bypass denied: %+v", v)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != big {
			t.Fatalf("the origin would receive %d of %d bytes, starting %q", len(got), len(big), got[:min(20, len(got))])
		}
	})

	t.Run("bypass on the response", func(t *testing.T) {
		in := build("bypass").Filter(&config.RouteICAP{Request: &no, Response: &yes}).Begin(context.Background(), &filter.Info{})
		in.Request(httptest.NewRequest("GET", "http://example.test/x", nil))
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}},
			Body: io.NopCloser(strings.NewReader(big)), ContentLength: -1}
		if v := in.Response(resp); v.Deny {
			t.Fatalf("bypass denied: %+v", v)
		}
		got, err := io.ReadAll(resp.Body)
		if err != nil || string(got) != big {
			t.Fatalf("the client would receive %d of %d bytes (%v)", len(got), len(big), err)
		}
	})
}

// TestScannerMayNotRewriteProtectedHeaders is the trust boundary: a
// compromised scanner returns a modified request, and the headers that
// decide who the client is and where the request goes must survive it.
func TestScannerMayNotRewriteProtectedHeaders(t *testing.T) {
	yes, no := true, false
	modified := "HTTP/1.1 200 OK\r\n" +
		"Host: evil.test\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\n" +
		"Authorization: Bearer attacker\r\n" +
		"Cookie: session=attacker\r\n" +
		"X-Scanner: clean\r\n\r\n"
	head := "GET /elsewhere HTTP/1.1\r\n" + modified[len("HTTP/1.1 200 OK\r\n"):]
	reply := fmt.Sprintf("ICAP/1.0 200 OK\r\nISTag: \"x\"\r\nEncapsulated: req-hdr=0, null-body=%d\r\n\r\n%s", len(head), head)
	raw := newRawServerFor(t, func(int) string { return reply })
	svc := hostileService(t, raw, "closed")
	in := svc.Filter(&config.RouteICAP{Request: &yes, Response: &no}).Begin(context.Background(), &filter.Info{})

	r := httptest.NewRequest("POST", "http://example.test/upload", strings.NewReader("data"))
	r.Host = "example.test"
	r.Header.Set("X-Forwarded-For", "192.0.2.1")
	r.Header.Set("Authorization", "Bearer real")
	r.Header.Set("Cookie", "session=real")
	if v := in.Request(r); v.Deny {
		t.Fatalf("a modified request was denied: %+v", v)
	}
	if r.Host != "example.test" {
		t.Fatalf("the scanner changed the host to %q", r.Host)
	}
	if r.URL.Host != "" && r.URL.Host != "example.test" {
		t.Fatalf("the scanner redirected the request to %q", r.URL.Host)
	}
	for h, want := range map[string]string{
		"X-Forwarded-For": "192.0.2.1",
		"Authorization":   "Bearer real",
		"Cookie":          "session=real",
	} {
		if got := r.Header.Get(h); got != want {
			t.Errorf("the scanner rewrote %s to %q, want %q", h, got, want)
		}
	}
	// Headers it may set are applied.
	if got := r.Header.Get("X-Scanner"); got != "clean" {
		t.Errorf("a header the scanner may set was dropped: %q", got)
	}
	if !protectedHeader("Authorization") || protectedHeader("X-Scanner") {
		t.Fatal("protectedHeader disagrees with the behaviour above")
	}
}

// TestItoa covers the small integer renderer used for Content-Length.
func TestItoa(t *testing.T) {
	for _, n := range []int{0, 1, 9, 10, 99, 100, 1023, 1 << 20, 1<<31 - 1} {
		if got, want := itoa(n), strconv.Itoa(n); got != want {
			t.Fatalf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestFilterIsInertWhenNotScanning covers a route that scans only one
// direction: the other must not be read, buffered or sent anywhere.
func TestFilterIsInertWhenNotScanning(t *testing.T) {
	yes, no := true, false
	raw := newRawServer(t, func(int) string {
		return "ICAP/1.0 204 No Content\r\nISTag: \"x\"\r\nEncapsulated: null-body=0\r\n\r\n"
	})
	svc := hostileService(t, raw, "closed")

	reqOnly := svc.Filter(&config.RouteICAP{Request: &yes, Response: &no}).Begin(context.Background(), &filter.Info{})
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("body")), ContentLength: 4}
	if v := reqOnly.Response(resp); v.Deny {
		t.Fatalf("a request-only filter denied a response: %+v", v)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "body" {
		t.Fatalf("a request-only filter touched the response body: %q", got)
	}

	respOnly := svc.Filter(&config.RouteICAP{Request: &no, Response: &yes}).Begin(context.Background(), &filter.Info{})
	r := httptest.NewRequest("POST", "http://example.test/upload", strings.NewReader("data"))
	if v := respOnly.Request(r); v.Deny {
		t.Fatalf("a response-only filter denied a request: %+v", v)
	}
	body, _ := io.ReadAll(r.Body)
	if string(body) != "data" {
		t.Fatalf("a response-only filter consumed the request body: %q", body)
	}
}

// TestServiceConstruction covers the URL and TLS settings, which decide
// where the proxy sends every request body it scans.
func TestServiceConstruction(t *testing.T) {
	dir := t.TempDir()
	notPEM := dir + "/not.pem"
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := config.ICAPService{
		Name: "av", ConnectTimeout: config.Duration(100 * time.Millisecond),
		Timeout: config.Duration(200 * time.Millisecond), MaxConns: 2, MaxBody: 1 << 20,
		BodyLimitAction: "reject", Fail: "closed", Preview: "off",
	}
	with := func(f func(c *config.ICAPService)) config.ICAPService {
		c := base
		f(&c)
		return c
	}

	// A URL without a port takes the scheme's default, so a typo in the
	// port does not silently become "some other service on this host".
	plain, err := NewService(with(func(c *config.ICAPService) { c.URL = "icap://icap.invalid/scan" }))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if !strings.HasSuffix(plain.host, ":1344") {
		t.Fatalf("icap:// resolved to %q", plain.host)
	}
	if plain.Name() != "av" {
		t.Fatalf("name %q", plain.Name())
	}

	secure, err := NewService(with(func(c *config.ICAPService) { c.URL = "icaps://icap.invalid/scan" }))
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Close()
	if !strings.HasSuffix(secure.host, ":11344") {
		t.Fatalf("icaps:// resolved to %q", secure.host)
	}
	if secure.tlsCfg == nil || secure.tlsCfg.ServerName != "icap.invalid" {
		t.Fatalf("tls config %+v", secure.tlsCfg)
	}

	// An explicit server name overrides the host, which is how a
	// deployment reaches a scanner through an address.
	named, err := NewService(with(func(c *config.ICAPService) {
		c.URL = "icaps://10.0.0.7:11344/scan"
		c.TLS = &config.ICAPTLS{ServerName: "scanner.example.com"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer named.Close()
	if named.tlsCfg.ServerName != "scanner.example.com" {
		t.Fatalf("server name %q", named.tlsCfg.ServerName)
	}

	// A CA file that is not a CA file is refused at load, where an
	// operator sees it, rather than at the first scan.
	if _, err := NewService(with(func(c *config.ICAPService) {
		c.URL = "icaps://icap.invalid/scan"
		c.TLS = &config.ICAPTLS{CAFile: notPEM}
	})); err == nil {
		t.Fatal("a ca_file with no certificates was accepted")
	}
	if _, err := NewService(with(func(c *config.ICAPService) {
		c.URL = "icaps://icap.invalid/scan"
		c.TLS = &config.ICAPTLS{CAFile: dir + "/absent.pem"}
	})); err == nil {
		t.Fatal("a missing ca_file was accepted")
	}
	if _, err := NewService(with(func(c *config.ICAPService) { c.URL = "://not a url" })); err == nil {
		t.Fatal("a malformed URL was accepted")
	}
}
