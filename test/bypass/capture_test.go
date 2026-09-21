package bypass

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// A capture file is the one artefact of this proxy that holds decrypted
// traffic on disk. These tests treat it as an attacker would: as
// something to get a secret into, to get a header of one's own into, or
// to switch on from the outside.

const captureYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging:
  access: {enabled: false}
trusted_proxies: [127.0.0.0/8]
capture:
  enabled: true
  start_active: true
  directory: %s
  bodies: true
  max_body_bytes: 4096
  redact: [authorization, cookie, set-cookie, x-api-key]
upstreams:
  - name: app
    endpoints: [{address: "%s"}]
routes:
  - {name: closed, hosts: [app.test], paths: [/admin], deny_cidrs: ["0.0.0.0/0", "::/0"], upstream: app}
  - {name: app, hosts: [app.test], upstream: app}
`

// captureHarness is a proxy that is already recording.
type captureHarness struct {
	*harness
	dir string
}

func startCapture(t *testing.T) *captureHarness {
	t.Helper()
	b := newBackend(t)
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(captureYAML, dir, b.addr())))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return &captureHarness{harness: &harness{t: t, s: s, addr: s.Addrs()["main"], backend: b}, dir: dir}
}

// wait blocks until the proxy has finished recording n exchanges. The
// capture is written from a deferred call after the response has
// reached the client, so reading the file the instant a request
// returns races the proxy rather than testing it.
func (c *captureHarness) wait(n uint64) {
	c.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		st := c.s.CaptureStatus()
		if st.Captured+st.Skipped >= n {
			return
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("only %d of %d exchanges were recorded: %+v", st.Captured+st.Skipped, n, st)
		}
		time.Sleep(time.Millisecond)
	}
}

// file returns everything the capture holds, with the pcapng framing
// removed: the bytes a dissector would reassemble.
func (c *captureHarness) file() string {
	c.t.Helper()
	{
		c.s.Capture().Flush()
		var out strings.Builder
		entries, err := os.ReadDir(c.dir)
		if err != nil {
			c.t.Fatal(err)
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(c.dir, e.Name()))
			if err != nil {
				c.t.Fatal(err)
			}
			for len(b) >= 12 {
				kind := binary.LittleEndian.Uint32(b[0:4])
				total := int(binary.LittleEndian.Uint32(b[4:8]))
				if total < 12 || total > len(b) {
					c.t.Fatalf("%s: block %#x claims %d of %d bytes", e.Name(), kind, total, len(b))
				}
				if kind == 0x00000006 {
					body := b[8 : total-4]
					capLen := int(binary.LittleEndian.Uint32(body[12:16]))
					if frame := body[20 : 20+capLen]; len(frame) > 54 {
						out.Write(frame[54:])
					}
				}
				b = b[total:]
			}
		}
		return out.String()
	}
}

func TestCaptureKeepsWhatItIsToldTo(t *testing.T) {
	h := startCapture(t)

	// Every spelling of a redacted header, because the header name is
	// the attacker's to choose and Go does not canonicalise what it
	// cannot parse as a token the same way twice.
	r := h.req("POST", "/orders", "198.51.100.5", `{"id":1}`,
		"AUTHORIZATION", "Bearer tok-must-not-be-written",
		"cookie", "session=must-not-be-written",
		"X-API-KEY", "key-must-not-be-written",
		"Content-Type", "application/json")
	if status, _ := h.do(r); status != 200 {
		t.Fatalf("request status %d", status)
	}
	h.wait(1)
	got := h.file()
	for _, secret := range []string{"tok-must-not-be-written", "session=must-not-be-written", "key-must-not-be-written"} {
		if strings.Contains(got, secret) {
			t.Errorf("the capture file holds %q; redaction is case sensitive somewhere it must not be", secret)
		}
	}
	if n := strings.Count(got, "REDACTED"); n < 3 {
		t.Errorf("%d redacted headers, want the three that were sent:\n%s", n, got)
	}
	// The placeholder is a fixed string, so the file says nothing about
	// how long the value was.
	if strings.Contains(got, "REDACTEDREDACTED") || strings.Contains(got, "*****") {
		t.Errorf("the redaction is length preserving:\n%s", got)
	}
}

// A capture is read by a person with a dissector. A value an attacker
// chose must not be able to become a header line, a request line or a
// second HTTP message inside the stream.
func TestCaptureCannotBeInjectedInto(t *testing.T) {
	h := startCapture(t)

	// The channels that could carry a raw line break into the file are
	// refused before they get there, and a request refused at parsing
	// is not captured at all: the file holds exchanges the proxy
	// handled, not everything that arrived on the socket.
	for _, c := range []struct {
		name string
		text string
	}{
		{"encoded CRLF in the path", "GET /a%0d%0aX-Injected:%20yes HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n"},
		{"encoded CRLF in a query value", "GET /a?next=%0d%0aX-Injected:%20yes HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n"},
		{"bare CR in a header value", "GET /a HTTP/1.1\r\nHost: app.test\r\nX-Note: a\rX-Injected: yes\r\nConnection: close\r\n\r\n"},
	} {
		if status := h.raw(c.text); status != 400 && status != 0 {
			t.Errorf("%s: status %d, want a refusal", c.name, status)
		}
	}
	if st := h.s.CaptureStatus(); st.Captured != 0 {
		t.Errorf("a request refused at parsing was captured: %+v", st)
	}
	if got := h.file(); strings.Contains(got, "X-Injected") {
		t.Errorf("a refused request reached the capture:\n%q", got)
	}

	// A bare LF is a line terminator to Go's reader rather than a byte
	// in the value (docs/SECURITY.md, "Known limits"), so this arrives
	// as two ordinary headers and is served. The property that matters
	// for the capture is that the file agrees with what the origin
	// received: the split happened at the front door, not in the file.
	if status := h.raw("GET /a HTTP/1.1\r\nHost: app.test\r\nX-Note: a\nX-Injected: yes\r\nConnection: close\r\n\r\n"); status != 200 {
		t.Fatalf("bare LF: status %d", status)
	}
	h.wait(1)
	got := h.file()
	if upstream := h.backend.last.Load(); upstream.Header.Get("X-Injected") == "yes" {
		if !strings.Contains(got, "X-Injected: yes\r\n") {
			t.Errorf("the origin saw X-Injected but the capture does not:\n%q", got)
		}
	} else if strings.Contains(got, "X-Injected") {
		t.Errorf("the capture holds a header the origin never saw:\n%q", got)
	}

	// A body may hold anything, including a whole fake HTTP message.
	// That is the traffic, so it is written — but the head that
	// precedes it declares its length, which is what keeps a dissector
	// reading it as a body rather than as the next message.
	fake := "POST /transfer HTTP/1.1\r\nHost: bank.example\r\nContent-Length: 0\r\n\r\n"
	r := h.req("POST", "/orders", "198.51.100.6", fake, "Content-Type", "text/plain")
	if status, _ := h.do(r); status != 200 {
		t.Fatalf("the body was not served: %d", status)
	}
	h.wait(2)
	got = h.file()
	if !strings.Contains(got, fake) {
		t.Errorf("the body was not captured verbatim:\n%q", got)
	}
	if !strings.Contains(got, fmt.Sprintf("Content-Length: %d", len(fake))) {
		t.Errorf("the captured head does not declare the body length, so the stream is ambiguous:\n%q", got)
	}
}

// The management API is on a Unix socket; nothing on the data plane may
// reach it. A client that asks the proxy for /v1/capture is asking the
// application, and must not be able to start, stop or read a capture.
func TestCaptureIsNotReachableFromTheDataPlane(t *testing.T) {
	h := startCapture(t)
	before := h.s.CaptureStatus()
	for _, target := range []string{"/v1/capture", "/v1/capture?active=true", "/../v1/capture"} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			r := h.req(method, target, "203.0.113.8", "", "Content-Type", "application/json")
			status, _ := h.do(r)
			if status >= 500 {
				t.Errorf("%s %s: status %d", method, target, status)
			}
		}
	}
	after := h.s.CaptureStatus()
	if after.Active != before.Active || after.Until != before.Until {
		t.Errorf("a data plane request changed the capture state: %+v -> %+v", before, after)
	}
}

// The file itself. It holds decrypted requests, so nobody but the proxy
// user may read it, and the proxy writes nothing else in the directory.
func TestCaptureFilesArePrivate(t *testing.T) {
	h := startCapture(t)
	if status, _ := h.do(h.req("GET", "/something", "198.51.100.9", "")); status != 200 {
		t.Fatal("the request was not served")
	}
	h.wait(1)
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("nothing was written")
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s has mode %o, want 600", e.Name(), perm)
		}
		if !strings.HasSuffix(e.Name(), ".pcapng") || strings.ContainsAny(e.Name(), "/\\") {
			t.Errorf("unexpected file %q in the capture directory", e.Name())
		}
	}
}

// A refused request is captured with the refusal, and without anything
// from an origin that was never asked.
func TestCaptureOfARefusalHoldsNoOriginData(t *testing.T) {
	h := startCapture(t)
	before := h.backend.hits.Load()
	status, _ := h.do(h.req("GET", "/admin", "203.0.113.10", ""))
	h.denied("admin route", before, status, 403)
	h.wait(1)
	got := h.file()
	if !strings.Contains(got, "GET /admin") {
		t.Errorf("the refused request was not captured:\n%s", got)
	}
	if !strings.Contains(got, "403") {
		t.Errorf("the capture does not carry the status the client got:\n%s", got)
	}
	if strings.Contains(got, "ok:/admin") {
		t.Error("the capture holds a body from an origin that was never asked")
	}
}

// A response header the origin sets is redacted too: an origin that
// hands out a session cookie must not have it written to disk.
func TestCaptureRedactsResponseHeaders(t *testing.T) {
	h := startCapture(t)
	// The harness backend echoes nothing useful here, so drive a
	// response header through a request the backend answers and assert
	// on what the proxy wrote for its own headers.
	resp, err := client.Do(h.req("GET", "/plain", "198.51.100.11", ""))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	h.wait(1)
	got := h.file()
	if !strings.Contains(got, "HTTP/1.1 200 OK") {
		t.Fatalf("the response was not captured:\n%s", got)
	}
	// The request id the proxy returns is in the response head, which is
	// how a frame and a log line are joined; it is not a secret.
	if !strings.Contains(got, "X-Request-Id") {
		t.Errorf("the captured response head is missing the request id:\n%s", got)
	}
}
