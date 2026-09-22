package http

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
)

// captureBytes returns everything the capture files in dir hold, with
// the pcapng framing stripped, so a test can assert on the exchange a
// dissector would reassemble rather than on the block structure (which
// internal/capture tests in its own right).
func captureBytes(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for len(b) >= 12 {
			kind := binary.LittleEndian.Uint32(b[0:4])
			total := int(binary.LittleEndian.Uint32(b[4:8]))
			if total < 12 || total > len(b) {
				t.Fatalf("%s: block %#x claims %d bytes of %d", e.Name(), kind, total, len(b))
			}
			if kind == 0x00000006 { // enhanced packet block
				body := b[8 : total-4]
				capLen := int(binary.LittleEndian.Uint32(body[12:16]))
				frame := body[20 : 20+capLen]
				// Ethernet + IPv4 + TCP, all minimum length here.
				if len(frame) > 14+20+20 {
					out.Write(frame[14+20+20:])
				}
			}
			b = b[total:]
		}
	}
	return out.String()
}

// waitCapture waits for the server to have finished recording n
// exchanges. The capture is written from a deferred call after the
// response has reached the client, so a test that reads the file the
// instant its request returns is racing the proxy, not testing it.
func waitCapture(t *testing.T, s *proxy.Server, n uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		st := s.CaptureStatus()
		if st.Captured+st.Skipped >= n {
			s.Capture().Flush()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d exchanges were recorded: %+v", st.Captured+st.Skipped, n, st)
		}
		time.Sleep(time.Millisecond)
	}
}

func captureYAML(t *testing.T, backendAddr, rules string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return dir, fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
capture:
  enabled: true
  directory: %s
  bodies: true
  max_body_bytes: 64
  redact: [authorization, cookie, x-api-key]
%s
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: api, paths: [/api], upstream: app}
  - {name: web, paths: [/], upstream: app}
`, dir, rules, backendAddr)
}

func TestCaptureWritesTheDecryptedExchange(t *testing.T) {
	a := newBackend(t, "a")
	dir, yaml := captureYAML(t, a.addr(), "")
	s, url := startServer(t, yaml)

	// Nothing is recorded until an operator throws the switch: the
	// section alone is a prepared capture, not a running one.
	if _, _ = get(t, url+"/api/things"); len(captureBytes(t, dir)) != 0 {
		t.Fatal("a capture section recorded before anyone turned it on")
	}
	if st := s.CaptureStatus(); !st.Enabled || st.Active {
		t.Fatalf("status %+v, want enabled and idle", st)
	}

	if _, err := s.SetCapture(true, time.Minute); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", url+"/api/things", strings.NewReader("name=widget"))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Cookie", "session=abcdef")
	req.Header.Set("X-Trace", "keep-me")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	waitCapture(t, s, 1)

	got := captureBytes(t, dir)
	for _, want := range []string{
		"POST /api/things HTTP/1.1",
		"X-Trace: keep-me",
		"name=widget",     // the request body the upstream got
		"HTTP/1.1 200 OK", // the response the client got
	} {
		if !strings.Contains(got, want) {
			t.Errorf("capture does not contain %q:\n%s", want, got)
		}
	}
	// A capture file is a secrets-bearing artefact, and the point of
	// redact is that these never reach it at all.
	for _, secret := range []string{"super-secret-token", "session=abcdef"} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted value %q reached the capture file", secret)
		}
	}
	if n := strings.Count(got, "REDACTED"); n != 2 {
		t.Errorf("%d redacted headers, want 2 (Authorization and Cookie)", n)
	}

	if _, err := s.SetCapture(false, 0); err != nil {
		t.Fatal(err)
	}
	before := len(captureBytes(t, dir))
	_, _ = get(t, url+"/api/more")
	if after := len(captureBytes(t, dir)); after != before {
		t.Errorf("recording continued after it was turned off (%d -> %d bytes)", before, after)
	}
}

func TestCaptureRuleSelectsOneFlow(t *testing.T) {
	a := newBackend(t, "a")
	dir, yaml := captureYAML(t, a.addr(), "  rules:\n    - {name: api-only, routes: [api], methods: [GET]}\n")
	s, url := startServer(t, yaml)
	if _, err := s.SetCapture(true, time.Minute); err != nil {
		t.Fatal(err)
	}
	_, _ = get(t, url+"/api/wanted")
	_, _ = get(t, url+"/other/unwanted")
	resp, err := http.Post(url+"/api/posted", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	waitCapture(t, s, 3)

	got := captureBytes(t, dir)
	if !strings.Contains(got, "/api/wanted") {
		t.Errorf("the selected flow is missing:\n%s", got)
	}
	if strings.Contains(got, "/other/unwanted") {
		t.Error("a flow on another route was captured; a rule must not widen on its own")
	}
	if strings.Contains(got, "/api/posted") {
		t.Error("a flow with another method was captured; every selector a rule names has to hold")
	}
	st := s.CaptureStatus()
	if st.Captured != 1 || st.Skipped != 2 {
		t.Errorf("captured %d and skipped %d, want 1 and 2", st.Captured, st.Skipped)
	}
	if len(st.Rules) != 1 || st.Rules[0].Name != "api-only" || st.Rules[0].Captured != 1 {
		t.Errorf("rule stats %+v, want one flow on api-only", st.Rules)
	}
}

// The selectors on the answer are the ones that make a capture useful
// during an incident: "show me what the proxy is refusing".
func TestCaptureRecordsRefusalsRetrospectively(t *testing.T) {
	a := newBackend(t, "a")
	dir, yaml := captureYAML(t, a.addr(), "  rules:\n    - {name: denials, denied: true}\n")
	yaml = strings.Replace(yaml, "  - {name: api, paths: [/api], upstream: app}",
		"  - {name: api, paths: [/api], upstream: app, deny_cidrs: [\"203.0.113.0/24\"]}", 1)
	s, url := startServer(t, yaml)
	if _, err := s.SetCapture(true, time.Minute); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get(t, url+"/api/blocked", "X-Forwarded-For", "203.0.113.5"); resp.StatusCode != 403 {
		t.Fatalf("the ACL did not refuse the request: %d", resp.StatusCode)
	}
	_, _ = get(t, url+"/api/allowed", "X-Forwarded-For", "192.0.2.5")
	waitCapture(t, s, 2)

	got := captureBytes(t, dir)
	if !strings.Contains(got, "/api/blocked") {
		t.Errorf("the refusal was not captured:\n%s", got)
	}
	if strings.Contains(got, "/api/allowed") {
		t.Error("an allowed request was captured by a denied: true rule")
	}
	if !strings.Contains(got, "403") {
		t.Error("the captured response does not carry the status the client got")
	}
}

func TestCaptureBoundsBodies(t *testing.T) {
	a := newBackend(t, "a")
	dir, yaml := captureYAML(t, a.addr(), "")
	s, url := startServer(t, yaml)
	if _, err := s.SetCapture(true, time.Minute); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("A", 4096)
	resp, err := http.Post(url+"/api/upload", "text/plain", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	waitCapture(t, s, 1)

	got := captureBytes(t, dir)
	if strings.Count(got, "A") > 200 {
		t.Errorf("the capture holds %d body bytes, over the configured 64", strings.Count(got, "A"))
	}
	if st := s.CaptureStatus(); st.Truncated != 1 {
		t.Errorf("truncated = %d, want 1: a reader has to be told the body was cut", st.Truncated)
	}
}

// A proxy with no capture section says so rather than accepting the
// call and recording nothing, which would leave an operator waiting
// for a file that is never written.
func TestCaptureWithoutASectionRefuses(t *testing.T) {
	a := newBackend(t, "a")
	s, _ := startServer(t, fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: app, paths: [/], upstream: app}
`, a.addr()))
	if _, err := s.SetCapture(true, time.Minute); !errors.Is(err, capture.ErrNotEnabled) {
		t.Fatalf("SetCapture without a section returned %v, want ErrNotEnabled", err)
	}
	if st := s.CaptureStatus(); st.Enabled || st.Active {
		t.Errorf("status %+v, want a section that does not exist", st)
	}
}

// The refusals that happen before routing — a ban, the maintenance
// gate, a malformed Host — are the ones an operator most wants in the
// file, and the only ones the capture hook cannot see, because it runs
// once the route is known. They are offered to the rules at the end of
// the exchange instead.
func TestCaptureRecordsRefusalsFromBeforeRouting(t *testing.T) {
	a := newBackend(t, "a")
	dir, yaml := captureYAML(t, a.addr(), "  rules:\n    - {name: denials, denied: true}\n")
	yaml = strings.Replace(yaml, "upstreams:\n",
		"maintenance: {enabled: true, status: 503, message: down}\nupstreams:\n", 1)
	s, url := startServer(t, yaml)
	if _, err := s.SetCapture(true, time.Minute); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get(t, url+"/api/held"); resp.StatusCode != 503 {
		t.Fatalf("the maintenance gate did not hold the request: %d", resp.StatusCode)
	}
	waitCapture(t, s, 1)
	got := captureBytes(t, dir)
	if !strings.Contains(got, "GET /api/held") {
		t.Errorf("a refusal from before routing was not captured:\n%s", got)
	}
	if !strings.Contains(got, "503") {
		t.Errorf("the captured response does not carry the status the client got:\n%s", got)
	}
	if st := s.CaptureStatus(); st.Captured != 1 {
		t.Errorf("captured %d, want the one refusal: %+v", st.Captured, st)
	}
}

// A reload during a reproduction must not stop the recording.
func TestCaptureSurvivesAReload(t *testing.T) {
	a := newBackend(t, "a")
	dir, yaml := captureYAML(t, a.addr(), "")
	s, url := startServer(t, yaml)
	if _, err := s.SetCapture(true, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	until := s.CaptureStatus().Until

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	st := s.CaptureStatus()
	if !st.Active {
		t.Fatal("the reload stopped a running capture")
	}
	if !st.Until.Equal(until) {
		t.Errorf("window now ends at %s, want the original %s", st.Until, until)
	}
	_, _ = get(t, url+"/api/after-reload")
	waitCapture(t, s, 1)
	if got := captureBytes(t, dir); !strings.Contains(got, "/api/after-reload") {
		t.Errorf("nothing was recorded after the reload:\n%s", got)
	}
}

func TestCaptureHeaderValueStaysOnOneLine(t *testing.T) {
	// A header value carrying CRLF would otherwise write a header of
	// the attacker's choosing into the file the next reader parses.
	got := headerValue("evil\r\nX-Injected: yes")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("headerValue kept the line break: %q", got)
	}
	if !strings.Contains(got, "X-Injected: yes") {
		t.Errorf("the value was dropped rather than folded: %q", got)
	}
}
