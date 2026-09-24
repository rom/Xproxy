package http

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// textprotoHeader is the type httptrace hands an informational response.
type textprotoHeader = textproto.MIMEHeader

// traced runs one request with a client trace and returns the response
// and its body.
func traced(t *testing.T, url, host string, trace *httptrace.ClientTrace) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Host = host
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	return resp, string(body)
}

// hintsBackend answers with informational responses before the real one,
// as a server sending 103 Early Hints does.
func hintsBackend(t *testing.T, hints int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < hints; i++ {
			w.Header().Set("Link", fmt.Sprintf("</style-%d.css>; rel=preload; as=style", i))
			w.WriteHeader(http.StatusEarlyHints)
		}
		w.Header().Del("Link")
		w.Header().Set("X-Real", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const hintsYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: pass, hosts: [pass.test], upstream: app}
  - {name: strip, hosts: [strip.test], upstream: app, early_hints: strip}
`

// An upstream that sends 103 Early Hints before its response must not
// lose the response: the informational status is not the final one, and a
// proxy that records it as such answers the client with a header and no
// status of its own.
func TestEarlyHintsReachTheClientAndTheRealStatusStillArrives(t *testing.T) {
	b := hintsBackend(t, 1)
	_, url := startServer(t, fmt.Sprintf(hintsYAML, strings.TrimPrefix(b.URL, "http://")))
	var hints []int
	var links []string
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textprotoHeader) error {
		hints = append(hints, code)
		links = append(links, h.Get("Link"))
		return nil
	}}
	resp, body := traced(t, url+"/page", "pass.test", trace)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 after an informational response", resp.StatusCode)
	}
	if body != "body" {
		t.Errorf("body %q", body)
	}
	if resp.Header.Get("X-Real") != "yes" {
		t.Errorf("the final headers did not arrive: %v", resp.Header)
	}
	if len(hints) != 1 || hints[0] != http.StatusEarlyHints {
		t.Fatalf("informational responses %v, want one 103", hints)
	}
	if !strings.Contains(links[0], "style-0.css") {
		t.Errorf("the hint carried no Link: %q", links[0])
	}
}

// And the status this exchange is recorded as is the real one. A proxy
// that treats the informational response as the status logs 103 for a
// page that returned 200, which is how the bug this branch fixes was
// invisible from the client's side: net/http sends an implicit 200 with
// the accumulated headers when the body is written, so the response looks
// right and every record of it is wrong.
func TestTheRecordedStatusIsTheFinalOne(t *testing.T) {
	b := hintsBackend(t, 1)
	dir := t.TempDir()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging:
  directory: %s
  access: {fields: [status, route]}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: pass, upstream: app}
`, dir, strings.TrimPrefix(b.URL, "http://"))
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := proxy.New(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	resp, body := traced(t, "http://"+srv.Addrs()["main"]+"/page", "any.test", &httptrace.ClientTrace{})
	if resp.StatusCode != 200 || body != "body" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	_ = srv.Shutdown(t.Context())
	logs.Close()
	data, err := os.ReadFile(filepath.Join(dir, "access.log"))
	if err != nil {
		t.Fatal(err)
	}
	line := string(data)
	if !strings.Contains(line, `"status":200`) {
		t.Errorf("the access log records the wrong status:\n%s", line)
	}
}

// strip is for the deployment that does not want them: the client sees
// the response and no hints, and the response is otherwise untouched.
func TestEarlyHintsCanBeStripped(t *testing.T) {
	b := hintsBackend(t, 2)
	_, url := startServer(t, fmt.Sprintf(hintsYAML, strings.TrimPrefix(b.URL, "http://")))
	var hints []int
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textprotoHeader) error {
		hints = append(hints, code)
		return nil
	}}
	resp, body := traced(t, url+"/page", "strip.test", trace)
	if resp.StatusCode != http.StatusOK || body != "body" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if len(hints) != 0 {
		t.Errorf("informational responses %v, want none", hints)
	}
}

// An upstream cannot make this proxy relay informational responses without
// end: each one is a header block written to the client, and a flood of
// them is a response that never finishes.
func TestInformationalResponsesAreBounded(t *testing.T) {
	b := hintsBackend(t, maxInformational+5)
	_, url := startServer(t, fmt.Sprintf(hintsYAML, strings.TrimPrefix(b.URL, "http://")))
	var hints []int
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textprotoHeader) error {
		hints = append(hints, code)
		return nil
	}}
	resp, body := traced(t, url+"/page", "pass.test", trace)
	if resp.StatusCode != http.StatusOK || body != "body" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if len(hints) > maxInformational {
		t.Errorf("%d informational responses relayed, over the bound of %d", len(hints), maxInformational)
	}
	if len(hints) == 0 {
		t.Error("the bound dropped every hint")
	}
}
