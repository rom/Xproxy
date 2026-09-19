// Package bypass is the adversarial harness: every test in it tries to
// get past a security control of the proxy the way an attacker would
// (encoding tricks, header games, protocol ambiguities, rotation, replay,
// disguises) and asserts that the control still holds and the backend
// never sees the request. A case that starts passing is a regression in
// a control; a case that is documented as accepted is marked so.
package bypass

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/filters" // built-in kinds
	"github.com/rom/xproxy/internal/filters/apikey"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// backend records what reaches it.
type backend struct {
	srv  *http.Server
	ln   net.Listener
	hits atomic.Int64
	last atomic.Pointer[http.Request]
}

func newBackend(t *testing.T) *backend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &backend{ln: ln}
	b.srv = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		r2 := r.Clone(context.Background())
		r2.Header.Set("X-Test-Body", string(body))
		b.last.Store(r2)
		switch r.URL.Path {
		case "/api/login":
			w.WriteHeader(401)
		case "/api/export":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"card":"4111 1111 1111 1111"}`)
		default:
			_, _ = fmt.Fprintf(w, "ok:%s", r.URL.Path)
		}
	})}
	go func() { _ = b.srv.Serve(ln) }()
	t.Cleanup(func() { _ = b.srv.Close() })
	return b
}

func (b *backend) addr() string { return b.ln.Addr().String() }

// harness is one proxy in front of one backend.
type harness struct {
	t       *testing.T
	s       *proxy.Server
	addr    string
	backend *backend
	apiKey  string
}

const harnessYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  limits: {max_header_bytes: 4096, max_uri_length: 1024, max_body_bytes: 65536, max_concurrent_requests: 200}
  normalization: {reject_double_encoding: true, reject_encoded_slashes: true, reject_backslashes: true, unicode: nfkc}
trusted_proxies: [%s]
logging:
  access: {enabled: false}
challenge:
  difficulty: 8
rate_limits:
  - {name: tiny, rate: 1, burst: 3}
bans:
  action: reject
  triggers:
    - {name: waf-repeat, reasons: [waf], threshold: 4, window: 1m, duration: 1h}
    - {name: probes, reasons: [honeypot], threshold: 1, window: 1m, duration: 1h}
    - {name: net-sweep, reasons: [rate_limit], aggregate: net, threshold: 8, min_sources: 3, window: 1m, duration: 1h}
waf:
  default_mode: block
  request_body_limit: 65536
  inspect_responses: false
  profiles:
    - name: default
      crs: {paranoia_level: 1}
virtual_patches:
  - id: cve-test
    paths: [/plugins/legacy/]
    query: [{name: cmd}]
    status: 404
filters:
  - name: headers
    kind: header_guard
    options:
      deny:
        - {header: X-Debug, pattern: "."}
        - {header: X-Original-URL, pattern: "."}
  - name: keys
    kind: api_key
    options: {keys_file: %s}
  - name: accounts
    kind: account_guard
    options:
      endpoints:
        - name: login
          class: login
          paths: [/api/login]
          identity: {form: user, json: user}
          failure: {statuses: [401]}
          steps:
            - {action: block, duration: 15m, pair: 3, ip_accounts: 4}
  - name: uploads
    kind: upload_guard
    options: {allowed_extensions: [jpg, png, pdf], max_file_bytes: 20000}
  - name: dlp
    kind: sensitive_data
    options:
      detectors: [card]
      request: {action: block, max_bytes: 512}
      response: {action: block}
  - name: spec
    kind: openapi
    options: {spec_file: %s, strict_query: true}
upstreams:
  - name: app
    endpoints: [{address: "%s"}]
routes:
  - {name: admin, hosts: [app.test], paths: [/admin], deny_cidrs: [0.0.0.0/0, "::/0"], upstream: app}
  - {name: internal, hosts: [app.test], paths: [/internal], allow_cidrs: [10.0.0.0/8], upstream: app}
  - {name: limited, hosts: [app.test], paths: [/limited], rate_limits: [tiny], waf: {mode: off}, upstream: app}
  - {name: gated, hosts: [app.test], paths: [/members], challenge: {mode: always}, upstream: app}
  - {name: strict, hosts: [app.test], paths: [/api/items], upstream: app, waf: {mode: off},
     policy: {methods: [GET], deny_unknown_query: true, max_query_params: 3, query: [{name: id, type: int, max_repeat: 1}, {name: q, max_length: 20}]}}
  - {name: patched, hosts: [app.test], paths: [/plugins], upstream: app, waf: {mode: off}}
  - {name: guarded, hosts: [app.test], paths: [/guarded], upstream: app, filters: [headers], waf: {mode: off}}
  - {name: keyed, hosts: [app.test], paths: [/keyed], upstream: app, filters: [keys], waf: {mode: off}}
  - {name: login, hosts: [app.test], paths: [/api/login], methods: [POST], upstream: app, filters: [accounts], waf: {mode: off}}
  - {name: upload, hosts: [app.test], paths: [/upload], methods: [POST], upstream: app, filters: [uploads], waf: {mode: off}}
  - {name: dlp, hosts: [app.test], paths: [/api/orders, /api/export], upstream: app, filters: [dlp], waf: {mode: off}}
  - {name: spec, hosts: [app.test], paths: [/v1], upstream: app, filters: [spec], waf: {mode: off}}
  - {name: trap, hosts: [app.test], paths: [/wp-login.php], honeypot: {decoy: wp-login}}
  - {name: app, hosts: [app.test], upstream: app}
`

const specYAML = `
openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /v1/things:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, maximum: 100}}
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema: {type: object, required: [name], additionalProperties: false, properties: {name: {type: string, maxLength: 10}}}
`

// start builds a proxy; trusted is the trusted_proxies entry, so
// forwarded headers are honoured (per client tests) or ignored
// (spoofing tests).
func start(t *testing.T, trusted string) *harness {
	t.Helper()
	b := newBackend(t)
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(spec, []byte(specYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys")
	plain, err := apikey.Add(keys, "svc", []string{"read"}, time.Time{}, "test")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(harnessYAML, trusted, keys, spec, b.addr())))
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
	return &harness{t: t, s: s, addr: s.Addrs()["main"], backend: b, apiKey: plain}
}

// req builds a request against the proxy for app.test from the given
// client address (through X-Forwarded-For; honoured only when the peer
// is trusted).
func (h *harness) req(method, target, ip string, body string, hdr ...string) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequest(method, "http://"+h.addr+target, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	r.Host = "app.test"
	if ip != "" {
		r.Header.Set("X-Forwarded-For", ip)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	return r
}

var client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// do sends r and returns the status and body; before counts backend
// hits so callers can assert the backend was never reached.
func (h *harness) do(r *http.Request) (int, string) {
	h.t.Helper()
	resp, err := client.Do(r)
	if err != nil {
		h.t.Fatalf("%s %s: %v", r.Method, r.URL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body)
}

// raw writes bytes on a fresh connection and returns the status, or 0
// when the proxy closed the connection without a response.
func (h *harness) raw(text string) int {
	h.t.Helper()
	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		h.t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(text)); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// denied asserts a status among want and that the backend did not see
// the request.
func (h *harness) denied(name string, before int64, status int, want ...int) {
	h.t.Helper()
	ok := false
	for _, w := range want {
		if status == w {
			ok = true
		}
	}
	if !ok {
		h.t.Errorf("%s: status %d, want one of %v", name, status, want)
	}
	if h.backend.hits.Load() != before {
		h.t.Errorf("%s: the backend saw the request", name)
	}
}

// served asserts the backend answered.
func (h *harness) served(name string, before int64, status int) {
	h.t.Helper()
	if status != 200 || h.backend.hits.Load() != before+1 {
		h.t.Errorf("%s: status %d hits %d (before %d)", name, status, h.backend.hits.Load(), before)
	}
}

func multipart(field, filename, ctype string, data []byte) (string, string) {
	var buf bytes.Buffer
	boundary := "xproxyboundary"
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=%q; filename=%q\r\n", field, filename))
	buf.WriteString("Content-Type: " + ctype + "\r\n\r\n")
	buf.Write(data)
	buf.WriteString("\r\n--" + boundary + "--\r\n")
	return buf.String(), "multipart/form-data; boundary=" + boundary
}
