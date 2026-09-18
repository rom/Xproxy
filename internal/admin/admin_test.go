package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMgmt is a minimal management API on a Unix socket.
type fakeMgmt struct {
	srv       *http.Server
	path      string
	reloads   atomic.Int64
	bans      atomic.Int64
	wafResets atomic.Int64
	rollbacks atomic.Value
}

func startFakeMgmt(t *testing.T) *fakeMgmt {
	t.Helper()
	dir := t.TempDir()
	f := &fakeMgmt{path: filepath.Join(dir, "m.sock")}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"version":"test","pid":1,"generation":3,"listeners":{"a":"127.0.0.1:1"},"routes":2,"upstreams":1,"stats":{"requests":10}}`)
	})
	mux.HandleFunc("GET /v1/bans", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `[]`) })
	mux.HandleFunc("POST /v1/bans", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !strings.HasPrefix(req["reason"], "admin:op: ") {
			w.WriteHeader(400)
			return
		}
		f.bans.Add(1)
		_, _ = io.WriteString(w, `{"target":"`+req["target"]+`"}`)
	})
	mux.HandleFunc("DELETE /v1/bans", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"ok":true}`) })
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dry_run") == "1" {
			_, _ = io.WriteString(w, `{"from":"active","to":"file","same":false,"changes":[{"section":"routes","name":"r","kind":"changed"}],"summary":["route r changed"],"restart_needed":[],"text":"--- active\n+++ file\n"}`)
			return
		}
		f.reloads.Add(1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("GET /v1/series", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"interval_seconds":1,"names":["requests"],"points":[],"since":"`+r.URL.Query().Get("since")+`"}`)
	})
	mux.HandleFunc("GET /v1/acme", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":"acme not configured"}`)
	})
	// 1.3 views: fixed documents the GUI passes through.
	for path, doc := range map[string]string{
		"/v1/pools":     `{"u":{"name":"u","balancer":"round_robin","endpoints":1,"available":1,"active":0,"circuit":{"state":"closed","failures":0,"opens":0,"rejected":0}}}`,
		"/v1/quotas":    `{"generation":3,"tenants":[],"routes":[{"route":"r","requests":10}],"rate_limits":[],"upstreams":[]}`,
		"/v1/waf":       `{"enabled":true,"profiles":[{"name":"default","modes":["block"],"crs":"embedded","version":"4250"}],"routes":[],"requests":5,"blocked":1,"rules":[],"total_rules":0,"learning":{"enabled":false,"proposals":[]}}`,
		"/v1/tls":       `{"main":[{"names":["a.test"],"issuer":"CA","not_after":"2030-01-01T00:00:00Z","ocsp":{"status":"good"},"ct":{"ok":true,"verified":2,"required":2}}]}`,
		"/v1/telemetry": `{"metrics":null,"traces":null,"logs":null}`,
		"/v1/sandbox":   `{"platform":"linux","enabled":true,"mechanisms":[{"name":"landlock","state":"applied"}],"landlocked":true,"read_paths":["/etc/xproxy"]}`,
		"/v1/dns":       `[]`,
		"/v1/history":   `[{"id":"20260918T100000Z-gen3","generation":3,"applied":"2026-09-18T10:00:00Z","note":"start","source":"/etc/xproxy/xproxy.yaml","size":100}]`,
		"/v1/diff":      `{"from":"active","to":"file","same":true,"changes":[],"summary":[],"restart_needed":[]}`,
	} {
		d := doc
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, d) })
	}
	mux.HandleFunc("GET /v1/waf/exclusions", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "# xproxy WAF exclusion proposals\n# (no proposals)\n")
	})
	mux.HandleFunc("POST /v1/waf/reset", func(w http.ResponseWriter, _ *http.Request) {
		f.wafResets.Add(1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("POST /v1/rollback", func(w http.ResponseWriter, r *http.Request) {
		f.rollbacks.Store(r.URL.Query().Get("id"))
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	ln, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = f.srv.Serve(ln) }()
	t.Cleanup(func() { _ = f.srv.Close() })
	return f
}

func writeUsers(t *testing.T, dir string) string {
	t.Helper()
	op, err := hashPassword("operator-password-1", 1000)
	if err != nil {
		t.Fatal(err)
	}
	vw, err := hashPassword("viewer-password-01", 1000)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "users")
	if err := os.WriteFile(p, []byte("# users\nop:operator:"+op+"\nview:viewer:"+vw+"\ncert:operator:x509\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalConfig = `version: 1
server:
  listeners:
    - name: http
      address: "127.0.0.1:0"
upstreams:
  - name: app
    endpoints:
      - {address: 127.0.0.1:9}
routes:
  - name: all
    paths: ["/"]
    upstream: app
`

type client struct {
	t      *testing.T
	base   string
	cookie *http.Cookie
}

func (c *client) do(method, path string, body any, csrf bool) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		req.Header.Set("X-Xproxy-Admin", "1")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	for _, ck := range resp.Cookies() {
		if ck.Name == "xproxy_admin" {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = ck
			}
		}
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (c *client) login(user, pw string) int {
	st, _ := c.do("POST", "/api/login", map[string]string{"user": user, "password": pw}, true)
	return st
}

func newTestServer(t *testing.T, o Options) (*Server, *client) {
	t.Helper()
	o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, &client{t: t, base: ts.URL}
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Fatalf("unexpected hash format %q", h)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "correct horse batter") {
		t.Fatal("verify")
	}
	if VerifyPassword("garbage", "x") || VerifyPassword("pbkdf2-sha256$10$AA$AA", "x") {
		t.Fatal("malformed hashes must not verify")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestUsersFile(t *testing.T) {
	dir := t.TempDir()
	p := writeUsers(t, dir)
	u, err := LoadUsers(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(u.List()); got != 3 {
		t.Fatalf("users = %d", got)
	}
	if err := u.Set(User{Name: "new", Role: RoleViewer, Hash: "x509"}); err != nil {
		t.Fatal(err)
	}
	if err := u.Delete("view"); err != nil {
		t.Fatal(err)
	}
	if err := u.Delete("nobody"); err == nil {
		t.Fatal("deleting unknown user succeeded")
	}
	u2, err := LoadUsers(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u2.Lookup("view"); ok {
		t.Fatal("view still present after delete")
	}
	if x, ok := u2.Lookup("new"); !ok || !x.CertOnly() {
		t.Fatal("new user missing or not cert-only")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	if err := u.Set(User{Name: "bad name", Role: RoleViewer, Hash: "x"}); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := LoadUsers(filepath.Join(dir, "missing")); err != nil {
		t.Fatalf("missing file should be empty set: %v", err)
	}
	if err := os.WriteFile(p, []byte("a:root:x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUsers(p); err == nil || !strings.Contains(err.Error(), "unknown role") {
		t.Fatalf("bad role: %v", err)
	}
}

func TestOptionsPolicy(t *testing.T) {
	dir := t.TempDir()
	users := writeUsers(t, dir)
	base := Options{Socket: "/nonexistent", UsersFile: users}
	cases := []struct {
		name string
		o    Options
		ok   bool
	}{
		{"loopback plain", Options{Listen: "127.0.0.1:0"}, true},
		{"localhost plain", Options{Listen: "localhost:0"}, true},
		{"unix", Options{Listen: "unix:" + filepath.Join(dir, "a.sock")}, true},
		{"public plain", Options{Listen: "0.0.0.0:8443"}, false},
		{"public tls only", Options{Listen: "0.0.0.0:8443", TLS: TLSOptions{CertFile: "c", KeyFile: "k"}}, false},
		{"public mtls", Options{Listen: "0.0.0.0:8443", TLS: TLSOptions{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"}}, true},
		{"cert without key", Options{Listen: "127.0.0.1:0", TLS: TLSOptions{CertFile: "c"}}, false},
	}
	for _, c := range cases {
		o := c.o
		o.Socket, o.UsersFile = base.Socket, base.UsersFile
		_, err := New(o)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v ok=%v", c.name, err, c.ok)
		}
	}
}

func TestAuthAndRoles(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(minimalConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	s, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir), ConfigFile: cfgPath,
		RestartCommand: []string{"/bin/sh", "-c", "echo restarted"}})

	// Anonymous.
	if st, _ := c.do("GET", "/api/status", nil, false); st != 401 {
		t.Fatalf("anonymous status: %d", st)
	}
	st, body := c.do("GET", "/", nil, false)
	if st != 200 || !strings.Contains(string(body), "xproxy admin") {
		t.Fatalf("index: %d", st)
	}
	req, _ := http.NewRequestWithContext(context.Background(), "GET", c.base+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("csp %q", csp)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing X-Frame-Options")
	}

	// Login without the CSRF header is refused; wrong password 401.
	if st, _ := c.do("POST", "/api/login", map[string]string{"user": "op", "password": "operator-password-1"}, false); st != 403 {
		t.Fatalf("login without header: %d", st)
	}
	if st := c.login("op", "wrong-password-000"); st != 401 {
		t.Fatalf("wrong password: %d", st)
	}
	if st := c.login("nobody", "operator-password-1"); st != 401 {
		t.Fatalf("unknown user: %d", st)
	}
	if st := c.login("cert", "anything-at-all-00"); st != 401 {
		t.Fatalf("cert-only user with password: %d", st)
	}

	// Viewer: reads yes, writes no.
	if st := c.login("view", "viewer-password-01"); st != 200 || c.cookie == nil {
		t.Fatalf("viewer login: %d", st)
	}
	if !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie attributes: %+v", c.cookie)
	}
	st, body = c.do("GET", "/api/me", nil, false)
	if st != 200 || !strings.Contains(string(body), `"role":"viewer"`) || strings.Contains(string(body), `"can_edit_file":true`) {
		t.Fatalf("me: %d %s", st, body)
	}
	if st, body := c.do("GET", "/api/status", nil, false); st != 200 || !strings.Contains(string(body), `"generation":3`) {
		t.Fatalf("status: %d %s", st, body)
	}
	if st, _ := c.do("POST", "/api/reload", nil, true); st != 403 {
		t.Fatalf("viewer reload: %d", st)
	}
	if st, _ := c.do("PUT", "/api/config/file", map[string]string{"text": minimalConfig}, true); st != 403 {
		t.Fatalf("viewer config save: %d", st)
	}
	if st, _ := c.do("GET", "/api/config/file", nil, false); st != 200 {
		t.Fatalf("viewer may read the config file: %d", st)
	}
	if st, _ := c.do("GET", "/api/acme", nil, false); st != 502 {
		t.Fatalf("acme passthrough of a 404 should be 502: %d", st)
	}
	if st, _ := c.do("POST", "/api/logout", nil, true); st != 200 || c.cookie != nil {
		t.Fatalf("logout: %d cookie=%v", st, c.cookie)
	}
	if st, _ := c.do("GET", "/api/status", nil, false); st != 401 {
		t.Fatalf("after logout: %d", st)
	}

	// Operator.
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatalf("operator login: %d", st)
	}
	if st, _ := c.do("POST", "/api/reload", nil, false); st != 403 {
		t.Fatalf("reload without CSRF header: %d", st)
	}
	req, _ = http.NewRequestWithContext(context.Background(), "POST", c.base+"/api/reload", nil)
	req.Header.Set("X-Xproxy-Admin", "1")
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(c.cookie)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin reload: %d", resp.StatusCode)
	}
	req, _ = http.NewRequestWithContext(context.Background(), "POST", c.base+"/api/reload", nil)
	req.Header.Set("X-Xproxy-Admin", "1")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(c.cookie)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-site fetch metadata reload: %d", resp.StatusCode)
	}
	if st, _ := c.do("POST", "/api/reload", nil, true); st != 200 || fm.reloads.Load() != 1 {
		t.Fatalf("reload: %d reloads=%d", st, fm.reloads.Load())
	}
	if st, body := c.do("POST", "/api/bans", map[string]string{"target": "203.0.113.9", "duration": "1h", "reason": "test"}, true); st != 200 || fm.bans.Load() != 1 {
		t.Fatalf("ban: %d %s", st, body)
	}
	if st, _ := c.do("DELETE", "/api/bans?target=203.0.113.9", nil, true); st != 200 {
		t.Fatalf("unban: %d", st)
	}
	if st, body := c.do("POST", "/api/restart", nil, true); st != 200 || !strings.Contains(string(body), "restarted") {
		t.Fatalf("restart: %d %s", st, body)
	}
	if st, body := c.do("GET", "/api/series?since=5m", nil, false); st != 200 || !strings.Contains(string(body), `"since":"5m"`) {
		t.Fatalf("series: %d %s", st, body)
	}
	if st, _ := c.do("GET", "/api/series?since=nonsense", nil, false); st != 400 {
		t.Fatal("bad since accepted")
	}

	// Configuration editing with validation and etag.
	st, body = c.do("GET", "/api/config/file", nil, false)
	if st != 200 {
		t.Fatalf("get config: %d", st)
	}
	var cf configFileView
	_ = json.Unmarshal(body, &cf)
	if cf.Text != minimalConfig || cf.ETag == "" || cf.Mode != "0640" {
		t.Fatalf("config view: %+v", cf)
	}
	st, body = c.do("POST", "/api/config/validate", map[string]string{"text": "version: 1\nroutes: []\n"}, true)
	if st != 200 || !strings.Contains(string(body), `"ok":false`) || !strings.Contains(string(body), "problems") {
		t.Fatalf("validate bad: %d %s", st, body)
	}
	st, body = c.do("PUT", "/api/config/file", map[string]string{"text": "version: 1\n", "etag": cf.ETag}, true)
	if st != 422 || !strings.Contains(string(body), "problems") {
		t.Fatalf("save invalid: %d %s", st, body)
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != minimalConfig {
		t.Fatal("invalid save changed the file")
	}
	newText := strings.Replace(minimalConfig, "name: all", "name: everything", 1)
	st, body = c.do("PUT", "/api/config/file", map[string]string{"text": newText, "etag": "stale"}, true)
	if st != 409 {
		t.Fatalf("stale etag: %d %s", st, body)
	}
	st, body = c.do("PUT", "/api/config/file", map[string]string{"text": newText, "etag": cf.ETag}, true)
	if st != 200 {
		t.Fatalf("save: %d %s", st, body)
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != newText {
		t.Fatal("file not written")
	}
	if bak, _ := os.ReadFile(cfgPath + ".bak"); string(bak) != minimalConfig {
		t.Fatal("backup missing or wrong")
	}
	if fi, _ := os.Stat(cfgPath); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode after save: %o", fi.Mode().Perm())
	}

	// Session expiry.
	s.sessions.now = func() time.Time { return time.Now().Add(31 * time.Minute) }
	if st, _ := c.do("GET", "/api/status", nil, false); st != 401 {
		t.Fatalf("idle session still valid: %d", st)
	}
}

func TestLoginLockout(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir)})
	for i := 0; i < 5; i++ {
		if st := c.login("op", "wrong-password-000"); st != 401 {
			t.Fatalf("attempt %d: %d", i, st)
		}
	}
	if st := c.login("op", "operator-password-1"); st != 429 {
		t.Fatalf("locked out login: %d", st)
	}
}

// TestExtendedViews covers the 1.3 pass-throughs and actions: every
// status document reaches a viewer unchanged, the SecLang download is
// text, the WAF reset and the rollback need the operator role, the
// rollback carries its id, the dry run answers with the change set.
func TestExtendedViews(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir)})
	if st := c.login("view", "viewer-password-01"); st != 200 {
		t.Fatalf("viewer login: %d", st)
	}
	for path, want := range map[string]string{
		"/api/pools": `"circuit"`, "/api/quotas": `"generation":3`, "/api/waf": `"version":"4250"`, "/api/tls": `"a.test"`,
		"/api/telemetry": `"traces":null`, "/api/sandbox": `"landlocked":true`, "/api/dns": `[]`, "/api/history": `-gen3"`,
		"/api/diff": `"same":true`, "/api/waf/exclusions": "(no proposals)",
	} {
		st, body := c.do("GET", path, nil, false)
		if st != 200 || !strings.Contains(string(body), want) {
			t.Fatalf("%s: %d %s", path, st, body)
		}
	}
	if st, _ := c.do("POST", "/api/waf/reset", nil, true); st != 403 {
		t.Fatalf("viewer waf reset: %d", st)
	}
	if st, _ := c.do("POST", "/api/rollback", map[string]string{"id": "x"}, true); st != 403 {
		t.Fatalf("viewer rollback: %d", st)
	}
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatalf("operator login: %d", st)
	}
	if st, _ := c.do("POST", "/api/waf/reset", nil, true); st != 200 || fm.wafResets.Load() != 1 {
		t.Fatalf("waf reset: %d (%d resets)", st, fm.wafResets.Load())
	}
	if st, _ := c.do("POST", "/api/rollback", map[string]string{}, true); st != 400 {
		t.Fatalf("rollback without id: %d", st)
	}
	if st, _ := c.do("POST", "/api/rollback", map[string]string{"id": "20260918T100000Z-gen3"}, true); st != 200 || fm.rollbacks.Load() != "20260918T100000Z-gen3" {
		t.Fatalf("rollback: %d (%v)", st, fm.rollbacks.Load())
	}
	if st, body := c.do("POST", "/api/reload/dry-run", nil, true); st != 200 || !strings.Contains(string(body), `"changes"`) || fm.reloads.Load() != 0 {
		t.Fatalf("dry run: %d %s (reloads %d)", st, body, fm.reloads.Load())
	}
}

func TestLogs(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "xproxy.yaml")
	cfgText := minimalConfig + "logging:\n  directory: " + logDir + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o640); err != nil {
		t.Fatal(err)
	}
	secPath := filepath.Join(logDir, "security.log")
	if err := os.WriteFile(secPath, []byte("{\"msg\":\"one\"}\n{\"msg\":\"two\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir), ConfigFile: cfgPath})
	if st := c.login("view", "viewer-password-01"); st != 200 {
		t.Fatal("login")
	}
	st, body := c.do("GET", "/api/logs/security?lines=1", nil, false)
	if st != 200 || !strings.Contains(string(body), `"lines":["{\"msg\":\"two\"}"]`) {
		t.Fatalf("tail: %d %s", st, body)
	}
	if st, _ := c.do("GET", "/api/logs/nope", nil, false); st != 400 {
		t.Fatal("unknown stream accepted")
	}
	// Follow: append a line and expect it as an event.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/api/logs/security/follow", nil)
	req.AddCookie(c.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("follow: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	f, err := os.OpenFile(secPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(f, `{"msg":"three"}`)
	_ = f.Close()
	buf := make([]byte, 4096)
	var got string
	for !strings.Contains(got, `data: {"msg":"three"}`) {
		n, err := resp.Body.Read(buf)
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, got)
		}
		got += string(buf[:n])
	}
}

func TestSplitProblems(t *testing.T) {
	err := fmt.Errorf("config: 2 problems:\n  - a: bad\n  - b: worse")
	got := splitProblems(err)
	if len(got) != 2 || got[0] != "a: bad" || got[1] != "b: worse" {
		t.Fatalf("%q", got)
	}
}
