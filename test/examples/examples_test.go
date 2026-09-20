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
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/waf"
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
			if strings.Contains(string(data), "\nversion: 1\n") || strings.HasPrefix(string(data), "version: 1\n") {
				if _, err := config.ParseWith(data, false); err != nil {
					t.Fatalf("complete document: %v", err)
				}
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
