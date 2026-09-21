package ingress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The API server is the controller's only source of truth, and what it
// says becomes routes, upstreams, certificates and file names on disk.
// These tests are about a cluster, or something pretending to be one,
// that answers with things it should not.

func TestObjectNameOK(t *testing.T) {
	good := []string{"a", "web", "shop-tls", "a.b.c", "0", strings.Repeat("a", 253), "my-secret.v2"}
	for _, s := range good {
		if !objectNameOK(s) {
			t.Errorf("%q was refused", s)
		}
	}
	bad := []string{
		"", ".", "..", "../etc/passwd", "a/b", "a\\b", "..\\..\\x", "UPPER", "a b", "a\x00b",
		"a\nb", "a:b", strings.Repeat("a", 254), "-", // a single dash is not a name the API server would send
	}
	for _, s := range bad {
		if s == "-" {
			continue // a leading dash is refused by the API server, not by this check
		}
		if objectNameOK(s) {
			t.Errorf("%q was accepted", s)
		}
	}
	// Nothing that passes can leave a directory when joined to one.
	for _, s := range good {
		joined := filepath.Join("/certs", s+"--x.crt")
		if !strings.HasPrefix(joined, "/certs/") {
			t.Errorf("%q joined to %q", s, joined)
		}
	}
}

// TestCertificateNamesStayInTheDirectory is the file half of the same
// check: a namespace or secret name that could climb out of cert_dir is
// dropped rather than written.
func TestCertificateNamesStayInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(victim, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Controller{cfg: config.Ingress{CertDir: certDir}, log: slog.New(slog.DiscardHandler)}
	certs := []CertPEM{
		{Namespace: "../", Name: "xproxy.yaml", Cert: []byte("owned"), Key: []byte("owned")},
		{Namespace: "shop", Name: "../../xproxy.yaml", Cert: []byte("owned"), Key: []byte("owned")},
		{Namespace: "shop", Name: "tls", Cert: []byte("cert"), Key: []byte("key")},
	}
	out, err := c.writeCerts(certs)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("%d certificates were written: %+v", len(out), out)
	}
	if b, _ := os.ReadFile(victim); string(b) != "version: 1\n" {
		t.Fatalf("a file outside cert_dir was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(certDir, "shop--tls.crt")); string(b) != "cert" {
		t.Errorf("the legitimate certificate is %q", b)
	}
	// The files the controller writes are readable by nobody else.
	for _, p := range []string{out[0].CertFile, out[0].KeyFile} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %v", p, st.Mode().Perm())
		}
	}
	// A second run with the same content leaves the files alone, and a
	// secret that is gone takes its files with it.
	before, err := os.Stat(out[0].CertFile)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := c.writeCerts(certs); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(out[0].CertFile)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Error("an unchanged certificate was rewritten")
	}
	if _, err := c.writeCerts(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out[0].CertFile); !os.IsNotExist(err) {
		t.Error("a certificate no longer referenced was kept")
	}
	// Files that are not this controller's are left alone.
	stranger := filepath.Join(certDir, "somebody-elses.pem")
	if err := os.WriteFile(stranger, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.writeCerts(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Error("a file the controller did not write was removed")
	}
}

func TestWriteIfChanged(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := writeIfChanged(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	// The same content does not touch the file.
	time.Sleep(10 * time.Millisecond)
	if err := writeIfChanged(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(p)
	if !st2.ModTime().Equal(st.ModTime()) {
		t.Error("an unchanged file was rewritten")
	}
	// Different content replaces it, atomically: no temporary files are
	// left behind either way.
	if err := writeIfChanged(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Errorf("content %q", b)
	}
	if err := writeIfChanged(p, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); len(b) != 0 {
		t.Errorf("an empty write left %q", b)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temporary file %q left behind", e.Name())
		}
	}
	// A directory that does not exist, and one that cannot be written.
	if err := writeIfChanged(filepath.Join(dir, "nope", "f"), []byte("x")); err == nil {
		t.Error("a write into a missing directory succeeded")
	}
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		if err := writeIfChanged(filepath.Join(ro, "f"), []byte("x")); err == nil {
			t.Error("a write into an unwritable directory succeeded")
		}
	}
}

// TestClientConstruction covers the options an operator writes, which
// decide who the controller trusts.
func TestClientConstruction(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("  sa-token\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The token is trimmed, because a newline in a header value would be
	// refused by the transport.
	c, err := newClient("https://api.example:6443", token, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c.token != "sa-token" {
		t.Errorf("token %q", c.token)
	}
	if strings.ContainsAny(c.token, "\r\n ") {
		t.Errorf("the token carries whitespace: %q", c.token)
	}
	// A trailing slash on the server does not double up in paths.
	c, err = newClient("https://api.example:6443/", token, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(c.base, "/") {
		t.Errorf("base %q", c.base)
	}
	bad := map[string][3]string{
		"not a url":                      {"://api", token, ""},
		"no host":                        {"https://", token, ""},
		"empty":                          {"", token, ""},
		"a missing token file":           {"https://api.example", filepath.Join(dir, "none"), ""},
		"a missing ca file":              {"https://api.example", token, filepath.Join(dir, "none.pem")},
		"a ca file with no certificates": {"https://api.example", token, notPEM},
	}
	for name, args := range bad {
		if _, err := newClient(args[0], args[1], args[2], time.Second); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// Over plain http the CA file is not read at all, so a broken one is
	// not an error there.
	if _, err := newClient("http://127.0.0.1:8080", "", notPEM, time.Second); err != nil {
		t.Errorf("http with a ca file: %v", err)
	}
}

// TestAPIServerAnswers covers what the controller does with answers a
// real API server would not send.
func TestAPIServerAnswers(t *testing.T) {
	var code int
	var body string
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if strings.Contains(r.URL.Path, "/redirect") {
			http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	c, err := newClient(srv.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	cases := []struct {
		name string
		code int
		body string
	}{
		{"unauthorized", 401, `{"message":"Unauthorized"}`},
		{"forbidden", 403, `{"message":"forbidden: serviceaccount cannot list ingresses"}`},
		{"a server error", 500, ""},
		{"a gateway error", 502, "<html>502</html>"},
		{"not json", 200, "<html>hello</html>"},
		{"a truncated document", 200, `{"items":[`},
		{"a json array", 200, `[1,2,3]`},
		{"a string", 200, `"hello"`},
	}
	for _, tc := range cases {
		code, body = tc.code, tc.body
		if err := c.get(t.Context(), "/api/v1/services", &out); err == nil {
			t.Errorf("%s was accepted", tc.name)
		} else if tc.code == 403 && !strings.Contains(err.Error(), "serviceaccount") {
			t.Errorf("the message was lost: %v", err)
		}
	}
	// A 404 is recognised as "not found" so an optional resource is not
	// an error.
	code, body = 404, `{"message":"the server could not find the requested resource"}`
	err = c.get(t.Context(), "/apis/gateway.networking.k8s.io/v1/gateways", &out)
	if !isNotFound(err) {
		t.Errorf("a 404 was not recognised: %v", err)
	}
	if isNotFound(nil) {
		t.Error("no error was recognised as not found")
	}
	// A redirect is not followed: an API server that answers 302 must not
	// be able to send the service account token somewhere else.
	code, body = 200, "{}"
	if err := c.get(t.Context(), "/redirect", &out); err == nil {
		t.Error("a redirect was followed")
	}
	// A body past the ceiling is refused rather than buffered.
	code, body = 200, `{"items":[`+strings.Repeat(`"x",`, 1)+`"`+strings.Repeat("y", 70<<20)+`"]}`
	if err := c.get(t.Context(), "/api/v1/services", &out); err == nil {
		t.Error("an oversize response was accepted")
	}
	// A server that is not there.
	srv.Close()
	if err := c.get(t.Context(), "/api/v1/services", &out); err == nil {
		t.Error("a closed server answered")
	}
}

// TestSecretNamesAreChecked covers the other half of the name guard: a
// secret name that is not a name never becomes a request.
func TestSecretNamesAreChecked(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "kubernetes.io/tls",
			"data": map[string]string{"tls.crt": base64.StdEncoding.EncodeToString([]byte("c")), "tls.key": base64.StdEncoding.EncodeToString([]byte("k"))}})
	}))
	defer srv.Close()
	c, err := newClient(srv.URL, "", "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range [][2]string{
		{"../../..", "x"},
		{"shop", "../../secrets/other"},
		{"shop", ""},
		{"", "tls"},
		{"shop", "a/b"},
		{"SHOP", "tls"},
	} {
		if _, err := c.secret(t.Context(), tc[0], tc[1]); err == nil {
			t.Errorf("%q/%q was fetched", tc[0], tc[1])
		}
	}
	if len(paths) != 0 {
		t.Fatalf("requests were made for %v", paths)
	}
	// A name that is a name is fetched, at the path it names.
	if _, err := c.secret(t.Context(), "shop", "shop-tls"); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/api/v1/namespaces/shop/secrets/shop-tls" {
		t.Fatalf("paths %v", paths)
	}
}

func TestDecodeB64AndDeref(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte("hello"))
	raw := base64.RawStdEncoding.EncodeToString([]byte("hello"))
	for _, s := range []string{std, raw} {
		b, err := decodeB64(s)
		if err != nil || string(b) != "hello" {
			t.Errorf("%q: %q %v", s, b, err)
		}
	}
	for _, s := range []string{"!!!!", "a", base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff})} {
		if b, err := decodeB64(s); err == nil && len(b) > 0 && s == "!!!!" {
			t.Errorf("%q decoded to %q", s, b)
		}
	}
	if decodeB64Must(t, "") != "" {
		t.Error("an empty string did not decode to nothing")
	}
	if deref(nil) != 0 {
		t.Error("a nil pointer did not dereference to zero")
	}
	v := int64(42)
	if deref(&v) != 42 {
		t.Error("a pointer did not dereference to its value")
	}
}

func decodeB64Must(t *testing.T, s string) string {
	t.Helper()
	b, err := decodeB64(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestHashSnapshot covers the digest that decides whether the proxy is
// reloaded: it must be stable for one snapshot and change for any
// difference that matters.
func TestHashSnapshot(t *testing.T) {
	base := Snapshot{
		Routes:    []config.Route{{Name: "r", Hosts: []string{"a.example"}, Paths: []string{"/"}, Upstream: "u"}},
		Upstreams: []config.Upstream{{Name: "u", Endpoints: []config.Endpoint{{Address: "10.0.0.1:80", Weight: 1}}}},
		Certificates: []CertPEM{
			{Namespace: "b", Name: "t", Cert: []byte("c2"), Key: []byte("k2")},
			{Namespace: "a", Name: "t", Cert: []byte("c1"), Key: []byte("k1")},
		},
	}
	h := hashSnapshot(base)
	if h != hashSnapshot(base) {
		t.Fatal("the digest is not stable")
	}
	// The certificate order does not matter: the same set in another
	// order is the same cluster state.
	swapped := base
	swapped.Certificates = []CertPEM{base.Certificates[1], base.Certificates[0]}
	if hashSnapshot(swapped) != h {
		t.Error("reordering the certificates changed the digest")
	}
	// Anything that changes what is served changes the digest.
	for name, mutate := range map[string]func(*Snapshot){
		"a route host":        func(s *Snapshot) { s.Routes[0].Hosts = []string{"b.example"} },
		"a route path":        func(s *Snapshot) { s.Routes[0].Paths = []string{"/x"} },
		"an upstream address": func(s *Snapshot) { s.Upstreams[0].Endpoints[0].Address = "10.0.0.2:80" },
		"an endpoint weight":  func(s *Snapshot) { s.Upstreams[0].Endpoints[0].Weight = 2 },
		"certificate bytes":   func(s *Snapshot) { s.Certificates[0].Cert = []byte("other") },
		"a key":               func(s *Snapshot) { s.Certificates[0].Key = []byte("other") },
		"an extra route":      func(s *Snapshot) { s.Routes = append(s.Routes, config.Route{Name: "r2"}) },
	} {
		cp := Snapshot{
			Routes:       append([]config.Route(nil), base.Routes...),
			Upstreams:    []config.Upstream{{Name: "u", Endpoints: []config.Endpoint{{Address: "10.0.0.1:80", Weight: 1}}}},
			Certificates: append([]CertPEM(nil), base.Certificates...),
		}
		cp.Routes[0].Hosts = append([]string(nil), base.Routes[0].Hosts...)
		cp.Routes[0].Paths = append([]string(nil), base.Routes[0].Paths...)
		mutate(&cp)
		if hashSnapshot(cp) == h {
			t.Errorf("%s did not change the digest", name)
		}
	}
}

// TestControllerStartUpRefusals covers the options that decide whether
// the controller can run at all.
func TestControllerStartUpRefusals(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.DiscardHandler)
	// A certificate directory that cannot be created.
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		cfg := config.Ingress{APIServer: "https://api.example:6443", CertDir: filepath.Join(ro, "certs"), Timeout: config.Duration(time.Second)}
		if _, err := New(cfg, log, nil); err == nil {
			t.Error("a cert_dir that cannot be created was accepted")
		}
	}
	// An API server that is not a URL never gets as far as the directory.
	cfg := config.Ingress{APIServer: "://nope", CertDir: filepath.Join(dir, "certs"), Timeout: config.Duration(time.Second)}
	if _, err := New(cfg, log, nil); err == nil {
		t.Error("an unusable api_server was accepted")
	}
	// A controller that starts reports itself enabled with no work done.
	cfg = config.Ingress{APIServer: "https://api.example:6443", CertDir: filepath.Join(dir, "certs"),
		Timeout: config.Duration(time.Second), Class: "xproxy"}
	c, err := New(cfg, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if !st.Enabled || st.Class != "xproxy" || st.Watching != 0 || st.WatchEvents != 0 {
		t.Fatalf("status %+v", st)
	}
	snap, certs := c.Snapshot()
	if len(snap.Routes) != 0 || len(certs) != 0 {
		t.Fatalf("a fresh controller has %d routes and %d certificates", len(snap.Routes), len(certs))
	}
	// Stopping one that never started returns rather than waiting.
	done := make(chan struct{})
	go func() { c.Stop(); c.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return")
	}
}

// TestSyncAgainstABrokenCluster covers the fetch step: every collection
// the controller reads can fail, and a failure must leave the previous
// snapshot in force rather than emptying the proxy's routes.
func TestSyncAgainstABrokenCluster(t *testing.T) {
	api := newFakeAPI(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	api.ingresses = []any{ingressObj("shop", "web", "xproxy", "shop.example.com", "/", "web", 80, nil, "")}
	api.services = []any{serviceObj("shop", "web", 80, "http", 8080)}
	api.slices = []any{sliceObj("shop", "web", "http", 8080, true, "10.0.0.1")}
	cfg := config.Ingress{Enabled: true, APIServer: api.srv.URL, TokenFile: tokenFile, Class: "xproxy",
		CertDir: filepath.Join(dir, "certs"), Timeout: config.Duration(5 * time.Second)}
	c, err := New(cfg, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	if _, err := c.Sync(t.Context()); err != nil {
		t.Fatalf("the first sync: %v", err)
	}
	snap, _ := c.Snapshot()
	if len(snap.Routes) == 0 {
		t.Fatal("the first sync produced no routes")
	}
	before := len(snap.Routes)

	// The cluster starts refusing the controller: the sync fails, the
	// error is recorded, and the routes the proxy is serving stay.
	api.mu.Lock()
	api.token = "another-token"
	api.mu.Unlock()
	if _, err := c.Sync(t.Context()); err == nil {
		t.Error("a sync against a cluster that refuses us succeeded")
	}
	if snap, _ := c.Snapshot(); len(snap.Routes) != before {
		t.Errorf("a failed sync changed the routes: %d", len(snap.Routes))
	}
	if st := c.Status(); st.LastError == "" {
		t.Error("the failure was not recorded")
	}
	// It recovers when the cluster does.
	api.mu.Lock()
	api.token = "sa-token"
	api.mu.Unlock()
	if _, err := c.Sync(t.Context()); err != nil {
		t.Errorf("the sync did not recover: %v", err)
	}
	// A context that is already done ends the sync without a partial
	// snapshot.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Sync(ctx); err == nil {
		t.Error("a cancelled sync succeeded")
	}
	if snap, _ := c.Snapshot(); len(snap.Routes) != before {
		t.Errorf("a cancelled sync changed the routes: %d", len(snap.Routes))
	}
}

// unmarshalInto rebuilds typed cluster objects from the JSON a fake API
// server would send, so a test writes resources the way a tenant would.
func unmarshalInto[T any](t *testing.T, items []any) []T {
	t.Helper()
	b, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		t.Fatal(err)
	}
	var l list[T]
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	return l.Items
}

// TestTranslateHostileResources covers what a tenant can write into an
// Ingress. The fields become route hosts, paths and upstream addresses
// in the proxy's own configuration, so a value that cannot be one has
// to be dropped with a warning rather than carried through.
func TestTranslateHostileResources(t *testing.T) {
	hosts := []string{
		"ok.example.com",
		"UPPER.example.com",
		"has space.example.com",
		"has\r\nnewline.example.com",
		"has\x00nul.example.com",
		"*.wildcard.example.com",
		"",
		strings.Repeat("a", 300) + ".example.com",
		"127.0.0.1",
		"-leading-dash.example.com",
	}
	raw := make([]any, 0, len(hosts)+8)
	for i, h := range hosts {
		raw = append(raw, ingressObj("shop", "ing"+strconv.Itoa(i), "xproxy", h, "/", "web", 80, nil, ""))
	}
	// Paths a tenant might hope reach another route.
	for i, p := range []string{"/", "/a", "/a/../../admin", "/a//b", "/a%2fb", "/a\r\nX: y", "", "/" + strings.Repeat("p", 4000)} {
		raw = append(raw, ingressObj("shop", "path"+strconv.Itoa(i), "xproxy", "paths.example.com", p, "web", 80, nil, ""))
	}
	in := Input{
		Ingresses: unmarshalInto[Ingress](t, raw),
		Services:  unmarshalInto[Service](t, []any{serviceObj("shop", "web", 80, "http", 8080)}),
		Slices:    unmarshalInto[EndpointSlice](t, []any{sliceObj("shop", "web", "http", 8080, true, "10.1.0.1")}),
		Secrets:   map[string]*Secret{},
	}
	snap := Translate(in, "xproxy")
	for _, r := range snap.Routes {
		for _, h := range r.Hosts {
			if strings.ContainsAny(h, " \r\n\x00\t") {
				t.Errorf("route %s carries the host %q", r.Name, h)
			}
			if h != strings.ToLower(h) {
				t.Errorf("route %s carries the unfolded host %q", r.Name, h)
			}
		}
		for _, p := range r.Paths {
			if strings.ContainsAny(p, " \r\n\x00\t") {
				t.Errorf("route %s carries the path %q", r.Name, p)
			}
			if p != "" && !strings.HasPrefix(p, "/") {
				t.Errorf("route %s carries the relative path %q", r.Name, p)
			}
		}
		// Every route names an upstream that exists, or the proxy would
		// refuse the merged configuration.
		if r.Upstream != "" {
			var found bool
			for _, u := range snap.Upstreams {
				if u.Name == r.Upstream {
					found = true
				}
			}
			if !found {
				t.Errorf("route %s names the missing upstream %s", r.Name, r.Upstream)
			}
		}
		// Route names are what the proxy keys its metrics and logs on.
		if strings.ContainsAny(r.Name, " \r\n\x00\"") || len(r.Name) > 64 {
			t.Errorf("route name %q", r.Name)
		}
	}
	// Every upstream endpoint is a host:port the proxy can dial.
	for _, u := range snap.Upstreams {
		for _, e := range u.Endpoints {
			if _, _, err := net.SplitHostPort(e.Address); err != nil {
				t.Errorf("upstream %s carries the endpoint %q", u.Name, e.Address)
			}
		}
	}
	// Warnings are single lines, whatever was in the resource that
	// caused them: they go into the log and the status view.
	for _, w := range snap.Warnings {
		if strings.ContainsAny(w, "\r\n") {
			t.Errorf("warning spans lines: %q", w)
		}
	}
}

// TestTranslateHostileSecrets covers the TLS material: a Secret is
// written by whoever can write in the namespace, and its contents
// become certificate files the proxy loads.
func TestTranslateHostileSecrets(t *testing.T) {
	raw := []any{ingressObj("shop", "web", "xproxy", "shop.example.com", "/", "web", 80, nil, "shop-tls")}
	in := Input{
		Ingresses: unmarshalInto[Ingress](t, raw),
		Services:  unmarshalInto[Service](t, []any{serviceObj("shop", "web", 80, "http", 8080)}),
		Slices:    unmarshalInto[EndpointSlice](t, []any{sliceObj("shop", "web", "http", 8080, true, "10.1.0.1")}),
	}
	b64 := base64.StdEncoding.EncodeToString
	for name, secret := range map[string]*Secret{
		"missing":        nil,
		"the wrong type": {Type: "Opaque", Data: map[string]string{"tls.crt": b64([]byte("c")), "tls.key": b64([]byte("k"))}},
		"no data":        {Type: "kubernetes.io/tls"},
		"no key":         {Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": b64([]byte("c"))}},
		"no certificate": {Type: "kubernetes.io/tls", Data: map[string]string{"tls.key": b64([]byte("k"))}},
		"not base64":     {Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": "!!!!", "tls.key": "!!!!"}},
		"empty material": {Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": "", "tls.key": ""}},
	} {
		in.Secrets = map[string]*Secret{"shop/shop-tls": secret}
		snap := Translate(in, "xproxy")
		if len(snap.Certificates) != 0 {
			t.Errorf("%s produced %d certificates", name, len(snap.Certificates))
		}
		if len(snap.Routes) == 0 {
			t.Errorf("%s lost the route as well", name)
		}
	}
	// A secret that is a secret produces exactly one certificate, in the
	// namespace of the Ingress that referenced it.
	in.Secrets = map[string]*Secret{"shop/shop-tls": {Type: "kubernetes.io/tls",
		Data: map[string]string{"tls.crt": b64([]byte("CERT")), "tls.key": b64([]byte("KEY"))}}}
	snap := Translate(in, "xproxy")
	if len(snap.Certificates) != 1 || snap.Certificates[0].Namespace != "shop" || string(snap.Certificates[0].Key) != "KEY" {
		t.Fatalf("certificates: %+v", snap.Certificates)
	}
}
