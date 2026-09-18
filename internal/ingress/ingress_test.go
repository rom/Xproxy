package ingress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/testutil"
)

// fakeAPI serves list endpoints from in-memory JSON.
type fakeAPI struct {
	srv       *httptest.Server
	mu        sync.Mutex
	ingresses []any
	services  []any
	slices    []any
	secrets   map[string]any
	token     string
	requests  int
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{secrets: map[string]any{}, token: "sa-token"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests++
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var items []any
		switch {
		case r.URL.Path == "/apis/networking.k8s.io/v1/ingresses":
			items = f.ingresses
		case r.URL.Path == "/api/v1/services":
			items = f.services
		case r.URL.Path == "/apis/discovery.k8s.io/v1/endpointslices":
			items = f.slices
		case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/") && strings.Contains(r.URL.Path, "/secrets/"):
			parts := strings.Split(r.URL.Path, "/")
			s, ok := f.secrets[parts[4]+"/"+parts[6]]
			if !ok {
				http.Error(w, `{"message":"secrets \"x\" not found"}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(s)
			return
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func ingressObj(ns, name, class, host, path, svc string, port int, ann map[string]any, tlsSecret string) map[string]any {
	spec := map[string]any{"ingressClassName": class}
	if host != "" || path != "" {
		spec["rules"] = []any{map[string]any{"host": host, "http": map[string]any{"paths": []any{
			map[string]any{"path": path, "pathType": "Prefix", "backend": map[string]any{"service": map[string]any{"name": svc, "port": map[string]any{"number": port}}}},
		}}}}
	}
	if tlsSecret != "" {
		spec["tls"] = []any{map[string]any{"hosts": []any{host}, "secretName": tlsSecret}}
	}
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": ns, "annotations": ann}, "spec": spec}
}

func serviceObj(ns, name string, port int, portName string, target int) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"ports": []any{map[string]any{"name": portName, "port": port, "targetPort": target}}}}
}

func sliceObj(ns, svc, portName string, port int, ready bool, addrs ...string) map[string]any {
	eps := make([]any, 0, len(addrs))
	for _, a := range addrs {
		eps = append(eps, map[string]any{"addresses": []any{a}, "conditions": map[string]any{"ready": ready}})
	}
	return map[string]any{"metadata": map[string]any{"name": svc + "-abc", "namespace": ns, "labels": map[string]any{"kubernetes.io/service-name": svc}},
		"addressType": "IPv4", "endpoints": eps, "ports": []any{map[string]any{"name": portName, "port": port, "protocol": "TCP"}}}
}

func TestTranslate(t *testing.T) {
	ready := true
	notReady := false
	in := Input{
		Ingresses: []Ingress{},
		Secrets:   map[string]*Secret{},
	}
	raw := []any{
		ingressObj("shop", "web", "xproxy", "shop.example.com", "/", "web", 80, map[string]any{
			AnnotationPrefix + "websocket": "true", AnnotationPrefix + "priority-class": "high", AnnotationPrefix + "rate-limits": "api, login",
			AnnotationPrefix + "timeout": "30s", AnnotationPrefix + "max-body-bytes": "1024", AnnotationPrefix + "host-header": "web.internal"}, "shop-tls"),
		ingressObj("shop", "api", "xproxy", "shop.example.com", "/api", "api", 8080, map[string]any{AnnotationPrefix + "strip-prefix": "true", AnnotationPrefix + "max-body-bytes": "x"}, ""),
		ingressObj("other", "ignored", "nginx", "x.test", "/", "web", 80, nil, ""),
		ingressObj("shop", "nosvc", "xproxy", "y.test", "/", "missing", 80, nil, ""),
		ingressObj("shop", "badport", "xproxy", "z.test", "/", "web", 9999, nil, ""),
		ingressObj("shop", "regex", "xproxy", "r.test", "/a/*", "web", 80, nil, ""),
	}
	// One Ingress with only a default backend and an annotation class.
	raw = append(raw, map[string]any{"metadata": map[string]any{"name": "fallback", "namespace": "shop", "annotations": map[string]any{"kubernetes.io/ingress.class": "xproxy"}},
		"spec": map[string]any{"defaultBackend": map[string]any{"service": map[string]any{"name": "web", "port": map[string]any{"number": 80}}}}})
	b, _ := json.Marshal(map[string]any{"items": raw})
	var l list[Ingress]
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	in.Ingresses = l.Items
	sb, _ := json.Marshal(map[string]any{"items": []any{serviceObj("shop", "web", 80, "http", 8080), serviceObj("shop", "api", 8080, "", 8080)}})
	var sl list[Service]
	_ = json.Unmarshal(sb, &sl)
	in.Services = sl.Items
	eb, _ := json.Marshal(map[string]any{"items": []any{sliceObj("shop", "web", "http", 8080, ready, "10.1.0.2", "10.1.0.1"), sliceObj("shop", "api", "", 8080, notReady, "10.1.0.9")}})
	var el list[EndpointSlice]
	_ = json.Unmarshal(eb, &el)
	in.Slices = el.Items
	in.Secrets["shop/shop-tls"] = &Secret{Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": base64.StdEncoding.EncodeToString([]byte("CERT")), "tls.key": base64.StdEncoding.EncodeToString([]byte("KEY"))}}

	snap := Translate(in, "xproxy")
	if snap.Ingresses != 6 {
		t.Fatalf("ingresses: %d", snap.Ingresses)
	}
	byName := map[string]config.Route{}
	for _, r := range snap.Routes {
		byName[r.Name] = r
	}
	web := byName["k8s-shop-web-0"]
	if web.Hosts[0] != "shop.example.com" || web.Paths[0] != "/" || web.Upstream != "k8s-shop-web-80" || !web.WebSocket || web.PriorityClass != "high" ||
		len(web.RateLimits) != 2 || web.RateLimits[1] != "login" || web.Timeout.D() != 30*time.Second || web.MaxBodyBytes == nil || *web.MaxBodyBytes != 1024 || web.HostHeader != "web.internal" {
		t.Fatalf("web route: %+v", web)
	}
	api := byName["k8s-shop-api-0"]
	if api.Paths[0] != "/api" || api.StripPrefix != "/api" || api.Upstream != "k8s-shop-api-8080" || api.MaxBodyBytes != nil {
		t.Fatalf("api route: %+v", api)
	}
	def := byName["k8s-shop-fallback-default"]
	if len(def.Hosts) != 0 || def.Priority != -100 || def.Upstream != "k8s-shop-web-80" {
		t.Fatalf("default route: %+v", def)
	}
	if len(snap.Routes) != 3 {
		t.Fatalf("routes: %d %+v", len(snap.Routes), snap.Routes)
	}
	ups := map[string]config.Upstream{}
	for _, u := range snap.Upstreams {
		ups[u.Name] = u
	}
	if w := ups["k8s-shop-web-80"]; len(w.Endpoints) != 2 || w.Endpoints[0].Address != "10.1.0.1:8080" || w.Endpoints[1].Address != "10.1.0.2:8080" {
		t.Fatalf("web upstream: %+v", w)
	}
	if a := ups["k8s-shop-api-8080"]; len(a.Endpoints) != 1 || a.Endpoints[0].Address != "127.0.0.1:1" {
		t.Fatalf("api upstream with no ready endpoints: %+v", a)
	}
	if len(snap.Certificates) != 1 || string(snap.Certificates[0].Cert) != "CERT" || snap.Certificates[0].Name != "shop-tls" {
		t.Fatalf("certs: %+v", snap.Certificates)
	}
	joined := strings.Join(snap.Warnings, "\n")
	for _, want := range []string{"service missing not found", "has no port 9999", "not a plain prefix", "max-body-bytes annotation", "no ready endpoints"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warning %q missing in:\n%s", want, joined)
		}
	}
	long := objName(strings.Repeat("a", 70), "b")
	if len(long) > 64 || !strings.HasPrefix(long, "k8s-aaaa") {
		t.Fatalf("long name: %q", long)
	}
}

// TestControllerAndProxy runs the controller against a fake API server,
// merges the snapshot into a base configuration, serves it with the
// proxy, then changes the cluster and checks the reload path.
func TestControllerAndProxy(t *testing.T) {
	api := newFakeAPI(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "backend:%s:%s", r.Host, r.URL.Path)
	}))
	t.Cleanup(backend.Close)
	host, port, _ := strings.Cut(strings.TrimPrefix(backend.URL, "http://"), ":")
	var portN int
	_, _ = fmt.Sscan(port, &portN)
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	crt, key := ca.Issue(t, dir, "shop.example.com")
	crtB, _ := os.ReadFile(crt)
	keyB, _ := os.ReadFile(key)
	tokenFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenFile, []byte("sa-token\n"), 0o600)
	api.ingresses = []any{ingressObj("shop", "web", "xproxy", "shop.example.com", "/", "web", 80, nil, "shop-tls")}
	api.services = []any{serviceObj("shop", "web", 80, "http", portN)}
	api.slices = []any{sliceObj("shop", "web", "http", portN, true, host)}
	api.secrets["shop/shop-tls"] = map[string]any{"type": "kubernetes.io/tls", "data": map[string]any{
		"tls.crt": base64.StdEncoding.EncodeToString(crtB), "tls.key": base64.StdEncoding.EncodeToString(keyB)}}

	certDir := filepath.Join(dir, "certs")
	baseYAML := fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
    - name: https
      address: "127.0.0.1:0"
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
logging:
  access: {enabled: false}
ingress:
  enabled: true
  api_server: %s
  allow_http: true
  token_file: %s
  listener: https
  cert_dir: %s
  resync: 1s
upstreams:
  - name: static
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - name: static
    hosts: [static.test]
    upstream: static
`, crt, key, api.srv.URL, tokenFile, certDir)
	base, err := config.Parse([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	var reloads int
	var mu sync.Mutex
	ctrl, err := New(*base.Ingress, slog.New(slog.DiscardHandler), func() { mu.Lock(); reloads++; mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ctrl.Sync(context.Background())
	if err != nil || !changed {
		t.Fatalf("first sync: changed=%v err=%v", changed, err)
	}
	if changed, err := ctrl.Sync(context.Background()); err != nil || changed {
		t.Fatalf("second sync should be unchanged: %v %v", changed, err)
	}
	snap, certs := ctrl.Snapshot()
	if len(certs) != 1 || !strings.HasSuffix(certs[0].CertFile, "shop--shop-tls.crt") {
		t.Fatalf("certs: %+v", certs)
	}
	if st, err := os.Stat(certs[0].KeyFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", st, err)
	}
	merged, err := Merge(base, snap, certs)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Routes) != 2 || len(merged.Upstreams) != 2 || len(merged.Server.Listeners[1].TLS.Certificates) != 2 {
		t.Fatalf("merged: routes %d upstreams %d certs %d", len(merged.Routes), len(merged.Upstreams), len(merged.Server.Listeners[1].TLS.Certificates))
	}
	if merged.Routes[0].Name != "static" || merged.Routes[1].Name != "k8s-shop-web-0" {
		t.Fatalf("route order: %v", merged.Routes)
	}
	s, err := proxy.New(merged, logging.Discard())
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
	req, _ := http.NewRequest(http.MethodGet, "http://"+s.Addrs()["main"]+"/hello", nil)
	req.Host = "shop.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "backend:shop.example.com:/hello" {
		t.Fatalf("through ingress route: %d %q", resp.StatusCode, body)
	}
	// The cluster changes: a new path appears; the controller notices on
	// its next poll and asks for a reload.
	api.mu.Lock()
	api.ingresses = append(api.ingresses, ingressObj("shop", "admin", "xproxy", "shop.example.com", "/admin", "web", 80, nil, ""))
	api.mu.Unlock()
	ctrl.Start()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := reloads
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	ctrl.Stop()
	mu.Lock()
	if reloads == 0 {
		mu.Unlock()
		t.Fatal("controller did not request a reload")
	}
	mu.Unlock()
	snap, certs = ctrl.Snapshot()
	if len(snap.Routes) != 2 {
		t.Fatalf("routes after change: %d", len(snap.Routes))
	}
	merged, err = Merge(base, snap, certs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(merged); err != nil {
		t.Fatal(err)
	}
	st := ctrl.Status()
	if !st.Enabled || st.Syncs < 3 || st.Routes != 2 || st.Upstreams != 1 || st.Certificates != 1 || st.LastError != "" || st.Ingresses != 2 {
		t.Fatalf("status: %+v", st)
	}
	// The secret disappears: its files are removed on the next sync and
	// the merge no longer carries it.
	api.mu.Lock()
	api.ingresses = api.ingresses[1:]
	api.mu.Unlock()
	if _, err := ctrl.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(certs[0].CertFile); !os.IsNotExist(err) {
		t.Fatalf("stale certificate file kept: %v", err)
	}
	// Name collisions with the file configuration are refused.
	snap.Routes = append(snap.Routes, config.Route{Name: "static", Upstream: "static"})
	if _, err := Merge(base, snap, nil); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("collision: %v", err)
	}
	// An unauthorised token is an error that keeps the last snapshot.
	api.mu.Lock()
	api.token = "rotated"
	api.mu.Unlock()
	if _, err := ctrl.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("auth error: %v", err)
	}
	if st := ctrl.Status(); st.Errors != 1 || st.LastError == "" || st.Routes != 1 {
		t.Fatalf("status after error: %+v", st)
	}
	off := *base
	off.Ingress = nil
	if _, err := Merge(&off, snap, nil); err != ErrNotEnabled { //nolint:errorlint // sentinel
		t.Fatal("merge with ingress off")
	}
}
