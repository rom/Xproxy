package ingress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

// The controller turns what an API server says into the proxy's own
// configuration and into files on disk. Everything below is driven with
// the answers a cluster — or a compromised one — can give.

const mergeBase = `
version: 1
server:
  listeners:
    - {name: main, address: ":8080"}
    - {name: web, address: ":8443", tls: {certificates: [{cert_file: CERT, key_file: KEY}]}}
    - {name: plain, address: ":8081"}
ingress: {enabled: true, api_server: "http://127.0.0.1:1", allow_http: true, token_file: TOKEN, cert_dir: CERTDIR, listener: LISTENER}
upstreams: [{name: app, endpoints: [{address: 127.0.0.1:1}]}]
routes: [{name: app, upstream: app}]
`

// mergeConfig parses the operator's own configuration with real files
// behind it, since Merge runs the result through the ordinary parser.
func mergeConfig(t *testing.T, listener string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "web.test")
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := strings.NewReplacer("CERTDIR", dir, "CERT", cert, "KEY", key, "TOKEN", token, "LISTENER", listener)
	c, err := config.Parse([]byte(r.Replace(mergeBase)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMergeRefusesCollisionsAndBadListeners(t *testing.T) {
	extraDir := t.TempDir()
	extraCert, extraKey := testutil.WriteCert(t, extraDir, "k8s.test")
	certs := []config.Certificate{{CertFile: extraCert, KeyFile: extraKey}}

	// A snapshot whose names collide with the operator's own must not be
	// merged: a tenant who can create an Ingress would otherwise take
	// over a route or an upstream the operator wrote.
	base := mergeConfig(t, "web")
	if _, err := Merge(base, Snapshot{Routes: []config.Route{{Name: "app", Upstream: "app"}}}, nil); err == nil {
		t.Error("a colliding route name was merged")
	}
	if _, err := Merge(base, Snapshot{Upstreams: []config.Upstream{{Name: "app", Endpoints: []config.Endpoint{{Address: "127.0.0.1:2"}}}}}, nil); err == nil {
		t.Error("a colliding upstream name was merged")
	}

	// The certificates go on the named listener, and only when there are
	// any: a listener that does not exist, or one with no tls section,
	// is an error rather than certificates quietly going nowhere.
	merged, err := Merge(base, Snapshot{}, certs)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	for _, ln := range merged.Server.Listeners {
		if ln.Name != "web" {
			continue
		}
		if n := len(ln.TLS.Certificates); n != 2 {
			t.Errorf("the ingress listener has %d certificates", n)
		}
	}
	// Validation already refuses these two in a configuration file, so
	// they are built by hand: Merge is the second line of defence for a
	// configuration assembled another way, and must report rather than
	// drop the certificates on the floor.
	noTLS := mergeConfig(t, "web")
	for i := range noTLS.Server.Listeners {
		if noTLS.Server.Listeners[i].Name == "web" {
			noTLS.Server.Listeners[i].TLS = nil
		}
	}
	if _, err := Merge(noTLS, Snapshot{}, certs); err == nil {
		t.Error("a listener with no tls section took certificates")
	}
	absent := mergeConfig(t, "web")
	absent.Ingress.Listener = "nosuchlistener"
	if _, err := Merge(absent, Snapshot{}, certs); err == nil {
		t.Error("certificates were merged onto a listener that does not exist")
	}
	// With no certificates Merge does not look for the listener itself,
	// but the reparse still validates the section, so the operator hears
	// about the name either way rather than only once a secret appears.
	if _, err := Merge(absent, Snapshot{}, nil); err == nil {
		t.Error("an unknown ingress listener passed the reparse")
	}

	// The whole document goes back through the ordinary parser, so a
	// snapshot that would not validate on its own is refused here.
	if _, err := Merge(base, Snapshot{Routes: []config.Route{{Name: "k8s-x", Upstream: "nosuchpool"}}}, nil); err == nil {
		t.Error("a route naming an upstream nobody defined was merged")
	}

	// Ingress mode off is refused with its own error, so a caller can
	// tell "not configured" from "bad configuration".
	off, err := config.Parse([]byte("version: 1\nserver: {listeners: [{name: main, address: \":8080\"}]}\nupstreams: [{name: app, endpoints: [{address: 127.0.0.1:1}]}]\nroutes: [{name: app, upstream: app}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(off, Snapshot{}, nil); !errors.Is(err, ErrNotEnabled) {
		t.Errorf("ingress off gave %v", err)
	}
	// The base is never modified: a failed merge must leave the running
	// configuration exactly as it was.
	beforeRoutes, beforeUps := len(base.Routes), len(base.Upstreams)
	_, _ = Merge(base, Snapshot{Routes: []config.Route{{Name: "k8s-y", Upstream: "app"}}}, certs)
	if len(base.Routes) != beforeRoutes || len(base.Upstreams) != beforeUps {
		t.Error("Merge modified the configuration it was given")
	}
}

func TestMatchesClass(t *testing.T) {
	cases := []struct {
		className, annotation, class string
		want                         bool
	}{
		{"xproxy", "", "xproxy", true},
		{"nginx", "", "xproxy", false},
		// The field wins over the annotation, which is the deprecated
		// spelling: an Ingress naming another controller in the field is
		// not ours whatever its annotations say.
		{"nginx", "xproxy", "xproxy", false},
		{"", "xproxy", "xproxy", true},
		{"", "nginx", "xproxy", false},
		// Neither means the Ingress is unclassed; the controller does not
		// adopt it, or two controllers would both serve it.
		{"", "", "xproxy", false},
		{"", "", "", false},
		{"XProxy", "", "xproxy", false},
		{"xproxy ", "", "xproxy", false},
	}
	for _, c := range cases {
		ing := &Ingress{}
		ing.Spec.IngressClassName = c.className
		if c.annotation != "" {
			ing.Metadata.Annotations = map[string]string{"kubernetes.io/ingress.class": c.annotation}
		}
		if got := matchesClass(ing, c.class); got != c.want {
			t.Errorf("class %q annotation %q against %q = %v", c.className, c.annotation, c.class, got)
		}
	}
}

func TestHeaderOpsFromAFilter(t *testing.T) {
	if ops := headerOps(nil); ops.Set != nil || ops.Add != nil || ops.Remove != nil {
		t.Errorf("a nil modifier produced %+v", ops)
	}
	if ops := headerOps(&headerModifier{}); ops.Set != nil || ops.Add != nil || ops.Remove != nil {
		t.Errorf("an empty modifier produced %+v", ops)
	}
	type nv = struct{ Name, Value string }
	ops := headerOps(&headerModifier{
		Set:    []nv{{Name: "X-A", Value: "1"}, {Name: "X-B", Value: "2"}},
		Add:    []nv{{Name: "X-C", Value: "3"}},
		Remove: []string{"X-D", "X-E"},
	})
	if ops.Set["X-A"] != "1" || ops.Set["X-B"] != "2" || ops.Add["X-C"] != "3" {
		t.Errorf("ops = %+v", ops)
	}
	if len(ops.Remove) != 2 {
		t.Errorf("remove = %v", ops.Remove)
	}
	// A repeated name keeps the last value rather than producing two
	// operations that fight each other on every request.
	dup := headerOps(&headerModifier{Set: []nv{{Name: "X-A", Value: "1"}, {Name: "X-A", Value: "2"}}})
	if dup.Set["X-A"] != "2" || len(dup.Set) != 1 {
		t.Errorf("a repeated name gave %+v", dup.Set)
	}
}

func TestAddCertRefusals(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	good := &Secret{Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": b64([]byte("CERT")), "tls.key": b64([]byte("KEY"))}}
	var warnings []string
	warn := func(format string, args ...any) { warnings = append(warnings, format) }

	snap := &Snapshot{}
	addCert(snap, "ns", "tls", good, []string{"a.test"}, warn)
	if len(snap.Certificates) != 1 || len(warnings) != 0 {
		t.Fatalf("a good secret gave %d certificates and %v", len(snap.Certificates), warnings)
	}
	// The same secret referenced twice is added once: a Gateway with
	// several listeners on one certificate must not write it twice.
	addCert(snap, "ns", "tls", good, []string{"b.test"}, warn)
	if len(snap.Certificates) != 1 {
		t.Errorf("the secret was added %d times", len(snap.Certificates))
	}

	// Everything that is not a usable TLS secret is refused with a
	// warning, never published as a certificate.
	refusals := map[string]*Secret{
		"another type":   {Type: "Opaque", Data: good.Data},
		"a docker type":  {Type: "kubernetes.io/dockerconfigjson", Data: good.Data},
		"no certificate": {Type: "kubernetes.io/tls", Data: map[string]string{"tls.key": b64([]byte("KEY"))}},
		"no key":         {Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": b64([]byte("CERT"))}},
		"empty values":   {Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": "", "tls.key": ""}},
		"not base64":     {Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": "!!!", "tls.key": "!!!"}},
		"empty material": {Type: "kubernetes.io/tls", Data: map[string]string{"tls.crt": b64(nil), "tls.key": b64(nil)}},
		"no data at all": {Type: "kubernetes.io/tls"},
	}
	for name, s := range refusals {
		before, warned := len(snap.Certificates), len(warnings)
		addCert(snap, "ns", name, s, []string{"c.test"}, warn)
		if len(snap.Certificates) != before {
			t.Errorf("%s was published as a certificate", name)
		}
		if len(warnings) == warned {
			t.Errorf("%s was refused without a warning", name)
		}
	}
	// A secret with no type at all is accepted: the API server fills the
	// field in, but an older object or a test fixture may not have it.
	untyped := &Secret{Data: good.Data}
	addCert(snap, "ns", "untyped", untyped, []string{"d.test"}, warn)
	if len(snap.Certificates) != 2 {
		t.Errorf("an untyped secret was refused: %d certificates", len(snap.Certificates))
	}
}

func TestWriteIfChangedFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.crt")
	if err := writeIfChanged(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	// Unchanged content is not rewritten, so the file the proxy is
	// reading is not replaced under it on every poll.
	before := info.ModTime()
	if err := writeIfChanged(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(path); !after.ModTime().Equal(before) {
		t.Error("unchanged content was rewritten")
	}
	// Changed content replaces the file atomically and leaves nothing
	// behind: a half-written key must never be readable.
	if err := writeIfChanged(path, []byte("two")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "two" {
		t.Errorf("content = %q", got)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
	// A directory that cannot be written to is an error, not a silent
	// skip that would leave the proxy serving an old certificate.
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := writeIfChanged(filepath.Join(ro, "b.crt"), []byte("x")); err == nil {
			t.Error("a write into an unwritable directory reported success")
		}
	}
	// A path whose parent does not exist is likewise an error.
	if err := writeIfChanged(filepath.Join(dir, "absent", "c.crt"), []byte("x")); err == nil {
		t.Error("a write into a missing directory reported success")
	}
	// A path that is a directory cannot be replaced by a file.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeIfChanged(sub, []byte("x")); err == nil {
		t.Error("a directory was replaced with a file")
	}
}

func TestWriteCertsSweepsOnlyItsOwnFiles(t *testing.T) {
	dir := t.TempDir()
	c := &Controller{cfg: config.Ingress{CertDir: dir}, log: slog.New(slog.DiscardHandler)}

	// A file the controller did not write is left alone: cert_dir may be
	// shared with the operator's own certificates.
	foreign := filepath.Join(dir, "operator.crt")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(other, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub--dir.crt"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "ns--gone.crt")
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := c.writeCerts([]CertPEM{{Namespace: "ns", Name: "live", Cert: []byte("C"), Key: []byte("K")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !strings.HasSuffix(out[0].CertFile, "ns--live.crt") {
		t.Fatalf("certificates = %+v", out)
	}
	for _, p := range []string{foreign, other, filepath.Join(dir, "sub--dir.crt")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed: %v", filepath.Base(p), err)
		}
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("a secret nobody references any more was left on disk")
	}

	// A namespace or name that could leave the directory is dropped, not
	// written: the name comes from whatever answered the API request.
	out, err = c.writeCerts([]CertPEM{
		{Namespace: "../../etc", Name: "shadow", Cert: []byte("C"), Key: []byte("K")},
		{Namespace: "ns", Name: "../../../etc/passwd", Cert: []byte("C"), Key: []byte("K")},
		{Namespace: "ns", Name: "", Cert: []byte("C"), Key: []byte("K")},
		{Namespace: "NS", Name: "upper", Cert: []byte("C"), Key: []byte("K")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("unusable names were written: %+v", out)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "..") {
			t.Errorf("a traversal name reached the directory: %s", e.Name())
		}
	}

	// A cert_dir that is not there at all is an error the caller reports,
	// rather than a sync that silently publishes nothing.
	missing := &Controller{cfg: config.Ingress{CertDir: filepath.Join(dir, "absent")}, log: slog.New(slog.DiscardHandler)}
	if _, err := missing.writeCerts(nil); err == nil {
		t.Error("a missing cert_dir reported success")
	}
}

func TestFetchReportsWhichResourceFailed(t *testing.T) {
	f := newFakeAPI(t)
	f.gatewayAPI = true
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(config.Ingress{
		Enabled: true, APIServer: f.srv.URL, AllowHTTP: true, TokenFile: tok,
		CertDir: dir, Class: "xproxy", Timeout: config.Duration(5 * time.Second),
	}, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}

	// A Gateway API the cluster does not serve is not an error: the CRDs
	// are optional and a cluster without them still has Ingresses.
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	f.gatewayAPI = false
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatalf("fetch without the Gateway CRDs: %v", err)
	}
	if c.gwAPI.Load() {
		t.Error("the Gateway API is reported present after a 404")
	}

	// An API server that refuses the token fails the fetch with the
	// resource named, rather than producing an empty snapshot that would
	// withdraw every route the cluster has.
	f.mu.Lock()
	f.token = "rotated"
	f.mu.Unlock()
	_, err = c.fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ingresses") {
		t.Errorf("an unauthorised fetch gave %v", err)
	}
}

func TestSecretFailuresDoNotStopTheSync(t *testing.T) {
	f := newFakeAPI(t)
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.ingresses = []any{ingressObj("ns", "one", "xproxy", "a.test", "/", "svc", 80, nil, "absent-secret")}
	f.services = []any{serviceObj("ns", "svc", 80, "", 8080)}
	f.slices = []any{sliceObj("ns", "svc", "", 8080, true, "10.0.0.1")}

	c, err := New(config.Ingress{
		Enabled: true, APIServer: f.srv.URL, AllowHTTP: true, TokenFile: tok,
		CertDir: dir, Class: "xproxy", Timeout: config.Duration(5 * time.Second),
	}, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A TLS secret that is not there is a warning: the route still
	// serves, without a certificate of its own.
	in, err := c.fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if s, ok := in.Secrets["ns/absent-secret"]; !ok || s != nil {
		t.Errorf("a missing secret was recorded as %v, %v", s, ok)
	}
	if len(in.Ingresses) != 1 {
		t.Errorf("%d ingresses", len(in.Ingresses))
	}
}

func TestNamespacedListPaths(t *testing.T) {
	// Namespaced mode builds a different path for every resource; the
	// fake cluster serves only the cluster-wide ones, so each call must
	// come back with the resource named rather than an empty list that
	// would look like "this namespace has nothing".
	f := newFakeAPI(t)
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := newClient(f.srv.URL, tok, "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	calls := map[string]func() error{
		"ingresses":      func() error { _, err := c.ingresses(ctx, "team-a"); return err },
		"services":       func() error { _, err := c.services(ctx, "team-a"); return err },
		"endpointslices": func() error { _, err := c.endpointSlices(ctx, "team-a"); return err },
		"gateways":       func() error { _, err := c.gateways(ctx, "team-a"); return err },
		"httproutes":     func() error { _, err := c.httpRoutes(ctx, "team-a"); return err },
	}
	for name, call := range calls {
		err := call()
		if err == nil {
			t.Errorf("%s in a namespace the cluster does not serve reported success", name)
			continue
		}
		if !isNotFound(err) {
			t.Errorf("%s gave %v, want a not-found", name, err)
		}
	}
	// The cluster-wide spellings are served, and answer an empty list.
	if items, err := c.ingresses(ctx, ""); err != nil || len(items) != 0 {
		t.Errorf("cluster-wide ingresses = %v, %v", items, err)
	}
}

func TestWatchStreamFailures(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A path that already carries a query keeps it: the watch parameters
	// are appended rather than replacing a field selector.
	var seenQuery, mode atomic.Value
	seenQuery.Store("")
	mode.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQuery.Store(r.URL.RawQuery)
		switch mode.Load().(string) {
		case "forbidden":
			http.Error(w, `{"message":"forbidden"}`, http.StatusForbidden)
		case "garbage":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{not json"))
		case "empty-kind":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"","object":{}}` + "\n" + `{"type":"ADDED","object":{}}` + "\n"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"BOOKMARK","object":{}}` + "\n"))
		}
	}))
	defer srv.Close()
	c, err := newClient(srv.URL, tok, "", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// A server that ends the stream returns the read error, which is what
	// the loop turns into a back-off; only a cancelled context is a
	// clean end. A bookmark is delivered like any other event here; the
	// loop is what ignores it.
	if err := c.watch(ctx, "/apis/x?fieldSelector=a", func(string) {}); err == nil {
		t.Error("the end of a stream was not reported")
	}
	if q := seenQuery.Load().(string); !strings.Contains(q, "fieldSelector=a") || !strings.Contains(q, "watch=1") {
		t.Errorf("the watch query is %q", q)
	}

	// A status other than 200 is an error naming it, so the loop backs
	// off rather than treating a 403 as a stream with no events.
	mode.Store("forbidden")
	err = c.watch(ctx, "/apis/x", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("a 403 gave %v", err)
	}
	// A body that is not a stream of events is an error, not a silent end.
	mode.Store("garbage")
	if err := c.watch(ctx, "/apis/x", func(string) {}); err == nil {
		t.Error("an undecodable stream reported a clean end")
	}
	// An event with no type is skipped; the next one is still delivered.
	mode.Store("empty-kind")
	var kinds []string
	if err := c.watch(ctx, "/apis/x", func(k string) { kinds = append(kinds, k) }); err == nil {
		t.Error("the end of the stream was not reported")
	}
	if len(kinds) != 1 || kinds[0] != "ADDED" {
		t.Errorf("kinds = %v", kinds)
	}

	// A context that is already done ends the stream without an error:
	// a shutdown is not a watch failure to back off from.
	done, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.watch(done, "/apis/x", func(string) {}); err == nil {
		t.Log("a cancelled context ended the stream before the request")
	}
	// An API server address that cannot become a request is reported.
	bad, err := newClient(srv.URL, tok, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	bad.base = "http://[::1"
	if err := bad.watch(ctx, "/apis/x", func(string) {}); err == nil {
		t.Error("an unbuildable request reported success")
	}
}

func TestWatchLoopBacksOffAndStops(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	var status atomic.Int64
	status.Store(http.StatusNotFound)
	calls := make(chan struct{}, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case calls <- struct{}{}:
		default:
		}
		http.Error(w, `{"message":"no"}`, int(status.Load()))
	}))
	defer srv.Close()

	run := func(code int) {
		status.Store(int64(code))
		c, err := New(config.Ingress{
			Enabled: true, APIServer: srv.URL, AllowHTTP: true, TokenFile: tok,
			CertDir: dir, Class: "xproxy", Timeout: config.Duration(2 * time.Second),
		}, slog.New(slog.DiscardHandler), nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		c.wg.Add(1)
		go c.watchLoop(ctx, "/apis/x")
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatalf("the watch was never opened for %d", code)
		}
		// The loop is now waiting out its back-off; cancelling must end
		// it rather than leave a goroutine sleeping for five minutes.
		cancel()
		wait := make(chan struct{})
		go func() { c.wg.Wait(); close(wait) }()
		select {
		case <-wait:
		case <-time.After(5 * time.Second):
			t.Fatalf("the watch loop did not stop for %d", code)
		}
		if n := c.watching.Load(); n != 0 {
			t.Errorf("%d watches are still counted open", n)
		}
	}
	// A resource the cluster does not serve backs off far; anything else
	// backs off a little. Either way the loop ends when the context does.
	run(http.StatusNotFound)
	run(http.StatusInternalServerError)

	// A context that is already done never opens a stream at all.
	c, err := New(config.Ingress{
		Enabled: true, APIServer: srv.URL, AllowHTTP: true, TokenFile: tok,
		CertDir: dir, Class: "xproxy", Timeout: config.Duration(time.Second),
	}, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.wg.Add(1)
	c.watchLoop(ctx, "/apis/x")
}

// gwObjects unmarshals Gateway API JSON into the shapes the translator
// reads, which is how they arrive from an API server.
func gwObjects(t *testing.T, gateways, routes string) Input {
	t.Helper()
	var in Input
	if gateways != "" {
		if err := json.Unmarshal([]byte(gateways), &in.Gateways); err != nil {
			t.Fatalf("gateways: %v", err)
		}
	}
	if routes != "" {
		if err := json.Unmarshal([]byte(routes), &in.HTTPRoutes); err != nil {
			t.Fatalf("httproutes: %v", err)
		}
	}
	in.Secrets = map[string]*Secret{}
	return in
}

func TestTranslateGatewayRefusals(t *testing.T) {
	noEndpoints := func(ns, svc string, port int, portName string) ([]config.Endpoint, error) {
		return []config.Endpoint{{Address: "10.0.0.1:8080"}}, nil
	}
	run := func(gateways, routes string, secrets map[string]*Secret) Snapshot {
		in := gwObjects(t, gateways, routes)
		if secrets != nil {
			in.Secrets = secrets
		}
		var snap Snapshot
		translateGateway(in, "xproxy", &snap, noEndpoints)
		return snap
	}
	warned := func(snap Snapshot, want string) bool {
		for _, w := range snap.Warnings {
			if strings.Contains(w, want) {
				return true
			}
		}
		return false
	}

	// A Gateway whose namespace or name is not a DNS label is refused:
	// both become part of an upstream name and a file name.
	snap := run(`[{"metadata":{"namespace":"Bad_NS","name":"gw"},"spec":{"gatewayClassName":"xproxy","listeners":[]}}]`, "", nil)
	if snap.Gateways != 0 || !warned(snap, "not a DNS label") {
		t.Errorf("a gateway with a bad name gave %d gateways, %v", snap.Gateways, snap.Warnings)
	}
	// Another controller's class is skipped silently: it is not ours to
	// warn about.
	snap = run(`[{"metadata":{"namespace":"ns","name":"gw"},"spec":{"gatewayClassName":"istio","listeners":[]}}]`, "", nil)
	if snap.Gateways != 0 || len(snap.Warnings) != 0 {
		t.Errorf("another class produced %d gateways and %v", snap.Gateways, snap.Warnings)
	}

	// A certificate reference to something that is not a Secret, and one
	// naming a Secret nobody fetched, are both refused with a warning
	// rather than a listener that comes up with no certificate.
	snap = run(`[{"metadata":{"namespace":"ns","name":"gw"},"spec":{"gatewayClassName":"xproxy","listeners":[
		{"name":"a","hostname":"a.test","protocol":"HTTPS","tls":{"certificateRefs":[{"kind":"ConfigMap","name":"cm"}]}},
		{"name":"b","hostname":"b.test","protocol":"HTTPS","tls":{"certificateRefs":[{"name":"absent"}]}},
		{"name":"c","hostname":"c.test","protocol":"HTTP"}]}}]`, "", nil)
	if snap.Gateways != 1 {
		t.Fatalf("%d gateways", snap.Gateways)
	}
	for _, want := range []string{"kind ConfigMap not supported", "tls secret absent not found"} {
		if !warned(snap, want) {
			t.Errorf("missing the warning %q in %v", want, snap.Warnings)
		}
	}
	if len(snap.Certificates) != 0 {
		t.Errorf("a refused reference produced %d certificates", len(snap.Certificates))
	}
	// A secret the fetch failed on is recorded as nil and refused too.
	snap = run(`[{"metadata":{"namespace":"ns","name":"gw"},"spec":{"gatewayClassName":"xproxy","listeners":[
		{"name":"a","hostname":"a.test","protocol":"HTTPS","tls":{"certificateRefs":[{"name":"broken"}]}}]}}]`,
		"", map[string]*Secret{"ns/broken": nil})
	if len(snap.Certificates) != 0 || !warned(snap, "not found") {
		t.Errorf("a failed secret gave %d certificates, %v", len(snap.Certificates), snap.Warnings)
	}

	const gw = `[{"metadata":{"namespace":"ns","name":"gw"},"spec":{"gatewayClassName":"xproxy","listeners":[
		{"name":"a","hostname":"a.test","protocol":"HTTP","allowedRoutes":{"namespaces":{"from":"All"}}}]}}]`

	// A route whose namespace or name is not a DNS label is dropped, and
	// so is one whose parent is another kind or a gateway nobody knows.
	for _, routes := range []string{
		`[{"metadata":{"namespace":"Bad_NS","name":"r"},"spec":{"parentRefs":[{"name":"gw","namespace":"ns"}],"rules":[]}}]`,
		`[{"metadata":{"namespace":"ns","name":"r"},"spec":{"parentRefs":[{"kind":"Service","name":"gw"}],"rules":[]}}]`,
		`[{"metadata":{"namespace":"ns","name":"r"},"spec":{"parentRefs":[{"name":"nosuchgateway"}],"rules":[]}}]`,
		`[{"metadata":{"namespace":"ns","name":"r"},"spec":{"parentRefs":[],"rules":[]}}]`,
	} {
		snap = run(gw, routes, nil)
		if snap.HTTPRoutes != 0 {
			t.Errorf("%s was attached", routes)
		}
	}

	// A filter the translator does not implement warns rather than being
	// dropped without trace: the operator asked for something the proxy
	// will not do, and must hear about it.
	snap = run(gw, `[{"metadata":{"namespace":"ns","name":"r"},"spec":{"parentRefs":[{"name":"gw"}],"rules":[
		{"filters":[{"type":"RequestMirror"}],"backendRefs":[{"name":"svc","port":80}]}]}}]`, nil)
	if !warned(snap, "filter RequestMirror not supported") {
		t.Errorf("warnings = %v", snap.Warnings)
	}
	// A rewrite the proxy cannot express, and a redirect with no host.
	snap = run(gw, `[{"metadata":{"namespace":"ns","name":"r"},"spec":{"parentRefs":[{"name":"gw"}],"rules":[
		{"filters":[{"type":"URLRewrite","urlRewrite":{"path":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/other"}}}],"backendRefs":[{"name":"svc","port":80}]},
		{"filters":[{"type":"RequestRedirect","requestRedirect":{"scheme":"https"}}],"backendRefs":[{"name":"svc","port":80}]},
		{"filters":[{"type":"URLRewrite"},{"type":"RequestRedirect"}],"backendRefs":[{"name":"svc","port":80}]}]}}]`, nil)
	for _, want := range []string{"not supported (only ReplaceFullPath", "RequestRedirect without hostname"} {
		if !warned(snap, want) {
			t.Errorf("missing %q in %v", want, snap.Warnings)
		}
	}

	// A redirect with a host, a port and a full path becomes one route
	// with no upstream at all, so nothing is proxied for it.
	snap = run(gw, `[{"metadata":{"namespace":"ns","name":"r"},"spec":{"parentRefs":[{"name":"gw"}],"hostnames":["Old.Test"],"rules":[
		{"filters":[{"type":"RequestRedirect","requestRedirect":{"hostname":"new.test","port":8443,"statusCode":301,"path":{"type":"ReplaceFullPath","replaceFullPath":"/moved"}}}]}]}}]`, nil)
	if len(snap.Routes) != 1 {
		t.Fatalf("%d routes: %+v", len(snap.Routes), snap.Routes)
	}
	r := snap.Routes[0]
	if r.Redirect == nil || r.Redirect.To != "https://new.test:8443/moved" || r.Redirect.Status != 301 {
		t.Errorf("redirect = %+v", r.Redirect)
	}
	if r.Upstream != "" {
		t.Errorf("a redirect route names the upstream %q", r.Upstream)
	}
	// The route's own hostname is lower-cased, so one name has one key.
	if len(r.Hosts) != 1 || r.Hosts[0] != "old.test" {
		t.Errorf("hosts = %v", r.Hosts)
	}
	// Without hostnames of its own the route takes the parents'.
	snap = run(gw, `[{"metadata":{"namespace":"ns","name":"r"},"spec":{"parentRefs":[{"name":"gw"}],"rules":[
		{"filters":[{"type":"RequestRedirect","requestRedirect":{"hostname":"new.test"}}]}]}}]`, nil)
	if len(snap.Routes) != 1 || len(snap.Routes[0].Hosts) != 1 || snap.Routes[0].Hosts[0] != "a.test" {
		t.Errorf("inherited hosts = %+v", snap.Routes)
	}
	// A redirect with no explicit status and no scheme defaults to a
	// temporary one over https.
	if to := snap.Routes[0].Redirect; to == nil || to.To != "https://new.test" || to.Status != 302 {
		t.Errorf("defaults = %+v", snap.Routes[0].Redirect)
	}
}
