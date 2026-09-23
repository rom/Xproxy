package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	"github.com/rom/xproxy/internal/testutil"
)

var nolog = slog.New(slog.NewTextHandler(io.Discard, nil))

const nodeConfig = `version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: web
    endpoints: [{address: "10.0.0.1:8080"}]
routes:
  - {name: default, upstream: web}
`

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestBundleReadValidateWrite(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "common", "waf", "rules.conf"), "SecRule ARGS \"@rx x\" \"id:1,deny\"\n")
	write(t, filepath.Join(dir, "common", "xproxy.yaml"), "version: 1\n")
	write(t, filepath.Join(dir, "nodes", "edge1", "xproxy.yaml"), nodeConfig)
	write(t, filepath.Join(dir, "nodes", "edge1", ".hidden"), "x")
	b, err := Read(filepath.Join(dir, "common"), filepath.Join(dir, "nodes", "edge1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 2 || b.Files[0].Path != "waf/rules.conf" || b.Files[1].Path != "xproxy.yaml" || string(b.Files[1].Content) != nodeConfig {
		t.Fatalf("bundle %+v", b.Files)
	}
	if b.Digest != Digest(b.Files) || b.Digest == "" {
		t.Fatal("digest")
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	// Digest is order independent and content sensitive.
	rev := []File{b.Files[1], b.Files[0]}
	if Digest(rev) != b.Digest {
		t.Fatal("digest depends on order")
	}
	rev[0].Content = append([]byte(nil), rev[0].Content...)
	rev[0].Content[0] = 'V'
	if Digest(rev) == b.Digest {
		t.Fatal("digest ignores content")
	}
	// Validation failures.
	bad := &Bundle{Files: []File{{Path: "xproxy.yaml", Mode: 0o640, Content: []byte("version: 1\nnonsense: [")}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("broken configuration accepted")
	}
	bad = &Bundle{Files: []File{{Path: "../xproxy.yaml", Mode: 0o640, Content: []byte(nodeConfig)}}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("traversal: %v", err)
	}
	bad = &Bundle{Files: []File{{Path: "other.yaml", Mode: 0o640, Content: []byte(nodeConfig)}}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "no xproxy.yaml") {
		t.Fatalf("missing config: %v", err)
	}
	bad = &Bundle{Digest: "abc", Files: []File{{Path: "xproxy.yaml", Mode: 0o640, Content: []byte(nodeConfig)}}}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("digest mismatch: %v", err)
	}
	for _, p := range []string{"", "/etc/passwd", "a/../b", "a//b", ".git/config", "a\x00b", strings.Repeat("d/", 9) + "f", "a\\b"} {
		if ValidPath(p) {
			t.Errorf("path %q accepted", p)
		}
	}
	for _, p := range []string{"xproxy.yaml", "waf/rules.conf", "a-b_c.d/e"} {
		if !ValidPath(p) {
			t.Errorf("path %q refused", p)
		}
	}

	// Write into a node directory, then restore.
	node := t.TempDir()
	write(t, filepath.Join(node, "xproxy.yaml"), "version: 1\n# old\n")
	write(t, filepath.Join(node, "keep.txt"), "keep")
	restore, err := Write(node, b)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(node, "xproxy.yaml"))
	rules, _ := os.ReadFile(filepath.Join(node, "waf", "rules.conf"))
	if string(got) != nodeConfig || !strings.HasPrefix(string(rules), "SecRule") {
		t.Fatalf("written: %q %q", got, rules)
	}
	if st, err := os.Stat(filepath.Join(node, "xproxy.yaml")); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("mode: %v %v", st, err)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(filepath.Join(node, "xproxy.yaml"))
	if string(got) != "version: 1\n# old\n" {
		t.Fatalf("restored: %q", got)
	}
	if _, err := os.Stat(filepath.Join(node, "waf", "rules.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new file not removed by restore")
	}
	if keep, _ := os.ReadFile(filepath.Join(node, "keep.txt")); string(keep) != "keep" {
		t.Fatal("unrelated file touched")
	}
	// A symlink escaping the directory is refused.
	if err := os.Symlink("/etc", filepath.Join(node, "waf")); err == nil {
		if _, err := Write(node, b); err == nil {
			t.Fatal("write through a symlink accepted")
		}
	}
}

// fleetTLS issues a CA, a controller certificate and one node
// certificate per name, returning the controller server and a client
// config factory.
type harness struct {
	dir   string
	ctrl  *Controller
	srv   *httptest.Server
	ca    *testutil.CA
	caPEM string
}

func newHarness(t *testing.T, requireName bool) *harness {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	certFile, keyFile := ca.Issue(t, dir, "controller")
	tc, err := ServerTLS(certFile, keyFile, filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := New(filepath.Join(dir, "fleet"), 50*time.Millisecond, requireName, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(ctrl.NodeHandler())
	srv.TLS = tc
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &harness{dir: dir, ctrl: ctrl, srv: srv, ca: ca, caPEM: filepath.Join(dir, "ca.pem")}
}

func (h *harness) agentConfig(t *testing.T, name string, apply bool) config.Fleet {
	t.Helper()
	certFile, keyFile := h.ca.Issue(t, h.dir, name)
	return config.Fleet{Controller: h.srv.URL, NodeID: name, TLS: config.FleetTLS{CertFile: certFile, KeyFile: keyFile, CAFile: h.caPEM, ServerName: "controller"},
		Interval: config.Duration(300 * time.Millisecond), Timeout: config.Duration(2 * time.Second), Apply: &apply, Tags: []string{"eu"}}
}

func (h *harness) client(t *testing.T, name string) *http.Client {
	t.Helper()
	certFile, keyFile := h.ca.Issue(t, h.dir, name)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := os.ReadFile(h.caPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "controller", MinVersion: tls.VersionTLS13}}}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second) // generous: the race detector and a loaded machine slow the TLS round trips
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestAgentAppliesAndReports(t *testing.T) {
	h := newHarness(t, true)
	write(t, filepath.Join(h.ctrl.Dir(), "common", "waf", "shared.conf"), "# shared\n")
	write(t, filepath.Join(h.ctrl.Dir(), "nodes", "edge1", "xproxy.yaml"), nodeConfig)
	h.ctrl.Scan()

	nodeDir := t.TempDir()
	cfgPath := filepath.Join(nodeDir, "xproxy.yaml")
	write(t, cfgPath, "version: 1\n")
	var mu sync.Mutex
	applies := 0
	var applyErr error
	hooks := Hooks{
		Apply: func() error {
			mu.Lock()
			defer mu.Unlock()
			applies++
			if applyErr != nil {
				return applyErr
			}
			_, err := config.Load(cfgPath)
			return err
		},
		Status: func() NodeStatus {
			return NodeStatus{Version: "test", Requests: 42, UpstreamsTotal: 1, UpstreamsHealthy: 1}
		},
	}
	ag, err := NewAgent(h.agentConfig(t, "edge1", true), cfgPath, hooks, nolog)
	if err != nil {
		t.Fatal(err)
	}
	ag.Start()
	defer ag.Stop()
	waitFor(t, "first apply", func() bool { return ag.Status().Applied.OK })
	st := ag.Status()
	got, _ := os.ReadFile(cfgPath)
	shared, _ := os.ReadFile(filepath.Join(nodeDir, "waf", "shared.conf"))
	if string(got) != nodeConfig || string(shared) != "# shared\n" || !st.Assigned || st.Applies != 1 {
		t.Fatalf("status %+v config %q", st, got)
	}
	if _, err := os.Stat(filepath.Join(nodeDir, markerFile)); err != nil {
		t.Fatal("marker not written")
	}
	waitFor(t, "report", func() bool {
		ov := h.ctrl.Nodes()
		return len(ov.Nodes) == 1 && ov.Nodes[0].Seen && ov.Nodes[0].InSync
	})
	n := h.ctrl.Nodes().Nodes[0]
	if n.NodeID != "edge1" || n.Status.Requests != 42 || n.Status.Version != "test" || n.CertName != "edge1" || len(n.Status.Tags) != 1 {
		t.Fatalf("node view %+v", n)
	}
	// The node view is updated in memory before the status file is
	// written, so this is waited for rather than checked once.
	waitFor(t, "status persisted", func() bool {
		_, err := os.Stat(filepath.Join(h.ctrl.Dir(), "status", "edge1.json"))
		return err == nil
	})

	// A change in the directory reaches the node through the long poll.
	first := st.Applied.Digest
	write(t, filepath.Join(h.ctrl.Dir(), "nodes", "edge1", "xproxy.yaml"), nodeConfig+"# v2\n")
	h.ctrl.Scan()
	waitFor(t, "second apply", func() bool { return ag.Status().Applied.OK && ag.Status().Applied.Digest != first })
	got, _ = os.ReadFile(cfgPath)
	if !strings.HasSuffix(string(got), "# v2\n") {
		t.Fatalf("second config %q", got)
	}

	// An invalid bundle on the controller keeps the last good one.
	write(t, filepath.Join(h.ctrl.Dir(), "nodes", "edge1", "xproxy.yaml"), "version: 1\nroutes: [{name: x}]\n")
	h.ctrl.Scan()
	b, scanErr := h.ctrl.Assignment("edge1")
	if b == nil || scanErr == "" || !strings.HasSuffix(string(b.Files[len(b.Files)-1].Content), "# v2\n") {
		t.Fatalf("invalid bundle handling: %v %q", b != nil, scanErr)
	}
	if v := h.ctrl.Nodes().Nodes[0]; v.ScanErr == "" || !v.InSync {
		t.Fatalf("node view after bad scan %+v", v)
	}

	// A bundle the proxy refuses is rolled back on the node.
	second := ag.Status().Applied.Digest
	mu.Lock()
	applyErr = errors.New("sandbox refuses")
	mu.Unlock()
	write(t, filepath.Join(h.ctrl.Dir(), "nodes", "edge1", "xproxy.yaml"), nodeConfig+"# v3\n")
	h.ctrl.Scan()
	// Applied is written inside apply, and Failures is incremented by
	// the loop once apply has returned the error, so a status with the
	// failed digest is not yet a status with the failure counted. Wait
	// for both, since both are asserted below.
	waitFor(t, "failed apply", func() bool {
		s := ag.Status()
		return !s.Applied.OK && s.Applied.Digest != second && s.Failures > 0
	})
	got, _ = os.ReadFile(cfgPath)
	if !strings.HasSuffix(string(got), "# v2\n") {
		t.Fatalf("not restored after failed reload: %q", got)
	}
	if s := ag.Status(); !strings.Contains(s.Applied.Error, "sandbox refuses") || s.Failures == 0 {
		t.Fatalf("failure status %+v", s)
	}
	waitFor(t, "failure reported", func() bool {
		v := h.ctrl.Nodes().Nodes[0]
		return v.Seen && !v.InSync && strings.Contains(v.Status.Applied.Error, "sandbox refuses")
	})

	// A restarted agent knows what it applied.
	ag.Stop()
	ag2, err := NewAgent(h.agentConfig(t, "edge1", true), cfgPath, hooks, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if ag2.Status().Applied.Digest != second {
		t.Fatalf("marker not read: %+v", ag2.Status())
	}
}

func TestAgentApplyOffAndUnassigned(t *testing.T) {
	h := newHarness(t, true)
	write(t, filepath.Join(h.ctrl.Dir(), "nodes", "edge2", "xproxy.yaml"), nodeConfig)
	h.ctrl.Scan()
	nodeDir := t.TempDir()
	cfgPath := filepath.Join(nodeDir, "xproxy.yaml")
	write(t, cfgPath, "version: 1\n")
	applied := false
	ag, err := NewAgent(h.agentConfig(t, "edge2", false), cfgPath, Hooks{Apply: func() error { applied = true; return nil }}, nolog)
	if err != nil {
		t.Fatal(err)
	}
	ag.Start()
	defer ag.Stop()
	waitFor(t, "pending", func() bool { return ag.Status().PendingDigest != "" })
	if got, _ := os.ReadFile(cfgPath); string(got) != "version: 1\n" || applied {
		t.Fatal("apply off still wrote or reloaded")
	}
	waitFor(t, "pending reported", func() bool {
		ov := h.ctrl.Nodes()
		return len(ov.Nodes) == 1 && ov.Nodes[0].Status.Pending != ""
	})
	// Remove the assignment: the agent reports unassigned.
	if err := os.RemoveAll(filepath.Join(h.ctrl.Dir(), "nodes", "edge2")); err != nil {
		t.Fatal(err)
	}
	h.ctrl.Scan()
	waitFor(t, "unassigned", func() bool { return !ag.Status().Assigned })
}

func TestControllerAuthorisation(t *testing.T) {
	h := newHarness(t, true)
	write(t, filepath.Join(h.ctrl.Dir(), "nodes", "edge1", "xproxy.yaml"), nodeConfig)
	h.ctrl.Scan()
	// A certificate for another node cannot fetch edge1's bundle or report as it.
	other := h.client(t, "edge9")
	resp, err := other.Get(h.srv.URL + "/v1/fleet/nodes/edge1/config?wait=1s")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("other node status %d", resp.StatusCode)
	}
	resp, err = other.Post(h.srv.URL+"/v1/fleet/nodes/edge1/status", "application/json", strings.NewReader(`{"node_id":"edge1"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("other node report status %d", resp.StatusCode)
	}
	// The right certificate gets the bundle, then 304 while unchanged.
	own := h.client(t, "edge1")
	resp, err = own.Get(h.srv.URL + "/v1/fleet/nodes/edge1/config?wait=1s")
	if err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || etag == "" {
		t.Fatalf("own fetch %d %q", resp.StatusCode, etag)
	}
	start := time.Now()
	resp, err = own.Get(h.srv.URL + "/v1/fleet/nodes/edge1/config?wait=200ms&digest=" + strings.Trim(etag, `"`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("long poll %d after %s", resp.StatusCode, time.Since(start))
	}
	// A bad node id and a mismatching report body are refused.
	resp, err = own.Get(h.srv.URL + "/v1/fleet/nodes/Edge%201/config")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad id status %d", resp.StatusCode)
	}
	resp, err = own.Post(h.srv.URL+"/v1/fleet/nodes/edge1/status", "application/json", strings.NewReader(`{"node_id":"edge2"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatching report status %d", resp.StatusCode)
	}
	// Without a client certificate the handshake fails.
	pem, _ := os.ReadFile(h.caPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	anon := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "controller", MinVersion: tls.VersionTLS13}}}
	if _, err := anon.Get(h.srv.URL + "/v1/fleet/nodes/edge1/config"); err == nil {
		t.Fatal("anonymous client accepted")
	}
	// The name map is the explicit exception: the certificate named
	// "agent" may act for edge1, and nothing else changes.
	h3 := newHarness(t, true)
	h3.ctrl.nameMap = map[string]string{"edge1": "agent"}
	write(t, filepath.Join(h3.ctrl.Dir(), "nodes", "edge1", "xproxy.yaml"), nodeConfig)
	write(t, filepath.Join(h3.ctrl.Dir(), "nodes", "edge2", "xproxy.yaml"), nodeConfig)
	h3.ctrl.Scan()
	resp, err = h3.client(t, "agent").Get(h3.srv.URL + "/v1/fleet/nodes/edge1/config")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("name map status %d", resp.StatusCode)
	}
	if h3.ctrl.mapped.Total() != 1 {
		t.Fatalf("the exception was not counted: %d", h3.ctrl.mapped.Total())
	}
	// A node the map does not name is still refused for that certificate.
	resp, err = h3.client(t, "agent").Get(h3.srv.URL + "/v1/fleet/nodes/edge2/config")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("a node outside the map: %d", resp.StatusCode)
	}
	// -any-name lets a differently named certificate act for a node,
	// loudly.
	h2 := newHarness(t, false)
	write(t, filepath.Join(h2.ctrl.Dir(), "nodes", "edge1", "xproxy.yaml"), nodeConfig)
	h2.ctrl.Scan()
	resp, err = h2.client(t, "agent").Get(h2.srv.URL + "/v1/fleet/nodes/edge1/config")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("any-name status %d", resp.StatusCode)
	}
	if h2.ctrl.anyName.Total() == 0 {
		t.Fatal("an authorisation without a name binding was silent")
	}
}

func TestAdminHandlerAndValidateDir(t *testing.T) {
	h := newHarness(t, true)
	write(t, filepath.Join(h.ctrl.Dir(), "nodes", "edge1", "xproxy.yaml"), nodeConfig)
	write(t, filepath.Join(h.ctrl.Dir(), "nodes", "edge2", "xproxy.yaml"), "version: 1\nroutes: [{name: x}]\n")
	h.ctrl.Scan()
	admin := httptest.NewServer(h.ctrl.AdminHandler())
	defer admin.Close()
	body := func(path string) (int, string) {
		resp, err := http.Get(admin.URL + path) //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, b := body("/v1/fleet/nodes"); code != 200 || !strings.Contains(b, `"node_id":"edge1"`) || !strings.Contains(b, `"scan_error"`) {
		t.Fatalf("nodes %d %s", code, b)
	}
	if code, b := body("/v1/fleet/nodes/edge1"); code != 200 || !strings.Contains(b, `"assigned":true`) {
		t.Fatalf("node %d %s", code, b)
	}
	if code, b := body("/v1/fleet/nodes/edge1/bundle"); code != 200 || !strings.Contains(b, `"path":"xproxy.yaml"`) || strings.Contains(b, "content") {
		t.Fatalf("bundle %d %s", code, b)
	}
	if code, _ := body("/v1/fleet/nodes/edge2/bundle"); code != 404 {
		t.Fatalf("invalid node bundle %d", code)
	}
	if code, _ := body("/v1/fleet/nodes/nope"); code != 404 {
		t.Fatalf("unknown node %d", code)
	}
	problems, ids, err := ValidateDir(h.ctrl.Dir())
	if err != nil || len(ids) != 2 || problems["edge1"] != "" || problems["edge2"] == "" {
		t.Fatalf("validate: %v %v %v", problems, ids, err)
	}
	if _, _, err := ValidateDir(t.TempDir()); err == nil {
		t.Fatal("directory without nodes accepted")
	}
	// A restarted controller remembers the reports.
	h.ctrl.record("edge1", NodeStatus{NodeID: "edge1", Version: "1"}, "10.0.0.1:1", "edge1")
	c2, err := New(h.ctrl.Dir(), time.Second, true, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if v := c2.Nodes().Nodes[0]; !v.Seen || v.Status.Version != "1" {
		t.Fatalf("status not restored: %+v", v)
	}
}

func TestAgentConstruction(t *testing.T) {
	h := newHarness(t, true)
	cfg := h.agentConfig(t, "edge1", true)
	dir := t.TempDir()
	write(t, filepath.Join(dir, "xproxy.yaml"), "version: 1\n")
	if _, err := NewAgent(cfg, filepath.Join(dir, "other.yaml"), Hooks{}, nolog); err == nil {
		t.Fatal("configuration file name not enforced")
	}
	cfg.Dir = t.TempDir()
	if _, err := NewAgent(cfg, filepath.Join(dir, "xproxy.yaml"), Hooks{}, nolog); err == nil {
		t.Fatal("dir outside the configuration directory accepted")
	}
	cfg.Dir = ""
	cfg.TLS.CAFile = filepath.Join(dir, "missing.pem")
	if _, err := NewAgent(cfg, filepath.Join(dir, "xproxy.yaml"), Hooks{}, nolog); err == nil {
		t.Fatal("missing CA accepted")
	}
}
