package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/listener"
)

// Ingress controller mode, and the management actions that only exist
// once something has gone wrong.
//
// In controller mode the running configuration is the file plus whatever
// the cluster's Ingress resources translate to, which puts a network call
// between the file on disk and the listeners. The question that matters is
// what the daemon does when that call does not answer: a controller that
// refused to start would leave the file configuration unserved, and a
// controller that merged an empty snapshot over it would take the routes
// away. It serves the file and keeps asking.

// ingressYAML writes a configuration in controller mode pointed at a stub
// API server, with the bearer token file it needs on disk.
func ingressYAML(t *testing.T, dir, api string) string {
	t.Helper()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("stub-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  shutdown_timeout: 2s
sandbox: {enabled: false}
management: {socket: `+filepath.Join(dir, "m.sock")+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
ingress:
  enabled: true
  api_server: `+api+`
  allow_http: true
  token_file: `+token+`
  cert_dir: `+filepath.Join(dir, "ingress")+`
  resync: 1s
  timeout: 2s
  watch: false
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
}

// TestTheFileConfigurationIsServedUntilTheAPIAnswers: the initial sync is
// a network call, and a daemon that treated its failure as fatal would be
// a daemon that will not start while the API server is being upgraded.
// The file is what it has, so the file is what it serves, and the
// controller keeps asking in the background.
func TestTheFileConfigurationIsServedUntilTheAPIAnswers(t *testing.T) {
	dir := t.TempDir()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "the api server is not ready", http.StatusServiceUnavailable)
	}))
	defer api.Close()
	path := ingressYAML(t, dir, api.URL)

	_, c, stop := running(t, path)

	// The routes from the file are the ones being served: the merge put an
	// empty snapshot over them and took nothing away.
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 1 {
		t.Errorf("generation %d", st.Generation)
	}

	// And the controller's own view says it is on, has asked, and has not
	// been answered -- which is what an operator needs to see to know the
	// configuration they are looking at is the file and not the cluster.
	b, err := c.Raw("/v1/ingress")
	if err != nil {
		t.Fatalf("ingress status: %v", err)
	}
	var got struct {
		Enabled   bool   `json:"enabled"`
		Class     string `json:"class"`
		Syncs     int    `json:"syncs"`
		Errors    int    `json:"errors"`
		LastError string `json:"last_error"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("ingress status: %s (%v)", b, err)
	}
	if !got.Enabled || got.Class != "xproxy" {
		t.Errorf("ingress status: %s", b)
	}
	if got.Syncs == 0 || got.Errors == 0 || got.LastError == "" {
		t.Errorf("the unanswered sync was not recorded: %s", b)
	}
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "initial ingress sync failed") {
		t.Errorf("the unanswered sync is not in the error log:\n%s", errs)
	}
}

// TestAnIngressControllerThatCannotBeBuiltIsAFailedStart: in controller
// mode the cluster's resources are part of the running configuration, so a
// controller that could not be built is a daemon that would serve a
// configuration nobody asked for. The token file is the example that
// happens: a service account token that was never mounted.
func TestAnIngressControllerThatCannotBeBuiltIsAFailedStart(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
sandbox: {enabled: false}
management: {socket: `+filepath.Join(dir, "m.sock")+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
ingress:
  enabled: true
  api_server: "https://127.0.0.1:6443"
  token_file: `+filepath.Join(dir, "token-that-was-never-mounted")+`
  cert_dir: `+filepath.Join(dir, "ingress")+`
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	if code := run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "ingress controller failed") {
		t.Errorf("the failure is not in the error log:\n%s", errs)
	}
}

// TestAReloadThatLoadsButCannotBeAppliedKeepsTheOldOne: a file that parses
// and validates can still be a file the running process cannot take -- an
// address on an interface this host does not have is the plain case -- and
// the generation that is already serving traffic has to survive it.
func TestAReloadThatLoadsButCannotBeAppliedKeepsTheOldOne(t *testing.T) {
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	_, c, stop := running(t, path)

	// An address this host cannot bind: the file is valid, and the bind is
	// where it fails, which is after the reload has begun.
	if err := os.WriteFile(path, []byte(`
version: 1
server:
  listeners: [{name: main, address: "10.255.255.1:9999"}]
  shutdown_timeout: 2s
sandbox: {enabled: false}
management:
  socket: `+filepath.Join(dir, "m.sock")+`
  history_dir: `+filepath.Join(dir, "history")+`
logging:
  directory: `+filepath.Join(dir, "logs")+`
  access: {enabled: false}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Post("/v1/reload"); err == nil {
		t.Error("a reload that cannot bind was reported as applied")
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 1 {
		t.Errorf("a failed reload moved the generation to %d", st.Generation)
	}
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "reload failed") {
		t.Errorf("the failure is not in the error log:\n%s", errs)
	}
}

// TestARollbackToAGenerationThatIsNotThereIsRefused: the identifier is
// operator input, typed from a listing that may be out of date, and a
// rollback to one that is not there has to be a refusal that names it
// rather than an apply of whatever was nearest.
func TestARollbackToAGenerationThatIsNotThereIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	_, c, stop := running(t, path)

	if err := c.Post("/v1/rollback?id=xproxy-gen99"); err == nil {
		t.Error("a rollback to a generation that is not recorded was accepted")
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 1 {
		t.Errorf("a refused rollback moved the generation to %d", st.Generation)
	}
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "rollback rejected") {
		t.Errorf("the refusal is not in the error log:\n%s", errs)
	}
}

// TestAHistoryThatCannotBeWrittenDoesNotFailTheReload: the history is for
// looking back at and rolling back to, and neither is worth refusing a
// configuration an operator has asked for. A directory that has gone away
// under the running process is a warning and the reload stands.
func TestAHistoryThatCannotBeWrittenDoesNotFailTheReload(t *testing.T) {
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	_, c, stop := running(t, path)

	if err := os.RemoveAll(filepath.Join(dir, "history")); err != nil {
		t.Fatal(err)
	}
	daemonYAML(t, dir, `, request_headers: {set: {X-Gen: "2"}}`)
	if err := c.Post("/v1/reload"); err != nil {
		t.Errorf("a history write failure refused the reload: %v", err)
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 2 {
		t.Errorf("the reload did not take: generation %d", st.Generation)
	}
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "configuration history write failed") {
		t.Errorf("the warning is not in the error log:\n%s", errs)
	}
}
