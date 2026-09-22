package daemon

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/http" // the kind the edge daemon serves
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/sandbox"
	"github.com/rom/xproxy/internal/testutil"
)

// A whole daemon, started and stopped the way a service manager does
// it. Everything between loading the file and the last log line is one
// function, and until it is driven end to end the parts of it that only
// run on a signal or through the management socket — the reload, the
// history, the rollback, the shutdown ordering — are not exercised at
// all by the pieces tested separately.

// daemonYAML is the smallest configuration with the things Run wires up
// that are worth watching: a management socket to ask through, a
// history directory to roll back from, and the sandbox off, because
// applying Landlock and seccomp to the test binary would confine the
// test.
func daemonYAML(t *testing.T, dir, body string) string {
	t.Helper()
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  shutdown_timeout: 2s
sandbox: {enabled: false}
management:
  socket: ` + filepath.Join(dir, "m.sock") + `
  history_dir: ` + filepath.Join(dir, "history") + `
logging:
  directory: ` + filepath.Join(dir, "logs") + `
  access: {enabled: false}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u` + body + `}
`
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// running starts a daemon and returns its signal channel, a management
// client and a function that stops it and reports the exit code.
func running(t *testing.T, path string) (chan<- os.Signal, *mgmt.Client, func() int) {
	t.Helper()
	sigs := make(chan os.Signal, 4)
	ready := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		// -allow-root because a test runs as whatever it was started
		// as, and a container test often runs as uid 0; the refusal
		// itself is TestRunRefusesRoot.
		done <- run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, sigs, func() { close(ready) })
	}()
	select {
	case <-ready:
	case code := <-done:
		t.Fatalf("the daemon exited with %d before it was ready", code)
	case <-time.After(20 * time.Second):
		t.Fatal("the daemon never became ready")
	}
	dir := filepath.Dir(path)
	t.Cleanup(func() {
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(dir, "logs", "error.log"))
			t.Logf("error log:\n%s", b)
		}
	})
	stopped := false
	stop := func() int {
		if stopped {
			return 0
		}
		stopped = true
		sigs <- syscall.SIGTERM
		select {
		case code := <-done:
			return code
		case <-time.After(30 * time.Second):
			t.Fatal("the daemon never stopped")
			return -1
		}
	}
	t.Cleanup(func() { stop() })
	return sigs, mgmt.NewClient(filepath.Join(dir, "m.sock")), stop
}

// TestRunStartsReloadsAndStops is the daemon's life: it becomes ready,
// answers the management socket, reopens its logs and reloads on a
// signal, and leaves on SIGTERM with status 0.
func TestRunStartsReloadsAndStops(t *testing.T) {
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	sigs, c, stop := running(t, path)

	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 1 {
		t.Errorf("generation %d at start", st.Generation)
	}
	// The sandbox status is the daemon's, set after everything is open.
	var sb struct {
		Enabled bool `json:"enabled"`
	}
	if b, err := c.Raw("/v1/sandbox"); err != nil {
		t.Errorf("sandbox: %v", err)
	} else if err := json.Unmarshal(b, &sb); err != nil || sb.Enabled {
		t.Errorf("sandbox: %s (%v)", b, err)
	}
	// The start is recorded, so there is something to roll back to.
	var entries []config.Entry
	if b, err := c.Raw("/v1/history"); err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(b, &entries); err != nil || len(entries) != 1 {
		t.Fatalf("history: %s (%v)", b, err)
	}

	// SIGUSR1 reopens the logs; the files are still written afterwards.
	sigs <- syscall.SIGUSR1
	// SIGHUP re-reads the file. The route gains a header operation, so
	// the change is visible in the running configuration rather than
	// only in the counter.
	daemonYAML(t, dir, `, request_headers: {set: {X-Reloaded: "1"}}`)
	sigs <- syscall.SIGHUP
	deadline := time.Now().Add(20 * time.Second)
	for {
		st, err = c.Status()
		if err == nil && st.Generation == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the reload never took effect: %+v (%v)", st, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Stats.Reloads != 1 || st.Stats.ReloadFailures != 0 {
		t.Errorf("reloads %d, failures %d", st.Stats.Reloads, st.Stats.ReloadFailures)
	}
	if b, err := c.Raw("/v1/config"); err != nil {
		t.Error(err)
	} else if !strings.Contains(string(b), "X-Reloaded") {
		t.Error("the running configuration is not the reloaded one")
	}

	// Roll back to the generation recorded at start: the header goes.
	if b, err := c.Raw("/v1/history"); err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(b, &entries); err != nil || len(entries) < 2 {
		t.Fatalf("history after the reload: %s (%v)", b, err)
	}
	oldest := entries[len(entries)-1]
	if err := c.Do("POST", "/v1/rollback?id="+oldest.ID, nil, nil); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if b, err := c.Raw("/v1/config"); err != nil {
		t.Error(err)
	} else if strings.Contains(string(b), "X-Reloaded") {
		t.Error("the rollback did not take")
	}

	// A diff of the running configuration against the file on disk
	// reports the difference the rollback just created.
	if b, err := c.Raw("/v1/diff?from=active&to=file"); err != nil {
		t.Error(err)
	} else if !strings.Contains(string(b), "X-Reloaded") {
		t.Errorf("diff: %s", b)
	}

	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	// The socket is gone: a second daemon may take the path.
	if _, err := os.Stat(filepath.Join(dir, "m.sock")); err == nil {
		t.Error("the management socket outlived the daemon")
	}
}

// TestRunRejectsABadReload: a file that no longer loads leaves the
// running generation alone and counts the failure. The daemon does not
// stop, because the configuration it is serving is still good.
func TestRunRejectsABadReload(t *testing.T) {
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	sigs, c, stop := running(t, path)

	if err := os.WriteFile(path, []byte("version: 1\nserver: {listeners: [}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Through the socket, because that is where the caller is told why:
	// a file that will not parse is refused before the running
	// generation is touched at all.
	err := c.Post("/v1/reload")
	if err == nil {
		t.Fatal("a file that does not parse was accepted")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("reload error: %v", err)
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 1 {
		t.Errorf("a refused reload moved the generation to %d", st.Generation)
	}
	// The same on a signal, where nobody is listening for an answer: it
	// is said in the log and the daemon keeps serving.
	sigs <- syscall.SIGHUP
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	logs, rerr := os.ReadFile(filepath.Join(dir, "logs", "error.log"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(logs), "reload rejected") {
		t.Error("the refusal is not in the error log")
	}
}

// TestRunRefusesAManagementSocketItCannotBind: the failure paths after
// the listeners are open have to take the server down with them, or the
// process stays alive serving traffic with no way to control it.
func TestRunRefusesAManagementSocketItCannotBind(t *testing.T) {
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	// A directory where the socket should go: binding it fails, and
	// nothing may delete it.
	sock := filepath.Join(dir, "m.sock")
	if err := os.Mkdir(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	if code := run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d", code)
	}
	if fi, err := os.Stat(sock); err != nil || !fi.IsDir() {
		t.Error("the directory at the socket path was removed")
	}
}

// TestRunRefusesAConfigurationItCannotServe: a listener kind this
// binary did not link is refused at start rather than bound as
// something else, and the daemon exits non-zero instead of running with
// a port answering nothing.
func TestRunRefusesAConfigurationItCannotServe(t *testing.T) {
	dir := t.TempDir()
	yaml := `
version: 1
server:
  listeners: [{name: bastion, address: "127.0.0.1:0", kind: ssh, ssh: {upstream: u, host_keys: [/dev/null], authorized_keys: /dev/null, upstream_key_file: /dev/null, upstream_known_hosts: /dev/null}}]
sandbox: {enabled: false}
logging: {directory: ` + filepath.Join(dir, "logs") + `, access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gate.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	// The gate daemon serves it; the edge daemon leaves it to a sibling
	// and has nothing left to bind.
	if code := run(listener.RoleGate, []string{"-config", path, "-validate"}, nil, nil); code != 0 {
		t.Errorf("the gate refused a configuration it serves: %d", code)
	}
	if code := run(listener.RoleEdge, []string{"-config", path, "-validate"}, nil, nil); code != 0 {
		t.Errorf("the edge daemon refused to validate a sibling's listener: %d", code)
	}
}

// TestRunFlagErrors: the exits that happen before anything is opened.
func TestRunFlagErrors(t *testing.T) {
	if code := Run(listener.RoleEdge, []string{"-nonsense"}); code != 2 {
		t.Errorf("an unknown flag: %d", code)
	}
	if code := Run(listener.RoleEdge, []string{"-config", filepath.Join(t.TempDir(), "absent.yaml")}); code != 1 {
		t.Errorf("a missing file: %d", code)
	}
}

// TestRunRefusesRoot: the shipped unit runs as its own user with socket
// activation for the privileged ports, so root is a mistake rather than
// a requirement, and a warning nobody reads is not a control.
func TestRunRefusesRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("not running as root")
	}
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	if code := run(listener.RoleEdge, []string{"-config", path}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("a daemon started as root without -allow-root: %d", code)
	}
}

// TestSignalsAreTheOnesTheUnitSends keeps the handler and the shipped
// systemd unit in step: the unit's ReloadSignal and KillSignal have to
// be signals Run acts on, or a reload silently kills the daemon.
func TestSignalsAreTheOnesTheUnitSends(t *testing.T) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)
	unit, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "xproxy.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ReloadSignal=SIGHUP", "KillSignal=SIGTERM"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("the unit does not set %s", want)
		}
	}
}

// TestNodeStatusSummarisesTheNode is what a fleet controller sees of a
// daemon: the counters, how much of the estate is healthy, when the
// first certificate expires, and whether the sandbox is on. A
// controller that cannot tell a healthy node from a sick one is worse
// than no controller.
func TestNodeStatusSummarisesTheNode(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "fleet.test")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer up.Close()
	s := proxytest.Start(t, `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
      tls: {certificates: [{cert_file: `+cert+`, key_file: `+key+`}]}
logging: {access: {enabled: false}}
upstreams:
  - name: live
    endpoints: [{address: "`+strings.TrimPrefix(up.URL, "http://")+`"}]
  - name: dead
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: live}
`)
	st := nodeStatus(s, &sandbox.Status{Enabled: true})
	if st.Version == "" || st.Generation != 1 {
		t.Errorf("%+v", st)
	}
	if st.UpstreamsTotal != 2 || st.EndpointsTotal != 2 {
		t.Errorf("upstreams %d, endpoints %d", st.UpstreamsTotal, st.EndpointsTotal)
	}
	// Endpoints start healthy until a probe says otherwise, so what is
	// pinned here is that the count is the endpoints and not the pools.
	if st.EndpointsHealthy > st.EndpointsTotal || st.UpstreamsHealthy > st.UpstreamsTotal {
		t.Errorf("more healthy than there are: %+v", st)
	}
	if st.CertExpiry.IsZero() || !st.CertExpiry.After(time.Now()) {
		t.Errorf("certificate expiry %v", st.CertExpiry)
	}
	if st.Sandbox != "enabled" {
		t.Errorf("sandbox %q", st.Sandbox)
	}
	if got := nodeStatus(s, &sandbox.Status{}); got.Sandbox != "disabled" {
		t.Errorf("sandbox %q with the sandbox off", got.Sandbox)
	}
	// No status at all is not "disabled": it is a node that has not got
	// there yet, and saying disabled would be a false all-clear.
	if got := nodeStatus(s, nil); got.Sandbox != "" {
		t.Errorf("sandbox %q without a status", got.Sandbox)
	}
}

// TestSdNotifyReachesTheServiceManager: Type=notify-reload in the
// shipped unit means systemd waits for these. A daemon that does not
// send them is a service that never reports ready and a reload that
// times out.
func TestSdNotifyReachesTheServiceManager(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "notify.sock")
	pc, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Skipf("unixgram: %v", err)
	}
	defer pc.Close()
	t.Setenv("NOTIFY_SOCKET", sock)

	got := make(chan string, 8)
	go func() {
		buf := make([]byte, 256)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n])
		}
	}()

	path := daemonYAML(t, dir, "")
	sigs, _, stop := running(t, path)
	if msg := <-got; msg != "READY=1" {
		t.Errorf("first notification %q", msg)
	}
	sigs <- syscall.SIGHUP
	// RELOADING carries the monotonic time stamp Type=notify-reload
	// needs; without it systemd ignores the notification.
	msg := <-got
	if !strings.HasPrefix(msg, "RELOADING=1\nMONOTONIC_USEC=") {
		t.Errorf("reload notification %q", msg)
	}
	if usec := strings.TrimPrefix(msg, "RELOADING=1\nMONOTONIC_USEC="); usec == "0" || usec == "" {
		t.Errorf("monotonic stamp %q", usec)
	}
	if msg := <-got; msg != "READY=1" {
		t.Errorf("after the reload %q", msg)
	}
	stop()
	if msg := <-got; msg != "STOPPING=1" {
		t.Errorf("shutdown notification %q", msg)
	}
	// A socket that is not there is not an error: a daemon started by
	// hand has no service manager and must not fail because of it.
	t.Setenv("NOTIFY_SOCKET", filepath.Join(dir, "absent.sock"))
	sdNotify("READY=1")
}

// TestRunRefusesABrokenExporter: everything built after the listeners
// are open has to take the server down with it on failure, or the
// process is left serving traffic in a state the operator asked not to
// have.
func TestRunRefusesABrokenExporter(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "not-a-ca.pem")
	if err := os.WriteFile(ca, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := daemonYAML(t, dir, "")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(body) + "metrics:\n  otlp: {endpoint: \"https://127.0.0.1:1/v1/metrics\", ca_file: " + ca + "}\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d", code)
	}
	// The management socket it opened on the way is gone again.
	if _, err := os.Stat(filepath.Join(dir, "m.sock")); err == nil {
		t.Error("the management socket outlived the failed start")
	}
}
