package daemon

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/testutil"
)

// The rest of a daemon's start: the branches that only happen when
// something about the deployment is unusual -- advice worth saying out loud,
// a history directory that cannot be written, an address already taken, a
// listener kind this binary does not serve -- and the management actions that
// read a configuration without applying it.
//
// These are the parts a reader of the code would most like to believe work,
// because each of them is a decision taken once at start and never again:
// either the daemon refused for the right reason or it is running with less
// than the operator asked for.

// write puts a configuration where a daemon will read it and makes the log
// directory it names.
func write(t *testing.T, dir, name, yaml string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// logFile is one of the daemon's streams, read back.
func logFile(t *testing.T, dir, stream string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "logs", stream+".log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// held takes a loopback port and keeps it, so a configuration naming it
// cannot bind. The address comes back with the port in it.
func held(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// TestTheAdviceIsSaidAtEveryStartAndNotOnlyByValidate: a configuration that
// loads but weakens the deployment is the one an operator most needs told,
// and the validate command is run once while the daemon starts every day.
// Shadow mode is the example that matters: a policy that refuses nothing
// looks exactly like a policy that is working.
func TestTheAdviceIsSaidAtEveryStartAndNotOnlyByValidate(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  shutdown_timeout: 2s
sandbox: {enabled: false}
policy: {mode: shadow}
management: {socket: `+filepath.Join(dir, "m.sock")+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	_, _, stop := running(t, path)
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	sec := logFile(t, dir, "security")
	if !strings.Contains(sec, "configuration advice") {
		t.Errorf("the advice is not in the security log:\n%s", sec)
	}
	if !strings.Contains(sec, "shadow") {
		t.Errorf("the advice does not say what it is about:\n%s", sec)
	}
}

// TestWithoutAHistoryTheDaemonServesAndSaysSo: history is a convenience, so
// a directory that cannot be written is a warning rather than a failed start
// -- but then every action built on it has to answer honestly instead of
// looking like an empty history, which is the difference between "there is
// nothing to roll back to" and "rolling back is not available here".
func TestWithoutAHistoryTheDaemonServesAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	// A file where the directory should be: creating it cannot succeed.
	blocked := filepath.Join(dir, "history")
	if err := os.WriteFile(blocked, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  shutdown_timeout: 2s
sandbox: {enabled: false}
management: {socket: `+filepath.Join(dir, "m.sock")+`, history_dir: `+blocked+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	sigs, c, stop := running(t, path)

	if _, err := c.Raw("/v1/history"); err == nil {
		t.Error("a listing was answered without a history")
	}
	if err := c.Do("POST", "/v1/rollback?id=whatever", nil, nil); err == nil {
		t.Error("a rollback was accepted without a history")
	}
	// A diff naming a history entry cannot resolve it, and says which side it
	// could not read rather than failing without a name.
	if _, err := c.Raw("/v1/diff?from=20240101-000000&to=file"); err == nil {
		t.Error("a diff resolved a history entry without a history")
	} else if !strings.Contains(err.Error(), "20240101-000000") {
		t.Errorf("the diff error does not name the side it failed on: %v", err)
	}
	// The daemon is still serving: a reload works, it is simply not recorded.
	sigs <- syscall.SIGHUP
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "configuration history disabled") {
		t.Errorf("the warning is not in the error log:\n%s", errs)
	}
}

// TestADryRunReadsTheFileWithoutApplyingIt is what an operator runs before a
// reload: the generation does not move, and a file that would be refused is
// refused here rather than at the reload.
func TestADryRunReadsTheFileWithoutApplyingIt(t *testing.T) {
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	_, c, stop := running(t, path)

	// A changed file: the dry run reports the change and nothing applies it.
	daemonYAML(t, dir, `, request_headers: {set: {X-Dry: "1"}}`)
	var raw json.RawMessage
	if err := c.Do("POST", "/v1/reload?dry_run=1", nil, &raw); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	var ch config.Changes
	if err := json.Unmarshal(raw, &ch); err != nil {
		t.Fatalf("dry run: %s (%v)", raw, err)
	}
	if !strings.Contains(string(raw), "X-Dry") {
		t.Errorf("the dry run did not report the change: %s", raw)
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 1 {
		t.Errorf("a dry run moved the generation to %d", st.Generation)
	}

	// A file that does not load is refused by the dry run, which is the whole
	// point of having one.
	if err := os.WriteFile(path, []byte("version: 1\nserver: {listeners: [}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Do("POST", "/v1/reload?dry_run=1", nil, &raw); err == nil {
		t.Error("a dry run accepted a file that does not parse")
	}
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
}

// TestADiffNamesTheSideItCannotRead: `from` and `to` are operator input, and
// an error that does not say which of the two was wrong is an error that
// takes a second attempt to understand.
func TestADiffNamesTheSideItCannotRead(t *testing.T) {
	dir := t.TempDir()
	path := daemonYAML(t, dir, "")
	_, c, stop := running(t, path)

	for _, q := range []string{"from=nosuchthing&to=active", "from=active&to=nosuchthing"} {
		_, err := c.Raw("/v1/diff?" + q)
		if err == nil {
			t.Errorf("%s was answered", q)
			continue
		}
		if !strings.Contains(err.Error(), "nosuchthing") {
			t.Errorf("%s: the error does not name the side: %v", q, err)
		}
	}
	// The running configuration against itself is a diff with nothing in it,
	// which is the reading that says the two names resolve at all.
	if b, err := c.Raw("/v1/diff?from=active&to=active"); err != nil {
		t.Errorf("active against active: %v", err)
	} else if strings.Contains(string(b), "\"listeners\":[{") {
		t.Errorf("active against active reported changes: %s", b)
	}
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
}

// TestAnAddressAlreadyTakenIsAFailedStart: the bind happens after the
// configuration is built and before READY, so it has to be an exit rather
// than a daemon that reports ready with a port it never got.
func TestAnAddressAlreadyTakenIsAFailedStart(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "`+held(t)+`"}]
sandbox: {enabled: false}
management: {socket: `+filepath.Join(dir, "m.sock")+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	if code := run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "start failed") {
		t.Errorf("the failure is not in the error log:\n%s", errs)
	}
}

// TestAMetricsAddressAlreadyTakenIsAFailedStart: the metrics listener is
// built after the data plane is bound, so its failure has to take the server
// down with it -- otherwise the process is left serving traffic with the
// operator's own view of it missing.
func TestAMetricsAddressAlreadyTakenIsAFailedStart(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
sandbox: {enabled: false}
metrics: {listen: "`+held(t)+`"}
management: {socket: `+filepath.Join(dir, "m.sock")+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	if code := run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "metrics listener failed") {
		t.Errorf("the failure is not in the error log:\n%s", errs)
	}
	// And it took the management socket with it.
	if _, err := os.Stat(filepath.Join(dir, "m.sock")); err == nil {
		t.Error("the management socket outlived the failed start")
	}
}

// TestAKindThisBinaryDoesNotLinkIsRefusedAtStart: this test binary links the
// http kind and no other, so a gate listener is a configuration the daemon
// validates and then cannot build. The refusal belongs at start, because the
// alternative -- which this project had once -- is a port that answers as
// something else.
func TestAKindThisBinaryDoesNotLinkIsRefusedAtStart(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "gate.yaml", `
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh: {upstream: u, host_keys: [/dev/null], authorized_keys: /dev/null, upstream_key_file: /dev/null, upstream_known_hosts: /dev/null}
sandbox: {enabled: false}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	if code := run(listener.RoleGate, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d", code)
	}
	errs := logFile(t, dir, "error")
	if !strings.Contains(errs, "start failed") {
		t.Errorf("the refusal is not in the error log:\n%s", errs)
	}
	// Naming the daemon that does serve it is the difference between an
	// operator fixing the file and an operator deleting the listener.
	if !strings.Contains(errs, "served by xgate") {
		t.Errorf("the refusal does not say which daemon serves the kind:\n%s", errs)
	}
}

// TestTheListenersLeftToASiblingAreNamedInTheLog: one file describes the
// whole estate and each daemon binds its own share of it, so the share it did
// not take is the line an operator needs when a port nobody is serving looks
// like a configuration that was ignored.
func TestTheListenersLeftToASiblingAreNamedInTheLog(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "estate.yaml", `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh: {upstream: u, host_keys: [/dev/null], authorized_keys: /dev/null, upstream_key_file: /dev/null, upstream_known_hosts: /dev/null}
  shutdown_timeout: 2s
sandbox: {enabled: false}
management: {socket: `+filepath.Join(dir, "m.sock")+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	_, _, stop := running(t, path)
	if code := stop(); code != 0 {
		t.Errorf("exit code %d", code)
	}
	errs := logFile(t, dir, "error")
	if !strings.Contains(errs, "listeners left to a sibling daemon") {
		t.Errorf("the share it did not take is not in the log:\n%s", errs)
	}
	if !strings.Contains(errs, "bastion") {
		t.Errorf("the log does not name the listener it left:\n%s", errs)
	}
}

// TestValidateSaysHowMuchOfTheFileThisDaemonWouldBind is the other half of
// the same property, on the command an operator runs before a deployment:
// the count of listeners served here and the count left to a sibling, plus
// the advice, so a shared file can be checked from any of the three daemons.
func TestValidateSaysHowMuchOfTheFileThisDaemonWouldBind(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "estate.yaml", `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh: {upstream: u, host_keys: [/dev/null], authorized_keys: /dev/null, upstream_key_file: /dev/null, upstream_known_hosts: /dev/null}
sandbox: {enabled: false}
policy: {mode: shadow}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	out := capture(t, func() {
		if code := run(listener.RoleEdge, []string{"-config", path, "-validate"}, nil, nil); code != 0 {
			t.Errorf("validate: %d", code)
		}
	})
	for _, want := range []string{"OK (2 listeners", "1 served by xproxy", "1 left to a sibling", "warning:"} {
		if !strings.Contains(out, want) {
			t.Errorf("validate did not say %q:\n%s", want, out)
		}
	}
}

// capture reads what a function printed on standard output.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				done <- b.String()
				return
			}
		}
	}()
	fn()
	os.Stdout = saved
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestSdNotifyIgnoresASocketThatIsNotADatagramOne: the service manager's
// socket is whatever NOTIFY_SOCKET names, and a daemon started by hand with a
// stale environment must not fail for it.
func TestSdNotifyIgnoresASocketThatIsNotADatagramOne(t *testing.T) {
	dir := t.TempDir()
	// A stream socket, not a datagram one: the dial fails and is ignored.
	sock := filepath.Join(dir, "stream.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix: %v", err)
	}
	defer func() { _ = ln.Close() }()
	t.Setenv("NOTIFY_SOCKET", sock)
	sdNotify("READY=1")
	// A monotonic stamp is still available, because Type=notify-reload needs
	// one whatever the socket turned out to be.
	if monotonicUSec() == 0 {
		t.Error("no monotonic stamp")
	}
}

// TestRunPrintsItsVersionAndLeaves: the one path that answers before a
// configuration is read at all, which is what a packaging check runs.
func TestRunPrintsItsVersionAndLeaves(t *testing.T) {
	out := capture(t, func() {
		if code := Run(listener.RoleRelay, []string{"-version"}); code != 0 {
			t.Errorf("-version: %d", code)
		}
	})
	if !strings.HasPrefix(out, "xrelay ") {
		t.Errorf("-version printed %q", out)
	}
}

// The rest of the failed starts, which share one property worth stating once:
// each of these subsystems is opened after the configuration has loaded and
// before READY, so a failure in any of them must take the start down rather
// than leave a process serving traffic with less than the operator configured.
// A daemon that came up without its log streams, without its exporter or
// without its fleet agent would be a daemon whose operator believes they are
// there.

// TestLogsThatCannotBeOpenedAreAFailedStart: the streams are the first thing
// opened and the only place a later failure could be reported, so a daemon
// that could not open them has nowhere to say anything and must not start.
// Nothing is in the log here by definition -- the exit code is the whole
// assertion.
func TestLogsThatCannotBeOpenedAreAFailedStart(t *testing.T) {
	dir := t.TempDir()
	// A file where the directory should be: the open fails with ENOTDIR,
	// which is a path in the configuration naming the wrong thing.
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
sandbox: {enabled: false}
logging: {directory: `+filepath.Join(blocker, "logs")+`, access: {enabled: false}}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	if code := run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
}

// TestAnExporterThatCannotBeBuiltIsAFailedStart: the OTLP exporter is the
// operator's own view of the proxy leaving the host. A CA file that is not
// there means the exporter would have to either skip verification or send
// nothing, and both are worse than a start that stops and says so.
func TestAnExporterThatCannotBeBuiltIsAFailedStart(t *testing.T) {
	dir := t.TempDir()
	// A file that exists, so the configuration loads, and is not a
	// certificate, so building the exporter's trust store fails. The
	// distinction matters: a path that is simply absent is caught at load,
	// and this is the later failure, after the data plane is already bound.
	ca := filepath.Join(dir, "not-a-certificate.pem")
	if err := os.WriteFile(ca, []byte("this is not PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
sandbox: {enabled: false}
management: {socket: `+filepath.Join(dir, "m.sock")+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
metrics:
  otlp:
    endpoint: "https://127.0.0.1:4318/v1/metrics"
    ca_file: `+ca+`
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	if code := run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "otlp exporter failed") {
		t.Errorf("the failure is not in the error log:\n%s", errs)
	}
}

// TestAFleetAgentThatCannotBeBuiltIsAFailedStart: the agent is how a node is
// managed and how it reports what it is running. One that failed quietly would
// leave a node absent from the fleet's own view of itself, which is the view an
// operator uses to decide the estate is configured as they think.
//
// The arrangement here is a fleet.dir that is not the configuration file's own
// directory, which the agent refuses because a bundle written anywhere else is
// a bundle the daemon would never read back.
func TestAFleetAgentThatCannotBeBuiltIsAFailedStart(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "node-1")
	caFile := ca.WriteKey(t, dir)
	// A bundle directory that is not the configuration file's own: the
	// agent refuses it because a bundle written anywhere else is a bundle
	// this daemon would never read back. The directory exists, so the
	// configuration loads and the refusal is the agent's own.
	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	path := write(t, dir, "xproxy.yaml", `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
sandbox: {enabled: false}
management: {socket: `+filepath.Join(dir, "m.sock")+`}
logging: {directory: `+filepath.Join(dir, "logs")+`, access: {enabled: false}}
fleet:
  controller: "https://127.0.0.1:9443"
  node_id: node-1
  dir: `+elsewhere+`
  tls: {cert_file: `+cert+`, key_file: `+key+`, ca_file: `+caFile+`}
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
`)
	if code := run(listener.RoleEdge, []string{"-config", path, "-allow-root"}, make(chan os.Signal), nil); code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	if errs := logFile(t, dir, "error"); !strings.Contains(errs, "fleet agent failed") {
		t.Errorf("the failure is not in the error log:\n%s", errs)
	}
}
