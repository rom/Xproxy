package mysql

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The two records this relay keeps, and the settings that decide them.
//
// Until this round the kind wrote no access line at all: the only record of a
// session was of what was refused, which answers "what did we stop" and not "what
// did they run" -- on the kind whose whole job is deciding what may run. And the
// security event could not be turned off, on a listener where refusals may be
// routine.

const auditYAML = `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: mysql
      mysql:
%s
logging:
  directory: %s
  access: {enabled: true, file: access.log}
  security: {enabled: true, file: security.log}
upstreams:
  - {name: my, endpoints: [{address: %q}]}
`

// auditRelay is a listener whose two log streams go to files a test can read.
//
// Built here rather than through proxytest.Start, which discards the logs: these
// tests are about what is written, so the streams have to be real.
func auditRelay(t *testing.T, section, serverAddr string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(auditYAML, section, dir, serverAddr)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	s, err := proxy.New(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		logs.Close()
	})
	return proxytest.Addr(t, s, "db"), dir
}

// logLines waits for the named stream to hold a line matching want, and returns
// everything it held. The streams are written from the connection's own goroutine
// and flushed by the logger, so reading the instant a client call returns races
// the proxy rather than testing it.
func logLines(t *testing.T, dir, name, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil && (want == "" || strings.Contains(string(b), want)) {
			return string(b)
		}
		if time.Now().After(deadline) {
			if err != nil {
				entries, _ := os.ReadDir(dir)
				var have []string
				for _, e := range entries {
					have = append(have, e.Name())
				}
				t.Fatalf("%s: %v (the directory holds: %v)", name, err, have)
			}
			t.Fatalf("%s never held %q:\n%s", name, want, b)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// quiet is what a stream holds after a settling pause, for asserting a negative.
func quiet(t *testing.T, dir, name string) string {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// log_requests off is the default, and a forwarded statement leaves no line.
// A refusal leaves one either way: it is rare, and it is the one line nobody
// would choose to lose.
func TestWithoutLogRequestsOnlyTheRefusalIsLogged(t *testing.T) {
	srv := startFake(t, &fakeServer{})
	addr, dir := auditRelay(t, base+"        deny_statements: [ddl]\n", srv.addr())
	cl := dial(t, addr, "report", "sales", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("login refused: %s", msg)
	}
	if msg := cl.send(t, wire.ComQuery, "SELECT total FROM invoices"); msg != "" {
		t.Fatalf("the query was refused: %s", msg)
	}
	if msg := cl.send(t, wire.ComQuery, "DROP TABLE invoices"); msg == "" {
		t.Fatal("the DROP was forwarded")
	}
	out := logLines(t, dir, "access.log", `"action":"deny"`)
	if strings.Contains(out, `"action":"allow"`) {
		t.Errorf("a forwarded statement was logged with log_requests off:\n%s", out)
	}
	// The kind, never the text: the line says a drop was refused and does not
	// repeat the statement.
	if strings.Contains(out, "invoices") {
		t.Errorf("the access line carries the statement text:\n%s", out)
	}
}

// With it on, every statement the relay forwards leaves a line -- the audit trail
// a DBA is asked for -- carrying the kind and never the text.
func TestLogRequestsRecordsWhatWasForwarded(t *testing.T) {
	srv := startFake(t, &fakeServer{})
	addr, dir := auditRelay(t, base+"        log_requests: true\n", srv.addr())
	cl := dial(t, addr, "report", "sales", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("login refused: %s", msg)
	}
	if msg := cl.send(t, wire.ComQuery, "SELECT total FROM invoices"); msg != "" {
		t.Fatalf("the query was refused: %s", msg)
	}
	out := logLines(t, dir, "access.log", `"action":"allow"`)
	for _, want := range []string{`"proto":"mysql"`, `"db_user":"report"`, `"database":"sales"`, `"what":"select"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the access line does not carry %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "invoices") {
		t.Errorf("the access line carries the statement text:\n%s", out)
	}
}

// alert_on_deny off loses the security event and keeps everything else. The
// counters are the proof that the refusal still happened, and the access line is
// the proof that the record an audit wants is still written.
func TestAlertOnDenyOffKeepsTheRefusalAndTheAccessLine(t *testing.T) {
	srv := startFake(t, &fakeServer{})
	section := base + "        deny_statements: [ddl]\n        alert_on_deny: false\n"
	addr, dir := auditRelay(t, section, srv.addr())
	cl := dial(t, addr, "report", "sales", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("login refused: %s", msg)
	}
	if msg := cl.send(t, wire.ComQuery, "DROP TABLE invoices"); msg == "" {
		t.Fatal("the DROP was forwarded")
	}
	// The access line is written, so the refusal reached the logging path at all.
	if out := logLines(t, dir, "access.log", `"action":"deny"`); out == "" {
		t.Fatal("no access line")
	}
	// The deny-class event is gone. The alert-class ones are not: alert_on_deny is
	// named for refusals, and a capability strip is not one -- nothing was
	// refused and the connection went through. The mms kind makes the same
	// distinction with a second setting of its own for its own alert.
	out := quiet(t, dir, "security.log")
	if strings.Contains(out, `"action":"deny"`) {
		t.Errorf("alert_on_deny: false still wrote a deny event:\n%s", out)
	}
	if !strings.Contains(out, `"action":"alert"`) {
		t.Errorf("alert_on_deny: false silenced an alert that is not a refusal:\n%s", out)
	}
}

// And with it on -- the default -- the event is there, which is what makes the
// test above an assertion about the setting rather than about the harness.
func TestAlertOnDenyOnWritesTheSecurityEvent(t *testing.T) {
	srv := startFake(t, &fakeServer{})
	addr, dir := auditRelay(t, base+"        deny_statements: [ddl]\n", srv.addr())
	cl := dial(t, addr, "report", "sales", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("login refused: %s", msg)
	}
	if msg := cl.send(t, wire.ComQuery, "DROP TABLE invoices"); msg == "" {
		t.Fatal("the DROP was forwarded")
	}
	logLines(t, dir, "security.log", `"action":"deny"`)
}
