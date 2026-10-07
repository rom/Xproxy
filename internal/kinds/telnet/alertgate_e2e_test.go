package telnet_test

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
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// What one refusal writes, and what alert_on_deny reaches.
//
// A refused factor used to be recorded twice: once through the kind's deny funnel,
// which is gated and observed by the ban ladder, and once from the failure site
// itself, which was neither. So the listener wrote two events for one refusal, and
// an operator who turned alert_on_deny off still got the second of them -- from a
// path nobody had written down.
//
// telnet stands for the four gate kinds that shared the shape: the same duplicate
// sat in ftp, vnc and rdp, and the sweep in test/observability holds all four.

const alertYAML = `
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        upstream: kit
        mfa: {file: %s}
%s
logging:
  directory: %s
  security: {enabled: true, file: security.log}
upstreams:
  - {name: kit, endpoints: [{address: %q}]}
`

// alertGateway is a telnet listener whose security log goes to a file, because
// proxytest.Start discards the streams and these tests are about what is in them.
func alertGateway(t *testing.T, mfaFile, extra string) (*proxy.Server, string, string) {
	t.Helper()
	tg := startTarget(t)
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(alertYAML, mfaFile, extra, dir, tg.addr())))
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
	return s, proxytest.Addr(t, s, "legacy"), dir
}

// refuseAFactor offers a name and the wrong code, and waits for the listener to
// have counted the refusal -- which is the point after which the records for it
// have been written.
func refuseAFactor(t *testing.T, s *proxy.Server, addr string) {
	t.Helper()
	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	c.readUntil("code: ")
	c.write([]byte("000000\r\n"))
	c.readUntil("not accepted")
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().TelnetMFAFailed == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the refused factor was never counted")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// securityLog waits for the stream to hold want and returns all of it.
func securityLog(t *testing.T, dir, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join(dir, "security.log"))
		if err == nil && strings.Contains(string(b), want) {
			return string(b)
		}
		if time.Now().After(deadline) {
			t.Fatalf("security.log never held %q: %v\n%s", want, err, b)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestARefusedFactorIsRecordedOnce(t *testing.T) {
	file, _ := enrol(t, "alice")
	s, addr, dir := alertGateway(t, file, "")
	refuseAFactor(t, s, addr)

	out := securityLog(t, dir, "telnet_mfa_failed")
	if n := strings.Count(out, "telnet_mfa_failed"); n != 1 {
		t.Errorf("%d records for one refused factor, want 1:\n%s", n, out)
	}
	// The fields the duplicate carried have to survive on the record that
	// stayed, or removing it would have cost the log the name it was about.
	for _, want := range []string{`"action":"deny"`, `"user":"alice"`, `"reason":`} {
		if !strings.Contains(out, want) {
			t.Errorf("the record does not carry %s:\n%s", want, out)
		}
	}
}

func TestAlertOnDenyOffSilencesTheRefusedFactor(t *testing.T) {
	file, _ := enrol(t, "alice")
	s, addr, dir := alertGateway(t, file, "        alert_on_deny: false")
	refuseAFactor(t, s, addr)

	// Settle: the records are written from the session's own goroutine, so
	// reading the instant the counter rises would pass whether or not one was
	// on its way.
	time.Sleep(150 * time.Millisecond)
	b, err := os.ReadFile(filepath.Join(dir, "security.log"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "telnet_mfa_failed") || strings.Contains(string(b), `"action":"deny"`) {
		t.Errorf("alert_on_deny: false still recorded the refusal:\n%s", b)
	}
	// The refusal itself is untouched: the client was turned away and counted.
	if n := s.Stats().TelnetMFAFailed; n != 1 {
		t.Errorf("telnet_mfa_failed %d, want 1", n)
	}
}
