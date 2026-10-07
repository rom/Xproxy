package forward

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
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

// alert_on_deny on the listener the setting is most for.
//
// An egress proxy refuses all day: a browser reaches for a destination the policy
// does not carry and that is an ordinary afternoon, not a finding. So an estate may
// want the refusals counted, answered and banned without a security event for each
// of them -- and until this round it had no way to say so on this kind, because the
// setting the other kinds carry was not here.
//
// What the setting must not touch is the refusal itself. These assert both halves:
// the record goes quiet, and the client is still turned away, still counted, still
// put in front of the ban ladder.

const egressAlertYAML = `
version: 1
server:
  listeners:
    - name: out
      address: "127.0.0.1:0"
      kind: forward
      forward:
        allow_private: true
        deny: ["*.denied.test"]
%s
bans:
  triggers:
    - {name: egress, reasons: [forward_denied], threshold: 1, window: 1m, duration: 1m}
logging:
  directory: %s
  security: {enabled: true, file: security.log}
upstreams:
  - {name: unused, endpoints: [{address: 127.0.0.1:1}]}
`

// egressProxy is a forward listener whose security log goes to a file, which
// proxytest.Start cannot give: it builds the server with logging.Discard.
func egressProxy(t *testing.T, extra string) (*proxy.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(egressAlertYAML, extra, dir)))
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
	return s, proxytest.Addr(t, s, "out"), dir
}

// reachForADeniedDestination asks the proxy for a destination its policy refuses
// and returns the status it answered with.
func reachForADeniedDestination(t *testing.T, proxyAddr string) int {
	t.Helper()
	c := forwardClient(t, proxyAddr, nil, "", "")
	resp, err := c.Get("http://blocked.denied.test/secrets")
	if err != nil {
		t.Fatalf("the proxy did not answer: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestTheEgressRefusalIsRecordedByDefault(t *testing.T) {
	_, addr, dir := egressProxy(t, "")
	if got := reachForADeniedDestination(t, addr); got != http.StatusForbidden {
		t.Fatalf("status %d, want 403", got)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join(dir, "security.log"))
		if err == nil && strings.Contains(string(b), `"action":"deny"`) {
			if !strings.Contains(string(b), "blocked.denied.test") {
				t.Errorf("the record does not name the destination:\n%s", b)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no refusal was recorded: %v\n%s", err, b)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestAlertOnDenyOffKeepsTheRefusalAndTheBan(t *testing.T) {
	s, addr, dir := egressProxy(t, "        alert_on_deny: false")
	if got := reachForADeniedDestination(t, addr); got != http.StatusForbidden {
		t.Fatalf("status %d, want 403: the setting silences the record, not the refusal", got)
	}
	// The ban observation sits in front of the gate, so waiting for the ban is
	// waiting for the point the record would have been written at.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if bl := s.Bans(); bl != nil && bl.Banned(netip.MustParseAddr("127.0.0.1")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refusal never reached the ban ladder")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if n := s.Stats().ForwardDenied; n != 1 {
		t.Errorf("forward_denied %d, want 1", n)
	}
	b, err := os.ReadFile(filepath.Join(dir, "security.log"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"action":"deny"`) {
		t.Errorf("alert_on_deny: false still recorded the refusal:\n%s", b)
	}
}
