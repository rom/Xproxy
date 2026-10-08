package pop3

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxytest"
)

// What a refused mail client leaves behind.
//
// A POP3 password is the only credential this protocol has and there is
// nothing else to guess, so a run of refusals from one address is the
// clearest signal this kind produces -- and the ban ladder is what acts
// on it. The access lines are turned off here on purpose: an estate that
// does not want a line per command still wants the refusal and the ban,
// because turning the logging down is not a decision to stop responding.
func TestARefusedClientReachesTheBanLadder(t *testing.T) {
	const yaml = `
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: pop3
      pop3:
        upstream: servers
        require_tls: false
        rate_limit: 1000
        log_commands: false
        log_retrievals: false
        commands: [USER, PASS, QUIT, STAT, RETR]
bans:
  triggers:
    - {name: mail, reasons: [pop3_denied], threshold: 2, window: 1m, duration: 10m}
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`
	srv := startServer(t, &fakeServer{})
	s := proxytest.Start(t, fmt.Sprintf(yaml, srv.addr()))
	addr := proxytest.Addr(t, s, "mail")

	// Two sessions, each asking for a command the policy does not carry.
	for i := 0; i < 2; i++ {
		c := dial(t, addr)
		c.login()
		c.send("LIST")
		if l := c.line(); !strings.HasPrefix(l, "-ERR") {
			t.Fatalf("LIST was not refused: %q", l)
		}
	}
	if got := s.Stats().Refusals["pop3"]; len(got) == 0 {
		t.Fatalf("no refusal was counted, so this test asserts nothing")
	}
	ip := netip.MustParseAddr("127.0.0.1")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !s.Bans().Banned(ip) {
		time.Sleep(10 * time.Millisecond)
	}
	if !s.Bans().Banned(ip) {
		t.Error("two refusals past the threshold left the client unbanned")
	}
}

// A password the server refuses is counted and handed to the ban ladder
// under its own reason, which is what lets an estate ban a guesser
// without banning everything else a refusal could be.
func TestARefusedPasswordIsCountedAndObserved(t *testing.T) {
	const yaml = `
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: pop3
      pop3:
        upstream: servers
        require_tls: false
bans:
  triggers:
    - {name: guessing, reasons: [pop3_auth_failed], threshold: 2, window: 1m, duration: 10m}
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`
	srv := startServer(t, &fakeServer{fail: map[string]bool{"PASS": true}})
	s := proxytest.Start(t, fmt.Sprintf(yaml, srv.addr()))
	addr := proxytest.Addr(t, s, "mail")

	for i := 0; i < 2; i++ {
		c := dial(t, addr)
		c.line() // the greeting
		c.send("USER bob")
		if l := c.line(); !strings.HasPrefix(l, "+OK") {
			t.Fatalf("USER: %q", l)
		}
		c.send("PASS wrong")
		if l := c.line(); !strings.HasPrefix(l, "-ERR") {
			t.Fatalf("PASS was accepted: %q", l)
		}
	}
	if got := s.Stats().POP3AuthFailures; got < 2 {
		t.Errorf("auth failures = %d, want at least 2", got)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !s.Bans().Banned(ip) {
		time.Sleep(10 * time.Millisecond)
	}
	if !s.Bans().Banned(ip) {
		t.Error("two refused passwords left the client unbanned")
	}
}
