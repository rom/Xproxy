package ftp_test

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// authzRelay is an FTP relay under the estate's authorisation policy.
func authzRelay(t *testing.T, policy string) (*proxy.Server, string, *targetFTP) {
	t.Helper()
	tg := startTargetFTP(t)
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:0"
      kind: ftp
      ftp:
        upstream: servers
logging: {access: {enabled: false}}
upstreams:
  - name: servers
    endpoints: [{address: %s}]
authorization:
%s
`, tg.addr(), policy))
	return s, s.Addrs()["files"], tg
}

// FTP dials the target before anybody has said who they are -- the greeting
// comes from the server -- so unlike the SSH and telnet gateways the policy
// cannot be asked before the target is reached. What it does instead is refuse
// the login: the session ends on a 530, the target has seen a login and nothing
// else, and no command of the person's is forwarded.
func TestAPolicyRefusesTheLogin(t *testing.T) {
	s, addr, tg := authzRelay(t, `  rules:
    - {name: restores, allow: true, users: [bob]}
`)
	c := dialFTP(t, addr)
	if code, _ := c.cmd("USER alice"); code != 331 {
		t.Fatalf("USER was %d", code)
	}
	code, text := c.cmd("PASS secret")
	if code != 530 {
		t.Fatalf("PASS was %d %q, want 530", code, text)
	}
	if !strings.Contains(text, "not authorised") {
		t.Errorf("the refusal did not say why: %q", text)
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "LIST") || strings.HasPrefix(seen, "RETR") || strings.HasPrefix(seen, "STOR") {
			t.Errorf("a command reached the target for somebody no rule covers: %s", seen)
		}
	}
	if n := s.Stats().Refusals["ftp"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["ftp"])
	}
}

// And for the person a rule does name, the login completes and files move.
func TestAPolicyAdmitsThePersonItNamesOnFTP(t *testing.T) {
	_, addr, tg := authzRelay(t, `  rules:
    - {name: restores, allow: true, users: [alice], targets: [servers], actions: [connect]}
`)

	c := dialFTP(t, addr)
	c.login("alice", "secret")
	dataAddr := c.passive()
	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dc.Close() }()
	if code, _ := c.cmd("RETR /pub/readme.txt"); code != 150 {
		t.Fatalf("RETR was %d", code)
	}
	body, err := io.ReadAll(dc)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != tg.content {
		t.Errorf("got %q, want %q", body, tg.content)
	}
}
