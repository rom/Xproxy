package ftp_test

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// grantBastion is an FTP relay that admits nothing without a live grant.
func grantBastion(t *testing.T) (*proxy.Server, string, *targetFTP) {
	t.Helper()
	tg := startTargetFTP(t)
	ledger := filepath.Join(t.TempDir(), "access.log")
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:0"
      kind: ftp
      ftp:
        upstream: servers
        require_grant: true
logging: {access: {enabled: false}}
upstreams:
  - name: servers
    endpoints: [{address: %s}]
access:
  ledger: %s
`, tg.addr(), ledger))
	return s, s.Addrs()["files"], tg
}

func grantFor(t *testing.T, s *proxy.Server, subject, target string, window time.Duration) *access.Grant {
	t.Helper()
	g, err := s.Access().Request(access.Request{Subject: subject, Listener: "files", Target: target,
		Reason: "restore a backup", By: "carol", Expires: time.Now().Add(window)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Access().Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	return g
}

// FTP dials the target before anybody has said who they are -- the greeting
// comes from the server -- so unlike the SSH and telnet gateways this cannot
// refuse before the target is reached. What it does instead is refuse the login
// itself: the session ends on a 530, and the target has seen the login and
// nothing else. No command of the person's is forwarded.
func TestWithoutAGrantTheLoginIsRefused(t *testing.T) {
	s, addr, tg := grantBastion(t)
	c := dialFTP(t, addr)
	if code, _ := c.cmd("USER alice"); code != 331 {
		t.Fatalf("USER was %d", code)
	}
	code, text := c.cmd("PASS secret")
	if code != 530 {
		t.Fatalf("PASS was %d %q, want 530", code, text)
	}
	if !strings.Contains(text, "no access grant") {
		t.Errorf("the refusal did not say why: %q", text)
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "LIST") || strings.HasPrefix(seen, "RETR") || strings.HasPrefix(seen, "STOR") {
			t.Errorf("a command reached the target with no grant: %s", seen)
		}
	}
	if n := s.Stats().Refusals["ftp"]["no_grant"]; n != 1 {
		t.Errorf("no_grant refusals %d, want 1: %v", n, s.Stats().Refusals["ftp"])
	}
}

// With a grant the login completes and files move, and the use is recorded.
func TestWithAGrantTheTransferWorks(t *testing.T) {
	s, addr, tg := grantBastion(t)
	g := grantFor(t, s, "alice", "servers", time.Hour)

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
	v, ok := s.Access().Get(g.ID)
	if !ok || v.Uses != 1 {
		t.Errorf("the use was not recorded: %+v", v)
	}
}

// A grant for somebody else is not a grant for this login, and the reason says
// the subject was wrong rather than that the file was.
func TestAnotherPersonsGrantDoesNotLogYouIn(t *testing.T) {
	s, addr, _ := grantBastion(t)
	grantFor(t, s, "dave", "servers", time.Hour)
	c := dialFTP(t, addr)
	if code, _ := c.cmd("USER alice"); code != 331 {
		t.Fatal("USER")
	}
	if code, _ := c.cmd("PASS secret"); code != 530 {
		t.Errorf("PASS was %d, want 530", code)
	}
	if n := s.Stats().Refusals["ftp"]["no_grant"]; n != 1 {
		t.Errorf("refusals %v", s.Stats().Refusals["ftp"])
	}
}

// The window closing ends the session that is running, mid-transfer session or
// not: a relay that only noticed at the next command would leave a logged-in
// session open for as long as somebody left the window open.
func TestTheWindowClosingEndsALiveFTPSession(t *testing.T) {
	s, addr, _ := grantBastion(t)
	grantFor(t, s, "alice", "servers", 2*time.Second)
	c := dialFTP(t, addr)
	c.login("alice", "secret")

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := c.conn.Write([]byte("NOOP\r\n")); err != nil {
			return
		}
		if _, err := c.conn.Read(make([]byte, 64)); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the session outlived its window")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
