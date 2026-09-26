package telnet_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// grantGateway is a telnet gateway that admits nothing without a live grant.
// The factor prompt is what gives it a name to match a grant against, which is
// why require_grant needs it on this kind.
func grantGateway(t *testing.T, mfaFile string) (*proxy.Server, string, *targetTelnet) {
	t.Helper()
	tg := startTarget(t)
	ledger := filepath.Join(t.TempDir(), "access.log")
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        upstream: kit
        require_grant: true
        mfa: {file: %s}
logging: {access: {enabled: false}}
upstreams:
  - name: kit
    endpoints: [{address: %s}]
access:
  ledger: %s
`, mfaFile, tg.addr(), ledger))
	return s, s.Addrs()["legacy"], tg
}

// grant requests and approves one, which is the four-eyes round trip.
func grant(t *testing.T, s *proxy.Server, subject, target string, window time.Duration) *access.Grant {
	t.Helper()
	g, err := s.Access().Request(access.Request{Subject: subject, Listener: "legacy", Target: target,
		Reason: "switch upgrade", By: "carol", Expires: time.Now().Add(window)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Access().Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	return g
}

// The factor proves who is at the keyboard; the grant says whether they may be
// there at all. Without one the equipment is never dialled -- which on a telnet
// device matters more than anywhere else, since the equipment has no
// authentication worth the name behind this gateway.
func TestWithoutAGrantTheEquipmentIsNeverDialled(t *testing.T) {
	file, secret := enrol(t, "alice")
	s, addr, tg := grantGateway(t, file)

	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	c.readUntil("code: ")
	c.write([]byte(totp(t, secret) + "\r\n"))
	if out := c.readUntil("no access grant"); !strings.Contains(out, "no access grant") {
		t.Errorf("the refusal did not say why: %q", out)
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the equipment was reached with no grant: %q", got)
	}
	if n := s.Stats().Refusals["telnet"]["no_grant"]; n != 1 {
		t.Errorf("no_grant refusals %d, want 1: %v", n, s.Stats().Refusals["telnet"])
	}
}

// With a grant somebody else approved, the session goes through and the use is
// recorded against it.
func TestWithAGrantTheSessionGoesThrough(t *testing.T) {
	file, secret := enrol(t, "alice")
	s, addr, tg := grantGateway(t, file)
	g := grant(t, s, "alice", "kit", time.Hour)

	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	c.readUntil("code: ")
	c.write([]byte(totp(t, secret) + "\r\n"))
	if out := c.readUntil("target ready"); !strings.Contains(out, "target ready") {
		t.Errorf("the session did not open: %q", out)
	}
	if !tg.waitSeen(t, []byte{}) {
		t.Error("the equipment saw nothing")
	}
	v, ok := s.Access().Get(g.ID)
	if !ok || v.Uses != 1 {
		t.Errorf("the use was not recorded: %+v", v)
	}
}

// The window closing ends the session that is running: a gateway that only
// noticed at the next keystroke would leave an idle shell on a switch for as
// long as somebody left the window open.
func TestTheWindowClosingEndsALiveTelnetSession(t *testing.T) {
	file, secret := enrol(t, "alice")
	s, addr, _ := grantGateway(t, file)
	grant(t, s, "alice", "kit", 2*time.Second)

	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	c.readUntil("code: ")
	c.write([]byte(totp(t, secret) + "\r\n"))
	c.readUntil("target ready")

	// The client's own socket closes when the window ends.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := c.c.Write([]byte("x")); err != nil {
			break
		}
		if _, err := c.c.Read(make([]byte, 1)); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the session outlived its window")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
