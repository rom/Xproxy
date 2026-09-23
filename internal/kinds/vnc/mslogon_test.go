package vnc_test

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rfb"
)

// MS-Logon II on both legs. The type protects nothing, which is said
// in the validation warning and in the documentation; what these tests
// hold is that the gateway completes it, decides on it, and keeps the
// two credentials apart the way it does everywhere else.

// msLogon completes the client's side of the exchange with the
// credential given, and leaves the security result to be read.
func (cl *client) msLogon(user, pass string) {
	cl.t.Helper()
	params, err := rfb.ReadMSLogonParams(cl.c)
	if err != nil {
		cl.t.Fatalf("mslogon parameters: %v", err)
	}
	pub, priv, err := rfb.MSLogonPublic(params)
	if err != nil {
		cl.t.Fatal(err)
	}
	shared, err := rfb.MSLogonShared(params.Pub, priv, params.Mod)
	if err != nil {
		cl.t.Fatal(err)
	}
	cred, err := rfb.MSLogonSeal(shared, user, pass)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(binary.BigEndian.AppendUint64(nil, pub))
	cl.write(cred)
}

// A client using MS-Logon II proves the gateway's own password, and
// the desktop is opened with the gateway's credential rather than the
// person's.
func TestMSLogonOnTheClientLeg(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, "gate.pw")
	write(t, mine, "gate-secret")
	tg := startTarget(t, &target{desktop: "windows-box"})
	s, addr := gateway(t, tg, "        security_types: [mslogon2]\n        password_file: "+mine)

	// A wrong password never reaches the desktop.
	cl := dial(t, addr)
	cl.version(rfb.V38)
	if list := cl.offered(); !contains(list, rfb.SecMSLogon2) {
		t.Fatalf("mslogon2 was not offered: %v", list)
	}
	cl.write([]byte{rfb.SecMSLogon2})
	cl.msLogon("LAB\\alice", "not-it")
	if ok, _ := cl.result(); ok {
		t.Fatal("a wrong password was accepted")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("a wrong password reached the desktop: %q", got)
	}

	// The right one opens the session.
	cl2 := dial(t, addr)
	cl2.version(rfb.V38)
	cl2.offered()
	cl2.write([]byte{rfb.SecMSLogon2})
	cl2.msLogon("LAB\\alice", "gate-secret")
	if ok, why := cl2.result(); !ok {
		t.Fatalf("the right password was refused: %s", why)
	}
	cl2.write(rfb.ClientInit{Shared: true}.Encode())
	si, err := rfb.ReadServerInit(cl2.c)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if si.Name != "windows-box" {
		t.Errorf("desktop %q, want windows-box", si.Name)
	}
	waitFor(t, "the refusal of the first attempt", func() bool { return s.Stats().VNCRefused > 0 })
}

// MS-Logon II carries a name, so it can carry a factor -- and unlike
// VeNCrypt's plain subtype it needs no certificate to do it, which is
// the one thing this type is good for.
func TestMSLogonCarriesTheSecondFactor(t *testing.T) {
	file, secret := enrol(t, "alice")
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [mslogon2]\n        mfa: {file: "+file+"}")

	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecMSLogon2})
	cl.msLogon("alice", "000000")
	if ok, _ := cl.result(); ok {
		t.Fatal("a wrong code was accepted")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("a wrong code reached the desktop: %q", got)
	}
	waitFor(t, "the failure to be counted", func() bool { return s.Stats().VNCMFAFailed == 1 })

	cl2 := dial(t, addr)
	cl2.version(rfb.V38)
	cl2.offered()
	cl2.write([]byte{rfb.SecMSLogon2})
	cl2.msLogon("alice", totp(t, secret))
	if ok, why := cl2.result(); !ok {
		t.Fatalf("the right code was refused: %s", why)
	}
	waitFor(t, "the factor to be counted", func() bool { return s.Stats().VNCMFAOK == 1 })
}

// Towards a desktop that speaks only MS-Logon II, the gateway sends
// the credential an operator configured -- never the one the person at
// the viewer proved.
func TestMSLogonTowardsTheTarget(t *testing.T) {
	dir := t.TempDir()
	theirs := filepath.Join(dir, "target.pw")
	write(t, theirs, "desktop-secret")
	tg := startTarget(t, &target{desktop: "old-windows",
		security: []uint8{rfb.SecMSLogon2}, password: "desktop-secret"})
	_, addr := gateway(t, tg, "        security_types: [none]\n"+
		"        upstream_security: mslogon2\n"+
		"        upstream_user: LAB\\service\n"+
		"        upstream_password_file: "+theirs)
	cl := dial(t, addr)
	if si := cl.open(true); si.Name != "old-windows" {
		t.Errorf("desktop %q, want old-windows", si.Name)
	}
	user, pass := tg.credential()
	if user != `LAB\service` || pass != "desktop-secret" {
		t.Errorf("the desktop was opened with %q and %q", user, pass)
	}
}

// Using it towards a target needs both halves of a named credential,
// and saying so at load beats failing at the first session.
func TestMSLogonUpstreamNeedsANameAndAPassword(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "target.pw")
	write(t, pw, "desktop-secret")
	cases := []struct{ name, extra, want string }{
		{"no user", "upstream_password_file: " + pw, "upstream_user"},
		{"no password", `upstream_user: svc`, "upstream_password_file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desktops
      address: "127.0.0.1:0"
      kind: vnc
      vnc: {upstream: screens, security_types: [none], upstream_security: mslogon2, %s}
upstreams:
  - name: screens
    endpoints: [{address: 127.0.0.1:5900}]
`, c.extra)
			_, err := config.Parse([]byte(yaml))
			if err == nil {
				t.Fatal("a half credential was accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not name %s", err, c.want)
			}
		})
	}
}

// The type is allowed and warned about rather than refused, and the
// warning says what it is actually worth.
func TestMSLogonIsWarnedAboutAtLoad(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "gate.pw")
	write(t, pw, "gate-secret")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desktops
      address: "127.0.0.1:0"
      kind: vnc
      vnc: {upstream: screens, security_types: [mslogon2], password_file: %s}
upstreams:
  - name: screens
    endpoints: [{address: 127.0.0.1:5900}]
`, pw)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("mslogon2 was refused: %v", err)
	}
	var found bool
	for _, w := range cfg.Advice() {
		if strings.Contains(w, "mslogon2") && strings.Contains(w, "DES") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning says what the type is worth: %v", cfg.Advice())
	}
}

// A client that fixes the shared secret is refused rather than
// authenticated against a key both ends can work out.
func TestMSLogonRefusesADegenerateClientKey(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{})
	_, addr := gateway(t, tg, "        security_types: [mslogon2]\n        password_file: "+pw)
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecMSLogon2})
	if _, err := rfb.ReadMSLogonParams(cl.c); err != nil {
		t.Fatal(err)
	}
	// A public value of 1 makes the shared secret 1 whatever the
	// server's private value is.
	cl.write(binary.BigEndian.AppendUint64(nil, 1))
	cl.write(make([]byte, rfb.MSLogonCredentialSize))
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := rfb.ReadSecurityResult(cl.c, rfb.V38); err == nil {
		t.Error("a fixed shared secret was authenticated against")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the desktop was reached anyway: %q", got)
	}
}
