package vnc_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/rfb"
)

// TightVNC's type 16 and Apple's type 30 on both legs.

// tight completes the client's side of the Tight negotiation.
func (cl *client) tight(want uint32) {
	cl.t.Helper()
	tunnels, err := rfb.ReadTightCapabilities(cl.c)
	if err != nil {
		cl.t.Fatalf("tunnels: %v", err)
	}
	if len(tunnels) != 0 {
		cl.t.Fatalf("the gateway offered %d tunnels, want none", len(tunnels))
	}
	auths, err := rfb.ReadTightCapabilities(cl.c)
	if err != nil {
		cl.t.Fatalf("auths: %v", err)
	}
	if !rfb.TightHasCapability(auths, want) {
		cl.t.Fatalf("authentication %d was not offered: %+v", want, auths)
	}
	cl.write(rfb.TightChoice(want))
}

// A Tight client reaches the desktop, and is told there are no
// extensions: the capabilities advertised in that block are things
// like file transfer, which the gateway cannot see inside.
func TestTightOnTheClientLeg(t *testing.T) {
	tg := startTarget(t, &target{desktop: "tight-box"})
	_, addr := gateway(t, tg, "        security_types: [tight]")
	cl := dial(t, addr)
	cl.version(rfb.V38)
	if list := cl.offered(); !contains(list, rfb.SecTight) {
		t.Fatalf("tight was not offered: %v", list)
	}
	cl.write([]byte{rfb.SecTight})
	cl.tight(rfb.TightAuthNone.Code)
	if ok, why := cl.result(); !ok {
		t.Fatalf("the gateway refused: %s", why)
	}
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	si, err := rfb.ReadServerInit(cl.c)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if si.Name != "tight-box" {
		t.Errorf("desktop %q, want tight-box", si.Name)
	}
	// The interaction block follows, and is empty.
	inter, err := rfb.ReadTightInteraction(cl.c)
	if err != nil {
		t.Fatalf("interaction block: %v", err)
	}
	if len(inter.Server)+len(inter.Client)+len(inter.Encodings) != 0 {
		t.Errorf("the gateway advertised extensions it cannot mediate: %+v", inter)
	}
}

// With a password, Tight settles on the DES challenge, and a wrong one
// never reaches the desktop.
func TestTightSettlesOnVNCAuth(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{})
	_, addr := gateway(t, tg, "        security_types: [tight]\n        password_file: "+pw)
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecTight})
	cl.tight(rfb.TightAuthVNC.Code)
	cl.answer("not-it")
	if ok, _ := cl.result(); ok {
		t.Fatal("a wrong password was accepted")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("a wrong password reached the desktop: %q", got)
	}
}

// An authentication the gateway did not offer is refused, the same as
// a security type outside the list.
func TestTightRefusesAnAuthenticationItDidNotOffer(t *testing.T) {
	tg := startTarget(t, &target{})
	_, addr := gateway(t, tg, "        security_types: [tight]")
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecTight})
	_, _ = rfb.ReadTightCapabilities(cl.c)
	_, _ = rfb.ReadTightCapabilities(cl.c)
	// 129 is TightVNC's unix login, which this gateway cannot check.
	cl.write(rfb.TightChoice(129))
	if ok, why := cl.result(); ok || !strings.Contains(why, "not offered") {
		t.Errorf("an authentication outside the offer was accepted (%v %q)", ok, why)
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the desktop was reached anyway: %q", got)
	}
}

// Towards a Tight target the gateway declines every tunnel, takes the
// authentication it can complete, and swallows the block after
// ServerInit rather than passing it to a client that is not expecting
// one.
func TestTightTowardsTheTarget(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "target.pw")
	write(t, pw, "desktop-secret")
	tg := startTarget(t, &target{desktop: "tight-target",
		security: []uint8{rfb.SecTight}, password: "desktop-secret", tightAuth: true})
	_, addr := gateway(t, tg, "        security_types: [none]\n"+
		"        upstream_password_file: "+pw)
	cl := dial(t, addr)
	si := cl.open(true)
	if si.Name != "tight-target" {
		t.Errorf("desktop %q, want tight-target", si.Name)
	}
	// The client asked for no Tight, so nothing of it reaches it: what
	// follows ServerInit is the desktop's own stream.
	got := cl.read(len(tg.shown))
	if string(got) != string(tg.shown) {
		t.Errorf("the interaction block was passed through: %q", got)
	}
}

// A target that offers only tunnelled connections is not used: a
// tunnel is another protocol around this one, which is a session the
// gateway could neither read nor record.
func TestATunnelledTightTargetIsNotUsed(t *testing.T) {
	tg := startTarget(t, &target{security: []uint8{rfb.SecTight}, tightTunnel: true})
	_, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecNone})
	cl.result()
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := rfb.ReadServerInit(cl.c); err == nil {
		t.Error("a tunnelled target was used")
	}
}

// ard completes the client's side of Apple's exchange.
func (cl *client) ard(user, pass string) {
	cl.t.Helper()
	params, err := rfb.ReadARDParams(cl.c)
	if err != nil {
		cl.t.Fatalf("ard parameters: %v", err)
	}
	pub, priv, err := rfb.ARDPublic(params)
	if err != nil {
		cl.t.Fatal(err)
	}
	key, err := rfb.ARDKey(params.Pub, params.Prime, priv)
	if err != nil {
		cl.t.Fatal(err)
	}
	blob, err := rfb.ARDSeal(key, user, pass)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(blob)
	cl.write(pub)
}

// An ARD client proves the gateway's own password.
func TestARDOnTheClientLeg(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{desktop: "mac-mini"})
	s, addr := gateway(t, tg, "        security_types: [ard]\n        password_file: "+pw)

	cl := dial(t, addr)
	cl.version(rfb.V38)
	if list := cl.offered(); !contains(list, rfb.SecARD) {
		t.Fatalf("ard was not offered: %v", list)
	}
	cl.write([]byte{rfb.SecARD})
	cl.ard("alice", "not-it")
	if ok, _ := cl.result(); ok {
		t.Fatal("a wrong password was accepted")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("a wrong password reached the desktop: %q", got)
	}

	cl2 := dial(t, addr)
	cl2.version(rfb.V38)
	cl2.offered()
	cl2.write([]byte{rfb.SecARD})
	cl2.ard("alice", "gate-secret")
	if ok, why := cl2.result(); !ok {
		t.Fatalf("the right password was refused: %s", why)
	}
	cl2.write(rfb.ClientInit{Shared: true}.Encode())
	if si, err := rfb.ReadServerInit(cl2.c); err != nil || si.Name != "mac-mini" {
		t.Errorf("server init: %v %+v", err, si)
	}
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().VNCRefused > 0 })
}

// ARD carries a name, so it carries a factor.
func TestARDCarriesTheSecondFactor(t *testing.T) {
	file, secret := enrol(t, "alice")
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [ard]\n        mfa: {file: "+file+"}")
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecARD})
	cl.ard("alice", totp(t, secret))
	if ok, why := cl.result(); !ok {
		t.Fatalf("the right code was refused: %s", why)
	}
	waitFor(t, "the factor to be counted", func() bool { return s.Stats().VNCMFAOK == 1 })
}

// Towards a Mac, the gateway sends the credential an operator
// configured.
func TestARDTowardsTheTarget(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "target.pw")
	write(t, pw, "desktop-secret")
	tg := startTarget(t, &target{desktop: "studio",
		security: []uint8{rfb.SecARD}, password: "desktop-secret"})
	_, addr := gateway(t, tg, "        security_types: [none]\n"+
		"        upstream_security: ard\n"+
		"        upstream_user: service\n"+
		"        upstream_password_file: "+pw)
	cl := dial(t, addr)
	if si := cl.open(true); si.Name != "studio" {
		t.Errorf("desktop %q, want studio", si.Name)
	}
	if user, pass := tg.credential(); user != "service" || pass != "desktop-secret" {
		t.Errorf("the desktop was opened with %q and %q", user, pass)
	}
}

// A target whose parameters fix the shared secret is not
// authenticated to.
func TestARDRefusesDegenerateTargetParameters(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "target.pw")
	write(t, pw, "desktop-secret")
	tg := startTarget(t, &target{security: []uint8{rfb.SecARD}, ardDegenerate: true})
	_, addr := gateway(t, tg, "        security_types: [none]\n"+
		"        upstream_security: ard\n"+
		"        upstream_user: service\n"+
		"        upstream_password_file: "+pw)
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecNone})
	cl.result()
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := rfb.ReadServerInit(cl.c); err == nil {
		t.Error("a credential was sent under a secret anyone can work out")
	}
	if user, _ := tg.credential(); user != "" {
		t.Errorf("the credential was sent anyway: %q", user)
	}
}
