package vnc_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rfb"
)

// RealVNC's RSA-AES on both legs, driven through real sockets so the
// framing is exercised in both directions.

// rsaKeyFile writes a key the listener can present and returns the
// path and the key.
func rsaKeyFile(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rsa.pem")
	body := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key
}

// rsaAES completes the client's side of the exchange and returns the
// channel the rest of it runs inside.
func (cl *client) rsaAES(sec uint8, user, pass string) *rfb.AESConn {
	cl.t.Helper()
	own, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		cl.t.Fatal(err)
	}
	peer, peerPub, err := rfb.ReadRSAAESKey(cl.c)
	if err != nil {
		cl.t.Fatalf("server key: %v", err)
	}
	ownKey, err := rfb.OwnRSAAESKey(&own.PublicKey)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(ownKey.Encode())
	clientRandom, err := rfb.RSAAESRandom(sec)
	if err != nil {
		cl.t.Fatal(err)
	}
	sealed, err := rfb.SealRSAAESRandom(peerPub, clientRandom)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(sealed)
	serverRandom, err := rfb.OpenRSAAESRandom(cl.c, own, sec)
	if err != nil {
		cl.t.Fatalf("server random: %v", err)
	}
	clientKey, serverKey := rfb.RSAAESSessionKeys(sec, clientRandom, serverRandom)
	ch, err := rfb.NewAESConn(cl.c, clientKey, serverKey)
	if err != nil {
		cl.t.Fatal(err)
	}
	want := rfb.RSAAESTranscript(sec, peer, ownKey)
	got, err := ch.ReadFull(len(want))
	if err != nil {
		cl.t.Fatalf("server transcript: %v", err)
	}
	if !rfb.RSAAESTranscriptMatches(got, want) {
		cl.t.Fatal("the gateway's transcript is not over the two keys exchanged")
	}
	if _, err := ch.Write(rfb.RSAAESTranscript(sec, ownKey, peer)); err != nil {
		cl.t.Fatal(err)
	}
	sub, err := ch.ReadFull(1)
	if err != nil {
		cl.t.Fatalf("subtype: %v", err)
	}
	if sub[0] != rfb.RSAAESSubtypeUserPassword {
		cl.t.Fatalf("subtype %d, want a name and a password", sub[0])
	}
	cred, err := rfb.RSAAESCredential(user, pass)
	if err != nil {
		cl.t.Fatal(err)
	}
	if _, err := ch.Write(cred); err != nil {
		cl.t.Fatal(err)
	}
	return ch
}

// A client using RSA-AES reaches the desktop, and the whole exchange
// is checked at both ends.
func TestRSAAESOnTheClientLeg(t *testing.T) {
	keyFile, _ := rsaKeyFile(t)
	dir := t.TempDir()
	pw := filepath.Join(dir, "gate.pw")
	write(t, pw, "gate-secret")
	for _, sec := range []struct {
		name string
		id   uint8
	}{{"rsa-aes", rfb.SecRSAAES}, {"rsa-aes-256", rfb.SecRSAAES256}} {
		t.Run(sec.name, func(t *testing.T) {
			tg := startTarget(t, &target{desktop: "realvnc-box"})
			_, addr := gateway(t, tg, "        security_types: ["+sec.name+"]\n"+
				"        rsa_key_file: "+keyFile+"\n        password_file: "+pw)
			cl := dial(t, addr)
			cl.version(rfb.V38)
			if list := cl.offered(); !contains(list, sec.id) {
				t.Fatalf("%s was not offered: %v", sec.name, list)
			}
			cl.write([]byte{sec.id})
			ch := cl.rsaAES(sec.id, "alice", "gate-secret")
			ok, why, err := rfb.ReadSecurityResult(ch, rfb.V38)
			if err != nil || !ok {
				t.Fatalf("the right password was refused: %v %q", err, why)
			}
			if _, err := ch.Write(rfb.ClientInit{Shared: true}.Encode()); err != nil {
				t.Fatal(err)
			}
			si, err := rfb.ReadServerInit(ch)
			if err != nil {
				t.Fatalf("server init: %v", err)
			}
			if si.Name != "realvnc-box" {
				t.Errorf("desktop %q, want realvnc-box", si.Name)
			}
			// The session stays inside the channel for these two
			// types, so what the desktop showed arrives through it.
			got, err := ch.ReadFull(len(tg.shown))
			if err != nil || !bytes.Equal(got, tg.shown) {
				t.Errorf("the stream did not come through the channel: %q (%v)", got, err)
			}
		})
	}
}

// rsa-aes-ne authenticates inside the channel and then hands the
// desktop back to a cleartext socket, which is the one thing about
// this family easiest to get wrong -- so it is held here rather than
// only described.
func TestTheNeTypeLeavesTheChannelAfterTheResult(t *testing.T) {
	keyFile, _ := rsaKeyFile(t)
	pw := filepath.Join(t.TempDir(), "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{desktop: "cleartext-after"})
	_, addr := gateway(t, tg, "        security_types: [rsa-aes-ne]\n"+
		"        rsa_key_file: "+keyFile+"\n        password_file: "+pw)
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecRSAAESne})
	ch := cl.rsaAES(rfb.SecRSAAESne, "alice", "gate-secret")
	// The result is the last message inside the channel.
	if ok, why, err := rfb.ReadSecurityResult(ch, rfb.V38); err != nil || !ok {
		t.Fatalf("the right password was refused: %v %q", err, why)
	}
	// Everything after it is in clear, on the socket underneath.
	raw, err := ch.Unwrap()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(rfb.ClientInit{Shared: true}.Encode()); err != nil {
		t.Fatal(err)
	}
	si, err := rfb.ReadServerInit(raw)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if si.Name != "cleartext-after" {
		t.Errorf("desktop %q, want cleartext-after", si.Name)
	}
	got := make([]byte, len(tg.shown))
	if _, err := io.ReadFull(raw, got); err != nil || !bytes.Equal(got, tg.shown) {
		t.Errorf("the stream did not continue in clear: %q (%v)", got, err)
	}
}

// A wrong password is refused, and the desktop is not dialled.
func TestRSAAESRefusesAWrongPassword(t *testing.T) {
	keyFile, _ := rsaKeyFile(t)
	pw := filepath.Join(t.TempDir(), "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [rsa-aes]\n"+
		"        rsa_key_file: "+keyFile+"\n        password_file: "+pw)
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecRSAAES})
	ch := cl.rsaAES(rfb.SecRSAAES, "alice", "not-it")
	if ok, _, _ := rfb.ReadSecurityResult(ch, rfb.V38); ok {
		t.Fatal("a wrong password was accepted")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("a wrong password reached the desktop: %q", got)
	}
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().VNCRefused > 0 })
}

// The factor rides this type too, since its credential carries a name.
func TestRSAAESCarriesTheSecondFactor(t *testing.T) {
	keyFile, _ := rsaKeyFile(t)
	file, secret := enrol(t, "alice")
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [rsa-aes-256]\n"+
		"        rsa_key_file: "+keyFile+"\n        mfa: {file: "+file+"}")
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecRSAAES256})
	ch := cl.rsaAES(rfb.SecRSAAES256, "alice", totp(t, secret))
	if ok, why, err := rfb.ReadSecurityResult(ch, rfb.V38); err != nil || !ok {
		t.Fatalf("the right code was refused: %v %q", err, why)
	}
	waitFor(t, "the factor to be counted", func() bool { return s.Stats().VNCMFAOK == 1 })
}

// A client whose transcript is over a different pair of keys is
// refused: that is what somebody swapping them in the middle looks
// like from here.
func TestRSAAESRefusesAWrongTranscript(t *testing.T) {
	keyFile, _ := rsaKeyFile(t)
	pw := filepath.Join(t.TempDir(), "gate.pw")
	write(t, pw, "gate-secret")
	tg := startTarget(t, &target{})
	_, addr := gateway(t, tg, "        security_types: [rsa-aes]\n"+
		"        rsa_key_file: "+keyFile+"\n        password_file: "+pw)
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecRSAAES})

	own, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, peerPub, err := rfb.ReadRSAAESKey(cl.c)
	if err != nil {
		t.Fatal(err)
	}
	ownKey, _ := rfb.OwnRSAAESKey(&own.PublicKey)
	cl.write(ownKey.Encode())
	clientRandom, _ := rfb.RSAAESRandom(rfb.SecRSAAES)
	sealed, _ := rfb.SealRSAAESRandom(peerPub, clientRandom)
	cl.write(sealed)
	serverRandom, err := rfb.OpenRSAAESRandom(cl.c, own, rfb.SecRSAAES)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, serverKey := rfb.RSAAESSessionKeys(rfb.SecRSAAES, clientRandom, serverRandom)
	ch, _ := rfb.NewAESConn(cl.c, clientKey, serverKey)
	if _, err := ch.ReadFull(20); err != nil {
		t.Fatal(err)
	}
	// A transcript over a key nobody sent.
	other, _ := rfb.OwnRSAAESKey(&own.PublicKey)
	if _, err := ch.Write(rfb.RSAAESTranscript(rfb.SecRSAAES, other, other)); err != nil {
		t.Fatal(err)
	}
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := ch.ReadFull(1); err == nil {
		t.Error("the exchange continued past a transcript over other keys")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the desktop was reached anyway: %q", got)
	}
}

// Towards a target, the key is pinned: an unpinned one is not a target
// to hand a credential to.
func TestRSAAESTowardsTheTarget(t *testing.T) {
	keyFile, _ := rsaKeyFile(t)
	_, targetKey := rsaKeyFile(t)
	pub, err := rfb.OwnRSAAESKey(&targetKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(t.TempDir(), "target.pw")
	write(t, pw, "desktop-secret")

	t.Run("the pinned key is reached", func(t *testing.T) {
		tg := startTarget(t, &target{desktop: "pinned-desktop",
			security: []uint8{rfb.SecRSAAES}, rsaKey: targetKey, password: "desktop-secret"})
		_, addr := gateway(t, tg, "        security_types: [none]\n"+
			"        rsa_key_file: "+keyFile+"\n"+
			"        upstream_security: rsa-aes\n"+
			"        upstream_user: service\n"+
			"        upstream_password_file: "+pw+"\n"+
			"        upstream_rsa_fingerprint: "+rfb.RSAAESFingerprint(pub))
		cl := dial(t, addr)
		if si := cl.open(true); si.Name != "pinned-desktop" {
			t.Errorf("desktop %q, want pinned-desktop", si.Name)
		}
		user, pass := tg.credential()
		if user != "service" || pass != "desktop-secret" {
			t.Errorf("the desktop was opened with %q and %q", user, pass)
		}
	})

	t.Run("another key is not", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		otherPub, _ := rfb.OwnRSAAESKey(&otherKey.PublicKey)
		tg := startTarget(t, &target{security: []uint8{rfb.SecRSAAES},
			rsaKey: targetKey, password: "desktop-secret"})
		_, addr := gateway(t, tg, "        security_types: [none]\n"+
			"        rsa_key_file: "+keyFile+"\n"+
			"        upstream_security: rsa-aes\n"+
			"        upstream_user: service\n"+
			"        upstream_password_file: "+pw+"\n"+
			"        upstream_rsa_fingerprint: "+rfb.RSAAESFingerprint(otherPub))
		cl := dial(t, addr)
		cl.version(rfb.V38)
		cl.offered()
		cl.write([]byte{rfb.SecNone})
		cl.result()
		cl.write(rfb.ClientInit{Shared: true}.Encode())
		_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := rfb.ReadServerInit(cl.c); err == nil {
			t.Error("a target whose key is not the pinned one was used")
		}
		if user, _ := tg.credential(); user != "" {
			t.Errorf("the credential was sent to an unpinned target: %q", user)
		}
	})
}

// The settings this family needs are required at load rather than
// discovered at the first session.
func TestRSAAESNeedsItsKeyAndItsPin(t *testing.T) {
	keyFile, _ := rsaKeyFile(t)
	cases := []struct{ name, vnc, want string }{
		{"no key of our own", `{upstream: screens, security_types: [rsa-aes]}`, "rsa_key_file"},
		{"no pinned target key", fmt.Sprintf(
			`{upstream: screens, security_types: [none], upstream_security: rsa-aes, rsa_key_file: %s, upstream_user: u}`, keyFile),
			"upstream_rsa_fingerprint"},
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
      vnc: %s
upstreams:
  - name: screens
    endpoints: [{address: 127.0.0.1:5900}]
`, c.vnc)
			_, err := config.Parse([]byte(yaml))
			if err == nil {
				t.Fatal("it was accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not name %s", err, c.want)
			}
		})
	}
}

// The warning says which of the three leaves the session in clear,
// because that is the thing easiest to get wrong.
func TestTheNeTypeIsWarnedAbout(t *testing.T) {
	keyFile, _ := rsaKeyFile(t)
	pw := filepath.Join(t.TempDir(), "gate.pw")
	write(t, pw, "gate-secret")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desktops
      address: "127.0.0.1:0"
      kind: vnc
      vnc: {upstream: screens, security_types: [rsa-aes-ne], rsa_key_file: %s, password_file: %s}
upstreams:
  - name: screens
    endpoints: [{address: 127.0.0.1:5900}]
`, keyFile, pw)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("rsa-aes-ne was refused: %v", err)
	}
	var found bool
	for _, a := range cfg.Advice() {
		if strings.Contains(a, "rsa-aes-ne") && strings.Contains(a, "in clear") {
			found = true
		}
	}
	if !found {
		t.Errorf("no advice says the session is in clear: %v", cfg.Advice())
	}
}
