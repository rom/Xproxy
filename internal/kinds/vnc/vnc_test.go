package vnc_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/vnc"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/rfb"
	"github.com/rom/xproxy/internal/testutil"
)

// target is a VNC server as far as the gateway is concerned: it
// completes the handshake the gateway drives, then shows something and
// keeps what reached it.
type target struct {
	ln       net.Listener
	security []uint8
	password string
	desktop  string
	// version is what the server announces; a 3.3 target names one
	// security type rather than offering a list.
	version rfb.Version
	// shown is written to the client once the handshake is done, so a
	// test has something to see at the far end.
	shown []byte
	// serverTLS is the certificate this target presents when it offers
	// VeNCrypt, which is how the gateway's own leg gets encrypted.
	serverTLS *tls.Config
	// rsaKey is the key this target presents when it offers one of the
	// rsa-aes types.
	rsaKey *rsa.PrivateKey
	// tightAuth makes a Tight target ask for the DES challenge, and
	// tightTunnel makes it offer only tunnels the gateway refuses.
	tightAuth, tightTunnel bool
	// ardDegenerate makes an ARD target send parameters that fix the
	// shared secret.
	ardDegenerate bool

	mu   sync.Mutex
	got  []byte
	init rfb.ClientInit
	// gotUser and gotPass are the credential a named security type
	// delivered, so a test can check whose it was.
	gotUser, gotPass string
}

func startTarget(t *testing.T, tg *target) *target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg.ln = ln
	if tg.version == (rfb.Version{}) {
		tg.version = rfb.V38
	}
	if len(tg.security) == 0 {
		tg.security = []uint8{rfb.SecNone}
	}
	if tg.desktop == "" {
		tg.desktop = "lab-console"
	}
	if tg.shown == nil {
		tg.shown = []byte("FRAMEBUFFER-ONE")
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go tg.session(c)
		}
	}()
	return tg
}

func (tg *target) addr() string { return tg.ln.Addr().String() }

func (tg *target) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	if _, err := c.Write(tg.version.Handshake()); err != nil {
		return
	}
	if _, err := rfb.ReadVersion(c); err != nil {
		return
	}
	var chosen uint8
	skipResult := false
	if tg.version.AtLeast(rfb.V37) {
		if _, err := c.Write(rfb.SecurityList(tg.security)); err != nil {
			return
		}
		var b [1]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		chosen = b[0]
	} else {
		if _, err := c.Write(rfb.Security33(tg.security[0])); err != nil {
			return
		}
		chosen = tg.security[0]
	}
	switch chosen {
	case rfb.SecVNCAuth:
		if !tg.vncAuth(c) {
			return
		}
	case rfb.SecVeNCrypt:
		inner, ok := tg.vencrypt(c)
		if !ok {
			return
		}
		// Everything after the subtype is inside the tunnel.
		c = inner
	case rfb.SecMSLogon2:
		if !tg.msLogon(c) {
			return
		}
	case rfb.SecRSAAES, rfb.SecRSAAESne, rfb.SecRSAAES256:
		inner, ok := tg.rsaAES(c, chosen)
		if !ok {
			return
		}
		c = inner
	case rfb.SecTight:
		ok, noResult := tg.tight(c)
		if !ok {
			return
		}
		// Tight with no authentication sends no security result
		// either, by its own rules.
		skipResult = noResult
	case rfb.SecARD:
		if !tg.ard(c) {
			return
		}
	}
	if rfb.SendsResult(tg.version, chosen) && !skipResult {
		if _, err := c.Write(rfb.SecurityResult(tg.version, true, "")); err != nil {
			return
		}
	}
	ci, err := rfb.ReadClientInit(c)
	if err != nil {
		return
	}
	tg.mu.Lock()
	tg.init = ci
	tg.mu.Unlock()
	si := rfb.ServerInit{Width: 1024, Height: 768, Name: tg.desktop}
	si.PixelFormat[0] = 32
	if _, err := c.Write(si.Encode()); err != nil {
		return
	}
	if chosen == rfb.SecTight {
		// A Tight server says what it has beyond the standard
		// protocol, which here is nothing.
		if _, err := c.Write(rfb.NoTightInteraction()); err != nil {
			return
		}
	}
	if _, err := c.Write(tg.shown); err != nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			tg.mu.Lock()
			tg.got = append(tg.got, buf[:n]...)
			tg.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// vncAuth runs the DES challenge as a server.
func (tg *target) vncAuth(c net.Conn) bool {
	challenge := bytes.Repeat([]byte{0x5a}, rfb.ChallengeSize)
	if _, err := c.Write(challenge); err != nil {
		return false
	}
	got := make([]byte, rfb.ChallengeSize)
	if _, err := io.ReadFull(c, got); err != nil {
		return false
	}
	want, err := rfb.VNCAuthResponse(challenge, tg.password)
	if err != nil || !bytes.Equal(got, want) {
		_, _ = c.Write(rfb.SecurityResult(tg.version, false, "bad password"))
		return false
	}
	return true
}

// msLogon plays the MS-Logon II server and keeps the credential it was
// given, so a test can see whose it was.
func (tg *target) msLogon(c net.Conn) bool {
	params, priv, err := rfb.NewMSLogonParams()
	if err != nil {
		return false
	}
	if _, err := c.Write(params.Encode()); err != nil {
		return false
	}
	var pub [rfb.MSLogonDHSize]byte
	if _, err := io.ReadFull(c, pub[:]); err != nil {
		return false
	}
	shared, err := rfb.MSLogonShared(binary.BigEndian.Uint64(pub[:]), priv, params.Mod)
	if err != nil {
		return false
	}
	user, pass, err := rfb.ReadMSLogonCredential(c, shared)
	if err != nil {
		return false
	}
	tg.mu.Lock()
	tg.gotUser, tg.gotPass = user, pass
	tg.mu.Unlock()
	if tg.password != "" && pass != tg.password {
		_, _ = c.Write(rfb.SecurityResult(tg.version, false, "bad credential"))
		return false
	}
	return true
}

// tight plays the Tight server: the tunnel list, then the
// authentication list, then whatever was picked.
func (tg *target) tight(c net.Conn) (ok, noResult bool) {
	tunnels := []rfb.TightCapability(nil)
	if tg.tightTunnel {
		// A tunnel type the gateway has no name for, which is the
		// case it must refuse rather than guess at.
		tunnels = []rfb.TightCapability{{Code: 1, Vendor: "TGHT", Signature: "SSLTUNNL"}}
	}
	if _, err := c.Write(rfb.TightCapabilities(tunnels)); err != nil {
		return false, false
	}
	if len(tunnels) > 0 {
		// The gateway should never get past a tunnel list with
		// nothing in it that it can take.
		return false, false
	}
	auths := []rfb.TightCapability(nil)
	if tg.tightAuth {
		auths = []rfb.TightCapability{rfb.TightAuthVNC}
	}
	if _, err := c.Write(rfb.TightCapabilities(auths)); err != nil {
		return false, false
	}
	if len(auths) == 0 {
		// No authentication and, by this type's rules, no security
		// result either.
		return true, true
	}
	if _, err := rfb.ReadTightChoice(c); err != nil {
		return false, false
	}
	return tg.vncAuth(c), false
}

// ard plays the ARD server.
func (tg *target) ard(c net.Conn) bool {
	params, priv, err := rfb.NewARDParams()
	if err != nil {
		return false
	}
	if tg.ardDegenerate {
		// A public value of 1 fixes the shared secret whatever the
		// other end's private value is.
		params.Pub = make([]byte, len(params.Prime))
		params.Pub[len(params.Pub)-1] = 1
	}
	if _, err := c.Write(params.Encode()); err != nil {
		return false
	}
	blob := make([]byte, rfb.ARDCredentialSize)
	if _, err := io.ReadFull(c, blob); err != nil {
		return false
	}
	pub := make([]byte, len(params.Prime))
	if _, err := io.ReadFull(c, pub); err != nil {
		return false
	}
	key, err := rfb.ARDKey(pub, params.Prime, priv)
	if err != nil {
		return false
	}
	user, pass, err := rfb.ARDOpen(key, blob)
	if err != nil {
		return false
	}
	tg.mu.Lock()
	tg.gotUser, tg.gotPass = user, pass
	tg.mu.Unlock()
	if tg.password != "" && pass != tg.password {
		_, _ = c.Write(rfb.SecurityResult(tg.version, false, "bad credential"))
		return false
	}
	return true
}

// rsaAES plays the RSA-AES server and returns the channel the rest of
// the handshake runs inside.
func (tg *target) rsaAES(c net.Conn, sec uint8) (net.Conn, bool) {
	own, err := rfb.OwnRSAAESKey(&tg.rsaKey.PublicKey)
	if err != nil {
		return nil, false
	}
	if _, err := c.Write(own.Encode()); err != nil {
		return nil, false
	}
	peer, peerPub, err := rfb.ReadRSAAESKey(c)
	if err != nil {
		return nil, false
	}
	clientRandom, err := rfb.OpenRSAAESRandom(c, tg.rsaKey, sec)
	if err != nil {
		return nil, false
	}
	serverRandom, err := rfb.RSAAESRandom(sec)
	if err != nil {
		return nil, false
	}
	sealed, err := rfb.SealRSAAESRandom(peerPub, serverRandom)
	if err != nil {
		return nil, false
	}
	if _, err := c.Write(sealed); err != nil {
		return nil, false
	}
	clientKey, serverKey := rfb.RSAAESSessionKeys(sec, clientRandom, serverRandom)
	ch, err := rfb.NewAESConn(c, serverKey, clientKey)
	if err != nil {
		return nil, false
	}
	if _, err := ch.Write(rfb.RSAAESTranscript(sec, own, peer)); err != nil {
		return nil, false
	}
	want := rfb.RSAAESTranscript(sec, peer, own)
	got, err := ch.ReadFull(len(want))
	if err != nil || !rfb.RSAAESTranscriptMatches(got, want) {
		return nil, false
	}
	if _, err := ch.Write([]byte{rfb.RSAAESSubtypeUserPassword}); err != nil {
		return nil, false
	}
	user, pass, err := rfb.ReadRSAAESCredential(ch)
	if err != nil {
		return nil, false
	}
	tg.mu.Lock()
	tg.gotUser, tg.gotPass = user, pass
	tg.mu.Unlock()
	if tg.password != "" && pass != tg.password {
		_, _ = ch.Write(rfb.SecurityResult(tg.version, false, "bad credential"))
		return nil, false
	}
	return ch, true
}

// credential is what the target was given, once it has one.
func (tg *target) credential() (string, string) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.gotUser, tg.gotPass
}

// vencrypt plays the VeNCrypt server, and returns the connection the
// rest of the handshake runs on.
func (tg *target) vencrypt(c net.Conn) (net.Conn, bool) {
	if _, err := c.Write(rfb.VeNCryptVersion(rfb.VeNCrypt02)); err != nil {
		return nil, false
	}
	if _, err := rfb.ReadVeNCryptVersion(c); err != nil {
		return nil, false
	}
	if _, err := c.Write([]byte{0}); err != nil {
		return nil, false
	}
	offer := []uint32{rfb.VeNCryptX509None}
	if tg.password != "" {
		offer = []uint32{rfb.VeNCryptX509Vnc, rfb.VeNCryptX509None}
	}
	if _, err := c.Write(rfb.Subtypes(offer)); err != nil {
		return nil, false
	}
	sub, err := rfb.ReadSubtypeChoice(c)
	if err != nil {
		return nil, false
	}
	if _, err := c.Write([]byte{1}); err != nil {
		return nil, false
	}
	tc := tls.Server(c, tg.serverTLS)
	if err := tc.Handshake(); err != nil {
		return nil, false
	}
	if rfb.AuthAfterTLS(sub) == rfb.SecVNCAuth && !tg.vncAuth(tc) {
		return nil, false
	}
	return tc, true
}

func (tg *target) seen() []byte {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]byte(nil), tg.got...)
}

func (tg *target) shared() bool {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.init.Shared
}

// waitSeen waits for the target to have received want.
func (tg *target) waitSeen(want []byte) bool {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if bytes.Contains(tg.seen(), want) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// gateway starts a server with one vnc listener in front of tg.
func gateway(t *testing.T, tg *target, extra string) (*proxy.Server, string) {
	t.Helper()
	return gatewayFor(t, tg.addr(), extra)
}

// gatewayFor is the same with the pool pointed at an address of the
// test's choosing, which is what an SSH jump host needs.
func gatewayFor(t *testing.T, endpoint, extra string) (*proxy.Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desktops
      address: "127.0.0.1:0"
      kind: vnc
      vnc:
        upstream: screens
%s
logging: {access: {enabled: false}}
upstreams:
  - name: screens
    endpoints: [{address: %s}]
`, extra, endpoint)
	s := proxytest.Start(t, yaml)
	return s, proxytest.Addr(t, s, "desktops")
}

// client is enough of a VNC viewer to drive the gateway.
type client struct {
	t *testing.T
	c net.Conn
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{t: t, c: c}
}

func (cl *client) write(b []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatalf("write: %v", err)
	}
}

func (cl *client) read(n int) []byte {
	cl.t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(cl.c, b); err != nil {
		cl.t.Fatalf("read %d: %v", n, err)
	}
	return b
}

// version settles the version on the client's leg and returns what the
// gateway announced.
func (cl *client) version(mine rfb.Version) rfb.Version {
	cl.t.Helper()
	v, err := rfb.ReadVersion(cl.c)
	if err != nil {
		cl.t.Fatalf("server version: %v", err)
	}
	cl.write(mine.Handshake())
	return v
}

// offered reads the security list the gateway sent.
func (cl *client) offered() []uint8 {
	cl.t.Helper()
	list, err := rfb.ReadSecurityList(cl.c)
	if err != nil {
		cl.t.Fatalf("security list: %v", err)
	}
	return list
}

func (cl *client) result() (bool, string) {
	cl.t.Helper()
	ok, why, err := rfb.ReadSecurityResult(cl.c, rfb.V38)
	if err != nil {
		cl.t.Fatalf("security result: %v", err)
	}
	return ok, why
}

// open finishes the handshake with the none type and returns what the
// target's ServerInit said.
func (cl *client) open(shared bool) rfb.ServerInit {
	cl.t.Helper()
	cl.version(rfb.V38)
	list := cl.offered()
	if !contains(list, rfb.SecNone) {
		cl.t.Fatalf("none was not offered: %v", list)
	}
	cl.write([]byte{rfb.SecNone})
	if ok, why := cl.result(); !ok {
		cl.t.Fatalf("the gateway refused: %s", why)
	}
	cl.write(rfb.ClientInit{Shared: shared}.Encode())
	si, err := rfb.ReadServerInit(cl.c)
	if err != nil {
		cl.t.Fatalf("server init: %v", err)
	}
	return si
}

func contains(list []uint8, want uint8) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A session reaches the target: the desktop it named comes back and the
// stream runs both ways.
func TestSessionReachesTheTarget(t *testing.T) {
	tg := startTarget(t, &target{desktop: "switch-room"})
	s, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	si := cl.open(true)
	if si.Name != "switch-room" {
		t.Errorf("desktop %q, want switch-room", si.Name)
	}
	if si.Width != 1024 || si.Height != 768 {
		t.Errorf("framebuffer %dx%d, want 1024x768", si.Width, si.Height)
	}
	if got := cl.read(len(tg.shown)); !bytes.Equal(got, tg.shown) {
		t.Errorf("the target's stream did not arrive: %q", got)
	}
	if !tg.shared() {
		t.Error("the client's shared flag did not reach the target")
	}
	// And what the client types reaches the desktop.
	cl.write([]byte{4, 1, 0, 0, 0, 0, 0, 'A'})
	if !tg.waitSeen([]byte{4, 1, 0, 0, 0, 0, 0, 'A'}) {
		t.Errorf("a key event did not reach the target: %v", tg.seen())
	}
	if sn := s.Stats(); sn.VNCSessions != 1 {
		t.Errorf("vnc_sessions %d, want 1", sn.VNCSessions)
	}
}

// The gateway offers only what an operator asked for, and a client that
// picks something else is refused rather than obliged.
func TestASecurityTypeThatWasNotOfferedIsRefused(t *testing.T) {
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	cl.version(rfb.V38)
	if list := cl.offered(); len(list) != 1 || list[0] != rfb.SecNone {
		t.Fatalf("offered %v, want just none", list)
	}
	// Tight is a type this gateway refuses to mediate.
	cl.write([]byte{rfb.SecTight})
	ok, why := cl.result()
	if ok {
		t.Fatal("a type outside the offer was accepted")
	}
	if !strings.Contains(why, "not offered") {
		t.Errorf("reason %q does not say why", why)
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the target was reached anyway: %q", got)
	}
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().VNCRefused > 0 })
}

// A vendor's own security type cannot be mediated, so a listener that
// names one does not start at all.
func TestAProprietaryTypeIsRefusedAtLoad(t *testing.T) {
	for _, name := range []string{"ultra", "ra2", "ra2ne", "sasl", "xvp"} {
		t.Run(name, func(t *testing.T) {
			yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desktops
      address: "127.0.0.1:0"
      kind: vnc
      vnc: {upstream: screens, security_types: [%s]}
upstreams:
  - name: screens
    endpoints: [{address: 127.0.0.1:5900}]
`, name)
			_, err := config.Parse([]byte(yaml))
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if !strings.Contains(err.Error(), "vendor") {
				t.Errorf("error %q does not say the type is a vendor's own", err)
			}
		})
	}
}

// The client proves the gateway's own password, and the gateway proves
// its own towards the target. The two are not the same secret, which is
// the point: nobody at a viewer learns what opens the desktop.
func TestVNCAuthIsCheckedHereAndAnsweredThere(t *testing.T) {
	tg := startTarget(t, &target{security: []uint8{rfb.SecVNCAuth}, password: "desktop-secret"})
	dir := t.TempDir()
	mine := filepath.Join(dir, "gate.pw")
	theirs := filepath.Join(dir, "target.pw")
	write(t, mine, "gate-secret")
	write(t, theirs, "desktop-secret")
	s, addr := gateway(t, tg, "        security_types: [vncauth]\n"+
		"        password_file: "+mine+"\n        upstream_password_file: "+theirs)

	// The wrong password never reaches the desktop.
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecVNCAuth})
	cl.answer("not-it")
	if ok, _ := cl.result(); ok {
		t.Fatal("a wrong password was accepted")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("a wrong password reached the target: %q", got)
	}

	// The right one opens the session, and the target sees the
	// gateway's credential rather than the client's.
	cl2 := dial(t, addr)
	cl2.version(rfb.V38)
	cl2.offered()
	cl2.write([]byte{rfb.SecVNCAuth})
	cl2.answer("gate-secret")
	if ok, why := cl2.result(); !ok {
		t.Fatalf("the right password was refused: %s", why)
	}
	cl2.write(rfb.ClientInit{Shared: true}.Encode())
	if _, err := rfb.ReadServerInit(cl2.c); err != nil {
		t.Fatalf("server init: %v", err)
	}
	waitFor(t, "the refusal of the first attempt", func() bool { return s.Stats().VNCRefused > 0 })
}

// answer reads a vncauth challenge and answers it with password.
func (cl *client) answer(password string) {
	cl.t.Helper()
	challenge := cl.read(rfb.ChallengeSize)
	resp, err := rfb.VNCAuthResponse(challenge, password)
	if err != nil {
		cl.t.Fatal(err)
	}
	cl.write(resp)
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A 3.3 client cannot choose a security type, so it is told one; the
// target's leg is unaffected, which is what terminating both legs buys.
func TestAThreeThreeClientReachesAThreeEightTarget(t *testing.T) {
	tg := startTarget(t, &target{})
	_, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	if v := cl.version(rfb.V33); !v.AtLeast(rfb.V38) {
		t.Fatalf("the gateway announced %s", v)
	}
	// Four bytes naming the one type, not a list.
	got := binary.BigEndian.Uint32(cl.read(4))
	if got != rfb.SecNone {
		t.Fatalf("told %d, want none", got)
	}
	// 3.3 has no security result for the none type.
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	si, err := rfb.ReadServerInit(cl.c)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if si.Name == "" {
		t.Error("no desktop name reached the 3.3 client")
	}
}

// A target that speaks 3.3 is reached by a 3.8 client, which is the
// same trick in the other direction.
func TestAThreeEightClientReachesAThreeThreeTarget(t *testing.T) {
	tg := startTarget(t, &target{version: rfb.V33, desktop: "old-kit"})
	_, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	si := cl.open(true)
	if si.Name != "old-kit" {
		t.Errorf("desktop %q, want old-kit", si.Name)
	}
}

// view_only is a promise about the desktop: what drives it is dropped,
// and what only describes what to send is not.
func TestViewOnlyDropsWhatDrivesTheDesktop(t *testing.T) {
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [none]\n        view_only: true")
	cl := dial(t, addr)
	cl.open(true)

	key := []byte{4, 1, 0, 0, 0, 0, 0, 'A'}
	pointer := []byte{5, 1, 0, 10, 0, 20}
	cut := append([]byte{6, 0, 0, 0, 0, 0, 0, 3}, []byte("abc")...)
	// A framebuffer update request only asks for pixels.
	update := []byte{3, 0, 0, 0, 0, 0, 4, 0, 3, 0}
	cl.write(key)
	cl.write(pointer)
	cl.write(cut)
	cl.write(update)

	if !tg.waitSeen(update) {
		t.Fatalf("an update request did not reach the target: %v", tg.seen())
	}
	for what, msg := range map[string][]byte{"key": key, "pointer": pointer, "cut text": cut} {
		if bytes.Contains(tg.seen(), msg) {
			t.Errorf("a %s event reached the desktop of a view_only session", what)
		}
	}
	waitFor(t, "the dropped messages to be counted", func() bool { return s.Stats().VNCRefused >= 3 })
}

// A message a gateway cannot frame cannot be dropped selectively
// either, so a view_only session ends rather than the promise breaking.
func TestAnUnframeableMessageEndsAViewOnlySession(t *testing.T) {
	tg := startTarget(t, &target{})
	_, addr := gateway(t, tg, "        security_types: [none]\n        view_only: true")
	cl := dial(t, addr)
	cl.open(true)
	cl.read(len(tg.shown))
	// 250 is a vendor extension whose length this gateway cannot know.
	cl.write([]byte{250, 0, 0, 0})
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(cl.c); err != nil && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("read: %v", err)
	}
	// The session is over rather than the message being guessed at.
	if _, err := cl.c.Read(make([]byte, 1)); err == nil {
		t.Error("the session outlived a message the gateway could not frame")
	}
}

// The recording holds what the desktop showed, and says what it is: a
// protocol stream, not a terminal.
func TestTheRecordingHoldsTheStream(t *testing.T) {
	dir := t.TempDir()
	tg := startTarget(t, &target{desktop: "lathe-hmi", shown: []byte("PIXELS-FOR-THE-RECORD")})
	s, addr := gateway(t, tg, "        security_types: [none]\n        recording: {directory: "+dir+"}")
	cl := dial(t, addr)
	cl.open(true)
	cl.read(len(tg.shown))
	_ = cl.c.Close()

	waitFor(t, "the recording to be finished", func() bool { return s.Stats().VNCRecorded == 1 })
	files, _ := filepath.Glob(filepath.Join(dir, "*.rfb.cast"))
	if len(files) != 1 {
		t.Fatalf("%d recordings, want 1", len(files))
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"PIXELS-FOR-THE-RECORD", "rfb-server-to-client", "lathe-hmi", "1024"} {
		if !strings.Contains(text, want) {
			t.Errorf("the recording does not carry %q:\n%s", want, text)
		}
	}
}

// A client outside allow_clients never reaches the handshake.
func TestAClientOutsideTheAllowListIsRefused(t *testing.T) {
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [none]\n        allow_clients: [10.99.0.0/16]")
	cl := dial(t, addr)
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(cl.c); err == nil && len(b) != 0 {
		t.Errorf("a refused client was spoken to: %q", b)
	}
	waitFor(t, "the rejection to be counted", func() bool { return s.Stats().VNCRejected > 0 })
}

// The second factor is checked before the target is dialled, and the
// code arrives the only way RFB allows: the plain credential inside
// VeNCrypt's TLS.
func TestTheFactorIsCheckedBeforeTheTargetIsDialled(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "gate.test")
	file, secret := enrol(t, "alice")
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, fmt.Sprintf(
		"        security_types: [vencrypt]\n"+
			"        vencrypt_subtypes: [x509-plain]\n"+
			"        mfa: {file: %s}\n"+
			"      tls: {certificates: [{cert_file: %s, key_file: %s}]}", file, cert, key))

	// A wrong code: the desktop is never dialled.
	inner := dial(t, addr).vencrypt(cert)
	if _, err := inner.Write(rfb.Plain("alice", "000000")); err != nil {
		t.Fatal(err)
	}
	ok, _, err := rfb.ReadSecurityResult(inner, rfb.V38)
	if err == nil && ok {
		t.Fatal("a wrong code was accepted")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("a wrong code reached the target: %q", got)
	}
	waitFor(t, "the failure to be counted", func() bool { return s.Stats().VNCMFAFailed == 1 })

	// The right one opens the session.
	inner2 := dial(t, addr).vencrypt(cert)
	if _, err := inner2.Write(rfb.Plain("alice", totp(t, secret))); err != nil {
		t.Fatal(err)
	}
	ok, why, err := rfb.ReadSecurityResult(inner2, rfb.V38)
	if err != nil || !ok {
		t.Fatalf("the right code was refused: %v %q", err, why)
	}
	if _, err := inner2.Write(rfb.ClientInit{Shared: true}.Encode()); err != nil {
		t.Fatal(err)
	}
	si, err := rfb.ReadServerInit(inner2)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if si.Name == "" {
		t.Error("no desktop name arrived")
	}
	waitFor(t, "the factor to be counted", func() bool { return s.Stats().VNCMFAOK == 1 })
}

// A name with no enrolment cannot decline the factor by not having one.
func TestAnUnenrolledNameIsRefused(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "gate.test")
	file, _ := enrol(t, "alice")
	tg := startTarget(t, &target{})
	_, addr := gateway(t, tg, fmt.Sprintf(
		"        security_types: [vencrypt]\n"+
			"        vencrypt_subtypes: [x509-plain]\n"+
			"        mfa: {file: %s}\n"+
			"      tls: {certificates: [{cert_file: %s, key_file: %s}]}", file, cert, key))
	inner := dial(t, addr).vencrypt(cert)
	if _, err := inner.Write(rfb.Plain("mallory", "123456")); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := rfb.ReadSecurityResult(inner, rfb.V38); err == nil && ok {
		t.Fatal("an unenrolled name was accepted")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("an unenrolled name reached the target: %q", got)
	}
}

// vencrypt negotiates VeNCrypt up to the point where the credential is
// sent, and returns the TLS connection it is sent inside.
func (cl *client) vencrypt(caFile string) net.Conn {
	cl.t.Helper()
	cl.version(rfb.V38)
	list := cl.offered()
	if !contains(list, rfb.SecVeNCrypt) {
		cl.t.Fatalf("vencrypt was not offered: %v", list)
	}
	cl.write([]byte{rfb.SecVeNCrypt})
	v, err := rfb.ReadVeNCryptVersion(cl.c)
	if err != nil {
		cl.t.Fatalf("vencrypt version: %v", err)
	}
	if v.Major != 0 || v.Minor != 2 {
		cl.t.Fatalf("vencrypt %d.%d, want 0.2", v.Major, v.Minor)
	}
	cl.write(rfb.VeNCryptVersion(rfb.VeNCrypt02))
	if ack := cl.read(1); ack[0] != 0 {
		cl.t.Fatalf("the gateway refused the vencrypt version: %d", ack[0])
	}
	subs, err := rfb.ReadSubtypes(cl.c)
	if err != nil {
		cl.t.Fatalf("subtypes: %v", err)
	}
	var found bool
	for _, s := range subs {
		if s == rfb.VeNCryptX509Plain {
			found = true
		}
	}
	if !found {
		cl.t.Fatalf("x509-plain was not offered: %v", subs)
	}
	cl.write(binary.BigEndian.AppendUint32(nil, rfb.VeNCryptX509Plain))
	if go1 := cl.read(1); go1[0] != 1 {
		cl.t.Fatalf("the gateway did not start TLS: %d", go1[0])
	}
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(caFile) //nolint:gosec // the test wrote this path
	if err != nil {
		cl.t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		cl.t.Fatal("the test certificate did not parse")
	}
	tc := tls.Client(cl.c, &tls.Config{ServerName: "gate.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		cl.t.Fatalf("tls: %v", err)
	}
	return tc
}

func enrol(t *testing.T, user string) (string, string) {
	t.Helper()
	secret, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mfa")
	if err := os.WriteFile(path, []byte(user+":"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, secret
}

func totp(t *testing.T, secret string) string {
	t.Helper()
	raw, err := mfa.ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	c, err := mfa.Code(raw, mfa.Counter(time.Now(), 30*time.Second), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
