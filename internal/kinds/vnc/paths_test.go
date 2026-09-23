package vnc_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rfb"
	"github.com/rom/xproxy/internal/testutil"
)

// The ways the session can be encrypted: the listener's own TLS, the
// anonymous TLS security type, VeNCrypt towards the target, and an SSH
// tunnel to it.

// serverTLS builds the certificate both legs use in these tests.
func serverTLS(t *testing.T, host string) (certFile, keyFile string, cfg *tls.Config, pool *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile = testutil.WriteCert(t, dir, host)
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(certFile) //nolint:gosec // the test wrote this path
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the test certificate did not parse")
	}
	return certFile, keyFile, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, pool
}

// tls_mode: wrap makes the socket itself TLS, which is what a viewer
// reaching an stunnel-wrapped port expects.
func TestWrapModeSpeaksRFBInsideTLS(t *testing.T) {
	cert, key, _, pool := serverTLS(t, "gate.test")
	tg := startTarget(t, &target{desktop: "wrapped"})
	_, addr := gateway(t, tg, fmt.Sprintf(
		"        security_types: [none]\n        tls_mode: wrap\n"+
			"      tls: {certificates: [{cert_file: %s, key_file: %s}]}", cert, key))
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	tc := tls.Client(raw, &tls.Config{ServerName: "gate.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	cl := &client{t: t, c: tc}
	if si := cl.open(true); si.Name != "wrapped" {
		t.Errorf("desktop %q, want wrapped", si.Name)
	}
}

// A port is TLS from the first byte or RFB from the first byte, and
// asking for both is a configuration error rather than two layers.
func TestWrapModeAndVeNCryptAreRefusedTogether(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "gate.test")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: desktops
      address: "127.0.0.1:0"
      kind: vnc
      vnc: {upstream: screens, security_types: [vencrypt], tls_mode: wrap}
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
upstreams:
  - name: screens
    endpoints: [{address: 127.0.0.1:5900}]
`, cert, key)
	_, err := config.Parse([]byte(yaml))
	if err == nil {
		t.Fatal("wrap with vencrypt was accepted")
	}
	if !strings.Contains(err.Error(), "two encryptions") {
		t.Errorf("error %q does not explain the conflict", err)
	}
}

// Security type 18 is anonymous TLS with a second negotiation inside
// it. It is old and weak, but an estate that has it should reach its
// desktops through the gateway rather than around it.
func TestTheAnonymousTLSTypeCarriesASecondNegotiation(t *testing.T) {
	cert, key, _, pool := serverTLS(t, "gate.test")
	tg := startTarget(t, &target{desktop: "anon"})
	_, addr := gateway(t, tg, fmt.Sprintf(
		"        security_types: [tls]\n"+
			"      tls: {certificates: [{cert_file: %s, key_file: %s}]}", cert, key))
	cl := dial(t, addr)
	cl.version(rfb.V38)
	if list := cl.offered(); !contains(list, rfb.SecTLS) {
		t.Fatalf("the tls type was not offered: %v", list)
	}
	cl.write([]byte{rfb.SecTLS})
	tc := tls.Client(cl.c, &tls.Config{ServerName: "gate.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	inner := &client{t: t, c: tc}
	// Inside the tunnel, a second security list. With no password
	// configured, none is all there is to offer.
	if list := inner.offered(); len(list) != 1 || list[0] != rfb.SecNone {
		t.Fatalf("inner list %v, want just none", list)
	}
	inner.write([]byte{rfb.SecNone})
	if ok, why := inner.result(); !ok {
		t.Fatalf("the gateway refused: %s", why)
	}
	inner.write(rfb.ClientInit{Shared: true}.Encode())
	si, err := rfb.ReadServerInit(tc)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	if si.Name != "anon" {
		t.Errorf("desktop %q, want anon", si.Name)
	}
}

// The target's leg gets VeNCrypt of its own, with the certificate
// checked against a pinned CA: an unchecked tunnel to the desktop would
// encrypt without saying who was at the other end.
func TestVeNCryptTowardsTheTarget(t *testing.T) {
	cert, _, srvTLS, _ := serverTLS(t, "target.test")
	tg := startTarget(t, &target{desktop: "encrypted-kit", security: []uint8{rfb.SecVeNCrypt}, serverTLS: srvTLS})
	s, addr := gateway(t, tg, "        security_types: [none]\n"+
		"        upstream_tls_mode: vencrypt\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: target.test}")
	cl := dial(t, addr)
	if si := cl.open(true); si.Name != "encrypted-kit" {
		t.Errorf("desktop %q, want encrypted-kit", si.Name)
	}
	if got := cl.read(len(tg.shown)); string(got) != string(tg.shown) {
		t.Errorf("the stream did not come through the tunnel: %q", got)
	}
	if sn := s.Stats(); sn.VNCSessions != 1 {
		t.Errorf("vnc_sessions %d, want 1", sn.VNCSessions)
	}
}

// A target offering nothing this gateway can complete is not reached at
// all, rather than reached with something weaker.
func TestATargetOfferingNothingUsableIsNotReached(t *testing.T) {
	// vncauth with no upstream password: there is nothing to answer
	// the challenge with.
	tg := startTarget(t, &target{security: []uint8{rfb.SecVNCAuth}, password: "desktop-secret"})
	_, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecNone})
	if ok, why := cl.result(); !ok {
		t.Fatalf("the client's own leg was refused: %s", why)
	}
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	// No ServerInit follows, because there is no session behind it.
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := rfb.ReadServerInit(cl.c); err == nil {
		t.Error("a session opened against a target the gateway could not authenticate to")
	}
}

// A 3.3 client cannot be told to use VeNCrypt: the version has no way
// to name it. It is refused in the form 3.3 understands rather than
// left waiting.
func TestAThreeThreeClientIsRefusedWhenOnlyVeNCryptIsOffered(t *testing.T) {
	cert, key, _, _ := serverTLS(t, "gate.test")
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, fmt.Sprintf(
		"        security_types: [vencrypt]\n"+
			"      tls: {certificates: [{cert_file: %s, key_file: %s}]}", cert, key))
	cl := dial(t, addr)
	cl.version(rfb.V33)
	// 3.3 says a failure as a four byte zero and then a reason.
	if code := binary.BigEndian.Uint32(cl.read(4)); code != rfb.SecInvalid {
		t.Fatalf("told security type %d, want the invalid marker", code)
	}
	why, err := rfb.ReadString(cl.c, rfb.MaxReason)
	if err != nil {
		t.Fatalf("reason: %v", err)
	}
	if !strings.Contains(why, "3.3") {
		t.Errorf("reason %q does not say what the trouble is", why)
	}
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().VNCRefused > 0 })
}

// The gateway reaches the desktop through an SSH connection it makes
// itself, so RFB never crosses the network in clear even though the VNC
// server speaks none of it.
func TestTheTargetIsReachedThroughSSH(t *testing.T) {
	dir := t.TempDir()
	tg := startTarget(t, &target{desktop: "tunnelled"})
	keyFile, hostSigner := sshKeys(t, dir)
	host := startSSHHost(t, hostSigner, tg.addr())
	known := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("%s %s", host.addr(),
		strings.TrimSpace(string(cssh.MarshalAuthorizedKey(hostSigner.PublicKey()))))
	if err := os.WriteFile(known, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The pool names the SSH host; the VNC server is reached from
	// there, on the loopback address only it can see.
	_, addr := gatewayFor(t, host.addr(), fmt.Sprintf(
		"        security_types: [none]\n"+
			"        ssh: {user: gate, key_file: %s, known_hosts: %s, address: %s, target: %s}",
		keyFile, known, host.addr(), tg.addr()))
	cl := dial(t, addr)
	if si := cl.open(true); si.Name != "tunnelled" {
		t.Errorf("desktop %q, want tunnelled", si.Name)
	}
	if got := cl.read(len(tg.shown)); string(got) != string(tg.shown) {
		t.Errorf("the stream did not come through the tunnel: %q", got)
	}
	if n := host.channels(); n != 1 {
		t.Errorf("%d channels through the tunnel, want 1", n)
	}
}

// A host key that is not in known_hosts is not connected to: an
// unpinned tunnel authenticates nothing, which is the whole reason for
// the tunnel.
func TestAnUnpinnedSSHHostIsNotReached(t *testing.T) {
	dir := t.TempDir()
	tg := startTarget(t, &target{})
	keyFile, hostSigner := sshKeys(t, dir)
	host := startSSHHost(t, hostSigner, tg.addr())
	// known_hosts names a different key for this address.
	_, otherSigner := sshKeys(t, filepath.Join(dir, "other"))
	known := filepath.Join(dir, "known_hosts")
	line := fmt.Sprintf("%s %s", host.addr(),
		strings.TrimSpace(string(cssh.MarshalAuthorizedKey(otherSigner.PublicKey()))))
	if err := os.WriteFile(known, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, addr := gatewayFor(t, host.addr(), fmt.Sprintf(
		"        security_types: [none]\n"+
			"        ssh: {user: gate, key_file: %s, known_hosts: %s, address: %s, target: %s}",
		keyFile, known, host.addr(), tg.addr()))
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecNone})
	cl.result()
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := rfb.ReadServerInit(cl.c); err == nil {
		t.Error("the gateway tunnelled through an unpinned host")
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the desktop was reached anyway: %q", got)
	}
}

// sshKeys writes the key the gateway authenticates with and returns a
// host key for the SSH server to present.
func sshKeys(t *testing.T, dir string) (string, cssh.Signer) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := cssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(der), 0o600); err != nil {
		t.Fatal(err)
	}
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	return path, signer
}

// sshHost is an SSH server that forwards direct-tcpip channels to one
// address, which is what a VNC server behind a jump host looks like.
type sshHost struct {
	ln   net.Listener
	to   string
	open chan struct{}
}

func startSSHHost(t *testing.T, hostKey cssh.Signer, to string) *sshHost {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &sshHost{ln: ln, to: to, open: make(chan struct{}, 8)}
	cfg := &cssh.ServerConfig{
		PublicKeyCallback: func(cssh.ConnMetadata, cssh.PublicKey) (*cssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(hostKey)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.serve(c, cfg)
		}
	}()
	return h
}

func (h *sshHost) addr() string { return h.ln.Addr().String() }

func (h *sshHost) channels() int { return len(h.open) }

func (h *sshHost) serve(c net.Conn, cfg *cssh.ServerConfig) {
	conn, chans, reqs, err := cssh.NewServerConn(c, cfg)
	if err != nil {
		_ = c.Close()
		return
	}
	defer func() { _ = conn.Close() }()
	go cssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			_ = nc.Reject(cssh.UnknownChannelType, "no")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		select {
		case h.open <- struct{}{}:
		default:
		}
		go cssh.DiscardRequests(chReqs)
		go func() {
			defer func() { _ = ch.Close() }()
			up, err := net.DialTimeout("tcp", h.to, 5*time.Second)
			if err != nil {
				return
			}
			defer func() { _ = up.Close() }()
			go func() { _, _ = io.Copy(up, ch) }()
			_, _ = io.Copy(ch, up)
		}()
	}
}
