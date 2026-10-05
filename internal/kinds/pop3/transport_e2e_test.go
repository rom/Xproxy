package pop3

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The transport, which on POP3 is two upgrades rather than one.
//
// STLS (RFC 2595) is an in-protocol upgrade on both legs, and this relay
// answers each of them itself rather than forwarding the command: the
// client's leg is this listener's certificate and the server's leg is this
// relay asking on its own behalf. The reason is the reason every kind here
// gives -- the two legs are two decisions -- and the consequence is that the
// client's upgrade and the upstream's can be configured, and can fail,
// independently.

// pop3TLSYAML is the plaintext listener with a certificate on it, which is
// what tls_mode: starttls needs to have something to offer.
const pop3TLSYAML = `
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: pop3
      tls: {certificates: [{cert_file: %[1]s, key_file: %[2]s}]}
      pop3:
        upstream: servers
%[3]s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %[4]q}]}
`

// tlsRelay is relay with a certificate, and returns the pool a client needs
// to verify it.
func tlsRelay(t *testing.T, section, serverAddr string) (*proxy.Server, string, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "mail.test")
	s := proxytest.Start(t, fmt.Sprintf(pop3TLSYAML, cert, key, section, serverAddr))
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return s, proxytest.Addr(t, s, "mail"), pool
}

// raw writes exactly what it is given, so a test can put two commands in one
// write -- which is the whole of the injection below.
func (c *client) raw(s string) {
	c.t.Helper()
	if _, err := c.c.Write([]byte(s)); err != nil {
		c.t.Fatalf("writing %q: %v", s, err)
	}
}

// starttls upgrades the client's side of an accepted STLS.
func (c *client) starttls(pool *x509.CertPool) {
	c.t.Helper()
	tc := tls.Client(c.c, &tls.Config{ServerName: "mail.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		c.t.Fatalf("the client's handshake: %v", err)
	}
	c.c = tc
	c.br = bufio.NewReader(tc)
}

// drain reads to the end of the connection. It is the signal that a refusal
// which ends the session has happened: the counter moves before the socket
// is closed, so the close is what to wait for rather than a timer that is
// long enough on an idle machine and not under load.
func (c *client) drain() {
	c.t.Helper()
	_ = c.c.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		if _, err := c.br.ReadString('\n'); err != nil {
			return
		}
	}
}

// TestTheUpgradeIsAnsweredHereAndTheSessionCarriesOnInsideIt: the relay
// answers STLS with its own certificate and keeps the session, so everything
// after it is the same relay reading the same protocol over a different
// socket. require_tls is left at its default, which is on, so the login that
// follows is also the proof that the upgrade registered: a plaintext USER
// would have been refused.
func TestTheUpgradeIsAnsweredHereAndTheSessionCarriesOnInsideIt(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr, pool := tlsRelay(t, "        tls_mode: starttls\n", srv.addr())

	c := dial(t, addr)
	c.line() // the greeting, in clear
	c.send("STLS")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("STLS: %q", l)
	}
	c.starttls(pool)

	c.send("USER bob")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("USER inside TLS: %q", l)
	}
	c.send("PASS s3cret")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("PASS inside TLS: %q", l)
	}
	c.send("STAT")
	if l := c.line(); l != "+OK 2 460" {
		t.Fatalf("STAT inside TLS: %q", l)
	}
	// The upgrade is this relay's own: the server never saw STLS, and the
	// credential reached it on the connection the relay opened.
	for _, line := range srv.saw() {
		if strings.EqualFold(line, "STLS") {
			t.Errorf("the upgrade was forwarded:\n%s", strings.Join(srv.saw(), "\n"))
		}
	}
	if s.Stats().POP3Connections == 0 {
		t.Error("the connection was not counted")
	}
}

// TestACommandPipelinedBehindTheUpgradeIsNotCarried is CVE-2011-0411 in
// POP3's spelling: a command written behind STLS travelled in clear, and a
// relay that read it after the handshake would attribute it to the encrypted
// session. Anything already buffered when the upgrade is answered is
// therefore the end of the connection rather than a command.
func TestACommandPipelinedBehindTheUpgradeIsNotCarried(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr, _ := tlsRelay(t, "        tls_mode: starttls\n", srv.addr())

	c := dial(t, addr)
	c.line()
	// Both in one write, which is what puts the second line in the reader's
	// buffer before the first has been answered.
	c.raw("STLS\r\nSTAT\r\n")
	c.drain()

	if s.Stats().Refusals["pop3"]["stls_injection"] == 0 {
		t.Errorf("the pipelined command was not refused: %v", s.Stats().Refusals["pop3"])
	}
	for _, line := range srv.saw() {
		if strings.EqualFold(line, "STAT") {
			t.Errorf("the smuggled command reached the server:\n%s", strings.Join(srv.saw(), "\n"))
		}
	}
}

// TestAnUpgradeThatDoesNotHandshakeEndsTheConnection: the +OK has gone, so
// there is no way back to the plaintext session. A relay that carried on
// would be reading commands a client believes are encrypted.
func TestAnUpgradeThatDoesNotHandshakeEndsTheConnection(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr, _ := tlsRelay(t, "        tls_mode: starttls\n", srv.addr())

	c := dial(t, addr)
	c.line()
	c.send("STLS")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("STLS: %q", l)
	}
	// Not a ClientHello.
	c.raw("STAT\r\n")
	c.drain()

	if s.Stats().Refusals["pop3"]["stls_failed"] == 0 {
		t.Errorf("the failed handshake was not counted: %v", s.Stats().Refusals["pop3"])
	}
}

// TestTheUpgradeIsRefusedWhereTheListenerDoesNotOfferIt: a listener with no
// certificate has nothing to upgrade with, and says so rather than answering
// +OK and failing afterwards.
func TestTheUpgradeIsRefusedWhereTheListenerDoesNotOfferIt(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS, srv.addr())

	c := dial(t, addr)
	c.line()
	c.send("STLS")
	if l := c.line(); !strings.Contains(l, "stls_not_offered") {
		t.Fatalf("STLS at a listener without a certificate: %q", l)
	}
}

// TestTheUpstreamLegIsUpgradedByTheRelayItself: upstream_tls_mode: starttls
// means this relay reads the server's greeting, asks for STLS and requires
// the +OK before it handshakes -- all of it before the client has seen
// anything, because the greeting the client gets is the one read inside the
// upgraded connection.
func TestTheUpstreamLegIsUpgradedByTheRelayItself(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "servers.test")
	srv := startServer(t, &fakeServer{tlsCert: cert, tlsKey: key})
	section := "        require_tls: false\n" +
		"        upstream_tls_mode: starttls\n" +
		"        upstream_tls: {server_name: servers.test, ca_file: " + ca.Path + ", min_version: \"1.2\"}\n"
	_, addr := relay(t, section, srv.addr())

	c := dial(t, addr)
	// The greeting the client gets is the one the server sent before the
	// upgrade, which is the only one it sends -- and on POP3 it is also the
	// APOP challenge, so losing it would cost the listener that mechanism.
	greeting := c.line()
	if !strings.HasPrefix(greeting, "+OK") || !strings.Contains(greeting, "<") {
		t.Fatalf("greeting: %q", greeting)
	}
	c.send("USER bob")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("USER: %q", l)
	}
	c.send("PASS s3cret")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("PASS: %q", l)
	}
	c.send("STAT")
	if l := c.line(); l != "+OK 2 460" {
		t.Fatalf("STAT: %q", l)
	}
	saw := srv.saw()
	if len(saw) == 0 || !strings.EqualFold(saw[0], "STLS") {
		t.Fatalf("the relay did not upgrade the server's leg:\n%s", strings.Join(saw, "\n"))
	}
	if !srv.wasUpgraded() {
		t.Error("the server's connection was never inside TLS")
	}
}

// TestAnUpstreamThatRefusesTheUpgradeIsNotTalkedToInPlaintext: the fallback
// a mail client would make here is the one that matters, because the
// password is what follows. There is no fallback: the session ends before
// the client is greeted.
func TestAnUpstreamThatRefusesTheUpgradeIsNotTalkedToInPlaintext(t *testing.T) {
	srv := startServer(t, &fakeServer{}) // no certificate: STLS is answered -ERR
	s, addr := relay(t, "        require_tls: false\n        upstream_tls_mode: starttls\n", srv.addr())

	c := dial(t, addr)
	c.drain()
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().Refusals["pop3"]["upstream_failed"] == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the refused upgrade was not counted: %v", s.Stats().Refusals["pop3"])
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, line := range srv.saw() {
		if strings.EqualFold(line, "USER") || strings.HasPrefix(strings.ToUpper(line), "USER ") {
			t.Errorf("the session continued in clear:\n%s", strings.Join(srv.saw(), "\n"))
		}
	}
}

// TestThePolicyIsAskedAboutTheAddressBeforeAServerIsDialled: the connect
// decision is taken before anything is opened towards the mailbox server, so
// a refused client costs the estate one accept and nothing else. On this
// protocol that is also an anti-enumeration property: the greeting carries
// the APOP timestamp, and a client that never sees one learns nothing about
// what is behind the listener.
func TestThePolicyIsAskedAboutTheAddressBeforeAServerIsDialled(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s := proxytest.Start(t, fmt.Sprintf(pop3YAML, noTLS, srv.addr())+`authorization:
  rules:
    - {name: elsewhere, allow: true, networks: ["192.0.2.0/24"], actions: [connect]}
`)
	c := dial(t, proxytest.Addr(t, s, "mail"))
	c.drain()
	if n := len(srv.saw()); n != 0 {
		t.Errorf("a refused client reached the server:\n%s", strings.Join(srv.saw(), "\n"))
	}
	if s.Stats().Refusals["pop3"]["authorization"] == 0 {
		t.Errorf("the refusal was not counted: %v", s.Stats().Refusals["pop3"])
	}
}

// TestThePolicyIsAskedAboutTheNameTheClientClaims: a USER names an identity
// the client has not proved yet, which is exactly why it is worth asking
// about -- the policy decides before the name and its password reach a
// server that would check them, so a name nobody has a rule for is not a
// login attempt anywhere.
func TestThePolicyIsAskedAboutTheNameTheClientClaims(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s := proxytest.Start(t, fmt.Sprintf(pop3YAML, noTLS, srv.addr())+`authorization:
  rules:
    # In order: the name nobody may use, then the door everything else comes
    # through. The connection itself has no name to match, so the first rule
    # cannot answer it and the second does.
    - {name: nomallory, allow: false, users: [mallory], actions: [connect]}
    - {name: door, allow: true, networks: ["127.0.0.0/8"], actions: [connect]}
`)
	addr := proxytest.Addr(t, s, "mail")

	c := dial(t, addr)
	c.line()
	c.send("USER mallory")
	if l := c.line(); !strings.Contains(l, "authorization") {
		t.Fatalf("a user the policy refuses: %q", l)
	}
	for _, line := range srv.saw() {
		if strings.Contains(line, "mallory") {
			t.Errorf("the name reached the server:\n%s", strings.Join(srv.saw(), "\n"))
		}
	}

	// The same listener carries the name the second rule covers, so what the
	// first rule refused is the user and not the policy being on at all.
	c2 := dial(t, addr)
	c2.line()
	c2.send("USER bob")
	if l := c2.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("a user the policy allows: %q", l)
	}
}
