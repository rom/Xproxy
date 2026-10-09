package imap

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/testutil"
)

// The client's half of the upgrade, which this relay terminates itself: the
// mail client's password is what follows STARTTLS, so the decisions here are
// the ones that decide whether it crosses the network in clear.
//
// Four of them, and each is a refusal an operator would otherwise meet as a
// support call: an upgrade on a listener that has no certificate to terminate
// it with, a command pipelined behind the upgrade (the injection this
// protocol shares with SMTP, where one end reads a line as plaintext and the
// other as ciphertext), a handshake that does not happen, and a second
// upgrade inside the first.

// starttlsRelay is a listener that offers the upgrade, with the pool a client
// needs to verify the certificate it upgrades to.
func starttlsRelay(t *testing.T, serverAddr string) (*proxy.Server, string, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "mail.test")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("the CA did not go into a pool")
	}
	s, addr := relay(t, noTLS+"        tls_mode: starttls\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}\n", serverAddr)
	return s, addr, pool
}

// waitRefused waits for a refusal to be counted under its reason.
//
// The refusal is written on the session's own goroutine, which is still on the
// path after the client has been answered or dropped: reading the counter once
// is reading it before the record exists on a loaded machine.
func waitRefused(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().Refusals["imap"][reason] == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s was not counted: %v", reason, s.Stats().Refusals["imap"])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTheClientsUpgradeIsTerminatedHere: the relay answers STARTTLS itself,
// hands the client its own certificate, and the session carries on inside TLS
// -- the command after the handshake still reaches the server.
func TestTheClientsUpgradeIsTerminatedHere(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr, pool := starttlsRelay(t, srv.addr())

	c := dial(t, addr)
	if g := c.line(); !strings.HasPrefix(g, "* OK") {
		t.Fatalf("greeting: %q", g)
	}
	c.send("a1 STARTTLS")
	if l := c.line(); !strings.HasPrefix(l, "a1 OK") {
		t.Fatalf("STARTTLS was answered %q", l)
	}
	tc := tls.Client(c.c, &tls.Config{RootCAs: pool, ServerName: "mail.test", MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the handshake this relay terminated: %v", err)
	}
	br := bufio.NewReader(tc)
	if _, err := fmt.Fprintf(tc, "a2 NOOP\r\n"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("after the upgrade: %v", err)
		}
		if strings.HasPrefix(l, "a2 ") {
			if !strings.Contains(l, "OK") {
				t.Fatalf("the command inside TLS was answered %q", strings.TrimSpace(l))
			}
			break
		}
	}
	var noop bool
	for _, l := range srv.saw() {
		if strings.Contains(strings.ToUpper(l), "NOOP") {
			noop = true
		}
	}
	if !noop {
		t.Errorf("the command inside TLS did not reach the server: %v", srv.saw())
	}

	// A second upgrade inside the first: there is nothing left to upgrade,
	// and a client that asks is told no rather than left waiting for a
	// handshake that will not come.
	if _, err := fmt.Fprintf(tc, "a3 STARTTLS\r\n"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("after the second STARTTLS: %v", err)
		}
		if strings.HasPrefix(l, "a3 ") {
			if !strings.Contains(l, "NO") {
				t.Errorf("a second STARTTLS was answered %q", strings.TrimSpace(l))
			}
			break
		}
	}
	waitRefused(t, s, "starttls_not_offered")
}

// TestAnUpgradeThisListenerCannotTerminateIsRefused: no certificate, so there
// is no upgrade to offer. The client is told so in its own terms rather than
// being left to guess from a connection that stays in clear.
func TestAnUpgradeThisListenerCannotTerminateIsRefused(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS, srv.addr())

	c := dial(t, addr)
	if g := c.line(); !strings.HasPrefix(g, "* OK") {
		t.Fatalf("greeting: %q", g)
	}
	c.send("a1 STARTTLS")
	if l := c.line(); !strings.HasPrefix(l, "a1 NO") {
		t.Errorf("STARTTLS on a listener with no certificate was answered %q", l)
	}
	waitRefused(t, s, "starttls_not_offered")
}

// TestACommandPipelinedBehindTheUpgradeEndsTheSession: the injection. A
// command sent in the same write as STARTTLS was written before the client
// could have seen the answer, so the client either never meant to protect it
// or is not the client it claims to be. Either way it is not carried.
func TestACommandPipelinedBehindTheUpgradeEndsTheSession(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr, _ := starttlsRelay(t, srv.addr())

	c := dial(t, addr)
	if g := c.line(); !strings.HasPrefix(g, "* OK") {
		t.Fatalf("greeting: %q", g)
	}
	// One write, so both lines are in the relay's buffer when it reads the
	// first: that is what the check is about.
	c.raw("a1 STARTTLS\r\na2 LOGIN someone hunter2\r\n")
	waitRefused(t, s, "starttls_injection")
	for _, l := range srv.saw() {
		if strings.Contains(strings.ToUpper(l), "LOGIN") {
			t.Errorf("the pipelined command was carried: %v", srv.saw())
		}
	}
}

// TestAnUpgradeThatIsNotAHandshakeIsCounted: the client was told to begin
// negotiation and sent something else. The session ends, said as its own
// reason rather than as an idle timeout a quarter of an hour later.
func TestAnUpgradeThatIsNotAHandshakeIsCounted(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr, _ := starttlsRelay(t, srv.addr())

	c := dial(t, addr)
	if g := c.line(); !strings.HasPrefix(g, "* OK") {
		t.Fatalf("greeting: %q", g)
	}
	c.send("a1 STARTTLS")
	if l := c.line(); !strings.HasPrefix(l, "a1 OK") {
		t.Fatalf("STARTTLS was answered %q", l)
	}
	c.raw("GET / HTTP/1.1\r\n\r\n")
	waitRefused(t, s, "starttls_failed")
}
