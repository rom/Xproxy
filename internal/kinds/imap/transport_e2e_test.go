package imap

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
)

// The upgrade towards the mailbox server, which this relay performs on its
// own behalf rather than forwarding -- the two legs are two decisions, as
// everywhere else in this project.
//
// That path had no test, and it did not work. `startTLSUpstream` read the
// server's greeting to get to the STARTTLS exchange and discarded it, and the
// relay then waited for a greeting that was never coming: after STARTTLS the
// server carries on in the state it was in, and RFC 3501 has the client
// re-issue CAPABILITY rather than expect a second greeting. Every session on a
// listener with `upstream_tls_mode: starttls` hung until the idle timeout. The
// greeting now comes back from the upgrade, which also keeps the two decisions
// this kind makes on it: the PREAUTH refusal and the capability narrowing.

// upstreamTLS is the section for a listener that upgrades the server's leg.
func upstreamTLS(caFile string) string {
	return "        require_tls: false\n" +
		"        upstream_tls_mode: starttls\n" +
		"        upstream_tls: {server_name: servers.test, ca_file: " + caFile + ", min_version: \"1.2\"}\n"
}

// waitUpgraded waits for the server's side of the handshake to finish.
//
// The client half of a TLS 1.3 handshake can return before the peer has
// processed the client's Finished message, so a flag the server sets after its
// own Handshake returns is not set the instant this relay's handshake is done.
// Waiting for it is the difference between a test that proves the upgrade
// happened and one that passes on an idle machine.
func waitUpgraded(t *testing.T, srv *fakeServer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !srv.wasUpgraded() {
		if time.Now().After(deadline) {
			t.Fatal("the server's connection was never inside TLS")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTheUpstreamLegIsUpgradedByTheRelayItself: the client is greeted with the
// greeting the server sent before the handshake, because that is the only one
// it sends, and the session then runs inside TLS.
func TestTheUpstreamLegIsUpgradedByTheRelayItself(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "servers.test")
	srv := startServer(t, &fakeServer{tlsCert: cert, tlsKey: key})
	s, addr := relay(t, upstreamTLS(ca.Path), srv.addr())

	c := dial(t, addr)
	greeting := c.line()
	if !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting: %q", greeting)
	}
	// The capability narrowing still happens, which is the proof that the
	// greeting reached the policy rather than being passed through from
	// somewhere else: the server offers COMPRESS=DEFLATE and the client is not
	// told about it.
	if strings.Contains(greeting, "COMPRESS=DEFLATE") {
		t.Errorf("the capability list was not narrowed: %q", greeting)
	}
	if s.Stats().IMAPCapabilitiesStripped == 0 {
		t.Error("nothing was stripped from the greeting")
	}

	c.send("a1 CAPABILITY")
	for i := 0; i < 8; i++ {
		if l := c.line(); strings.HasPrefix(l, "a1 ") {
			if !strings.Contains(l, "OK") {
				t.Fatalf("CAPABILITY: %q", l)
			}
			break
		}
	}
	saw := srv.saw()
	if len(saw) == 0 || !strings.Contains(strings.ToUpper(saw[0]), "STARTTLS") {
		t.Fatalf("the relay did not upgrade the server's leg:\n%s", strings.Join(saw, "\n"))
	}
	waitUpgraded(t, srv)
}

// TestAnUpstreamThatRefusesTheUpgradeIsNotTalkedToInPlaintext: the fallback a
// mail client would make here is the one that matters, because the password is
// what follows. There is no fallback -- the session ends before the client is
// greeted at all.
func TestAnUpstreamThatRefusesTheUpgradeIsNotTalkedToInPlaintext(t *testing.T) {
	srv := startServer(t, &fakeServer{}) // no certificate: STARTTLS is answered NO
	s, addr := relay(t, "        require_tls: false\n        upstream_tls_mode: starttls\n", srv.addr())

	c := dial(t, addr)
	// Nothing comes back: read to the end of the connection rather than
	// waiting a fixed time, because the close is the signal.
	_ = c.c.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		if _, err := c.br.ReadString('\n'); err != nil {
			break
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().Refusals["imap"]["upstream_failed"] == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the refused upgrade was not counted: %v", s.Stats().Refusals["imap"])
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, line := range srv.saw() {
		if strings.Contains(strings.ToUpper(line), "LOGIN") {
			t.Errorf("the session continued in clear:\n%s", strings.Join(srv.saw(), "\n"))
		}
	}
}

// TestAPreauthGreetingIsStillRefusedAcrossTheUpgrade: the greeting read during
// the upgrade is the one the policy decides on, so the decision that matters
// most about it has to survive being read a step earlier. A PREAUTH greeting
// says the connection is already authenticated when no identity was claimed,
// and a relay that lost it would hand the client an authenticated session
// nobody logged into.
func TestAPreauthGreetingIsStillRefusedAcrossTheUpgrade(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "servers.test")
	srv := startServer(t, &fakeServer{
		greeting: "* PREAUTH IMAP4rev2 already authenticated",
		tlsCert:  cert, tlsKey: key,
	})
	s, addr := relay(t, upstreamTLS(ca.Path), srv.addr())

	c := dial(t, addr)
	if l := c.line(); !strings.HasPrefix(l, "* BYE") {
		t.Fatalf("a PREAUTH greeting from an upgraded leg: %q", l)
	}
	if s.Stats().IMAPPreauthRefused == 0 {
		t.Error("the PREAUTH refusal was not counted")
	}
	// And the upgrade did happen, so the refusal is the policy's and not a
	// failure to connect.
	waitUpgraded(t, srv)
}

// TestTheUpgradeReadsPastUntaggedDataBeforeTheAnswer: a server may send
// untagged responses before the tagged answer, and a relay that took the first
// line as the answer would either refuse a server that was agreeing or
// handshake with one that had not.
func TestTheUpgradeReadsPastUntaggedDataBeforeTheAnswer(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "servers.test")
	srv := startServer(t, &fakeServer{
		untagged: map[string]string{"STARTTLS": "* OK still thinking about it"},
		tlsCert:  cert, tlsKey: key,
	})
	_, addr := relay(t, upstreamTLS(ca.Path), srv.addr())

	c := dial(t, addr)
	if l := c.line(); !strings.HasPrefix(l, "* OK") {
		t.Fatalf("greeting: %q", l)
	}
	waitUpgraded(t, srv)
}
