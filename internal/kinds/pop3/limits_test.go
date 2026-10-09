package pop3

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sesslimit"
)

// The bounds and the credential policy, each refusal in the terms the
// protocol has for it: an -ERR the mail client shows the person using it, or
// nothing at all where the listener would rather tell a prober nothing.
//
// These are the refusals an operator sets and never sees again until a
// Monday morning, which is exactly why each one needs a test that says what
// it does: a bound that silently stopped bounding, or a user list that
// admitted a name it was never given, is not visible from a working mailbox.

// waitRefusal waits for a refusal to be counted under its reason.
//
// The record is written on the session's own goroutine, which is still on the
// path after the client has been answered or dropped: reading the counter once
// reads it before the record exists on a loaded machine.
func waitRefusal(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().Refusals["pop3"][reason] == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s was not counted: %v", reason, s.Stats().Refusals["pop3"])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestWhatIsRefusedBeforeACredentialIsRead: the four bounds that act before
// the session is a session at all.
func TestWhatIsRefusedBeforeACredentialIsRead(t *testing.T) {
	t.Run("a client past its rate", func(t *testing.T) {
		srv := startServer(t, &fakeServer{})
		s, addr := relay(t, noTLS+"        rate_limit: 1\n        rate_burst: 1\n", srv.addr())
		// The first connection spends the only token. The second is refused
		// before the relay dials the server on its behalf.
		c := dial(t, addr)
		if g := c.line(); !strings.HasPrefix(g, "+OK") {
			t.Fatalf("greeting: %q", g)
		}
		_ = dial(t, addr)
		waitRefusal(t, s, "rate_limited")
	})

	t.Run("a second session where one is allowed", func(t *testing.T) {
		srv := startServer(t, &fakeServer{})
		s, addr := relay(t, noTLS+"        max_sessions: 1\n", srv.addr())
		c := dial(t, addr)
		if g := c.line(); !strings.HasPrefix(g, "+OK") {
			t.Fatalf("greeting: %q", g)
		}
		_ = dial(t, addr)
		waitRefusal(t, s, sesslimit.ReasonTooMany)
	})

	t.Run("a greeting from the server that is not one", func(t *testing.T) {
		// The server's own greeting is the first thing this relay reads, and
		// a client is never greeted on the strength of something that is not
		// a POP3 reply: the far end is not the server it was configured to be.
		srv := startServer(t, &fakeServer{greeting: "SSH-2.0-OpenSSH_9.6"})
		s, addr := relay(t, noTLS, srv.addr())
		c := dial(t, addr)
		if _, err := c.br.ReadString('\n'); err == nil {
			t.Error("the client was greeted anyway")
		}
		waitRefusal(t, s, "malformed_greeting")
	})

	t.Run("a command line past the bound", func(t *testing.T) {
		srv := startServer(t, &fakeServer{})
		s, addr := relay(t, noTLS+"        max_line_bytes: 512\n", srv.addr())
		c := dial(t, addr)
		if g := c.line(); !strings.HasPrefix(g, "+OK") {
			t.Fatalf("greeting: %q", g)
		}
		c.send("USER " + strings.Repeat("a", 600))
		if l := c.line(); !strings.Contains(l, "line too long") {
			t.Errorf("an overlong command was answered %q", l)
		}
		waitRefusal(t, s, "line_too_long")
		if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "aaaa") {
			t.Errorf("the overlong line reached the server: %q", seen)
		}
	})

	t.Run("a command that is not one", func(t *testing.T) {
		srv := startServer(t, &fakeServer{})
		s, addr := relay(t, noTLS, srv.addr())
		c := dial(t, addr)
		if g := c.line(); !strings.HasPrefix(g, "+OK") {
			t.Fatalf("greeting: %q", g)
		}
		c.send("1337 h4x")
		if l := c.line(); !strings.HasPrefix(l, "-ERR") {
			t.Errorf("a command whose name is not a name was answered %q", l)
		}
		waitRefusal(t, s, "malformed_command")
	})
}

// TestTheCredentialPolicyAdmitsOnlyWhatItWasTold: the mechanism and the user,
// which on this protocol are the whole of the admission decision -- there is
// nothing else in POP3 to key one on.
func TestTheCredentialPolicyAdmitsOnlyWhatItWasTold(t *testing.T) {
	// USER and APOP are allowed, SASL is not, and alice is the only name.
	const section = noTLS + "        mechanisms: [user, apop]\n        users: [alice]\n"

	t.Run("a name that is not on the list", func(t *testing.T) {
		srv := startServer(t, &fakeServer{})
		s, addr := relay(t, section, srv.addr())
		c := dial(t, addr)
		if g := c.line(); !strings.HasPrefix(g, "+OK") {
			t.Fatalf("greeting: %q", g)
		}
		c.send("USER bob")
		if l := c.line(); !strings.Contains(l, "user_not_allowed") {
			t.Errorf("USER bob was answered %q", l)
		}
		// And the name never reached the server, which is the point of
		// deciding here rather than letting the mailbox decide.
		if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "bob") {
			t.Errorf("the refused name reached the server: %q", seen)
		}
		waitRefusal(t, s, "user_not_allowed")
	})

	t.Run("APOP for a name that is not on the list", func(t *testing.T) {
		// The same list governs the digest exchange, which carries the name
		// in its own place: a policy that read only USER would be bypassed by
		// a client that never sends one.
		srv := startServer(t, &fakeServer{})
		s, addr := relay(t, section, srv.addr())
		c := dial(t, addr)
		if g := c.line(); !strings.HasPrefix(g, "+OK") {
			t.Fatalf("greeting: %q", g)
		}
		c.send("APOP bob c4c9334bac560ecc979e58001b3e22fb")
		if l := c.line(); !strings.Contains(l, "user_not_allowed") {
			t.Errorf("APOP for bob was answered %q", l)
		}
		waitRefusal(t, s, "user_not_allowed")
	})

	t.Run("a mechanism that was not allowed", func(t *testing.T) {
		srv := startServer(t, &fakeServer{})
		s, addr := relay(t, section, srv.addr())
		c := dial(t, addr)
		if g := c.line(); !strings.HasPrefix(g, "+OK") {
			t.Fatalf("greeting: %q", g)
		}
		c.send("AUTH PLAIN")
		if l := c.line(); !strings.Contains(l, "mechanism_not_allowed") {
			t.Errorf("AUTH PLAIN was answered %q", l)
		}
		waitRefusal(t, s, "mechanism_not_allowed")
	})

	t.Run("the SASL line with nothing left on it", func(t *testing.T) {
		// A capability list that still said SASL would offer the client a
		// choice of nothing: every mechanism on the server's line is one
		// this listener refuses, so the line goes rather than being sent
		// empty.
		srv := startServer(t, &fakeServer{})
		s, addr := relay(t, section, srv.addr())
		c := dial(t, addr)
		if g := c.line(); !strings.HasPrefix(g, "+OK") {
			t.Fatalf("greeting: %q", g)
		}
		c.send("CAPA")
		var lines []string
		for i := 0; i < 16; i++ {
			l := c.line()
			if l == "." {
				break
			}
			lines = append(lines, l)
		}
		for _, l := range lines {
			if strings.HasPrefix(strings.ToUpper(l), "SASL") {
				t.Errorf("the capability list still offers SASL: %v", lines)
			}
		}
		if s.Stats().POP3CapabilitiesStripped == 0 {
			t.Error("nothing was recorded as stripped from the list")
		}
	})
}

// TestADenyResponseOfCloseSaysNothing: a listener that would rather tell a
// prober nothing at all drops the connection instead of naming the reason.
// The refusal is still recorded, which is where an operator reads it.
func TestADenyResponseOfCloseSaysNothing(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS+"        users: [alice]\n        deny_response: close\n", srv.addr())
	c := dial(t, addr)
	if g := c.line(); !strings.HasPrefix(g, "+OK") {
		t.Fatalf("greeting: %q", g)
	}
	c.send("USER bob")
	if l, err := c.br.ReadString('\n'); err == nil {
		t.Errorf("the refusal was announced as %q", strings.TrimSpace(l))
	}
	waitRefusal(t, s, "user_not_allowed")
}

// TestAReplyFromTheServerThatIsNotOneEndsTheSession: the far end stopped
// speaking the protocol. Carrying the line on would hand the client bytes no
// POP3 client can place; the session ends and says why.
func TestAReplyFromTheServerThatIsNotOneEndsTheSession(t *testing.T) {
	srv := startServer(t, &fakeServer{garbage: map[string]bool{"USER": true}})
	s, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	if g := c.line(); !strings.HasPrefix(g, "+OK") {
		t.Fatalf("greeting: %q", g)
	}
	c.send("USER alice")
	if l, err := c.br.ReadString('\n'); err == nil {
		t.Errorf("the client was handed %q", strings.TrimSpace(l))
	}
	waitRefusal(t, s, "malformed_reply")
}

// TestTheSessionEndsOnQuitAndADeletionIsCounted: QUIT is the one command whose
// reply is the last thing on the connection, and DELE is the one that changes
// the mailbox -- an operator reviewing a session wants to know it happened.
func TestTheSessionEndsOnQuitAndADeletionIsCounted(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	if g := c.line(); !strings.HasPrefix(g, "+OK") {
		t.Fatalf("greeting: %q", g)
	}
	c.send("USER alice")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("USER: %q", l)
	}
	c.send("PASS hunter2")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("PASS: %q", l)
	}
	c.send("DELE 1")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("DELE: %q", l)
	}
	c.send("QUIT")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Errorf("QUIT was answered %q", l)
	}
	// The connection is finished after that reply rather than waiting for a
	// line nobody is going to send.
	if l, err := c.br.ReadString('\n'); err == nil {
		t.Errorf("the session carried on past QUIT: %q", strings.TrimSpace(l))
	}
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().POP3Deletes == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the deletion was not counted")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
