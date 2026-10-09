package smtp_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The edges of a mail session: the bounds around it, the commands it refuses
// to take in the order they arrived, and what it tells a client when the
// server behind it is not behaving like a mail server.
//
// A relay is the one listener kind where both ends talk, so a refusal has two
// shapes. Towards the client it is a reply code, and the code decides whether
// the message bounces (5xx) or is tried again later (4xx) -- a mail proxy that
// answers 5xx where it meant "not now" loses mail. Towards the upstream it is
// a connection that ends: the proxy will not relay a reply it could not read,
// because that is precisely where the client reads something the proxy did not.

// edgeRelay is a relay whose listener address, listener-level block, smtp
// block and top-level sections are each the test's to write: the settings
// these tests reach for sit in four different places in the file.
func edgeRelay(t *testing.T, addr, listener, section, top, up string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: mail
      address: %q
      kind: smtp
%s
      smtp:
        upstream: mta
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: mta, endpoints: [{address: %q}]}
%s
`, addr, listener, section, up, top))
	return s, proxytest.Addr(t, s, "mail")
}

// relayTo is edgeRelay for the common case: a plain listener on loopback, no
// encryption on either leg, every setting in the smtp block.
func relayTo(t *testing.T, section, up string) (*proxy.Server, string) {
	t.Helper()
	return edgeRelay(t, "127.0.0.1:0", "", section, "", up)
}

// certificate issues one for mail.test and returns the listener block that
// serves it and the pool a client verifies it with.
func certificate(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "mail.test")
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return fmt.Sprintf("      tls: {certificates: [{cert_file: %s, key_file: %s}]}", cert, key), pool
}

// awaitReason waits for a refusal to be counted. The counter is written after
// the client has its answer, so reading it once races the session.
func awaitReason(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.Refusals["smtp"][reason] > 0 },
		"refusals: %v", func() any { return s.Stats().Refusals["smtp"] })
}

func awaitStat(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, format string, arg func() any) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if ok(s.Stats()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(format, arg())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A connection over the bound is told to come back rather than that the mail
// is undeliverable: 421 is the one refusal a sending server retries, and a
// relay at its connection limit has said nothing about the message.
func TestAConnectionOverTheBoundIsToldToTryAgainLater(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	s, addr := relayTo(t, "        max_connections: 1", m.addr())

	held := dialSMTP(t, addr)
	held.expect(220, "the first greeting")

	over := dialSMTP(t, addr)
	code, text := over.reply()
	if code != 421 {
		t.Fatalf("a connection over the bound: got %d (%s), want 421", code, text)
	}
	if !strings.Contains(text, "4.3.2") {
		t.Errorf("the refusal does not carry the enhanced status code: %q", text)
	}
	if _, err := over.br.ReadString('\n'); err == nil {
		t.Error("the connection over the bound was left open")
	}
	awaitReason(t, s, "max_connections")
	if sn := s.Stats(); sn.SMTPRejected == 0 {
		t.Error("the refused connection was not counted as rejected")
	}
	// And the session that held the slot is still usable: the bound turns
	// the new connection away rather than making room for it.
	held.send("EHLO client.test")
	held.expect(250, "ehlo on the held session")
}

// An implicit-TLS listener is the submission-on-465 shape: there is no
// cleartext greeting to upgrade, so a client that opens with a command
// instead of a handshake is answered with nothing at all.
func TestAnImplicitTLSListenerSpeaksTLSFromTheFirstOctet(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	tlsBlock, pool := certificate(t)
	_, addr := edgeRelay(t, "127.0.0.1:0", tlsBlock, "        tls_mode: implicit", "", m.addr())

	c := dialSMTP(t, addr)
	c.starttls(pool)
	c.expect(220, "the greeting inside the handshake")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	// require_tls defaults on for an encrypted listener, and this session
	// already satisfies it: there is no STARTTLS to send.
	c.send("MAIL FROM:<a@client.test>")
	c.expect(250, "mail")
	c.send("QUIT")
	c.expect(221, "quit")

	t.Run("and a client that sends cleartext is not answered", func(t *testing.T) {
		p := dialSMTP(t, addr)
		p.raw("EHLO client.test\r\n")
		if line, err := p.br.ReadString('\n'); err == nil {
			t.Errorf("a cleartext client was answered %q", line)
		}
	})
}

// A refusal reaches the ban ladder whether or not it is worth an alert.
// alert_on_deny is about the security event alone: an operator who turns the
// log down on a listener whose refusals are routine has not asked the relay
// to stop responding to them.
func TestARefusalReachesTheBanLadderWithTheAlertTurnedOff(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	s, addr := edgeRelay(t, "127.0.0.1:0", "", `        allow_clients: ["10.0.0.0/8"]
        alert_on_deny: false`, `bans:
  action: reject
  triggers: [{name: mail, reasons: [smtp_denied], threshold: 1, window: 1m, duration: 1h}]`, m.addr())

	c := dialSMTP(t, addr)
	code, text := c.reply()
	if code != 554 {
		t.Fatalf("an address off the list: got %d (%s), want 554", code, text)
	}
	awaitReason(t, s, "client_not_allowed")
	awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.BansActive >= 1 },
		"the refusal did not reach the ban ladder: %v bans", func() any { return s.Stats().BansActive })
	// Nothing was dialled: the address was answered before the upstream
	// knew a client existed.
	if cmds, _ := m.got(); len(cmds) != 0 {
		t.Errorf("the upstream saw %v", cmds)
	}
}

// In shadow mode a verb this listener does not carry is written down and
// carried anyway, which is how an operator measures a command list before
// turning it on.
func TestAVerbOffTheListIsRecordedRatherThanRefusedInShadowMode(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	s, addr := edgeRelay(t, "127.0.0.1:0", "      policy: {mode: shadow}",
		"        commands: [EHLO, MAIL, RCPT, DATA, QUIT]", "", m.addr())

	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	c.send("NOOP")
	c.expect(250, "a verb off the list in shadow mode")

	awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.WouldRefusals["smtp"]["command_refused"] > 0 },
		"the verb was not recorded: %v", func() any { return s.Stats().WouldRefusals["smtp"] })
	if n := s.Stats().Refusals["smtp"]["command_refused"]; n != 0 {
		t.Errorf("a shadowed listener refused the verb %d times", n)
	}
	var found bool
	for _, e := range s.Shadow().Report() {
		if e.Kind == "smtp" && e.Reason == "command_refused" {
			found = true
			if e.Sample != "NOOP" {
				t.Errorf("the record does not say which verb: %q", e.Sample)
			}
			if e.Listener != "mail" {
				t.Errorf("the record names listener %q", e.Listener)
			}
		}
	}
	if !found {
		t.Errorf("the ledger holds %+v", s.Shadow().Report())
	}
	// And it did reach the upstream, which is the whole point of the mode.
	cmds, _ := m.got()
	if !strings.Contains(strings.Join(cmds, "|"), "NOOP") {
		t.Errorf("the upstream saw %v", cmds)
	}
}

// RSET ends the transaction on both legs, and a verb with no rule of its own
// is passed through with its reply. Both are easy to get wrong in the same
// way: by answering the client out of the proxy's own state and leaving the
// upstream with a transaction nobody will finish.
func TestRSETEndsTheTransactionAndAnOrdinaryVerbIsPassedThrough(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	_, addr := relayTo(t, "", m.addr())

	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	c.send("MAIL FROM:<a@client.test>")
	c.expect(250, "mail")
	c.send("RCPT TO:<b@mta.invalid>")
	c.expect(250, "rcpt")
	c.send("RSET")
	c.expect(250, "rset")
	// The transaction is gone here and not only at the upstream.
	c.send("RCPT TO:<b@mta.invalid>")
	c.expect(503, "rcpt after rset")
	c.send("NOOP")
	c.expect(250, "noop")
	// HELO is relayed as it is: a client that asked for the old greeting
	// gets the old greeting, with no capability list invented for it.
	c.send("HELO client.test")
	caps := c.expect(250, "helo")
	if strings.Contains(caps, "SIZE") || strings.Contains(caps, "-") {
		t.Errorf("a HELO was answered with an EHLO's capability list: %q", caps)
	}
	// And the greeting counts: a transaction may open after it.
	c.send("MAIL FROM:<a@client.test>")
	c.expect(250, "mail after helo")

	cmds, _ := m.got()
	if !strings.Contains(strings.Join(cmds, "|"), "RSET") {
		t.Errorf("RSET did not reach the upstream: %v", cmds)
	}
}

// The transaction state machine, which is the part of SMTP a proxy must hold
// for itself: every one of these refusals is answered without asking the
// upstream, so a client cannot walk a server's state through the relay.
func TestTheTransactionRefusesCommandsOutOfOrder(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	_, addr := relayTo(t, "", m.addr())

	for _, c := range []struct {
		name string
		send []string
		code int
		text string
	}{
		{"mail before a greeting", []string{"MAIL FROM:<a@client.test>"}, 503, "EHLO first"},
		{"a recipient before a sender", []string{"EHLO client.test", "RCPT TO:<b@mta.invalid>"}, 503, "MAIL first"},
		{"a message before either", []string{"EHLO client.test", "DATA"}, 503, "MAIL and RCPT first"},
		{"a second transaction inside the first", []string{"EHLO client.test",
			"MAIL FROM:<a@client.test>", "MAIL FROM:<c@client.test>"}, 503, "already open"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := dialSMTP(t, addr)
			cl.expect(220, "greeting")
			for i, line := range c.send {
				cl.send("%s", line)
				if i < len(c.send)-1 {
					cl.expect(250, line)
					continue
				}
				code, text := cl.reply()
				if code != c.code {
					t.Fatalf("%s: got %d (%s), want %d", line, code, text, c.code)
				}
				if !strings.Contains(text, c.text) {
					t.Errorf("the refusal does not say %q: %q", c.text, text)
				}
			}
		})
	}
}

// A listener that requires authentication refuses the transaction before the
// envelope travels, and one with a message bound refuses the next message
// rather than the connection: a sender with more mail is told to come back.
func TestTheRequirementsAroundATransaction(t *testing.T) {
	t.Run("authentication", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		s, addr := relayTo(t, "        require_auth: true", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		c.expect(250, "ehlo")
		c.send("MAIL FROM:<a@client.test>")
		code, text := c.reply()
		if code != 530 {
			t.Fatalf("mail without authentication: got %d (%s), want 530", code, text)
		}
		awaitReason(t, s, "authentication_required")
		// The envelope did not reach the upstream.
		cmds, _ := m.got()
		if strings.Contains(strings.Join(cmds, "|"), "MAIL") {
			t.Errorf("the envelope travelled anyway: %v", cmds)
		}
	})

	t.Run("messages on one connection", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		_, addr := relayTo(t, "        max_messages: 1", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		c.expect(250, "ehlo")
		for _, want := range []int{250, 421} {
			c.send("MAIL FROM:<a@client.test>")
			code, text := c.reply()
			if code != want {
				t.Fatalf("mail: got %d (%s), want %d", code, text, want)
			}
			if want != 250 {
				if !strings.Contains(text, "too many messages") {
					t.Errorf("the refusal does not say why: %q", text)
				}
				break
			}
			c.send("RCPT TO:<b@mta.invalid>")
			c.expect(250, "rcpt")
			c.send("DATA")
			c.expect(354, "data")
			c.raw("Subject: one\r\n\r\nbody\r\n.\r\n")
			c.expect(250, "message")
		}
	})
}

// What the proxy will not read from a client. Both of these end the session
// rather than refusing one command, because in both cases the reader is at an
// offset inside something it did not understand.
func TestTheLinesTheProxyWillNotReadFromAClient(t *testing.T) {
	t.Run("a line that is not a command", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		s, addr := relayTo(t, "        max_errors: 2", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		// A verb is letters: a line that starts with digits is a reply, and
		// a client that sends a reply is talking to the wrong end.
		c.send("421 4.3.0 upstream failure")
		c.expect(500, "a reply sent as a command")
		c.send("")
		c.expect(500, "an empty command")
		// The second refusal is the last one this session is allowed.
		c.expect(421, "the session ending on too many errors")
		if _, err := c.br.ReadString('\n'); err == nil {
			t.Error("the session was left open after too many errors")
		}
		awaitReason(t, s, "unknown_command")
		if cmds, _ := m.got(); strings.Contains(strings.Join(cmds, "|"), "421") {
			t.Errorf("a line the proxy could not parse reached the upstream: %v", cmds)
		}
	})

	t.Run("a line ended by LF alone", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		s, addr := relayTo(t, "", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.raw("NOOP\n")
		code, text := c.reply()
		if code != 500 {
			t.Fatalf("a bare newline: got %d (%s), want 500", code, text)
		}
		if !strings.Contains(text, "CRLF") {
			t.Errorf("the refusal does not say what was wrong: %q", text)
		}
		if _, err := c.br.ReadString('\n'); err == nil {
			t.Error("the session went on after a line the two ends would read differently")
		}
		awaitReason(t, s, "bare_newline")
		awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.SMTPProtocolErrors > 0 },
			"the bare newline was not counted as a protocol error", func() any { return nil })
	})
}

// A message the proxy will not carry to the end. In both cases the upstream
// connection is dropped without the terminator, so the half of the message
// already written is never delivered as a whole one.
func TestAMessageTheProxyWillNotCarryIsNotDelivered(t *testing.T) {
	t.Run("a body line over the bound", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		s, addr := relayTo(t, "        max_command_line: 128\n        max_text_line: 128", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		c.expect(250, "ehlo")
		c.send("MAIL FROM:<a@client.test>")
		c.expect(250, "mail")
		c.send("RCPT TO:<b@mta.invalid>")
		c.expect(250, "rcpt")
		c.send("DATA")
		c.expect(354, "data")
		c.raw("Subject: hello\r\n\r\n" + strings.Repeat("x", 400) + "\r\n.\r\n")
		code, text := c.reply()
		if code != 500 {
			t.Fatalf("a body line over the bound: got %d (%s), want 500", code, text)
		}
		awaitReason(t, s, "line_too_long")
		if _, msgs := m.got(); len(msgs) != 0 {
			t.Errorf("a message the proxy refused was delivered: %q", msgs)
		}
	})

	t.Run("a client that disappears mid-message", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		s, addr := relayTo(t, "", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		c.expect(250, "ehlo")
		c.send("MAIL FROM:<a@client.test>")
		c.expect(250, "mail")
		c.send("RCPT TO:<b@mta.invalid>")
		c.expect(250, "rcpt")
		c.send("DATA")
		c.expect(354, "data")
		c.raw("Subject: half a message\r\n\r\nthe first line\r\n")
		_ = c.conn.Close()
		awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.SMTPSessionsOpen == 0 },
			"the session outlived the client: %v open", func() any { return s.Stats().SMTPSessionsOpen })
		if _, msgs := m.got(); len(msgs) != 0 {
			t.Errorf("half a message was delivered: %q", msgs)
		}
	})
}

// STARTTLS on a listener that cannot offer it, twice over, and a client that
// asks for it and then does not handshake.
func TestWhatSTARTTLSRefuses(t *testing.T) {
	t.Run("a listener with no certificate", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		s, addr := relayTo(t, "", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		caps := c.expect(250, "ehlo")
		if strings.Contains(caps, "STARTTLS") {
			t.Fatalf("a listener with no certificate offered STARTTLS: %q", caps)
		}
		// Not offered, and refused when asked for anyway: 454 is temporary,
		// because the listener may well have a certificate tomorrow.
		c.send("STARTTLS")
		code, text := c.reply()
		if code != 454 {
			t.Fatalf("starttls with no certificate: got %d (%s), want 454", code, text)
		}
		awaitReason(t, s, "tls_unavailable")
	})

	t.Run("a second upgrade inside the first", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		tlsBlock, pool := certificate(t)
		s, addr := edgeRelay(t, "127.0.0.1:0", tlsBlock, "        tls_mode: starttls", "", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		c.expect(250, "ehlo")
		c.send("STARTTLS")
		c.expect(220, "starttls")
		c.starttls(pool)
		c.send("EHLO client.test")
		c.expect(250, "ehlo inside tls")
		c.send("STARTTLS")
		code, text := c.reply()
		if code != 503 {
			t.Fatalf("a second starttls: got %d (%s), want 503", code, text)
		}
		awaitReason(t, s, "tls_already_active")
	})

	t.Run("a client that asks and then does not handshake", func(t *testing.T) {
		m := startMTA(t, &fakeMTA{})
		tlsBlock, _ := certificate(t)
		s, addr := edgeRelay(t, "127.0.0.1:0", tlsBlock, "        tls_mode: starttls", "", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		c.expect(250, "ehlo")
		c.send("STARTTLS")
		c.expect(220, "starttls")
		// Not a handshake: the session ends, and the cleartext commands
		// behind it are never read as though they had been inside it.
		c.raw("MAIL FROM:<a@client.test>\r\n")
		if _, err := c.br.ReadString('\n'); err == nil {
			t.Error("the session went on without a handshake")
		}
		awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.SMTPSessionsOpen == 0 },
			"the session outlived the handshake: %v open", func() any { return s.Stats().SMTPSessionsOpen })
		if cmds, _ := m.got(); strings.Contains(strings.Join(cmds, "|"), "MAIL") {
			t.Errorf("a command sent in clear after STARTTLS was relayed: %v", cmds)
		}
	})
}

// A client that goes away in the middle of an authentication exchange leaves
// the proxy holding a challenge nobody will answer. Nothing from those lines
// is logged, so the session ending is the whole of what is recorded.
func TestAClientThatLeavesMidAuthenticationEndsTheSession(t *testing.T) {
	m := startMTA(t, &fakeMTA{caps: []string{"AUTH LOGIN"}, authChallenges: 2})
	s, addr := relayTo(t, "", m.addr())
	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	c.send("AUTH LOGIN")
	c.expect(334, "the first challenge")
	_ = c.conn.Close()
	awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.SMTPSessionsOpen == 0 },
		"the session outlived the client: %v open", func() any { return s.Stats().SMTPSessionsOpen })
}

// rudeMTA is an upstream that answers from a script instead of behaving. It
// is how the failures on the upstream leg are reached: every one of them is a
// server that is not a mail server, and the proxy has to answer the client
// for it without passing on anything it could not read itself.
type rudeMTA struct {
	ln net.Listener
	// greeting is written before anything is read; "" closes instead.
	greeting string
	// answer is the reply to the nth command, written as it goes on the
	// wire -- several replies in one write where a test wants them -- and
	// "" closes the connection rather than answering.
	answer func(cmd string, n int) string
	// implicit handshakes before the greeting, upgrade after the answer to
	// STARTTLS.
	implicit *tls.Config
	upgrade  *tls.Config
	// header reads a PROXY protocol v2 header before the greeting.
	header bool

	mu   sync.Mutex
	cmds []string
	hdr  []byte
}

func startRude(t *testing.T, m *rudeMTA) *rudeMTA {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.session(c)
		}
	}()
	return m
}

func (m *rudeMTA) addr() string { return m.ln.Addr().String() }

func (m *rudeMTA) saw() ([]string, []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.cmds...), append([]byte(nil), m.hdr...)
}

func (m *rudeMTA) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	if m.implicit != nil {
		tc := tls.Server(c, m.implicit)
		if err := tc.Handshake(); err != nil {
			return
		}
		c = tc
	}
	br := bufio.NewReader(c)
	if m.header {
		head := make([]byte, 16)
		if _, err := io.ReadFull(br, head); err != nil {
			return
		}
		rest := make([]byte, int(head[14])<<8|int(head[15]))
		if _, err := io.ReadFull(br, rest); err != nil {
			return
		}
		m.mu.Lock()
		m.hdr = append(append([]byte(nil), head...), rest...)
		m.mu.Unlock()
	}
	if m.greeting == "" {
		return
	}
	if _, err := io.WriteString(c, m.greeting+"\r\n"); err != nil {
		return
	}
	for i := 0; ; i++ {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		m.mu.Lock()
		m.cmds = append(m.cmds, cmd)
		m.mu.Unlock()
		rep := m.answer(cmd, i)
		if rep == "" {
			return
		}
		if _, err := io.WriteString(c, rep); err != nil {
			return
		}
		if strings.HasPrefix(rep, "354") {
			// It said to send the message, so the lines that follow are the
			// message and not commands.
			for {
				l, rerr := br.ReadString('\n')
				if rerr != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
			}
			i++
			final := m.answer(".", i)
			if final == "" {
				return
			}
			if _, err := io.WriteString(c, final); err != nil {
				return
			}
		}
		if m.upgrade != nil && strings.EqualFold(cmd, "STARTTLS") {
			tc := tls.Server(c, m.upgrade)
			if err := tc.Handshake(); err != nil {
				return
			}
			c = tc
			br = bufio.NewReader(c)
		}
	}
}

// replies answers each verb from a table and everything else with 250. The
// body of a message is answered under the key ".".
func replies(table map[string]string) func(string, int) string {
	return func(cmd string, _ int) string {
		verb, _, _ := strings.Cut(strings.ToUpper(cmd), " ")
		if r, ok := table[verb]; ok {
			return r
		}
		return "250 2.0.0 ok\r\n"
	}
}

// upstreamCert issues a certificate the rude upstream serves and returns the
// server configuration and the path a client verifies it with. The endpoint
// is dialled by address, so the certificate's loopback SAN is what the
// proxy's own server name ends up matching.
func upstreamCert(t *testing.T) (*tls.Config, string) {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "mta.test")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, ca.Path
}

// What the proxy does when the server behind it is not a mail server. The
// client is told 4xx throughout: the message is not undeliverable, this relay
// could not deliver it now, and a sending server that is told 5xx here
// bounces mail over a broken hop.
func TestWhatTheProxyWillNotAcceptFromTheUpstream(t *testing.T) {
	for _, c := range []struct {
		name     string
		greeting string
		answer   func(string, int) string
	}{
		{
			name:     "a server that says nothing at all",
			greeting: "",
			answer:   replies(nil),
		},
		{
			// A greeting that refuses the connection is still a server
			// refusing this proxy, and the client hears none of it: its own
			// address is not the one that was turned away.
			name:     "a greeting that is a refusal",
			greeting: "554 5.7.1 go away",
			answer:   replies(nil),
		},
		{
			name:     "a greeting with no EHLO behind it",
			greeting: "220 mta.invalid ESMTP",
			answer:   replies(map[string]string{"EHLO": ""}),
		},
		{
			// A server that will not take the proxy's own EHLO is one the
			// proxy cannot speak ESMTP to at all.
			name:     "an EHLO it refuses",
			greeting: "220 mta.invalid ESMTP",
			answer:   replies(map[string]string{"EHLO": "500 5.5.1 unknown command\r\n"}),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := startRude(t, &rudeMTA{greeting: c.greeting, answer: c.answer})
			s, addr := relayTo(t, "", m.addr())
			cl := dialSMTP(t, addr)
			code, text := cl.reply()
			if code != 421 {
				t.Fatalf("got %d (%s), want 421", code, text)
			}
			if !strings.Contains(text, "4.4.1") {
				t.Errorf("the refusal does not carry the enhanced status code: %q", text)
			}
			awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.SMTPRefused > 0 },
				"the session was not counted as refused", func() any { return nil })
		})
	}
}

// A reply the proxy cannot read is never passed through. This is the case the
// whole two-session design is for: a client that read a reply the proxy did
// not is a client whose idea of the session has diverged from the proxy's.
func TestAReplyTheProxyCannotReadIsNotPassedOn(t *testing.T) {
	m := startRude(t, &rudeMTA{
		greeting: "220 mta.invalid ESMTP",
		answer:   replies(map[string]string{"NOOP": "hello there\r\n"}),
	})
	s, addr := relayTo(t, "", m.addr())
	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	c.send("NOOP")
	code, text := c.reply()
	if code != 421 {
		t.Fatalf("an unreadable reply: got %d (%s), want 421", code, text)
	}
	if strings.Contains(text, "hello there") {
		t.Fatalf("the unreadable reply reached the client: %q", text)
	}
	if !strings.Contains(text, "4.3.0") {
		t.Errorf("the refusal does not carry the enhanced status code: %q", text)
	}
	awaitStat(t, s, func(sn proxy.Snapshot) bool { return sn.SMTPProtocolErrors > 0 },
		"the unreadable reply was not counted as a protocol error", func() any { return nil })
}

// The three places a message can end on the upstream leg, and what the client
// is told about each. A refusal is the server's own answer and is relayed; a
// server that goes away is this proxy's to answer for.
func TestAMessageTheUpstreamWillNotTake(t *testing.T) {
	t.Run("a refusal is the server's answer and is relayed", func(t *testing.T) {
		m := startRude(t, &rudeMTA{
			greeting: "220 mta.invalid ESMTP",
			answer:   replies(map[string]string{"DATA": "554 5.7.1 no thank you\r\n"}),
		})
		_, addr := relayTo(t, "", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		c.expect(250, "ehlo")
		c.send("MAIL FROM:<a@client.test>")
		c.expect(250, "mail")
		c.send("RCPT TO:<b@mta.invalid>")
		c.expect(250, "rcpt")
		c.send("DATA")
		code, text := c.reply()
		if code != 554 {
			t.Fatalf("a refused message: got %d (%s), want 554", code, text)
		}
		// And the transaction is over on this side too: the proxy does not
		// hold a transaction the upstream has already closed.
		c.send("RCPT TO:<b@mta.invalid>")
		c.expect(503, "rcpt after a refused DATA")
	})

	for _, c := range []struct {
		name  string
		table map[string]string
	}{
		{"a server that goes away on DATA", map[string]string{"DATA": ""}},
		{"a server that goes away mid-message", map[string]string{"DATA": "354 end with .\r\n", ".": ""}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := startRude(t, &rudeMTA{greeting: "220 mta.invalid ESMTP", answer: replies(c.table)})
			_, addr := relayTo(t, "", m.addr())
			cl := dialSMTP(t, addr)
			cl.expect(220, "greeting")
			cl.send("EHLO client.test")
			cl.expect(250, "ehlo")
			cl.send("MAIL FROM:<a@client.test>")
			cl.expect(250, "mail")
			cl.send("RCPT TO:<b@mta.invalid>")
			cl.expect(250, "rcpt")
			cl.send("DATA")
			code, text := cl.reply()
			if code == 354 {
				cl.raw("Subject: hello\r\n\r\nbody\r\n.\r\n")
				code, text = cl.reply()
			}
			if code != 421 {
				t.Fatalf("got %d (%s), want 421", code, text)
			}
		})
	}
}

// An authentication exchange the upstream abandons. The proxy answers for it
// rather than leaving a client waiting on a challenge that will never come,
// and nothing from the exchange is written down either way.
func TestAnAuthenticationTheUpstreamAbandons(t *testing.T) {
	m := startRude(t, &rudeMTA{
		greeting: "220 mta.invalid ESMTP",
		answer:   replies(map[string]string{"AUTH": ""}),
	})
	_, addr := relayTo(t, "", m.addr())
	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	c.send("AUTH LOGIN")
	code, text := c.reply()
	if code != 421 {
		t.Fatalf("an abandoned exchange: got %d (%s), want 421", code, text)
	}
}

// The upstream leg's own encryption. The proxy fills in the server name from
// the endpoint it dialled, because an upstream pool is written as addresses:
// without that there is nothing for verification to check against, and a
// verified hop to the wrong server is the one failure TLS is there to stop.
func TestTheUpstreamLegIsVerifiedAgainstTheEndpointItDialled(t *testing.T) {
	serverTLS, caFile := upstreamCert(t)
	m := startRude(t, &rudeMTA{
		implicit: serverTLS,
		greeting: "220 mta.invalid ESMTP",
		answer:   replies(nil),
	})
	_, addr := relayTo(t, fmt.Sprintf(`        upstream_tls_mode: implicit
        upstream_tls: {ca_file: %s}`, caFile), m.addr())

	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	c.send("QUIT")
	c.expect(221, "quit")
	// The session the upstream saw was inside the handshake: it read the
	// proxy's EHLO, which it could only do on the far side of it.
	cmds, _ := m.saw()
	if !strings.Contains(strings.Join(cmds, "|"), "EHLO") {
		t.Errorf("the upstream saw %v", cmds)
	}
}

// STARTTLS on the upstream leg, which has the same injection to refuse as the
// client leg and three more ways to fail. In every one of them the client is
// told the relay is unavailable rather than carried over a hop that was
// supposed to be encrypted and is not.
func TestWhatTheProxyRefusesWhenTheUpstreamUpgradeFails(t *testing.T) {
	const offered = "250-mta.invalid\r\n250 STARTTLS\r\n"
	serverTLS, caFile := upstreamCert(t)
	for _, c := range []struct {
		name    string
		answer  func(string, int) string
		upgrade *tls.Config
		tls     string
	}{
		{
			name:   "a server that refuses its own STARTTLS",
			answer: replies(map[string]string{"EHLO": offered, "STARTTLS": "502 5.5.1 no\r\n"}),
		},
		{
			name:   "a server that does not answer STARTTLS",
			answer: replies(map[string]string{"EHLO": offered, "STARTTLS": ""}),
		},
		{
			// CVE-2011-0411 from the other side: octets written before the
			// handshake could have been known about would be read as part of
			// the encrypted session.
			name:   "a server that writes behind its own reply",
			answer: replies(map[string]string{"EHLO": offered, "STARTTLS": "220 2.0.0 go ahead\r\n250 2.0.0 ok\r\n"}),
		},
		{
			name: "a server that says yes and does not handshake",
			answer: func(cmd string, n int) string {
				switch {
				case n == 0:
					return offered
				case strings.EqualFold(cmd, "STARTTLS"):
					return "220 2.0.0 go ahead\r\n"
				default:
					return ""
				}
			},
		},
		{
			// The second EHLO is asked inside the encrypted session, and a
			// server that refuses it there has left the proxy with no
			// capability list for a session it cannot fall back from.
			name: "a server that refuses the EHLO inside the upgrade",
			answer: func(cmd string, n int) string {
				if strings.EqualFold(cmd, "STARTTLS") {
					return "220 2.0.0 go ahead\r\n"
				}
				if n == 0 {
					return offered
				}
				return "500 5.5.1 unknown command\r\n"
			},
			upgrade: serverTLS,
			tls:     fmt.Sprintf("\n        upstream_tls: {ca_file: %s}", caFile),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := startRude(t, &rudeMTA{greeting: "220 mta.invalid ESMTP", answer: c.answer, upgrade: c.upgrade})
			_, addr := relayTo(t, "        upstream_tls_mode: starttls"+c.tls, m.addr())
			cl := dialSMTP(t, addr)
			code, text := cl.reply()
			if code != 421 {
				t.Fatalf("got %d (%s), want 421", code, text)
			}
		})
	}
}

// Two ways the proxy tells the upstream which client it is relaying for, so
// the server's own logs and policies see the address that connected rather
// than the proxy's. The header is written before anything is read; XCLIENT is
// a command, and a server that refuses it has refused the session.
func TestTheUpstreamIsToldWhichAddressConnected(t *testing.T) {
	t.Run("a PROXY protocol header", func(t *testing.T) {
		m := startRude(t, &rudeMTA{header: true, greeting: "220 mta.invalid ESMTP", answer: replies(nil)})
		_, addr := relayTo(t, "        proxy_protocol: true", m.addr())
		c := dialSMTP(t, addr)
		c.expect(220, "greeting")
		c.send("EHLO client.test")
		c.expect(250, "ehlo")

		_, hdr := m.saw()
		if len(hdr) != 28 {
			t.Fatalf("the header is %d octets: %x", len(hdr), hdr)
		}
		if hdr[12] != 0x21 || hdr[13] != 0x11 {
			t.Errorf("version, command and family: %#x %#x", hdr[12], hdr[13])
		}
		src := net.IP(hdr[16:20])
		if !src.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("the header names %s as the client", src)
		}
		port := int(hdr[24])<<8 | int(hdr[25])
		if want := c.conn.LocalAddr().(*net.TCPAddr).Port; port != want {
			t.Errorf("the header names port %d, the client connected from %d", port, want)
		}
	})

	t.Run("an XCLIENT the server refuses to answer", func(t *testing.T) {
		m := startRude(t, &rudeMTA{
			greeting: "220 mta.invalid ESMTP",
			answer: replies(map[string]string{
				"EHLO":    "250-mta.invalid\r\n250 XCLIENT ADDR PORT\r\n",
				"XCLIENT": "",
			}),
		})
		_, addr := relayTo(t, "        xclient: true", m.addr())
		c := dialSMTP(t, addr)
		code, text := c.reply()
		if code != 421 {
			t.Fatalf("got %d (%s), want 421", code, text)
		}
		cmds, _ := m.saw()
		var sent string
		for _, cmd := range cmds {
			if strings.HasPrefix(cmd, "XCLIENT") {
				sent = cmd
			}
		}
		if !strings.Contains(sent, "ADDR=127.0.0.1 PORT=") {
			t.Errorf("the upstream was told %q", sent)
		}
	})
}
