package imap

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// End to end: a mail client, this relay, and an IMAP server.
//
// The server below is a real one as far as the protocol goes -- it greets
// with a capability list, answers tagged commands, asks for a literal with a
// continuation request and reads the octets -- because most of what this kind
// does is about exactly those: the greeting it narrows, the literal it
// decides about before the octets arrive, and the state the tagged answers
// move it through.

const imapYAML = `
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: imap
      imap:
        upstream: servers
%[1]s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %[2]q}]}
`

// noTLS turns the transport check off, because the client in these tests is
// a plain socket to a fake server: the check has its own test, and leaving it
// on here would make every other one a test of it.
const noTLS = "        require_tls: false\n"

func relay(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(imapYAML, section, serverAddr))
	return s, proxytest.Addr(t, s, "mail")
}

// fakeServer is an IMAP server that says what the test tells it to.
type fakeServer struct {
	ln net.Listener
	// greeting is the first line it sends.
	greeting string
	// caps is what a CAPABILITY command answers with.
	caps string
	// answers maps a command name to the tagged status it answers.
	answers map[string]string
	// sasl makes AUTHENTICATE a real exchange: a continuation request, one
	// line read back, and then the tagged answer. Without it AUTHENTICATE is
	// answered straight away, which is the initial-response case.
	sasl bool
	// untagged is sent before the tagged answer of the named command.
	untagged map[string]string

	mu      sync.Mutex
	idleTag string
	seen    []string
	// literals holds the octets the server read as literals, which is how a
	// test proves an APPEND's body crossed intact.
	literals []string
}

func startServer(t *testing.T, f *fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	if f.greeting == "" {
		f.greeting = "* OK [CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN AUTH=GSSAPI LITERAL+ COMPRESS=DEFLATE IDLE] ready"
	}
	if f.caps == "" {
		f.caps = "IMAP4rev2 AUTH=PLAIN AUTH=GSSAPI LITERAL+ COMPRESS=DEFLATE IDLE"
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeServer) addr() string { return f.ln.Addr().String() }

func (f *fakeServer) record(s string) {
	f.mu.Lock()
	f.seen = append(f.seen, s)
	f.mu.Unlock()
}

func (f *fakeServer) saw() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func (f *fakeServer) bodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.literals...)
}

func (f *fakeServer) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	_, _ = fmt.Fprintf(c, "%s\r\n", f.greeting)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.record(line)
		if strings.EqualFold(strings.TrimSpace(line), "DONE") {
			f.mu.Lock()
			tag := f.idleTag
			f.idleTag = ""
			f.mu.Unlock()
			if tag != "" {
				_, _ = fmt.Fprintf(c, "%s OK IDLE completed\r\n", tag)
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		tag, name := fields[0], strings.ToUpper(fields[1])
		if name == "UID" && len(fields) > 2 {
			name = strings.ToUpper(fields[2])
		}
		// A literal: ask for it unless the client used LITERAL+, then read
		// exactly the octets announced.
		if i := strings.LastIndex(line, "{"); i >= 0 && strings.HasSuffix(line, "}") {
			decl := line[i+1 : len(line)-1]
			plus := strings.HasSuffix(decl, "+")
			size := 0
			if _, err := fmt.Sscanf(strings.TrimSuffix(decl, "+"), "%d", &size); err != nil {
				return
			}
			if !plus {
				_, _ = fmt.Fprintf(c, "+ go ahead\r\n")
			}
			buf := make([]byte, size)
			if _, err := io_ReadFull(br, buf); err != nil {
				return
			}
			f.mu.Lock()
			f.literals = append(f.literals, string(buf))
			f.mu.Unlock()
			// The rest of the command's line.
			if _, err := br.ReadString('\n'); err != nil {
				return
			}
		}
		if u, ok := f.untagged[name]; ok {
			_, _ = fmt.Fprintf(c, "%s\r\n", u)
		}
		status := "OK"
		if f.answers != nil {
			if s, ok := f.answers[name]; ok {
				status = s
			}
		}
		switch name {
		case "AUTHENTICATE":
			if f.sasl && status == "OK" {
				_, _ = fmt.Fprintf(c, "+ \r\n")
				answer, err := br.ReadString('\n')
				if err != nil {
					return
				}
				f.record("sasl:" + strings.TrimRight(answer, "\r\n"))
			}
		case "CAPABILITY":
			_, _ = fmt.Fprintf(c, "* CAPABILITY %s\r\n", f.caps)
		case "IDLE":
			f.mu.Lock()
			f.idleTag = tag
			f.mu.Unlock()
			_, _ = fmt.Fprintf(c, "+ idling\r\n")
			continue
		case "LOGOUT":
			_, _ = fmt.Fprintf(c, "* BYE closing\r\n")
		}
		_, _ = fmt.Fprintf(c, "%s %s %s completed\r\n", tag, status, name)
	}
}

// io_ReadFull is io.ReadFull, named so the import list of this test file
// stays the short one the rest of the package uses.
func io_ReadFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// client is a mail client: it reads lines and writes commands.
type client struct {
	t  *testing.T
	c  net.Conn
	br *bufio.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{t: t, c: c, br: bufio.NewReader(c)}
}

func (c *client) line() string {
	c.t.Helper()
	s, err := c.br.ReadString('\n')
	if err != nil {
		c.t.Fatalf("reading a line: %v", err)
	}
	return strings.TrimRight(s, "\r\n")
}

func (c *client) send(s string) {
	c.t.Helper()
	if _, err := fmt.Fprintf(c.c, "%s\r\n", s); err != nil {
		c.t.Fatalf("writing %q: %v", s, err)
	}
}

func (c *client) raw(s string) {
	c.t.Helper()
	if _, err := c.c.Write([]byte(s)); err != nil {
		c.t.Fatalf("writing: %v", err)
	}
}

// until reads until a line starting with the tag, and returns everything.
func (c *client) until(tag string) []string {
	c.t.Helper()
	var out []string
	for i := 0; i < 64; i++ {
		l := c.line()
		out = append(out, l)
		if strings.HasPrefix(l, tag+" ") {
			return out
		}
	}
	c.t.Fatalf("no tagged answer for %s in %v", tag, out)
	return nil
}

// An ordinary session: the greeting crosses, a login is carried, a mailbox is
// selected and a bounded fetch is answered.
func TestACommandReachesTheServerAndItsAnswerComesBack(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        max_fetch_messages: 100\n", srv.addr())
	c := dial(t, addr)
	if g := c.line(); !strings.HasPrefix(g, "* OK ") {
		t.Fatalf("greeting %q", g)
	}
	c.send("a1 LOGIN bob secret")
	if got := c.until("a1"); !strings.Contains(got[len(got)-1], "OK") {
		t.Fatalf("login: %v", got)
	}
	c.send("a2 SELECT INBOX")
	if got := c.until("a2"); !strings.Contains(got[len(got)-1], "OK") {
		t.Fatalf("select: %v", got)
	}
	c.send("a3 UID FETCH 1:50 (UID FLAGS)")
	if got := c.until("a3"); !strings.Contains(got[len(got)-1], "OK") {
		t.Fatalf("fetch: %v", got)
	}
	seen := strings.Join(srv.saw(), "\n")
	for _, want := range []string{"LOGIN bob secret", "SELECT INBOX", "UID FETCH 1:50"} {
		if !strings.Contains(seen, want) {
			t.Errorf("the server never saw %q in\n%s", want, seen)
		}
	}
}

// The bound that is the point of this kind: a request may not name more of a
// mailbox than the policy allows, and an open-ended set names all of it.
func TestAFetchThatNamesMoreOfTheMailboxThanAllowedIsRefused(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        max_fetch_messages: 10\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 SELECT INBOX")
	c.until("a2")
	c.send("a3 FETCH 1:50 (BODY[])")
	last := c.until("a3")
	answer := last[len(last)-1]
	if !strings.Contains(answer, "NO") || !strings.Contains(answer, "fetch_too_large") {
		t.Fatalf("a 50-message fetch under a bound of 10: %q", answer)
	}
	c.send("a4 FETCH 1:* (BODY[])")
	last = c.until("a4")
	if answer = last[len(last)-1]; !strings.Contains(answer, "open_sequence_set") {
		t.Fatalf("an open set under a bound: %q", answer)
	}
	// And a request inside the bound still crosses, which is the half that
	// makes the bound a bound rather than a refusal.
	c.send("a5 FETCH 1:5 (BODY[])")
	last = c.until("a5")
	if answer = last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("a 5-message fetch under a bound of 10: %q", answer)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "1:50") || strings.Contains(seen, "1:*") {
		t.Errorf("a refused fetch reached the server:\n%s", seen)
	}
}

// An APPEND is decided on the size it declares, before the octets arrive --
// which is the only place it can be decided, because LITERAL+ sends them
// without waiting.
func TestAnAppendIsDecidedOnItsDeclaredSizeAndItsOctetsAreDropped(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        max_append_bytes: 32\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	// A small one crosses, body intact.
	body := "Subject: hello\r\n\r\nhi\r\n"
	c.send(fmt.Sprintf("a2 APPEND INBOX {%d}", len(body)))
	if l := c.line(); !strings.HasPrefix(l, "+ ") {
		t.Fatalf("expected a continuation request, got %q", l)
	}
	c.raw(body + "\r\n")
	last := c.until("a2")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("an append inside the bound: %q", answer)
	}
	if got := srv.bodies(); len(got) != 1 || got[0] != body {
		t.Fatalf("the server received %q", got)
	}
	// A large one is refused on the command line, and its octets are read and
	// dropped rather than left to desynchronise the connection: the proof is
	// that the next command still gets its own answer.
	big := strings.Repeat("x", 64)
	c.send(fmt.Sprintf("a3 APPEND INBOX {%d+}", len(big)))
	c.raw(big + "\r\n")
	last = c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "append_too_large") {
		t.Fatalf("an append past the bound: %q", answer)
	}
	c.send("a4 NOOP")
	last = c.until("a4")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("the connection did not resynchronise: %q", answer)
	}
	if got := srv.bodies(); len(got) != 1 {
		t.Fatalf("the refused body reached the server: %q", got)
	}
}

// A line the server did not ask for is not credential material.
//
// Inside a SASL exchange the lines are forwarded unparsed, which is right --
// they are a password in base64 -- and is also the shape of the hole this test
// is about. A client that sends `AUTHENTICATE` with a mechanism the server does
// not implement is answered with a tagged NO and is then back at a command
// boundary at the far end; this relay was not, so the next line it read was
// forwarded without being parsed as the command the server would read it as.
func TestALineTheServerDidNotAskForIsNotCredentialMaterial(t *testing.T) {
	srv := startServer(t, &fakeServer{answers: map[string]string{"AUTHENTICATE": "NO"}})
	s, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	// Both lines in one write, which is what makes this work against a relay
	// that reads the second before the server has answered the first.
	c.raw("a1 AUTHENTICATE XNOTAMECH\r\na2 LOGIN victim@example.com Hunter2\r\n")
	// The connection ends, and the smuggled command is not forwarded.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().Refusals["imap"]["auth_injection"] > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Stats().Refusals["imap"]["auth_injection"] == 0 {
		t.Errorf("the line was carried as a credential: %v", s.Stats().Refusals["imap"])
	}
	for _, line := range srv.saw() {
		if strings.Contains(strings.ToUpper(line), "LOGIN") {
			t.Fatalf("a command was smuggled past the policy:\n%s", strings.Join(srv.saw(), "\n"))
		}
	}
}

// And the exchange itself still works, one continuation request at a time.
func TestASASLExchangeIsCarriedAStepAtATime(t *testing.T) {
	srv := startServer(t, &fakeServer{sasl: true})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 AUTHENTICATE PLAIN")
	if l := c.line(); !strings.HasPrefix(l, "+") {
		t.Fatalf("expected the server's continuation request, got %q", l)
	}
	c.send("AGJvYgBzZWNyZXQ=")
	last := c.until("a1")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("the exchange was refused: %q", answer)
	}
	if seen := strings.Join(srv.saw(), "\n"); !strings.Contains(seen, "sasl:AGJvYgBzZWNyZXQ=") {
		t.Errorf("the credential did not reach the server:\n%s", seen)
	}
}

// An argument sent as a literal is refused rather than decided about.
//
// A literal is the last token on the line, so the argument list ends where it
// begins: `SELECT {25+}` parses as SELECT with no arguments, and every list the
// policy keeps -- mailboxes, deny_mailboxes, the rule selectors, the user list
// -- then reads "this command names none" and allows it, while the server
// receives the name intact.
func TestAnArgumentSentAsALiteralIsRefused(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS+"        mailboxes: [INBOX, Sent]\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	for i, tc := range []struct{ cmd, octets string }{
		{"a2 SELECT {21+}", "Other Users/ceo/INBOX\r\n"},
		{"a3 COPY 1:* {11+}", "Exfil/Stash\r\n"},
		{"a4 LOGIN {5+}", "alice\r\n"},
	} {
		tag := strings.Fields(tc.cmd)[0]
		c.send(tc.cmd)
		c.raw(tc.octets)
		last := c.until(tag)
		if answer := last[len(last)-1]; !strings.Contains(answer, "literal_argument") {
			t.Errorf("case %d: %q was not refused: %q", i, tc.cmd, answer)
		}
	}
	if s.Stats().Refusals["imap"]["literal_argument"] != 3 {
		t.Errorf("refusals: %v", s.Stats().Refusals["imap"])
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "Other Users") ||
		strings.Contains(seen, "Exfil") {
		t.Errorf("a refused name reached the server:\n%s", seen)
	}
}

// A synchronising literal is not read after a refusal. The client is waiting
// for a continuation request and RFC 9051 §4.3 says it must not send the octets
// once it has a tagged refusal instead -- so reading them would block on octets
// nobody is going to send, and then swallow the next command.
func TestASynchronisingLiteralIsNotReadAfterARefusal(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        max_append_bytes: 32\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	// No `+` on the literal, and the octets are never sent.
	c.send("a2 APPEND INBOX {64}")
	last := c.until("a2")
	if answer := last[len(last)-1]; !strings.Contains(answer, "append_too_large") {
		t.Fatalf("the refusal did not arrive: %q", answer)
	}
	// The next command is read as a command rather than as the first 64 octets
	// of something.
	c.send("a3 NOOP")
	last = c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("the connection lost step: %q", answer)
	}
}

// A chained literal is bounded by the rule that decided the command. The first
// literal on the line was checked against the rule's own bound and the chained
// ones against the listener's, so a rule tightening the bound for one user
// applied to the mailbox name and not to the message.
func TestAChainedLiteralIsBoundedByTheRuleThatDecided(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	section := noTLS + "        max_append_bytes: 1048576\n" +
		"        rules:\n" +
		"          - {name: interns, users: [bob], max_append_bytes: 64}\n"
	s, addr := relay(t, section, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	// The mailbox as the first literal, a message past the rule's bound as the
	// second. The listener's bound is a megabyte, the rule's is 64 octets.
	c.send("a2 APPEND INBOX (\\Seen) {4096+}")
	c.raw(strings.Repeat("x", 4096) + "\r\n")
	last := c.until("a2")
	if answer := last[len(last)-1]; !strings.Contains(answer, "append_too_large") {
		t.Fatalf("the rule's bound did not apply to the chained literal: %q", answer)
	}
	if s.Stats().Refusals["imap"]["append_too_large"] == 0 {
		t.Errorf("refusals: %v", s.Stats().Refusals["imap"])
	}
}

// An anomaly refusal drops the octets the client has already committed, the
// same as a policy refusal does. Without that the next line this relay reads is
// the middle of a message, and a body line that happens to parse as a command
// is forwarded as one.
func TestAnAnomalyRefusalDropsTheOctetsTheClientCommitted(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	section := noTLS + `        anomaly:
          enabled: true
          action: deny
          settle: 0s
          novelty: {symbols: true}
`
	s, addr := relay(t, section, srv.addr())
	c := dial(t, addr)
	c.line()
	// The password in a literal, which no policy list reads -- so the command
	// reaches the anomaly check with octets already on the wire.
	c.send("a1 LOGIN bob {6+}")
	c.raw("secret\r\n")
	last := c.until("a1")
	if answer := last[len(last)-1]; !strings.Contains(answer, "anomaly") {
		t.Fatalf("the models did not refuse the first command: %q", answer)
	}
	// The next line is read as a command: it gets an answer under its own tag
	// rather than being taken for the rest of a message.
	c.send("a2 NOOP")
	last = c.until("a2")
	if answer := last[len(last)-1]; !strings.HasPrefix(answer, "a2 ") {
		t.Fatalf("the connection lost step: %q", answer)
	}
	if n := s.Stats().Refusals["imap"]["malformed_command"]; n != 0 {
		t.Errorf("the dropped literal left %d octets behind", n)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "secret") {
		t.Errorf("the refused command's octets reached the server:\n%s", seen)
	}
}

// The INBOX fold reaches the hierarchy below it, because the servers that put
// mail there fold that component too: `inbox/Finance` and `INBOX/Finance` are
// one mailbox at the server and were two different strings here.
func TestTheInboxFoldCoversTheHierarchyBelowIt(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := relay(t, noTLS+"        deny_mailboxes: [\"INBOX/Finance*\"]\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	for i, cmd := range []string{
		"a2 SELECT INBOX/Finance/Payroll",
		"a3 SELECT inbox/Finance/Payroll",
		"a4 SELECT InBoX/Finance/Payroll",
	} {
		tag := strings.Fields(cmd)[0]
		c.send(cmd)
		last := c.until(tag)
		if answer := last[len(last)-1]; !strings.Contains(answer, "mailbox_denied") {
			t.Errorf("case %d: %q was allowed: %q", i, cmd, answer)
		}
	}
	// And a mailbox whose name merely begins with those letters is not INBOX.
	c.send("a5 SELECT Inboxes/Finance")
	last := c.until("a5")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Errorf("a mailbox that is not under INBOX was denied: %q", answer)
	}
	if s.Stats().Refusals["imap"]["mailbox_denied"] != 3 {
		t.Errorf("refusals: %v", s.Stats().Refusals["imap"])
	}
}

// The capability list the client reads is not the one the server sent:
// compression is gone, a mechanism the policy refuses is gone, and
// LOGINDISABLED is there when a password would be refused.
func TestTheCapabilityListIsNarrowedBeforeTheClientSeesIt(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, "        mechanisms: [gssapi]\n        require_tls: true\n", srv.addr())
	c := dial(t, addr)
	greeting := c.line()
	for _, gone := range []string{"COMPRESS=DEFLATE", "AUTH=PLAIN"} {
		if strings.Contains(greeting, gone) {
			t.Errorf("the greeting still advertises %s: %q", gone, greeting)
		}
	}
	for _, kept := range []string{"AUTH=GSSAPI", "LOGINDISABLED"} {
		if !strings.Contains(greeting, kept) {
			t.Errorf("the greeting does not carry %s: %q", kept, greeting)
		}
	}
	c.send("a1 CAPABILITY")
	got := strings.Join(c.until("a1"), "\n")
	if strings.Contains(got, "COMPRESS=DEFLATE") || strings.Contains(got, "AUTH=PLAIN") {
		t.Errorf("the CAPABILITY response was not narrowed:\n%s", got)
	}
}

// A password in the clear is refused, and the refusal is not shadowable:
// monitor_only does not make it pass, because by then the password has
// travelled.
func TestALoginInTheClearIsRefusedEvenInShadowMode(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, "        require_tls: true\n        monitor_only: true\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	last := c.until("a1")
	if answer := last[len(last)-1]; !strings.Contains(answer, "tls_required") {
		t.Fatalf("a plaintext login under monitor_only: %q", answer)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "secret") {
		t.Errorf("the password reached the server:\n%s", seen)
	}
}

// The state machine is the relay's own: a FETCH before a SELECT is refused
// here, so the mailbox never sees it.
func TestACommandInTheWrongStateIsRefusedBeforeTheServerSeesIt(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 FETCH 1 (BODY[])")
	last := c.until("a1")
	if answer := last[len(last)-1]; !strings.Contains(answer, "wrong_state") {
		t.Fatalf("a FETCH before authentication: %q", answer)
	}
	c.send("a2 LOGIN bob secret")
	c.until("a2")
	c.send("a3 FETCH 1 (BODY[])")
	last = c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "wrong_state") {
		t.Fatalf("a FETCH before SELECT: %q", answer)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "FETCH") {
		t.Errorf("a FETCH in the wrong state reached the server:\n%s", seen)
	}
}

// A mailbox list is compared on the decoded name, so a rule written in UTF-8
// matches the modified UTF-7 a client sends.
func TestAMailboxPolicyComparesTheDecodedName(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        mailboxes: [INBOX, \"Sent\", \"Shared/%\"]\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	for _, tc := range []struct {
		cmd     string
		allowed bool
	}{
		{"a2 SELECT INBOX", true},
		{"a3 SELECT Sent", true},
		{"a4 SELECT Archive", false},
		{"a5 SELECT Shared/HR", true},
		{"a6 SELECT Shared/HR/Payroll", false},
	} {
		tag := strings.Fields(tc.cmd)[0]
		c.send(tc.cmd)
		last := c.until(tag)
		answer := last[len(last)-1]
		if tc.allowed && !strings.Contains(answer, "OK") {
			t.Errorf("%q was refused: %q", tc.cmd, answer)
		}
		if !tc.allowed && !strings.Contains(answer, "mailbox_not_allowed") {
			t.Errorf("%q was allowed: %q", tc.cmd, answer)
		}
	}
}

// A PREAUTH greeting is not carried: the connection is closed with a BYE
// that says why, because every later decision would otherwise be about a
// name this relay never saw.
func TestAPreauthGreetingIsNotCarried(t *testing.T) {
	srv := startServer(t, &fakeServer{greeting: "* PREAUTH IMAP4rev2 already authenticated"})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	if g := c.line(); !strings.Contains(g, "BYE") || !strings.Contains(g, "preauth_greeting") {
		t.Fatalf("a PREAUTH greeting was carried: %q", g)
	}
}

// A read-only listener refuses what changes a mailbox, including the UID
// forms -- which is the half a policy written about command names misses.
func TestAReadOnlyListenerRefusesTheWritesIncludingTheUIDForms(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        read_only: true\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 SELECT INBOX")
	c.until("a2")
	for i, cmd := range []string{
		"UID STORE 1 +FLAGS (\\Deleted)",
		"EXPUNGE",
		"UID COPY 1 Archive",
		"CREATE Scratch",
	} {
		tag := fmt.Sprintf("w%d", i)
		c.send(tag + " " + cmd)
		last := c.until(tag)
		if answer := last[len(last)-1]; !strings.Contains(answer, "read_only") {
			t.Errorf("%q on a read-only listener: %q", cmd, answer)
		}
	}
	// A read still works.
	c.send("a3 FETCH 1 (FLAGS)")
	last := c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("a read on a read-only listener: %q", answer)
	}
}

// IDLE parks the connection, and the only line the protocol allows after it
// is DONE: anything else is a client that has lost track of its own state, or
// somebody pipelining into a parked connection.
func TestIdleAcceptsOnlyDone(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 IDLE")
	if l := c.line(); !strings.HasPrefix(l, "+ ") {
		t.Fatalf("IDLE was not accepted: %q", l)
	}
	c.send("DONE")
	last := c.until("a2")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("DONE: %q", answer)
	}
	// And a second IDLE followed by something else ends the connection.
	c.send("a3 IDLE")
	if l := c.line(); !strings.HasPrefix(l, "+ ") {
		t.Fatalf("the second IDLE: %q", l)
	}
	c.send("a4 NOOP")
	if _, err := c.br.ReadString('\n'); err == nil {
		t.Fatal("a command inside an IDLE was carried")
	}
}

// A command list is an allow list, and an unknown command is refused rather
// than forwarded -- a relay that carried what it cannot name is a tunnel.
func TestTheCommandListAndTheUnknownCommand(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        commands: [CAPABILITY, LOGIN, SELECT, FETCH, NOOP, LOGOUT]\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 SELECT INBOX")
	c.until("a2")
	c.send("a3 SEARCH ALL")
	last := c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "command_not_allowed") {
		t.Fatalf("SEARCH off the allow list: %q", answer)
	}
	c.send("a4 FROBNICATE now")
	last = c.until("a4")
	if answer := last[len(last)-1]; !strings.Contains(answer, "unknown_command") {
		t.Fatalf("an unknown command: %q", answer)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "FROBNICATE") {
		t.Errorf("an unknown command reached the server:\n%s", seen)
	}
}

// An authentication failure is counted and reaches the ban ladder, which is
// the one non-policy refusal this kind reports: a mailbox password is the
// credential on an estate most worth guessing.
func TestAFailedLoginIsCountedAndReported(t *testing.T) {
	srv := startServer(t, &fakeServer{answers: map[string]string{"LOGIN": "NO"}})
	s, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob wrong")
	last := c.until("a1")
	if answer := last[len(last)-1]; !strings.Contains(answer, "NO") {
		t.Fatalf("a refused login: %q", answer)
	}
	if got := s.Stats().IMAPAuthFailures; got != 1 {
		t.Fatalf("imap_auth_failures is %d, want 1", got)
	}
}

// A rule is how the one account that really does synchronise a whole mailbox
// is written down, and its bounds and lists are its own.
func TestARuleCarriesItsOwnBoundsAndLists(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	section := noTLS + `        max_fetch_messages: 5
        rules:
          - name: sync
            users: [backup]
            max_fetch_messages: 500
          - name: people
            clients: [127.0.0.0/8]
            deny_commands: [SEARCH]
`
	_, addr := relay(t, section, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN backup secret")
	c.until("a1")
	c.send("a2 SELECT INBOX")
	c.until("a2")
	c.send("a3 FETCH 1:100 (BODY[])")
	last := c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("a 100-message fetch for the named account: %q", answer)
	}
	// Everybody else matches the second rule: the listener's bound applies
	// and SEARCH is refused.
	o := dial(t, addr)
	o.line()
	o.send("b1 LOGIN bob secret")
	o.until("b1")
	o.send("b2 SELECT INBOX")
	o.until("b2")
	o.send("b3 FETCH 1:100 (BODY[])")
	last = o.until("b3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "fetch_too_large") {
		t.Fatalf("a 100-message fetch for everybody else: %q", answer)
	}
	o.send("b4 SEARCH ALL")
	last = o.until("b4")
	if answer := last[len(last)-1]; !strings.Contains(answer, "command_denied") {
		t.Fatalf("SEARCH under the rule: %q", answer)
	}
}

// A client that is not allowed to connect is refused before the server is
// dialled at all.
func TestAClientOffTheListIsRefusedBeforeTheServerIsDialled(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        allow_clients: [10.0.0.0/8]\n", srv.addr())
	c := dial(t, addr)
	if _, err := c.br.ReadString('\n'); err == nil {
		t.Fatal("a client off the allow list got a greeting")
	}
	if seen := srv.saw(); len(seen) != 0 {
		t.Errorf("the server was dialled anyway: %v", seen)
	}
}

// The behavioural models see the command, the mailbox, the account and the
// number of messages a request named.
func TestTheAnomalyModelsSeeTheCommandsAndTheVolume(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	section := noTLS + `        anomaly:
          enabled: true
          action: alert
          settle: 0s
          novelty: {symbols: true}
`
	s, addr := relay(t, section, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 SELECT INBOX")
	c.until("a2")
	c.send("a3 FETCH 1:3 (BODY[])")
	last := c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("a fetch with the models on: %q", answer)
	}
	if counts := s.Counters().RefusalCounts()["imap"]; len(counts) == 0 {
		t.Error("the models reported nothing with settle: 0s and novelty on")
	}
	if got := s.Stats().IMAPFetchedMessages; got != 3 {
		t.Errorf("imap_fetched_messages is %d, want 3", got)
	}
}

// deny_response: drop says nothing, and the connection stays in step: the
// next command gets its own answer.
func TestDenyResponseDropSaysNothing(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        read_only: true\n        deny_response: drop\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGIN bob secret")
	c.until("a1")
	c.send("a2 CREATE Scratch")
	c.send("a3 NOOP")
	last := c.until("a3")
	if answer := last[len(last)-1]; !strings.Contains(answer, "OK") {
		t.Fatalf("after a dropped refusal: %q", answer)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "CREATE") {
		t.Errorf("the refused command reached the server:\n%s", seen)
	}
}

// A LOGOUT ends the session the protocol's own way: the server's BYE and its
// tagged OK both cross, and the connection closes.
func TestALogoutEndsTheSession(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("a1 LOGOUT")
	got := strings.Join(c.until("a1"), "\n")
	if !strings.Contains(got, "BYE") || !strings.Contains(got, "OK") {
		t.Fatalf("a logout: %q", got)
	}
}
