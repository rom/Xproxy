package pop3

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// End to end: a mail client, this relay, and a POP3 server.
//
// The server below answers in the protocol's two shapes -- one line, or many
// ending in a dot -- because that distinction is what this kind can get
// wrong in the way that matters: a relay that read a multi-line reply as one
// line would hand the client the next reply's text and leave both ends
// disagreeing about where the message ended.

const pop3YAML = `
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: pop3
      pop3:
        upstream: servers
%[1]s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %[2]q}]}
`

// noTLS turns the transport check off: the client here is a plain socket to a
// fake server, and the check has a test of its own.
const noTLS = "        require_tls: false\n"

func relay(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(pop3YAML, section, serverAddr))
	return s, proxytest.Addr(t, s, "mail")
}

// fakeServer is a POP3 server that answers what the test tells it to.
type fakeServer struct {
	ln net.Listener
	// greeting is the first line, with the APOP timestamp in it.
	greeting string
	// capa is the CAPA list, one capability per line.
	capa []string
	// message is what RETR and TOP return.
	message []string
	// fail names the commands answered -ERR.
	fail map[string]bool
	// sasl answers AUTH with a challenge and then an +OK, which is the
	// exchange whose lines are credential material.
	sasl bool
	// tlsCert and tlsKey make the server answer STLS and upgrade. Without
	// them STLS is refused, which is the other half of that decision.
	tlsCert, tlsKey string
	tlsCfg          *tls.Config

	mu       sync.Mutex
	seen     []string
	upgraded bool
}

func startServer(t *testing.T, f *fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	if f.greeting == "" {
		f.greeting = "+OK POP3 ready <1896.697170952@mail.test>"
	}
	if f.capa == nil {
		f.capa = []string{"TOP", "USER", "SASL PLAIN GSSAPI", "STLS", "UIDL"}
	}
	if f.message == nil {
		f.message = []string{"Subject: hello", "", "hi", ".hidden leading dot"}
	}
	if f.tlsCert != "" {
		pair, err := tls.LoadX509KeyPair(f.tlsCert, f.tlsKey)
		if err != nil {
			t.Fatal(err)
		}
		f.tlsCfg = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
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

// wasUpgraded reports whether this server's connection ended up inside TLS.
func (f *fakeServer) wasUpgraded() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.upgraded
}

func (f *fakeServer) saw() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
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
		f.mu.Lock()
		f.seen = append(f.seen, line)
		f.mu.Unlock()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToUpper(fields[0])
		if f.fail[name] {
			_, _ = fmt.Fprintf(c, "-ERR %s refused\r\n", name)
			continue
		}
		switch name {
		case "AUTH":
			if f.sasl {
				_, _ = fmt.Fprintf(c, "+ Y2hhbGxlbmdl\r\n")
				answer, err := br.ReadString('\n')
				if err != nil {
					return
				}
				f.mu.Lock()
				f.seen = append(f.seen, strings.TrimRight(answer, "\r\n"))
				f.mu.Unlock()
				_, _ = fmt.Fprintf(c, "+OK welcome\r\n")
				continue
			}
			_, _ = fmt.Fprintf(c, "+OK AUTH\r\n")
		case "STLS":
			// A server with no certificate refuses, which is what a relay
			// configured to upgrade has to treat as a failure rather than as
			// permission to carry on in clear.
			if f.tlsCfg == nil {
				_, _ = fmt.Fprintf(c, "-ERR no STLS here\r\n")
				continue
			}
			_, _ = fmt.Fprintf(c, "+OK begin TLS\r\n")
			tc := tls.Server(c, f.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, br = tc, bufio.NewReader(tc)
			f.mu.Lock()
			f.upgraded = true
			f.mu.Unlock()
		case "CAPA":
			_, _ = fmt.Fprintf(c, "+OK capability list follows\r\n")
			for _, l := range f.capa {
				_, _ = fmt.Fprintf(c, "%s\r\n", l)
			}
			_, _ = fmt.Fprintf(c, ".\r\n")
		case "RETR", "TOP":
			_, _ = fmt.Fprintf(c, "+OK message follows\r\n")
			for _, l := range f.message {
				// The server stuffs its own leading dots, as the protocol
				// requires; the relay has to unstuff and restuff them.
				if strings.HasPrefix(l, ".") {
					l = "." + l
				}
				_, _ = fmt.Fprintf(c, "%s\r\n", l)
			}
			_, _ = fmt.Fprintf(c, ".\r\n")
		case "LIST", "UIDL":
			if len(fields) > 1 {
				_, _ = fmt.Fprintf(c, "+OK %s 1 120\r\n", name)
				continue
			}
			_, _ = fmt.Fprintf(c, "+OK 2 messages\r\n1 120\r\n2 340\r\n.\r\n")
		case "STAT":
			_, _ = fmt.Fprintf(c, "+OK 2 460\r\n")
		case "QUIT":
			_, _ = fmt.Fprintf(c, "+OK bye\r\n")
			return
		default:
			_, _ = fmt.Fprintf(c, "+OK %s\r\n", name)
		}
	}
}

// client is a mail client.
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

// body reads a multi-line reply's lines up to the terminator.
func (c *client) body() []string {
	c.t.Helper()
	var out []string
	for i := 0; i < 256; i++ {
		l := c.line()
		if l == "." {
			return out
		}
		out = append(out, l)
	}
	c.t.Fatal("no terminator")
	return nil
}

// login takes the connection into the transaction state.
func (c *client) login() {
	c.t.Helper()
	c.line() // the greeting
	c.send("USER bob")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		c.t.Fatalf("USER: %q", l)
	}
	c.send("PASS secret")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		c.t.Fatalf("PASS: %q", l)
	}
}

// An ordinary session: a login, a STAT, and a message retrieved whole.
func TestACommandReachesTheServerAndItsAnswerComesBack(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.login()
	c.send("STAT")
	if l := c.line(); l != "+OK 2 460" {
		t.Fatalf("STAT: %q", l)
	}
	c.send("RETR 1")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("RETR: %q", l)
	}
	got := c.body()
	// The stuffed dot is unstuffed and restuffed across the relay, so the
	// client sees what the server's user wrote rather than one dot fewer.
	want := []string{"Subject: hello", "", "hi", "..hidden leading dot"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("the message arrived as %q, want %q", got, want)
	}
	if seen := strings.Join(srv.saw(), "\n"); !strings.Contains(seen, "RETR 1") {
		t.Errorf("the server never saw the RETR:\n%s", seen)
	}
}

// The one thing this relay must not get wrong. `LIST` is many lines and
// `LIST 3` is one, and a relay that guessed would read the next reply as part
// of this one -- so the test asks for both, in both orders, and checks that
// every later reply still lines up.
func TestWhetherAReplyIsOneLineOrManyIsDerivedNotGuessed(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.login()
	c.send("LIST 2")
	if l := c.line(); l != "+OK LIST 1 120" {
		t.Fatalf("LIST with an argument: %q", l)
	}
	c.send("LIST")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("LIST: %q", l)
	}
	if got := c.body(); len(got) != 2 {
		t.Fatalf("LIST body: %q", got)
	}
	c.send("UIDL 1")
	if l := c.line(); l != "+OK UIDL 1 120" {
		t.Fatalf("UIDL with an argument: %q", l)
	}
	c.send("UIDL")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("UIDL: %q", l)
	}
	if got := c.body(); len(got) != 2 {
		t.Fatalf("UIDL body: %q", got)
	}
	// The proof the two ends are still in step: one more single-line reply
	// lands where it should.
	c.send("STAT")
	if l := c.line(); l != "+OK 2 460" {
		t.Fatalf("the connection desynchronised: %q", l)
	}
}

// The copying bound, enforced mid-transfer: a client that reaches it is cut
// off rather than allowed to finish, because one RETR of a large message is a
// copy of a mailbox by itself.
func TestTheByteBoundStopsTheTransferRatherThanTheNextCommand(t *testing.T) {
	big := make([]string, 200)
	for i := range big {
		big[i] = strings.Repeat("x", 100)
	}
	srv := startServer(t, &fakeServer{message: big})
	s, addr := relay(t, noTLS+"        max_retr_bytes: 2048\n", srv.addr())
	c := dial(t, addr)
	c.login()
	c.send("RETR 1")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("RETR: %q", l)
	}
	// The relay carries what fits and then ends the connection: the client
	// never sees a terminator, which is the honest outcome -- a truncated
	// message that claimed to be whole would be worse.
	lines := 0
	for {
		l, err := c.br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimRight(l, "\r\n") == "." {
			t.Fatal("the whole message crossed despite the bound")
		}
		lines++
		if lines > 200 {
			t.Fatal("more lines than the message has")
		}
	}
	if got := s.Counters().RefusalCounts()["pop3"]["retrieval_too_large"]; got == 0 {
		t.Errorf("the refusal was not counted: %v", s.Counters().RefusalCounts()["pop3"])
	}
}

// The message bound is decided before the command, so a client that has taken
// its allowance is told no rather than cut off.
func TestTheMessageBoundIsAnsweredBeforeTheCommand(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        max_messages: 2\n", srv.addr())
	c := dial(t, addr)
	c.login()
	for i := 1; i <= 2; i++ {
		c.send(fmt.Sprintf("RETR %d", i))
		if l := c.line(); !strings.HasPrefix(l, "+OK") {
			t.Fatalf("RETR %d: %q", i, l)
		}
		c.body()
	}
	c.send("RETR 3")
	if l := c.line(); !strings.Contains(l, "too_many_messages") {
		t.Fatalf("the third RETR under a bound of two: %q", l)
	}
	// And the connection is still usable for everything else, which is what
	// makes this a bound rather than a disconnection.
	c.send("STAT")
	if l := c.line(); l != "+OK 2 460" {
		t.Fatalf("after the bound: %q", l)
	}
}

// The password is on the line after the name, so the transport check is the
// only thing between it and the wire -- and it is not shadowable.
func TestAPasswordInTheClearIsRefusedEvenInShadowMode(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, "        require_tls: true\n        monitor_only: true\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("USER bob")
	if l := c.line(); !strings.Contains(l, "tls_required") {
		t.Fatalf("USER on an unencrypted connection under monitor_only: %q", l)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "bob") {
		t.Errorf("the identity reached the server:\n%s", seen)
	}
}

// The CAPA list the client reads is narrowed: a mechanism the policy refuses
// is gone from the SASL line, and USER goes when the pair is refused.
func TestTheCapabilityListIsNarrowedBeforeTheClientSeesIt(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, "        require_tls: true\n        mechanisms: [gssapi]\n", srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("CAPA")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("CAPA: %q", l)
	}
	got := strings.Join(c.body(), "\n")
	if strings.Contains(got, "PLAIN") {
		t.Errorf("a refused mechanism is still advertised:\n%s", got)
	}
	if !strings.Contains(got, "SASL GSSAPI") {
		t.Errorf("the allowed mechanism is gone:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if line == "USER" {
			t.Errorf("USER is advertised although the pair is refused:\n%s", got)
		}
	}
}

// A read-only listener refuses the two commands that change what the mailbox
// will hold after the update state.
func TestAReadOnlyListenerRefusesDeleAndRset(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        read_only: true\n", srv.addr())
	c := dial(t, addr)
	c.login()
	for _, cmd := range []string{"DELE 1", "RSET"} {
		c.send(cmd)
		if l := c.line(); !strings.Contains(l, "read_only") {
			t.Errorf("%s on a read-only listener: %q", cmd, l)
		}
	}
	c.send("LIST 1")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("a read on a read-only listener: %q", l)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "DELE") {
		t.Errorf("a DELE reached the server:\n%s", seen)
	}
}

// The state table is the relay's own: a RETR before a credential is refused
// here, which is also the shape of somebody probing for an open server.
func TestACommandInTheWrongStateIsRefusedBeforeTheServerSeesIt(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("RETR 1")
	if l := c.line(); !strings.Contains(l, "wrong_state") {
		t.Fatalf("a RETR before a login: %q", l)
	}
	c.send("STLS")
	if l := c.line(); !strings.Contains(l, "stls_not_offered") {
		t.Fatalf("STLS on a listener that does not offer it: %q", l)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "RETR") {
		t.Errorf("a RETR in the wrong state reached the server:\n%s", seen)
	}
}

// A command list is an allow list, and a name this relay does not know is
// refused rather than forwarded.
func TestTheCommandListAndTheUnknownCommand(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        commands: [USER, PASS, STAT, LIST, RETR, QUIT]\n", srv.addr())
	c := dial(t, addr)
	c.login()
	c.send("UIDL")
	if l := c.line(); !strings.Contains(l, "command_not_allowed") {
		t.Fatalf("UIDL off the allow list: %q", l)
	}
	c.send("FROBNICATE")
	if l := c.line(); !strings.Contains(l, "unknown_command") {
		t.Fatalf("an unknown command: %q", l)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "FROBNICATE") {
		t.Errorf("an unknown command reached the server:\n%s", seen)
	}
}

// A refused credential is counted and reaches the ban ladder: on this
// protocol the password is the only thing to guess.
func TestAFailedLoginIsCountedAndReported(t *testing.T) {
	srv := startServer(t, &fakeServer{fail: map[string]bool{"PASS": true}})
	s, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("USER bob")
	c.line()
	c.send("PASS wrong")
	if l := c.line(); !strings.HasPrefix(l, "-ERR") {
		t.Fatalf("a refused password: %q", l)
	}
	if got := s.Stats().POP3AuthFailures; got != 1 {
		t.Fatalf("pop3_auth_failures is %d, want 1", got)
	}
}

// The greeting crosses unchanged, which is what makes APOP possible at all:
// the digest is computed over the timestamp in it.
func TestTheGreetingIsCarriedUnchangedSoAPOPCanWork(t *testing.T) {
	srv := startServer(t, &fakeServer{greeting: "+OK ready <1234.5678@mail.test>"})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	if g := c.line(); g != "+OK ready <1234.5678@mail.test>" {
		t.Fatalf("the greeting was rewritten: %q", g)
	}
	c.send("APOP bob c4c9334bac560ecc979e58001b3e22fb")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("APOP: %q", l)
	}
	if seen := strings.Join(srv.saw(), "\n"); !strings.Contains(seen, "c4c9334bac560ecc979e58001b3e22fb") {
		t.Errorf("the digest did not reach the server:\n%s", seen)
	}
}

// A rule is how the one account that really does take its whole mailbox
// every morning is written down, and the bound it carries is its own.
func TestARuleCarriesItsOwnBoundAndItsOwnLists(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	section := noTLS + `        max_messages: 1
        rules:
          - name: archiver
            users: [archive]
            max_messages: 3
          - name: readers
            clients: [127.0.0.0/8]
            deny_commands: [DELE]
`
	_, addr := relay(t, section, srv.addr())
	// The named account gets the rule's bound.
	c := dial(t, addr)
	c.line()
	c.send("USER archive")
	c.line()
	c.send("PASS secret")
	c.line()
	for i := 1; i <= 3; i++ {
		c.send(fmt.Sprintf("RETR %d", i))
		if l := c.line(); !strings.HasPrefix(l, "+OK") {
			t.Fatalf("RETR %d for the named account: %q", i, l)
		}
		c.body()
	}
	c.send("RETR 4")
	if l := c.line(); !strings.Contains(l, "too_many_messages") {
		t.Fatalf("the fourth RETR under the rule's bound of three: %q", l)
	}
	// Everybody else matches the second rule, which allows one message and
	// refuses DELE.
	o := dial(t, addr)
	o.login()
	o.send("DELE 1")
	if l := o.line(); !strings.Contains(l, "command_denied") {
		t.Fatalf("DELE under the rule: %q", l)
	}
	o.send("RETR 1")
	if l := o.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("the first RETR: %q", l)
	}
	o.body()
	o.send("RETR 2")
	if l := o.line(); !strings.Contains(l, "too_many_messages") {
		t.Fatalf("the second RETR under the listener's bound of one: %q", l)
	}
}

// A SASL exchange's lines are credential material: forwarded, never parsed
// as commands, and the state moves only on the answer that ends it.
func TestASASLExchangeIsCarriedWithoutBeingRead(t *testing.T) {
	srv := startServer(t, &fakeServer{sasl: true})
	_, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("AUTH PLAIN")
	if l := c.line(); !strings.HasPrefix(l, "+ ") {
		t.Fatalf("the challenge: %q", l)
	}
	// A line that looks like a command is a credential here, and is carried
	// as one rather than decided about.
	c.send("UkVUUiAx")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("the answer to the exchange: %q", l)
	}
	// And the connection is in the transaction state afterwards, which is
	// what the exchange established.
	c.send("STAT")
	if l := c.line(); l != "+OK 2 460" {
		t.Fatalf("after the exchange: %q", l)
	}
	if seen := strings.Join(srv.saw(), "\n"); !strings.Contains(seen, "UkVUUiAx") {
		t.Errorf("the exchange's line did not reach the server:\n%s", seen)
	}
}

// `AUTH` with no mechanism is refused. It names nothing, so neither require_tls
// nor the mechanism list has anything to decide about -- and the exchange that
// used to follow it moved this relay's state to transaction on the server's
// `+OK`, with no credential behind it and no name to attribute anything to.
// From there every command the RFC 1939 state table exists to hold back passed.
func TestAuthWithNoMechanismIsRefused(t *testing.T) {
	srv := startServer(t, &fakeServer{sasl: true})
	s, addr := relay(t, noTLS, srv.addr())
	c := dial(t, addr)
	c.line()
	c.send("AUTH")
	if l := c.line(); !strings.HasPrefix(l, "-ERR") || !strings.Contains(l, "auth_no_mechanism") {
		t.Fatalf("a bare AUTH: %q", l)
	}
	// The state did not move, so a transaction command is still refused.
	c.send("RETR 1")
	if l := c.line(); !strings.HasPrefix(l, "-ERR") {
		t.Fatalf("RETR after a bare AUTH: %q", l)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "AUTH") ||
		strings.Contains(seen, "RETR") {
		t.Errorf("a refused command reached the server:\n%s", seen)
	}
	if s.Stats().Refusals["pop3"]["auth_no_mechanism"] == 0 {
		t.Errorf("refusals: %v", s.Stats().Refusals["pop3"])
	}
}

// A client that is not allowed to connect is refused before anything is
// dialled, which is the one refusal this kind makes with no session at all.
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

// deny_response: drop says nothing at all, which is what a listener facing
// the open internet may prefer: a refused client learns that the command
// went nowhere and nothing about why.
func TestDenyResponseDropSaysNothing(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	_, addr := relay(t, noTLS+"        read_only: true\n        deny_response: drop\n", srv.addr())
	c := dial(t, addr)
	c.login()
	c.send("DELE 1")
	// Nothing comes back for the refused command, and the next one is
	// answered normally -- so the connection is still in step.
	c.send("STAT")
	if l := c.line(); l != "+OK 2 460" {
		t.Fatalf("after a dropped refusal: %q", l)
	}
	if seen := strings.Join(srv.saw(), "\n"); strings.Contains(seen, "DELE") {
		t.Errorf("the refused command reached the server:\n%s", seen)
	}
}

// The behavioural models see the account, the command and the volume, and a
// finding on this kind reaches the ban ladder.
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
	c.login()
	c.send("STAT")
	if l := c.line(); l != "+OK 2 460" {
		t.Fatalf("STAT with the models on: %q", l)
	}
	c.send("UIDL")
	if l := c.line(); !strings.HasPrefix(l, "+OK") {
		t.Fatalf("UIDL with the models on: %q", l)
	}
	c.body()
	// With no settling window every command is a symbol the models have not
	// seen, and the action is alert -- so the traffic is carried and the
	// findings are counted, which is the combination an estate turns on
	// first.
	if counts := s.Counters().RefusalCounts()["pop3"]; len(counts) == 0 {
		t.Error("the models reported nothing with settle: 0s and novelty on")
	}
}
