package proxy

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

	"github.com/rom/xproxy/internal/testutil"
)

// fakeMTA is a mail server that says yes. It records the messages it
// received so a test can prove that what the proxy forwarded is what the
// client sent, byte for byte.
type fakeMTA struct {
	ln       net.Listener
	mu       sync.Mutex
	messages []string
	commands []string
	// caps are the EHLO keywords it advertises.
	caps []string
	// tlsCfg makes it accept STARTTLS.
	tlsCfg *tls.Config
	// garbage replaces every reply with something unparseable.
	garbage bool
}

func startMTA(t *testing.T, m *fakeMTA) *fakeMTA {
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

func (m *fakeMTA) addr() string { return m.ln.Addr().String() }

func (m *fakeMTA) got() ([]string, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.commands...), append([]string(nil), m.messages...)
}

func (m *fakeMTA) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	write := func(s string) bool {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := io.WriteString(c, s)
		return err == nil
	}
	if m.garbage {
		_ = write("hello there\r\n")
		return
	}
	if !write("220 mta.invalid ESMTP Postfix (secret build 3.4.1)\r\n") {
		return
	}
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		m.mu.Lock()
		m.commands = append(m.commands, cmd)
		m.mu.Unlock()
		verb, _, _ := strings.Cut(strings.ToUpper(cmd), " ")
		switch verb {
		case "EHLO":
			reply := "250-mta.invalid\r\n"
			for _, cp := range m.caps {
				reply += "250-" + cp + "\r\n"
			}
			reply += "250 HELP\r\n"
			if !write(reply) {
				return
			}
		case "HELO":
			if !write("250 mta.invalid\r\n") {
				return
			}
		case "STARTTLS":
			if m.tlsCfg == nil {
				if !write("502 5.5.1 no\r\n") {
					return
				}
				continue
			}
			if !write("220 2.0.0 go ahead\r\n") {
				return
			}
			tc := tls.Server(c, m.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			c = tc
			br = bufio.NewReader(c)
		case "AUTH":
			if !write("235 2.7.0 authenticated\r\n") {
				return
			}
		case "DATA":
			if !write("354 end with .\r\n") {
				return
			}
			var body strings.Builder
			for {
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				body.WriteString(l)
			}
			m.mu.Lock()
			m.messages = append(m.messages, body.String())
			m.mu.Unlock()
			if !write("250 2.0.0 queued as ABC123\r\n") {
				return
			}
		case "QUIT":
			_ = write("221 2.0.0 bye\r\n")
			return
		default:
			if !write("250 2.0.0 ok\r\n") {
				return
			}
		}
	}
}

// smtpClient is the test's side of a session: write a line, read a reply.
type smtpClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func dialSMTP(t *testing.T, addr string) *smtpClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &smtpClient{t: t, conn: c, br: bufio.NewReader(c)}
}

func (c *smtpClient) send(format string, args ...any) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(c.conn, format+"\r\n", args...); err != nil {
		c.t.Fatalf("write %q: %v", format, err)
	}
}

// raw writes exactly what it is given, so a test can pipeline or send a
// bare newline on purpose.
func (c *smtpClient) raw(s string) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c.conn, s); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// reply reads one reply and returns its code and every line joined.
func (c *smtpClient) reply() (int, string) {
	c.t.Helper()
	var lines []string
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := c.br.ReadString('\n')
		if err != nil {
			c.t.Fatalf("read reply: %v (so far %q)", err, strings.Join(lines, "|"))
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) >= 4 && line[3] == '-' {
			continue
		}
		code := 0
		if _, err := fmt.Sscanf(line[:3], "%d", &code); err != nil {
			c.t.Fatalf("bad reply %q", line)
		}
		return code, strings.Join(lines, "|")
	}
}

func (c *smtpClient) expect(want int, what string) string {
	c.t.Helper()
	code, text := c.reply()
	if code != want {
		c.t.Fatalf("%s: got %d (%s), want %d", what, code, text, want)
	}
	return text
}

func (c *smtpClient) starttls(pool *x509.CertPool) {
	c.t.Helper()
	tc := tls.Client(c.conn, &tls.Config{ServerName: "mail.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		c.t.Fatalf("client handshake: %v", err)
	}
	c.conn = tc
	c.br = bufio.NewReader(tc)
}

const smtpYAML = `
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: smtp
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      smtp:
        upstream: mta
        banner: "mail.test ESMTP xproxy"
        max_recipients: 2
        max_errors: 3
        max_message_size: 400
%s
logging: {access: {enabled: false}}
upstreams:
  - name: mta
    endpoints: [{address: %s}]
`

func smtpServerFor(t *testing.T, m *fakeMTA, extra string) (*Server, string, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "mail.test")
	yaml := fmt.Sprintf(smtpYAML, cert, key, extra, m.addr())
	s, _ := startServer(t, yaml)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return s, s.Addrs()["mail"], pool
}

// TestSMTPRelay walks a whole submission session and checks that the
// message the upstream stored is the one the client sent, that the
// banner is the proxy's rather than the mail server's, and that the
// capability list is the proxy's promise and not the upstream's.
func TestSMTPRelay(t *testing.T) {
	m := startMTA(t, &fakeMTA{caps: []string{"PIPELINING", "SIZE 10240000", "CHUNKING", "STARTTLS"}})
	s, addr, pool := smtpServerFor(t, m, "        require_tls: true")

	c := dialSMTP(t, addr)
	greeting := c.expect(220, "greeting")
	if strings.Contains(greeting, "Postfix") {
		t.Fatalf("the upstream banner reached the client: %q", greeting)
	}
	c.send("EHLO client.test")
	caps := c.expect(250, "ehlo")
	for _, gone := range []string{"CHUNKING"} {
		if strings.Contains(caps, gone) {
			t.Fatalf("%s should not be advertised: %q", gone, caps)
		}
	}
	for _, want := range []string{"STARTTLS", "SIZE 400", "PIPELINING"} {
		if !strings.Contains(caps, want) {
			t.Fatalf("%s should be advertised: %q", want, caps)
		}
	}
	if strings.Contains(caps, "SIZE 10240000") {
		t.Fatalf("the upstream's larger SIZE survived: %q", caps)
	}
	// require_tls holds the transaction until STARTTLS has happened.
	c.send("MAIL FROM:<a@client.test>")
	c.expect(530, "mail before tls")

	c.send("STARTTLS")
	c.expect(220, "starttls")
	c.starttls(pool)
	c.send("EHLO client.test")
	caps = c.expect(250, "ehlo after tls")
	if strings.Contains(caps, "STARTTLS") {
		t.Fatalf("STARTTLS offered twice: %q", caps)
	}
	c.send("MAIL FROM:<a@client.test>")
	c.expect(250, "mail")
	c.send("RCPT TO:<b@mta.invalid>")
	c.expect(250, "rcpt")
	c.send("DATA")
	c.expect(354, "data")
	c.raw("Subject: hello\r\n\r\n..dot stuffed\r\nbody\r\n.\r\n")
	c.expect(250, "message")
	c.send("QUIT")
	c.expect(221, "quit")

	_, msgs := m.got()
	if len(msgs) != 1 {
		t.Fatalf("upstream stored %d messages", len(msgs))
	}
	if want := "Subject: hello\r\n\r\n..dot stuffed\r\nbody\r\n"; msgs[0] != want {
		t.Fatalf("message was rewritten:\n got %q\nwant %q", msgs[0], want)
	}
	sn := s.stats.snapshot()
	if sn.SMTPMessages != 1 || sn.SMTPTLSUpgrades != 1 || sn.SMTPSessions != 1 {
		t.Fatalf("counters: %+v", struct{ M, T, S uint64 }{sn.SMTPMessages, sn.SMTPTLSUpgrades, sn.SMTPSessions})
	}
}

// TestSMTPStartTLSInjection is CVE-2011-0411: a command pipelined behind
// STARTTLS is written in clear and would be read as though it had
// arrived inside the encrypted session.
func TestSMTPStartTLSInjection(t *testing.T) {
	m := startMTA(t, &fakeMTA{caps: []string{"PIPELINING"}})
	s, addr, _ := smtpServerFor(t, m, "        require_tls: true")

	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	c.raw("STARTTLS\r\nRSET\r\n")
	code, text := c.reply()
	if code != 554 {
		t.Fatalf("pipelined STARTTLS: got %d (%s), want 554", code, text)
	}
	if _, err := c.br.ReadString('\n'); err == nil {
		t.Fatal("the session should have ended")
	}
	if sn := s.stats.snapshot(); sn.SMTPProtocolErrors == 0 {
		t.Fatal("the injection was not counted")
	}
	cmds, _ := m.got()
	for _, cmd := range cmds {
		if strings.EqualFold(cmd, "RSET") {
			t.Fatal("the injected command reached the upstream")
		}
	}
}

// TestSMTPSmuggling is the 2023 class: a dot on a line ended by LF alone
// ends the message for a permissive parser and not for a strict one.
// The proxy refuses to be either, so the second message never exists.
func TestSMTPSmuggling(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	_, addr, _ := smtpServerFor(t, m, "        tls_mode: none\n        require_tls: false")

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
	c.raw("innocent\r\n\n.\nMAIL FROM:<spoofed@mta.invalid>\r\nRCPT TO:<victim@mta.invalid>\r\nDATA\r\nforged\r\n.\r\n")
	code, text := c.reply()
	if code != 500 {
		t.Fatalf("smuggled message: got %d (%s), want 500", code, text)
	}
	_, msgs := m.got()
	for _, msg := range msgs {
		if strings.Contains(msg, "forged") {
			t.Fatalf("the smuggled message was delivered: %q", msg)
		}
	}
}

// TestSMTPLimits covers the bounds that keep one session from becoming a
// fan-out: recipients, message size, unknown verbs and the error count
// that ends a walk through the command space.
func TestSMTPLimits(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	_, addr, _ := smtpServerFor(t, m, "        tls_mode: none\n        require_tls: false")

	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	// A declared size over the limit costs nobody the body.
	c.send("MAIL FROM:<a@client.test> SIZE=99999")
	c.expect(552, "declared size")
	c.send("MAIL FROM:<a@client.test>")
	c.expect(250, "mail")
	c.send("RCPT TO:<one@mta.invalid>")
	c.expect(250, "rcpt 1")
	c.send("RCPT TO:<two@mta.invalid>")
	c.expect(250, "rcpt 2")
	c.send("RCPT TO:<three@mta.invalid>")
	c.expect(452, "rcpt 3")
	// VRFY is not in the default command set. It is also the third
	// refusal, which is max_errors: the walk through the command space
	// ends here rather than going on for free.
	c.send("VRFY postmaster")
	c.expect(502, "vrfy")
	c.expect(421, "too many errors")
}

// A message that runs past max_message_size is refused, and the upstream
// is dropped rather than handed a truncated message.
func TestSMTPMessageTooLarge(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	_, addr, _ := smtpServerFor(t, m, "        tls_mode: none\n        require_tls: false")

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
	c.raw(strings.Repeat("x", 200) + "\r\n" + strings.Repeat("y", 300) + "\r\n.\r\n")
	c.expect(552, "oversize message")
	if _, msgs := m.got(); len(msgs) != 0 {
		t.Fatalf("a truncated message was delivered: %q", msgs)
	}
}

// A client outside allow_clients gets one refusal and no session.
func TestSMTPAllowClients(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	s, addr, _ := smtpServerFor(t, m, "        tls_mode: none\n        require_tls: false\n        allow_clients: [\"192.0.2.0/24\"]")

	c := dialSMTP(t, addr)
	c.expect(554, "denied")
	if _, err := c.br.ReadString('\n'); err == nil {
		t.Fatal("the session should have ended")
	}
	if sn := s.stats.snapshot(); sn.SMTPRejected == 0 {
		t.Fatal("the refusal was not counted")
	}
	if cmds, _ := m.got(); len(cmds) != 0 {
		t.Fatal("a denied client reached the upstream")
	}
}

// A reply the proxy cannot parse is never passed through: it is exactly
// the case where the client would read something the proxy did not.
func TestSMTPUpstreamGarbage(t *testing.T) {
	m := startMTA(t, &fakeMTA{garbage: true})
	_, addr, _ := smtpServerFor(t, m, "        tls_mode: none\n        require_tls: false")

	c := dialSMTP(t, addr)
	c.expect(421, "upstream garbage")
}

// An overlong command line is answered once and ends the session; the
// tail of it is never read as a command of its own.
func TestSMTPLongCommand(t *testing.T) {
	m := startMTA(t, &fakeMTA{})
	_, addr, _ := smtpServerFor(t, m, "        tls_mode: none\n        require_tls: false")

	c := dialSMTP(t, addr)
	c.expect(220, "greeting")
	c.raw("NOOP " + strings.Repeat("x", 600) + "\r\nQUIT\r\n")
	c.expect(500, "overlong line")
	cmds, _ := m.got()
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "NOOP") {
			t.Fatalf("the overlong command reached the upstream: %q", cmd)
		}
	}
}

// The upstream leg can have its own TLS, negotiated with STARTTLS, and
// the proxy refuses to continue in clear if the upstream will not.
func TestSMTPUpstreamSTARTTLS(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "mta.test")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	m := startMTA(t, &fakeMTA{caps: []string{"STARTTLS"},
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}})
	lcert, lkey := ca.Issue(t, dir, "mail.test")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: smtp
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      smtp:
        upstream: mta
        tls_mode: none
        require_tls: false
        upstream_tls_mode: starttls
        upstream_tls: {server_name: mta.test, ca_file: %s}
logging: {access: {enabled: false}}
upstreams:
  - name: mta
    endpoints: [{address: %s}]
`, lcert, lkey, ca.Path, m.addr())
	s, _ := startServer(t, yaml)

	c := dialSMTP(t, s.Addrs()["mail"])
	c.expect(220, "greeting")
	c.send("EHLO client.test")
	c.expect(250, "ehlo")
	c.send("MAIL FROM:<a@client.test>")
	c.expect(250, "mail")
	c.send("QUIT")
	c.expect(221, "quit")

	cmds, _ := m.got()
	if len(cmds) == 0 || !strings.EqualFold(cmds[1], "STARTTLS") {
		t.Fatalf("the proxy did not upgrade the upstream leg: %v", cmds)
	}
}

// A listener whose upstream will not do STARTTLS fails the session
// rather than falling back to plaintext.
func TestSMTPUpstreamSTARTTLSRefused(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	m := startMTA(t, &fakeMTA{}) // no STARTTLS capability
	lcert, lkey := ca.Issue(t, dir, "mail.test")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: mail
      address: "127.0.0.1:0"
      kind: smtp
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      smtp:
        upstream: mta
        tls_mode: none
        require_tls: false
        upstream_tls_mode: starttls
logging: {access: {enabled: false}}
upstreams:
  - name: mta
    endpoints: [{address: %s}]
`, lcert, lkey, m.addr())
	s, _ := startServer(t, yaml)
	c := dialSMTP(t, s.Addrs()["mail"])
	c.expect(421, "no upstream tls")
}
