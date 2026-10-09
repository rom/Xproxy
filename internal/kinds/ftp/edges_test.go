package ftp_test

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

	_ "github.com/rom/xproxy/internal/kinds/ftp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The edges of an FTP session: the bounds around it, every refusal being
// able to be the last one, and what the proxy tells a client when the server
// behind it is not behaving like an FTP server.
//
// FTP is two connections, and the proxy is one end of both. That is what
// makes the failure cases worth their own tests: a control reply the proxy
// could not read, or a passive address it will not use, has to end as a reply
// to the client rather than as a data connection going somewhere nobody
// chose.

// rudeTarget is a server that answers from a script rather than behaving.
type rudeTarget struct {
	ln net.Listener
	// greeting is written before anything is read; "" closes instead.
	greeting string
	// answer is the reply to the nth command, written as it goes on the
	// wire; "" closes the connection rather than answering.
	answer func(verb, arg string, n int) string
	// implicit wraps the connection in TLS before the greeting.
	implicit *tls.Config

	mu   sync.Mutex
	cmds []string
}

func startRude(t *testing.T, tg *rudeTarget) *rudeTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go tg.serve(c)
		}
	}()
	return tg
}

func (tg *rudeTarget) addr() string { return tg.ln.Addr().String() }

func (tg *rudeTarget) saw() []string {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]string(nil), tg.cmds...)
}

func (tg *rudeTarget) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	if tg.implicit != nil {
		tc := tls.Server(c, tg.implicit)
		if err := tc.Handshake(); err != nil {
			return
		}
		c = tc
	}
	if tg.greeting == "" {
		return
	}
	if _, err := io.WriteString(c, tg.greeting+"\r\n"); err != nil {
		return
	}
	br := bufio.NewReader(c)
	for i := 0; ; i++ {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		tg.mu.Lock()
		tg.cmds = append(tg.cmds, line)
		tg.mu.Unlock()
		verb, arg, _ := strings.Cut(line, " ")
		rep := tg.answer(strings.ToUpper(verb), arg, i)
		if rep == "" {
			return
		}
		if _, err := io.WriteString(c, rep); err != nil {
			return
		}
	}
}

// ordinary answers the commands a login needs and nothing else, which is
// what a test about one later command wants behind it.
func ordinary(table map[string]string) func(string, string, int) string {
	return func(verb, _ string, _ int) string {
		if r, ok := table[verb]; ok {
			return r
		}
		switch verb {
		case "USER":
			return "331 password please\r\n"
		case "PASS":
			return "230 logged in\r\n"
		case "QUIT":
			return "221 bye\r\n"
		}
		return "200 ok\r\n"
	}
}

// rudeBastion is a listener in front of a scripted target.
func rudeBastion(t *testing.T, section string, tg *rudeTarget, top string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:0"
      kind: ftp
      ftp:
        upstream: servers
%s
logging: {access: {enabled: false}}
upstreams:
  - name: servers
    endpoints: [{address: %q}]
%s
`, section, tg.addr(), top))
	return s, proxytest.Addr(t, s, "files")
}

// dialRaw opens a connection without expecting a greeting, which is what
// the tests about greetings that are not 220 need.
func dialRaw(t *testing.T, addr string) *ftpClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &ftpClient{t: t, conn: c, br: bufio.NewReader(c)}
}

func awaitFTPReason(t *testing.T, s *proxy.Server, reason string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if s.Stats().Refusals["ftp"][reason] > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not counted: %v", reason, s.Stats().Refusals["ftp"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Every refusal this proxy makes can also be the last one a session gets,
// and that is separate code at every refusal site: the reply, and the
// decision to stop talking to this client. A prober walking the command
// space to find the policy's edges is what max_errors is for, so each site
// is driven with the bound set to one -- the refusal is the one allowed, and
// the session ends on it.
func TestEveryRefusalCanBeTheLastOne(t *testing.T) {
	for _, c := range []struct {
		name    string
		section string
		send    []string
		code    int
		reason  string
	}{
		{
			name: "a verb this proxy cannot name the effect of",
			send: []string{"XYZZY"}, code: 502, reason: "unknown_command",
		},
		{
			name:    "a verb off the command list",
			section: "        commands: [USER, PASS, QUIT, NOOP]",
			send:    []string{"SYST"}, code: 502, reason: "command_refused",
		},
		{
			name: "a line that is not a command",
			send: []string{"  "}, code: 500, reason: "malformed_command",
		},
		{
			name:    "a write where the policy is read only",
			section: "        read_only: true",
			send:    []string{"DELE /pub/x"}, code: 532, reason: "read_only",
		},
		{
			name:    "a path outside the policy",
			section: `        allow_paths: ["/pub/**"]`,
			send:    []string{"RETR /etc/shadow"}, code: 550, reason: "path_refused",
		},
		{
			// CCC asks the server to drop TLS on the control channel and
			// keep the session: the commands after it, the passwords and
			// the paths, would cross in clear.
			name:    "a request to drop the control channel's protection",
			section: "        commands: [USER, PASS, QUIT, NOOP, CCC]",
			send:    []string{"CCC"}, code: 534, reason: "ccc_refused",
		},
		{
			name: "active mode where it is not available",
			send: []string{"PORT 127,0,0,1,4,1"}, code: 502, reason: "active_refused",
		},
		{
			name:    "an active address that is not the client's own",
			section: "        allow_active: true",
			send:    []string{"PORT 10,1,2,3,4,1"}, code: 501, reason: "bounce_refused",
		},
		{
			name:    "an active address that is not an address",
			section: "        allow_active: true",
			send:    []string{"PORT sideways"}, code: 501, reason: "malformed_address",
		},
		{
			// On a listener with no certificate there is no AUTH to offer
			// at all, which is what this answers; a listener that has one
			// refuses everything but TLS with 504.
			name: "an authentication mechanism on a listener with no certificate",
			send: []string{"AUTH GSSAPI"}, code: 534, reason: "auth_refused",
		},
		{
			name: "a transfer with no data connection arranged",
			send: []string{"RETR /pub/readme.txt"}, code: 425, reason: "no_data_connection",
		},
		{
			name: "a restart marker that is not an offset",
			send: []string{"REST sideways"}, code: 501, reason: "rest_invalid",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			tg := startRude(t, &rudeTarget{greeting: "220 target ready", answer: ordinary(nil)})
			s, addr := rudeBastion(t, "        max_errors: 1\n"+c.section, tg, "")
			cl := dialFTP(t, addr)
			cl.login("alice", "secret")
			for i, line := range c.send {
				if i < len(c.send)-1 {
					cl.cmd("%s", line)
					continue
				}
				cl.raw(line + "\r\n")
				code, text := cl.reply()
				if code != c.code {
					t.Fatalf("%s: got %d (%s), want %d", line, code, text, c.code)
				}
			}
			awaitFTPReason(t, s, c.reason)
			// The one refusal this session was allowed was its last: the
			// connection ends rather than letting the walk continue.
			_ = cl.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := cl.br.ReadString('\n'); err == nil {
				t.Error("the session was left open after its last allowed refusal")
			}
			// And the target never heard the command that was refused.
			if verb := strings.Fields(c.send[len(c.send)-1]); len(verb) > 0 && verb[0] != "USER" && verb[0] != "PASS" {
				for _, seen := range tg.saw() {
					if strings.HasPrefix(seen, verb[0]) {
						t.Errorf("the refused command reached the target: %s", seen)
					}
				}
			}
		})
	}
}

// What the proxy does with a passive reply it cannot use. The port the
// target announces is used and the address is not -- the proxy dials the
// host its control connection is already talking to -- so a reply that
// cannot be read at all is the one case left, and it ends as a reply to the
// client rather than as a data connection to nowhere.
func TestAPassiveReplyTheProxyCannotUse(t *testing.T) {
	for _, c := range []struct {
		name, verb, reply string
		code              int
	}{
		{"six octets that are not six octets", "PASV", "227 Entering Passive Mode (sideways)\r\n", 425},
		{"an extended reply with no port in it", "EPSV", "229 Entering Extended Passive Mode (|||nope|)\r\n", 425},
		{"a refusal, which is the target's own answer", "PASV", "500 no passive mode here\r\n", 500},
	} {
		t.Run(c.name, func(t *testing.T) {
			tg := startRude(t, &rudeTarget{greeting: "220 target ready",
				answer: ordinary(map[string]string{c.verb: c.reply})})
			s, addr := rudeBastion(t, "", tg, "")
			cl := dialFTP(t, addr)
			cl.login("alice", "secret")
			code, text := cl.cmd("%s", c.verb)
			if code != c.code {
				t.Fatalf("%s: got %d (%s), want %d", c.verb, code, text, c.code)
			}
			if c.code == 425 {
				awaitFTPReason(t, s, "upstream_address")
			}
			// The session goes on: the target answered, and a client that
			// asked for passive mode can ask again.
			if code, _ := cl.cmd("NOOP"); code != 200 {
				t.Errorf("the session did not go on: NOOP got %d", code)
			}
		})
	}
}

// A target that goes away mid-session. Each of the three places the proxy
// reads a reply has to end as a 4xx to the client: a client left waiting on
// a reply that will never come is a client that hangs until its own timeout.
func TestATargetThatGoesAwayMidSession(t *testing.T) {
	for _, c := range []struct {
		name  string
		after string
		send  []string
		code  int
	}{
		{"on an ordinary command", "NOOP", []string{"NOOP"}, 421},
		{"on a passive reply", "PASV", []string{"PASV"}, 421},
		{"on a transfer", "RETR", []string{"PASV", "RETR /pub/readme.txt"}, 421},
	} {
		t.Run(c.name, func(t *testing.T) {
			tg := startRude(t, &rudeTarget{greeting: "220 target ready",
				answer: func(verb, _ string, _ int) string {
					if verb == c.after {
						return "" // the connection ends instead of answering
					}
					switch verb {
					case "USER":
						return "331 password please\r\n"
					case "PASS":
						return "230 logged in\r\n"
					case "PASV":
						// A parseable address, so the proxy gets as far as
						// the transfer: the port is one nothing listens on.
						return "227 Entering Passive Mode (127,0,0,1,0,1)\r\n"
					}
					return "200 ok\r\n"
				}})
			_, addr := rudeBastion(t, "", tg, "")
			cl := dialFTP(t, addr)
			cl.login("alice", "secret")
			var code int
			var text string
			for _, line := range c.send {
				code, text = cl.cmd("%s", line)
			}
			if code != c.code {
				t.Fatalf("got %d (%s), want %d", code, text, c.code)
			}
		})
	}
}

// A refusal reaches the ban ladder whether or not it is worth an alert, and
// a banned client is turned away before the greeting: the ban is on the
// address, and a session that got as far as a greeting has already cost
// something.
func TestARefusalReachesTheBanLadderAndTheBanIsAppliedAtTheDoor(t *testing.T) {
	tg := startRude(t, &rudeTarget{greeting: "220 target ready", answer: ordinary(nil)})
	s, addr := rudeBastion(t, "        max_errors: 1\n        alert_on_deny: false", tg, `bans:
  action: reject
  triggers: [{name: files, reasons: [ftp_denied], threshold: 1, window: 1m, duration: 1h}]`)

	first := dialFTP(t, addr)
	first.login("alice", "secret")
	if code, _ := first.cmd("XYZZY"); code != 502 {
		t.Fatalf("an unknown verb was not refused")
	}
	awaitFTPReason(t, s, "unknown_command")
	for deadline := time.Now().Add(5 * time.Second); s.Stats().BansActive == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the refusal did not reach the ban ladder")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The next session from that address is refused with 421 before a
	// greeting, and the target never hears about it.
	before := len(tg.saw())
	second := dialRaw(t, addr)
	code, text := second.reply()
	if code != 421 {
		t.Fatalf("a banned client: got %d (%s), want 421", code, text)
	}
	awaitFTPReason(t, s, "banned")
	if n := len(tg.saw()); n != before {
		t.Errorf("the target saw %d more commands for a banned client", n-before)
	}
}

// The greeting a client is given is the proxy's own where one is
// configured: a greeting that names the target's software and version saves
// an attacker a question.
func TestTheConfiguredBannerReplacesTheTargets(t *testing.T) {
	tg := startRude(t, &rudeTarget{
		greeting: "220 ProFTPD 1.3.5a Server (Debian) [10.0.0.9]",
		answer:   ordinary(nil),
	})
	_, addr := rudeBastion(t, `        banner: "files.test FTP"`, tg, "")
	cl := dialRaw(t, addr)
	code, text := cl.reply()
	if code != 220 {
		t.Fatalf("greeting: %d %s", code, text)
	}
	if !strings.Contains(text, "files.test") {
		t.Errorf("the greeting is not the proxy's: %q", text)
	}
	if strings.Contains(text, "ProFTPD") || strings.Contains(text, "Debian") {
		t.Errorf("the target's own greeting reached the client: %q", text)
	}
}

// A target whose greeting is not a greeting is a target this proxy cannot
// start a session with, and the client is told the service is unavailable
// rather than being handed a reply nobody can act on.
func TestATargetThatDoesNotGreet(t *testing.T) {
	for _, c := range []struct{ name, greeting string }{
		{"a target that says nothing", ""},
		{"a target that refuses the connection", "421 too many users"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tg := startRude(t, &rudeTarget{greeting: c.greeting, answer: ordinary(nil)})
			_, addr := rudeBastion(t, "", tg, "")
			cl := dialRaw(t, addr)
			code, text := cl.reply()
			if code != 421 {
				t.Fatalf("got %d (%s), want 421", code, text)
			}
			if !strings.Contains(text, "unavailable") {
				t.Errorf("the refusal does not say what is wrong: %q", text)
			}
		})
	}
}

// An implicit-TLS listener is the FTPS-on-990 shape: there is no cleartext
// greeting to upgrade, so a client that opens with a command instead of a
// handshake is answered with nothing at all.
func TestAnImplicitTLSListenerSpeaksTLSFromTheFirstOctet(t *testing.T) {
	tg := startRude(t, &rudeTarget{greeting: "220 target ready", answer: ordinary(nil)})
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "files.test")
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:0"
      kind: ftp
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      ftp:
        upstream: servers
        tls_mode: implicit
logging: {access: {enabled: false}}
upstreams:
  - name: servers
    endpoints: [{address: %q}]
`, cert, key, tg.addr()))
	addr := proxytest.Addr(t, s, "files")

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	tc := tls.Client(raw, &tls.Config{ServerName: "files.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	br := bufio.NewReader(tc)
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "220") {
		t.Fatalf("greeting inside the handshake: %q %v", line, err)
	}
	if _, err := io.WriteString(tc, "USER alice\r\n"); err != nil {
		t.Fatal(err)
	}
	if line, err = br.ReadString('\n'); err != nil || !strings.HasPrefix(line, "331") {
		t.Fatalf("USER: %q %v", line, err)
	}

	t.Run("and a client that sends cleartext is not answered", func(t *testing.T) {
		plain, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = plain.Close() }()
		if _, err := io.WriteString(plain, "USER alice\r\n"); err != nil {
			t.Fatal(err)
		}
		_ = plain.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := plain.Read(make([]byte, 1)); err == nil {
			t.Errorf("a cleartext client read %d bytes", n)
		}
	})
}

// The leg to the target can be encrypted from its first octet too, and the
// proxy fills in the server name from the endpoint it dialled: an upstream
// pool is written as addresses, so without that there is nothing for
// verification to check against.
func TestTheUpstreamLegIsVerifiedAgainstTheEndpointItDialled(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "target.test")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	tg := startRude(t, &rudeTarget{
		implicit: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		greeting: "220 target ready", answer: ordinary(nil),
	})
	_, addr := rudeBastion(t, fmt.Sprintf(`        upstream_tls_mode: implicit
        upstream_tls: {ca_file: %s}`, ca.Path), tg, "")

	cl := dialFTP(t, addr)
	cl.login("alice", "secret")
	if code, _ := cl.cmd("NOOP"); code != 200 {
		t.Error("the session did not reach the target through TLS")
	}
	// What the target saw was inside the handshake: it read the login, which
	// it could only do on the far side of it.
	if !strings.Contains(strings.Join(tg.saw(), "|"), "USER alice") {
		t.Errorf("the target saw %v", tg.saw())
	}
}

// The session bound is on the whole session rather than on one command: a
// client that sends a legal command every few minutes would otherwise hold
// a connection, and a bastion's sessions are the thing an operator is
// accountable for.
func TestTheSessionBoundEndsALongSession(t *testing.T) {
	tg := startRude(t, &rudeTarget{greeting: "220 target ready", answer: ordinary(nil)})
	s, addr := rudeBastion(t, "        session_timeout: 400ms", tg, "")
	cl := dialFTP(t, addr)
	cl.login("alice", "secret")
	_ = cl.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	if _, err := cl.br.ReadString('\n'); err == nil {
		t.Error("the session was not ended by its bound")
	}
	if took := time.Since(start); took > 8*time.Second {
		t.Errorf("the session ended after %v, which is not the bound", took)
	}
	for deadline := time.Now().Add(5 * time.Second); s.Stats().FTPSessionsOpen != 0; {
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions are still open", s.Stats().FTPSessionsOpen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
