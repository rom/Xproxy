package ftp_test

import (
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"

	"bufio"
	"fmt"
	_ "github.com/rom/xproxy/internal/kinds/ftp"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// targetFTP is a minimal FTP server standing in for a real one: it
// answers the commands this proxy relays, opens a passive data
// connection when asked, and records what it was told to do.
type targetFTP struct {
	ln   net.Listener
	t    *testing.T
	mu   chan struct{}
	seen []string
	// content is what a RETR sends.
	content string
	// stored is what the last STOR received.
	stored string
}

func startTargetFTP(t *testing.T) *targetFTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg := &targetFTP{ln: ln, t: t, mu: make(chan struct{}, 1), content: "hello from the server\r\n"}
	tg.mu <- struct{}{}
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

func (tg *targetFTP) addr() string { return tg.ln.Addr().String() }

func (tg *targetFTP) record(s string) {
	<-tg.mu
	tg.seen = append(tg.seen, s)
	tg.mu <- struct{}{}
}

func (tg *targetFTP) commands() []string {
	<-tg.mu
	out := append([]string(nil), tg.seen...)
	tg.mu <- struct{}{}
	return out
}

func (tg *targetFTP) lastStored() string {
	<-tg.mu
	out := tg.stored
	tg.mu <- struct{}{}
	return out
}

func (tg *targetFTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	write := func(s string) bool {
		_, err := io.WriteString(c, s)
		return err == nil
	}
	if !write("220 target ftpd 1.2.3 ready\r\n") {
		return
	}
	var dataLn net.Listener
	defer func() {
		if dataLn != nil {
			_ = dataLn.Close()
		}
	}()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		tg.record(line)
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "USER":
			write("331 password please\r\n")
		case "PASS":
			write("230 logged in\r\n")
		case "SYST":
			write("215 UNIX Type: L8\r\n")
		case "TYPE", "MODE", "STRU", "NOOP", "PBSZ", "PROT", "OPTS":
			write("200 ok\r\n")
		case "PWD":
			write(`257 "/" is the current directory` + "\r\n")
		case "CWD":
			write("250 changed\r\n")
		case "FEAT":
			write("211-Features:\r\n MLST\r\n EPSV\r\n211 End\r\n")
		case "PASV":
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				write("425 cannot open\r\n")
				continue
			}
			if dataLn != nil {
				_ = dataLn.Close()
			}
			dataLn = l
			host, port := splitHostPortForTest(tg.t, l.Addr().String())
			write(fmt.Sprintf("227 Entering Passive Mode (%s,%d,%d)\r\n",
				strings.ReplaceAll(host, ".", ","), port>>8, port&0xff))
		case "EPSV":
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				write("425 cannot open\r\n")
				continue
			}
			if dataLn != nil {
				_ = dataLn.Close()
			}
			dataLn = l
			_, port := splitHostPortForTest(tg.t, l.Addr().String())
			write(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", port))
		case "PORT", "EPRT":
			write("200 ok\r\n")
		case "RETR", "LIST", "NLST", "MLSD":
			if dataLn == nil {
				write("425 no data connection\r\n")
				continue
			}
			write("150 opening data connection\r\n")
			dc, err := dataLn.Accept()
			if err != nil {
				write("426 failed\r\n")
				continue
			}
			_, _ = io.WriteString(dc, tg.content)
			_ = dc.Close()
			_ = dataLn.Close()
			dataLn = nil
			write("226 transfer complete\r\n")
		case "STOR", "APPE", "STOU":
			if dataLn == nil {
				write("425 no data connection\r\n")
				continue
			}
			write("150 opening data connection\r\n")
			dc, err := dataLn.Accept()
			if err != nil {
				write("426 failed\r\n")
				continue
			}
			b, _ := io.ReadAll(dc)
			_ = dc.Close()
			_ = dataLn.Close()
			dataLn = nil
			<-tg.mu
			tg.stored = string(b)
			tg.mu <- struct{}{}
			write("226 transfer complete\r\n")
		case "DELE", "MKD", "RMD", "RNFR", "RNTO":
			write("250 done\r\n")
		case "SIZE":
			write(fmt.Sprintf("213 %d\r\n", len(tg.content)))
		case "QUIT":
			write("221 bye\r\n")
			return
		default:
			write("502 not implemented: " + arg + "\r\n")
		}
	}
}

func splitHostPortForTest(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		t.Fatal(err)
	}
	return host, p
}

// ftpClient is the other end: enough of a client to drive the proxy.
type ftpClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func dialFTP(t *testing.T, addr string) *ftpClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	cl := &ftpClient{t: t, conn: c, br: bufio.NewReader(c)}
	if code, _ := cl.reply(); code != 220 {
		t.Fatalf("greeting was %d", code)
	}
	return cl
}

// reply reads one reply, following the continuation rule.
func (c *ftpClient) reply() (int, string) {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.br.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read reply: %v", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 4 {
		c.t.Fatalf("short reply %q", line)
	}
	var code int
	if _, err := fmt.Sscanf(line[:3], "%d", &code); err != nil {
		c.t.Fatalf("reply %q", line)
	}
	text := line[4:]
	if line[3] == '-' {
		for {
			more, err := c.br.ReadString('\n')
			if err != nil {
				c.t.Fatalf("read continuation: %v", err)
			}
			more = strings.TrimRight(more, "\r\n")
			if len(more) >= 4 && more[:3] == line[:3] && more[3] == ' ' {
				break
			}
		}
	}
	return code, text
}

// cmd sends a command and returns its reply.
func (c *ftpClient) cmd(format string, a ...any) (int, string) {
	c.t.Helper()
	line := fmt.Sprintf(format, a...)
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		c.t.Fatalf("write %q: %v", line, err)
	}
	return c.reply()
}

// raw sends bytes exactly as given, for the cases where a well formed
// command is not the point.
func (c *ftpClient) raw(s string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, s); err != nil {
		c.t.Fatalf("write %q: %v", s, err)
	}
}

// login does the usual opening exchange.
func (c *ftpClient) login(user, pass string) {
	c.t.Helper()
	if code, _ := c.cmd("USER %s", user); code != 331 {
		c.t.Fatalf("USER was %d", code)
	}
	if code, _ := c.cmd("PASS %s", pass); code != 230 {
		c.t.Fatalf("PASS was %d", code)
	}
}

// passive negotiates a transfer and returns the address the proxy
// advertised.
func (c *ftpClient) passive() string {
	c.t.Helper()
	code, text := c.cmd("PASV")
	if code != 227 {
		c.t.Fatalf("PASV was %d %q", code, text)
	}
	open := strings.IndexByte(text, '(')
	close := strings.LastIndexByte(text, ')')
	if open < 0 || close < open {
		c.t.Fatalf("PASV reply %q", text)
	}
	var h1, h2, h3, h4, p1, p2 int
	if _, err := fmt.Sscanf(text[open+1:close], "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2); err != nil {
		c.t.Fatalf("PASV reply %q: %v", text, err)
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", h1, h2, h3, h4, p1<<8|p2)
}

// ftpBastion starts a proxy in front of a target FTP server, with extra
// configuration lines indented under the ftp section.
func ftpBastion(t *testing.T, extra string) (*proxy.Server, string, *targetFTP) {
	t.Helper()
	tg := startTargetFTP(t)
	yaml := fmt.Sprintf(`
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
    endpoints: [{address: %s}]
`, extra, tg.addr())
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["files"], tg
}

// The proxy is one end of the data connection: the address a client is
// given is the proxy's own, never the target's, and the file still
// arrives.
func TestFTPPassiveIsMediated(t *testing.T) {
	s, addr, tg := ftpBastion(t, "")
	c := dialFTP(t, addr)
	c.login("alice", "secret")

	dataAddr := c.passive()
	if dataAddr == tg.addr() {
		t.Fatal("the client was given the target's own data address")
	}
	proxyHost, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	gotHost, _, err := net.SplitHostPort(dataAddr)
	if err != nil {
		t.Fatal(err)
	}
	if gotHost != proxyHost {
		t.Fatalf("data address %s is not on the proxy (%s)", dataAddr, proxyHost)
	}

	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the data connection: %v", err)
	}
	defer func() { _ = dc.Close() }()
	if code, _ := c.cmd("RETR /pub/readme.txt"); code != 150 {
		t.Fatalf("RETR was %d", code)
	}
	body, err := io.ReadAll(dc)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != tg.content {
		t.Fatalf("got %q, want %q", body, tg.content)
	}
	if code, _ := c.reply(); code != 226 {
		t.Fatalf("completion was %d", code)
	}
	if sn := s.Stats(); sn.FTPTransfers != 1 {
		t.Fatalf("transfers counted: %d", sn.FTPTransfers)
	}
}

// EPSV is mediated the same way, and the port advertised is the
// proxy's.
func TestFTPExtendedPassive(t *testing.T) {
	_, addr, tg := ftpBastion(t, "")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	code, text := c.cmd("EPSV")
	if code != 229 {
		t.Fatalf("EPSV was %d %q", code, text)
	}
	var port int
	if _, err := fmt.Sscanf(text[strings.IndexByte(text, '('):], "(|||%d|)", &port); err != nil {
		t.Fatalf("EPSV reply %q: %v", text, err)
	}
	_, targetPort := splitHostPortForTest(t, tg.addr())
	if port == targetPort {
		t.Fatal("the client was given the target's port")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the data connection: %v", err)
	}
	defer func() { _ = dc.Close() }()
	if code, _ := c.cmd("LIST"); code != 150 {
		t.Fatalf("LIST was %d", code)
	}
	if _, err := io.ReadAll(dc); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.reply(); code != 226 {
		t.Fatal("the transfer did not complete")
	}
}

// PORT and EPRT ask the proxy to connect to an address the client
// names. That is the bounce attack, and it is refused by default.
func TestFTPActiveRefused(t *testing.T) {
	_, addr, tg := ftpBastion(t, "")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	for _, cmd := range []string{"PORT 10,0,0,1,4,1", "EPRT |1|10.0.0.1|1025|"} {
		if code, _ := c.cmd("%s", cmd); code != 502 {
			t.Errorf("%s was %d, want 502", cmd, code)
		}
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "PORT") || strings.HasPrefix(seen, "EPRT") {
			t.Fatalf("an active command reached the target: %s", seen)
		}
	}
}

// With active mode on, the address still has to be the client's own:
// that check is the whole of the bounce defence.
func TestFTPActiveMustBeYourOwnAddress(t *testing.T) {
	_, addr, tg := ftpBastion(t, "        allow_active: true")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	for _, cmd := range []string{
		"PORT 10,0,0,1,4,1",      // somebody else entirely
		"PORT 127,0,0,1,0,25",    // the client's address, a privileged port
		"EPRT |1|10.0.0.1|1025|", // the same by the other spelling
	} {
		code, _ := c.cmd("%s", cmd)
		if code != 501 {
			t.Errorf("%s was %d, want 501", cmd, code)
		}
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "PORT") || strings.HasPrefix(seen, "EPRT") {
			t.Fatalf("a bounce reached the target: %s", seen)
		}
	}
	// The client's own address, on an unprivileged port, is accepted —
	// and the target is told the proxy's address, not the client's.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, port := splitHostPortForTest(t, ln.Addr().String())
	if code, _ := c.cmd("PORT 127,0,0,1,%d,%d", port>>8, port&0xff); code != 200 {
		t.Fatalf("the client's own address was refused: %d", code)
	}
	var forwarded string
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "PORT") {
			forwarded = seen
		}
	}
	if forwarded == "" {
		t.Fatal("nothing was forwarded")
	}
	if strings.Contains(forwarded, fmt.Sprintf(",%d,%d", port>>8, port&0xff)) {
		t.Fatalf("the client's own port was forwarded to the target: %s", forwarded)
	}
}

// A verb the proxy cannot name the effect of never reaches the target.
func TestFTPUnknownAndRefusedCommands(t *testing.T) {
	_, addr, tg := ftpBastion(t, "        commands: [USER, PASS, QUIT, NOOP, SYST]")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, _ := c.cmd("SITE CHMOD 777 /etc"); code != 502 {
		t.Errorf("SITE was allowed")
	}
	if code, _ := c.cmd("XYZZY"); code != 502 {
		t.Errorf("an unknown verb was allowed")
	}
	if code, _ := c.cmd("SYST"); code != 215 {
		t.Errorf("an allowed command was refused")
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "SITE") || strings.HasPrefix(seen, "XYZZY") {
			t.Fatalf("a refused command reached the target: %s", seen)
		}
	}
}

// A command line that is not exactly CRLF-terminated is refused: a bare
// LF inside an argument is how one command becomes two, with the proxy
// reading one and the target reading both.
func TestFTPCommandSplitting(t *testing.T) {
	_, addr, tg := ftpBastion(t, "")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	c.raw("NOOP\nDELE /etc/passwd\r\n")
	if code, _ := c.reply(); code != 500 {
		t.Error("a bare newline was accepted")
	}
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "DELE") {
			t.Fatalf("the smuggled command reached the target: %s", seen)
		}
	}
}

// read_only refuses what changes the server, before the target hears
// it.
func TestFTPReadOnly(t *testing.T) {
	_, addr, tg := ftpBastion(t, "        read_only: true")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	for _, cmd := range []string{"DELE /pub/x", "MKD /pub/y", "RMD /pub/z", "STOR /pub/a"} {
		if code, _ := c.cmd("%s", cmd); code != 532 {
			t.Errorf("%s was %d, want 532", cmd, code)
		}
	}
	if code, _ := c.cmd("SIZE /pub/readme.txt"); code != 213 {
		t.Error("a read was refused by a read-only policy")
	}
	for _, seen := range tg.commands() {
		for _, bad := range []string{"DELE", "MKD", "RMD", "STOR"} {
			if strings.HasPrefix(seen, bad) {
				t.Fatalf("%s reached the target", bad)
			}
		}
	}
}

// Paths are matched after the working directory the proxy has been
// following, so a relative path cannot walk out of the tree.
func TestFTPPathPolicy(t *testing.T) {
	_, addr, tg := ftpBastion(t, `        allow_paths: ["/pub/**"]
        deny_paths: ["/pub/private/**"]`)
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, _ := c.cmd("RETR /pub/readme.txt"); code != 425 {
		// 425 because no data connection was arranged; the path passed.
		t.Errorf("an allowed path was refused with %d", code)
	}
	for _, path := range []string{"/etc/passwd", "/pub/private/keys", "../etc/passwd"} {
		if code, _ := c.cmd("RETR %s", path); code != 550 {
			t.Errorf("%s was %d, want 550", path, code)
		}
	}
	// The working directory is followed, so a relative path resolves
	// where the target would resolve it.
	if code, _ := c.cmd("CWD /pub"); code != 250 {
		t.Fatal("CWD was refused")
	}
	if code, _ := c.cmd("RETR ../etc/passwd"); code != 550 {
		t.Error("a relative path walked out of the tree")
	}
	for _, seen := range tg.commands() {
		if strings.Contains(seen, "passwd") || strings.Contains(seen, "private") {
			t.Fatalf("a refused path reached the target: %s", seen)
		}
	}
}

// Extensions decide what a file may be called, and every extension in
// the name is read.
func TestFTPExtensionPolicy(t *testing.T) {
	_, addr, _ := ftpBastion(t, "        deny_extensions: [exe, php]")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	for _, name := range []string{"/pub/a.exe", "/pub/invoice.pdf.exe", "/pub/shell.PHP"} {
		if code, _ := c.cmd("STOR %s", name); code != 550 {
			t.Errorf("%s was %d, want 550", name, code)
		}
	}
	if code, _ := c.cmd("STOR /pub/report.csv"); code != 425 {
		t.Errorf("an allowed name was refused: %d", code)
	}
}

// The size bound acts by cutting the transfer, because a transfer
// cannot be un-sent, and the client is told the transfer was refused
// rather than completed.
func TestFTPMaxFileBytes(t *testing.T) {
	_, addr, tg := ftpBastion(t, "        max_file_bytes: 16")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	dataAddr := c.passive()
	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := c.cmd("STOR /pub/big.bin"); code != 150 {
		t.Fatalf("STOR was %d", code)
	}
	_, _ = dc.Write([]byte(strings.Repeat("x", 4096)))
	_ = dc.Close()
	code, _ := c.reply()
	if code != 426 {
		t.Fatalf("completion was %d, want 426", code)
	}
	if got := tg.lastStored(); len(got) > 4096 {
		t.Fatalf("the target received %d octets", len(got))
	}
}
