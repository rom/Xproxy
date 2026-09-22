package ftp_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/ftp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The parts of an FTP session that are not commands: getting the
// control connection encrypted, deciding whether to accept the
// connection at all, and what the target is told about who is on the
// other end.

// ftpTLSBastion starts a proxy with a certificate on the listener, and
// returns the target as well so a test can give it one too.
func ftpTLSBastion(t *testing.T, extra string, target func(*targetFTP)) (*proxy.Server, string, *targetFTP) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "files.test")
	tg := startTargetFTPWith(t, target)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:0"
      kind: ftp
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      ftp:
        upstream: servers
%s
logging: {access: {enabled: false}}
upstreams:
  - name: servers
    endpoints: [{address: %s}]
`, cert, key, extra, tg.addr())
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["files"], tg
}

// upgrade sends AUTH TLS and wraps the connection, the way a client
// does. The login starts again afterwards (RFC 4217 section 4).
func (c *ftpClient) upgrade() {
	c.t.Helper()
	if code, text := c.cmd("AUTH TLS"); code != 234 {
		c.t.Fatalf("AUTH TLS was %d %q", code, text)
	}
	tc := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true, ServerName: "files.test"}) //nolint:gosec // test
	if err := tc.Handshake(); err != nil {
		c.t.Fatalf("handshake: %v", err)
	}
	c.conn = tc
	c.br = bufio.NewReader(tc)
}

// TestFTPStartTLS: a client that asks for TLS gets it, the login starts
// again on the protected connection, and a transfer still works through
// it. Without this the password crosses the network in clear.
func TestFTPStartTLS(t *testing.T) {
	_, addr, tg := ftpTLSBastion(t, "        require_tls: false", nil)
	c := dialFTP(t, addr)
	c.upgrade()
	c.login("alice", "secret")
	if code, _ := c.cmd("PWD"); code != 257 {
		t.Errorf("PWD after the upgrade was %d", code)
	}
	dataAddr := c.passive()
	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	if code, _ := c.cmd("RETR /pub/file.txt"); code != 150 {
		t.Fatalf("RETR was %d", code)
	}
	got, err := io.ReadAll(dc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != tg.content {
		t.Errorf("transferred %q", got)
	}
	if code, _ := c.reply(); code != 226 {
		t.Error("the transfer did not complete")
	}
	// The target never saw AUTH: its leg is in clear unless
	// upstream_tls_mode says otherwise, and the proxy must not pretend
	// otherwise to the client either.
	for _, cmd := range tg.commands() {
		if strings.HasPrefix(cmd, "AUTH") {
			t.Errorf("the target was sent %q with upstream_tls_mode none", cmd)
		}
	}
}

// TestFTPRequireTLS: with require_tls, everything but the commands that
// get to TLS is refused until the connection is encrypted. A control
// connection in clear carries the password.
func TestFTPRequireTLS(t *testing.T) {
	_, addr, _ := ftpTLSBastion(t, "        require_tls: true", nil)
	c := dialFTP(t, addr)
	if code, _ := c.cmd("USER alice"); code != 534 {
		t.Errorf("USER before TLS was %d, want 534", code)
	}
	c.upgrade()
	c.login("alice", "secret")
	if code, _ := c.cmd("PWD"); code != 257 {
		t.Errorf("PWD after the upgrade was %d", code)
	}
}

// TestFTPPipeliningAcrossAUTHIsRefused: octets sent behind AUTH TLS
// would be read as if they had arrived inside the session the
// handshake is about to create. The session ends rather than guessing
// whose they were.
func TestFTPPipeliningAcrossAUTHIsRefused(t *testing.T) {
	_, addr, _ := ftpTLSBastion(t, "", nil)
	c := dialFTP(t, addr)
	c.raw("AUTH TLS\r\nUSER smuggled\r\n")
	if code, _ := c.reply(); code != 500 {
		t.Fatalf("pipelined AUTH was %d, want 500", code)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); err == nil {
		t.Error("the session survived data pipelined across AUTH")
	}
}

// TestFTPAUTHWithoutACertificate: a listener with no TLS cannot offer
// AUTH, and says so rather than failing the handshake later.
func TestFTPAUTHWithoutACertificate(t *testing.T) {
	_, addr, _ := ftpBastion(t, "")
	c := dialFTP(t, addr)
	if code, _ := c.cmd("AUTH TLS"); code != 534 {
		t.Errorf("AUTH on a listener without TLS was %d, want 534", code)
	}
	// A mechanism that is not TLS is refused separately: the proxy
	// mediates TLS and nothing else.
	_, addr2, _ := ftpTLSBastion(t, "", nil)
	c2 := dialFTP(t, addr2)
	if code, _ := c2.cmd("AUTH GSSAPI"); code != 504 {
		t.Errorf("AUTH GSSAPI was %d, want 504", code)
	}
}

// TestFTPUpstreamTLS: the target's leg is upgraded first, so a target
// that cannot do TLS is found out before the client is told its
// connection is protected.
func TestFTPUpstreamTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "target.test")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the target speaks TLS", func(t *testing.T) {
		_, addr, tg := ftpTLSBastion(t, "        upstream_tls_mode: starttls\n        upstream_tls: {ca_file: "+cert+", server_name: target.test}",
			func(tg *targetFTP) {
				tg.tls = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
			})
		c := dialFTP(t, addr)
		c.upgrade()
		c.login("alice", "secret")
		if code, _ := c.cmd("PWD"); code != 257 {
			t.Errorf("PWD was %d", code)
		}
		var sawAUTH bool
		for _, cmd := range tg.commands() {
			if strings.HasPrefix(cmd, "AUTH") {
				sawAUTH = true
			}
		}
		if !sawAUTH {
			t.Error("the target's leg was never upgraded")
		}
	})

	t.Run("the target will not", func(t *testing.T) {
		// tg.tls stays nil, so the target answers AUTH with 534.
		_, addr, _ := ftpTLSBastion(t, "        upstream_tls_mode: starttls\n        upstream_tls: {ca_file: "+cert+", server_name: target.test}", nil)
		c := dialFTP(t, addr)
		if code, _ := c.cmd("AUTH TLS"); code != 431 {
			t.Errorf("AUTH TLS against a target without TLS was %d, want 431", code)
		}
	})
}

// TestFTPClientAdmission: who may open a control connection at all.
// These run before anything is read from the client, so a refused
// address never reaches the protocol.
func TestFTPClientAdmission(t *testing.T) {
	t.Run("outside allow_clients", func(t *testing.T) {
		_, addr, tg := ftpBastion(t, "        allow_clients: [192.0.2.0/24]")
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Error("a client outside allow_clients was greeted")
		}
		if len(tg.commands()) != 0 {
			t.Error("a refused client reached the target")
		}
	})

	t.Run("over max_connections", func(t *testing.T) {
		_, addr, _ := ftpBastion(t, "        max_connections: 1")
		first := dialFTP(t, addr)
		defer first.conn.Close()
		second, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 128)
		n, err := second.Read(buf)
		if err != nil {
			t.Fatalf("the second connection was dropped without a reply: %v", err)
		}
		if !strings.HasPrefix(string(buf[:n]), "421") {
			t.Errorf("the second connection got %q, want 421", buf[:n])
		}
	})
}

// TestFTPProxyProtocolToTheTarget: the target is told the client's
// address rather than the proxy's, which is what makes its own logs
// and its own policy mean anything.
func TestFTPProxyProtocolToTheTarget(t *testing.T) {
	tg := startTargetFTPWith(t, func(tg *targetFTP) { tg.expectProxy = true })
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:0"
      kind: ftp
      ftp: {upstream: servers, proxy_protocol: true}
logging: {access: {enabled: false}}
upstreams:
  - name: servers
    endpoints: [{address: %s}]
`, tg.addr())
	s := proxytest.Start(t, yaml)
	c := dialFTP(t, s.Addrs()["files"])
	c.login("alice", "secret")
	if code, _ := c.cmd("PWD"); code != 257 {
		t.Fatalf("PWD was %d", code)
	}
	hdr := tg.lastProxyHeader()
	if len(hdr) < 16 || hdr[:12] != "\r\n\r\n\x00\r\nQUIT\n" {
		t.Fatalf("the target did not receive a PROXY v2 header: %q", hdr)
	}
	// The client port the header carries is the client's own, not the
	// proxy's outbound one.
	local := c.conn.LocalAddr().(*net.TCPAddr)
	want := []byte{byte(local.Port >> 8), byte(local.Port & 0xff)}
	if !strings.Contains(hdr, string(want)) {
		t.Errorf("the header does not carry the client port %d: %q", local.Port, hdr)
	}
}

// TestFTPTargetUnavailable: a target that is not there is 421 to the
// client, not a hung connection.
func TestFTPTargetUnavailable(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addrOfDead := dead.Addr().String()
	_ = dead.Close()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:0"
      kind: ftp
      ftp: {upstream: servers}
logging: {access: {enabled: false}}
upstreams:
  - name: servers
    endpoints: [{address: %s}]
`, addrOfDead)
	s := proxytest.Start(t, yaml)
	c, err := net.DialTimeout("tcp", s.Addrs()["files"], 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no reply from a proxy whose target is down: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "421") {
		t.Errorf("got %q, want 421", buf[:n])
	}
}

// TestFTPPathTemplate: an allow list written once with {user} in it is
// a per-user home directory, which is the difference between a policy
// an operator can write and one they have to generate.
func TestFTPPathTemplate(t *testing.T) {
	_, addr, _ := ftpBastion(t, "        allow_paths: [\"/home/{user}/**\"]")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	if code, _ := c.cmd("SIZE /home/alice/report.csv"); code != 213 {
		t.Errorf("a path in the user's own tree was %d", code)
	}
	if code, _ := c.cmd("SIZE /home/bob/report.csv"); code != 550 {
		t.Errorf("another user's tree was %d, want 550", code)
	}

	// A login that cannot be put in a path ends the session rather than
	// being substituted into one: "../../etc" as a user name would
	// otherwise rewrite the policy it is checked against.
	c2 := dialFTP(t, addr)
	if code, _ := c2.cmd("USER ../../etc"); code != 331 {
		t.Fatalf("USER was %d", code)
	}
	if code, _ := c2.cmd("PASS x"); code != 421 {
		t.Errorf("a login that cannot be templated was answered %d, want 421", code)
	}
	_ = c2.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c2.conn.Read(make([]byte, 1)); err == nil {
		t.Error("the session survived a login that cannot be templated")
	}
}

// TestFTPYARAOnUpload: the rules see what is written through the proxy,
// and a match cuts the transfer rather than letting the file land and
// reporting it afterwards.
func TestFTPYARAOnUpload(t *testing.T) {
	rules := testutil.YARARules(t)
	_, addr, tg := ftpBastion(t, "        yara: {rules_file: "+rules+", directions: [client]}")
	c := dialFTP(t, addr)
	c.login("alice", "secret")
	dataAddr := c.passive()
	dc, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := c.cmd("STOR /pub/notes.txt"); code != 150 {
		t.Fatalf("STOR was %d", code)
	}
	_, _ = dc.Write([]byte("nothing to see here TOP-SECRET-MARKER and more\r\n"))
	_ = dc.Close()
	if code, _ := c.reply(); code != 426 {
		t.Errorf("the completion was %d, want 426", code)
	}
	if got := tg.lastStored(); strings.Contains(got, "TOP-SECRET-MARKER") {
		t.Errorf("the marked content reached the target: %q", got)
	}

	// A clean upload through the same policy still arrives: a scanner
	// that stops everything is not a scanner.
	c2 := dialFTP(t, addr)
	c2.login("alice", "secret")
	dataAddr2 := c2.passive()
	dc2, err := net.DialTimeout("tcp", dataAddr2, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := c2.cmd("STOR /pub/clean.txt"); code != 150 {
		t.Fatalf("STOR was %d", code)
	}
	_, _ = dc2.Write([]byte("an ordinary file\r\n"))
	_ = dc2.Close()
	if code, _ := c2.reply(); code != 226 {
		t.Errorf("a clean upload was %d, want 226", code)
	}
	if got := tg.lastStored(); got != "an ordinary file\r\n" {
		t.Errorf("the target stored %q", got)
	}
}
