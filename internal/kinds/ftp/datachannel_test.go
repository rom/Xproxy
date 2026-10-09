package ftp_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
)

// The data connection, which is the half of FTP that carries the file:
// where the proxy opens it, and whether it is protected.

// freePort returns a port nothing is listening on, and the listener it
// came from, already closed. It is a guess, as it has to be: the
// kernel will not reserve a port for later.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port := splitHostPortForTest(t, ln.Addr().String())
	_ = ln.Close()
	return port
}

// A firewall in front of the proxy can only be narrow if the proxy
// keeps to the ports it was given, and only be written at all if the
// address it advertises is the one the estate routes to. Both are
// configuration the proxy has to honour exactly.
func TestTheDataConnectionKeepsToTheConfiguredAddressAndPorts(t *testing.T) {
	t.Run("inside the range", func(t *testing.T) {
		low := freePort(t)
		high := low + 7
		_, addr, tg := ftpBastion(t, fmt.Sprintf("        data_address: 127.0.0.1\n        data_ports: %d-%d", low, high))
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		data := c.passive()
		host, port := splitHostPortForTest(t, data)
		if host != "127.0.0.1" {
			t.Errorf("the proxy advertised %q, want the configured data_address", host)
		}
		if port < low || port > high {
			t.Errorf("the proxy advertised port %d, outside the configured %d-%d", port, low, high)
		}
		conn, err := net.DialTimeout("tcp", data, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if code, _ := c.cmd("RETR /pub/file.txt"); code != 150 {
			t.Fatal("RETR was refused on a port inside the range")
		}
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tg.content {
			t.Errorf("transferred %q", got)
		}
		if code, _ := c.reply(); code != 226 {
			t.Error("the transfer did not complete")
		}
	})

	t.Run("the range is full", func(t *testing.T) {
		// A range of one port, and something else is holding it. The
		// session is not ended over it: the transfer is refused and the
		// client may try again, which is what a client does when a
		// server is out of data ports.
		busy, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = busy.Close() }()
		_, only := splitHostPortForTest(t, busy.Addr().String())
		_, addr, _ := ftpBastion(t, fmt.Sprintf("        data_address: 127.0.0.1\n        data_ports: %d-%d", only, only))
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		if code, text := c.cmd("PASV"); code != 425 {
			t.Fatalf("PASV with no free data port was %d %q, want 425", code, text)
		}
		// The control connection is still there.
		if code, _ := c.cmd("PWD"); code != 257 {
			t.Errorf("the session ended over a full port range: PWD was %d", code)
		}
	})

	t.Run("an active transfer needs a port too", func(t *testing.T) {
		busy, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = busy.Close() }()
		_, only := splitHostPortForTest(t, busy.Addr().String())
		_, addr, tg := ftpBastion(t, fmt.Sprintf("        allow_active: true\n        data_address: 127.0.0.1\n        data_ports: %d-%d", only, only))
		c := dialFTP(t, addr)
		c.login("alice", "secret")
		mine := freePort(t)
		if code, text := c.cmd("PORT 127,0,0,1,%d,%d", mine>>8, mine&0xff); code != 425 {
			t.Fatalf("PORT with no free data port was %d %q, want 425", code, text)
		}
		// The target was never told to expect a connection the proxy
		// cannot accept.
		for _, seen := range tg.commands() {
			if strings.HasPrefix(seen, "PORT") {
				t.Errorf("the target was sent %q with no data port to offer", seen)
			}
		}
	})
}

// An active transfer by the extended spelling. EPRT carries the
// address as text rather than as six octets, so it is the spelling the
// proxy has to use when its own address cannot be written the old way
// -- and the one a modern client sends regardless.
func TestAnActiveTransferCanBeArrangedWithEPRT(t *testing.T) {
	_, addr, tg := ftpBastion(t, "        allow_active: true")
	c := dialFTP(t, addr)
	c.login("alice", "secret")

	// The client's own data listener, which the proxy will dial.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, port := splitHostPortForTest(t, ln.Addr().String())
	if code, text := c.cmd("EPRT |1|127.0.0.1|%d|", port); code != 200 {
		t.Fatalf("EPRT was %d %q", code, text)
	}
	var forwarded string
	for _, seen := range tg.commands() {
		if strings.HasPrefix(seen, "EPRT") {
			forwarded = seen
		}
	}
	if forwarded == "" {
		t.Fatal("the EPRT was never forwarded")
	}
	if strings.Contains(forwarded, fmt.Sprintf("|%d|", port)) {
		t.Fatalf("the client's own port was forwarded to the target: %s", forwarded)
	}

	type got struct {
		b   []byte
		err error
	}
	arrived := make(chan got, 1)
	go func() {
		dc, err := ln.Accept()
		if err != nil {
			arrived <- got{err: err}
			return
		}
		defer func() { _ = dc.Close() }()
		b, err := io.ReadAll(dc)
		arrived <- got{b: b, err: err}
	}()
	if code, text := c.cmd("RETR /pub/file.txt"); code != 150 {
		t.Fatalf("RETR was %d %q", code, text)
	}
	select {
	case g := <-arrived:
		if g.err != nil {
			t.Fatal(g.err)
		}
		if string(g.b) != tg.content {
			t.Errorf("the active transfer carried %q", g.b)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the proxy never dialled the address EPRT named")
	}
	if code, _ := c.reply(); code != 226 {
		t.Error("the transfer did not complete")
	}
}

// PROT P asks for the data connection to be protected too. The proxy
// is one end of both halves, so it protects both: TLS to the client and
// TLS to the server, rather than one opaque tunnel it cannot inspect.
// A proxy that answered 200 to PROT and then moved the file in clear
// would be telling the client a lie about the wire.
func TestAProtectedDataChannelIsTLSOnBothLegs(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "target.test")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	server := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	_, addr, tg := ftpTLSBastion(t,
		"        upstream_tls_mode: starttls\n        upstream_tls: {ca_file: "+cert+", server_name: target.test}",
		func(tg *targetFTP) {
			tg.tls = server
			tg.dataTLS = server
		})

	c := dialFTP(t, addr)
	c.upgrade()
	c.login("alice", "secret")
	if code, _ := c.cmd("PBSZ 0"); code != 200 {
		t.Fatal("PBSZ was refused")
	}
	if code, _ := c.cmd("PROT P"); code != 200 {
		t.Fatal("PROT P was refused")
	}
	data := c.passive()
	conn, err := net.DialTimeout("tcp", data, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if code, text := c.cmd("RETR /pub/file.txt"); code != 150 {
		t.Fatalf("RETR was %d %q", code, text)
	}
	// The proxy is the server of this handshake: a data connection in
	// clear would read as a protocol error rather than as a file.
	dc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "files.test"}) //nolint:gosec // test
	if err := dc.Handshake(); err != nil {
		t.Fatalf("the proxy did not offer TLS on the data connection: %v", err)
	}
	got, err := io.ReadAll(dc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != tg.content {
		t.Errorf("the protected transfer carried %q, want %q", got, tg.content)
	}
	if code, _ := c.reply(); code != 226 {
		t.Error("the protected transfer did not complete")
	}
}

// The same the other way: an active upload. The direction a transfer
// moves is decided by the command, not by which side opened the
// connection, and in active mode those two are opposite.
func TestAnActiveUploadStillGoesToTheServer(t *testing.T) {
	_, addr, tg := ftpBastion(t, "        allow_active: true")
	c := dialFTP(t, addr)
	c.login("alice", "secret")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, port := splitHostPortForTest(t, ln.Addr().String())
	if code, text := c.cmd("PORT 127,0,0,1,%d,%d", port>>8, port&0xff); code != 200 {
		t.Fatalf("PORT was %d %q", code, text)
	}

	const payload = "a file sent the active way"
	sent := make(chan error, 1)
	go func() {
		dc, err := ln.Accept()
		if err != nil {
			sent <- err
			return
		}
		_, err = io.WriteString(dc, payload)
		_ = dc.Close()
		sent <- err
	}()
	if code, text := c.cmd("STOR active.txt"); code != 150 {
		t.Fatalf("STOR was %d %q", code, text)
	}
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the proxy never dialled the address PORT named")
	}
	if code, _ := c.reply(); code != 226 {
		t.Error("the upload did not complete")
	}
	if got := tg.lastStored(); got != payload {
		t.Errorf("the server got %q, want %q", got, payload)
	}
}
