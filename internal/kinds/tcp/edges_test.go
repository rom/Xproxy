package tcp_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	_ "github.com/rom/xproxy/internal/kinds/tcp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The edges of a layer 4 listener: the bounds it applies before it has read
// anything, what it does with a client whose first bytes never resolve into a
// server name, and what it does when there is no endpoint to reach.
//
// A stream relay has no protocol of its own to answer with, so every refusal
// here is a connection that ends. What is asserted is therefore the counter
// and the record beside it: on this kind they are the only account an
// operator gets of why somebody's connection did not work.

// echo is a TCP echo server, which is what a layer 4 listener is usually
// pointed at in a test: it proves bytes crossed in both directions.
func echo(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// l4 is a listener whose tcp block and top-level sections the test writes.
func l4(t *testing.T, section, top string, endpoints string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
%s
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [%s]
%s
`, section, endpoints, top))
	return s, proxytest.Addr(t, s, "l4")
}

// A connection over the bound is closed at accept, before a byte of it is
// read: the bound is on connections this listener holds, and a connection it
// has started reading is already one of them.
func TestAConnectionOverTheBoundIsClosedAtAccept(t *testing.T) {
	s, addr := l4(t, "        max_connections: 1\n        idle_timeout: 30s\n        default: u", "", fmt.Sprintf("{address: %q}", echo(t)))

	held, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	// Established end to end, so the slot is certainly taken.
	if _, err := io.WriteString(held, "first\n"); err != nil {
		t.Fatal(err)
	}
	line := make([]byte, 6)
	_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(held, line); err != nil || string(line) != "first\n" {
		t.Fatalf("the held connection did not reach the endpoint: %q %v", line, err)
	}

	over, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = over.Close() }()
	_ = over.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := over.Read(make([]byte, 1)); err == nil {
		t.Errorf("the connection over the bound read %d bytes instead of being closed", n)
	}
	waitFor(t, 5*time.Second, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["tcp"]["max_connections"] > 0
	})
	if sn := s.Stats(); sn.TCPRejected == 0 {
		t.Error("the refused connection was not counted as rejected")
	}
	// The held connection is still serving: the bound turns the new
	// connection away rather than making room for it.
	if _, err := io.WriteString(held, "again\n"); err != nil {
		t.Errorf("the held connection was disturbed: %v", err)
	}
}

// A client whose first bytes look like a TLS record and never finish one is
// relayed on the default route with no name. The alternative is holding the
// connection until the hard bound while the buffer grows, which is a client
// holding memory by sending a length and then nothing of consequence.
func TestAHelloThatNeverEndsIsRelayedWithoutAName(t *testing.T) {
	_, addr := l4(t, "        idle_timeout: 30s\n        default: u", "", fmt.Sprintf("{address: %q}", echo(t)))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// A handshake message that says it is 60000 octets long, carried a
	// record at a time and never finished. Each record is well formed, so
	// the parser keeps asking for more -- and the bound on what it will
	// hold waiting is what ends it.
	record := func(body []byte) []byte {
		head := []byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}
		return append(head, body...)
	}
	first := make([]byte, 1024)
	first[0] = 0x01 // ClientHello
	first[1], first[2], first[3] = 0x00, 0xea, 0x60
	sent := record(first)
	for i := 0; i < 16; i++ {
		filler := make([]byte, 1024)
		for j := range filler {
			filler[j] = byte('a' + (i+j)%26)
		}
		sent = append(sent, record(filler)...)
	}
	if _, err := c.Write(sent); err != nil {
		t.Fatal(err)
	}
	// Everything the proxy read while it was waiting is relayed, in order,
	// rather than dropped on the floor when it gave up on the name.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	back := make([]byte, len(sent))
	if _, err := io.ReadFull(c, back); err != nil {
		t.Fatalf("the buffered bytes did not reach the endpoint: %v", err)
	}
	if string(back) != string(sent) {
		t.Error("the bytes that came back are not the ones that went in")
	}
}

// Every endpoint unreachable is this proxy's error rather than the client's
// refusal: the client did nothing wrong, and an operator looking for a dead
// backend should find it under errors and not in a deny log.
func TestAConnectionWithNoReachableEndpointIsCountedAsAnError(t *testing.T) {
	s, addr := l4(t, "        default: u", "", `{address: "127.0.0.1:1"}`)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := io.WriteString(c, "anybody there\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil {
		t.Errorf("the connection read %d bytes with no endpoint to read from", n)
	}
	waitFor(t, 5*time.Second, "the unreachable endpoint to be counted", func() bool {
		return s.Stats().TCPErrors > 0
	})
	if n := s.Stats().Refusals["tcp"]["no_route"]; n != 0 {
		t.Errorf("a dead endpoint was recorded as %d refusals of the client", n)
	}
}

// A refusal reaches the ban ladder whether or not it is worth an alert.
// alert_on_deny is about the security event alone: a listener on a port
// facing the internet refuses constantly, and an operator who turns that
// record down has not asked the proxy to stop responding to it.
func TestARefusalReachesTheBanLadderWithTheAlertTurnedOff(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "listed.txt")
	if err := os.WriteFile(listPath, []byte("127.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, addr := l4(t, "        default: u\n        alert_on_deny: false", fmt.Sprintf(`threat_intel:
  lists:
    - {name: listed-clients, file: %s, action: block}
bans:
  action: reject
  triggers: [{name: l4, reasons: [tcp_denied], threshold: 1, window: 1m, duration: 1h}]`, listPath),
		fmt.Sprintf("{address: %q}", echo(t)))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil {
		t.Errorf("a listed client read %d bytes", n)
	}
	waitFor(t, 5*time.Second, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["tcp"]["threat_intel"] > 0
	})
	waitFor(t, 5*time.Second, "the refusal to reach the ban ladder", func() bool {
		return s.Stats().BansActive >= 1
	})
}

// A server name with no route is the refusal a listener facing the internet
// makes most of, so it is the one the ban ladder is most often configured
// for: nothing legitimate asks this listener for a name it does not carry.
func TestAnUnroutableNameReachesTheBanLadder(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	s, addr := l4(t, "        routes:\n          - {sni: [known.test], upstream: u}", `bans:
  action: reject
  triggers: [{name: l4, reasons: [tcp_no_route], threshold: 1, window: 1m, duration: 1h}]`,
		fmt.Sprintf("{address: %q}", echo(t)))

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	tc := tls.Client(conn, &tls.Config{ServerName: "stranger.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Error("a name with no route completed a handshake")
	}
	waitFor(t, 5*time.Second, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["tcp"]["no_route"] > 0
	})
	waitFor(t, 5*time.Second, "the refusal to reach the ban ladder", func() bool {
		return s.Stats().BansActive >= 1
	})
}

// The QUIC side of the same listener, where a flow is the unit rather than a
// connection. The bound is the same number: a datagram from a new client
// address is as expensive to serve as an accepted connection, and anyone can
// send one from an address they do not have.
func TestQUICFlowsOverTheBoundAreRefused(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "q.test")
	origin := quicEcho(t, cert, key)
	s, addr := l4(t, `        quic: true
        quic_idle_timeout: 10s
        max_connections: 1
        routes:
          - {sni: [q.test], upstream: u}`, "", fmt.Sprintf("{address: %q}", origin))

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	dial := func() (*quic.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return quic.DialAddr(ctx, addr, &tls.Config{ServerName: "q.test", RootCAs: pool,
			NextProtos: []string{"echo"}, MinVersion: tls.VersionTLS13},
			&quic.Config{HandshakeIdleTimeout: 2 * time.Second})
	}
	held, err := dial()
	if err != nil {
		t.Fatalf("the first flow: %v", err)
	}
	defer func() { _ = held.CloseWithError(0, "") }()
	waitFor(t, 5*time.Second, "the first flow to be routed", func() bool {
		return s.Stats().QUICFlowsOpen == 1
	})
	if _, err := dial(); err == nil {
		t.Error("a second flow was relayed over a bound of one")
	}
	waitFor(t, 5*time.Second, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["tcp"]["quic_max_flows"] > 0
	})
}

// A QUIC flow whose endpoint cannot even be resolved never reaches a pump:
// the flow is dropped as unreachable rather than held open waiting for an
// address that does not exist.
func TestAQUICFlowWithNoReachableEndpointIsDropped(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	s, addr := l4(t, `        quic: true
        quic_idle_timeout: 2s
        routes:
          - {sni: [q.test], upstream: u}`, "", `{address: "nowhere.invalid:443"}`)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: "q.test", RootCAs: pool,
		NextProtos: []string{"echo"}, MinVersion: tls.VersionTLS13},
		&quic.Config{HandshakeIdleTimeout: 2 * time.Second}); err == nil {
		t.Error("a flow was relayed to an endpoint that does not resolve")
	}
	waitFor(t, 5*time.Second, "the unreachable endpoint to be counted", func() bool {
		return s.Stats().TCPErrors > 0
	})
	if n := s.Stats().QUICFlowsOpen; n != 0 {
		t.Errorf("%d flows are open with no endpoint behind them", n)
	}
}

// A flow still open when the listener shuts down is ended rather than left
// with an upstream socket nothing reads. The shutdown has to return, too: a
// reload that hangs on a live flow is a proxy that stops serving everything
// else while one client holds it.
func TestAQUICFlowStillOpenAtShutdownIsEnded(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "q.test")
	origin := quicEcho(t, cert, key)
	s, addr := l4(t, `        quic: true
        quic_idle_timeout: 30s
        routes:
          - {sni: [q.test], upstream: u}`, "", fmt.Sprintf("{address: %q}", origin))

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: "q.test", RootCAs: pool,
		NextProtos: []string{"echo"}, MinVersion: tls.VersionTLS13},
		&quic.Config{HandshakeIdleTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("dial through the relay: %v", err)
	}
	st, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(st, "still here")
	_ = st.Close()
	if b, err := io.ReadAll(st); err != nil || string(b) != "echo:still here" {
		t.Fatalf("the flow did not reach the origin: %q %v", b, err)
	}
	waitFor(t, 5*time.Second, "the flow to be counted open", func() bool {
		return s.Stats().QUICFlowsOpen == 1
	})

	stopped := make(chan error, 1)
	go func() {
		sctx, scancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer scancel()
		stopped <- s.Shutdown(sctx)
	}()
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("shutdown with a live flow: %v", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("shutdown did not return while a flow was open")
	}
	if n := s.Stats().QUICFlowsOpen; n != 0 {
		t.Errorf("%d flows survived the shutdown", n)
	}
	// And the client's own connection is over: nothing is relayed by a
	// listener that has gone away.
	sctx, scancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer scancel()
	if _, err := conn.OpenStreamSync(sctx); err == nil {
		if _, err := io.WriteString(st, "anybody"); err == nil {
			t.Error("the flow was still carrying traffic after the shutdown")
		}
	}
	_ = conn.CloseWithError(0, "")
}

// The settings a layer 4 listener cannot be started with. The destinations
// list is parsed once, at load, because a prefix nobody can parse would
// otherwise be a connection relayed to an endpoint the policy never meant to
// allow -- and that is found on the first client rather than at start.
func TestWhatTheListenerRefusesToStartWith(t *testing.T) {
	for _, c := range []struct{ name, section string }{
		{"a destination that is not a prefix", "        original_destination: true\n        allow_destinations: [\"10.0.0.1\"]"},
		{"a yara rule file that is not there", "        default: u\n        yara: {rules: [/nonexistent/none.yar]}"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := proxytest.StartError(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
%s
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
`, c.section))
			if err == nil {
				t.Fatalf("%s was accepted", c.name)
			}
			if strings.Contains(err.Error(), "panic") {
				t.Errorf("refused with %v", err)
			}
		})
	}
}

// The QUIC side under a ban, and what it does with a datagram that is not an
// Initial it can read.
//
// A banned client is turned away before the Initial is parsed, which is the
// point: reading one means decrypting it, and the whole reason the ban exists
// is that this address has already been given the benefit of the doubt.
func TestAQUICDatagramFromABannedClientIsNotRead(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "q.test")
	origin := quicEcho(t, cert, key)
	s, addr := l4(t, `        quic: true
        quic_idle_timeout: 10s
        routes:
          - {sni: [q.test], upstream: u}`, `bans:
  action: reject
  triggers: [{name: l4, reasons: [tcp_no_route], threshold: 1, window: 1m, duration: 1h}]`,
		fmt.Sprintf("{address: %q}", origin))

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	dial := func(sni string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: sni, RootCAs: pool,
			NextProtos: []string{"echo"}, MinVersion: tls.VersionTLS13},
			&quic.Config{HandshakeIdleTimeout: 2 * time.Second})
		return err
	}
	// A name with no route is the refusal that trips the ladder.
	if err := dial("stranger.test"); err == nil {
		t.Fatal("a name with no route was relayed")
	}
	waitFor(t, 5*time.Second, "the refusal to reach the ban ladder", func() bool {
		return s.Stats().BansActive >= 1
	})
	// And now the name that does have a route is turned away too: the ban
	// is on the address, not on what it asked for.
	if err := dial("q.test"); err == nil {
		t.Error("a banned client was relayed")
	}
	waitFor(t, 5*time.Second, "the ban to be counted", func() bool {
		return s.Stats().Refusals["tcp"]["banned"] > 0
	})
}

// A datagram that is not a QUIC Initial this proxy can read is dropped
// silently: a short header from a flow it never saw is what a client
// migrating or a server restarting produces, and answering it would make the
// listener an amplifier for anybody who can spell a UDP packet.
func TestADatagramThatIsNotAnInitialIsDropped(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "q.test")
	origin := quicEcho(t, cert, key)
	s, addr := l4(t, `        quic: true
        quic_idle_timeout: 2s
        routes:
          - {sni: [q.test], upstream: u}`, "", fmt.Sprintf("{address: %q}", origin))

	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("this is not a quic initial")); err != nil {
		t.Fatal(err)
	}
	// Nothing comes back, and nothing is counted as a flow: there is no
	// flow, and no answer either.
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := c.Read(make([]byte, 64)); err == nil {
		t.Errorf("the listener answered %d bytes to a datagram it could not read", n)
	}
	if sn := s.Stats(); sn.QUICFlows != 0 || sn.QUICFlowsOpen != 0 {
		t.Errorf("a flow was opened for it: %d total, %d open", sn.QUICFlows, sn.QUICFlowsOpen)
	}
}

// halfForwarder stands between a QUIC client and the listener and passes on
// only the client's first datagram, so the listener is left holding a
// ClientHello that will never be completed. Anyone can produce that from a
// spoofed address, which is why the listener bounds such flows apart from the
// connection limit and sweeps them.
type halfForwarder struct {
	addr string
	seen atomic.Int64
}

func startHalfForwarder(t *testing.T, to string) *halfForwarder {
	t.Helper()
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	onward, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = onward.Close() })
	dst, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		t.Fatal(err)
	}
	f := &halfForwarder{addr: client.LocalAddr().String()}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := client.ReadFrom(buf)
			if err != nil {
				return
			}
			if f.seen.Add(1) == 1 {
				_, _ = onward.WriteTo(buf[:n], dst)
			}
		}
	}()
	return f
}

// dialBigHello dials with a ClientHello too large for one datagram, so that
// passing on the first datagram alone leaves the hello unfinished. It is
// expected to fail: nothing answers it.
func dialBigHello(t *testing.T, addr string, pool *x509.CertPool) {
	t.Helper()
	alpn := make([]string, 0, 64)
	for i := range 64 {
		alpn = append(alpn, fmt.Sprintf("padding-%02d-%s", i, strings.Repeat("x", 48)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: "q.test", RootCAs: pool,
		NextProtos: append(alpn, "echo"), MinVersion: tls.VersionTLS13},
		&quic.Config{HandshakeIdleTimeout: time.Second}); err == nil {
		t.Fatal("a handshake completed through a forwarder that dropped most of it")
	}
}

// A flow whose ClientHello never arrives in full holds a slot in the flow
// table, and the sweeper is what gives it back. Without that, anybody able
// to send one datagram from each of a thousand addresses closes the listener
// to everyone else for as long as they care to keep it up.
func TestAFlowWhoseHandshakeNeverFinishesStopsHoldingItsSlot(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "q.test")
	origin := quicEcho(t, cert, key)
	s, addr := l4(t, `        quic: true
        quic_idle_timeout: 30s
        max_connections: 1
        routes:
          - {sni: [q.test], upstream: u}`, "", fmt.Sprintf("{address: %q}", origin))

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	fw := startHalfForwarder(t, addr)
	dialBigHello(t, fw.addr, pool)
	if n := fw.seen.Load(); n < 2 {
		t.Fatalf("the client sent %d datagrams, so holding one back left nothing unfinished", n)
	}

	// The unfinished flow holds the only slot this listener has.
	direct := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, addr, &tls.Config{ServerName: "q.test", RootCAs: pool,
			NextProtos: []string{"echo"}, MinVersion: tls.VersionTLS13},
			&quic.Config{HandshakeIdleTimeout: 2 * time.Second})
		if err == nil {
			t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
		}
		return err
	}
	if err := direct(); err == nil {
		t.Error("a second flow was relayed while the unfinished one held the slot")
	}
	waitFor(t, 5*time.Second, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["tcp"]["quic_max_flows"] > 0
	})

	// And once the sweeper has given the slot back, an ordinary client gets
	// it. The sweep runs on its own timer, so this is the wait that proves
	// it ran rather than a reading of an internal counter.
	waitFor(t, 20*time.Second, "the unfinished flow to be swept", func() bool {
		return direct() == nil
	})
}

// The same unfinished flow when the listener goes away rather than when the
// sweeper reaches it: it is ended, so nothing is left in the table behind a
// listener that has shut down.
func TestAnUnfinishedHandshakeAtShutdownIsEnded(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "q.test")
	origin := quicEcho(t, cert, key)
	s, addr := l4(t, `        quic: true
        quic_idle_timeout: 30s
        routes:
          - {sni: [q.test], upstream: u}`, "", fmt.Sprintf("{address: %q}", origin))

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	fw := startHalfForwarder(t, addr)
	dialBigHello(t, fw.addr, pool)
	if n := fw.seen.Load(); n < 2 {
		t.Fatalf("the client sent %d datagrams, so holding one back left nothing unfinished", n)
	}

	stopped := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		stopped <- s.Shutdown(ctx)
	}()
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("shutdown with an unfinished flow: %v", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("shutdown did not return while a flow was still assembling")
	}
}
