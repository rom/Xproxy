package dns_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dns"
	_ "github.com/rom/xproxy/internal/kinds/dns"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// What a resolver answers about itself: the encrypted endpoints a
// client can move to (RFC 9462), the SVCB and HTTPS records it owns
// (RFC 9460), and DNS over QUIC (RFC 9250) on the same port. None of
// these leaves the listener, so none of them needs an upstream — which
// is also why a mistake in them is invisible until somebody asks.

// doq asks one query over a fresh QUIC connection, as a client does.
func doq(t *testing.T, addr, name string, qtype uint16) []byte {
	t.Helper()
	q, err := wire.Query(9, name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{wire.ALPNDoQ},
		ServerName:         "wire.test",
	}, &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("doq dial: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(out, uint16(len(q))) //nolint:gosec // a query is small
	copy(out[2:], q)
	if _, err := st.Write(out); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	var length [2]byte
	if _, err := io.ReadFull(st, length[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(st, resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// udpQuery asks one query over UDP, which is what a client with no
// encrypted transport yet has.
func udpQuery(t *testing.T, addr, name string, qtype uint16) []byte {
	t.Helper()
	q, err := wire.Query(7, name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, wire.MaxMessage)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// TestDiscoveryRecordsAndDoQ: a plaintext listener advertises the
// encrypted endpoints so a client upgrades itself and answers the
// records the resolver owns, and an encrypted listener answers the same
// records over QUIC. One policy, two transports.
func TestDiscoveryRecordsAndDoQ(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "wire.test")
	// A trust anchor in a file, with the comments and blank lines an
	// operator's copy of the root anchors has in it.
	anchors := filepath.Join(dir, "anchors.txt")
	body := "; the root, as published\n\n. 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n# and nothing else\n"
	if err := os.WriteFile(anchors, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// The records both listeners own. A resolver that answers them
	// differently depending on how it was reached is worse than one
	// that answers neither.
	const records = `
        records:
          - name: www.wire.test
            type: https
            priority: 1
            target: "."
            ttl: 120
            params: {alpn: "h3,h2", port: "443", ipv4hint: "10.0.1.10"}
          - {name: wire.test, type: https, priority: 0, target: www.wire.test}
          - {name: _dns.wire.test, type: svcb, priority: 1, target: dns.wire.test, params: {alpn: dot}}`
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: plain
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["127.0.0.1:1"]
        timeout: 1s
        block: [elsewhere.test]
        block_action: sinkhole
        sinkhole_ipv4: 10.9.9.9
        dnssec: {enabled: true, trust_anchors_file: %s}
        discovery:
          - {transport: doq, name: wire.test, port: 8853, ipv4: [127.0.0.1], ttl: 60}
          - {transport: dot, name: wire.test, port: 8853, ipv4: [127.0.0.1]}
          - {transport: doh, name: wire.test, port: 8443, doh_path: "/dns-query{?dns}"}%s
    - name: enc
      address: "127.0.0.1:0"
      kind: dns
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      dns:
        upstreams: ["127.0.0.1:1"]
        timeout: 1s
        doq: true%s
logging: {access: {enabled: false}}
`, anchors, records, cert, key, records)
	s := proxytest.Start(t, yaml)

	// The plaintext listener answers the discovery name itself. This is
	// the whole of DDR: a client that gets nothing here has no way to
	// learn it could be encrypted, and stays in plaintext forever.
	plain := s.Addrs()["plain"]
	resp := udpQuery(t, plain, wire.DiscoveryName, wire.TypeSVCB)
	h, _ := wire.ParseHeader(resp)
	if h.Rcode() != wire.RcodeNoError || h.ANCount != 3 {
		t.Fatalf("discovery: rcode %d, %d answers", h.Rcode(), h.ANCount)
	}
	for _, alpn := range []string{"doq", "dot", "h2"} {
		if !bytes.Contains(resp, []byte(alpn)) {
			t.Errorf("the discovery answer does not advertise %s: %x", alpn, resp)
		}
	}

	// The records, over UDP on one listener and over QUIC on the other.
	// The QUIC endpoint shares the encrypted listener's address: only
	// the transport differs.
	enc := s.Addrs()["enc"]
	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"www.wire.test", wire.TypeHTTPS},
		{"wire.test", wire.TypeHTTPS},
		{"_dns.wire.test", wire.TypeSVCB},
	} {
		over := udpQuery(t, plain, tc.name, tc.qtype)
		h, _ := wire.ParseHeader(over)
		if h.Rcode() != wire.RcodeNoError || h.ANCount != 1 {
			t.Errorf("%s over udp: rcode %d, %d answers", tc.name, h.Rcode(), h.ANCount)
		}
		quicResp := doq(t, enc, tc.name, tc.qtype)
		qh, _ := wire.ParseHeader(quicResp)
		if qh.Rcode() != h.Rcode() || qh.ANCount != h.ANCount {
			t.Errorf("%s: udp said %d/%d, quic said %d/%d", tc.name, h.Rcode(), h.ANCount, qh.Rcode(), qh.ANCount)
		}
	}
	// The address hint is in the record, so a client need not resolve
	// the name it was just handed.
	if !bytes.Contains(udpQuery(t, plain, "www.wire.test", wire.TypeHTTPS), []byte{10, 0, 1, 10}) {
		t.Error("the ipv4hint is missing from the HTTPS record")
	}
	// A name the resolver does not own goes through the rest of the
	// policy: the local table answers what it owns and nothing else.
	if got := udpQuery(t, plain, "elsewhere.test", wire.TypeA); !bytes.Contains(got, []byte{10, 9, 9, 9}) {
		t.Errorf("a name the resolver does not own missed the block list: %x", got)
	}
	// The status view names what each listener serves, which is how an
	// operator checks that DDR and DoQ are actually on.
	var sawDoQ, sawNames bool
	for _, st := range s.DNS() {
		if st.Listener == "enc" && st.DoQ {
			sawDoQ = true
		}
		if st.Listener == "plain" && len(st.LocalNames) > 0 {
			sawNames = true
		}
	}
	if !sawDoQ {
		t.Error("the status view does not report DoQ")
	}
	if !sawNames {
		t.Error("the status view does not name the local records")
	}
}

// refused loads a configuration and starts it, and returns the error
// that stopped it. A record that cannot be encoded has to be refused
// somewhere between the parser and the bound socket; which of the two
// is not the point, and a test that pins it would break on a change
// that only made the message better.
func refused(yaml string) error {
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		return err
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.Shutdown(ctx)
	return nil
}

// TestBadRecordsAreRefusedAtLoad: a record the resolver could not
// encode must fail the configuration, not fail every query for it.
func TestBadRecordsAreRefusedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		name, params, want string
	}{
		{"an unknown parameter", `{nosuchparam: "1"}`, "nosuchparam"},
		{"a port that is not one", `{port: "not-a-port"}`, "port"},
		{"an address hint that is not an address", `{ipv4hint: "::1"}`, "ipv4hint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `
version: 1
server:
  listeners:
    - name: d
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["127.0.0.1:1"]
        records:
          - {name: x.test, type: https, priority: 1, target: ".", params: ` + tc.params + `}
logging: {access: {enabled: false}}
`
			err := refused(yaml)
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: %v does not name the parameter", tc.name, err)
			}
		})
	}
}
