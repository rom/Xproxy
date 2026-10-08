package dns_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// alert_on_deny on a resolver, and what it must leave alone.
//
// Every refusal this listener records goes through one closure, and the gate is
// inside it -- so the setting reaches the block list, the threat lists, the
// tunnel detector and the admission policy together. What it must not reach is
// the rest: the query is still answered the way block_action says, the counters
// still rise, and the address still goes in front of the ban ladder.
//
// Over TCP, because the gate sits behind the verified check: a UDP source is a
// datagram's unproven claim about itself, and a refusal recorded against one is
// aggregated and attributed to nobody. A connection proves the address, so this
// is the path where there is a per-client record for the setting to silence.

const dnsAlertYAML = `
version: 1
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["%s"]
        block: [blocked.test]
%s
bans:
  action: reject
  triggers: [{name: dns, reasons: [dns_blocked], threshold: 1, window: 1m, duration: 1m}]
logging:
  directory: %s
  access: {enabled: false}
  security: {enabled: true, file: security.log}
upstreams:
  - {name: unused, endpoints: [{address: 127.0.0.1:1}]}
`

// dnsAlertResolver is a resolver listener whose security log goes to a file,
// which proxytest.Start cannot give: it builds the server with logging.Discard.
func dnsAlertResolver(t *testing.T, extra string) (*proxy.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(dnsAlertYAML, fakeUpstream(t), extra, dir)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	s, err := proxy.New(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		logs.Close()
	})
	return s, proxytest.Addr(t, s, "resolver"), dir
}

// tcpAsk puts one question over TCP, where the connection proves the client
// address. RFC 1035 s4.2.2: each message is preceded by its two-byte length.
func tcpAsk(t *testing.T, addr, name string) *wire.Message {
	t.Helper()
	q, err := wire.Query(0x4242, name, wire.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed, uint16(len(q))) //nolint:gosec // a query is far under 64 KiB
	copy(framed[2:], q)
	if _, err := c.Write(framed); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatalf("%s: reply length: %v", name, err)
	}
	buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("%s: reply: %v", name, err)
	}
	m, err := wire.ParseMessage(buf)
	if err != nil {
		t.Fatalf("%s: the reply does not parse: %v", name, err)
	}
	return m
}

// askForABlockedName asks over TCP and waits for the listener to have counted the
// refusal, which is the point after which its records have been written.
func askForABlockedName(t *testing.T, s *proxy.Server, addr string) *wire.Message {
	t.Helper()
	m := tcpAsk(t, addr, "blocked.test")
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().DNSBlocked == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the blocked name was never counted")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return m
}

func TestAResolverRefusalIsRecordedByDefault(t *testing.T) {
	s, addr, dir := dnsAlertResolver(t, "")
	askForABlockedName(t, s, addr)

	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join(dir, "security.log"))
		if err == nil && strings.Contains(string(b), `"action":"deny"`) {
			if !strings.Contains(string(b), "dns_blocked") {
				t.Errorf("the record does not name the reason:\n%s", b)
			}
			if !strings.Contains(string(b), `"client_ip":"127.0.0.1"`) {
				t.Errorf("the record does not name the client:\n%s", b)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no refusal was recorded: %v\n%s", err, b)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestAlertOnDenyOffKeepsTheResolversAnswerAndBan(t *testing.T) {
	s, addr, dir := dnsAlertResolver(t, "        alert_on_deny: false")
	m := askForABlockedName(t, s, addr)

	// The name is still refused, by the protocol's own word for it: with the
	// default block_action the answer is NXDOMAIN, and the setting has nothing
	// to say about what the client is told.
	if m.Header.Rcode() != wire.RcodeNXDomain {
		t.Errorf("rcode %d, want NXDOMAIN: the setting silences the record, not the refusal", m.Header.Rcode())
	}
	// The ban observation sits in front of the gate, so waiting for the ban is
	// waiting for the point the record would have been written at.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if bl := s.Bans(); bl != nil && bl.Banned(netip.MustParseAddr("127.0.0.1")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refusal never reached the ban ladder")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if n := s.Stats().DNSBlocked; n != 1 {
		t.Errorf("dns blocked %d, want 1", n)
	}
	b, err := os.ReadFile(filepath.Join(dir, "security.log"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"action":"deny"`) {
		t.Errorf("alert_on_deny: false still recorded the refusal:\n%s", b)
	}
}
