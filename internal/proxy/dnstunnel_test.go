package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/dns"
)

// nxUpstream answers NXDOMAIN to everything, which is what the name
// server behind a tunnel domain does for the probing and the encoding
// that produce names nothing resolves.
func nxUpstream(t *testing.T) string {
	t.Helper()
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			h, herr := dns.ParseHeader(buf[:n])
			_, qEnd, qerr := dns.ParseQuestion(buf[:n])
			if herr != nil || qerr != nil {
				continue
			}
			_, _ = up.WriteTo(dns.Reply(buf[:n], qEnd, h, dns.RcodeNXDomain), addr)
		}
	}()
	return up.LocalAddr().String()
}

// askDNS sends one query over UDP and returns the response code.
func askDNS(t *testing.T, addr, name string, qtype uint16, id uint16) int {
	t.Helper()
	q := buildQuery(name, qtype, id)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer for %s: %v", name, err)
	}
	h, err := dns.ParseHeader(buf[:n])
	if err != nil {
		t.Fatalf("bad answer: %v", err)
	}
	return h.Rcode()
}

// buildQuery writes a minimal query message.
func buildQuery(name string, qtype, id uint16) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:2], id)
	b[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(b[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	return b
}

func tunnelListener(t *testing.T, action string) (*Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["%s"]
        cache: {negative_ttl: 0}
        tunnel_detection:
          min_queries: 20
          min_signals: 2
          action: %s
          cooldown: 1h
          allow_domains: [reputation.test]
logging:
  access: {enabled: false}
bans:
  action: reject
  triggers: [{name: t, reasons: [dns_tunnel], threshold: 1000, window: 1m, duration: 1h}]
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - {name: r, upstream: app}
`, nxUpstream(t), action)
	s, _ := startServer(t, yaml)
	return s, s.Addrs()["resolver"]
}

// sendTunnel sends n tunnel-shaped queries under a domain and returns
// how many were answered NXDOMAIN by something other than the upstream
// -- which, with an upstream that says NXDOMAIN to everything, is what
// the rcodes cannot tell apart, so the counters are what the caller
// checks.
func sendTunnel(t *testing.T, addr, domain string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("mfzwizltoq2gk3tfor4hi7dbnzsw4y3pnu%04x.%s", i, domain)
		askDNS(t, addr, name, dns.TypeTXT, uint16(i+1)) //nolint:gosec // a test counter
	}
}

// TestDNSTunnelDetected drives the detector through a real listener:
// encoded names, a new one each time, TXT, all answering NXDOMAIN.
func TestDNSTunnelDetected(t *testing.T) {
	s, addr := tunnelListener(t, "log")
	sendTunnel(t, addr, "evil.test", 40)

	st := s.DNS()[0]
	if st.Tunnel == nil {
		t.Fatal("no tunnel status on a listener that configured one")
	}
	if st.Tunnel.Detections == 0 {
		t.Fatalf("a tunnel through a real listener was not detected: %+v", st.Tunnel)
	}
	if st.Tunnel.Action != "log" || st.Tunnel.Blocked != 0 {
		t.Fatalf("action: log blocked queries: %+v", st.Tunnel)
	}
	snap := s.Stats()
	if snap.DNSTunnels == 0 || snap.DNSTunnelTracked == 0 {
		t.Fatalf("the detection did not reach the stats: %+v", snap)
	}
}

// TestDNSTunnelBlocked: with action: block the domain is refused for
// the client that tripped it, and the queries never reach an upstream.
func TestDNSTunnelBlocked(t *testing.T) {
	s, addr := tunnelListener(t, "block")
	sendTunnel(t, addr, "evil.test", 60)
	st := s.DNS()[0]
	if st.Tunnel.Detections == 0 {
		t.Fatalf("not detected: %+v", st.Tunnel)
	}
	if st.Tunnel.Blocked == 0 {
		t.Fatalf("action: block refused nothing: %+v", st.Tunnel)
	}
	// A name under an unrelated domain still resolves normally, which
	// is the difference between a detector and an outage.
	if rc := askDNS(t, addr, "www.ordinary.test", dns.TypeA, 9999); rc != dns.RcodeNXDomain {
		t.Fatalf("unrelated name got rcode %d", rc) // the upstream says NXDOMAIN to everything
	}
	if s.DNS()[0].Tunnel.Blocked == st.Tunnel.Blocked+1 {
		t.Fatal("an unrelated domain was counted as blocked")
	}
}

// TestDNSTunnelAllowList: a domain that legitimately looks like this --
// a reputation service encodes a hash into a name and answers TXT -- is
// named rather than scored.
func TestDNSTunnelAllowList(t *testing.T) {
	s, addr := tunnelListener(t, "block")
	sendTunnel(t, addr, "reputation.test", 80)
	if st := s.DNS()[0]; st.Tunnel.Detections != 0 || st.Tunnel.Blocked != 0 {
		t.Fatalf("an allowed domain was judged: %+v", st.Tunnel)
	}
}

// TestDNSOrdinaryTrafficIsQuiet: the resolver's day job must not set
// this off, or nobody will leave it on.
func TestDNSOrdinaryTrafficIsQuiet(t *testing.T) {
	s, addr := tunnelListener(t, "block")
	names := []string{"www.example.test", "api.example.test", "mail.example.test",
		"cdn.example.test", "login.example.test", "static.example.test"}
	for i := 0; i < 200; i++ {
		askDNS(t, addr, names[i%len(names)], dns.TypeA, uint16(i+1)) //nolint:gosec // a test counter
	}
	if st := s.DNS()[0]; st.Tunnel.Detections != 0 || st.Tunnel.Blocked != 0 {
		t.Fatalf("ordinary lookups were called a tunnel: %+v", st.Tunnel)
	}
}
