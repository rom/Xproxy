package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
)

// TestDNSListener runs a kind: dns listener against a fake upstream and
// resolves through it with Go's resolver over UDP and TCP; a blocked
// name is NXDOMAIN and counted as a ban reason, the block list reloads,
// counters reach the stats and the management view.
func TestDNSListener(t *testing.T) {
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
			h, _ := dns.ParseHeader(buf[:n])
			q, qEnd, err := dns.ParseQuestion(buf[:n])
			if err != nil {
				continue
			}
			var resp []byte
			switch {
			case q.Type == dns.TypeA && strings.HasSuffix(q.Name, ".test"):
				resp = dns.AnswerA(buf[:n], qEnd, h, q, []byte{192, 0, 2, 7}, 120)
			case q.Type == dns.TypeAAAA:
				resp = dns.Reply(buf[:n], qEnd, h, dns.RcodeNoError)
			default:
				resp = dns.Reply(buf[:n], qEnd, h, dns.RcodeNXDomain)
			}
			_, _ = up.WriteTo(resp, addr)
		}
	}()
	dir := t.TempDir()
	blockFile := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(blockFile, []byte("0.0.0.0 ads.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["%s"]
        block: [tracker.test]
        block_file: %s
        log_queries: true
        cache: {min_ttl: 1s}
logging:
  access: {enabled: false}
bans:
  action: reject
  triggers: [{name: dns, reasons: [dns_blocked], threshold: 100, window: 1m, duration: 1h}]
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - {name: r, upstream: app}
`
	s, _ := startServer(t, fmt.Sprintf(yaml, up.LocalAddr().String(), blockFile))
	addr := s.Addrs()["resolver"]
	for _, network := range []string{"udp", "tcp"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := r.LookupHost(ctx, "www.example.test")
		cancel()
		if err != nil || len(ips) != 1 || ips[0] != "192.0.2.7" {
			t.Fatalf("%s lookup: %v %v", network, ips, err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		_, err = r.LookupHost(ctx, "www.ads.test")
		cancel()
		if err == nil || !strings.Contains(err.Error(), "no such host") {
			t.Fatalf("%s blocked lookup: %v", network, err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		_, err = r.LookupHost(ctx, "x.tracker.test")
		cancel()
		if err == nil {
			t.Fatalf("%s inline block: %v", network, err)
		}
	}
	// Reload with the block list emptied: the name resolves.
	if err := os.WriteFile(blockFile, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(strings.Replace(fmt.Sprintf(yaml, up.LocalAddr().String(), blockFile), "block: [tracker.test]", "block: []", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", addr)
	}}
	if ips, err := r.LookupHost(context.Background(), "www.ads.test"); err != nil || len(ips) != 1 {
		t.Fatalf("after reload: %v %v", ips, err)
	}
	sn := s.Stats()
	st := s.DNS()
	if len(st) != 1 || st[0].Listener != "resolver" || sn.DNSQueries < 8 || sn.DNSBlocked < 4 || sn.DNSCacheEntries == 0 || st[0].BlockEntries != 0 {
		t.Fatalf("stats: %+v %+v", sn.DNSQueries, st)
	}
	if s.PurgeDNS() == 0 || s.Stats().DNSCacheEntries != 0 {
		t.Fatal("purge")
	}
	// A block file that vanishes fails the reload.
	if err := os.Remove(blockFile); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err == nil || !strings.Contains(err.Error(), "block_file") {
		t.Fatalf("reload with a missing block file: %v", err)
	}
}
