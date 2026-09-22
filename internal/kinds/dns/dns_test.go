package dns_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dns"
	_ "github.com/rom/xproxy/internal/kinds/dns"
	"github.com/rom/xproxy/internal/proxytest"
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
			h, _ := wire.ParseHeader(buf[:n])
			q, qEnd, err := wire.ParseQuestion(buf[:n])
			if err != nil {
				continue
			}
			var resp []byte
			switch {
			case q.Type == wire.TypeA && strings.HasSuffix(q.Name, ".test"):
				resp = wire.AnswerA(buf[:n], qEnd, h, q, []byte{192, 0, 2, 7}, 120)
			case q.Type == wire.TypeAAAA:
				resp = wire.Reply(buf[:n], qEnd, h, wire.RcodeNoError)
			default:
				resp = wire.Reply(buf[:n], qEnd, h, wire.RcodeNXDomain)
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
	s := proxytest.Start(t, fmt.Sprintf(yaml, up.LocalAddr().String(), blockFile))
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

// TestDoHRoute answers RFC 8484 GET and POST on an http route through
// a dns listener's policy and cache.
func TestDoHRoute(t *testing.T) {
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
			h, _ := wire.ParseHeader(buf[:n])
			q, qEnd, err := wire.ParseQuestion(buf[:n])
			if err != nil {
				continue
			}
			_, _ = up.WriteTo(wire.AnswerA(buf[:n], qEnd, h, q, []byte{192, 0, 2, 9}, 90), addr)
		}
	}()
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
        block: [blocked.test]
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - name: doh
    paths: [/dns-query]
    doh: {listener: resolver}
  - name: rest
    upstream: app
`
	s := proxytest.Start(t, fmt.Sprintf(yaml, up.LocalAddr().String()))
	base := "http://" + proxytest.Addr(t, s, "main")
	q, _ := wire.Query(7, "www.example.test", wire.TypeA)
	resp, err := http.Get(base + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(q))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/dns-message" || resp.Header.Get("Cache-Control") != "max-age=90" {
		t.Fatalf("GET: %d %v", resp.StatusCode, resp.Header)
	}
	if h, _ := wire.ParseHeader(body); h.ID != 7 || h.Rcode() != wire.RcodeNoError || h.ANCount != 1 {
		t.Fatalf("GET answer: %+v", h)
	}
	pr, err := http.Post(base+"/dns-query", "application/dns-message", bytes.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := io.ReadAll(pr.Body)
	_ = pr.Body.Close()
	if pr.StatusCode != 200 || len(pb) != len(body) || s.Stats().DNSCacheHits != 1 {
		t.Fatalf("POST: %d len %d hits %d", pr.StatusCode, len(pb), s.Stats().DNSCacheHits)
	}
	bq, _ := wire.Query(8, "x.blocked.test", wire.TypeA)
	resp, err = http.Get(base + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(bq))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if h, _ := wire.ParseHeader(body); resp.StatusCode != 200 || h.Rcode() != wire.RcodeNXDomain || resp.Header.Get("Cache-Control") != "max-age=0" {
		t.Fatalf("blocked over DoH: %d %+v %v", resp.StatusCode, h, resp.Header)
	}
	for _, tc := range []struct {
		method, path, ct, body string
		want                   int
	}{
		{"GET", "/dns-query", "", "", 400},
		{"GET", "/dns-query?dns=%%%", "", "", 400},
		{"GET", "/dns-query?dns=AAAA", "", "", 400},
		{"POST", "/dns-query", "text/plain", "x", 415},
		{"PUT", "/dns-query", "", "", 405},
	} {
		req, _ := http.NewRequest(tc.method, base+tc.path, strings.NewReader(tc.body))
		if tc.ct != "" {
			req.Header.Set("Content-Type", tc.ct)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != tc.want {
			t.Errorf("%s %s: got %d want %d", tc.method, tc.path, r.StatusCode, tc.want)
		}
	}
	if st := s.DNS(); len(st) != 1 || st[0].Queries < 3 || st[0].Blocked != 1 {
		t.Fatalf("listener status: %+v", st)
	}
}
