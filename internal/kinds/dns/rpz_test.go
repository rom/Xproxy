package dns

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
	wire "github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// fakeUpstream answers A for anything under .test, so a name a policy
// zone lets through resolves and one it acts on does not.
func fakeUpstream(t *testing.T) string {
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
			h, _ := wire.ParseHeader(buf[:n])
			q, qEnd, err := wire.ParseQuestion(buf[:n])
			if err != nil {
				continue
			}
			var resp []byte
			if q.Type == wire.TypeA {
				resp = wire.AnswerA(buf[:n], qEnd, h, q, []byte{192, 0, 2, 7}, 120)
			} else {
				resp = wire.Reply(buf[:n], qEnd, h, wire.RcodeNoError)
			}
			_, _ = up.WriteTo(resp, addr)
		}
	}()
	return up.LocalAddr().String()
}

// End to end through a listener: each action of a policy zone, answered
// as the rule says.
func TestAPolicyZoneDecidesWhatTheRuleSays(t *testing.T) {
	upstream := fakeUpstream(t)
	dir := t.TempDir()
	zone := filepath.Join(dir, "feed.rpz")
	body := `$TTL 60
$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
@ NS ns.rpz.local.
evil.test.rpz.local.       CNAME .
*.evil.test.rpz.local.     CNAME .
good.evil.test.rpz.local.  CNAME rpz-passthru.
empty.test.rpz.local.      CNAME *.
walled.test.rpz.local.     A 10.0.0.1
quiet.test.rpz.local.      CNAME rpz-drop.
`
	if err := os.WriteFile(zone, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
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
        rpz:
          refresh: 0
          zones:
            - {name: feed, file: %s}
logging:
  access: {enabled: false}
bans:
  action: reject
  triggers: [{name: rpz, reasons: [dns_rpz], threshold: 100, window: 1m, duration: 1h}]
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - {name: r, upstream: app}
`, upstream, zone)
	s := proxytest.Start(t, yaml)
	addr := s.Addrs()["resolver"]
	lookup := func(name string) ([]string, error) {
		t.Helper()
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return r.LookupHost(ctx, name)
	}
	// A name the zone denies: NXDOMAIN, and so is everything under the
	// wildcard.
	if _, err := lookup("evil.test"); err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Errorf("a denied name: %v", err)
	}
	if _, err := lookup("login.evil.test"); err == nil {
		t.Error("the wildcard did not apply")
	}
	// The exception resolves, through the upstream.
	if ips, err := lookup("good.evil.test"); err != nil || len(ips) != 1 || ips[0] != "192.0.2.7" {
		t.Errorf("the exception did not resolve: %v %v", ips, err)
	}
	// NODATA: no error, no addresses.
	if ips, err := lookup("empty.test"); err == nil && len(ips) > 0 {
		t.Errorf("a nodata rule answered %v", ips)
	}
	// Local data: the zone's own address, not the upstream's.
	if ips, err := lookup("walled.test"); err != nil || len(ips) != 1 || ips[0] != "10.0.0.1" {
		t.Errorf("local data answered %v (%v)", ips, err)
	}
	// A drop rule answers nothing at all, so the client times out.
	if _, err := lookup("quiet.test"); err == nil {
		t.Error("a drop rule answered")
	}
	// The type filtering, which needs a raw query: the zone answers
	// walled.test with an A record, so an AAAA query is NODATA rather
	// than an A record in an AAAA answer.
	query, err := wire.Query(0x4242, "walled.test", wire.TypeAAAA)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no answer to the AAAA query: %v", err)
	}
	h, err := wire.ParseHeader(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if h.ANCount != 0 {
		t.Errorf("an AAAA query got %d answers from a rule holding an A record", h.ANCount)
	}
	if rc := wire.ExtendedRcode(buf[:n]); rc != wire.RcodeNoError {
		t.Errorf("rcode %d, want NOERROR: the name exists, the type does not", rc)
	}

	st := s.DNS()
	if len(st) != 1 {
		t.Fatalf("status: %+v", st)
	}
	// The drop is a query with no answer at all, counted as a drop
	// rather than as a refusal with one.
	if st[0].Dropped == 0 {
		t.Error("the drop rule did not count a dropped query")
	}
	if st[0].RPZMatched < 5 {
		t.Errorf("rpz_matched %d, want the five decisions", st[0].RPZMatched)
	}
	// The resolver asks for A and AAAA, so the exception is counted once
	// per query rather than once per name.
	if st[0].RPZPassthru == 0 {
		t.Error("the exception was not counted")
	}
	if len(st[0].RPZZones) != 1 || st[0].RPZZones[0].Name != "feed" || st[0].RPZZones[0].Rules != 6 {
		t.Errorf("zones: %+v", st[0].RPZZones)
	}
	if st[0].RPZZones[0].Matches < 5 {
		t.Errorf("per zone matches: %+v", st[0].RPZZones[0])
	}
	if st[0].RPZWatching {
		t.Error("refresh: 0 started a watcher")
	}
}

// A zone file that cannot be read fails the load, and a zone with a
// trigger this resolver does not implement says which.
func TestABrokenZoneFailsTheListener(t *testing.T) {
	upstream := fakeUpstream(t)
	dir := t.TempDir()
	zone := filepath.Join(dir, "feed.rpz")
	body := `$ORIGIN rpz.local.
@ SOA ns.rpz.local. hostmaster.rpz.local. 1 3600 600 86400 60
8.0.0.0.10.rpz-ip.rpz.local. CNAME .
`
	if err := os.WriteFile(zone, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
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
        rpz: {refresh: 0, zones: [{name: feed, file: %s}]}
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - {name: r, upstream: app}
`, upstream, zone)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	srv, err := proxy.New(cfg, logging.Discard())
	if err == nil {
		err = srv.Start()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "rpz-ip") {
		t.Errorf("a zone with an unsupported trigger loaded: %v", err)
	}
}
