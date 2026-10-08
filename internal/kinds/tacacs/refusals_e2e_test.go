package tacacs

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/tacacs"
)

// tacacsRelay starts a relay with its own top-level sections, which the
// shared helper does not reach: the ban ladder sits outside the
// listener.
func tacacsRelay(t *testing.T, section, top, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	key := filepath.Join(t.TempDir(), "tacacs.key")
	if err := os.WriteFile(key, []byte(theKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: admin
      address: "127.0.0.1:0"
      kind: tacacs
      tacacs:
        upstream: servers
        secret_file: %q
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`, top, key, section, serverAddr))
	return s, proxytest.Addr(t, s, "admin")
}

// refused asserts that the relay ends the connection without answering,
// which is what every refusal before the first exchange looks like: on
// TACACS+ there is no reply that is not already a session.
func refused(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return // refused at accept is a refusal too
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf [1]byte
	if n, err := c.Read(buf[:]); err == nil {
		t.Fatalf("a refused device was answered with %d octets", n)
	}
}

// Everything that ends a TACACS+ connection before the first exchange,
// and what it leaves behind.
//
// This relay sits in front of the thing that decides who may configure
// the network, so a refusal here is the one that matters most: the
// counters name it, and the ban ladder hears about it before any
// logging setting can turn the record down.
func TestEveryRefusalBeforeTheFirstExchange(t *testing.T) {
	bans := `bans:
  triggers:
    - {name: admin, reasons: [tacacs_denied], threshold: 1, window: 1m, duration: 10m}`

	t.Run("a client the lists hold out", func(t *testing.T) {
		srv := startServer(t, &fakeServer{})
		s, addr := tacacsRelay(t, `        allow_clients: ["10.0.0.0/8"]`, bans, srv.addr())
		refused(t, addr)
		if n := refusals(s, "client_not_allowed"); n < 1 {
			t.Errorf("the refusal was not counted: %d", n)
		}
		deadline := time.Now().Add(2 * time.Second)
		ip := netip.MustParseAddr("127.0.0.1")
		for time.Now().Before(deadline) && !s.Bans().Banned(ip) {
			time.Sleep(10 * time.Millisecond)
		}
		if !s.Bans().Banned(ip) {
			t.Error("the refusal never reached the ban ladder")
		}
	})

	t.Run("a device past the connection rate", func(t *testing.T) {
		srv := startServer(t, &fakeServer{})
		s, addr := tacacsRelay(t, `        rate_limit: 1
        rate_burst: 1`, "", srv.addr())
		// The first connection takes the burst; the second is refused.
		d := connect(t, addr)
		if _, ok := d.authorize(0x1000, "alice", 15, "service=shell", "cmd=show"); !ok {
			t.Fatal("the first device was refused")
		}
		refused(t, addr)
		if n := refusals(s, "rate_limited"); n < 1 {
			t.Errorf("the rate limit was not counted: %d", n)
		}
	})

	t.Run("a server that cannot be reached", func(t *testing.T) {
		// A port nothing is listening on: the device connects, the relay
		// cannot, and the device is told by being closed on.
		dead, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		gone := dead.Addr().String()
		_ = dead.Close()
		s, addr := tacacsRelay(t, "", "", gone)
		refused(t, addr)
		if n := refusals(s, "upstream_failed"); n < 1 {
			t.Errorf("the unreachable server was not counted: %d", n)
		}
	})
}

// The access lines are a setting, and turning them off must not turn off
// anything else: the exchange still happens and the counters still move.
func TestTheAccessLinesCanBeTurnedOffWithoutTurningOffTheRelay(t *testing.T) {
	srv := startServer(t, &fakeServer{})
	s, addr := tacacsRelay(t, `        allow_clients: ["127.0.0.1/32"]
        commands: ["show ..."]
        default_action: allow
        log_requests: false
        log_accounting: false`, "", srv.addr())
	d := connect(t, addr)
	if _, ok := d.authorize(0x1000, "alice", 15, "service=shell", "cmd=show"); !ok {
		t.Fatal("the authorization was refused")
	}
	// An accounting record on the same listener, which has a line of its
	// own and a switch of its own.
	h, body := d.ask(wire.TypeAcct, 0x2000, 1, 0, acctBody(wire.AcctFlagStop, "alice", "service=shell", "cmd=show"))
	if body == nil {
		t.Fatalf("the accounting record was not answered: %+v", h)
	}
	if sn := s.Stats(); sn.TACACSCommands < 1 || sn.TACACSAccounting < 1 {
		t.Errorf("commands %d, accounting records %d: both should have been counted",
			sn.TACACSCommands, sn.TACACSAccounting)
	}
}
