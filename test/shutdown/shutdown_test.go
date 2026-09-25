// Package shutdown_test starts every listener kind through the real engine
// and shuts it down while clients are still arriving.
//
// It exists because of one bug that four kinds shared and that no per-kind
// test was looking for. Session tracking is usually written as a
// sync.WaitGroup: Add one per accepted connection in the accept loop, Done
// when the session ends, Wait in shutdown. A WaitGroup's Add must not run
// concurrently with its Wait while the counter is at zero -- and an accept
// loop can do exactly that, because the engine closes the front socket
// before it calls a kind's Shutdown, which leaves the accept goroutine
// between a connection it has already accepted and the Add it has not
// reached yet.
//
// What this test does *not* do is catch that window from outside. It is a
// few instructions wide and needs the counter at exactly zero, and twenty
// runs of twenty-four dialers against the unfixed telnet kind never hit it
// -- which is worth writing down, because a test that looks like it covers
// a race and does not is worse than one that admits what it covers. The
// mechanism is tested directly in internal/acceptgroup, and the kinds are
// correct by construction: the check and the Add happen under one lock.
//
// What this test does catch is the other half of getting it wrong, and the
// risk of changing twenty listeners to fix it: a shutdown that **hangs**.
// A WaitGroup whose Add landed after its Wait began leaves the counter
// above zero for ever, and an acceptgroup adopted wrongly -- an Enter
// without its Leave, a Close that never happens -- does the same. So every
// kind is started, hammered with arriving clients, and asserted to shut
// down cleanly inside a bound, with the race detector on for whatever else
// it finds along the way.
package shutdown_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/bacnet"
	_ "github.com/rom/xproxy/internal/kinds/dhcp"
	_ "github.com/rom/xproxy/internal/kinds/ftp"
	_ "github.com/rom/xproxy/internal/kinds/iec104"
	_ "github.com/rom/xproxy/internal/kinds/ldap"
	_ "github.com/rom/xproxy/internal/kinds/modbus"
	_ "github.com/rom/xproxy/internal/kinds/mqtt"
	_ "github.com/rom/xproxy/internal/kinds/mysql"
	_ "github.com/rom/xproxy/internal/kinds/ntp"
	_ "github.com/rom/xproxy/internal/kinds/ntske"
	_ "github.com/rom/xproxy/internal/kinds/postgres"
	_ "github.com/rom/xproxy/internal/kinds/rdp"
	_ "github.com/rom/xproxy/internal/kinds/redis"
	_ "github.com/rom/xproxy/internal/kinds/smtp"
	_ "github.com/rom/xproxy/internal/kinds/snmp"
	_ "github.com/rom/xproxy/internal/kinds/syslog"
	_ "github.com/rom/xproxy/internal/kinds/tcp"
	_ "github.com/rom/xproxy/internal/kinds/tds"
	_ "github.com/rom/xproxy/internal/kinds/telnet"
	_ "github.com/rom/xproxy/internal/kinds/tftp"
	_ "github.com/rom/xproxy/internal/kinds/udp"
	_ "github.com/rom/xproxy/internal/kinds/vnc"
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/testutil"
)

// kindCase is one listener to start, hammer and shut down. datagram says
// which transport a client uses to arrive, since a UDP listener is not
// reached by dialling TCP.
type kindCase struct {
	// section is the listener's own configuration, indented to sit under
	// "      " in the document below. %[1]s is a directory the test owns,
	// for a kind that needs a certificate on disk.
	section  string
	datagram bool
}

// cases are the kinds this test starts. Every kind in the roster must be
// either here or in excluded, which TestEveryKindIsCoveredOrExcluded
// asserts -- so a kind added tomorrow is covered or says why not.
var cases = map[string]kindCase{
	"tcp":      {section: "tcp: {default: u}"},
	"telnet":   {section: "telnet: {upstream: u}"},
	"vnc":      {section: "vnc: {upstream: u, security_types: [none]}"},
	"smtp":     {section: "smtp: {upstream: u}"},
	"mqtt":     {section: "mqtt: {upstream: u}"},
	"ftp":      {section: "ftp: {upstream: u}"},
	"modbus":   {section: "modbus: {upstream: u}"},
	"iec104":   {section: "iec104: {upstream: u}"},
	"ldap":     {section: "ldap: {upstream: u}"},
	"postgres": {section: "postgres: {upstream: u, require_tls: false}"},
	"mysql":    {section: "mysql: {upstream: u, require_tls: false}"},
	"tds":      {section: "tds: {upstream: u, require_tls: false}"},
	"redis":    {section: "redis: {upstream: u, require_tls: false}"},
	"rdp": {section: "rdp: {upstream: u}\n      " +
		"tls: {certificates: [{cert_file: %[1]s/c.pem, key_file: %[1]s/k.pem}]}"},
	"ntske": {section: "ntske: {upstream: u}\n      " +
		"tls: {certificates: [{cert_file: %[1]s/c.pem, key_file: %[1]s/k.pem}]}"},
	"udp":    {section: "udp: {upstream: u}", datagram: true},
	"syslog": {section: "syslog: {upstream: u}", datagram: true},
	"tftp":   {section: "tftp: {upstream: u}", datagram: true},
	"snmp":   {section: "snmp: {upstream: u}", datagram: true},
	"ntp":    {section: "ntp: {upstream: u}", datagram: true},
	"bacnet": {section: "bacnet: {upstream: u}", datagram: true},
	"dhcp":   {section: "dhcp: {upstream: u, relay_address: 10.0.0.1}", datagram: true},
}

// excluded are the kinds this test does not start, each with the reason.
// They are listed rather than left out so that the parity check below can
// tell a deliberate omission from a kind nobody thought about.
var excluded = map[string]string{
	"http":    "the HTTP data plane has no accept loop of its own: net/http owns it",
	"forward": "the forward proxy is an HTTP listener, and the same applies",
	"dns":     "internal/dns has its own lifecycle test, which this one would duplicate",
	"ssh":     "starting it needs a host key pair, a client key and a known_hosts file on disk",
}

const doc = `
version: 1
server:
  listeners:
    - name: subject
      address: "127.0.0.1:0"
      kind: %[1]s
      %[2]s
logging: {access: {enabled: false}}
upstreams:
  - {name: u, endpoints: [{address: %[3]q}]}
`

// TestShutdownDoesNotRaceArrivingClients is the test the bug needed.
//
// The upstream is deliberately a closed port: what is being exercised is
// the accept path and the shutdown, not a session that goes anywhere. A
// session that fails to dial ends quickly, which is what makes this
// affordable to run for every kind.
func TestShutdownDoesNotRaceArrivingClients(t *testing.T) {
	for _, kind := range sortedKinds() {
		c := cases[kind]
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			section := c.section
			if strings.Contains(section, "%[1]s") {
				// A kind that needs a certificate on disk. WriteCert names
				// the files itself, so they are copied to the names the
				// section expects -- and only then is the directory
				// substituted, because a Sprintf over a format string with
				// no verbs appends its argument as an error.
				dir := t.TempDir()
				cert, key := testutil.WriteCert(t, dir, "127.0.0.1")
				copyFile(t, cert, filepath.Join(dir, "c.pem"))
				copyFile(t, key, filepath.Join(dir, "k.pem"))
				section = fmt.Sprintf(section, dir)
			}
			// A sink that accepts and closes at once. An upstream that
			// merely refuses would end every session inside the dial, and a
			// session that never starts is one the accept loop's own
			// bookkeeping is never exercised by.
			s := start(t, fmt.Sprintf(doc, kind, section, sink(t, c.datagram)))
			addr := addrOf(t, s)

			// Clients keep arriving for as long as this runs, so the
			// shutdown below happens while the accept loop is admitting.
			stop := make(chan struct{})
			var dialers sync.WaitGroup
			network := "tcp"
			if c.datagram {
				network = "udp"
			}
			for i := 0; i < 24; i++ {
				dialers.Add(1)
				go func() {
					defer dialers.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						conn, err := net.Dial(network, addr)
						if err != nil {
							return
						}
						// One octet, so a datagram listener sees a client
						// at all: a UDP socket that nothing was sent to is
						// not a session.
						_ = conn.SetDeadline(time.Now().Add(time.Second))
						_, _ = conn.Write([]byte{0})
						_ = conn.Close()
					}
				}()
			}
			// Let a few land before the shutdown starts.
			time.Sleep(20 * time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Shutdown(ctx) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("shutdown: %v", err)
				}
			case <-time.After(10 * time.Second):
				// A shutdown that hangs is the other half of getting this
				// wrong: a WaitGroup whose Add landed after Wait began can
				// leave the counter above zero for ever.
				t.Fatal("shutdown did not return")
			}
			close(stop)
			dialers.Wait()
		})
	}
}

// TestEveryKindIsCoveredOrExcluded keeps this test honest as kinds are
// added. The alternative is a table that silently stops covering the thing
// it was written for.
func TestEveryKindIsCoveredOrExcluded(t *testing.T) {
	for _, kind := range listener.Kinds() {
		_, covered := cases[kind]
		reason, said := excluded[kind]
		switch {
		case covered && said:
			t.Errorf("kind %q is both started and excluded", kind)
		case !covered && !said:
			t.Errorf("kind %q is neither started here nor excluded with a reason", kind)
		case said && strings.TrimSpace(reason) == "":
			t.Errorf("kind %q is excluded with no reason", kind)
		}
	}
	for kind := range cases {
		if _, ok := listener.RoleOf(kind); !ok {
			t.Errorf("this test starts %q, which is not a kind", kind)
		}
	}
}

// sink is an upstream that answers and goes away, on whichever transport
// the kind under test relays.
func sink(t *testing.T, datagram bool) string {
	t.Helper()
	if datagram {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(buf[:n], from)
			}
		}()
		return pc.LocalAddr().String()
	}
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
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

func start(t *testing.T, yaml string) *proxy.Server {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	return s
}

func addrOf(t *testing.T, s *proxy.Server) string {
	t.Helper()
	a, ok := s.Addrs()["subject"]
	if !ok {
		t.Fatal("the listener did not bind")
	}
	return a
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	if from == to {
		return
	}
	b, err := os.ReadFile(from) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sortedKinds() []string {
	out := make([]string, 0, len(cases))
	for k := range cases {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
