// Package authorization holds the estate's authorisation policy against every
// listener kind at once.
//
// The per-kind tests next to each kind say what that kind's admission point does
// with the name it has: an SSH key, a bind DN, a telnet factor. This one says the
// thing none of them can say alone, and the thing the feature is actually for --
// that one policy sits above the protocols. Fourteen kinds with no identity at the connection are
// driven here from one table, and each has to refuse the same client for the
// same reason and count it under its own name.
//
// It is one table rather than fourteen near-identical files because the interesting
// failure is a kind drifting out of line with its siblings, and a table is where
// that shows.
package authorization

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/amqp"
	_ "github.com/rom/xproxy/internal/kinds/bacnet"
	_ "github.com/rom/xproxy/internal/kinds/dhcp"
	_ "github.com/rom/xproxy/internal/kinds/dns"
	_ "github.com/rom/xproxy/internal/kinds/iec104"
	_ "github.com/rom/xproxy/internal/kinds/modbus"
	_ "github.com/rom/xproxy/internal/kinds/ntp"
	_ "github.com/rom/xproxy/internal/kinds/ntske"
	_ "github.com/rom/xproxy/internal/kinds/redis"
	_ "github.com/rom/xproxy/internal/kinds/s7"
	_ "github.com/rom/xproxy/internal/kinds/smtp"
	_ "github.com/rom/xproxy/internal/kinds/snmp"
	_ "github.com/rom/xproxy/internal/kinds/syslog"
	_ "github.com/rom/xproxy/internal/kinds/tftp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// kinds is every listener kind whose clients have no identity: nothing in the
// protocol names a person, and the address is all there is. The policy therefore
// decides on the address, the listener, the pool and the hour, and that is the
// same decision for all of them -- so it is made in one place, and asserted here
// in one place.
//
// block is the kind's own configuration. Every one of them points at a pool
// called "far" that nothing is listening on, because nothing should reach it: the
// admission point is before the dial in every kind, and a test that needed a
// working device to prove a refusal would be proving something else.
var kinds = []struct {
	kind  string
	block string
	// datagram says the client sends one datagram and expects silence. The rest
	// open a connection, which is itself the thing being refused.
	datagram bool
	// first is what the client says. Only dns needs it to parse: every other kind
	// here decides before it reads, which is the point.
	first []byte
}{
	{kind: "modbus", block: "modbus: {upstream: far}"},
	{kind: "iec104", block: "iec104: {upstream: far}"},
	{kind: "s7", block: "s7: {upstream: far}"},
	{kind: "ntske", block: "ntske: {upstream: far}"},
	{kind: "snmp", block: "snmp: {upstream: far}", datagram: true, first: []byte{0x30, 0x0c}},
	{kind: "tftp", block: "tftp: {upstream: far}", datagram: true, first: []byte{0, 1, 'a', 0, 'o', 'c', 't', 'e', 't', 0}},
	{kind: "bacnet", block: "bacnet: {upstream: far}", datagram: true, first: []byte{0x81, 0x0a, 0, 4}},
	{
		kind:     "dhcp",
		block:    "dhcp: {upstream: far, relay_address: 127.0.0.1}",
		datagram: true,
		first:    []byte{1, 1, 6, 0, 0, 0, 0, 1},
	},
	{kind: "syslog", block: "syslog: {upstream: far}", datagram: true, first: []byte("<13>hello")},
	{kind: "dns", block: `dns: {upstreams: ["127.0.0.1:1"]}`, datagram: true, first: dnsQuery()},
	// The last three relays. On these the connection is the identity-less half of
	// the question: redis and amqp ask again once the server has proved a name,
	// which is what test/authorization's proven-name test below is about, and smtp
	// never gets a name at all.
	{kind: "smtp", block: "smtp: {upstream: far}"},
	{kind: "redis", block: "redis: {upstream: far, require_tls: false, require_auth: false}"},
	{kind: "amqp", block: "amqp: {upstream: far, require_tls: false}"},
	{kind: "ntp", block: "ntp: {upstream: far}", datagram: true, first: ntpRequest()},
}

// ntpRequest is a version 4 client request: mode 3 in the first octet and the rest
// zero, which is what an unsynchronised client's first packet looks like.
func ntpRequest() []byte {
	p := make([]byte, 48)
	p[0] = 0x23 // leap 0, version 4, mode 3
	return p
}

// dnsQuery is one standard query for example.com A IN. dns is the only kind here
// that has to read the message before it can refuse the client, because a query
// it cannot parse is a formerr and that is a different answer.
func dnsQuery() []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:], 0x1234) // identifier
	binary.BigEndian.PutUint16(q[2:], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(q[4:], 1)      // one question
	for _, label := range []string{"example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1) // root, A, IN
}

// start brings up one listener of a kind with the given top-level section.
func start(t *testing.T, kind, block, top string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: front
      address: "127.0.0.1:0"
      kind: %s
      %s
logging: {access: {enabled: false}}
upstreams:
  - {name: far, endpoints: [{address: "127.0.0.1:1"}]}
%s
`, kind, block, top))
	return s, proxytest.Addr(t, s, "front")
}

// knock makes the one client move each kind needs and returns once the relay has
// had its chance to answer. A refusal here is a drop or a close, never a reply,
// so what it returns is deliberately ignored: the counter is the assertion.
func knock(t *testing.T, addr string, k struct {
	kind     string
	block    string
	datagram bool
	first    []byte
}) {
	t.Helper()
	network := "tcp"
	if k.datagram {
		network = "udp"
	}
	c, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		t.Fatalf("%s: dial: %v", k.kind, err)
	}
	defer func() { _ = c.Close() }()
	if len(k.first) > 0 {
		if _, err := c.Write(k.first); err != nil {
			t.Fatalf("%s: write: %v", k.kind, err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	_, _ = c.Read(make([]byte, 512))
}

// A policy that does not cover the client refuses it, on every kind, under the
// one reason. Before this the same rule meant eleven different things: on some
// kinds a refusal, on the rest nothing at all.
func TestOnePolicyRefusesAnUncoveredClientOnEveryIdentitylessKind(t *testing.T) {
	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			t.Parallel()
			// A rule for a network the loopback client is not in, so the client
			// falls through to the default, which is deny.
			s, addr := start(t, k.kind, k.block, `authorization:
  rules:
    - {name: plant-floor, allow: true, networks: ["10.0.0.0/8"]}`)
			knock(t, addr, k)
			if n := s.Stats().Refusals[k.kind]["authorization"]; n != 1 {
				t.Errorf("%s refused %d times for %q, want 1: %v",
					k.kind, n, "authorization", s.Stats().Refusals[k.kind])
			}
		})
	}
}

// And a rule that does cover the client does not refuse it. This is the half that
// catches a kind wired to refuse everything, which would pass the test above.
func TestAPolicyThatCoversTheClientRefusesNothing(t *testing.T) {
	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			t.Parallel()
			s, addr := start(t, k.kind, k.block, `authorization:
  rules:
    - {name: loopback, allow: true, networks: ["127.0.0.0/8"]}`)
			knock(t, addr, k)
			if n := s.Stats().Refusals[k.kind]["authorization"]; n != 0 {
				t.Errorf("%s refused a client its own rule allows %d times", k.kind, n)
			}
			az := s.Stats().Authz
			if az == nil {
				t.Fatal("no authorisation summary")
			}
			if az.Allowed == 0 {
				t.Errorf("%s never asked the policy: allowed %d, denied %d",
					k.kind, az.Allowed, az.Denied)
			}
		})
	}
}

// An imported list blocking the client's address refuses it too, and names the
// list rather than a rule: an operator who reads "authorization" goes looking for
// a rule they wrote, and on a feed's decision they would not find one.
func TestAListedClientIsRefusedOnEveryIdentitylessKind(t *testing.T) {
	list := writeList(t, "127.0.0.1/32\n")
	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			t.Parallel()
			s, addr := start(t, k.kind, k.block, fmt.Sprintf(`threat_intel:
  lists:
    - {name: listed-clients, file: %s, action: block}`, list))
			knock(t, addr, k)
			if n := s.Stats().Refusals[k.kind]["threat_intel"]; n != 1 {
				t.Errorf("%s refused %d times for %q, want 1: %v",
					k.kind, n, "threat_intel", s.Stats().Refusals[k.kind])
			}
		})
	}
}

// Shadow mode is the same decision written down and not applied. A listener under
// trial must not report a refusal it did not make, which is the one thing an
// operator reading its counters during the trial depends on.
func TestShadowModeRecordsWithoutRefusingOnEveryIdentitylessKind(t *testing.T) {
	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			t.Parallel()
			s, addr := start(t, k.kind, k.block, `authorization:
  shadow: true
  rules:
    - {name: plant-floor, allow: true, networks: ["10.0.0.0/8"]}`)
			knock(t, addr, k)
			st := s.Stats()
			if n := st.Refusals[k.kind]["authorization"]; n != 0 {
				t.Errorf("%s in shadow mode refused %d times", k.kind, n)
			}
			if n := st.WouldRefusals[k.kind]["authorization"]; n != 1 {
				t.Errorf("%s would-refusals %d, want 1: %v",
					k.kind, n, st.WouldRefusals[k.kind])
			}
		})
	}
}

// writeList puts one cidr list on disk.
func writeList(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nets.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
