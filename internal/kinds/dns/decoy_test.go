package dns_test

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A resolver that is not there, through the whole listener.
//
// These are the tests that say the wiring is right rather than that the answers
// are: a honeypot that answers with no resolver behind it, a blocked name
// fabricated instead of refused on a listener that really resolves, and -- the
// one that matters most -- a name that was going to be resolved reaching the
// upstream and coming back with the upstream's answer.

// udpAsk puts one question to a listener over UDP and parses the reply.
func udpAsk(t *testing.T, addr, name string, typ uint16) *wire.Message {
	t.Helper()
	q, err := wire.Query(0x3131, name, typ)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	m, err := wire.ParseMessage(buf[:n])
	if err != nil {
		t.Fatalf("%s: the reply does not parse: %v", name, err)
	}
	return m
}

// answerA is the one address in an A reply, or "" when there is none.
func answerA(m *wire.Message) string {
	for _, rr := range m.Answer {
		if rr.Type == wire.TypeA {
			if a, ok := netip.AddrFromSlice(rr.Data); ok {
				return a.String()
			}
		}
	}
	return ""
}

// fakeUpstream is a resolver that answers one address for everything, so a test
// can tell an answer that came from upstream from one that did not.
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
			h, err := wire.ParseHeader(buf[:n])
			if err != nil {
				continue
			}
			q, qEnd, err := wire.ParseQuestion(buf[:n])
			if err != nil {
				continue
			}
			resp := wire.Reply(buf[:n], qEnd, h, wire.RcodeNXDomain)
			if q.Type == wire.TypeA {
				resp = wire.AnswerA(buf[:n], qEnd, h, q, []byte{198, 51, 100, 7}, 60)
			}
			_, _ = up.WriteTo(resp, addr)
		}
	}()
	return up.LocalAddr().String()
}

// A honeypot resolver: it answers, and there is nothing behind it.
const decoyResolverYAML = `
version: 1
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        deception:
          mode: decoy
          profile: documentation
          ttl: 120s
          tripwire: [payroll.internal]
logging: {access: {enabled: false}}
`

func TestADecoyResolverAnswersWithNothingBehindIt(t *testing.T) {
	s := proxytest.Start(t, decoyResolverYAML)
	addr := s.Addrs()["resolver"]

	m := udpAsk(t, addr, "update.malware.example", wire.TypeA)
	if m.Header.Rcode() != wire.RcodeNoError {
		t.Fatalf("rcode %d", m.Header.Rcode())
	}
	got := answerA(m)
	if got == "" || !netip.MustParsePrefix("192.0.2.0/24").Contains(netip.MustParseAddr(got)) {
		t.Fatalf("the fabrication answered %q", got)
	}
	if m.Answer[0].TTL != 120 {
		t.Errorf("TTL %d, want the configured 120", m.Answer[0].TTL)
	}
	// The same name twice is the same address: a visitor who looked twice and
	// saw two would have found the fabrication.
	if again := answerA(udpAsk(t, addr, "update.malware.example", wire.TypeA)); again != got {
		t.Errorf("two lookups answered %s and %s", got, again)
	}
	// A different name is a different address, which is what a sinkhole is not.
	other := answerA(udpAsk(t, addr, "cdn.malware.example", wire.TypeA))
	if other == "" || other == got {
		t.Errorf("a second name answered %q", other)
	}
	// A type the fabrication does not hold is NODATA rather than an invention.
	if mx := udpAsk(t, addr, "update.malware.example", wire.TypeMX); len(mx.Answer) != 0 ||
		mx.Header.Rcode() != wire.RcodeNoError {
		t.Errorf("an MX query answered %d records, rcode %d", len(mx.Answer), mx.Header.Rcode())
	}
	// A configured tripwire, and one of the built-in shapes.
	_ = udpAsk(t, addr, "reports.payroll.internal", wire.TypeA)
	_ = udpAsk(t, addr, strings.Repeat("abcdefghij.", 10)+"tunnel.example", wire.TypeA)
	awaitDNS(t, s, func(sn proxy.Snapshot) bool { return sn.DNSDeceived >= 6 },
		"the deception counter did not move")
	awaitDNS(t, s, func(sn proxy.Snapshot) bool { return sn.DNSTripwire >= 2 },
		"the tripwires did not fire")
	// The status view knows about it, which is where an operator looks.
	st, ok := dnsDecoyStatus(s)
	if !ok {
		t.Fatal("the listener reported no decoy")
	}
	if st.Mode != "decoy" || st.Kind != "dns" || st.Profile != "documentation" {
		t.Errorf("status %+v", st)
	}
	if st.Served == 0 || st.Tripped == 0 || !st.Anyone || len(st.Visitors) != 1 {
		t.Errorf("status %+v", st)
	}
	// And the resolver's own status view carries the same numbers.
	if ds := s.DNS(); len(ds) != 1 || ds[0].Deceived == 0 || ds[0].Tripwire == 0 {
		t.Errorf("the resolver status is %+v", ds)
	}
}

// The same fabrication on a listener that really resolves: it answers where a
// refusal would be written, and nowhere else.
//
// That is the invariant the whole feature rests on -- a query on its way to a
// resolver is never answered from here -- and this is the test of it.
func TestOnARealResolverOnlyRefusalsAreFabricated(t *testing.T) {
	yaml := `
version: 1
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["%s"]
        block: [malware.example]
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          profile: documentation
logging: {access: {enabled: false}}
`
	s := proxytest.Start(t, fmt.Sprintf(yaml, fakeUpstream(t)))
	addr := s.Addrs()["resolver"]

	// A name nobody blocked is resolved, and the answer is the upstream's.
	if got := answerA(udpAsk(t, addr, "www.example.test", wire.TypeA)); got != "198.51.100.7" {
		t.Fatalf("an ordinary name answered %q, and the upstream answers 198.51.100.7", got)
	}
	// A blocked name would have been NXDOMAIN. It is fabricated instead, out of
	// the pool -- and the address is not the upstream's, which is what says the
	// query never went there.
	blocked := udpAsk(t, addr, "update.malware.example", wire.TypeA)
	if blocked.Header.Rcode() != wire.RcodeNoError {
		t.Fatalf("a blocked name answered rcode %d", blocked.Header.Rcode())
	}
	got := answerA(blocked)
	if got == "" || !netip.MustParsePrefix("192.0.2.0/24").Contains(netip.MustParseAddr(got)) {
		t.Fatalf("a blocked name answered %q", got)
	}
	awaitDNS(t, s, func(sn proxy.Snapshot) bool { return sn.DNSDeceived >= 1 },
		"the fabrication did not answer the blocked name")
	// The refusal counters still moved: the fabrication replaces what the client
	// is told, not what the operator is told.
	if n := s.Stats().Refusals["dns"]["blocked"]; n < 1 {
		t.Errorf("the refusal was not counted: %+v", s.Stats().Refusals["dns"])
	}
	if n := s.Stats().DNSBlocked; n < 1 {
		t.Errorf("the block was not counted: %d", n)
	}
}

// A client outside the section's list is refused rather than lied to.
func TestAResolverClientOutsideTheListIsStillRefused(t *testing.T) {
	yaml := `
version: 1
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["%s"]
        block: [malware.example]
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]
logging: {access: {enabled: false}}
`
	s := proxytest.Start(t, fmt.Sprintf(yaml, fakeUpstream(t)))
	addr := s.Addrs()["resolver"]
	m := udpAsk(t, addr, "update.malware.example", wire.TypeA)
	if m.Header.Rcode() != wire.RcodeNXDomain {
		t.Errorf("a client outside the list got rcode %d, want NXDOMAIN", m.Header.Rcode())
	}
	if n := s.Stats().DNSDeceived; n != 0 {
		t.Errorf("the fabrication answered %d queries for a client outside its list", n)
	}
}

// A decoy listener needs no upstreams, and a listener that fronts real
// resolvers cannot be one.
func TestWhatADecoyResolverRefusesToLoad(t *testing.T) {
	for _, c := range []struct{ name, yaml, wants string }{
		{
			name: "a decoy with upstreams is a contradiction",
			yaml: `
version: 1
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["127.0.0.1:53"]
        deception: {mode: decoy}
logging: {access: {enabled: false}}
`,
			wants: "decoy is the whole listener",
		},
		{
			name: "mode answer with no client list",
			yaml: `
version: 1
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns:
        upstreams: ["127.0.0.1:53"]
        deception: {mode: answer}
logging: {access: {enabled: false}}
`,
			wants: "clients: required in mode answer",
		},
		{
			name: "a listener with neither upstreams nor a decoy",
			yaml: `
version: 1
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:0"
      kind: dns
      dns: {}
logging: {access: {enabled: false}}
`,
			wants: "upstreams: at least one resolver is required",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := config.Parse([]byte(c.yaml)); err == nil {
				t.Fatalf("loaded, want %q", c.wants)
			} else if !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("error %v, want %q", err, c.wants)
			}
		})
	}
}

// dnsDecoyStatus finds this listener's decoy in the status view.
func dnsDecoyStatus(s *proxy.Server) (proxy.DecoyStatus, bool) {
	for _, st := range s.DeviceDecoys() {
		if st.Kind == "dns" {
			return st, true
		}
	}
	return proxy.DecoyStatus{}, false
}

// awaitDNS polls for a condition, because the resolver answers on its own
// goroutines.
func awaitDNS(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	sn := s.Stats()
	t.Fatalf("%s: deceived %d, tripped %d", what, sn.DNSDeceived, sn.DNSTripwire)
}
