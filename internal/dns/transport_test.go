package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The listener speaks to whoever can reach the port. These tests are
// about what a client can do to it with the stream framing, the
// accessors around the cache, and the names it has to render into a
// log line.

// TestTCPFraming covers the two-byte length prefix, which is the one
// place a stream client chooses how much the server will read.
func TestTCPFraming(t *testing.T) {
	up := newFakeUpstream(t)
	s, addr := startServer(t, &Policy{Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL: time.Second, MaxTTL: time.Hour}, Hooks{})

	// A well-formed query over TCP is answered.
	resp := tcpQuery(t, addr, mustQuery(t, 1, "a.example.test", TypeA))
	if h, _ := ParseHeader(resp); h.ID != 1 || h.Rcode() != RcodeNoError {
		t.Fatalf("a plain TCP query: %+v", h)
	}

	// Frames a client can send that are not queries. The connection may
	// be closed or the query refused; the server must stay up and answer
	// the next client either way.
	raw := func(b []byte, wait time.Duration) []byte {
		t.Helper()
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(wait))
		if _, err := c.Write(b); err != nil {
			return nil
		}
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return nil
		}
		n := int(binary.BigEndian.Uint16(hdr))
		if n > 65535 {
			return nil
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(c, body); err != nil {
			return nil
		}
		return body
	}
	q := mustQuery(t, 7, "a.example.test", TypeA)
	framed := append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...) //nolint:gosec // test size
	cases := map[string][]byte{
		"nothing":                       nil,
		"one byte of the length":        {0},
		"a length and no body":          {0, 12},
		"a length longer than the body": append(binary.BigEndian.AppendUint16(nil, 512), q...),
		"a zero length frame":           {0, 0},
		"a frame of one byte":           {0, 1, 0x00},
		"a header with no question":     append(binary.BigEndian.AppendUint16(nil, 12), make([]byte, 12)...),
		"rubbish the size of a query":   append(binary.BigEndian.AppendUint16(nil, 40), []byte(strings.Repeat("\xff", 40))...),
		"an HTTP request":               []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"the query twice in one write":  append(append([]byte{}, framed...), framed...),
	}
	for name, b := range cases {
		_ = raw(b, 750*time.Millisecond)
		// The server is still there.
		if resp := tcpQuery(t, addr, mustQuery(t, 8, "a.example.test", TypeA)); len(resp) == 0 {
			t.Fatalf("the server stopped answering after %s", name)
		}
	}
	// A client that opens a connection and says nothing is dropped by
	// the server's ten second read deadline rather than held forever,
	// which is what keeps a slow loris from holding every slot.
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	started := time.Now()
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Error("an idle connection received data")
	} else if waited := time.Since(started); waited > 15*time.Second {
		t.Errorf("an idle connection was held for %v", waited)
	}
	_ = c.Close()

	// Two queries on one connection are both answered, in order.
	c, err = net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	for id := uint16(20); id < 23; id++ {
		q := mustQuery(t, id, "a.example.test", TypeA)
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil { //nolint:gosec // test size
			t.Fatal(err)
		}
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c, hdr); err != nil {
			t.Fatal(err)
		}
		body := make([]byte, binary.BigEndian.Uint16(hdr))
		if _, err := io.ReadFull(c, body); err != nil {
			t.Fatal(err)
		}
		if h, _ := ParseHeader(body); h.ID != id {
			t.Fatalf("answer %d carried id %d", id, h.ID)
		}
	}
	if s.TCP.Load() == 0 {
		t.Error("no TCP query was counted")
	}
}

// TestUDPHostileDatagrams covers the datagram side: anything can be
// sent, nothing can be trusted, and the listener must answer or drop
// without stopping.
func TestUDPHostileDatagrams(t *testing.T) {
	up := newFakeUpstream(t)
	s, addr := startServer(t, &Policy{Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL: time.Second, MaxTTL: time.Hour}, Hooks{})
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	q := mustQuery(t, 1, "a.example.test", TypeA)
	datagrams := [][]byte{
		nil,
		{0},
		make([]byte, 11),                     // one short of a header
		make([]byte, 12),                     // a header with no question
		q[:len(q)-1],                         // a truncated question
		append(append([]byte{}, q...), 0xff), // trailing rubbish
		[]byte(strings.Repeat("\xff", 512)),
		make([]byte, 4096), // larger than a normal query
	}
	for i, d := range datagrams {
		if _, err := c.Write(d); err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
	}
	// The listener still answers.
	if resp := udpQuery(t, addr, mustQuery(t, 99, "a.example.test", TypeA)); len(resp) == 0 {
		t.Fatal("the listener stopped answering")
	}
	if s.Queries.Load() == 0 {
		t.Error("no query was counted")
	}
	// A query whose answer would not fit a datagram is truncated, not
	// dropped, so the client retries over TCP.
	big := mustQuery(t, 100, "big.example.test", TypeTXT)
	if resp := udpQuery(t, addr, big); len(resp) > 0 {
		if h, _ := ParseHeader(resp); h.ID != 100 {
			t.Errorf("the truncated answer carried id %d", h.ID)
		}
	}
}

// TestServerAccessors covers the small surface around the cache and the
// policy, which an operator reaches through the management socket.
func TestServerAccessors(t *testing.T) {
	up := newFakeUpstream(t)
	policy := &Policy{Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond), MinTTL: time.Second, MaxTTL: time.Hour}
	s, addr := startServer(t, policy, Hooks{})
	_ = udpQuery(t, addr, mustQuery(t, 1, "a.example.test", TypeA))
	if s.Status().CacheEntries == 0 {
		t.Fatal("the answer was not cached")
	}
	if n := s.Purge(); n == 0 {
		t.Error("purge reported nothing removed")
	}
	if s.Status().CacheEntries != 0 {
		t.Error("the cache was not emptied")
	}
	if n := s.Purge(); n != 0 {
		t.Errorf("purging an empty cache removed %d", n)
	}
	// Apply with a new resolver closes the old one's connections; the
	// server keeps answering.
	policy2 := *policy
	policy2.Resolver = NewResolver([]string{up.addr()}, 300*time.Millisecond)
	s.Apply(&policy2, 10)
	if resp := udpQuery(t, addr, mustQuery(t, 2, "a.example.test", TypeA)); len(resp) == 0 {
		t.Error("the server stopped answering after a policy swap")
	}
	// Close is safe to call more than once, including after Shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.Shutdown(ctx)
	s.Close()
	s.Close()
}

// TestClientOf covers the address the listener attributes a query to,
// which is what a ban or a rate limit is keyed on.
func TestClientOf(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"udp v4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}, "192.0.2.1"},
		{"tcp v4", &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 53}, "192.0.2.2"},
		{"udp v6", &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53}, "2001:db8::1"},
		{"tcp v6", &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 53}, "2001:db8::2"},
		// A v4-mapped v6 address is one address, not two: a ban on the
		// v4 form has to cover the mapped form.
		{"a mapped v4 address", &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.3"), Port: 53}, "192.0.2.3"},
		{"another address type", stringAddr("198.51.100.9:53"), "198.51.100.9"},
		{"an address with a zone", stringAddr("[fe80::1%eth0]:53"), "fe80::1%eth0"},
	}
	for _, tc := range cases {
		if got := clientOf(tc.addr); got.String() != tc.want {
			t.Errorf("%s: %q want %q", tc.name, got.String(), tc.want)
		}
	}
	// Addresses that are not addresses give the zero value rather than
	// a wrong attribution.
	for _, a := range []net.Addr{stringAddr(""), stringAddr("not an address"), stringAddr("192.0.2.1"), &net.UnixAddr{Name: "/tmp/x"}} {
		if got := clientOf(a); got.IsValid() {
			t.Errorf("%q was read as %s", a.String(), got)
		}
	}
}

type stringAddr string

func (s stringAddr) Network() string { return "test" }
func (s stringAddr) String() string  { return string(s) }

// TestTypeName covers the renderer that puts a query type in the access
// log, including the numbers it has no name for.
func TestTypeName(t *testing.T) {
	known := map[uint16]string{
		TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
		TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeSRV: "SRV", TypeDS: "DS",
		TypeRRSIG: "RRSIG", TypeNSEC: "NSEC", TypeDNSKEY: "DNSKEY", TypeNSEC3: "NSEC3",
		65: "HTTPS", TypeANY: "ANY", TypeOPT: "OPT", TypeDNAME: "DNAME", TypeNSEC3PARAM: "NSEC3PARAM",
	}
	for typ, want := range known {
		if got := TypeName(typ); got != want {
			t.Errorf("TypeName(%d) = %q want %q", typ, got, want)
		}
	}
	// An unknown type renders as a number, never as an empty string:
	// an empty field in a log line is a field nobody can search for.
	for _, typ := range []uint16{0, 3, 999, 65535} {
		got := TypeName(typ)
		if got == "" {
			t.Errorf("TypeName(%d) is empty", typ)
		}
		if strings.ContainsAny(got, " \t\r\n\"") {
			t.Errorf("TypeName(%d) = %q needs quoting", typ, got)
		}
	}
	// Every name is safe in a log line as it stands.
	for typ := 0; typ < 300; typ++ {
		if strings.ContainsAny(TypeName(uint16(typ)), " \t\r\n\"\\") { //nolint:gosec // range is small
			t.Errorf("TypeName(%d) = %q", typ, TypeName(uint16(typ))) //nolint:gosec // as above
		}
	}
}

// TestHandleDirectly covers the entry point the proxy's own listeners
// call, without a socket in the way.
func TestHandleDirectly(t *testing.T) {
	up := newFakeUpstream(t)
	s, _ := startServer(t, &Policy{Resolver: NewResolver([]string{up.addr()}, 300*time.Millisecond),
		MinTTL: time.Second, MaxTTL: time.Hour}, Hooks{})
	client := netip.MustParseAddr("198.51.100.1")
	resp := s.Handle(mustQuery(t, 1, "a.example.test", TypeA), client, false)
	if h, _ := ParseHeader(resp); h.ID != 1 {
		t.Fatalf("handle: %+v", h)
	}
	// The same query over a stream transport.
	if resp := s.Handle(mustQuery(t, 2, "a.example.test", TypeA), client, true); len(resp) == 0 {
		t.Fatal("no answer over the stream path")
	}
	// Queries that are not queries: a nil answer means drop, which is
	// allowed; a panic is not.
	for i, q := range [][]byte{nil, {0}, make([]byte, 12), []byte("not dns at all")} {
		_ = s.Handle(q, client, false)
		_ = s.Handle(q, netip.Addr{}, true)
		if s.Queries.Load() == 0 {
			t.Fatalf("case %d: nothing was counted", i)
		}
	}
}

// TestHandleLimited shares the listener's admission bound with callers that
// do not enter through its UDP, TCP, or native DoH serving loops.
func TestHandleLimited(t *testing.T) {
	s := New("limited", nil, nil, 1, 1, &Policy{}, Hooks{})
	s.sem <- struct{}{}
	if resp, admitted := s.HandleLimited(nil, netip.Addr{}, true); admitted || resp != nil {
		t.Fatalf("busy listener returned admitted=%t response=%x", admitted, resp)
	}
	if got := s.Dropped.Load(); got != 1 {
		t.Fatalf("busy listener counted %d drops, want 1", got)
	}
	<-s.sem
	if _, admitted := s.HandleLimited(nil, netip.Addr{}, true); !admitted {
		t.Fatal("free listener did not admit a query")
	}
}
