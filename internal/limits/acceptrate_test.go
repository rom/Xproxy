package limits

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A gate with nothing configured admits everything, so no caller has to
// test for one.
func TestAcceptRateInactiveAdmits(t *testing.T) {
	a := NewAcceptRate(0, 0, 0, 0, 0, 0, 0)
	if a.Active() {
		t.Fatal("a gate with no rates says it is active")
	}
	for i := 0; i < 100; i++ {
		if ok, _ := a.Allow(addr(t, "192.0.2.1")); !ok {
			t.Fatal("an inactive gate refused a connection")
		}
	}
}

// The total rate is what protects the accept path whatever the traffic
// is spread across: two addresses share one bucket.
func TestAcceptRateTotalIsShared(t *testing.T) {
	a := NewAcceptRate(1, 3, 0, 0, 0, 0, 0)
	var refused int
	for i := 0; i < 10; i++ {
		src := "192.0.2.1"
		if i%2 == 1 {
			src = "198.51.100.1"
		}
		if ok, reason := a.Allow(addr(t, src)); !ok {
			refused++
			if reason != ReasonRate {
				t.Fatalf("refusal reason %q", reason)
			}
		}
	}
	if refused == 0 {
		t.Fatal("a burst of 3 admitted ten connections")
	}
	if got := a.Rejected.Load(); int(got) != refused {
		t.Errorf("counted %d refusals, saw %d", got, refused)
	}
}

// The per source rate is keyed by a network, not an address: an
// attacker with a /64 of IPv6 has more addresses than any table could
// hold, so an address bound would be no bound at all.
func TestAcceptRatePerSourceCountsANetwork(t *testing.T) {
	a := NewAcceptRate(0, 0, 2, 2, 32, 64, 1024)
	// Ten different addresses inside one /64.
	refused := 0
	for i := 0; i < 10; i++ {
		src := netip.MustParseAddr("2001:db8::1")
		b := src.As16()
		b[15] = byte(i + 1)
		if ok, reason := a.Allow(netip.AddrFrom16(b)); !ok {
			refused++
			if reason != ReasonRateSource {
				t.Fatalf("refusal reason %q", reason)
			}
		}
	}
	if refused < 5 {
		t.Fatalf("only %d of ten addresses in one /64 were refused by a bound of 2", refused)
	}
	// Another /64 has its own budget.
	if ok, _ := a.Allow(addr(t, "2001:db8:1::1")); !ok {
		t.Fatal("a different /64 was refused on its first connection")
	}
}

// An IPv4 address is counted on its own by default, which is what a /32
// means.
func TestAcceptRatePerSourceIPv4(t *testing.T) {
	a := NewAcceptRate(0, 0, 1, 1, 32, 64, 1024)
	if ok, _ := a.Allow(addr(t, "192.0.2.1")); !ok {
		t.Fatal("the first connection was refused")
	}
	if ok, _ := a.Allow(addr(t, "192.0.2.1")); ok {
		t.Fatal("the second connection from one address was admitted past a burst of 1")
	}
	if ok, _ := a.Allow(addr(t, "192.0.2.2")); !ok {
		t.Fatal("another address was refused for its neighbour's traffic")
	}
}

// A wider IPv4 prefix makes a whole network share one budget, which is
// what an operator sets when one customer has a block.
func TestAcceptRateWiderPrefixSharesABudget(t *testing.T) {
	a := NewAcceptRate(0, 0, 1, 1, 24, 64, 1024)
	if ok, _ := a.Allow(addr(t, "192.0.2.1")); !ok {
		t.Fatal("the first connection was refused")
	}
	if ok, _ := a.Allow(addr(t, "192.0.2.99")); ok {
		t.Fatal("a neighbour in the same /24 had its own budget")
	}
}

// A connection refused by the per-source bound must not consume the shared
// total budget, or one source can deny service to every other source.
func TestAcceptRateSourceRejectionDoesNotConsumeTotal(t *testing.T) {
	a := NewAcceptRate(1, 2, 1, 1, 32, 64, 1024)
	attacker := addr(t, "192.0.2.1")
	other := addr(t, "198.51.100.1")

	if ok, _ := a.Allow(attacker); !ok {
		t.Fatal("the attacker's first connection was refused")
	}
	if ok, reason := a.Allow(attacker); ok || reason != ReasonRateSource {
		t.Fatalf("second attacker connection: ok=%v reason=%q", ok, reason)
	}
	if ok, reason := a.Allow(other); !ok {
		t.Fatalf("another source was refused after a source rejection: %q", reason)
	}
	if ok, reason := a.Allow(addr(t, "203.0.113.1")); ok || reason != ReasonRate {
		t.Fatalf("total bound did not account for admitted connections: ok=%v reason=%q", ok, reason)
	}
}

// The gate closes what it refuses at accept, before a byte is read.
func TestAcceptRateWrapClosesRefusedConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	a := NewAcceptRate(0, 0, 1, 1, 32, 64, 16)
	wrapped := a.Wrap(ln)
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := wrapped.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	<-accepted // the first is served
	// The gate refuses on the accept loop's own schedule, so the count
	// lands after the dial returns rather than with it.
	deadline := time.Now().Add(5 * time.Second)
	for a.Rejected.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("nothing was counted as refused")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(accepted) > 0 {
		t.Fatalf("%d more connections got past a burst of 1", len(accepted))
	}
}
