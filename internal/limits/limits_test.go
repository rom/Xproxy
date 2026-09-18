package limits

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestKeyedLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewKeyedLimiter(10, 5, 100)
	l.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if !l.Allow("a") {
			t.Fatalf("burst %d refused", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("6th request allowed")
	}
	if !l.Allow("b") {
		t.Fatal("other key affected")
	}
	now = now.Add(100 * time.Millisecond) // +1 token
	if !l.Allow("a") || l.Allow("a") {
		t.Fatal("refill wrong")
	}
	now = now.Add(time.Hour)
	if !l.Allow("a") {
		t.Fatal("full refill")
	}
}

func TestKeyedLimiterBound(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewKeyedLimiter(1, 1, 2)
	l.now = func() time.Time { return now }
	for i := 0; i < 1000; i++ {
		l.Allow(string(rune('a'+i%26)) + string(rune(i)))
	}
	if l.Len() > 2*64 {
		t.Fatalf("limiter grew to %d keys", l.Len())
	}
	now = now.Add(time.Hour)
	// All stale now; new keys evict old ones.
	before := l.Len()
	l.Allow("fresh-key")
	if l.Len() > before {
		t.Fatalf("did not evict: before %d after %d", before, l.Len())
	}
}

func TestPeerRates(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewKeyedLimiter(10, 10, 100)
	l.now = func() time.Time { return now }
	l.SetPeerStale(3 * time.Second)
	// Drain the bucket, then let a peer consume the whole rate: no refill.
	for i := 0; i < 10; i++ {
		l.Allow("k")
	}
	l.ReportPeer("b", []PeerReport{{Key: "k", Rate: 10}})
	now = now.Add(time.Second)
	if l.Allow("k") {
		t.Fatal("refilled while a peer consumed the full rate")
	}
	// Peer at half the rate: local refills at 5/s.
	l.ReportPeer("b", []PeerReport{{Key: "k", Rate: 5}})
	now = now.Add(time.Second)
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.Allow("k") {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("allowed %d, want 5", allowed)
	}
	// Two peers over-consuming clamp refill at zero, never negative tokens.
	l.ReportPeer("b", []PeerReport{{Key: "k", Rate: 8}})
	l.ReportPeer("c", []PeerReport{{Key: "k", Rate: 8}})
	now = now.Add(2 * time.Second)
	if l.Allow("k") {
		t.Fatal("refilled with peers over the rate")
	}
	// Stale reports expire (3s window, reports were made 2s ago).
	now = now.Add(4 * time.Second)
	if !l.Allow("k") {
		t.Fatal("stale peer reports still applied")
	}
	// Flush reports local consumption and resets.
	f := l.Flush(0)
	if f["k"] != 16 { // 10 + 5 + 1
		t.Fatalf("flush %v", f)
	}
	if len(l.Flush(0)) != 0 {
		t.Fatal("flush did not reset")
	}
	// Flush limit keeps the largest consumers.
	for i := 0; i < 5; i++ {
		l.Allow("small")
	}
	for i := 0; i < 8; i++ {
		l.Allow("big")
	}
	f = l.Flush(1)
	if len(f) != 1 || f["big"] != 8 {
		t.Fatalf("flush limit %v", f)
	}
	// Unknown key from a peer creates a bucket already under pressure.
	l.ReportPeer("b", []PeerReport{{Key: "new", Rate: 10}})
	now = now.Add(time.Second)
	n := 0
	for i := 0; i < 20; i++ {
		if l.Allow("new") {
			n++
		}
	}
	if n != 10 { // burst only, no refill
		t.Fatalf("new key allowed %d", n)
	}
	// Peer accounting disabled: reports are ignored.
	l2 := NewKeyedLimiter(10, 10, 100)
	l2.ReportPeer("b", []PeerReport{{Key: "k", Rate: 100}})
	if l2.Len() != 0 {
		t.Fatal("report accepted without peer accounting")
	}
}

func TestConcurrency(t *testing.T) {
	c := NewConcurrency(2)
	r1, ok := c.Acquire()
	if !ok {
		t.Fatal("1")
	}
	_, ok = c.Acquire()
	if !ok {
		t.Fatal("2")
	}
	if _, ok := c.Acquire(); ok {
		t.Fatal("3 admitted")
	}
	r1()
	r1() // idempotent
	if c.InFlight() != 1 {
		t.Fatalf("inflight %d", c.InFlight())
	}
	if _, ok := c.Acquire(); !ok {
		t.Fatal("after release")
	}
	if c.Rejected.Load() != 1 {
		t.Fatal("rejected count")
	}
}

func TestConnLimiterBanned(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lim := NewConnLimiter(10, 10)
	reasons := make(chan string, 1)
	lim.Banned = func(netip.Addr) bool { return true }
	lim.OnReject = func(_ netip.Addr, r string) { reasons <- r }
	ln := lim.Wrap(base)
	defer ln.Close()
	go func() {
		for {
			if _, err := ln.Accept(); err != nil {
				return
			}
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("banned connection was not closed")
	}
	reason := <-reasons
	if lim.Rejected.Load() != 1 || reason != "banned" || lim.Open() != 0 {
		t.Fatalf("rejected=%d reason=%q open=%d", lim.Rejected.Load(), reason, lim.Open())
	}
}

func TestAdmit(t *testing.T) {
	lim := NewConnLimiter(2, 1)
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	r1, reason := lim.Admit(a)
	if r1 == nil || reason != "" {
		t.Fatal("first admit")
	}
	if r, reason := lim.Admit(a); r != nil || reason != "max_connections_per_ip" {
		t.Fatalf("per ip: %v %q", r != nil, reason)
	}
	r2, _ := lim.Admit(b)
	if r2 == nil {
		t.Fatal("second address")
	}
	if r, reason := lim.Admit(netip.MustParseAddr("192.0.2.3")); r != nil || reason != "max_connections" {
		t.Fatalf("global: %v %q", r != nil, reason)
	}
	r1()
	r1()
	if lim.Open() != 1 {
		t.Fatalf("open %d", lim.Open())
	}
	lim.Banned = func(x netip.Addr) bool { return x == a }
	if r, reason := lim.Admit(a); r != nil || reason != "banned" {
		t.Fatalf("banned: %v %q", r != nil, reason)
	}
	if lim.Rejected.Load() != 3 {
		t.Fatalf("rejected %d", lim.Rejected.Load())
	}
	r2()
}

func TestConnLimiter(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lim := NewConnLimiter(10, 2)
	ln := lim.Wrap(base)
	defer ln.Close()
	accepted := make(chan net.Conn, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	var clients []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	// Two should be accepted, the third closed by the server.
	var srv []net.Conn
	for i := 0; i < 2; i++ {
		select {
		case c := <-accepted:
			srv = append(srv, c)
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for accept")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for lim.Rejected.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if lim.Rejected.Load() != 1 {
		t.Fatalf("rejected %d", lim.Rejected.Load())
	}
	if lim.Open() != 2 {
		t.Fatalf("open %d", lim.Open())
	}
	srv[0].Close()
	srv[0].Close()
	if lim.Open() != 1 {
		t.Fatalf("open after close %d", lim.Open())
	}
	for _, c := range clients {
		c.Close()
	}
}
