package botscore

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

// The scorer keeps a history per client and per device. Both tables are
// filled by whoever sends requests, so their bounds are the difference
// between a memory ceiling and an attacker choosing how much the proxy
// allocates.

func TestClientTableIsBounded(t *testing.T) {
	s := build(t, filter.Options{"deny_at": 90})
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	// Fill the table past its ceiling from distinct addresses.
	ip := func(i int) netip.Addr {
		var b [4]byte
		b[0], b[1], b[2], b[3] = 10, byte(i>>16), byte(i>>8), byte(i)
		return netip.AddrFrom4(b)
	}
	for i := 0; i < maxClients+2000; i++ {
		info := filter.Info{ClientIP: ip(i), Path: "/p"}
		s.Begin(nil, &info).Request(req(chromeUA)) //nolint:staticcheck // the scorer ignores the context
		if i%5000 == 0 {
			now = now.Add(time.Second)
		}
	}
	s.mu.Lock()
	n := len(s.clients)
	s.mu.Unlock()
	if n > maxClients {
		t.Fatalf("the client table holds %d entries, ceiling %d", n, maxClients)
	}
	if n == 0 {
		t.Fatal("the client table is empty")
	}
	// The proxy still scores a request after the eviction.
	info := filter.Info{ClientIP: netip.MustParseAddr("198.51.100.1"), Path: "/p"}
	in := s.Begin(nil, &info).(*instance) //nolint:staticcheck // as above
	if v := in.Request(req(chromeUA)); v.Deny {
		t.Errorf("a clean request was denied after eviction: %+v", v)
	}

	// evict drops entries older than the window outright, and a quarter
	// of the rest when the table is still full.
	s.mu.Lock()
	before := len(s.clients)
	s.evict(now.Add(time.Hour))
	after := len(s.clients)
	s.mu.Unlock()
	if after >= before {
		t.Errorf("eviction left %d of %d entries", after, before)
	}
}

func TestDeviceTableIsBounded(t *testing.T) {
	s := build(t, filter.Options{"deny_at": 90, "device_addresses": 3})
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	addr := netip.MustParseAddr("198.51.100.1")

	// A device identifier nobody sent is not tracked.
	if s.observeDevice("", addr) {
		t.Error("an empty device identifier was tracked")
	}
	// One device seen from more addresses than the bound is shared.
	for i := 0; i < 2; i++ {
		if s.observeDevice("dev", netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})) {
			t.Errorf("address %d already counted as shared", i)
		}
	}
	if !s.observeDevice("dev", netip.AddrFrom4([4]byte{10, 0, 0, 3})) {
		t.Error("the third address did not count as shared")
	}
	// The same address again does not add to the count.
	for i := 0; i < 100; i++ {
		s.observeDevice("dev2", addr)
	}
	s.mu.Lock()
	n := len(s.devices["dev2"].addrs)
	s.mu.Unlock()
	if n != 1 {
		t.Errorf("one address was counted %d times", n)
	}
	// A flood of device identifiers is bounded: the table never grows
	// past its ceiling, whatever a client sends.
	for i := 0; i < maxDevices+2000; i++ {
		s.observeDevice(string(rune('a'+i%26))+string(rune(i)), netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}))
		if i%10000 == 0 {
			now = now.Add(time.Second)
		}
	}
	s.mu.Lock()
	devices := len(s.devices)
	s.mu.Unlock()
	if devices > maxDevices {
		t.Fatalf("the device table holds %d entries, ceiling %d", devices, maxDevices)
	}
	// A device sending from thousands of addresses is bounded too: the
	// set of addresses per device does not grow without limit.
	for i := 0; i < 5000; i++ {
		s.observeDevice("wide", netip.AddrFrom4([4]byte{10, 2, byte(i >> 8), byte(i)}))
	}
	s.mu.Lock()
	wide := len(s.devices["wide"].addrs)
	s.mu.Unlock()
	if wide > 4096 {
		t.Errorf("one device recorded %d addresses", wide)
	}
	// The window resets a device's addresses, so a shared office
	// address does not mark a device for ever.
	now = now.Add(time.Hour)
	if s.observeDevice("dev", addr) {
		t.Error("the device is still shared after the window")
	}
}

func TestClampThreshold(t *testing.T) {
	cases := map[int]int{
		-100: 10, -1: 10, 0: 10, 9: 10, 10: 10, 55: 55, 100: 100, 101: 100, 1 << 20: 100,
	}
	for in, want := range cases {
		if got := clampThreshold(in); got != want {
			t.Errorf("clampThreshold(%d) = %d want %d", in, got, want)
		}
	}
	// The suggestions stay inside the range and keep the challenge
	// threshold below the deny one, whatever the measured percentiles.
	for _, p := range [][2]int{{0, 0}, {5, 9}, {50, 50}, {90, 95}, {99, 99}, {200, 300}, {-5, -1}, {100, 10}} {
		deny, challenge := suggestThresholds(p[0], p[1])
		if deny < 20 || deny > 100 {
			t.Errorf("percentiles %v gave deny %d", p, deny)
		}
		if challenge < 10 || challenge > 100 {
			t.Errorf("percentiles %v gave challenge %d", p, challenge)
		}
		if challenge >= deny {
			t.Errorf("percentiles %v gave challenge %d at or above deny %d", p, challenge, deny)
		}
	}
}
