package forward

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/masque"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// CONNECT-IP: the half of MASQUE that carries whole IP packets rather
// than datagrams to one address. It is the most dangerous thing in this
// proxy -- a client that could put any source address on the wire
// through it would have a VPN with no policy -- so what is driven here
// is the packet path: which packets reach the device, which are
// refused as spoofing, and what the client is told before it may send
// any at all.
//
// The device is a fake. Attaching a real tun interface needs a
// privilege a test suite does not have, and nothing about the decision
// depends on the kernel: the anti-spoofing check is this package's
// own, over the addresses the operator configured.

// fakeTunnel is a tun device that keeps what was written to it and
// answers reads from a script.
type fakeTunnel struct {
	assign, routes []netip.Prefix

	mu      sync.Mutex
	written [][]byte
	reads   [][]byte
	closed  bool
	ready   chan struct{}
}

func newFakeTunnel(assign, routes []string) *fakeTunnel {
	d := &fakeTunnel{ready: make(chan struct{})}
	for _, s := range assign {
		d.assign = append(d.assign, netip.MustParsePrefix(s))
	}
	for _, s := range routes {
		d.routes = append(d.routes, netip.MustParsePrefix(s))
	}
	return d
}

func (d *fakeTunnel) Assign() []netip.Prefix { return d.assign }
func (d *fakeTunnel) Routes() []netip.Prefix { return d.routes }

// Allowed is the real check: the fake does not get to decide policy.
func (d *fakeTunnel) Allowed(p []byte) bool { return packetAllowed(p, d.assign, d.routes) }

func (d *fakeTunnel) Write(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, errors.New("device closed")
	}
	d.written = append(d.written, append([]byte(nil), b...))
	return len(b), nil
}

// Read hands out the scripted packets and then blocks until the device
// is closed, the way a device with nothing to deliver does.
func (d *fakeTunnel) Read(b []byte) (int, error) {
	d.mu.Lock()
	if len(d.reads) > 0 {
		p := d.reads[0]
		d.reads = d.reads[1:]
		n := copy(b, p)
		d.mu.Unlock()
		return n, nil
	}
	d.mu.Unlock()
	<-d.ready
	return 0, io.EOF
}

func (d *fakeTunnel) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.ready)
	}
	return nil
}

func (d *fakeTunnel) sent() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.written...)
}

// ipProxy starts a forward listener with CONNECT-IP enabled and the
// tunnel opener pointed at a fake device.
func ipProxy(t *testing.T, extra string, dev *fakeTunnel) (*proxy.Server, *forwardServer) {
	t.Helper()
	was := openTun
	openTun = func(name string, assign, routes []string) (tunnel, error) {
		if dev == nil {
			return nil, errors.New("no such device")
		}
		return dev, nil
	}
	t.Cleanup(func() { openTun = was })
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward:
        allow_private: true
        masque:
          ip: true
          ip_device: xproxy0
          ip_assign: [192.0.2.7/32]
          ip_routes: [198.51.100.0/24]
%s
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, extra)
	s := proxytest.Start(t, yaml)
	return s, forwardOf(t, s)
}

// connectIP opens a CONNECT-IP session for one target and protocol.
func connectIP(t *testing.T, f *forwardServer, target, proto string) (io.WriteCloser, *io.PipeReader, func() int) {
	t.Helper()
	return connectMasque(t, f, "connect-ip",
		masque.IPPrefix+url.PathEscape(target)+"/"+proto+"/")
}

// ipv4 builds a minimal IPv4 packet from one address to another.
func ipv4(src, dst string, payload ...byte) []byte {
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	p := make([]byte, 20)
	p[0] = 0x45
	p[9] = 17 // UDP, so the protocol field is not zero
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return append(p, payload...)
}

// A session is told its address and its routes before it may send
// anything, because a client cannot choose a source address or know
// where it may send without being told.
func TestACONNECTIPSessionIsToldItsAddressAndRoutesFirst(t *testing.T) {
	dev := newFakeTunnel([]string{"192.0.2.7/32"}, []string{"198.51.100.0/24"})
	_, f := ipProxy(t, "", dev)
	pw, body, status := connectIP(t, f, "*", "*")
	defer func() { _ = body.Close() }()
	if code := status(); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	first, err := masque.ReadCapsule(body)
	if err != nil {
		t.Fatal(err)
	}
	if first.Type != masque.CapsuleAddressAssign {
		t.Errorf("the first capsule was %d, want an address assignment", first.Type)
	}
	second, err := masque.ReadCapsule(body)
	if err != nil {
		t.Fatal(err)
	}
	if second.Type != masque.CapsuleRouteAdvertisement {
		t.Errorf("the second capsule was %d, want a route advertisement", second.Type)
	}

	// A client that asks for an address of its own is answered with
	// the one it was given rather than ignored.
	if err := masque.WriteCapsule(pw, masque.Capsule{Type: masque.CapsuleAddressRequest}); err != nil {
		t.Fatal(err)
	}
	again, err := masque.ReadCapsule(body)
	if err != nil {
		t.Fatal(err)
	}
	if again.Type != masque.CapsuleAddressAssign {
		t.Errorf("an address request was answered with %d", again.Type)
	}
	_ = pw.Close()
}

// The anti-spoofing check, which is the whole reason a VPN endpoint is
// a sensitive thing to run: a packet whose source is not the address
// this client was assigned, or whose destination is outside the routes
// it was advertised, never reaches the device.
func TestACONNECTIPSessionCannotSpoofItsSourceOrItsDestination(t *testing.T) {
	dev := newFakeTunnel([]string{"192.0.2.7/32"}, []string{"198.51.100.0/24"})
	s, f := ipProxy(t, "", dev)
	pw, body, status := connectIP(t, f, "*", "*")
	defer func() { _ = body.Close() }()
	if code := status(); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	// The two capsules the session opens with.
	for range 2 {
		if _, err := masque.ReadCapsule(body); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range []struct {
		name   string
		packet []byte
		reach  bool
	}{
		{name: "its own address to an advertised route", packet: ipv4("192.0.2.7", "198.51.100.9", 'o', 'k'), reach: true},
		{name: "somebody else's address", packet: ipv4("203.0.113.1", "198.51.100.9", 'n', 'o')},
		{name: "a destination outside the routes", packet: ipv4("192.0.2.7", "10.0.0.1", 'n', 'o')},
		// Too short to hold an IP header at all.
		{name: "not a packet", packet: []byte{0x45, 0, 0}},
	} {
		if err := masque.WriteCapsule(pw, masque.Datagram(0, c.packet)); err != nil {
			t.Fatal(err)
		}
	}
	// A datagram on a context this session never registered.
	if err := masque.WriteCapsule(pw, masque.Datagram(7, ipv4("192.0.2.7", "198.51.100.9"))); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()

	deadline := time.Now().Add(10 * time.Second)
	for len(dev.sent()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := dev.sent()
	if len(got) != 1 {
		t.Fatalf("%d packets reached the device, want only the one that was allowed", len(got))
	}
	if string(got[0][20:]) != "ok" {
		t.Errorf("the packet that reached the device was %q", got[0][20:])
	}
	if n := s.Stats().MasqueDropped; n < 4 {
		t.Errorf("masque_dropped %d, want the four that were refused", n)
	}
}

// What the device delivers reaches the client as a datagram capsule.
func TestWhatTheDeviceDeliversReachesTheClient(t *testing.T) {
	dev := newFakeTunnel([]string{"192.0.2.7/32"}, []string{"198.51.100.0/24"})
	dev.reads = [][]byte{ipv4("198.51.100.9", "192.0.2.7", 'i', 'n')}
	_, f := ipProxy(t, "", dev)
	pw, body, status := connectIP(t, f, "*", "*")
	defer func() { _ = body.Close() }()
	if code := status(); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for range 2 {
		if _, err := masque.ReadCapsule(body); err != nil {
			t.Fatal(err)
		}
	}
	c, err := masque.ReadCapsule(body)
	if err != nil {
		t.Fatal(err)
	}
	ctx, payload, err := masque.SplitDatagram(c)
	if err != nil || ctx != 0 {
		t.Fatalf("the delivered packet arrived as %d %v", ctx, err)
	}
	if string(payload[20:]) != "in" {
		t.Errorf("the delivered packet was %q", payload[20:])
	}
	_ = pw.Close()
}

// The refusals, each said plainly enough for an operator to act on:
// a target that is not one, no device at all, and a target the egress
// policy refuses.
func TestACONNECTIPSessionIsRefusedForAReasonAnOperatorCanAct(t *testing.T) {
	t.Run("a target that is not one", func(t *testing.T) {
		dev := newFakeTunnel([]string{"192.0.2.7/32"}, []string{"198.51.100.0/24"})
		_, f := ipProxy(t, "", dev)
		pw, body, status := connectMasque(t, f, "connect-ip", masque.IPPrefix+"only-one-segment")
		_ = pw.Close()
		if code := status(); code != http.StatusBadRequest {
			t.Errorf("a malformed target gave %d, want 400", code)
		}
		_ = body.Close()
	})

	t.Run("no device", func(t *testing.T) {
		// The device is configured and cannot be opened, which is the
		// case an operator most needs told: the request is understood
		// and refused for a reason, not failed generically.
		_, f := ipProxy(t, "", nil)
		pw, body, status := connectIP(t, f, "*", "*")
		_ = pw.Close()
		if code := status(); code != http.StatusNotImplemented {
			t.Errorf("a session with no device gave %d, want 501", code)
		}
		_ = body.Close()
		// Counted on the listener, which is where its status view
		// reads the figure an operator is shown.
		if n := f.masque.refused.Load(); n == 0 {
			t.Error("the refusal was not counted")
		}
	})

	t.Run("a target the policy refuses", func(t *testing.T) {
		dev := newFakeTunnel([]string{"192.0.2.7/32"}, []string{"198.51.100.0/24"})
		_, f := ipProxy(t, "        deny: [\"203.0.113.5\"]\n", dev)
		pw, body, status := connectIP(t, f, "203.0.113.5", "17")
		_ = pw.Close()
		if code := status(); code != http.StatusForbidden {
			t.Errorf("a denied target gave %d, want 403", code)
		}
		_ = body.Close()
	})
}

// The session bound, which is what stops a MASQUE listener being an
// unbounded socket factory, and the context field, which is what stops
// a datagram for an extension nobody registered being forwarded as a
// payload.
func TestAMasqueSessionPastTheBoundIsRefused(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	port := echo.LocalAddr().(*net.UDPAddr).Port
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%d]
        allow_private: true
        masque:
          udp: true
          max_sessions: 1
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, port)
	s := proxytest.Start(t, yaml)
	f := forwardOf(t, s)

	// The first session is held open, so the second meets the bound.
	pw, body, status := connectUDP(t, f, "127.0.0.1", port)
	defer func() { _ = body.Close() }()
	if code := status(); code != http.StatusOK {
		t.Fatalf("the first session gave %d", code)
	}
	pw2, body2, status2 := connectUDP(t, f, "127.0.0.1", port)
	_ = pw2.Close()
	if code := status2(); code != http.StatusServiceUnavailable {
		t.Errorf("a session past the bound gave %d, want 503", code)
	}
	_ = body2.Close()
	if n := f.masque.refused.Load(); n == 0 {
		t.Error("the refusal was not counted")
	}

	// And on the session that is open, a datagram for a context this
	// proxy never registered is dropped rather than forwarded.
	before := s.Stats().MasqueDropped
	if err := masque.WriteCapsule(pw, masque.Datagram(9, []byte("not for context zero"))); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().MasqueDropped <= before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Stats().MasqueDropped <= before {
		t.Error("a datagram on an unregistered context was not dropped")
	}
	_ = pw.Close()
}
