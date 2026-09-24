package forward

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/masque"
)

// MASQUE proxying on a forward listener: CONNECT-UDP (RFC 9298) and
// CONNECT-IP (RFC 9484).
//
// HTTP CONNECT tunnels TCP and nothing else. Everything an estate runs
// that is not TCP — DNS, QUIC, NTP, WireGuard, telemetry — either
// leaves the network outside the proxy's policy or does not leave at
// all, and "outside the policy" is the usual answer, which is the
// problem. CONNECT-UDP is the same explicit proxy for datagrams: the
// same destination rules, the same credentials, the same access log,
// the same bans.
//
// Both use the capsule protocol (RFC 9297) rather than HTTP datagrams.
// Capsules are what RFC 9298 requires when datagrams are unavailable,
// they work on every HTTP version from 2 upwards, and they are
// reliable and ordered — which for a proxy that has to apply a policy
// to each datagram is a feature, not a cost: an unreliable path would
// make a refused datagram indistinguishable from a lost one.

// masqueUDPTimeout bounds how long an association sits with no traffic.
const masqueUDPTimeout = 5 * time.Minute

// masquePolicy is the compiled forward.masque section.
type masquePolicy struct {
	udp bool
	ip  bool
	// maxSessions bounds concurrent MASQUE sessions on the listener.
	maxSessions int

	sessions atomic.Int64
	udpTotal atomic.Uint64
	ipTotal  atomic.Uint64
	refused  atomic.Uint64
}

func newMasquePolicy(c *config.Masque) *masquePolicy {
	if c == nil {
		return nil
	}
	m := &masquePolicy{udp: c.UDP, ip: c.IP, maxSessions: c.MaxSessions}
	if m.maxSessions <= 0 {
		m.maxSessions = 1024
	}
	return m
}

// masqueProtocol reads the :protocol pseudo-header an extended CONNECT
// carries. HTTP/1.1 has no such thing, which is why RFC 9298 needs
// HTTP/2 or later.
func masqueProtocol(r *http.Request) string {
	if r.Method != http.MethodConnect || r.ProtoMajor < 2 {
		return ""
	}
	return r.Header.Get(":protocol")
}

// serveMasque handles an extended CONNECT. It returns false when the
// request is not one, so the caller falls through to ordinary CONNECT.
func (f *forwardServer) serveMasque(w http.ResponseWriter, r *http.Request, p *forwardPolicy, ip netip.Addr, user string, start time.Time) bool {
	proto := masqueProtocol(r)
	if proto == "" {
		return false
	}
	// Every extended CONNECT is claimed here, not only the two this
	// proxy implements. An extended CONNECT carries a path and no
	// authority, so letting an unimplemented one fall through to the
	// ordinary CONNECT path would mean treating a request for some
	// other protocol as a TCP tunnel to whatever its :authority said —
	// two different things confused, which is how a tunnel gets opened
	// to somewhere nobody asked for.
	m := f.masque
	if m == nil || (proto != "connect-udp" && proto != "connect-ip") ||
		(proto == "connect-udp" && !m.udp) || (proto == "connect-ip" && !m.ip) {
		// 501 rather than 405: the method is fine, this proxy does not
		// implement that protocol.
		f.deny(w, r, ip, user, http.StatusNotImplemented, "masque_"+proto, start)
		return true
	}
	if m.sessions.Add(1) > int64(m.maxSessions) {
		m.sessions.Add(-1)
		m.refused.Add(1)
		f.host.Counters().ForwardRejected.Add(1)
		f.deny(w, r, ip, user, http.StatusServiceUnavailable, "masque_session_limit", start)
		return true
	}
	defer m.sessions.Add(-1)
	switch proto {
	case "connect-udp":
		f.masqueUDP(w, r, p, ip, user, start)
	case "connect-ip":
		f.masqueIP(w, r, p, ip, user, start)
	}
	return true
}

// masqueUDP opens a UDP association for the client and relays capsules.
func (f *forwardServer) masqueUDP(w http.ResponseWriter, r *http.Request, p *forwardPolicy, ip netip.Addr, user string, start time.Time) {
	h := f.host
	target, err := masque.ParseUDPTarget(r.URL.Path)
	if err != nil {
		f.deny(w, r, ip, user, http.StatusBadRequest, "masque_target", start)
		return
	}
	dest := target.String()
	ips, reason := f.check(r.Context(), p, target.Host, target.Port)
	if reason != "" {
		f.deny(w, r, ip, user, http.StatusForbidden, reason, start)
		return
	}
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(r.Context(), "udp", udpBindFor(ips[0]))
	if err != nil {
		h.Counters().ForwardErrors.Add(1)
		f.deny(w, r, ip, user, http.StatusBadGateway, "masque_bind", start)
		return
	}
	defer func() { _ = pc.Close() }()
	remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ips[0], uint16(target.Port))) //nolint:gosec // a port is 16 bits

	// The response opens the tunnel. Capsules flow in both directions
	// from here, so the headers must reach the client before anything
	// waits for its first datagram.
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	// A tunnel lives as long as the client keeps it, not as long as a
	// response is expected to take.
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	f.masque.udpTotal.Add(1)
	h.Counters().MasqueUDP.Add(1)
	h.Counters().MasqueOpen.Add(1)
	defer h.Counters().MasqueOpen.Add(-1)

	var in, out int64
	done := make(chan struct{})
	// Destination to client.
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(masqueUDPTimeout))
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// Only the destination this association is for: the socket
			// is bound to one target, and a datagram from anywhere else
			// is somebody probing the port.
			if fa, err := netip.ParseAddrPort(from.String()); err != nil ||
				fa.Addr().Unmap() != ips[0] || int(fa.Port()) != target.Port {
				h.Counters().MasqueDropped.Add(1)
				h.Counters().Refuse("forward", "masque_unsolicited")
				continue
			}
			if err := masque.WriteCapsule(w, masque.Datagram(0, buf[:n])); err != nil {
				return
			}
			_ = rc.Flush()
			out += int64(n)
		}
	}()
	// Client to destination.
	for {
		c, err := masque.ReadCapsule(r.Body)
		if err != nil {
			break
		}
		if c.Type != masque.CapsuleDatagram {
			// An unknown capsule type is skipped, which RFC 9297
			// requires: it is how the protocol is extended without
			// breaking proxies that do not know the extension.
			continue
		}
		ctx, payload, err := masque.SplitDatagram(c)
		if err != nil || ctx != 0 {
			// Context 0 is the raw payload; a registered extension
			// would use another, and this proxy registers none.
			h.Counters().MasqueDropped.Add(1)
			h.Counters().Refuse("forward", "masque_context")
			continue
		}
		_ = pc.SetWriteDeadline(time.Now().Add(masqueUDPTimeout))
		if _, err := pc.WriteTo(payload, remote); err != nil {
			break
		}
		in += int64(len(payload))
	}
	_ = pc.Close()
	<-done
	h.Counters().ForwardBytesIn.Add(uint64(in))   //nolint:gosec // non-negative
	h.Counters().ForwardBytesOut.Add(uint64(out)) //nolint:gosec // non-negative
	f.logMasque(ip, user, "connect-udp", dest, in, out, start, "")
}

// udpBindFor picks a local bind address of the destination's family.
func udpBindFor(dst netip.Addr) string {
	if dst.Is4() {
		return "0.0.0.0:0"
	}
	return "[::]:0"
}

// masqueIP handles CONNECT-IP. The protocol half is implemented here —
// target parsing, the policy check, the address and route capsules a
// client needs before it can send anything — and the forwarding half
// needs a tunnel device, because a userspace process cannot put an
// arbitrary IP packet on the wire without one.
func (f *forwardServer) masqueIP(w http.ResponseWriter, r *http.Request, p *forwardPolicy, ip netip.Addr, user string, start time.Time) {
	target, err := masque.ParseIPTarget(r.URL.Path)
	if err != nil {
		f.deny(w, r, ip, user, http.StatusBadRequest, "masque_target", start)
		return
	}
	dev := f.masqueDevice()
	if dev == nil {
		// Said plainly rather than hidden behind a generic failure: the
		// request is understood and refused for a reason an operator
		// can act on.
		f.masque.refused.Add(1)
		f.deny(w, r, ip, user, http.StatusNotImplemented, "masque_no_device", start)
		return
	}
	defer func() { _ = dev.Close() }()
	if target.Target != "*" {
		if _, reason := f.check(r.Context(), p, target.Target, 0); reason != "" && reason != "port" {
			f.deny(w, r, ip, user, http.StatusForbidden, reason, start)
			return
		}
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	f.masque.ipTotal.Add(1)
	f.host.Counters().MasqueIP.Add(1)
	f.host.Counters().MasqueOpen.Add(1)
	defer f.host.Counters().MasqueOpen.Add(-1)

	// The client needs a source address and the ranges it may reach
	// before it can send a packet, so both capsules go out first.
	if err := masque.WriteCapsule(w, masque.AddressAssign(dev.Assign())); err != nil {
		return
	}
	if err := masque.WriteCapsule(w, masque.RouteAdvertisement(dev.Routes(), target.Protocol)); err != nil {
		return
	}
	_ = rc.Flush()

	var in, out int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			if err := masque.WriteCapsule(w, masque.Datagram(0, buf[:n])); err != nil {
				return
			}
			_ = rc.Flush()
			out += int64(n)
		}
	}()
	for {
		c, err := masque.ReadCapsule(r.Body)
		if err != nil {
			break
		}
		switch c.Type {
		case masque.CapsuleDatagram:
			ctx, payload, err := masque.SplitDatagram(c)
			if err != nil || ctx != 0 || len(payload) < 20 {
				f.host.Counters().MasqueDropped.Add(1)
				f.host.Counters().Refuse("forward", "masque_context")
				continue
			}
			if !dev.Allowed(payload) {
				// A packet whose source is not the address this client
				// was assigned, or whose destination is outside the
				// advertised routes, is spoofing.
				f.host.Counters().MasqueDropped.Add(1)
				f.host.Counters().Refuse("forward", "masque_spoofed")
				continue
			}
			if _, err := dev.Write(payload); err != nil {
				break
			}
			in += int64(len(payload))
		case masque.CapsuleAddressRequest:
			// A client asking for a particular address: this
			// implementation assigns, it does not take requests, so the
			// assignment is repeated rather than ignored.
			if err := masque.WriteCapsule(w, masque.AddressAssign(dev.Assign())); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
	_ = dev.Close()
	<-done
	f.logMasque(ip, user, "connect-ip", target.Target+"/"+ipProtoName(target.Protocol), in, out, start, "")
}

func ipProtoName(n int) string {
	if n < 0 {
		return "*"
	}
	return strconv.Itoa(n)
}

func (f *forwardServer) logMasque(ip netip.Addr, user, proto, dest string, in, out int64, start time.Time, reason string) {
	attrs := []any{"listener", f.name, "protocol", proto, "client_ip", ip.String(), "user", user,
		"destination", dest, "bytes_in", in, "bytes_out", out,
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	f.host.Logs().Access.Info("forward", attrs...)
}

var errNoTunnel = errors.New("connect-ip needs a tunnel device; see forward.masque.ip_device")

// tunnel is what CONNECT-IP forwards through.
type tunnel interface {
	io.ReadWriteCloser
	// Assign is the address the client is told to use as its source.
	Assign() []netip.Prefix
	// Routes are the ranges it may send to.
	Routes() []netip.Prefix
	// Allowed reports whether a packet's source and destination match
	// what was assigned and advertised.
	Allowed(packet []byte) bool
}

// masqueDevice opens the configured tunnel, or nil when there is none.
func (f *forwardServer) masqueDevice() tunnel {
	p := f.policy.Load()
	if p == nil || p.cfg.Masque == nil || p.cfg.Masque.IPDevice == "" {
		return nil
	}
	t, err := openTunnel(p.cfg.Masque.IPDevice, p.cfg.Masque.IPAssign, p.cfg.Masque.IPRoutes)
	if err != nil {
		f.host.Logs().Error.Warn("connect-ip tunnel unavailable", "listener", f.name,
			"device", p.cfg.Masque.IPDevice, "err", err.Error())
		return nil
	}
	return t
}

func (f *forwardServer) masqueDeviceName() string {
	p := f.policy.Load()
	if p == nil || p.cfg.Masque == nil {
		return ""
	}
	return p.cfg.Masque.IPDevice
}
