package tcp

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/relay"
	"github.com/rom/xproxy/internal/transparent"
)

// A transparently intercepted connection: the client dialled some
// service, a routing rule put the packets on this listener, and the
// destination is on the socket rather than in the configuration.
//
// Three things have to hold before such a connection is relayed, and the
// order is deliberate -- each is cheaper than the one after it:
//
//  1. There is an original destination to read. Without one the
//     connection arrived by some other route and there is nothing to do
//     with it.
//  2. It is not one of this proxy's own addresses. A firewall rule that
//     sends a listener's own port to itself makes a loop that consumes
//     descriptors until the process dies, from one client packet. This
//     is the only place in the proxy with a destination it did not
//     choose, so it is the only place that needs the check.
//  3. It is inside allow_destinations. A listener that dials whatever
//     the firewall hands it is otherwise a relay to anywhere for anyone
//     who can reach the port.

// intercepted relays a connection whose destination comes from the
// socket.
func (t *server) intercepted(client net.Conn, ip netip.Addr, start time.Time, sni string, early []byte) {
	s := t.engine
	dst, err := transparent.Destination(client)
	if err != nil {
		s.Counters().TCPRejected.Add(1)
		t.finish(client, ip, start, sni, "", "", "no_original_destination", 0, 0)
		return
	}
	if err := transparent.Loop(dst, t.ownAddrs()); err != nil {
		// Counted as an error rather than a refusal: the client did
		// nothing wrong, the firewall rule is wrong, and an operator
		// looking for a misconfiguration should not have to read it out
		// of a deny log full of real refusals.
		s.Counters().TCPErrors.Add(1)
		s.Logs().Error.Warn("intercepted connection would loop back to this proxy",
			"listener", t.cfg.Name, "destination", dst.String())
		t.finish(client, ip, start, sni, "", dst.String(), "destination_loop", 0, 0)
		return
	}
	if !transparent.Allowed(dst, t.allowDst, t.cfg.TCP.DestinationPorts) {
		s.Counters().TCPRejected.Add(1)
		t.deny(ip, dst)
		t.finish(client, ip, start, sni, "", dst.String(), "destination_not_allowed", 0, 0)
		return
	}
	d := &net.Dialer{Timeout: t.cfg.TCP.ConnectTimeout.D()}
	if t.cfg.TCP.Transparent {
		d = transparent.Dialer(d, ip)
	}
	up, err := d.DialContext(context.Background(), "tcp", dst.String())
	if err != nil {
		s.Counters().TCPErrors.Add(1)
		s.Logs().Error.Warn("intercepted destination unreachable", "listener", t.cfg.Name,
			"destination", dst.String(), "err", err.Error())
		t.finish(client, ip, start, sni, "", dst.String(), "upstream_unavailable", 0, 0)
		return
	}
	if _, err := up.Write(early); err != nil {
		_ = up.Close()
		t.finish(client, ip, start, sni, "", dst.String(), "upstream_write", 0, 0)
		return
	}
	in, out, end := t.spliceScanned(client, up, ip, sni)
	s.Counters().TCPBytesIn.Add(uint64(in + int64(len(early)))) //nolint:gosec // non-negative
	s.Counters().TCPBytesOut.Add(uint64(out))                   //nolint:gosec // non-negative
	if end != "" {
		s.Counters().TCPBounded.Add(1)
	}
	t.finish(client, ip, start, sni, "", dst.String(), end, in+int64(len(early)), out)
}

// deny records a destination outside the policy. It is a security event
// and a ban observation: a client choosing where an intercepting proxy
// sends its traffic is exactly what the policy is there to stop.
func (t *server) deny(ip netip.Addr, dst netip.AddrPort) {
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "tcp_no_route",
		"listener", t.cfg.Name, "proto", "tcp", "client_ip", ip.String(),
		"destination", dst.String(), "detail", "destination_not_allowed")
	if bl := t.engine.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "tcp_no_route")
	}
}

// ownAddrs are the addresses this listener is bound to, for the loop
// check. Only this listener's: a connection intercepted onto this port
// comes back to this port.
func (t *server) ownAddrs() []netip.AddrPort {
	var out []netip.AddrPort
	if t.ln == nil {
		return out
	}
	if ta, ok := t.ln.Addr().(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		out = append(out, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	}
	return out
}

// relayLimits is the bounds an intercepted connection is relayed under,
// the same as any other on this listener.
func (t *server) relayLimits() relay.Limits {
	return relay.Limits{
		Idle:     t.cfg.TCP.IdleTimeout.D(),
		Lifetime: t.cfg.TCP.SessionTimeout.D(),
		BytesIn:  t.cfg.TCP.MaxBytesIn,
		BytesOut: t.cfg.TCP.MaxBytesOut,
	}
}
