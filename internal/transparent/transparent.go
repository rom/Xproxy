// Package transparent holds the two socket tricks an interception
// deployment needs, and the checks that keep them from becoming a hole.
//
// Both are Linux only, and both need a capability the proxy does not
// otherwise want: CAP_NET_ADMIN (or CAP_NET_RAW) for IP_TRANSPARENT.
// They are off by default and a listener has to ask.
//
// # The original destination
//
// A transparently intercepted connection was not addressed to the proxy.
// The client dialled some service and a routing rule put the packets on
// this socket instead, so "which upstream" is not a configuration
// question: the answer is on the socket.
//
//   - With TPROXY the socket keeps the original destination as its own
//     local address, so the answer is LocalAddr.
//   - With iptables REDIRECT the kernel rewrote the destination, and the
//     original is readable with getsockopt SO_ORIGINAL_DST.
//
// Reading REDIRECT's first and falling back to LocalAddr covers both
// without asking the operator which one they used -- which they would
// then have to keep in step with the firewall.
//
// # The client's source address
//
// An upstream that must see the client's own address, with no PROXY
// protocol header to read, needs the proxy to dial *as* the client:
// IP_TRANSPARENT on the outgoing socket and a bind to the client's
// address. The return traffic then has to be routed back to the proxy,
// which is the firewall's business and not this package's -- but the
// socket half is here.
//
// # The check that matters
//
// A listener that takes its destination from the socket will dial
// whatever the socket says, and a misconfigured firewall rule can make
// that the proxy's own address. The connection then comes back to the
// same listener, which dials it again: a loop that consumes descriptors
// until the process dies, from one client packet. Nothing else in the
// proxy protects against it, because nothing else has a destination it
// did not choose. Loop is the check, and it runs before every dial.
package transparent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ErrNoOriginalDestination means the socket carries no original
// destination: it was not intercepted, or the interception was not one
// of the two kinds this package reads.
var ErrNoOriginalDestination = errors.New("no original destination on this socket")

// ErrUnsupported means this build has no transparent proxying: the
// socket options are Linux's.
var ErrUnsupported = errors.New("transparent proxying needs Linux (IP_TRANSPARENT and SO_ORIGINAL_DST)")

// ErrLoop means a destination is one of this proxy's own listening
// addresses, so dialling it would send the connection back to itself.
var ErrLoop = errors.New("the destination is this proxy's own address")

// Destination reads the address a transparently intercepted connection
// was originally addressed to.
func Destination(c net.Conn) (netip.AddrPort, error) {
	// originalDST reports ErrNoOriginalDestination and nothing else -- on
	// Linux from every path, and on a platform without the socket options
	// unconditionally -- so there is no third case to carry here.
	if ap, err := originalDST(c); err == nil {
		return ap, nil
	}
	// TPROXY: the socket's own local address is the original
	// destination, because the socket was bound to it non-locally.
	ta, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, ErrNoOriginalDestination
	}
	ap := ta.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, ErrNoOriginalDestination
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// Loop reports whether dialling dst would come back to one of this
// proxy's own listening addresses. A listener bound to a wildcard
// address matches the port on any address, because that is what the
// kernel will do with the connection.
func Loop(dst netip.AddrPort, own []netip.AddrPort) error {
	for _, o := range own {
		if o.Port() != dst.Port() {
			continue
		}
		if !o.Addr().IsValid() || o.Addr().IsUnspecified() || o.Addr() == dst.Addr() {
			return fmt.Errorf("%w (%s)", ErrLoop, dst)
		}
	}
	return nil
}

// Allowed reports whether a destination is inside the policy. An empty
// policy allows nothing: a listener that dials whatever a firewall hands
// it must say where that may be, or it is a relay to anywhere for
// anyone who can reach the port.
func Allowed(dst netip.AddrPort, allow []netip.Prefix, ports []int) bool {
	inRange := false
	for _, p := range allow {
		if p.Contains(dst.Addr()) {
			inRange = true
			break
		}
	}
	if !inRange {
		return false
	}
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p == int(dst.Port()) {
			return true
		}
	}
	return false
}
