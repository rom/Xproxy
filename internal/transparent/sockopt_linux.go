package transparent

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// originalDST reads the destination iptables REDIRECT rewrote.
//
// The option answers with a sockaddr_in, which is sixteen bytes -- the
// same size as the IPv6Mreq x/sys/unix can read -- so that struct is the
// buffer. It is the standard way to read this option from Go and it is
// exact: what comes back is family, port and address at fixed offsets.
//
// Only IPv4. ip6tables has a REDIRECT of its own, but reading its option
// needs a 28-byte buffer that x/sys/unix has no typed getter for, and
// IPv6 interception is done with TPROXY in practice -- where the
// destination is the socket's own local address and no option is read at
// all. So an IPv6 REDIRECT falls through to that path, which answers the
// listener's address: the loop check then refuses it rather than
// relaying somewhere wrong, which is the safe way to be incomplete.
func originalDST(c net.Conn) (netip.AddrPort, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return netip.AddrPort{}, ErrNoOriginalDestination
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, ErrNoOriginalDestination
	}
	var ap netip.AddrPort
	serr := ErrNoOriginalDestination
	cerr := raw.Control(func(fd uintptr) {
		a4, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
		if err != nil {
			return
		}
		if ap = ip4FromSockaddr(a4.Multiaddr); ap.IsValid() {
			serr = nil
		}
	})
	if cerr != nil {
		return netip.AddrPort{}, ErrNoOriginalDestination
	}
	return ap, serr
}

// ip4FromSockaddr reads a sockaddr_in: family (2 bytes, host order),
// port (2, network order), address (4).
func ip4FromSockaddr(b [16]byte) netip.AddrPort {
	if uint16(b[1])<<8|uint16(b[0]) != unix.AF_INET {
		return netip.AddrPort{}
	}
	port := uint16(b[2])<<8 | uint16(b[3])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port)
}

// Dialer returns a dialler that opens the connection as the client:
// IP_TRANSPARENT on the socket and a bind to the client's address with
// an ephemeral port, so the upstream sees the client rather than the
// proxy. IP_FREEBIND goes with it, because the address being bound is
// not one of this machine's.
//
// The return traffic must be routed back to this host, which is the
// firewall's business. Without that the upstream answers the client
// directly and the connection never completes -- a failure that looks
// like a dead upstream, which is why the listener warns at load rather
// than leaving it to be discovered.
func Dialer(base *net.Dialer, client netip.Addr) *net.Dialer {
	d := *base
	d.LocalAddr = &net.TCPAddr{IP: client.AsSlice()}
	d.Control = func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			level, opt := unix.SOL_IP, unix.IP_TRANSPARENT
			free := unix.IP_FREEBIND
			if client.Is6() {
				level, opt, free = unix.SOL_IPV6, unix.IPV6_TRANSPARENT, unix.IPV6_FREEBIND
			}
			if serr = unix.SetsockoptInt(int(fd), level, opt, 1); serr != nil {
				return
			}
			serr = unix.SetsockoptInt(int(fd), level, free, 1)
		}); err != nil {
			return err
		}
		return serr
	}
	return &d
}

// Available reports whether this build can set IP_TRANSPARENT at all. It
// says nothing about the capability, which only a real socket can test.
func Available() bool { return true }

// Check reports whether this process may set IP_TRANSPARENT, so a
// listener can refuse at load rather than on the first connection. It
// makes a socket, sets the option and closes it again: nothing is bound
// and nothing is connected, and the error is the kernel's own, which
// says whether the capability is missing rather than guessing.
func Check() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
}
