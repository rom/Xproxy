//go:build linux

package forward

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The tunnel device CONNECT-IP forwards through.
//
// A userspace process cannot put an arbitrary IP packet on the wire.
// Raw sockets need CAP_NET_RAW, do not receive the replies a session
// needs, and would let a bug in this proxy forge any packet on the
// network. A tun device is the honest way: the kernel routes for us,
// the packets are confined to whatever the operator's firewall and
// routing table allow for that interface, and the proxy needs no
// privilege beyond opening a device that already exists.
//
// So the device is not created here. An operator creates it, addresses
// it, routes it and firewalls it — `ip tuntap add mode tun xproxy0`
// and the rest — and grants the proxy access to /dev/net/tun. That
// division is deliberate: the network policy for a VPN belongs to the
// host's configuration, not to a proxy's YAML.

const tunPath = "/dev/net/tun"

// tunDevice is an open tun interface.
type tunDevice struct {
	f      *os.File
	name   string
	assign []netip.Prefix
	routes []netip.Prefix
	mu     sync.Mutex
	closed bool
}

// openTunnel attaches to an existing tun device by name.
func openTunnel(name string, assign, routes []string) (tunnel, error) {
	if name == "" {
		return nil, errNoTunnel
	}
	f, err := os.OpenFile(tunPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w (the device must exist and this process must be allowed to open it)", tunPath, err)
	}
	// TUNSETIFF attaches to the named device. IFF_TUN is IP packets
	// without an Ethernet header, IFF_NO_PI drops the 4 byte packet
	// information header, so what is read is the IP packet itself.
	var req struct {
		name  [unix.IFNAMSIZ]byte
		flags uint16
		_     [22]byte
	}
	if len(name) >= unix.IFNAMSIZ {
		_ = f.Close()
		return nil, fmt.Errorf("device name %q is too long", name)
	}
	copy(req.name[:], name)
	req.flags = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req))); errno != 0 { //nolint:gosec // the ioctl's own argument
		_ = f.Close()
		return nil, fmt.Errorf("attach to %s: %w (create it first: ip tuntap add mode tun %s)", name, errno, name)
	}
	d := &tunDevice{f: f, name: name}
	for _, a := range assign {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("ip_assign %q: %w", a, err)
		}
		d.assign = append(d.assign, p)
	}
	for _, rt := range routes {
		p, err := netip.ParsePrefix(rt)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("ip_routes %q: %w", rt, err)
		}
		d.routes = append(d.routes, p)
	}
	if len(d.assign) == 0 || len(d.routes) == 0 {
		_ = f.Close()
		return nil, errors.New("connect-ip needs ip_assign and ip_routes: a client cannot send a packet until it has been told a source address and where it may send")
	}
	return d, nil
}

func (d *tunDevice) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *tunDevice) Write(p []byte) (int, error) { return d.f.Write(p) }

func (d *tunDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.f.Close()
}

func (d *tunDevice) Assign() []netip.Prefix { return d.assign }
func (d *tunDevice) Routes() []netip.Prefix { return d.routes }

func (d *tunDevice) Allowed(packet []byte) bool { return packetAllowed(packet, d.assign, d.routes) }
