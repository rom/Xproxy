package masque

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Request targets.
//
// RFC 9298 and RFC 9484 both address the destination through a URI
// template rather than the authority, because the authority names the
// proxy. The templates the RFCs give as the default, and the ones this
// implements, are:
//
//	https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/
//	https://proxy.example/.well-known/masque/ip/{target}/{ipproto}/
//
// The values are percent-decoded path segments, so a host with a colon
// (an IPv6 literal) arrives encoded and a name cannot smuggle a slash.

// UDPPrefix and IPPrefix are the well known path prefixes.
const (
	UDPPrefix = "/.well-known/masque/udp/"
	IPPrefix  = "/.well-known/masque/ip/"
)

// UDPTarget is a parsed CONNECT-UDP request target.
type UDPTarget struct {
	Host string
	Port int
}

// ParseUDPTarget reads the target out of a request path.
func ParseUDPTarget(path string) (UDPTarget, error) {
	rest, ok := strings.CutPrefix(path, UDPPrefix)
	if !ok {
		return UDPTarget{}, errors.New("not a connect-udp target")
	}
	rest = strings.TrimSuffix(rest, "/")
	host, portStr, ok := strings.Cut(rest, "/")
	if !ok || host == "" || portStr == "" {
		return UDPTarget{}, errors.New("target must be /{host}/{port}/")
	}
	if strings.Contains(portStr, "/") {
		return UDPTarget{}, errors.New("target has more segments than {host}/{port}")
	}
	h, err := url.PathUnescape(host)
	if err != nil || h == "" {
		return UDPTarget{}, errors.New("target host is not a valid path segment")
	}
	// A host that arrives with control characters, a slash or a space
	// is not a host; refusing here keeps the policy check and the dial
	// looking at the same string.
	for _, r := range h {
		if r < 0x21 || r > 0x7e || r == '/' || r == '\\' {
			return UDPTarget{}, fmt.Errorf("target host %q has a character a host cannot have", h)
		}
	}
	h = strings.Trim(h, "[]")
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return UDPTarget{}, fmt.Errorf("target port %q is not a port", portStr)
	}
	return UDPTarget{Host: h, Port: p}, nil
}

// String renders the target as host:port.
func (t UDPTarget) String() string {
	if a, err := netip.ParseAddr(t.Host); err == nil && a.Is6() {
		return "[" + t.Host + "]:" + strconv.Itoa(t.Port)
	}
	return t.Host + ":" + strconv.Itoa(t.Port)
}

// IPTarget is a parsed CONNECT-IP request target. Both fields may be
// the wildcard "*", which RFC 9484 uses to mean the client will say
// where it is going in the packets themselves.
type IPTarget struct {
	// Target is a host, an address, or "*".
	Target string
	// Protocol is an IP protocol number, or -1 for "*".
	Protocol int
}

// ParseIPTarget reads a CONNECT-IP target.
func ParseIPTarget(path string) (IPTarget, error) {
	rest, ok := strings.CutPrefix(path, IPPrefix)
	if !ok {
		return IPTarget{}, errors.New("not a connect-ip target")
	}
	rest = strings.TrimSuffix(rest, "/")
	target, proto, ok := strings.Cut(rest, "/")
	if !ok || target == "" || proto == "" {
		return IPTarget{}, errors.New("target must be /{target}/{ipproto}/")
	}
	if strings.Contains(proto, "/") {
		return IPTarget{}, errors.New("target has more segments than {target}/{ipproto}")
	}
	t, err := url.PathUnescape(target)
	if err != nil || t == "" {
		return IPTarget{}, errors.New("target is not a valid path segment")
	}
	out := IPTarget{Target: strings.Trim(t, "[]"), Protocol: -1}
	if proto != "*" {
		n, err := strconv.Atoi(proto)
		if err != nil || n < 0 || n > 255 {
			return IPTarget{}, fmt.Errorf("ipproto %q is not a protocol number", proto)
		}
		out.Protocol = n
	}
	if out.Target != "*" {
		for _, r := range out.Target {
			if r < 0x21 || r > 0x7e || r == '/' || r == '\\' {
				return IPTarget{}, fmt.Errorf("target %q has a character a host cannot have", out.Target)
			}
		}
	}
	return out, nil
}

// AddressAssign builds an ADDRESS_ASSIGN capsule (RFC 9484 section
// 4.7.1): the addresses the proxy gives the client to use as a source.
func AddressAssign(prefixes []netip.Prefix) Capsule {
	v := make([]byte, 0, len(prefixes)*20)
	var id uint64
	for _, p := range prefixes {
		id++
		v = AppendVarint(v, id) // request id, echoing the order
		if p.Addr().Is4() {
			v = append(v, 4)
			a := p.Addr().As4()
			v = append(v, a[:]...)
		} else {
			v = append(v, 6)
			a := p.Addr().As16()
			v = append(v, a[:]...)
		}
		v = append(v, byte(p.Bits())) //nolint:gosec // a prefix length is 0..128
	}
	return Capsule{Type: CapsuleAddressAssign, Value: v}
}

// RouteAdvertisement builds a ROUTE_ADVERTISEMENT capsule (RFC 9484
// section 4.7.3): the ranges the client may send packets to. It is the
// destination policy expressed in the protocol's own terms, so a
// client knows what it may reach before it tries.
func RouteAdvertisement(routes []netip.Prefix, protocol int) Capsule {
	var v []byte
	for _, p := range routes {
		if p.Addr().Is4() {
			v = append(v, 4)
			start := p.Masked().Addr().As4()
			v = append(v, start[:]...)
			end := lastAddr4(p)
			v = append(v, end[:]...)
		} else {
			v = append(v, 6)
			start := p.Masked().Addr().As16()
			v = append(v, start[:]...)
			end := lastAddr16(p)
			v = append(v, end[:]...)
		}
		if protocol < 0 {
			v = append(v, 0)
		} else {
			v = append(v, byte(protocol)) //nolint:gosec // validated 0..255
		}
	}
	return Capsule{Type: CapsuleRouteAdvertisement, Value: v}
}

// lastAddr4 and lastAddr16 give the last address of a prefix, which is
// what a route range's end field holds.
func lastAddr4(p netip.Prefix) [4]byte {
	a := p.Masked().Addr().As4()
	bits := p.Bits()
	for i := range a {
		shift := max(0, min(8, bits-i*8))
		a[i] |= byte(0xff >> shift)
	}
	return a
}

func lastAddr16(p netip.Prefix) [16]byte {
	a := p.Masked().Addr().As16()
	bits := p.Bits()
	for i := range a {
		shift := max(0, min(8, bits-i*8))
		a[i] |= byte(0xff >> shift)
	}
	return a
}
