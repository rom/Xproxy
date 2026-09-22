package forward

import "net/netip"

// packetAllowed checks an IP packet from a CONNECT-IP client against
// the address it was assigned and the routes it was advertised. It is
// the anti-spoofing check: without it a client could put any source
// address it liked on the wire through the proxy's tunnel, which is
// the whole reason a VPN endpoint is a sensitive thing to run.
func packetAllowed(packet []byte, assign, routes []netip.Prefix) bool {
	src, dst, ok := packetAddrs(packet)
	if !ok {
		return false
	}
	inAssign := false
	for _, p := range assign {
		if p.Contains(src) {
			inAssign = true
			break
		}
	}
	if !inAssign {
		return false
	}
	for _, p := range routes {
		if p.Contains(dst) {
			return true
		}
	}
	return false
}

// packetAddrs reads the source and destination out of an IPv4 or IPv6
// header. Anything that is not one of those is not a packet this proxy
// forwards.
func packetAddrs(b []byte) (src, dst netip.Addr, ok bool) {
	if len(b) < 20 {
		return netip.Addr{}, netip.Addr{}, false
	}
	switch b[0] >> 4 {
	case 4:
		// The header length field is in 32 bit words and must cover at
		// least the fixed header.
		if int(b[0]&0x0f)*4 < 20 || len(b) < int(b[0]&0x0f)*4 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), true
	case 6:
		if len(b) < 40 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40])), true
	}
	return netip.Addr{}, netip.Addr{}, false
}
