package netutil

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// ProxyHeader is a parsed PROXY protocol header (HAProxy, versions 1
// and 2). Local reports a v2 LOCAL command or a v1 UNKNOWN family: the
// connection carries no client address and the peer's is kept.
type ProxyHeader struct {
	Src, Dst netip.AddrPort
	Local    bool
	Version  int
}

var (
	ErrNoProxyHeader  = errors.New("no PROXY protocol header")
	ErrBadProxyHeader = errors.New("malformed PROXY protocol header")

	proxyV2Sig = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
)

const maxProxyV1Line = 108 // the specification's bound

// ReadProxyHeader consumes a PROXY protocol header from br. It peeks
// first, so a connection without one returns ErrNoProxyHeader with
// nothing consumed.
func ReadProxyHeader(br *bufio.Reader) (ProxyHeader, error) {
	head, err := br.Peek(6)
	if err != nil {
		return ProxyHeader{}, ErrNoProxyHeader
	}
	switch {
	case string(head) == "PROXY ":
		return readProxyV1(br)
	case head[0] == 0x0d && head[1] == 0x0a:
		sig, err := br.Peek(12)
		if err != nil || string(sig) != string(proxyV2Sig) {
			return ProxyHeader{}, ErrNoProxyHeader
		}
		return readProxyV2(br)
	}
	return ProxyHeader{}, ErrNoProxyHeader
}

func readProxyV1(br *bufio.Reader) (ProxyHeader, error) {
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > maxProxyV1Line || len(line) < 2 || line[len(line)-2] != '\r' {
		return ProxyHeader{}, ErrBadProxyHeader
	}
	fields := strings.Split(strings.TrimSuffix(string(line), "\r\n"), " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return ProxyHeader{}, ErrBadProxyHeader
	}
	h := ProxyHeader{Version: 1}
	switch fields[1] {
	case "UNKNOWN":
		h.Local = true
		return h, nil
	case "TCP4", "TCP6":
	default:
		return ProxyHeader{}, ErrBadProxyHeader
	}
	if len(fields) != 6 {
		return ProxyHeader{}, ErrBadProxyHeader
	}
	src, err1 := netip.ParseAddr(fields[2])
	dst, err2 := netip.ParseAddr(fields[3])
	sp, err3 := strconv.ParseUint(fields[4], 10, 16)
	dp, err4 := strconv.ParseUint(fields[5], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || (fields[1] == "TCP4") != src.Is4() || src.Is4() != dst.Is4() {
		return ProxyHeader{}, ErrBadProxyHeader
	}
	h.Src = netip.AddrPortFrom(src.Unmap(), uint16(sp))
	h.Dst = netip.AddrPortFrom(dst.Unmap(), uint16(dp))
	return h, nil
}

func readProxyV2(br *bufio.Reader) (ProxyHeader, error) {
	var fixed [16]byte
	if err := readFull(br, fixed[:]); err != nil {
		return ProxyHeader{}, ErrBadProxyHeader
	}
	if fixed[12]>>4 != 2 {
		return ProxyHeader{}, ErrBadProxyHeader
	}
	cmd := fixed[12] & 0x0f
	fam := fixed[13] >> 4
	length := int(binary.BigEndian.Uint16(fixed[14:16]))
	if length > 4096 {
		return ProxyHeader{}, ErrBadProxyHeader
	}
	body := make([]byte, length)
	if err := readFull(br, body); err != nil {
		return ProxyHeader{}, ErrBadProxyHeader
	}
	h := ProxyHeader{Version: 2}
	switch cmd {
	case 0: // LOCAL
		h.Local = true
		return h, nil
	case 1: // PROXY
	default:
		return ProxyHeader{}, ErrBadProxyHeader
	}
	switch fam {
	case 1: // AF_INET
		if length < 12 {
			return ProxyHeader{}, ErrBadProxyHeader
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[0:4])), binary.BigEndian.Uint16(body[8:10]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[4:8])), binary.BigEndian.Uint16(body[10:12]))
	case 2: // AF_INET6
		if length < 36 {
			return ProxyHeader{}, ErrBadProxyHeader
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[0:16])).Unmap(), binary.BigEndian.Uint16(body[32:34]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[16:32])).Unmap(), binary.BigEndian.Uint16(body[34:36]))
	case 0: // AF_UNSPEC with PROXY: no usable address
		h.Local = true
	default: // AF_UNIX and others: not a network client
		h.Local = true
	}
	return h, nil
}

func readFull(br *bufio.Reader, b []byte) error {
	n := 0
	for n < len(b) {
		m, err := br.Read(b[n:])
		n += m
		if err != nil {
			return err
		}
	}
	return nil
}
