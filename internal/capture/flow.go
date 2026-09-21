package capture

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// A flow is one synthesised TCP conversation: the handshake, the bytes
// each side sent, and the close. A dissector needs the handshake and
// consistent sequence numbers to reassemble the stream, so they are
// written even though the proxy never saw those packets as packets.
type flow struct {
	client, server netip.AddrPort
	// seq counters, one per direction, in the units TCP uses.
	cseq, sseq uint32
	mtu        int
	comment    string
	// v6 is decided once for the conversation. A client and a listener
	// of different families would otherwise produce frames whose
	// ethertype and address length disagree; mapping both into IPv6 is
	// how a dissector is told what this pairing is.
	v6 bool
}

// newFlow pairs the two endpoints and fixes the address family.
func newFlow(client, server netip.AddrPort, comment string) *flow {
	f := &flow{client: client, server: server, mtu: defaultMTU, comment: comment}
	f.v6 = native6(client.Addr()) || native6(server.Addr())
	return f
}

// native6 reports an address that is IPv6 and not a mapped IPv4 one.
func native6(a netip.Addr) bool { return a.Is6() && !a.Is4In6() }

// TCP flags.
const (
	tcpFIN = 1 << 0
	tcpSYN = 1 << 1
	tcpPSH = 1 << 3
	tcpACK = 1 << 4
)

// synthetic MAC addresses. The locally administered bit is set and the
// rest spells the direction, so anyone reading the frame sees at once
// that these are not real interfaces.
var (
	macClient = [6]byte{0x02, 'c', 'l', 'n', 't', 0x01}
	macServer = [6]byte{0x02, 's', 'r', 'v', 'r', 0x01}
)

// defaultMTU is how much payload one synthesised segment carries. It is
// the usual Ethernet MSS, so a body arrives as the run of segments a
// reader expects rather than one impossible jumbo frame.
const defaultMTU = 1460

// open writes the three-way handshake.
func (f *flow) open(p *writer, t time.Time) error {
	if err := f.segment(p, t, true, tcpSYN, nil); err != nil {
		return err
	}
	if err := f.segment(p, t, false, tcpSYN|tcpACK, nil); err != nil {
		return err
	}
	return f.segment(p, t, true, tcpACK, nil)
}

// send writes payload as one or more segments from one side, splitting
// at the MTU. An empty payload writes nothing: a direction that said
// nothing should not appear to have sent an empty segment.
func (f *flow) send(p *writer, t time.Time, fromClient bool, payload []byte) error {
	mtu := f.mtu
	if mtu <= 0 {
		mtu = defaultMTU
	}
	for len(payload) > 0 {
		n := min(len(payload), mtu)
		if err := f.segment(p, t, fromClient, tcpPSH|tcpACK, payload[:n]); err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

// close writes the two-sided shutdown, so a dissector sees a complete
// conversation rather than one it is still waiting on.
func (f *flow) close(p *writer, t time.Time) error {
	if err := f.segment(p, t, true, tcpFIN|tcpACK, nil); err != nil {
		return err
	}
	if err := f.segment(p, t, false, tcpFIN|tcpACK, nil); err != nil {
		return err
	}
	return f.segment(p, t, true, tcpACK, nil)
}

// segment builds one Ethernet frame carrying IP and TCP and writes it.
func (f *flow) segment(p *writer, t time.Time, fromClient bool, flags uint8, payload []byte) error {
	src, dst := f.client, f.server
	srcMAC, dstMAC := macClient, macServer
	seq, ack := &f.cseq, &f.sseq
	if !fromClient {
		src, dst = f.server, f.client
		srcMAC, dstMAC = macServer, macClient
		seq, ack = &f.sseq, &f.cseq
	}

	frame := make([]byte, 0, 14+40+20+len(payload))
	frame = append(frame, dstMAC[:]...)
	frame = append(frame, srcMAC[:]...)

	tcpLen := 20 + len(payload)
	if f.v6 {
		frame = binary.BigEndian.AppendUint16(frame, 0x86DD)
		frame = appendIPv6(frame, src.Addr(), dst.Addr(), tcpLen)
	} else {
		frame = binary.BigEndian.AppendUint16(frame, 0x0800)
		frame = appendIPv4(frame, src.Addr(), dst.Addr(), tcpLen)
	}
	tcp := appendTCP(nil, src.Port(), dst.Port(), *seq, *ack, flags, payload)
	sum := tcpChecksum(src.Addr(), dst.Addr(), tcp, f.v6)
	binary.BigEndian.PutUint16(tcp[16:18], sum)
	frame = append(frame, tcp...)

	// SYN and FIN each consume one sequence number, as they do on a real
	// connection; without that a dissector reports every later segment
	// as out of order.
	adv := uint32(len(payload)) //nolint:gosec // bounded by the MTU
	if flags&(tcpSYN|tcpFIN) != 0 {
		adv++
	}
	*seq += adv
	return p.packet(t, frame, len(frame), f.comment)
}

func appendIPv4(dst []byte, src, dt netip.Addr, payloadLen int) []byte {
	start := len(dst)
	dst = append(dst, 0x45, 0x00)                                   // version, IHL, DSCP
	dst = binary.BigEndian.AppendUint16(dst, uint16(20+payloadLen)) //nolint:gosec // bounded
	dst = binary.BigEndian.AppendUint16(dst, 0)                     // id
	dst = binary.BigEndian.AppendUint16(dst, 0x4000)                // don't fragment
	dst = append(dst, 64, 6)                                        // TTL, TCP
	dst = binary.BigEndian.AppendUint16(dst, 0)                     // checksum, below
	s4, d4 := src.Unmap().As4(), dt.Unmap().As4()
	dst = append(dst, s4[:]...)
	dst = append(dst, d4[:]...)
	binary.BigEndian.PutUint16(dst[start+10:start+12], checksum(dst[start:start+20]))
	return dst
}

func appendIPv6(dst []byte, src, dt netip.Addr, payloadLen int) []byte {
	dst = binary.BigEndian.AppendUint32(dst, 6<<28)              // version, no class or label
	dst = binary.BigEndian.AppendUint16(dst, uint16(payloadLen)) //nolint:gosec // bounded
	dst = append(dst, 6, 64)                                     // next header TCP, hop limit
	s16, d16 := src.As16(), dt.As16()
	dst = append(dst, s16[:]...)
	dst = append(dst, d16[:]...)
	return dst
}

func appendTCP(dst []byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, srcPort)
	dst = binary.BigEndian.AppendUint16(dst, dstPort)
	dst = binary.BigEndian.AppendUint32(dst, seq)
	dst = binary.BigEndian.AppendUint32(dst, ack)
	dst = append(dst, 5<<4, flags)                  // data offset 5 words, flags
	dst = binary.BigEndian.AppendUint16(dst, 65535) // window
	dst = binary.BigEndian.AppendUint16(dst, 0)     // checksum, filled by the caller
	dst = binary.BigEndian.AppendUint16(dst, 0)     // urgent pointer
	return append(dst, payload...)
}

// checksum is the ones' complement sum RFC 1071 describes.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	// The fold above leaves the value in the low 16 bits, which is what
	// makes the conversion exact rather than a truncation.
	return ^uint16(sum & 0xffff) //nolint:gosec // masked to 16 bits
}

// tcpChecksum covers the pseudo-header and the segment, which is what
// makes a dissector accept the segment rather than flag it.
func tcpChecksum(src, dst netip.Addr, tcp []byte, v6 bool) uint16 {
	var pseudo []byte
	if v6 {
		s, d := src.As16(), dst.As16()
		pseudo = append(pseudo, s[:]...)
		pseudo = append(pseudo, d[:]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(tcp))) //nolint:gosec // bounded
		pseudo = append(pseudo, 0, 0, 0, 6)
	} else {
		s, d := src.Unmap().As4(), dst.Unmap().As4()
		pseudo = append(pseudo, s[:]...)
		pseudo = append(pseudo, d[:]...)
		pseudo = append(pseudo, 0, 6)
		pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(tcp))) //nolint:gosec // bounded
	}
	return checksum(append(pseudo, tcp...))
}
