package capture

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// A reader for what this package writes. The tests assert on the file a
// pcap tool would open, not on the calls that produced it: a capture
// that only this package can read is of no use to the operator it is
// written for.

type blockRec struct {
	kind uint32
	body []byte
}

// packetRec is one enhanced packet block, taken apart.
type packetRec struct {
	iface   uint32
	stamp   time.Time
	frame   []byte
	origLen uint32
	comment string
}

func readBlocks(t *testing.T, b []byte) []blockRec {
	t.Helper()
	var out []blockRec
	for len(b) > 0 {
		if len(b) < 12 {
			t.Fatalf("trailing %d bytes: not a block", len(b))
		}
		kind := binary.LittleEndian.Uint32(b[0:4])
		total := binary.LittleEndian.Uint32(b[4:8])
		if total%4 != 0 {
			t.Fatalf("block %#x length %d is not a multiple of 4", kind, total)
		}
		if int(total) > len(b) || total < 12 {
			t.Fatalf("block %#x length %d exceeds the %d bytes left", kind, total, len(b))
		}
		if tail := binary.LittleEndian.Uint32(b[total-4 : total]); tail != total {
			t.Fatalf("block %#x trailing length %d != %d", kind, tail, total)
		}
		out = append(out, blockRec{kind: kind, body: b[8 : total-4]})
		b = b[total:]
	}
	return out
}

// options walks the option list at the end of a block body.
func options(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	out := map[uint16][]byte{}
	for len(b) >= 4 {
		code := binary.LittleEndian.Uint16(b[0:2])
		n := int(binary.LittleEndian.Uint16(b[2:4]))
		if code == optEnd {
			return out
		}
		if 4+n > len(b) {
			t.Fatalf("option %d claims %d bytes, %d left", code, n, len(b)-4)
		}
		out[code] = b[4 : 4+n]
		b = b[4+n+len(pad(n)):]
	}
	return out
}

func readPackets(t *testing.T, blocks []blockRec) []packetRec {
	t.Helper()
	out := make([]packetRec, 0, len(blocks))
	for _, blk := range blocks {
		if blk.kind != blockEnhanced {
			continue
		}
		body := blk.body
		if len(body) < 20 {
			t.Fatal("short packet block")
		}
		capLen := binary.LittleEndian.Uint32(body[12:16])
		if 20+int(capLen) > len(body) {
			t.Fatalf("captured length %d exceeds the block", capLen)
		}
		high := uint64(binary.LittleEndian.Uint32(body[4:8]))
		low := uint64(binary.LittleEndian.Uint32(body[8:12]))
		p := packetRec{
			iface:   binary.LittleEndian.Uint32(body[0:4]),
			stamp:   time.UnixMicro(int64(high<<32 | low)).UTC(),
			frame:   body[20 : 20+capLen],
			origLen: binary.LittleEndian.Uint32(body[16:20]),
		}
		opts := options(t, body[20+int(capLen)+len(pad(int(capLen))):])
		p.comment = string(opts[optComment])
		out = append(out, p)
	}
	return out
}

// segment is one synthesised TCP segment as a dissector would see it.
type segment struct {
	v6                 bool
	src, dst           netip.AddrPort
	seq, ack           uint32
	flags              uint8
	payload            []byte
	ipSumOK, tcpSumOK  bool
	fromClient         bool
	totalLenConsistent bool
}

func parseFrame(t *testing.T, frame []byte, client netip.AddrPort) segment {
	t.Helper()
	if len(frame) < 14 {
		t.Fatal("frame shorter than an Ethernet header")
	}
	var s segment
	ether := binary.BigEndian.Uint16(frame[12:14])
	ip := frame[14:]
	var srcIP, dstIP netip.Addr
	var tcp []byte
	switch ether {
	case 0x0800:
		if len(ip) < 20 {
			t.Fatal("frame shorter than an IPv4 header")
		}
		if ip[0]>>4 != 4 {
			t.Fatalf("ethertype says IPv4, version nibble says %d", ip[0]>>4)
		}
		if ip[9] != 6 {
			t.Fatalf("protocol %d, want TCP", ip[9])
		}
		s.ipSumOK = checksum(ip[:20]) == 0
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		s.totalLenConsistent = total == len(ip)
		srcIP, _ = netip.AddrFromSlice(ip[12:16])
		dstIP, _ = netip.AddrFromSlice(ip[16:20])
		tcp = ip[20:total]
	case 0x86DD:
		s.v6 = true
		if len(ip) < 40 {
			t.Fatal("frame shorter than an IPv6 header")
		}
		if ip[0]>>4 != 6 {
			t.Fatalf("ethertype says IPv6, version nibble says %d", ip[0]>>4)
		}
		if ip[6] != 6 {
			t.Fatalf("next header %d, want TCP", ip[6])
		}
		s.ipSumOK = true // IPv6 has no header checksum
		payload := int(binary.BigEndian.Uint16(ip[4:6]))
		s.totalLenConsistent = payload == len(ip)-40
		srcIP, _ = netip.AddrFromSlice(ip[8:24])
		dstIP, _ = netip.AddrFromSlice(ip[24:40])
		tcp = ip[40 : 40+payload]
	default:
		t.Fatalf("ethertype %#04x is neither IPv4 nor IPv6", ether)
	}
	if len(tcp) < 20 {
		t.Fatal("TCP header truncated")
	}
	s.src = netip.AddrPortFrom(srcIP, binary.BigEndian.Uint16(tcp[0:2]))
	s.dst = netip.AddrPortFrom(dstIP, binary.BigEndian.Uint16(tcp[2:4]))
	s.seq = binary.BigEndian.Uint32(tcp[4:8])
	s.ack = binary.BigEndian.Uint32(tcp[8:12])
	s.flags = tcp[13]
	s.payload = tcp[int(tcp[12]>>4)*4:]
	// A segment whose checksum is right sums to zero over the same
	// pseudo-header, which is exactly what a dissector computes.
	s.tcpSumOK = tcpChecksum(srcIP, dstIP, tcp, s.v6) == 0
	s.fromClient = s.src == client
	return s
}

func segments(t *testing.T, pkts []packetRec, client netip.AddrPort) []segment {
	t.Helper()
	out := make([]segment, 0, len(pkts))
	for _, p := range pkts {
		if int(p.origLen) < len(p.frame) {
			t.Fatalf("original length %d below the captured %d", p.origLen, len(p.frame))
		}
		out = append(out, parseFrame(t, p.frame, client))
	}
	return out
}

func flagString(f uint8) string {
	s := ""
	for _, p := range []struct {
		bit  uint8
		name string
	}{{tcpFIN, "F"}, {tcpSYN, "S"}, {tcpPSH, "P"}, {tcpACK, "A"}} {
		if f&p.bit != 0 {
			s += p.name
		}
	}
	if s == "" {
		return "-"
	}
	return s
}

func TestPad(t *testing.T) {
	for n, want := range map[int]int{0: 0, 1: 3, 2: 2, 3: 1, 4: 0, 5: 3, 7: 1, 8: 0} {
		if got := len(pad(n)); got != want {
			t.Errorf("pad(%d) = %d bytes, want %d", n, got, want)
		}
		if (n+len(pad(n)))%4 != 0 {
			t.Errorf("pad(%d) does not reach a 32-bit boundary", n)
		}
	}
}

func TestOptionSkipsEmpty(t *testing.T) {
	if got := option(nil, optComment, nil); got != nil {
		t.Errorf("an empty option wrote %d bytes; an option that says nothing should not be there", len(got))
	}
	got := option(nil, optComment, []byte("hi"))
	if len(got)%4 != 0 {
		t.Errorf("option is %d bytes, not padded to a 32-bit boundary", len(got))
	}
}

func TestHeaderIsAWholeFile(t *testing.T) {
	var buf capBuffer
	p := &writer{w: &buf}
	if err := p.header(4096); err != nil {
		t.Fatal(err)
	}
	blocks := readBlocks(t, buf.b)
	if len(blocks) != 2 {
		t.Fatalf("header wrote %d blocks, want a section header and one interface", len(blocks))
	}
	if blocks[0].kind != blockSectionHeader || blocks[1].kind != blockInterface {
		t.Fatalf("blocks are %#x and %#x, want %#x and %#x", blocks[0].kind, blocks[1].kind, blockSectionHeader, blockInterface)
	}
	shb := blocks[0].body
	if magic := binary.LittleEndian.Uint32(shb[0:4]); magic != byteOrderMagic {
		t.Fatalf("byte order magic %#x, want %#x: the file would be read the wrong way round", magic, byteOrderMagic)
	}
	if v := binary.LittleEndian.Uint16(shb[4:6]); v != 1 {
		t.Errorf("major version %d, want 1", v)
	}
	if got := string(options(t, shb[16:])[optShbApp]); got != "xproxy" {
		t.Errorf("application option %q, want xproxy", got)
	}
	idb := blocks[1].body
	if lt := binary.LittleEndian.Uint16(idb[0:2]); lt != linkTypeEthernet {
		t.Errorf("link type %d, want Ethernet (%d)", lt, linkTypeEthernet)
	}
	if snap := binary.LittleEndian.Uint32(idb[4:8]); snap != 4096 {
		t.Errorf("snap length %d, want 4096", snap)
	}
	opts := options(t, idb[8:])
	if name := string(opts[optIfName]); name != "proxy-view" {
		t.Errorf("interface name %q, want proxy-view", name)
	}
	// Microseconds: the packet timestamps below are written in them, and
	// a mismatch shifts every frame by six orders of magnitude.
	if res := opts[optIfTsRes]; len(res) != 1 || res[0] != 6 {
		t.Errorf("timestamp resolution %v, want microseconds (6)", res)
	}
}

func TestPacketTimestampAndTruncation(t *testing.T) {
	var buf capBuffer
	p := &writer{w: &buf}
	when := time.Date(2026, 9, 21, 12, 0, 0, 123456000, time.UTC)
	if err := p.packet(when, []byte{1, 2, 3}, 900, "request_id=abc"); err != nil {
		t.Fatal(err)
	}
	pkts := readPackets(t, readBlocks(t, buf.b))
	if len(pkts) != 1 {
		t.Fatalf("wrote %d packets, want 1", len(pkts))
	}
	if !pkts[0].stamp.Equal(when) {
		t.Errorf("timestamp %s, want %s", pkts[0].stamp, when)
	}
	if pkts[0].origLen != 900 {
		t.Errorf("original length %d, want 900: a reader must see that the frame was cut", pkts[0].origLen)
	}
	if pkts[0].comment != "request_id=abc" {
		t.Errorf("comment %q, want request_id=abc", pkts[0].comment)
	}
	if pkts[0].iface != 0 {
		t.Errorf("interface %d, want the only one the file describes (0)", pkts[0].iface)
	}
}

// capBuffer is a writer that also counts, so the tests can assert on
// what the sink above believes it has written.
type capBuffer struct {
	b    []byte
	fail error
	n    int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if c.fail != nil {
		return 0, c.fail
	}
	c.b = append(c.b, p...)
	c.n++
	return len(p), nil
}

func TestWriterReportsFailure(t *testing.T) {
	buf := &capBuffer{fail: fmt.Errorf("disk full")}
	p := &writer{w: buf}
	if err := p.header(4096); err == nil {
		t.Fatal("a failed write reported success; the capture would look healthy while nothing was recorded")
	}
}
