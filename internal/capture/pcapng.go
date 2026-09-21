// Package capture writes the exchanges the proxy handled as a pcapng
// file that Wireshark, tshark and every other pcap tool can read.
//
// What this is, and what it is not. The proxy terminates TLS, so a
// capture taken on the wire in front of it is ciphertext and a capture
// taken behind it has lost the client. What this package writes is the
// proxy's own view: the request as it parsed it and the response as it
// wrote it, synthesised into a TCP conversation so that a pcap tool
// dissects it as HTTP. It is not a byte-for-byte record of the wire —
// header order and framing are the proxy's, not the client's — and it
// is exactly the thing a wire capture of a TLS listener cannot give
// you. Each packet carries the request id as a pcapng comment, so a
// frame in Wireshark and a line in the access log name each other.
package capture

import (
	"encoding/binary"
	"io"
	"time"
)

// Block types (pcapng, RFC 9518 section 4).
const (
	blockSectionHeader = 0x0A0D0D0A
	blockInterface     = 0x00000001
	blockEnhanced      = 0x00000006

	byteOrderMagic = 0x1A2B3C4D

	// linkTypeEthernet is what every dissector handles best; the frames
	// below carry synthetic addresses that say what they are.
	linkTypeEthernet = 1
)

// Option codes.
const (
	optEnd     = 0
	optComment = 1
	optIfName  = 2
	optIfTsRes = 9
	optShbApp  = 4
)

// writer emits pcapng blocks to an underlying writer. It is not safe
// for concurrent use; the sink above it serialises.
type writer struct {
	w       io.Writer
	written int64
}

func (p *writer) write(b []byte) error {
	n, err := p.w.Write(b)
	p.written += int64(n)
	return err
}

// pad returns the bytes needed to reach a 32-bit boundary.
func pad(n int) []byte {
	switch n % 4 {
	case 0:
		return nil
	case 1:
		return []byte{0, 0, 0}
	case 2:
		return []byte{0, 0}
	default:
		return []byte{0}
	}
}

// option appends one pcapng option; an empty value is skipped, because
// an option of length zero is legal but says nothing.
func option(dst []byte, code uint16, value []byte) []byte {
	if len(value) == 0 {
		return dst
	}
	dst = binary.LittleEndian.AppendUint16(dst, code)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(value))) //nolint:gosec // bounded by the caller
	dst = append(dst, value...)
	return append(dst, pad(len(value))...)
}

// block frames a body as a pcapng block: type, total length, body,
// padding, and the total length again so a reader can walk backwards.
func (p *writer) block(kind uint32, body []byte) error {
	total := 12 + len(body) + len(pad(len(body)))
	out := make([]byte, 0, total)
	out = binary.LittleEndian.AppendUint32(out, kind)
	out = binary.LittleEndian.AppendUint32(out, uint32(total)) //nolint:gosec // bounded by the caller
	out = append(out, body...)
	out = append(out, pad(len(body))...)
	out = binary.LittleEndian.AppendUint32(out, uint32(total)) //nolint:gosec // same value
	return p.write(out)
}

// header writes the section header and one interface description. Every
// file begins with exactly this, so a rotated file is a whole file
// rather than a fragment that needs the previous one to be read.
func (p *writer) header(app, iface string, snapLen uint32) error {
	body := make([]byte, 0, 64)
	body = binary.LittleEndian.AppendUint32(body, byteOrderMagic)
	body = binary.LittleEndian.AppendUint16(body, 1) // major
	body = binary.LittleEndian.AppendUint16(body, 0) // minor
	// Section length unknown: this file is written as it goes and its
	// length is not known until it is closed.
	body = binary.LittleEndian.AppendUint64(body, ^uint64(0))
	body = option(body, optShbApp, []byte(app))
	body = binary.LittleEndian.AppendUint16(body, optEnd)
	body = binary.LittleEndian.AppendUint16(body, 0)
	if err := p.block(blockSectionHeader, body); err != nil {
		return err
	}

	idb := make([]byte, 0, 32)
	idb = binary.LittleEndian.AppendUint16(idb, linkTypeEthernet)
	idb = binary.LittleEndian.AppendUint16(idb, 0) // reserved
	idb = binary.LittleEndian.AppendUint32(idb, snapLen)
	idb = option(idb, optIfName, []byte(iface))
	// Microsecond timestamps, which is what the packets below carry.
	idb = option(idb, optIfTsRes, []byte{6})
	idb = binary.LittleEndian.AppendUint16(idb, optEnd)
	idb = binary.LittleEndian.AppendUint16(idb, 0)
	return p.block(blockInterface, idb)
}

// packet writes one enhanced packet block. origLen is what was on the
// wire before the snap length truncated it, so a reader can see that a
// frame was cut rather than believing the short one.
func (p *writer) packet(t time.Time, frame []byte, origLen int, comment string) error {
	us := uint64(t.UnixMicro()) //nolint:gosec // times before 1970 are not produced here
	body := make([]byte, 0, 32+len(frame)+len(comment))
	body = binary.LittleEndian.AppendUint32(body, 0) // interface 0
	body = binary.LittleEndian.AppendUint32(body, uint32(us>>32))
	body = binary.LittleEndian.AppendUint32(body, uint32(us))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(frame)))               //nolint:gosec // bounded by snapLen
	body = binary.LittleEndian.AppendUint32(body, uint32(max(origLen, len(frame)))) //nolint:gosec // bounded by the caller
	body = append(body, frame...)
	body = append(body, pad(len(frame))...)
	body = option(body, optComment, []byte(comment))
	body = binary.LittleEndian.AppendUint16(body, optEnd)
	body = binary.LittleEndian.AppendUint16(body, 0)
	return p.block(blockEnhanced, body)
}
