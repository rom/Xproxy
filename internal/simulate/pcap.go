package simulate

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Reading back what `xproxyctl capture` wrote.
//
// The capture package writes pcapng: synthesised TCP conversations, one per
// exchange the proxy handled, each frame carrying a comment that names the
// request, its route, its status and the reason it was denied. That comment is
// why this is worth reading rather than only generating synthetic traffic --
// the file says what the proxy decided at the time, so a simulation over it can
// report "this got 200 on Tuesday and gets 403 under the change" rather than
// only "this gets 403".
//
// It is a reader for the files this project writes, not a general pcapng
// dissector. It understands the blocks the writer emits, the link type it
// chose, and IPv4 and IPv6 over Ethernet with TCP inside. Anything else is
// refused by name rather than guessed at: a simulation fed a file it
// half-understood would be answering about traffic nobody sent.

// pcapng block types.
const (
	blockSHB = 0x0A0D0D0A // section header
	blockIDB = 0x00000001 // interface description
	blockEPB = 0x00000006 // enhanced packet
)

// byteOrderMagic distinguishes a little-endian section header from a big-endian
// one.
const byteOrderMagic = 0x1A2B3C4D

// linkEthernet is the only link type this reads, which is the one the writer
// uses.
const linkEthernet = 1

// maxCaptureBytes bounds a capture file read into memory. A capture is bounded
// by the capture section's own limits; this is the bound on a file somebody
// hands the simulator by mistake.
const maxCaptureBytes = 512 << 20

// A Flow is one conversation out of a capture file.
type Flow struct {
	// Client and Server are the endpoints, from the conversation's first SYN.
	Client, Server netip.AddrPort
	// Request is everything the client sent, in order.
	Request []byte
	// Comment is the capture's own note on the exchange, which carries the
	// request identifier, the route, the status and the denial reason.
	Comment string
	// Truncated says the capture's body bound cut the request. Simulating half
	// a body may decide differently from the whole one, so this is carried
	// rather than dropped.
	Truncated bool
}

// RequestID, Route, Status and Denied read the capture's comment.
func (f Flow) RequestID() string { return f.commentField("request_id") }
func (f Flow) Route() string     { return f.commentField("route") }
func (f Flow) Denied() string    { return f.commentField("denied") }

// Status is the status the proxy answered at capture time, or 0.
func (f Flow) Status() int {
	s := f.commentField("status")
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func (f Flow) commentField(key string) string {
	for _, part := range strings.Fields(f.Comment) {
		if k, v, ok := strings.Cut(part, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// ReadCapture reads the conversations out of a pcapng file written by this
// project's capture.
func ReadCapture(r io.Reader) ([]Flow, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxCaptureBytes))
	if err != nil {
		return nil, fmt.Errorf("capture file: %w", err)
	}
	var (
		order  binary.ByteOrder = binary.LittleEndian
		flows  []*Flow
		byKey  = map[string]*Flow{}
		seenHB bool
	)
	for off := 0; off < len(b); {
		if len(b)-off < 12 {
			return nil, fmt.Errorf("capture file: a block header past the end of the file")
		}
		kind := binary.LittleEndian.Uint32(b[off:])
		switch {
		case kind == blockSHB:
			if len(b)-off < 16 {
				return nil, fmt.Errorf("capture file: a truncated section header")
			}
			// The magic decides the section's byte order, and the length has
			// to be read in that order.
			switch {
			case binary.LittleEndian.Uint32(b[off+8:]) == byteOrderMagic:
				order = binary.LittleEndian
			case binary.BigEndian.Uint32(b[off+8:]) == byteOrderMagic:
				order = binary.BigEndian
			default:
				return nil, fmt.Errorf("capture file: not a pcapng section header")
			}
			seenHB = true
		case !seenHB:
			return nil, fmt.Errorf("capture file: a block before any section header")
		default:
			kind = order.Uint32(b[off:])
		}
		total := int(order.Uint32(b[off+4:]))
		if total < 12 || total%4 != 0 || off+total > len(b) {
			return nil, fmt.Errorf("capture file: a block of %d bytes at offset %d", total, off)
		}
		body := b[off+8 : off+total-4]
		switch kind {
		case blockIDB:
			if len(body) < 2 {
				return nil, fmt.Errorf("capture file: a truncated interface description")
			}
			if lt := order.Uint16(body); lt != linkEthernet {
				return nil, fmt.Errorf("capture file: link type %d; this reads Ethernet (1), "+
					"which is what this project's capture writes", lt)
			}
		case blockEPB:
			if err := readPacket(order, body, &flows, byKey); err != nil {
				return nil, err
			}
		}
		off += total
	}
	if !seenHB {
		return nil, fmt.Errorf("capture file: empty, or not a pcapng file")
	}
	out := make([]Flow, 0, len(flows))
	for _, f := range flows {
		if len(f.Request) == 0 {
			continue // a conversation the client said nothing in
		}
		if strings.Contains(f.Comment, "request=truncated") {
			f.Truncated = true
		}
		out = append(out, *f)
	}
	return out, nil
}

// readPacket folds one enhanced packet block into the flows.
func readPacket(order binary.ByteOrder, body []byte, flows *[]*Flow, byKey map[string]*Flow) error {
	// interface id, timestamp high and low, captured length, original length.
	if len(body) < 20 {
		return fmt.Errorf("capture file: a truncated packet block")
	}
	capLen := int(order.Uint32(body[12:]))
	if capLen < 0 || 20+capLen > len(body) {
		return fmt.Errorf("capture file: a packet of %d bytes in a block of %d", capLen, len(body))
	}
	frame := body[20 : 20+capLen]
	comment := packetComment(order, body[20+((capLen+3)&^3):])

	src, dst, payload, flags, ok := dissect(frame)
	if !ok {
		return nil // not a TCP frame this reads; the writer only makes those
	}
	// The client is whoever sent the SYN without the ACK, which the writer
	// always emits first for a conversation.
	const synOnly = 0x02
	key := src.String() + ">" + dst.String()
	rev := dst.String() + ">" + src.String()
	if flags&0x3f == synOnly {
		f := &Flow{Client: src, Server: dst, Comment: comment}
		byKey[key] = f
		byKey[rev] = f
		*flows = append(*flows, f)
		return nil
	}
	f := byKey[key]
	if f == nil {
		return nil // a conversation whose opening we never saw
	}
	if f.Comment == "" {
		f.Comment = comment
	}
	if src == f.Client && len(payload) > 0 {
		f.Request = append(f.Request, payload...)
	}
	return nil
}

// packetComment reads the one option the writer sets.
func packetComment(order binary.ByteOrder, opts []byte) string {
	for len(opts) >= 4 {
		code := order.Uint16(opts)
		length := int(order.Uint16(opts[2:]))
		if code == 0 {
			return ""
		}
		padded := (length + 3) &^ 3
		if 4+padded > len(opts) {
			return ""
		}
		if code == 1 { // opt_comment
			return string(bytes.TrimRight(opts[4:4+length], "\x00"))
		}
		opts = opts[4+padded:]
	}
	return ""
}

// dissect reads Ethernet, IPv4 or IPv6, and TCP, and returns the endpoints, the
// payload and the TCP flags.
func dissect(frame []byte) (src, dst netip.AddrPort, payload []byte, flags uint8, ok bool) {
	if len(frame) < 14 {
		return src, dst, nil, 0, false
	}
	ethertype := binary.BigEndian.Uint16(frame[12:])
	rest := frame[14:]
	var sa, da netip.Addr
	switch ethertype {
	case 0x0800: // IPv4
		if len(rest) < 20 {
			return src, dst, nil, 0, false
		}
		ihl := int(rest[0]&0x0f) * 4
		if ihl < 20 || len(rest) < ihl || rest[9] != 6 {
			return src, dst, nil, 0, false
		}
		sa = netip.AddrFrom4([4]byte(rest[12:16]))
		da = netip.AddrFrom4([4]byte(rest[16:20]))
		rest = rest[ihl:]
	case 0x86DD: // IPv6
		if len(rest) < 40 || rest[6] != 6 {
			return src, dst, nil, 0, false
		}
		sa = netip.AddrFrom16([16]byte(rest[8:24]))
		da = netip.AddrFrom16([16]byte(rest[24:40]))
		rest = rest[40:]
	default:
		return src, dst, nil, 0, false
	}
	if len(rest) < 20 {
		return src, dst, nil, 0, false
	}
	sp := binary.BigEndian.Uint16(rest[0:])
	dp := binary.BigEndian.Uint16(rest[2:])
	doff := int(rest[12]>>4) * 4
	if doff < 20 || len(rest) < doff {
		return src, dst, nil, 0, false
	}
	return netip.AddrPortFrom(sa, sp), netip.AddrPortFrom(da, dp), rest[doff:], rest[13], true
}

// CaptureInputs turns the conversations in a capture file into simulation
// inputs, for the listener named.
//
// The listener has to be named because a capture file says which port the proxy
// was listening on, not which listener in a configuration that is -- and in a
// configuration being changed it may not be the same listener at all. Guessing
// would be the kind of convenience that makes a report about the wrong thing.
func CaptureInputs(flows []Flow, listener string) []Input {
	out := make([]Input, 0, len(flows))
	for i, f := range flows {
		name := f.RequestID()
		if name == "" {
			name = fmt.Sprintf("flow %d", i+1)
		}
		if f.Truncated {
			name += " (truncated by the capture)"
		}
		out = append(out, Input{
			Name:     name,
			Listener: listener,
			Client:   f.Client.Addr().String(),
			Bytes:    f.Request,
		})
	}
	return out
}
