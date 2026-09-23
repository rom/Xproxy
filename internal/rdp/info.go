package rdp

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// The session layer this gateway touches: the multipoint data units
// that carry a channel's traffic, and the one packet inside them that
// carries the person's credential.

// The T.125 data unit types, in the top six bits of the first byte.
const (
	mcsSendDataRequest    = 25
	mcsSendDataIndication = 26
	// MCSChannelJoinRequest and its confirmation are named because a
	// gateway that removes a channel has to answer the join for it
	// itself.
	MCSChannelJoinRequest = 14
	MCSChannelJoinConfirm = 15
)

// SendData is one channel's traffic: which channel, and what was on
// it.
type SendData struct {
	// Request is true for a client's data unit and false for a
	// server's, which differ only in their type.
	Request   bool
	Initiator uint16
	Channel   uint16
	// Priority is the byte carrying the data priority and the
	// segmentation flags, kept as it arrived.
	Priority byte
	Payload  []byte
}

// MCSType returns the data unit type in a conference layer payload.
func MCSType(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}
	return int(b[0] >> 2), true
}

// ParseSendData reads a channel data unit. It returns false without an
// error for a unit of another type, which a gateway forwards without
// looking inside.
func ParseSendData(b []byte) (SendData, bool, error) {
	var s SendData
	typ, ok := MCSType(b)
	if !ok {
		return s, false, nil
	}
	switch typ {
	case mcsSendDataRequest:
		s.Request = true
	case mcsSendDataIndication:
	default:
		return s, false, nil
	}
	// The initiator, the channel, the priority byte, then a length.
	if len(b) < 7 {
		return s, false, fmt.Errorf("%w: a data unit of %d bytes", ErrMCS, len(b))
	}
	s.Initiator = binary.BigEndian.Uint16(b[1:3])
	s.Channel = binary.BigEndian.Uint16(b[3:5])
	s.Priority = b[5]
	payload, err := perOctetString(b[6:])
	if err != nil {
		return s, false, err
	}
	s.Payload = payload
	return s, true, nil
}

// Encode renders a channel data unit.
func (s SendData) Encode() []byte {
	typ := byte(mcsSendDataIndication << 2)
	if s.Request {
		typ = mcsSendDataRequest << 2
	}
	out := []byte{typ, 0, 0, 0, 0, s.Priority}
	binary.BigEndian.PutUint16(out[1:3], s.Initiator)
	binary.BigEndian.PutUint16(out[3:5], s.Channel)
	out = append(out, perLength(len(s.Payload))...)
	return append(out, s.Payload...)
}

// The basic security header flags of MS-RDPBCGR 2.2.8.1.1.2.1. Only
// the ones that say what a packet is are named.
const (
	SecExchangePkt = 0x0001
	SecEncrypt     = 0x0008
	SecInfoPkt     = 0x0040
	SecLicensePkt  = 0x0080
)

// SecurityHeader is the four bytes in front of a packet that say what
// it is and whether it is encrypted.
type SecurityHeader struct{ Flags, FlagsHi uint16 }

// ParseSecurityHeader reads it and returns what follows.
func ParseSecurityHeader(b []byte) (SecurityHeader, []byte, error) {
	if len(b) < 4 {
		return SecurityHeader{}, nil, fmt.Errorf("%w: a security header of %d bytes", ErrMCS, len(b))
	}
	return SecurityHeader{
		Flags:   binary.LittleEndian.Uint16(b[0:2]),
		FlagsHi: binary.LittleEndian.Uint16(b[2:4]),
	}, b[4:], nil
}

// Encode renders the header.
func (h SecurityHeader) Encode() []byte {
	out := binary.LittleEndian.AppendUint16(nil, h.Flags)
	return binary.LittleEndian.AppendUint16(out, h.FlagsHi)
}

// The client info flags of MS-RDPBCGR 2.2.1.11.1.1 that this gateway
// reads or sets.
const (
	InfoAutologon = 0x00000008
	InfoUnicode   = 0x00000010
)

// ClientInfo is the packet that carries who is connecting and with
// what. It is the only place in the protocol where a person's name and
// password appear, which makes it where a second factor is checked and
// where the credential towards the target is substituted.
type ClientInfo struct {
	CodePage uint32
	Flags    uint32
	Domain   string
	Username string
	Password string
	Shell    string
	Dir      string
	// Extra is whatever followed the five strings, carried across
	// unchanged: it holds the client address, the time zone and the
	// performance flags, none of which is this gateway's business.
	Extra []byte
	// unicode records how the strings arrived, so they go out the same
	// way.
	unicode bool
}

// MaxInfoField bounds one string in the packet. The protocol's own
// limits are smaller than this; it is here so a length a peer chose
// cannot ask for a large allocation before anything has been checked.
const MaxInfoField = 4096

// ParseClientInfo reads the packet.
func ParseClientInfo(b []byte) (*ClientInfo, error) {
	if len(b) < 18 {
		return nil, fmt.Errorf("%w: a client info packet of %d bytes", ErrMCS, len(b))
	}
	ci := &ClientInfo{
		CodePage: binary.LittleEndian.Uint32(b[0:4]),
		Flags:    binary.LittleEndian.Uint32(b[4:8]),
	}
	ci.unicode = ci.Flags&InfoUnicode != 0
	// Five lengths, each the size of the text without its terminator.
	sizes := make([]int, 5)
	for i := range sizes {
		sizes[i] = int(binary.LittleEndian.Uint16(b[8+i*2 : 10+i*2]))
		if sizes[i] > MaxInfoField {
			return nil, fmt.Errorf("%w: a client info field of %d bytes", ErrMCS, sizes[i])
		}
	}
	rest := b[18:] //nolint:gosec // the length was checked above, and 18 is its own bound
	out := make([]string, 5)
	for i, n := range sizes {
		total := n + 1
		if ci.unicode {
			total = n + 2
		}
		if total > len(rest) {
			return nil, fmt.Errorf("%w: a client info field of %d bytes with %d there", ErrMCS, total, len(rest))
		}
		out[i] = decodeText(rest[:n], ci.unicode)
		rest = rest[total:]
	}
	ci.Domain, ci.Username, ci.Password, ci.Shell, ci.Dir = out[0], out[1], out[2], out[3], out[4]
	ci.Extra = append([]byte(nil), rest...)
	return ci, nil
}

// Encode renders the packet, which is what the gateway sends the
// target once it has substituted the credential.
func (ci *ClientInfo) Encode() ([]byte, error) {
	fields := []string{ci.Domain, ci.Username, ci.Password, ci.Shell, ci.Dir}
	encoded := make([][]byte, len(fields))
	head := binary.LittleEndian.AppendUint32(nil, ci.CodePage)
	head = binary.LittleEndian.AppendUint32(head, ci.Flags)
	for i, f := range fields {
		encoded[i] = encodeText(f, ci.unicode)
		if len(encoded[i]) > MaxInfoField {
			return nil, fmt.Errorf("%w: a client info field of %d bytes", ErrMCS, len(encoded[i]))
		}
		head = binary.LittleEndian.AppendUint16(head, uint16(len(encoded[i]))) //nolint:gosec // bounded above
	}
	out := head
	for _, e := range encoded {
		out = append(out, e...)
		if ci.unicode {
			out = append(out, 0, 0)
		} else {
			out = append(out, 0)
		}
	}
	return append(out, ci.Extra...), nil
}

// Unicode says how the strings travelled, which a test and a log line
// both want to know.
func (ci *ClientInfo) Unicode() bool { return ci.unicode }

// SetUnicode is for building a packet rather than parsing one.
func (ci *ClientInfo) SetUnicode(u bool) {
	ci.unicode = u
	if u {
		ci.Flags |= InfoUnicode
	} else {
		ci.Flags &^= InfoUnicode
	}
}

func decodeText(b []byte, unicode bool) string {
	if !unicode {
		return string(b)
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}

func encodeText(s string, unicode bool) []byte {
	if !unicode {
		return []byte(s)
	}
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}
