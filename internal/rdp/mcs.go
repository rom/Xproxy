package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// The conference layer: T.125's Connect Initial and Connect Response,
// and the T.124 conference request inside them that carries the data
// blocks the two ends exchange before the session starts. One of those
// blocks is the channel list, which is the whole reason this package
// decodes any of it: a gateway that can rewrite the list decides which
// virtual channels exist, and a channel that does not exist cannot
// carry a file.
//
// Only the outer structure is decoded. The fields this gateway does
// not decide are carried across as the bytes that arrived, so a
// capability it has never heard of is not lost in a re-encoding.

// Connect Initial and Connect Response are tagged as T.125
// application types 101 and 102.
var (
	tagConnectInitial  = []byte{0x7F, 0x65}
	tagConnectResponse = []byte{0x7F, 0x66}
)

// The T.124 object identifier that opens the conference layer, and the
// H.221 key that names the block area inside it.
var (
	t124Identifier = []byte{0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01}
	h221Duca       = []byte("Duca")
)

// ErrMCS is a conference layer this package cannot make sense of.
var ErrMCS = fmt.Errorf("rdp: conference layer")

// Connect is either end's half of the conference exchange: everything
// before the block area, carried as it arrived, and the blocks
// themselves.
type Connect struct {
	// response says which of the two this is, since they differ only
	// in their tag and their prefix.
	response bool
	// prefix is the encoded fields before the user data, byte for
	// byte as they arrived.
	prefix []byte
	// gccHead is the conference request or response up to and
	// including the H.221 key.
	gccHead []byte
	// Blocks is the data block area, which is what this gateway reads
	// and rewrites.
	Blocks []byte
}

// ParseConnect reads either half from a slow path PDU's X.224 payload.
func ParseConnect(payload []byte) (*Connect, error) {
	var c Connect
	switch {
	case bytes.HasPrefix(payload, tagConnectInitial):
	case bytes.HasPrefix(payload, tagConnectResponse):
		c.response = true
	default:
		return nil, fmt.Errorf("%w: not a connect initial or response", ErrMCS)
	}
	body, err := berContent(payload[2:])
	if err != nil {
		return nil, err
	}
	// Every field before the user data is carried across unchanged.
	// The user data is the last one, and it is an octet string.
	off, err := berSkipTo(body, c.response)
	if err != nil {
		return nil, err
	}
	c.prefix = body[:off]
	if off >= len(body) || body[off] != 0x04 {
		return nil, fmt.Errorf("%w: the user data is not an octet string", ErrMCS)
	}
	gcc, err := berContent(body[off+1:])
	if err != nil {
		return nil, err
	}
	if err := c.parseGCC(gcc); err != nil {
		return nil, err
	}
	return &c, nil
}

// parseGCC reads the conference request or response and keeps
// everything up to the block area verbatim.
func (c *Connect) parseGCC(gcc []byte) error {
	if !bytes.HasPrefix(gcc, t124Identifier) {
		return fmt.Errorf("%w: no t.124 identifier", ErrMCS)
	}
	rest := gcc[len(t124Identifier):]
	inner, err := perOctetString(rest)
	if err != nil {
		return err
	}
	i := bytes.Index(inner, h221Duca)
	if i < 0 {
		return fmt.Errorf("%w: no data block area", ErrMCS)
	}
	c.gccHead = inner[:i+len(h221Duca)]
	blocks, err := perOctetString(inner[i+len(h221Duca):])
	if err != nil {
		return err
	}
	c.Blocks = blocks
	return nil
}

// Encode renders the half back into a slow path PDU, with whatever the
// blocks now say and every length recomputed.
func (c *Connect) Encode() ([]byte, error) {
	inner := append(append([]byte(nil), c.gccHead...), perLength(len(c.Blocks))...)
	inner = append(inner, c.Blocks...)
	gcc := append(append([]byte(nil), t124Identifier...), perLength(len(inner))...)
	gcc = append(gcc, inner...)

	body := append(append([]byte(nil), c.prefix...), 0x04)
	body = append(body, berLength(len(gcc))...)
	body = append(body, gcc...)

	tag := tagConnectInitial
	if c.response {
		tag = tagConnectResponse
	}
	out := append(append([]byte(nil), tag...), berLength(len(body))...)
	return DataPDU(append(out, body...))
}

// berSkipTo walks the fields before the user data and returns where it
// starts. A Connect Initial has three octet-string-or-boolean fields
// and three domain parameter sequences in front of it; a Connect
// Response has a result, a connect identifier and one sequence.
func berSkipTo(body []byte, response bool) (int, error) {
	n := 6
	if response {
		n = 3
	}
	off := 0
	for i := 0; i < n; i++ {
		if off >= len(body) {
			return 0, fmt.Errorf("%w: the conference layer ends before its user data", ErrMCS)
		}
		size, head, err := berHeader(body[off+1:])
		if err != nil {
			return 0, err
		}
		off += 1 + head + size
		if off > len(body) {
			return 0, fmt.Errorf("%w: a field runs past the conference layer", ErrMCS)
		}
	}
	return off, nil
}

// berContent returns what a definite-length BER value carries, given
// the bytes from its length onwards.
func berContent(b []byte) ([]byte, error) {
	size, head, err := berHeader(b)
	if err != nil {
		return nil, err
	}
	if head+size > len(b) {
		return nil, fmt.Errorf("%w: a value of %d bytes runs past the %d there are", ErrMCS, size, len(b)-head)
	}
	return b[head : head+size], nil
}

// berHeader reads a definite length and says how many bytes it took.
func berHeader(b []byte) (size, head int, err error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("%w: a value with no length", ErrMCS)
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	n := int(b[0] & 0x7F)
	// An indefinite length has no place in this protocol, and a length
	// of a length longer than four bytes is not one either.
	if n == 0 || n > 4 || 1+n > len(b) {
		return 0, 0, fmt.Errorf("%w: a length of %d bytes", ErrMCS, n)
	}
	for i := 1; i <= n; i++ {
		size = size<<8 | int(b[i])
	}
	if size > MaxPDU {
		return 0, 0, fmt.Errorf("%w: a value of %d bytes, over what a pdu can carry", ErrMCS, size)
	}
	return size, 1 + n, nil
}

// berLength renders a definite length.
func berLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// perOctetString reads a PER length determinant and the bytes behind
// it.
func perOctetString(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: an octet string with no length", ErrMCS)
	}
	size, head := int(b[0]), 1
	if b[0]&0x80 != 0 {
		if len(b) < 2 {
			return nil, fmt.Errorf("%w: a two byte length with one byte", ErrMCS)
		}
		if b[0]&0xC0 == 0xC0 {
			// A fragmented string, which nothing in this exchange uses
			// and which this package will not guess at.
			return nil, fmt.Errorf("%w: a fragmented octet string", ErrMCS)
		}
		size, head = int(b[0]&0x3F)<<8|int(b[1]), 2
	}
	if head+size > len(b) {
		return nil, fmt.Errorf("%w: an octet string of %d bytes with %d there", ErrMCS, size, len(b)-head)
	}
	return b[head : head+size], nil
}

// perLength renders a PER length determinant.
func perLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return []byte{byte(0x80 | n>>8), byte(n)}
}

// The data block types this gateway reads. The rest are carried across
// without being decoded.
const (
	BlockClientCore     = 0xC001
	BlockClientSecurity = 0xC002
	BlockClientNetwork  = 0xC003
	BlockClientCluster  = 0xC004
	BlockServerCore     = 0x0C01
	BlockServerSecurity = 0x0C02
	BlockServerNetwork  = 0x0C03
)

// Block is one data block: its type and what it carries.
type Block struct {
	Type uint16
	Data []byte
}

// Walk splits the block area into blocks.
func (c *Connect) Walk() ([]Block, error) {
	var out []Block
	for off := 0; off < len(c.Blocks); {
		if off+4 > len(c.Blocks) {
			return nil, fmt.Errorf("%w: a block header of %d bytes", ErrMCS, len(c.Blocks)-off)
		}
		typ := binary.LittleEndian.Uint16(c.Blocks[off : off+2])
		n := int(binary.LittleEndian.Uint16(c.Blocks[off+2 : off+4]))
		if n < 4 || off+n > len(c.Blocks) {
			return nil, fmt.Errorf("%w: a block of %d bytes at %d of %d", ErrMCS, n, off, len(c.Blocks))
		}
		out = append(out, Block{Type: typ, Data: c.Blocks[off+4 : off+n]})
		off += n
	}
	return out, nil
}

// Replace puts new contents in the first block of a type, recomputing
// its length and the block area around it.
func (c *Connect) Replace(typ uint16, data []byte) error {
	blocks, err := c.Walk()
	if err != nil {
		return err
	}
	if len(data)+4 > 0xFFFF {
		return fmt.Errorf("%w: a block of %d bytes", ErrMCS, len(data)+4)
	}
	var out []byte
	replaced := false
	for _, b := range blocks {
		body := b.Data
		if b.Type == typ && !replaced {
			body, replaced = data, true
		}
		head := make([]byte, 4)
		binary.LittleEndian.PutUint16(head[0:2], b.Type)
		binary.LittleEndian.PutUint16(head[2:4], uint16(len(body)+4)) //nolint:gosec // bounded above
		out = append(append(out, head...), body...)
	}
	if !replaced {
		return fmt.Errorf("%w: no block of type %#04x to replace", ErrMCS, typ)
	}
	c.Blocks = out
	return nil
}
