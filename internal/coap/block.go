package coap

import "fmt"

// Block-wise transfer, RFC 7959.
//
// CoAP's message layer carries about a kilobyte, so anything larger moves in
// numbered blocks: Block1 for a request body going up, Block2 for a response body
// coming down. Each option is a number, a more-to-come bit and a size exponent,
// packed into at most three octets.
//
// Two things make this a relay's business rather than an implementation detail.
// The first is that a transfer's total size is not in any one message -- it is the
// block number times the block size, growing as the transfer proceeds -- so a
// bound on one datagram bounds nothing, and a client can walk a device through a
// transfer of any size in messages that each look small. The second is Size1 and
// Size2, which are a *declaration* of the total; a relay can read the intent
// before the transfer happens, which is the only point at which refusing it is
// cheap.

// Block is one Block1 or Block2 option.
type Block struct {
	// Num is which block this is, counting from zero.
	Num uint32
	// More says another block follows. In a request's Block1 it means the
	// client has more body to send; in a response's Block2 it means the server
	// has more body to give.
	More bool
	// SizeExp is the size exponent: the block is 1 << (SizeExp + 4) octets, so
	// 0 is sixteen and 6 is a kilobyte. Seven is reserved.
	SizeExp uint8
}

// MaxSizeExp is the largest exponent RFC 7959 defines. Seven is reserved and a
// message using it is a format error, which is worth refusing rather than
// clamping: a relay that read 7 as 6 would be accounting for a transfer in blocks
// of a different size than the one taking place.
const MaxSizeExp = 6

// ParseBlock reads a block option value.
func ParseBlock(v []byte) (Block, error) {
	if len(v) > 3 {
		return Block{}, fmt.Errorf("%w: a block option of %d octets", ErrOption, len(v))
	}
	if len(v) == 0 {
		// An empty value is block zero of sixteen octets with nothing to
		// follow, which is what the omitted leading zeros of a numeric option
		// come to (RFC 7252 s3.2).
		return Block{}, nil
	}
	n := num(v)
	b := Block{
		Num:     n >> 4,
		More:    n&0x08 != 0,
		SizeExp: uint8(n & 0x07), //nolint:gosec // three bits
	}
	if b.SizeExp > MaxSizeExp {
		return Block{}, fmt.Errorf("%w: a reserved block size exponent", ErrOption)
	}
	return b, nil
}

// Size is the block's length in octets.
func (b Block) Size() int64 { return 1 << (int64(b.SizeExp) + 4) }

// Offset is where this block starts in the whole body.
func (b Block) Offset() int64 { return int64(b.Num) * b.Size() }

// End is where this block ends, which is the smallest the whole transfer can be.
// It is the number a bound on a block-wise transfer is compared against, because
// it is a fact about what has already been asked for rather than a declaration
// about what is intended.
func (b Block) End() int64 { return b.Offset() + b.Size() }

// AppendTo renders the block back into an option value, leading zeros left out.
func (b Block) AppendTo(out []byte) []byte {
	n := b.Num << 4
	if b.More {
		n |= 0x08
	}
	n |= uint32(b.SizeExp) & 0x07
	switch {
	case n == 0:
		return out
	case n <= 0xff:
		return append(out, byte(n))
	case n <= 0xffff:
		return append(out, byte(n>>8), byte(n))
	}
	return append(out, byte(n>>16), byte(n>>8), byte(n))
}

func (b Block) String() string {
	more := ""
	if b.More {
		more = "+"
	}
	return fmt.Sprintf("%d%s/%d", b.Num, more, b.Size())
}

// Block1 and Block2 read the options, saying whether each was present.
func (m *Message) Block1() (Block, bool, error) { return m.block(OptionBlock1) }
func (m *Message) Block2() (Block, bool, error) { return m.block(OptionBlock2) }

func (m *Message) block(n uint16) (Block, bool, error) {
	v, ok := m.Get(n)
	if !ok {
		return Block{}, false, nil
	}
	b, err := ParseBlock(v)
	if err != nil {
		return Block{}, true, fmt.Errorf("%s: %w", OptionName(n), err)
	}
	return b, true, nil
}

// TransferSize is the largest total this message says its transfer will be: the
// end of the block it carries, and the declared size where one is declared.
//
// Both are returned as one number because a bound cares about the larger. A
// client on block zero of sixteen that declares a megabyte in Size1 has said what
// it intends, and refusing it then costs one datagram rather than sixty-four
// thousand.
func (m *Message) TransferSize() int64 {
	var most int64
	if b, ok, err := m.Block1(); ok && err == nil {
		most = max(most, b.End())
	}
	if b, ok, err := m.Block2(); ok && err == nil {
		most = max(most, b.End())
	}
	if n, ok := m.Size1(); ok {
		most = max(most, int64(n))
	}
	if n, ok := m.Size2(); ok {
		most = max(most, int64(n))
	}
	return most
}
