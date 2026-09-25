package tftp

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/rom/xproxy/internal/textsafe"
)

// MaxErrorMessage bounds the message in an error packet this relay builds.
// RFC 1350 does not bound it, and a peer that is about to be refused does not
// need a paragraph.
const MaxErrorMessage = 200

// EncodeError builds an error packet.
//
// The message is clipped and stripped of control characters even though this
// relay writes its own messages, because some of them name what was refused
// and what was refused is a string a client chose. A filename with an escape
// sequence in it is the reason for a refusal; sending it back out in the
// refusal is the same mistake one hop further on.
func EncodeError(code uint16, msg string) []byte {
	msg = textsafe.Clip(msg, MaxErrorMessage)
	out := make([]byte, 0, 5+len(msg))
	out = binary.BigEndian.AppendUint16(out, uint16(OpError))
	out = binary.BigEndian.AppendUint16(out, code)
	out = append(out, msg...)
	return append(out, 0)
}

// EncodeAck builds an acknowledgement.
func EncodeAck(block uint16) []byte {
	out := make([]byte, 0, 4)
	out = binary.BigEndian.AppendUint16(out, uint16(OpAck))
	return binary.BigEndian.AppendUint16(out, block)
}

// EncodeRequest builds a read or write request.
//
// This is how a bound is applied rather than enforced by refusal: a client
// that asked for a block size or a window this relay will not carry has its
// request rewritten to the bound and forwarded, so the transfer happens and
// the amplification does not. A device whose TFTP client nobody can
// reconfigure is the normal case in an estate, and a bound that only refuses
// is a bound that gets turned off.
func EncodeRequest(op Op, filename, mode string, opts []Option) ([]byte, error) {
	if op != OpRead && op != OpWrite {
		return nil, fmt.Errorf("%w: %s is not a request", ErrOpcode, op)
	}
	if err := encodable(filename, "filename"); err != nil {
		return nil, err
	}
	if err := encodable(mode, "mode"); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 32+len(filename)+len(mode))
	out = binary.BigEndian.AppendUint16(out, uint16(op))
	out = append(out, filename...)
	out = append(out, 0)
	out = append(out, mode...)
	out = append(out, 0)
	body, err := encodeOptions(opts)
	if err != nil {
		return nil, err
	}
	return append(out, body...), nil
}

// EncodeOAck builds an option acknowledgement, which is what a relay sends
// when it answers a request's options itself rather than passing the server's
// answer through -- and what it rebuilds when the server accepted a larger
// block or window than the bound allows.
func EncodeOAck(opts []Option) ([]byte, error) {
	out := binary.BigEndian.AppendUint16(make([]byte, 0, 32), uint16(OpOAck))
	body, err := encodeOptions(opts)
	if err != nil {
		return nil, err
	}
	return append(out, body...), nil
}

// encodeOptions writes the name and value pairs.
func encodeOptions(opts []Option) ([]byte, error) {
	if len(opts) > MaxOptions {
		return nil, fmt.Errorf("%w: %d options", ErrCount, len(opts))
	}
	out := make([]byte, 0, 16*len(opts))
	for _, o := range opts {
		if o.Name == "" {
			return nil, fmt.Errorf("%w: an option with no name", ErrShape)
		}
		if err := encodable(o.Name, "option name"); err != nil {
			return nil, err
		}
		if err := encodable(o.Value, "option value"); err != nil {
			return nil, err
		}
		out = append(out, o.Name...)
		out = append(out, 0)
		out = append(out, o.Value...)
		out = append(out, 0)
	}
	return out, nil
}

// encodable refuses a string this package cannot write into a
// zero-terminated field. A NUL in a value would end the field early, so the
// packet would say something other than what the caller asked for -- which is
// the bug this relay exists to stop, and so is not one to commit while
// stopping it.
func encodable(s, what string) error {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return fmt.Errorf("%w: a NUL at octet %d of the %s", ErrShape, i, what)
	}
	if len(s) > MaxFilename {
		return fmt.Errorf("%w: a %s of %d octets", ErrCount, what, len(s))
	}
	return nil
}
