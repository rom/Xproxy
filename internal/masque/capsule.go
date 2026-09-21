// Package masque implements the proxying protocols of the MASQUE work:
// the HTTP capsule protocol (RFC 9297), UDP proxying (RFC 9298) and IP
// proxying (RFC 9484).
//
// What these are for. HTTP CONNECT tunnels TCP, and that is all it
// tunnels. Everything an estate runs that is not TCP — DNS, QUIC,
// NTP, WireGuard, a game protocol — either leaves the network outside
// the proxy's policy or does not leave at all. CONNECT-UDP is the
// missing half: the same explicit proxy, the same destination policy,
// the same logs, for datagrams. CONNECT-IP goes further and carries IP
// packets, which is how a MASQUE VPN is built.
//
// The transport is the capsule protocol: once a request is accepted,
// the stream stops being a body and becomes a sequence of
// type-length-value capsules in both directions. Over HTTP/3 the
// datagrams can also ride QUIC DATAGRAM frames, which is faster but
// unreliable; the capsule form works on any HTTP version from 2 up and
// is what RFC 9298 requires as the fallback, so it is what this
// implements.
package masque

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Capsule types. RFC 9297 registers DATAGRAM; the address and route
// capsules are RFC 9484's.
const (
	CapsuleDatagram           uint64 = 0x00
	CapsuleAddressAssign      uint64 = 0x01
	CapsuleAddressRequest     uint64 = 0x02
	CapsuleRouteAdvertisement uint64 = 0x03
)

// MaxCapsule bounds one capsule's value. A datagram capsule carries a
// UDP payload, which cannot exceed 65535 bytes, and the address
// capsules are tiny; the bound is what stops a peer choosing how much
// memory the proxy uses.
const MaxCapsule = 65 << 10

// Capsule is one type-length-value unit.
type Capsule struct {
	Type  uint64
	Value []byte
}

// ErrCapsuleTooLarge is returned for a capsule over MaxCapsule. It is
// distinguished from a parse error because a peer can legitimately be
// speaking the protocol and simply be too enthusiastic.
var ErrCapsuleTooLarge = errors.New("masque: capsule over the size bound")

// ReadCapsule reads one capsule. Both fields are QUIC variable length
// integers (RFC 9000 section 16), which is what makes a capsule cheap
// for the common small case and still able to carry a jumbo payload.
func ReadCapsule(r io.Reader) (Capsule, error) {
	typ, err := ReadVarint(r)
	if err != nil {
		return Capsule{}, err
	}
	length, err := ReadVarint(r)
	if err != nil {
		return Capsule{}, err
	}
	if length > MaxCapsule {
		return Capsule{}, fmt.Errorf("%w: %d bytes", ErrCapsuleTooLarge, length)
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return Capsule{}, err
	}
	return Capsule{Type: typ, Value: value}, nil
}

// WriteCapsule writes one capsule.
func WriteCapsule(w io.Writer, c Capsule) error {
	if uint64(len(c.Value)) > MaxCapsule {
		return ErrCapsuleTooLarge
	}
	buf := AppendVarint(nil, c.Type)
	buf = AppendVarint(buf, uint64(len(c.Value)))
	buf = append(buf, c.Value...)
	_, err := w.Write(buf)
	return err
}

// ReadVarint reads a QUIC variable length integer.
func ReadVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	// The top two bits give the length: 1, 2, 4 or 8 bytes.
	size := 1 << (first[0] >> 6)
	v := uint64(first[0] & 0x3f)
	if size == 1 {
		return v, nil
	}
	rest := make([]byte, size-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return 0, err
	}
	for _, b := range rest {
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// AppendVarint appends a QUIC variable length integer, using the
// shortest encoding — which matters, because a receiver that compares
// encodings rather than values would otherwise see two different
// context ids for the same number.
func AppendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000) //nolint:gosec // bounded above
	case v <= 1073741823:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000) //nolint:gosec // bounded above
	case v <= 4611686018427387903:
		return binary.BigEndian.AppendUint64(b, v|0xc000000000000000)
	default:
		// Not representable; the callers bound their values, so this is
		// a programming error rather than something on the wire.
		return b
	}
}

// ParseVarint reads a varint from a byte slice, returning the value and
// how many bytes it used.
func ParseVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	size := 1 << (b[0] >> 6)
	if len(b) < size {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v := uint64(b[0] & 0x3f)
	for _, c := range b[1:size] {
		v = v<<8 | uint64(c)
	}
	return v, size, nil
}

// Datagram builds a DATAGRAM capsule for a context id and payload.
// Context 0 is the raw payload of the proxied flow (RFC 9298 section
// 5); other contexts negotiate extensions this implementation does not
// register, and are dropped rather than guessed at.
func Datagram(context uint64, payload []byte) Capsule {
	v := AppendVarint(nil, context)
	v = append(v, payload...)
	return Capsule{Type: CapsuleDatagram, Value: v}
}

// SplitDatagram takes a DATAGRAM capsule apart.
func SplitDatagram(c Capsule) (context uint64, payload []byte, err error) {
	if c.Type != CapsuleDatagram {
		return 0, nil, errors.New("masque: not a datagram capsule")
	}
	ctx, n, err := ParseVarint(c.Value)
	if err != nil {
		return 0, nil, fmt.Errorf("masque: datagram context: %w", err)
	}
	return ctx, c.Value[n:], nil
}
