package rfb

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Tight is TightVNC's security type 16. Unlike the other vendors'
// types it is not a cipher at all: it is a negotiation that picks a
// tunnel and then an authentication, each named by a capability
// record. Which is why it is the safest of them to reimplement --
// there is nothing cryptographic to get wrong, only framing -- and
// why it protects nothing by itself: what it settles on is one of the
// ordinary types, and that is what does the work.
//
// It follows TightVNC's rfbproto, which describes this part of the
// protocol. Interoperability with TightVNC and TurboVNC is not
// verified by this repository's tests.

// TightCapability is the 16 byte record that names one capability: a
// code, a four byte vendor, and an eight byte signature.
type TightCapability struct {
	Code      uint32
	Vendor    string
	Signature string
}

// The capabilities this gateway names. A tunnel of none, and the two
// authentications it can complete on both legs.
var (
	TightTunnelNone = TightCapability{Code: 0, Vendor: "TGHT", Signature: "NOTUNNEL"}
	TightAuthNone   = TightCapability{Code: 1, Vendor: "STDV", Signature: "NOAUTH__"}
	TightAuthVNC    = TightCapability{Code: 2, Vendor: "STDV", Signature: "VNCAUTH_"}
)

// TightMaxCapabilities bounds a capability list, which a peer chooses
// the length of.
const TightMaxCapabilities = 256

// tightCapabilitySize is a record on the wire.
const tightCapabilitySize = 4 + 4 + 8

// Encode renders a capability record.
func (c TightCapability) Encode() []byte {
	out := binary.BigEndian.AppendUint32(nil, c.Code)
	out = append(out, pad(c.Vendor, 4)...)
	return append(out, pad(c.Signature, 8)...)
}

func pad(s string, n int) []byte {
	out := make([]byte, n)
	copy(out, s)
	return out
}

// TightCapabilities renders a list: a count and then the records.
func TightCapabilities(caps []TightCapability) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(caps))) //nolint:gosec // callers pass short lists
	for _, c := range caps {
		out = append(out, c.Encode()...)
	}
	return out
}

// ReadTightCapabilities reads one, bounding the count before anything
// is allocated for it.
func ReadTightCapabilities(r io.Reader) ([]TightCapability, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n > TightMaxCapabilities {
		return nil, fmt.Errorf("rfb: tight capability list of %d, over the %d bound", n, TightMaxCapabilities)
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, int(n)*tightCapabilitySize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	out := make([]TightCapability, 0, n)
	for i := 0; i < int(n); i++ {
		b := buf[i*tightCapabilitySize:]
		out = append(out, TightCapability{
			Code:      binary.BigEndian.Uint32(b[0:4]),
			Vendor:    string(b[4:8]),
			Signature: string(b[8:16]),
		})
	}
	return out, nil
}

// TightHasCapability says whether a list names a code.
func TightHasCapability(caps []TightCapability, code uint32) bool {
	for _, c := range caps {
		if c.Code == code {
			return true
		}
	}
	return false
}

// TightChoice renders the four byte code one end picks.
func TightChoice(code uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, code)
}

// ReadTightChoice reads it.
func ReadTightChoice(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// TightInteraction is the block a Tight server sends after ServerInit:
// the message types and encodings it has beyond the standard ones.
type TightInteraction struct {
	Server, Client, Encodings []TightCapability
}

// tightInteractionHead is the three counts and the padding.
const tightInteractionHead = 2 + 2 + 2 + 2

// NoTightInteraction is what this gateway offers a client: nothing
// beyond the standard protocol. It is not a limitation being hidden --
// the extensions a Tight server advertises here are things like file
// transfer, which a gateway that cannot see inside them has no
// business passing through.
func NoTightInteraction() []byte { return make([]byte, tightInteractionHead) }

// ReadTightInteraction reads and discards a server's block, which is
// what the gateway does with a target's: the client on the other leg
// was told there are none.
func ReadTightInteraction(r io.Reader) (TightInteraction, error) {
	var head [tightInteractionHead]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return TightInteraction{}, err
	}
	var out TightInteraction
	for i, dst := range []*[]TightCapability{&out.Server, &out.Client, &out.Encodings} {
		n := binary.BigEndian.Uint16(head[i*2 : i*2+2])
		if n > TightMaxCapabilities {
			return TightInteraction{}, fmt.Errorf("rfb: tight interaction list of %d, over the %d bound", n, TightMaxCapabilities)
		}
		if n == 0 {
			continue
		}
		buf := make([]byte, int(n)*tightCapabilitySize)
		if _, err := io.ReadFull(r, buf); err != nil {
			return TightInteraction{}, err
		}
		caps := make([]TightCapability, 0, n)
		for j := 0; j < int(n); j++ {
			b := buf[j*tightCapabilitySize:]
			caps = append(caps, TightCapability{
				Code:      binary.BigEndian.Uint32(b[0:4]),
				Vendor:    string(b[4:8]),
				Signature: string(b[8:16]),
			})
		}
		*dst = caps
	}
	return out, nil
}
