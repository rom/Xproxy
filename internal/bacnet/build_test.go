package bacnet

import "encoding/binary"

// The builders below encode messages the way a device or a client would,
// so the tests assert against something that could have arrived on a
// socket rather than against the parser's own idea of a message.

// bvlc wraps a payload in a virtual link header with the length filled
// in, which is where a hand-written test gets it wrong.
func bvlc(fn Function, payload ...[]byte) []byte {
	var body []byte
	for _, p := range payload {
		body = append(body, p...)
	}
	out := []byte{0x81, byte(fn), 0, 0}
	out = append(out, body...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// npdu builds a network header. control is the NPCI octet; the caller
// passes the addressing fields it turns on.
func npdu(control byte, rest ...[]byte) []byte {
	out := []byte{1, control}
	for _, r := range rest {
		out = append(out, r...)
	}
	return out
}

// confirmed builds a confirmed request: unsegmented, the largest APDU,
// invoke identifier 1.
func confirmed(choice uint8, params ...byte) []byte {
	return append([]byte{0x00, 0x05, 0x01, choice}, params...)
}

// unconfirmed builds an unconfirmed request.
func unconfirmed(choice uint8, params ...byte) []byte {
	return append([]byte{0x10, choice}, params...)
}

// ctx encodes a primitive context-tagged value.
func ctx(number uint32, data ...byte) []byte {
	return tagged(number, true, data)
}

// app encodes a primitive application-tagged value.
func app(number uint32, data ...byte) []byte {
	return tagged(number, false, data)
}

func tagged(number uint32, context bool, data []byte) []byte {
	head := byte(0)
	if context {
		head |= 0x08
	}
	var out []byte
	if number < extendedTag {
		head |= byte(number) << 4
	} else {
		head |= 0xF0
	}
	switch n := len(data); {
	case n < 5:
		head |= byte(n)
		out = append(out, head)
		if number >= extendedTag {
			out = append(out, byte(number))
		}
	case n < 254:
		head |= 5
		out = append(out, head)
		if number >= extendedTag {
			out = append(out, byte(number))
		}
		out = append(out, byte(n))
	default:
		head |= 5
		out = append(out, head)
		if number >= extendedTag {
			out = append(out, byte(number))
		}
		out = append(out, 254, byte(n>>8), byte(n))
	}
	return append(out, data...)
}

// open and closed are the markers around a constructed value.
func open(number uint32) []byte   { return marker(number, 6) }
func closed(number uint32) []byte { return marker(number, 7) }

func marker(number uint32, lvt byte) []byte {
	head := byte(0x08) | lvt
	if number < extendedTag {
		return []byte{head | byte(number)<<4}
	}
	return []byte{head | 0xF0, byte(number)}
}

// objid encodes an object identifier as the four octets of clause 20.2.14.
func objid(t ObjectType, instance uint32) []byte {
	return ObjectID{Type: t, Instance: instance}.Encode()
}

// u32 encodes an unsigned integer in as few octets as it needs, which is
// how BACnet encodes one.
func u32(v uint32) []byte {
	switch {
	case v <= 0xFF:
		return []byte{byte(v)}
	case v <= 0xFFFF:
		return []byte{byte(v >> 8), byte(v)}
	case v <= 0xFFFFFF:
		return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// readRequest is a whole readProperty datagram: the shape almost every
// test starts from.
func readRequest(o ObjectID, p PropertyID) []byte {
	params := append(ctx(0, o.Encode()...), ctx(1, u32(uint32(p))...)...)
	return bvlc(FuncOriginalUnicast, npdu(0x04), confirmed(ReadProperty, params...))
}

// parse runs a datagram through all three layers, which is what the relay
// does and therefore what the tests should exercise.
func parse(b []byte) (BVLC, NPDU, APDU, error) {
	v, err := ParseBVLC(b)
	if err != nil {
		return v, NPDU{}, APDU{}, err
	}
	if !v.Function.CarriesNPDU() {
		return v, NPDU{}, APDU{}, nil
	}
	n, err := ParseNPDU(v.Payload)
	if err != nil {
		return v, n, APDU{}, err
	}
	if n.NetworkMessage {
		return v, n, APDU{}, nil
	}
	a, err := ParseAPDU(n.APDU)
	return v, n, a, err
}
