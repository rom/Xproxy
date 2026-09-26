package s7

import "encoding/binary"

// The frames the tests are written with. They are willing to build a
// malformed one, because most of what is tested here is what this package
// does with one.

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// tpkt wraps a payload in a TPKT header whose length is correct.
func tpkt(payload []byte) []byte {
	return cat([]byte{TPKTVersion, 0}, be16(uint16(TPKTHeader+len(payload))), payload)
}

// cotpData wraps an S7 PDU in a COTP data PDU.
func cotpData(s7 []byte) []byte {
	return cat([]byte{0x02, COTPData, 0x80}, s7)
}

// cotpCR builds a connection request with a TPDU size and two TSAPs.
func cotpCR(dst, src uint16, tpdu uint8, calling, called []byte) []byte {
	params := cat([]byte{paramTPDUSize, 1, tpdu},
		[]byte{paramCalling, uint8(len(calling))}, calling,
		[]byte{paramCalled, uint8(len(called))}, called)
	body := cat(be16(dst), be16(src), []byte{0x00}, params)
	return cat([]byte{uint8(len(body) + 1), COTPConnectionRequest}, body)
}

// tsap is the two octets Siemens puts a connection resource, a rack and a
// slot in.
func tsap(resource uint8, rack, slot int) []byte {
	return []byte{resource, uint8(rack<<5 | slot)}
}

// s7job builds a job PDU: a parameter half and a data half.
func s7job(ref uint16, param, data []byte) []byte {
	return cat([]byte{ProtocolID, uint8(Job), 0, 0}, be16(ref),
		be16(uint16(len(param))), be16(uint16(len(data))), param, data)
}

// s7ack builds an acknowledgement with its error octets.
func s7ack(ref uint16, errClass, errCode uint8, param, data []byte) []byte {
	return cat([]byte{ProtocolID, uint8(AckData), 0, 0}, be16(ref),
		be16(uint16(len(param))), be16(uint16(len(data))),
		[]byte{errClass, errCode}, param, data)
}

// s7user builds a user-data PDU.
func s7user(ref uint16, method, typeGroup, sub, seq uint8, data []byte) []byte {
	param := cat([]byte{0x00, 0x01, 0x12, 0x04}, []byte{method, typeGroup, sub, seq})
	return cat([]byte{ProtocolID, uint8(Userdata), 0, 0}, be16(ref),
		be16(uint16(len(param))), be16(uint16(len(data))), param, data)
}

// itemSpec builds one S7ANY item specification.
func itemSpec(transport uint8, count, db uint16, area uint8, bit uint32) []byte {
	return cat([]byte{0x12, 0x0a, SyntaxAny, transport}, be16(count), be16(db),
		[]byte{area, uint8(bit >> 16), uint8(bit >> 8), uint8(bit)})
}

// readParam builds a read or write job's parameter half.
func readParam(fn uint8, items ...[]byte) []byte {
	return cat([]byte{fn, uint8(len(items))}, cat(items...))
}

// dataItem builds one data item of a write job's data half, with the fill
// octet the protocol puts after an odd length.
func dataItem(transport uint8, value []byte) []byte {
	n := len(value)
	if transport == TransportBit || transport == TransportByte || transport == TransportChar {
		n *= 8
	}
	out := cat([]byte{0x00, transport}, be16(uint16(n)), value)
	if len(value)%2 != 0 {
		out = append(out, 0x00)
	}
	return out
}

// blockName is the nine-character filename a download or upload names a
// block with.
func blockName(kind string, number int) []byte {
	out := []byte{'_'}
	out = append(out, kind...)
	num := []byte{'0', '0', '0', '0', '0'}
	for i := 4; i >= 0 && number > 0; i-- {
		num[i] = byte('0' + number%10)
		number /= 10
	}
	out = append(out, num...)
	return append(out, 'P')
}
