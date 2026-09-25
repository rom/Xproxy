package s7

import (
	"encoding/binary"

	wire "github.com/rom/xproxy/internal/s7"
)

// The frames the tests are written with, so a test reads as the operation it
// is about rather than as a table of octets.

func be16b(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// tsap is the two octets a called TSAP puts a connection resource, a rack and
// a slot in.
func tsap(resource uint8, rack, slot int) []byte {
	return []byte{resource, uint8(rack<<5 | slot)}
}

// connectionRequest builds a COTP connection request naming a CPU.
func connectionRequest(resource uint8, rack, slot int) []byte {
	params := join([]byte{0xc0, 1, 0x0a},
		[]byte{0xc1, 2}, tsap(resource, 0, 0),
		[]byte{0xc2, 2}, tsap(resource, rack, slot))
	body := join(be16b(0), be16b(0x0100), []byte{0x00}, params)
	return tpkt(join([]byte{uint8(len(body) + 1), wire.COTPConnectionRequest}, body))
}

// connectionConfirm is what a PLC answers it with.
func connectionConfirm() []byte {
	body := join(be16b(0x0100), be16b(0x0002), []byte{0x00}, []byte{0xc0, 1, 0x0a})
	return tpkt(join([]byte{uint8(len(body) + 1), wire.COTPConnectionConfirm}, body))
}

// job builds a TPKT frame carrying an S7 job.
func job(ref uint16, param, data []byte) []byte {
	return tpktData(join([]byte{wire.ProtocolID, byte(wire.Job), 0, 0}, be16b(ref),
		be16b(uint16(len(param))), be16b(uint16(len(data))), param, data))
}

// ackData builds an acknowledgement, which is what the fake PLC answers with.
func ackData(ref uint16, errClass, errCode uint8, param, data []byte) []byte {
	return tpktData(join([]byte{wire.ProtocolID, byte(wire.AckData), 0, 0}, be16b(ref),
		be16b(uint16(len(param))), be16b(uint16(len(data))),
		[]byte{errClass, errCode}, param, data))
}

// userData builds a user-data request.
func userData(ref uint16, group, sub uint8) []byte {
	param := join([]byte{0x00, 0x01, 0x12, 0x04}, []byte{0x11, wire.UserRequest<<4 | group, sub, 0})
	return tpktData(join([]byte{wire.ProtocolID, byte(wire.Userdata), 0, 0}, be16b(ref),
		be16b(uint16(len(param))), be16b(0), param))
}

// item builds one S7ANY item specification, with the byte address an operator
// would write rather than the bit address the protocol carries.
func item(transport uint8, count, db uint16, area uint8, byteAddr int) []byte {
	bit := uint32(byteAddr) * 8
	return join([]byte{0x12, 0x0a, wire.SyntaxAny, transport}, be16b(count), be16b(db),
		[]byte{area, uint8(bit >> 16), uint8(bit >> 8), uint8(bit)})
}

// readJob and writeJob build the two operations a plant spends its day on.
func readJob(ref uint16, items ...[]byte) []byte {
	return job(ref, join([]byte{wire.FnReadVar, uint8(len(items))}, join(items...)), nil)
}

func writeJob(ref uint16, spec []byte, transport uint8, value []byte) []byte {
	n := len(value)
	if transport == wire.TransportBit || transport == wire.TransportByte {
		n *= 8
	}
	data := join([]byte{0x00, transport}, be16b(uint16(n)), value)
	if len(value)%2 != 0 {
		data = append(data, 0x00)
	}
	return job(ref, join([]byte{wire.FnWriteVar, 1}, spec), data)
}

// setupJob is the negotiation every connection begins with.
func setupJob(ref uint16, pduLength uint16) []byte {
	return job(ref, join([]byte{wire.FnSetupComm, 0}, be16b(1), be16b(1), be16b(pduLength)), nil)
}

// stopJob and controlJob are the two that stop a machine.
func stopJob(ref uint16) []byte {
	return job(ref, join([]byte{wire.FnPLCStop, 0, 0, 0, 0, 0, 9}, []byte("P_PROGRAM")), nil)
}

func controlJob(ref uint16, service string) []byte {
	block := []byte{0xfd, 0x00, 0x00}
	return job(ref, join([]byte{wire.FnPLCControl, 0, 0, 0, 0, 0, 0, 0},
		be16b(uint16(len(block))), block, []byte{uint8(len(service))}, []byte(service)), nil)
}

// downloadJob and uploadJob name a block.
func downloadJob(ref uint16, kind string, number int) []byte {
	return job(ref, join([]byte{wire.FnRequestDownload, 0, 0, 0, 0, 0, 0, 0},
		blockName(kind, number)), nil)
}

func uploadJob(ref uint16, kind string, number int) []byte {
	return job(ref, join([]byte{wire.FnStartUpload, 0, 0, 0, 0, 0, 0, 0},
		blockName(kind, number)), nil)
}

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
