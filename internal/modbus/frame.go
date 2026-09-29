package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Framing is how a Modbus frame is delimited on a stream.
//
// Modbus/TCP has a length field and is unambiguous. The other two are
// serial framings tunnelled over TCP by terminal servers and by every
// "Modbus gateway" ever sold, and they are ambiguous on a stream: RTU
// delimits by silence, which TCP does not carry, and ASCII delimits by
// a line ending inside a hexadecimal alphabet. This package reads them
// by length, computed from the function code, and validates the
// checksum -- which is the only way to know a frame ended where the
// device will think it ended.
type Framing int

const (
	// FramingTCP is Modbus/TCP: the MBAP header and its length field.
	FramingTCP Framing = iota
	// FramingRTU is an RTU frame on a stream: address, function, data,
	// CRC-16.
	FramingRTU
	// FramingASCII is an ASCII frame: ':', hexadecimal, LRC, CRLF.
	FramingASCII
)

// FramingOf reads a framing name as the configuration spells it.
func FramingOf(s string) (Framing, error) {
	switch s {
	case "", "tcp":
		return FramingTCP, nil
	case "rtu":
		return FramingRTU, nil
	case "ascii":
		return FramingASCII, nil
	}
	return 0, fmt.Errorf("modbus framing %q", s)
}

// String names a framing.
func (f Framing) String() string {
	switch f {
	case FramingRTU:
		return "rtu"
	case FramingASCII:
		return "ascii"
	}
	return "tcp"
}

// Frame is one application data unit: who it is for, what transaction
// it belongs to, and the PDU.
type Frame struct {
	// Transaction is the MBAP transaction identifier. RTU and ASCII
	// have no such field, and it is zero there -- which is why a relay
	// bridging them has to keep one request in flight at a time.
	Transaction uint16
	// Unit is the unit identifier (MBAP) or the slave address (RTU and
	// ASCII). It is the same field for policy: which device the frame
	// is for.
	Unit byte
	// PDU is the function code and its data.
	PDU []byte
}

// Errors the framing returns.
var (
	// ErrProtocol is an MBAP header whose protocol identifier is not
	// zero: not Modbus/TCP, whatever else it may be.
	ErrProtocol = errors.New("modbus: not protocol 0")
	// ErrLength is a length field outside what the specification
	// allows.
	ErrLength = errors.New("modbus: bad frame length")
	// ErrChecksum is an RTU CRC or an ASCII LRC that does not match.
	ErrChecksum = errors.New("modbus: checksum mismatch")
	// ErrFormat is an ASCII frame that is not one.
	ErrFormat = errors.New("modbus: bad ascii frame")
)

// Reader reads frames from a stream in one framing.
type Reader struct {
	r   io.Reader
	f   Framing
	buf []byte
	// request says which direction this reader reads, because the
	// expected length of an RTU frame depends on it: a read request is
	// fixed, a read response is counted.
	request bool
	// pending is the function code of the request a response reader is
	// waiting for, needed to compute an RTU response's length for the
	// fixed-length codes.
	pending byte
}

// NewReader reads frames arriving from a master (request=true) or from
// a slave (request=false).
func NewReader(r io.Reader, f Framing, request bool) *Reader {
	return &Reader{r: r, f: f, request: request, buf: make([]byte, 0, MaxADU)}
}

// Expect tells a response reader which function code the outstanding
// request used. It is how the RTU reader knows how long a fixed-length
// response is.
func (rd *Reader) Expect(fc byte) { rd.pending = fc }

// ReadFrame reads one frame. It returns the parsed frame and the bytes
// it came in, because a relay that forwards what it read has to forward
// exactly those bytes: re-encoding a frame is how a relay and a device
// come to disagree about what was said.
func (rd *Reader) ReadFrame() (*Frame, []byte, error) {
	switch rd.f {
	case FramingRTU:
		return rd.readRTU()
	case FramingASCII:
		return rd.readASCII()
	}
	return rd.readTCP()
}

func (rd *Reader) readTCP() (*Frame, []byte, error) {
	var head [HeaderLen]byte
	if _, err := io.ReadFull(rd.r, head[:]); err != nil {
		return nil, nil, err
	}
	if binary.BigEndian.Uint16(head[2:]) != ProtocolID {
		return nil, nil, ErrProtocol
	}
	length := int(binary.BigEndian.Uint16(head[4:]))
	// The length covers the unit identifier and the PDU, so it is at
	// least two and at most the longest PDU plus one.
	if length < 2 || length > MaxPDU+1 {
		return nil, nil, ErrLength
	}
	body := make([]byte, length-1)
	if _, err := io.ReadFull(rd.r, body); err != nil {
		return nil, nil, err
	}
	raw := make([]byte, 0, HeaderLen+len(body))
	raw = append(raw, head[:]...)
	raw = append(raw, body...)
	return &Frame{
		Transaction: binary.BigEndian.Uint16(head[:]),
		Unit:        head[6],
		PDU:         raw[HeaderLen:],
	}, raw, nil
}

// readRTU reads an RTU frame by computing its length from the function
// code. There is no other way on a stream: the silent interval that
// delimits an RTU frame on a serial line does not survive TCP, and a
// reader that guessed would hand the device a frame that starts in the
// middle of the last one.
func (rd *Reader) readRTU() (*Frame, []byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(rd.r, head); err != nil {
		return nil, nil, err
	}
	fc := head[1]
	n, err := rtuRemaining(rd.r, fc, rd.request, rd.pending)
	if err != nil {
		return nil, nil, err
	}
	raw := make([]byte, 0, 2+n.prefix+n.body+2)
	raw = append(raw, head...)
	raw = append(raw, n.read...)
	rest := make([]byte, n.body+2) // the data plus the CRC
	if _, err := io.ReadFull(rd.r, rest); err != nil {
		return nil, nil, err
	}
	raw = append(raw, rest...)
	if len(raw) < 4 || len(raw) > MaxPDU+3 {
		return nil, nil, ErrLength
	}
	want := binary.LittleEndian.Uint16(raw[len(raw)-2:])
	if CRC16(raw[:len(raw)-2]) != want {
		return nil, nil, ErrChecksum
	}
	return &Frame{Unit: raw[0], PDU: raw[1 : len(raw)-2]}, raw, nil
}

// rtuLen is what the length computation read while working it out.
type rtuLen struct {
	// read are the bytes consumed past the address and function code
	// (a byte count, for the counted shapes).
	read []byte
	// prefix is len(read); body is what is still to come, without the
	// CRC.
	prefix, body int
}

// rtuRemaining works out how much of an RTU frame is left. The counted
// shapes carry their own byte count, which is read here so it can be
// believed once and checked by the CRC afterwards.
func rtuRemaining(r io.Reader, fc byte, request bool, pending byte) (rtuLen, error) {
	counted := func() (rtuLen, error) {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return rtuLen{}, err
		}
		return rtuLen{read: b[:], prefix: 1, body: int(b[0])}, nil
	}
	if fc&ExceptionBit != 0 {
		// An exception response: one byte of exception code.
		return rtuLen{body: 1}, nil
	}
	if request {
		switch fc {
		case FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters, FCReadInputRegisters,
			FCWriteSingleCoil, FCWriteSingleRegister:
			return rtuLen{body: 4}, nil
		case FCReadExceptionStatus, FCGetCommEventCounter, FCGetCommEventLog, FCReportServerID:
			return rtuLen{}, nil
		case FCMaskWriteRegister:
			return rtuLen{body: 6}, nil
		case FCReadFIFOQueue:
			return rtuLen{body: 2}, nil
		case FCWriteMultipleCoils, FCWriteMultipleRegisters:
			// Address, quantity, then a counted body.
			pre := make([]byte, 5)
			if _, err := io.ReadFull(r, pre); err != nil {
				return rtuLen{}, err
			}
			return rtuLen{read: pre, prefix: 5, body: int(pre[4])}, nil
		case FCReadWriteMultiple:
			pre := make([]byte, 9)
			if _, err := io.ReadFull(r, pre); err != nil {
				return rtuLen{}, err
			}
			return rtuLen{read: pre, prefix: 9, body: int(pre[8])}, nil
		case FCReadFileRecord, FCWriteFileRecord:
			return counted()
		case FCDiagnostic:
			// Sub-function and one data word: the diagnostic requests
			// the specification defines are all four bytes.
			return rtuLen{body: 4}, nil
		case FCEncapsulatedInterface:
			// Read Device Identification (MEI type 14) is three bytes:
			// the type, the identification code and the object id. A
			// CANopen request (MEI type 13) carries whatever CANopen
			// carries, which this framing cannot measure, so it is
			// refused rather than guessed at.
			var mei [1]byte
			if _, err := io.ReadFull(r, mei[:]); err != nil {
				return rtuLen{}, err
			}
			if mei[0] != 14 {
				return rtuLen{}, ErrUnknownFunction
			}
			return rtuLen{read: mei[:], prefix: 1, body: 2}, nil
		}
		return rtuLen{}, ErrUnknownFunction
	}
	switch fc {
	case FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters, FCReadInputRegisters,
		FCReadWriteMultiple, FCReadFileRecord, FCWriteFileRecord, FCReportServerID:
		return counted()
	case FCWriteSingleCoil, FCWriteSingleRegister, FCWriteMultipleCoils, FCWriteMultipleRegisters:
		return rtuLen{body: 4}, nil
	case FCMaskWriteRegister:
		return rtuLen{body: 6}, nil
	case FCReadExceptionStatus:
		return rtuLen{body: 1}, nil
	case FCGetCommEventCounter:
		return rtuLen{body: 4}, nil
	case FCDiagnostic:
		return rtuLen{body: 4}, nil
	case FCReadFIFOQueue:
		// A two-byte byte count, then that many bytes.
		pre := make([]byte, 2)
		if _, err := io.ReadFull(r, pre); err != nil {
			return rtuLen{}, err
		}
		n := int(binary.BigEndian.Uint16(pre))
		if n > MaxPDU {
			return rtuLen{}, ErrLength
		}
		return rtuLen{read: pre, prefix: 2, body: n}, nil
	case FCGetCommEventLog:
		return counted()
	case FCEncapsulatedInterface:
		// Read Device Identification (MEI type 14) answers with a list
		// of objects, each carrying its own length, and no byte count
		// over the whole of it. Walking the list is the only way to
		// know where the frame ends -- and a CANopen answer (MEI type
		// 13) carries whatever CANopen carries, which this framing
		// cannot measure at all, so it is refused rather than guessed.
		//
		// Six fields come before the list, and all six have to be read
		// here: the MEI type, the identification code, the conformity
		// level, more-follows, the object id a walk resumes at, and
		// only then the number of objects (section 6.21). Reading five
		// of them takes the resume point for the count, which on the
		// ordinary answer -- more-follows nought, resume nought -- is
		// a frame that ends five bytes in with the objects still on
		// the wire, and the device's answer becomes a malformed one.
		head := make([]byte, 6)
		if _, err := io.ReadFull(r, head); err != nil {
			return rtuLen{}, err
		}
		if head[0] != 14 {
			return rtuLen{}, ErrUnknownFunction
		}
		out := head
		for i := 0; i < int(head[5]); i++ {
			pair := make([]byte, 2)
			if _, err := io.ReadFull(r, pair); err != nil {
				return rtuLen{}, err
			}
			val := make([]byte, int(pair[1]))
			if _, err := io.ReadFull(r, val); err != nil {
				return rtuLen{}, err
			}
			out = append(out, pair...)
			out = append(out, val...)
			if len(out) > MaxPDU {
				return rtuLen{}, ErrLength
			}
		}
		return rtuLen{read: out, prefix: len(out)}, nil
	}
	if pending != 0 && pending != fc {
		// A response to a request that was not made: the length cannot
		// be worked out and the frame cannot be believed.
		return rtuLen{}, ErrUnknownFunction
	}
	return rtuLen{}, ErrUnknownFunction
}

// readASCII reads an ASCII frame: ':' then hexadecimal pairs then the
// LRC then CRLF (Modbus over Serial Line v1.02 section 2.5.2).
func (rd *Reader) readASCII() (*Frame, []byte, error) {
	// Skip to the start character. Anything before it is not part of a
	// frame, and a reader that treated it as one would resync on
	// somebody else's bytes.
	var b [1]byte
	for {
		if _, err := io.ReadFull(rd.r, b[:]); err != nil {
			return nil, nil, err
		}
		if b[0] == ':' {
			break
		}
		if b[0] != '\r' && b[0] != '\n' {
			return nil, nil, ErrFormat
		}
	}
	line := make([]byte, 0, MaxADU*2+4)
	line = append(line, ':')
	for {
		if _, err := io.ReadFull(rd.r, b[:]); err != nil {
			return nil, nil, err
		}
		line = append(line, b[0])
		if b[0] == '\n' {
			break
		}
		if len(line) > MaxADU*2+4 {
			return nil, nil, ErrLength
		}
	}
	body := line[1 : len(line)-1]
	if len(body) < 1 || body[len(body)-1] != '\r' {
		return nil, nil, ErrFormat
	}
	body = body[:len(body)-1]
	if len(body)%2 != 0 || len(body) < 6 {
		return nil, nil, ErrFormat
	}
	raw := make([]byte, len(body)/2)
	if _, err := hex.Decode(raw, upperHex(body)); err != nil {
		return nil, nil, ErrFormat
	}
	if LRC(raw[:len(raw)-1]) != raw[len(raw)-1] {
		return nil, nil, ErrChecksum
	}
	return &Frame{Unit: raw[0], PDU: raw[1 : len(raw)-1]}, line, nil
}

// upperHex accepts either case, which devices mix.
func upperHex(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// Encode writes a frame in one framing. It is used for the frames this
// relay originates -- an exception it answers itself, or a request
// bridged from one framing to another -- and never to re-encode a frame
// it is forwarding unchanged.
func Encode(f Framing, fr *Frame) []byte {
	switch f {
	case FramingRTU:
		out := make([]byte, 0, 1+len(fr.PDU)+2)
		out = append(out, fr.Unit)
		out = append(out, fr.PDU...)
		return binary.LittleEndian.AppendUint16(out, CRC16(out))
	case FramingASCII:
		body := make([]byte, 0, 1+len(fr.PDU)+1)
		body = append(body, fr.Unit)
		body = append(body, fr.PDU...)
		body = append(body, LRC(body))
		out := make([]byte, 0, len(body)*2+3)
		out = append(out, ':')
		dst := make([]byte, hex.EncodedLen(len(body)))
		hex.Encode(dst, body)
		out = append(out, upperHex(dst)...)
		return append(out, '\r', '\n')
	}
	out := make([]byte, HeaderLen, HeaderLen+len(fr.PDU))
	binary.BigEndian.PutUint16(out, fr.Transaction)
	binary.BigEndian.PutUint16(out[2:], ProtocolID)
	binary.BigEndian.PutUint16(out[4:], uint16(len(fr.PDU)+1)) //nolint:gosec // bounded by MaxPDU
	out[6] = fr.Unit
	return append(out, fr.PDU...)
}

// CRC16 is the Modbus RTU checksum: the reversed CRC-16/IBM with an
// initial value of 0xFFFF, sent low byte first.
func CRC16(b []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, c := range b {
		crc ^= uint16(c)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// LRC is the Modbus ASCII checksum: the two's complement of the sum of
// the frame's bytes.
func LRC(b []byte) byte {
	var sum byte
	for _, c := range b {
		sum += c
	}
	return -sum
}
