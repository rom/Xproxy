package modbus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Every public function code, in both directions, in every framing.
//
// A relay that decides about frames has to be able to read all of them:
// a code it cannot parse is a code it cannot decide about, and the
// device behind it will read those bytes somehow. So each shape the
// specification defines is driven through the request parser, the
// response parser and all three framings, and the round trip is the
// property — what comes out of the reader is what went into the writer.
func TestEveryFunctionCodeRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name     string
		request  []byte
		response []byte
		// access is what the code does, which is what a read-only
		// listener decides on.
		access Access
	}{
		{"read coils", []byte{1, 0x00, 0x13, 0x00, 0x13},
			[]byte{1, 3, 0xCD, 0x6B, 0x05}, AccessRead},
		{"read discrete inputs", []byte{2, 0x00, 0xC4, 0x00, 0x16},
			[]byte{2, 3, 0xAC, 0xDB, 0x35}, AccessRead},
		{"read holding registers", []byte{3, 0x00, 0x6B, 0x00, 0x03},
			[]byte{3, 6, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64}, AccessRead},
		{"read input registers", []byte{4, 0x00, 0x08, 0x00, 0x01},
			[]byte{4, 2, 0x00, 0x0A}, AccessRead},
		{"write single coil", []byte{5, 0x00, 0xAC, 0xFF, 0x00},
			[]byte{5, 0x00, 0xAC, 0xFF, 0x00}, AccessWrite},
		{"write single register", []byte{6, 0x00, 0x01, 0x00, 0x03},
			[]byte{6, 0x00, 0x01, 0x00, 0x03}, AccessWrite},
		{"read exception status", []byte{7},
			[]byte{7, 0x6D}, AccessRead},
		{"diagnostic", []byte{8, 0x00, 0x00, 0xA5, 0x37},
			[]byte{8, 0x00, 0x00, 0xA5, 0x37}, AccessDiagnostic},
		{"get comm event counter", []byte{11},
			[]byte{11, 0xFF, 0xFF, 0x01, 0x08}, AccessDiagnostic},
		{"get comm event log", []byte{12},
			[]byte{12, 8, 0x00, 0x00, 0x01, 0x08, 0x01, 0x21, 0x20, 0x00}, AccessDiagnostic},
		{"write multiple coils", []byte{15, 0x00, 0x13, 0x00, 0x0A, 2, 0xCD, 0x01},
			[]byte{15, 0x00, 0x13, 0x00, 0x0A}, AccessWrite},
		{"write multiple registers", []byte{16, 0x00, 0x01, 0x00, 0x02, 4, 0x00, 0x0A, 0x01, 0x02},
			[]byte{16, 0x00, 0x01, 0x00, 0x02}, AccessWrite},
		{"report server id", []byte{17},
			[]byte{17, 3, 0x01, 0xFF, 0x00}, AccessIdentify},
		{"read file record", []byte{20, 7, 6, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02},
			[]byte{20, 6, 5, 6, 0x0D, 0xFE, 0x00, 0x20}, AccessRead},
		{"write file record", []byte{21, 9, 6, 0x00, 0x04, 0x00, 0x07, 0x00, 0x01, 0x06, 0xAF},
			[]byte{21, 9, 6, 0x00, 0x04, 0x00, 0x07, 0x00, 0x01, 0x06, 0xAF}, AccessWrite},
		{"mask write register", []byte{22, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25},
			[]byte{22, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25}, AccessWrite},
		{"read write multiple registers",
			[]byte{23, 0x00, 0x03, 0x00, 0x06, 0x00, 0x0E, 0x00, 0x03, 6, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF},
			[]byte{23, 12, 0x00, 0xFE, 0x0A, 0xCD, 0x00, 0x01, 0x00, 0x03, 0x00, 0x0D, 0x00, 0xFF}, AccessWrite},
		{"read fifo queue", []byte{24, 0x04, 0xDE},
			[]byte{24, 0x00, 0x06, 0x00, 0x02, 0x01, 0xB8, 0x12, 0x84}, AccessRead},
		{"encapsulated interface", []byte{43, 14, 0x01, 0x00},
			// Read Device Identification: the identification code, the
			// conformity level, more-follows, the object id a walk
			// resumes at, the number of objects, and the object itself.
			[]byte{43, 14, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 'A', 'C', 'M'}, AccessIdentify},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := ParseRequest(tc.request)
			if err != nil {
				t.Fatalf("request % x: %v", tc.request, err)
			}
			if req.Access != tc.access {
				t.Errorf("access %q, want %q", req.Access, tc.access)
			}
			if !req.Known {
				t.Error("a public function code is a known one")
			}
			if _, err := ParseResponse(tc.response, req); err != nil {
				t.Fatalf("response % x: %v", tc.response, err)
			}
			// Every framing carries every code, in both directions, and
			// what comes back out is what went in.
			for _, f := range []Framing{FramingTCP, FramingRTU, FramingASCII} {
				for _, dir := range []struct {
					request bool
					pdu     []byte
				}{{true, tc.request}, {false, tc.response}} {
					fr := &Frame{Transaction: 0x1234, Unit: 17, PDU: dir.pdu}
					raw := Encode(f, fr)
					rd := NewReader(bytes.NewReader(raw), f, dir.request)
					rd.Expect(tc.request[0])
					got, gotRaw, err := rd.ReadFrame()
					if err != nil {
						t.Fatalf("%s %v: %v", f, dir.request, err)
					}
					if !bytes.Equal(got.PDU, dir.pdu) {
						t.Fatalf("%s %v: pdu % x, want % x", f, dir.request, got.PDU, dir.pdu)
					}
					if got.Unit != 17 {
						t.Fatalf("%s: unit %d", f, got.Unit)
					}
					if !bytes.Equal(gotRaw, raw) {
						t.Fatalf("%s: the bytes the reader returns are not the bytes that arrived", f)
					}
				}
			}
		})
	}
}

// The shapes that must not parse. Each one is a field a device would act
// on, so a relay that let it through would be letting through what it
// could not decide about.
func TestTheShapesThatMustNotParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
	}{
		{"an empty pdu", nil},
		{"a read of no registers", []byte{3, 0x00, 0x00, 0x00, 0x00}},
		{"a read past the register bound", []byte{3, 0x00, 0x00, 0x00, 0x7E}},
		{"a read of coils past the bound", []byte{1, 0x00, 0x00, 0x07, 0xD1}},
		{"a read running past the address space", []byte{3, 0xFF, 0xFF, 0x00, 0x02}},
		{"a single coil value that is neither on nor off", []byte{5, 0x00, 0x01, 0x12, 0x34}},
		{"a write of no coils", []byte{15, 0x00, 0x00, 0x00, 0x00, 0, 0x00}},
		{"a coil byte count that does not match the quantity", []byte{15, 0x00, 0x00, 0x00, 0x0A, 3, 0x01, 0x02, 0x03}},
		{"a register byte count that does not match the quantity", []byte{16, 0x00, 0x00, 0x00, 0x02, 2, 0x00, 0x0A}},
		{"a write of more registers than one frame holds", []byte{16, 0x00, 0x00, 0x07, 0xB1, 2, 0x00, 0x0A}},
		{"a mask write missing a mask", []byte{22, 0x00, 0x04, 0x00, 0xF2}},
		{"a read-write whose write quantity is zero", []byte{23, 0x00, 0x03, 0x00, 0x06, 0x00, 0x0E, 0x00, 0x00, 0}},
		{"a fifo read with no address", []byte{24, 0x04}},
		{"a file record group that is not a multiple of seven", []byte{20, 8, 6, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00}},
		{"a file record of a reference type the specification does not have",
			[]byte{20, 7, 5, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02}},
		{"a file record number past the bound",
			[]byte{20, 7, 6, 0x00, 0x04, 0x99, 0x99, 0x00, 0x02}},
		{"a file record of no length", []byte{20, 7, 6, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}},
		{"a written file record whose values do not fit",
			[]byte{21, 9, 6, 0x00, 0x04, 0x00, 0x07, 0x00, 0x09, 0x06, 0xAF}},
		{"an encapsulated request with no mei type", []byte{43}},
		{"an mei type the specification does not have", []byte{43, 0x30, 0x00, 0x01}},
		{"an identification code outside the four defined", []byte{43, 14, 0x09, 0x00}},
		{"an identification request with a byte past its shape", []byte{43, 14, 0x01, 0x00, 0x00}},
		{"a diagnostic with no sub-function", []byte{8, 0x00}},
		{"a request carrying the exception bit", []byte{0x83, 0x02}},
		{"a function code the specification does not have", []byte{9, 0x00}},
		{"a request with data a code that takes none", []byte{7, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p, err := ParseRequest(tc.pdu); err == nil {
				t.Fatalf("parsed as %+v", p)
			}
		})
	}
}

// A response is read against the request it answers, because the wire
// form says how many bytes follow and not what they are.
func TestAResponseIsReadAgainstItsRequest(t *testing.T) {
	req, err := ParseRequest([]byte{3, 0x00, 0x6B, 0x00, 0x03})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		pdu  []byte
	}{
		{"a byte count that is not the quantity asked for", []byte{3, 4, 0, 1, 0, 2}},
		{"an odd byte count for registers", []byte{3, 5, 0, 1, 0, 2, 3}},
		{"a byte count that does not match the data", []byte{3, 6, 0, 1, 0, 2}},
		{"no byte count at all", []byte{3}},
		{"an exception with no code", []byte{0x83}},
		{"an exception carrying more than a code", []byte{0x83, 0x02, 0x00}},
		{"a response to a different function code", []byte{9, 6, 0, 1, 0, 2, 0, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if p, err := ParseResponse(tc.pdu, req); err == nil {
				t.Fatalf("parsed as %+v", p)
			}
		})
	}
	// A coil response is checked the same way, against the quantity the
	// request asked for rather than what the byte count claims.
	coilReq, err := ParseRequest([]byte{1, 0x00, 0x00, 0x00, 0x0A})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResponse([]byte{1, 1, 0xFF}, coilReq); err == nil {
		t.Error("a coil response one byte short of the quantity was accepted")
	}
	p, err := ParseResponse([]byte{1, 2, 0xFF, 0x03}, coilReq)
	if err != nil {
		t.Fatalf("a coil response: %v", err)
	}
	if len(p.Coils) != 10 || !p.Coils[0] || !p.Coils[9] {
		t.Errorf("coils %v", p.Coils)
	}
	// A fifo response's two length fields have to agree with each other.
	fifoReq, _ := ParseRequest([]byte{24, 0x04, 0xDE})
	for _, bad := range [][]byte{
		{24, 0x00, 0x06, 0x00, 0x03, 0x01, 0xB8, 0x12, 0x84},
		{24, 0x00, 0x08, 0x00, 0x02, 0x01, 0xB8, 0x12, 0x84},
		{24, 0x00, 0x42, 0x00, 0x20},
	} {
		if _, err := ParseResponse(bad, fifoReq); err == nil {
			t.Errorf("a fifo response whose lengths disagree was accepted: % x", bad)
		}
	}
}

// An exception response names its exception, because "the device refused
// it" is not something to put in a log when the code says which refusal.
func TestExceptionNames(t *testing.T) {
	for code, want := range map[byte]string{
		ExIllegalFunction:    "illegal_function",
		ExIllegalAddress:     "illegal_data_address",
		ExIllegalValue:       "illegal_data_value",
		ExServerFailure:      "server_device_failure",
		ExAcknowledge:        "acknowledge",
		ExServerBusy:         "server_device_busy",
		ExMemoryParity:       "memory_parity_error",
		ExGatewayPathUnavail: "gateway_path_unavailable",
		ExGatewayNoResponse:  "gateway_target_no_response",
	} {
		if got := ExceptionName(code); got != want {
			t.Errorf("exception %d is %q, want %q", code, got, want)
		}
	}
	if got := ExceptionName(0x42); got != "exception_66" {
		t.Errorf("an exception code nobody defined: %q", got)
	}
	// And a relay's own refusal is built the same way a device's is.
	p, err := ParseResponse(ExceptionPDU(FCReadHoldingRegisters, ExGatewayNoResponse), &PDU{Function: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsException || p.Exception != ExGatewayNoResponse || p.Function != FCReadHoldingRegisters {
		t.Errorf("exception pdu: %+v", p)
	}
}

// RTU has no start or end delimiter: a frame's length is computed from
// its function code and direction, and the CRC is the only proof the
// frame ended where the device will think it did. So the length rules
// are tested per code, in both directions, including the ones that read
// a counted body.
func TestRTULengthsAreComputedPerCodeAndDirection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request bool
		pdu     []byte
	}{
		{"a counted coil write request", true, []byte{15, 0x00, 0x13, 0x00, 0x0A, 2, 0xCD, 0x01}},
		{"a counted register write request", true, []byte{16, 0x00, 0x01, 0x00, 0x02, 4, 0x00, 0x0A, 0x01, 0x02}},
		{"a counted read-write request", true,
			[]byte{23, 0x00, 0x03, 0x00, 0x06, 0x00, 0x0E, 0x00, 0x03, 6, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF}},
		{"a counted file read request", true, []byte{20, 7, 6, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02}},
		{"a request that carries nothing", true, []byte{17}},
		{"a counted read response", false, []byte{3, 6, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64}},
		{"a fixed write response", false, []byte{16, 0x00, 0x01, 0x00, 0x02}},
		{"an exception response", false, []byte{0x83, 0x02}},
		{"a two-byte counted fifo response", false, []byte{24, 0x00, 0x06, 0x00, 0x02, 0x01, 0xB8, 0x12, 0x84}},
		{"a counted event log response", false, []byte{12, 8, 0x00, 0x00, 0x01, 0x08, 0x01, 0x21, 0x20, 0x00}},
		// Six fields before the object list: the MEI type, the
		// identification code, the conformity level, more-follows, the
		// object id a walk resumes at, and the number of objects.
		{"a walked identification response", false,
			[]byte{43, 14, 0x01, 0x01, 0xFF, 0x02, 0x02, 0x00, 0x03, 'A', 'C', 'M', 0x01, 0x02, 'v', '2'}},
		{"a comm event counter response", false, []byte{11, 0xFF, 0xFF, 0x01, 0x08}},
		{"an exception status response", false, []byte{7, 0x6D}},
		{"a diagnostic response", false, []byte{8, 0x00, 0x00, 0xA5, 0x37}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := Encode(FramingRTU, &Frame{Unit: 3, PDU: tc.pdu})
			// A second frame follows immediately: a length rule that is
			// wrong by a byte reads into it and the CRC says so.
			next := Encode(FramingRTU, &Frame{Unit: 3, PDU: []byte{0x87, 0x02}})
			rd := NewReader(bytes.NewReader(append(raw, next...)), FramingRTU, tc.request)
			rd.Expect(tc.pdu[0] &^ ExceptionBit)
			f, gotRaw, err := rd.ReadFrame()
			if err != nil {
				t.Fatalf("first frame: %v", err)
			}
			if !bytes.Equal(f.PDU, tc.pdu) || !bytes.Equal(gotRaw, raw) {
				t.Fatalf("pdu % x, want % x", f.PDU, tc.pdu)
			}
			if !tc.request {
				rd.Expect(7)
				if f, _, err := rd.ReadFrame(); err != nil || f.PDU[0] != 0x87 {
					t.Fatalf("the frame behind it: %v", err)
				}
			}
		})
	}
	// A fifo response claiming more than a PDU can hold is refused
	// before anything is read for it.
	var head [3]byte
	head[0] = 3
	head[1] = 24
	body := append(head[:2], 0x01, 0x00)
	rd := NewReader(bytes.NewReader(body), FramingRTU, false)
	if _, _, err := rd.ReadFrame(); err == nil {
		t.Error("a fifo byte count past the longest PDU was accepted")
	}
	// A response whose function code is not the one asked for cannot be
	// measured, so it is refused rather than guessed at.
	rd = NewReader(bytes.NewReader([]byte{3, 99, 0, 0}), FramingRTU, false)
	rd.Expect(3)
	if _, _, err := rd.ReadFrame(); err == nil {
		t.Error("a response to a request nobody made was accepted")
	}
}

// The framings' own refusals: the fields that say how long a frame is,
// and the checks that say it arrived whole.
func TestFramingRefusals(t *testing.T) {
	short := func(f Framing, b []byte, request bool) error {
		rd := NewReader(bytes.NewReader(b), f, request)
		rd.Expect(3)
		_, _, err := rd.ReadFrame()
		return err
	}
	// MBAP: the protocol identifier, the length field and a body that
	// stops early.
	if err := short(FramingTCP, []byte{0, 1, 0, 1, 0, 6, 1, 3, 0, 0, 0, 1}, true); !errors.Is(err, ErrProtocol) {
		t.Errorf("a protocol identifier that is not modbus: %v", err)
	}
	for _, length := range [][]byte{{0x00, 0x01}, {0x01, 0x00}} {
		b := append([]byte{0, 1, 0, 0}, length...)
		b = append(b, 1, 3, 0, 0, 0, 1)
		if err := short(FramingTCP, b, true); !errors.Is(err, ErrLength) {
			t.Errorf("length % x: %v", length, err)
		}
	}
	if err := short(FramingTCP, []byte{0, 1, 0, 0, 0, 6, 1, 3, 0}, true); err == nil {
		t.Error("a body that stops early was accepted")
	}
	// RTU: a CRC that does not match, and a frame that stops inside its
	// own body.
	raw := Encode(FramingRTU, &Frame{Unit: 1, PDU: []byte{3, 0x00, 0x00, 0x00, 0x01}})
	raw[len(raw)-1] ^= 0xFF
	if err := short(FramingRTU, raw, true); !errors.Is(err, ErrChecksum) {
		t.Errorf("a bad crc: %v", err)
	}
	if err := short(FramingRTU, []byte{1, 3, 0x00}, true); err == nil {
		t.Error("an rtu frame that stops inside its body was accepted")
	}
	// ASCII: a character that is not hexadecimal, an odd number of
	// them, a frame with nothing in it, a bad LRC and a line with no
	// ending.
	for _, tc := range []struct {
		name string
		line string
	}{
		{"a character that is not hexadecimal", ":01030000000Iz\r\n"},
		{"an odd number of characters", ":01030000000\r\n"},
		{"a frame with nothing in it", ":\r\n"},
		{"a frame that is only an address", ":01F0\r\n"},
		{"a line that never ends", ":010300000001F8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := short(FramingASCII, []byte(tc.line), true); err == nil {
				t.Error("accepted")
			}
		})
	}
	bad := []byte(":010300000001F8\r\n")
	bad[13] = '0' // break the LRC
	if err := short(FramingASCII, bad, true); !errors.Is(err, ErrChecksum) {
		t.Errorf("a bad lrc: %v", err)
	}
	// A line ending before the start character is the gap between
	// frames; anything else before it is not part of a frame at all,
	// and a reader that skipped over it would be resyncing on somebody
	// else's bytes.
	good := Encode(FramingASCII, &Frame{Unit: 1, PDU: []byte{3, 0x00, 0x00, 0x00, 0x01}})
	rd := NewReader(bytes.NewReader(append([]byte("\r\n\r\n"), good...)), FramingASCII, true)
	if f, _, err := rd.ReadFrame(); err != nil || f.Unit != 1 {
		t.Errorf("a frame after the gap between frames: %v", err)
	}
	if err := short(FramingASCII, append([]byte("noise"), good...), true); !errors.Is(err, ErrFormat) {
		t.Errorf("bytes that are not a frame before one: %v", err)
	}
	// A framing name that is not one.
	if _, err := FramingOf("serial"); err == nil {
		t.Error("a framing nobody implements was accepted")
	}
}

// FuzzReadFrame drives each framing with whatever bytes arrive. The
// property is the one a relay rests on: a frame that reads has bytes
// that re-encode to themselves, so the frame the device is sent is the
// frame the policy decided about.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 0, 6, 1, 3, 0x00, 0x6B, 0x00, 0x03})
	f.Add([]byte{0x11, 0x03, 0x00, 0x6B, 0x00, 0x03, 0x76, 0x87})
	f.Add([]byte(":0103006B00037E\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, framing := range []Framing{FramingTCP, FramingRTU, FramingASCII} {
			for _, request := range []bool{true, false} {
				rd := NewReader(bytes.NewReader(data), framing, request)
				rd.Expect(FCReadHoldingRegisters)
				fr, raw, err := rd.ReadFrame()
				if err != nil {
					continue
				}
				if len(fr.PDU) < MinPDU || len(fr.PDU) > MaxPDU {
					t.Fatalf("%s: a frame whose pdu is %d bytes", framing, len(fr.PDU))
				}
				if len(raw) > MaxADU+16 {
					t.Fatalf("%s: %d raw bytes for one frame", framing, len(raw))
				}
				again := Encode(framing, fr)
				if framing == FramingTCP && !bytes.Equal(again, raw) {
					t.Fatalf("%s: re-encoding changed the frame:\n % x\n % x", framing, raw, again)
				}
				// Whatever the framing, what re-encodes has to read
				// back to the same frame, or a bridged relay would be
				// saying something else to the device.
				rd2 := NewReader(bytes.NewReader(again), framing, request)
				rd2.Expect(FCReadHoldingRegisters)
				back, _, err := rd2.ReadFrame()
				if err != nil {
					t.Fatalf("%s: a re-encoded frame does not read: %v", framing, err)
				}
				if !bytes.Equal(back.PDU, fr.PDU) || back.Unit != fr.Unit {
					t.Fatalf("%s: round trip changed the frame", framing)
				}
			}
		}
	})
}

// FuzzParseRequest drives the PDU parser. A request that parses has to
// have the fields a policy decides on, and those fields have to be
// inside the protocol's own bounds -- because a policy that compared a
// register range that ran past the address space would be deciding about
// a request the device cannot serve.
func FuzzParseRequest(f *testing.F) {
	f.Add([]byte{3, 0x00, 0x6B, 0x00, 0x03})
	f.Add([]byte{16, 0x00, 0x01, 0x00, 0x02, 4, 0x00, 0x0A, 0x01, 0x02})
	f.Add([]byte{23, 0x00, 0x03, 0x00, 0x06, 0x00, 0x0E, 0x00, 0x03, 6, 0, 1, 0, 2, 0, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseRequest(data)
		if err != nil {
			return
		}
		if p.IsException {
			t.Fatal("a request parsed as an exception response")
		}
		if p.Function&ExceptionBit != 0 {
			t.Fatalf("a request whose function code carries the exception bit: %d", p.Function)
		}
		if p.HasRange {
			last, ok := p.Last()
			if !ok {
				t.Fatalf("a request with a range whose end is not a number: %+v", p)
			}
			if int(last) < int(p.Address) {
				t.Fatalf("a range that runs backwards: %d..%d", p.Address, last)
			}
		}
		if _, ok := functions[p.Function]; !ok && !userDefined(p.Function) {
			t.Fatalf("a function code that is neither public nor user defined: %d", p.Function)
		}
		// What parsed has to survive being written and read again.
		for _, framing := range []Framing{FramingTCP, FramingRTU, FramingASCII} {
			raw := Encode(framing, &Frame{Unit: 1, PDU: data})
			rd := NewReader(bytes.NewReader(raw), framing, true)
			fr, _, err := rd.ReadFrame()
			if err != nil {
				// RTU cannot frame every PDU shape -- the length rules
				// are per code -- and that is a refusal, not a bug.
				continue
			}
			if !bytes.Equal(fr.PDU, data) {
				t.Fatalf("%s: a request that parsed came back different", framing)
			}
		}
	})
}

// FuzzParseResponse drives the response parser against a real request,
// because a response is only readable against the request it answers.
func FuzzParseResponse(f *testing.F) {
	f.Add([]byte{3, 6, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64})
	f.Add([]byte{0x83, 0x02})
	f.Add([]byte{1, 2, 0xCD, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, reqPDU := range [][]byte{
			{3, 0x00, 0x6B, 0x00, 0x03},
			{1, 0x00, 0x00, 0x00, 0x0A},
			{16, 0x00, 0x01, 0x00, 0x02, 4, 0x00, 0x0A, 0x01, 0x02},
			{24, 0x04, 0xDE},
		} {
			req, err := ParseRequest(reqPDU)
			if err != nil {
				t.Fatalf("the seed request does not parse: %v", err)
			}
			p, err := ParseResponse(data, req)
			if err != nil {
				continue
			}
			if p.IsException {
				if p.Function&ExceptionBit != 0 {
					t.Fatal("an exception's function code kept the exception bit")
				}
				continue
			}
			// A read response's values are the quantity that was asked
			// for, never more: that is what stops a relay handing a
			// master data the request did not cover.
			if len(p.Registers) > 0 && p.Function == req.Function && req.Access == AccessRead {
				if len(p.Registers) != int(req.Quantity) {
					t.Fatalf("%d registers for a request of %d", len(p.Registers), req.Quantity)
				}
			}
			if len(p.Coils) > 0 && p.Function == req.Function {
				if len(p.Coils) != int(req.Quantity) {
					t.Fatalf("%d coils for a request of %d", len(p.Coils), req.Quantity)
				}
			}
		}
	})
}

// The quantity bounds are the specification's own, and they are what a
// max_quantity rule narrows rather than replaces.
func TestTheProtocolsOwnBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
		ok   bool
	}{
		{"2000 coils", coilRead(2000), true},
		{"2001 coils", coilRead(2001), false},
		{"125 registers", regRead(125), true},
		{"126 registers", regRead(126), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRequest(tc.pdu)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func coilRead(n int) []byte {
	b := []byte{1, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[3:], uint16(n)) //nolint:gosec // a test builds the field it is testing
	return b
}

func regRead(n int) []byte {
	b := []byte{3, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[3:], uint16(n)) //nolint:gosec // a test builds the field it is testing
	return b
}
