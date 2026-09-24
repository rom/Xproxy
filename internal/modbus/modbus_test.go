package modbus

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Every field a policy decides on is read out of the frame, so every
// field a policy decides on is tested against the specification's own
// bounds rather than against this implementation's idea of them.
func TestARequestIsReadAsTheSpecificationWritesIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
		want PDU
	}{
		{"read coils", []byte{1, 0x00, 0x13, 0x00, 0x13},
			PDU{Function: 1, Access: AccessRead, Known: true, Address: 0x13, Quantity: 0x13, HasRange: true}},
		{"read holding registers", []byte{3, 0x00, 0x6B, 0x00, 0x03},
			PDU{Function: 3, Access: AccessRead, Known: true, Address: 0x6B, Quantity: 3, HasRange: true}},
		{"write single coil on", []byte{5, 0x00, 0xAC, 0xFF, 0x00},
			PDU{Function: 5, Access: AccessWrite, Known: true, Address: 0xAC, Quantity: 1, HasRange: true}},
		{"write single register", []byte{6, 0x00, 0x01, 0x00, 0x03},
			PDU{Function: 6, Access: AccessWrite, Known: true, Address: 1, Quantity: 1, HasRange: true}},
		{"mask write register", []byte{22, 0x00, 0x04, 0x00, 0xF2, 0x00, 0x25},
			PDU{Function: 22, Access: AccessWrite, Known: true, Address: 4, Quantity: 1, HasRange: true}},
		{"read fifo queue", []byte{24, 0x04, 0xDE},
			PDU{Function: 24, Access: AccessRead, Known: true, Address: 0x04DE, Quantity: 1, HasRange: true}},
	} {
		got, err := ParseRequest(tc.pdu)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got.Function != tc.want.Function || got.Access != tc.want.Access ||
			got.Address != tc.want.Address || got.Quantity != tc.want.Quantity ||
			got.HasRange != tc.want.HasRange {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// The worked example from the specification, both halves: a write of two
// registers and the response that echoes the range.
func TestTheWriteExampleFromTheSpecification(t *testing.T) {
	req := []byte{16, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02}
	p, err := ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Address != 1 || p.Quantity != 2 || p.ByteCount != 4 {
		t.Fatalf("%+v", p)
	}
	if len(p.Registers) != 2 || p.Registers[0] != 0x000A || p.Registers[1] != 0x0102 {
		t.Errorf("registers %v", p.Registers)
	}
	if !p.Writes() {
		t.Error("a write of two registers does not read as a write")
	}
	resp, err := ParseResponse([]byte{16, 0x00, 0x01, 0x00, 0x02}, p)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Address != 1 || resp.Quantity != 2 {
		t.Errorf("response %+v", resp)
	}
}

// A read response's shape comes from the request: the wire form says how
// many bytes follow and not what they are, so a relay that lost the
// request cannot read the answer.
func TestAReadResponseIsReadAgainstItsRequest(t *testing.T) {
	req, err := ParseRequest([]byte{3, 0x00, 0x6B, 0x00, 0x03})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ParseResponse([]byte{3, 6, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64}, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Registers) != 3 || resp.Registers[0] != 0x022B || resp.Registers[2] != 100 {
		t.Errorf("registers %v", resp.Registers)
	}
	// A byte count that does not match the quantity asked for is a
	// response the master and this relay would read differently.
	if _, err := ParseResponse([]byte{3, 4, 0x02, 0x2B, 0x00, 0x00}, req); !errors.Is(err, ErrBounds) {
		t.Errorf("a short answer: %v", err)
	}
	coilReq, _ := ParseRequest([]byte{1, 0x00, 0x13, 0x00, 0x13})
	coils, err := ParseResponse([]byte{1, 3, 0xCD, 0x6B, 0x05}, coilReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(coils.Coils) != 19 || !coils.Coils[0] || coils.Coils[1] {
		t.Errorf("coils %v", coils.Coils)
	}
}

// An exception response is a refusal the master understands, and it is
// read as one rather than as a function code nobody implements.
func TestAnExceptionResponseIsReadAsARefusal(t *testing.T) {
	req, _ := ParseRequest([]byte{3, 0x00, 0x6B, 0x00, 0x03})
	resp, err := ParseResponse([]byte{0x83, 0x02}, req)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsException || resp.Function != 3 || resp.Exception != ExIllegalAddress {
		t.Fatalf("%+v", resp)
	}
	if got := ExceptionName(resp.Exception); got != "illegal_data_address" {
		t.Errorf("name %q", got)
	}
	if got := ExceptionPDU(3, ExIllegalFunction); !bytes.Equal(got, []byte{0x83, 0x01}) {
		t.Errorf("built %x", got)
	}
	// A request carrying the exception bit is a response arriving where
	// a request belongs.
	if _, err := ParseRequest([]byte{0x83, 0x02}); !errors.Is(err, ErrBounds) {
		t.Errorf("an exception as a request: %v", err)
	}
}

// What a malformed frame is, each named. Every one of these is a bound
// the device would have to check itself, and the ones firmware forgets
// are exactly these.
func TestAMalformedRequestIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		name string
		pdu  []byte
		want error
	}{
		{"empty", nil, ErrShort},
		{"read with no fields", []byte{3}, ErrShort},
		{"read of zero registers", []byte{3, 0, 1, 0, 0}, ErrBounds},
		{"read of 126 registers", []byte{3, 0, 1, 0, 126}, ErrBounds},
		{"read of 2001 coils", []byte{1, 0, 1, 0x07, 0xD1}, ErrBounds},
		{"write single coil with an invented value", []byte{5, 0, 1, 0x12, 0x34}, ErrBounds},
		{"write multiple registers with a byte count that lies", []byte{16, 0, 1, 0, 2, 2, 0, 10}, ErrBounds},
		{"write multiple registers with data past the count", []byte{16, 0, 1, 0, 1, 2, 0, 10, 0, 11}, ErrBounds},
		{"write multiple coils with the wrong byte count", []byte{15, 0, 1, 0, 10, 1, 0xFF}, ErrBounds},
		{"read/write with a write quantity of zero", []byte{23, 0, 1, 0, 1, 0, 2, 0, 0, 0}, ErrBounds},
		{"read exception status with data", []byte{7, 0}, ErrBounds},
		{"a reserved function code", []byte{9, 0, 1}, ErrUnknownFunction},
		{"a file record with a reference type nobody uses", []byte{20, 7, 5, 0, 4, 0, 1, 0, 2}, ErrBounds},
		{"a pdu over the bound", append([]byte{3}, make([]byte, MaxPDU)...), ErrBounds},
	} {
		_, err := ParseRequest(tc.pdu)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// A range that wraps past the end of the address space is not a range,
// and a policy written about addresses must not be walked around with
// one.
func TestARangeThatWrapsIsNotARange(t *testing.T) {
	// The parser refuses it, so nothing later has to wonder whether a
	// parsed request has an end.
	if p, err := ParseRequest([]byte{3, 0xFF, 0xFF, 0x00, 0x02}); err == nil {
		t.Errorf("a read starting at 65535 for two registers parsed: %+v", p)
	}
	if _, ok := (&PDU{HasRange: true, Address: 0xFFFF, Quantity: 2}).Last(); ok {
		t.Error("a range past the address space reads as a valid one")
	}
	if _, ok := (&PDU{HasRange: true, Address: 0, Quantity: 0}).Last(); ok {
		t.Error("a range of nothing reads as a valid one")
	}
	if _, ok := (&PDU{}).Last(); !ok {
		t.Error("a request with no range has nothing to refuse")
	}
	p2, _ := ParseRequest([]byte{3, 0x00, 0x00, 0x00, 0x7D})
	last, ok := p2.Last()
	if !ok || last != 124 {
		t.Errorf("last %d (%v)", last, ok)
	}
	if rw, err := ParseRequest([]byte{23, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x02, 4, 0, 1, 0, 2}); err == nil {
		t.Errorf("a write half that wraps parsed: %+v", rw)
	}
	if _, ok := (&PDU{Function: FCWriteSingleRegister}).WriteLast(); !ok {
		t.Error("a code with no write half of its own has nothing to refuse")
	}
}

// The function code table is what a read-only policy is made of, so the
// classification of every code it holds is checked rather than assumed.
func TestTheAccessOfEveryFunctionCode(t *testing.T) {
	writes := []byte{FCWriteSingleCoil, FCWriteSingleRegister, FCWriteMultipleCoils,
		FCWriteMultipleRegisters, FCMaskWriteRegister, FCReadWriteMultiple, FCWriteFileRecord}
	for _, fc := range writes {
		if ReadOnlySafe(fc) {
			t.Errorf("%s passes a read-only policy", FunctionName(fc))
		}
		if a, _ := AccessOf(fc); a != AccessWrite {
			t.Errorf("%s reads as %s", FunctionName(fc), a)
		}
	}
	for _, fc := range []byte{FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters,
		FCReadInputRegisters, FCReadFileRecord, FCReadFIFOQueue} {
		if !ReadOnlySafe(fc) {
			t.Errorf("%s does not pass a read-only policy", FunctionName(fc))
		}
	}
	// Diagnostics read nothing of the process and can still restart a
	// link, so they are their own class and not read-only.
	if a, _ := AccessOf(FCDiagnostic); a != AccessDiagnostic || ReadOnlySafe(FCDiagnostic) {
		t.Error("a diagnostic reads as a read")
	}
	// A vendor code is known to be unknown, and never read-only.
	if a, ok := AccessOf(100); a != AccessVendor || !ok {
		t.Errorf("a user-defined code reads as %s (%v)", a, ok)
	}
	if ReadOnlySafe(100) {
		t.Error("a vendor code passes a read-only policy")
	}
	if _, ok := AccessOf(9); ok {
		t.Error("a reserved code reads as known")
	}
	if got := FunctionName(100); got != "vendor_100" {
		t.Errorf("name %q", got)
	}
	if fc, ok := FunctionCode("write_multiple_registers"); !ok || fc != 16 {
		t.Errorf("code by name: %d %v", fc, ok)
	}
	if _, ok := FunctionCode("not_a_function"); ok {
		t.Error("an invented name resolved")
	}
}

func TestMBAPFramingReadsOneFrameAtATime(t *testing.T) {
	first := Encode(FramingTCP, &Frame{Transaction: 1, Unit: 17, PDU: []byte{3, 0, 0x6B, 0, 3}})
	second := Encode(FramingTCP, &Frame{Transaction: 2, Unit: 18, PDU: []byte{1, 0, 0x13, 0, 0x13}})
	r := NewReader(bytes.NewReader(append(first, second...)), FramingTCP, true)
	f, raw, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Transaction != 1 || f.Unit != 17 || !bytes.Equal(raw, first) {
		t.Fatalf("%+v %x", f, raw)
	}
	f2, raw2, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f2.Transaction != 2 || f2.Unit != 18 || !bytes.Equal(raw2, second) {
		t.Errorf("%+v %x", f2, raw2)
	}
	// The bytes handed back are the bytes that arrived, because that is
	// what gets forwarded: re-encoding is how a relay and a device come
	// to disagree.
	if _, _, err := r.ReadFrame(); err == nil {
		t.Error("a reader past the end returned a frame")
	}
}

func TestMBAPHeaderChecks(t *testing.T) {
	for _, tc := range []struct {
		name string
		head []byte
		want error
	}{
		{"another protocol", []byte{0, 1, 0, 1, 0, 3, 17, 3, 0}, ErrProtocol},
		{"a length of one", []byte{0, 1, 0, 0, 0, 1, 17}, ErrLength},
		{"a length over the longest pdu", []byte{0, 1, 0, 0, 0xFF, 0xFF, 17}, ErrLength},
	} {
		r := NewReader(bytes.NewReader(tc.head), FramingTCP, true)
		if _, _, err := r.ReadFrame(); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// RTU on a stream has no delimiter, so the length is computed from the
// function code and the CRC is what proves the computation right.
func TestRTUFramingIsReadByLengthAndProvedByCRC(t *testing.T) {
	req := Encode(FramingRTU, &Frame{Unit: 17, PDU: []byte{3, 0, 0x6B, 0, 3}})
	write := Encode(FramingRTU, &Frame{Unit: 17, PDU: []byte{16, 0, 1, 0, 2, 4, 0, 10, 1, 2}})
	r := NewReader(bytes.NewReader(append(req, write...)), FramingRTU, true)
	f, raw, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Unit != 17 || !bytes.Equal(raw, req) || !bytes.Equal(f.PDU, []byte{3, 0, 0x6B, 0, 3}) {
		t.Fatalf("%+v %x", f, raw)
	}
	f2, _, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f2.PDU, []byte{16, 0, 1, 0, 2, 4, 0, 10, 1, 2}) {
		t.Errorf("counted body: %x", f2.PDU)
	}
	// A frame whose CRC does not match is refused: on a stream that is
	// the only evidence the frame ended where the device will think it
	// did.
	bad := append([]byte(nil), req...)
	bad[len(bad)-1] ^= 0xFF
	r2 := NewReader(bytes.NewReader(bad), FramingRTU, true)
	if _, _, err := r2.ReadFrame(); !errors.Is(err, ErrChecksum) {
		t.Errorf("a bad CRC: %v", err)
	}
	// A response is read with the response lengths, which differ.
	resp := Encode(FramingRTU, &Frame{Unit: 17, PDU: []byte{3, 6, 0x02, 0x2B, 0, 0, 0, 0x64}})
	r3 := NewReader(bytes.NewReader(resp), FramingRTU, false)
	f3, _, err := r3.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if len(f3.PDU) != 8 {
		t.Errorf("response pdu %x", f3.PDU)
	}
	// An exception response is two bytes whichever function it answers.
	exc := Encode(FramingRTU, &Frame{Unit: 17, PDU: []byte{0x83, 2}})
	r4 := NewReader(bytes.NewReader(exc), FramingRTU, false)
	if f4, _, err := r4.ReadFrame(); err != nil || len(f4.PDU) != 2 {
		t.Errorf("exception: %v %x", err, f4)
	}
	// A function code whose length cannot be worked out is refused
	// rather than guessed at.
	r5 := NewReader(bytes.NewReader([]byte{17, 99, 0, 0, 0, 0}), FramingRTU, true)
	if _, _, err := r5.ReadFrame(); !errors.Is(err, ErrUnknownFunction) {
		t.Errorf("an unknown code: %v", err)
	}
}

func TestASCIIFramingReadsHexAndChecksTheLRC(t *testing.T) {
	frame := Encode(FramingASCII, &Frame{Unit: 17, PDU: []byte{3, 0, 0x6B, 0, 3}})
	if !bytes.HasPrefix(frame, []byte(":11")) || !bytes.HasSuffix(frame, []byte("\r\n")) {
		t.Fatalf("encoded %q", frame)
	}
	r := NewReader(bytes.NewReader(frame), FramingASCII, true)
	f, raw, err := r.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if f.Unit != 17 || !bytes.Equal(f.PDU, []byte{3, 0, 0x6B, 0, 3}) || !bytes.Equal(raw, frame) {
		t.Fatalf("%+v %q", f, raw)
	}
	// Lower case hex is accepted, because devices mix the two.
	lower := bytes.ToLower(frame[1 : len(frame)-2])
	mixed := append(append([]byte(":"), lower...), '\r', '\n')
	r2 := NewReader(bytes.NewReader(mixed), FramingASCII, true)
	if _, _, err := r2.ReadFrame(); err != nil {
		t.Errorf("lower case: %v", err)
	}
	for _, tc := range []struct {
		name  string
		frame string
		want  error
	}{
		{"a bad LRC", ":1103006B000300\r\n", ErrChecksum},
		{"an odd number of digits", ":1103006B0003F\r\n", ErrFormat},
		{"not hexadecimal", ":11ZZ006B0003F1\r\n", ErrFormat},
		{"no carriage return", ":1103006B0003F1\n", ErrFormat},
		{"nothing but the start", ":\r\n", ErrFormat},
	} {
		r := NewReader(strings.NewReader(tc.frame), FramingASCII, true)
		if _, _, err := r.ReadFrame(); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// The checksums against values from the specification's own examples.
func TestTheChecksums(t *testing.T) {
	// The specification's own example: a read of three registers from
	// unit 17 is 11 03 006B 0003 with the CRC field 76 87 on the wire.
	// The field is sent low byte first, so the value is 0x8776 and the
	// encoder is what puts the bytes in that order.
	body := []byte{0x11, 0x03, 0x00, 0x6B, 0x00, 0x03}
	if got := CRC16(body); got != 0x8776 {
		t.Errorf("CRC16 = %#04x", got)
	}
	if raw := Encode(FramingRTU, &Frame{Unit: 0x11, PDU: body[1:]}); !bytes.Equal(raw[len(raw)-2:], []byte{0x76, 0x87}) {
		t.Errorf("the CRC field is %x, want 76 87 as the example writes it", raw[len(raw)-2:])
	}
	// The LRC is the two's complement of the sum, so a frame and its
	// LRC sum to zero.
	var sum byte
	for _, c := range append(append([]byte(nil), body...), LRC(body)) {
		sum += c
	}
	if sum != 0 {
		t.Errorf("a frame and its LRC sum to %d", sum)
	}
}

func TestFramingNames(t *testing.T) {
	for name, want := range map[string]Framing{"": FramingTCP, "tcp": FramingTCP, "rtu": FramingRTU, "ascii": FramingASCII} {
		got, err := FramingOf(name)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", name, got, err)
		}
	}
	if _, err := FramingOf("serial"); err == nil {
		t.Error("an invented framing was accepted")
	}
	if got := FramingRTU.String(); got != "rtu" {
		t.Errorf("String %q", got)
	}
}

// The role a certificate carries is what Modbus/TCP Security authorises
// by, so it is read out of a real certificate rather than out of a
// string.
func TestTheRoleComesOutOfTheCertificate(t *testing.T) {
	cert := certWithRole(t, "operator", "cn-name", "plant-ou")
	role, err := RoleFromCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	if role != "operator" {
		t.Errorf("role %q", role)
	}
	// The documented compromises, for an authority that cannot issue
	// the extension yet.
	if got, err := RoleFromSubject(cert, "cn"); err != nil || got != "cn-name" {
		t.Errorf("cn: %q %v", got, err)
	}
	if got, err := RoleFromSubject(cert, "ou"); err != nil || got != "plant-ou" {
		t.Errorf("ou: %q %v", got, err)
	}
	if _, err := RoleFromSubject(cert, "serial"); err == nil {
		t.Error("an invented subject field was accepted")
	}
	plain := certWithRole(t, "", "cn-name", "")
	if _, err := RoleFromCert(plain); !errors.Is(err, ErrNoRole) {
		t.Errorf("no extension: %v", err)
	}
	if _, err := RoleFromCert(nil); !errors.Is(err, ErrNoRole) {
		t.Errorf("no certificate: %v", err)
	}
	if _, err := RoleFromSubject(plain, "ou"); !errors.Is(err, ErrNoRole) {
		t.Errorf("no organisational unit: %v", err)
	}
}

// A role this relay would read differently from the device is worse than
// no role, so every shape that cannot be compared is refused.
func TestARoleThatCannotBeComparedIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, role string }{
		{"empty", ""},
		{"a space", "plant operator"},
		{"a control character", "operator\n"},
		{"too long", strings.Repeat("r", MaxRoleLen+1)},
	} {
		if _, _, err := RoleExtension(tc.role); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	// The extension a test builds is the extension the reader reads,
	// which is what makes the two halves one claim.
	oid, der, err := RoleExtension("engineer")
	if err != nil {
		t.Fatal(err)
	}
	if !oid.Equal(RoleOID) {
		t.Errorf("oid %v", oid)
	}
	cert := &x509.Certificate{Extensions: []pkix.Extension{{Id: RoleOID, Value: der}}}
	if got, err := RoleFromCert(cert); err != nil || got != "engineer" {
		t.Errorf("round trip: %q %v", got, err)
	}
	// A value that is not a string at all is an error rather than a
	// guess.
	bad := &x509.Certificate{Extensions: []pkix.Extension{{Id: RoleOID, Value: []byte{0x02, 0x01, 0x05}}}}
	if _, err := RoleFromCert(bad); err == nil {
		t.Error("an integer read as a role")
	}
}

// certWithRole issues a self-signed certificate carrying the role
// extension when role is not empty.
func certWithRole(t *testing.T, role, cn, ou string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{CommonName: cn}
	if ou != "" {
		subject.OrganizationalUnit = []string{ou}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if role != "" {
		oid, der, err := RoleExtension(role)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oid, Value: der}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Encoding a frame is only for the frames this relay originates, and
// each framing has to round trip through its own reader.
func TestEncodeRoundTripsThroughEveryFraming(t *testing.T) {
	for _, f := range []Framing{FramingTCP, FramingRTU, FramingASCII} {
		raw := Encode(f, &Frame{Transaction: 7, Unit: 3, PDU: ExceptionPDU(3, ExIllegalFunction)})
		r := NewReader(bytes.NewReader(raw), f, false)
		got, _, err := r.ReadFrame()
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if got.Unit != 3 || !bytes.Equal(got.PDU, []byte{0x83, 1}) {
			t.Errorf("%s: %+v", f, got)
		}
		if f == FramingTCP && got.Transaction != 7 {
			t.Errorf("tcp transaction %d", got.Transaction)
		}
	}
	// The MBAP length field covers the unit identifier and the PDU.
	raw := Encode(FramingTCP, &Frame{PDU: []byte{3, 0, 1, 0, 1}})
	if n := binary.BigEndian.Uint16(raw[4:]); n != 6 {
		t.Errorf("length field %d", n)
	}
}
