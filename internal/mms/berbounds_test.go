package mms

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

// Every length and tag this reader refuses.
//
// An MMS message arrives from whatever is on the substation network, and
// BER is the format where a length is a number somebody else chose: the
// encoding allows a length of a length, so a reader that trusted one
// would allocate or index on an attacker's figure. Each case below is a
// refusal that has to happen before anything is read.
func TestTheBERReaderRefusesEveryLengthItCannotTrust(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want error
		says string
	}{
		{"nothing at all", nil, ErrShort, "where a tag and length must be"},
		{"an identifier with no length octet", []byte{0x30}, ErrShort, ""},
		{
			// 0x1f in the identifier means the tag number follows in the
			// high form, one septet per octet with the top bit set to
			// continue. Four octets of continuation is past what this
			// reader will read.
			"a tag number in more octets than a tag can be",
			[]byte{0x3f, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00}, ErrSize, "tag number in more than",
		},
		{"a tag number that never ends", []byte{0x3f, 0x81, 0x81}, ErrEncoding, "never ends"},
		{
			"a length of a length longer than four octets",
			[]byte{0x04, 0x85, 0, 0, 0, 0, 1, 0}, ErrSize, "",
		},
		{
			"a length of a length that is not all there",
			[]byte{0x04, 0x83, 0x01}, ErrShort, "length octets",
		},
		{
			// 0x84 0x7f ff ff ff is 2 GiB - 1, past what this reader
			// reads into an int32.
			"a length past the top of an int32",
			[]byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xff}, ErrSize, "length",
		},
		{
			"a length longer than what follows it",
			[]byte{0x04, 0x08, 1, 2, 3}, ErrShort, "",
		},
		{
			"the indefinite length, which a substation does not send",
			[]byte{0x30, 0x80, 0x00, 0x00}, ErrEncoding, "",
		},
	} {
		_, err := NewBER(tc.in).Next()
		switch {
		case tc.want == nil && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != nil && !errors.Is(err, tc.want):
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
		case tc.says != "" && err != nil && !strings.Contains(err.Error(), tc.says):
			t.Errorf("%s: error %q, want it to mention %q", tc.name, err, tc.says)
		}
	}
}

// What is inside an element, and what is not: a primitive element has no
// children, and asking for them is a mistake in the reader rather than
// in the message -- so it is an error and not an empty list, which would
// read as "a sequence of nothing".
func TestOnlyAConstructedElementHasChildren(t *testing.T) {
	// A sequence holding one integer.
	seq, err := NewBER([]byte{0x30, 0x03, 0x02, 0x01, 0x07}).Next()
	if err != nil {
		t.Fatal(err)
	}
	sub, err := NewBER(nil).Sub(seq)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := sub.Next()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := Int(inner); err != nil || n != 7 {
		t.Errorf("the integer inside read as %d, %v", n, err)
	}
	if !sub.Empty() {
		t.Errorf("there is more inside than the integer: %x", sub.Rest())
	}
	if _, err := NewBER(nil).Sub(inner); !errors.Is(err, ErrEncoding) {
		t.Errorf("asking a primitive element for its children: %v", err)
	}
}

// The integers a message carries, and the ones it cannot.
func TestTheIntegerReadersRefuseWhatWillNotFit(t *testing.T) {
	el := func(data ...byte) Element {
		return Element{Class: ClassUniversal, Tag: TagInteger, Data: data}
	}
	if n, err := Int(el(0xff)); err != nil || n != -1 {
		t.Errorf("one sign octet read as %d, %v", n, err)
	}
	if n, err := Int(el(0x7f, 0xff)); err != nil || n != 32767 {
		t.Errorf("two octets read as %d, %v", n, err)
	}
	if _, err := Int(el()); err == nil {
		t.Error("an integer of no octets was read")
	}
	if _, err := Int(el(1, 2, 3, 4, 5, 6, 7, 8, 9)); err == nil {
		t.Error("an integer of nine octets was read")
	}
	if n, err := Uint(el(0x01, 0x00)); err != nil || n != 256 {
		t.Errorf("an unsigned integer read as %d, %v", n, err)
	}
	if _, err := Uint(el(0xff)); err == nil {
		t.Error("a negative integer was read as unsigned")
	}
	if b, err := Bool(el(0x01)); err != nil || !b {
		t.Errorf("a true read as %v, %v", b, err)
	}
	if b, err := Bool(el(0x00)); err != nil || b {
		t.Errorf("a false read as %v, %v", b, err)
	}
	if _, err := Bool(el(0x01, 0x02)); err == nil {
		t.Error("a boolean of two octets was read")
	}
}

// The COTP header every MMS message arrives inside, and the shapes of it
// that are not one.
func TestTheCOTPHeaderIsCheckedBeforeItIsRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want error
		says string
	}{
		{"two octets where a header must be", []byte{0x02}, ErrShort, "where a COTP header must be"},
		{"a header length of zero", []byte{0x00, 0xf0}, ErrSize, "length 0"},
		{"a connection request with no references", []byte{0x06, 0xe0, 0x00, 0x00}, ErrShort, ""},
		{"a data PDU with no sequence octet", []byte{0x01, 0xf0}, ErrShort, "no sequence octet"},
		{
			"a parameter header cut in half",
			[]byte{0x07, 0xe0, 0, 0, 0, 0, 0, 0xc0}, ErrShort, "parameter header in",
		},
		{
			"a parameter whose length runs past the header",
			[]byte{0x09, 0xe0, 0, 0, 0, 0, 0, 0xc0, 0x08, 0x0a}, ErrShort, "are left",
		},
	} {
		_, err := ParseCOTP(tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
			continue
		}
		if tc.says != "" && !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: error %q, want it to mention %q", tc.name, err, tc.says)
		}
	}
	// A TPDU size parameter is an exponent, and the ones outside RFC
	// 905's range are not a size: 2^7 to 2^13 is what the protocol
	// defines, and a reader that shifted by anything else would hand a
	// relay a buffer bound of its correspondent's choosing.
	for _, exp := range []uint8{0, 6, 14, 255} {
		if n := TPDUBytes(exp); n != 0 {
			t.Errorf("TPDUBytes(%d) = %d, want 0", exp, n)
		}
	}
	for exp, want := range map[uint8]int{7: 128, 10: 1024, 13: 8192} {
		if n := TPDUBytes(exp); n != want {
			t.Errorf("TPDUBytes(%d) = %d, want %d", exp, n, want)
		}
	}
	_ = bytes.Equal
	_ = math.MaxInt32
}

// What an MMS PDU may not be. The outer tag decides which service this
// is, so a reader that guessed at it would hand the policy the wrong
// service name -- and a rule written about a read would then be applied
// to a write.
func TestEveryShapeAnMMSPDUIsRefusedFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		says string
	}{
		{"nothing readable at all", []byte{0x30}, ""},
		{"a universal tag where a service must be", []byte{0x30, 0x00}, "an MMS PDU is a context tag"},
		{"a service number nothing defines", []byte{0xbf, 0x7f, 0x00}, "MMS PDU"},
		{"a body that is not there", []byte{0xa0, 0x05, 0x02, 0x01}, ""},
	} {
		if _, err := ParsePDU(tc.in); err == nil {
			t.Errorf("%s: parsed", tc.name)
		} else if tc.says != "" && !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: error %q, want it to mention %q", tc.name, err, tc.says)
		}
	}
	// The two PDUs that are encoded primitively, because their bodies
	// are empty: a conclude request and its response carry nothing, so
	// there is nothing inside the tag to read.
	for _, tag := range []byte{0x88, 0x89} {
		if _, err := ParsePDU([]byte{tag, 0x00}); err != nil {
			t.Errorf("a primitive PDU %#02x: %v", tag, err)
		}
	}
}

// The connection request every MMS session begins with: the references
// both ends will use are read, and a request too short to hold them is
// refused rather than read out of the octets after it.
func TestTheCOTPConnectionRequestCarriesBothReferences(t *testing.T) {
	cr := []byte{0x06, 0xe0, 0x00, 0x01, 0x00, 0x02, 0x00}
	c, err := ParseCOTP(cr)
	if err != nil {
		t.Fatalf("a connection request: %v", err)
	}
	if c.DstRef != 1 || c.SrcRef != 2 {
		t.Errorf("references %d and %d, want 1 and 2", c.DstRef, c.SrcRef)
	}
	if _, err := ParseCOTP([]byte{0x04, 0xe0, 0x00, 0x01, 0x00}); !errors.Is(err, ErrShort) {
		t.Errorf("a connection request with room for one reference: %v", err)
	}
}

// A frame whose TPKT header promises more than the connection delivers,
// which is what the last read of a session that was cut looks like. The
// frame is not returned half read: a body short of its own length would
// be parsed as whatever the uninitialised tail decoded to.
func TestAFrameShortOfItsOwnLengthIsNotReturned(t *testing.T) {
	// Version 3, reserved 0, length 16, and four octets of body.
	short := []byte{0x03, 0x00, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04}
	if f, err := NewReader(bytes.NewReader(short), 1024).Next(); err == nil {
		t.Errorf("a truncated frame was returned: %x", f.Raw)
	}
	// And the whole frame, to say the reader is not simply always
	// failing: eight octets of header and body, declared as eight.
	whole := []byte{0x03, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04}
	f, err := NewReader(bytes.NewReader(whole), 1024).Next()
	if err != nil {
		t.Fatalf("a whole frame: %v", err)
	}
	if !bytes.Equal(f.Body, whole[4:]) {
		t.Errorf("body %x, want %x", f.Body, whole[4:])
	}
}

// Inside a confirmed request, the first context tag after the invoke
// identifier is the service -- and the service is what every rule in
// the policy is written about, so what is not a service has to be
// passed over rather than read as one.
func TestWhatIsNotAServiceInsideAConfirmedRequest(t *testing.T) {
	// A universal element that is not the invoke identifier: skipped,
	// and the message carries no service rather than the wrong one.
	m, err := ParsePDU([]byte{0xa0, 0x03, 0x04, 0x01, 0x41})
	if err != nil {
		t.Fatalf("a request carrying no service: %v", err)
	}
	if m.HasService {
		t.Errorf("an octet string was read as service %d", m.Service)
	}
	// A context tag past an octet cannot be a service: ISO 9506 defines
	// none, and Service is an octet, so narrowing it would name a
	// different service in the log than the one on the wire.
	if _, err := ParsePDU([]byte{0xa0, 0x04, 0xbf, 0x82, 0x00, 0x00}); err == nil ||
		!strings.Contains(err.Error(), "confirmed service tagged 256") {
		t.Errorf("a service tagged past an octet: %v", err)
	}
	// And the invoke identifier itself, which is what ties a reply to
	// the request it answers.
	m, err = ParsePDU([]byte{0xa0, 0x03, 0x02, 0x01, 0x2a})
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasInvokeID || m.InvokeID != 42 {
		t.Errorf("invoke identifier %d, %v", m.InvokeID, m.HasInvokeID)
	}
}
