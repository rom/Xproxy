package kerberos

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The DER reader on its own, at the level the message parser uses it.
//
// The parser's own tests drive whole requests and replies, which is what proves
// the fields are read from the right places. What this file is for is the layer
// underneath: every refusal the reader makes about an encoding, one case each.
// They matter because this reader is what stands between a KDC and whatever can
// reach the proxy's port, and because each refusal is about a *second spelling*
// of something -- a field encoded two ways is a field a rule is written about in
// one spelling and sent in the other.

// el reads the first element of a rendered TLV, which is how each case below
// gets the element its subject takes.
func el(t *testing.T, b []byte) element {
	t.Helper()
	e, err := newDER(b).next()
	if err != nil {
		t.Fatalf("reading the element back: %v", err)
	}
	return e
}

// A KerberosString arrives under five different universal tags, because the
// installed base encodes it as GeneralString and implementations that read
// RFC 4120 §5.2.1 literally use IA5String -- with UTF-8 and the other two
// turning up as well. All five are text; nothing else is, whatever it contains.
func TestAKerberosStringIsReadUnderEveryTagTheInstalledBaseUses(t *testing.T) {
	for _, tag := range []uint32{tagGeneralStr, tagIA5Str, tagUTF8Str, tagPrintableStr, tagVisibleStr} {
		e := el(t, derTLV(classUniversal, tag, []byte("CORP.EXAMPLE")))
		if !e.isString() {
			t.Errorf("tag %#x is not read as a string", tag)
			continue
		}
		got, err := derString(e)
		if err != nil || got != "CORP.EXAMPLE" {
			t.Errorf("tag %#x read %q, %v", tag, got, err)
		}
	}
	// The class is not enough on its own: a realm encoded under the INTEGER or
	// OCTET STRING tag would be read as text here while a KDC reads it as the
	// type it claims to be.
	for _, tag := range []uint32{tagInteger, tagOctetString, tagBitString, tagSequence} {
		e := el(t, derTLV(classUniversal, tag, []byte("CORP.EXAMPLE")))
		if e.isString() {
			t.Errorf("tag %#x is read as a string", tag)
		}
		if _, err := derString(e); !errors.Is(err, ErrTag) {
			t.Errorf("tag %#x read as a string with error %v", tag, err)
		}
	}
	// And a context tag is not a string either, whatever its number: the
	// field's own tag wraps the string rather than replacing it.
	ctxEl := el(t, derTLV(classContext, 1, []byte("CORP.EXAMPLE")))
	if ctxEl.isString() {
		t.Error("a context tag is read as a string")
	}
	// Control characters are refused rather than cleaned: a realm with a
	// newline in it is a second line in a log file, and one with an escape
	// sequence is a terminal doing what the sequence says.
	for _, bad := range []string{"CORP\nEXAMPLE", "CORP\x1b[2JEXAMPLE", "CORP\x7fEXAMPLE",
		"CORP\x00EXAMPLE"} {
		if _, err := derString(el(t, derTLV(classUniversal, tagGeneralStr, []byte(bad)))); !errors.Is(err, ErrText) {
			t.Errorf("%q was read with error %v, want ErrText", bad, err)
		}
	}
	// And one past the bound, which is longer than any real principal.
	long := strings.Repeat("a", maxString+1)
	if _, err := derString(el(t, derTLV(classUniversal, tagGeneralStr, []byte(long)))); !errors.Is(err, ErrString) {
		t.Errorf("a %d-octet string was read with error %v", len(long), err)
	}
}

// Every field of every Kerberos structure is `[n] EXPLICIT something`, which is
// a constructed context tag with the value inside it as its own TLV. A
// primitive context tag whose content happens to parse is a second spelling of
// the field, and a reader that took it would accept an encoding a KDC rejects.
func TestAnExplicitTagHasToBeConstructed(t *testing.T) {
	// The shape the standard defines: [1] wrapping an INTEGER.
	good := derTLV(classContext|constructed, 1, derTLV(classUniversal, tagInteger, []byte{5}))
	r := newDER(good)
	e, err := r.next()
	if err != nil {
		t.Fatal(err)
	}
	inner, _, err := r.only(e)
	if err != nil {
		t.Fatalf("a constructed context tag was refused: %v", err)
	}
	if n, err := derInteger(inner); err != nil || n != 5 {
		t.Fatalf("the wrapped INTEGER read %d, %v", n, err)
	}

	// The same octets with the constructed bit off: the content still parses as
	// an INTEGER, and the element is still refused.
	bad := derTLV(classContext, 1, derTLV(classUniversal, tagInteger, []byte{5}))
	br := newDER(bad)
	be, err := br.next()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := br.only(be); !errors.Is(err, ErrTag) {
		t.Fatalf("a primitive explicit tag was read with error %v, want ErrTag", err)
	}

	// A SEQUENCE has to be constructed for the same reason.
	seq := newDER(derTLV(classUniversal|constructed, tagSequence, nil))
	se, err := seq.next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seq.sequence(se); err != nil {
		t.Fatalf("a constructed SEQUENCE was refused: %v", err)
	}
	flat := newDER(derTLV(classUniversal, tagSequence, nil))
	fe, err := flat.next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flat.sequence(fe); !errors.Is(err, ErrTag) {
		t.Fatalf("a primitive SEQUENCE was read with error %v, want ErrTag", err)
	}
}

// A KerberosTime is a GeneralizedTime in UTC with no fractional seconds, which
// is what RFC 4120 §5.2.3 requires -- and the only form this reader accepts,
// because a ticket's lifetime is decided from it.
func TestAKerberosTimeIsTheOneFormTheStandardDefines(t *testing.T) {
	want := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	got, err := derTime(el(t, derTLV(classUniversal, tagGeneralTime, []byte("20260304120000Z"))))
	if err != nil {
		t.Fatalf("a well-formed time was refused: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("read %v, want %v", got, want)
	}
	// A trailing fractional second is read rather than refused: Go's own
	// GeneralizedTime parse tolerates one, so a KDC that sends
	// `20260304120000.5Z` is understood. RFC 4120 §5.2.3 says not to send one;
	// nothing here depends on the difference, because what the field is used
	// for is a lifetime comparison and the instant is the same.
	got, err = derTime(el(t, derTLV(classUniversal, tagGeneralTime,
		[]byte("20260304120000.5Z"))))
	if err != nil || !got.Truncate(time.Second).Equal(want) {
		t.Errorf("a fractional second read %v, %v", got, err)
	}
	// Wrong tag: a time encoded as a string is not a time.
	if _, err := derTime(el(t, derTLV(classUniversal, tagGeneralStr,
		[]byte("20260304120000Z")))); !errors.Is(err, ErrTag) {
		t.Errorf("a time under the string tag was read with error %v", err)
	}
	// And every spelling the standard excludes. Each would otherwise be a
	// second way to write one instant, and a lifetime bound is compared
	// against it.
	for _, bad := range []string{
		"20260304120000",         // no zone
		"2026030412Z",            // no seconds
		"202603041200Z",          // no seconds
		"20260304120000+0100",    // an offset rather than Z
		"20261304120000Z",        // month 13
		"",                       // nothing at all
		"not a time at all....Z", // and something that is not one
	} {
		if _, err := derTime(el(t, derTLV(classUniversal, tagGeneralTime,
			[]byte(bad)))); !errors.Is(err, ErrTime) {
			t.Errorf("%q was read with error %v, want ErrTime", bad, err)
		}
	}
}

// KDCOptions and APOptions are 32-bit flag fields, so the unused-bits octet of
// the BIT STRING has to be zero: a non-zero count would mean this reader and
// the KDC disagree about the low bits -- the bits that say renew, validate and
// enc-tkt-in-skey.
func TestTheOptionsBitsAreReadOnlyFromAWholeNumberOfOctets(t *testing.T) {
	// The ordinary encoding: no unused bits, four octets of flags.
	e := el(t, derTLV(classUniversal, tagBitString, []byte{0x00, 0x40, 0x81, 0x00, 0x10}))
	got, err := derBits(e)
	if err != nil {
		t.Fatalf("a well-formed BIT STRING was refused: %v", err)
	}
	if got != 0x40810010 {
		t.Errorf("read %#x, want %#x", got, 0x40810010)
	}
	// Fewer than four octets is read as the high ones, which is what a peer
	// that trimmed trailing zero octets sends.
	short := el(t, derTLV(classUniversal, tagBitString, []byte{0x00, 0x40}))
	if got, err := derBits(short); err != nil || got != 0x40000000 {
		t.Errorf("a two-octet field read %#x, %v", got, err)
	}
	// A non-zero unused-bits count is refused, and the message says what the
	// count was.
	bad := el(t, derTLV(classUniversal, tagBitString, []byte{0x03, 0x40, 0x81, 0x00, 0x10}))
	if _, err := derBits(bad); !errors.Is(err, ErrTag) || !strings.Contains(err.Error(), "3 unused bits") {
		t.Errorf("a field with unused bits was read with error %v", err)
	}
	// An empty BIT STRING has no count octet at all. It is refused, and the
	// message says so rather than reading past the end of the element.
	empty := el(t, derTLV(classUniversal, tagBitString, nil))
	if _, err := derBits(empty); !errors.Is(err, ErrTag) {
		t.Errorf("an empty BIT STRING was read with error %v", err)
	}
	// Wrong tag.
	if _, err := derBits(el(t, derTLV(classUniversal, tagOctetString,
		[]byte{0x00, 0x40}))); !errors.Is(err, ErrTag) {
		t.Errorf("an OCTET STRING was read as options with error %v", err)
	}
}

// An INTEGER is read in one spelling, because every value a rule is written
// about is compared against it.
func TestAnIntegerIsReadInOneSpelling(t *testing.T) {
	for _, c := range []struct {
		data []byte
		want int32
	}{
		{[]byte{0x05}, 5},
		{[]byte{0x00, 0x80}, 128},
		{[]byte{0xff}, -1},
		{[]byte{0x80}, -128},
		{[]byte{0x7f, 0xff, 0xff, 0xff}, 2147483647},
	} {
		got, err := derInteger(el(t, derTLV(classUniversal, tagInteger, c.data)))
		if err != nil || got != c.want {
			t.Errorf("%#v read %d, %v, want %d", c.data, got, err, c.want)
		}
	}
	// A leading octet that adds no information is not DER: it is a second
	// encoding of one number.
	for _, data := range [][]byte{{0x00, 0x05}, {0xff, 0x80}} {
		if _, err := derInteger(el(t, derTLV(classUniversal, tagInteger,
			data))); !errors.Is(err, ErrNonMinimal) {
			t.Errorf("%#v was read with error %v, want ErrNonMinimal", data, err)
		}
	}
	// Nothing at all, something wider than the fields this package has, and a
	// value outside Int32.
	for _, data := range [][]byte{{}, {1, 2, 3, 4, 5, 6}, {0x00, 0x80, 0x00, 0x00, 0x00}} {
		if _, err := derInteger(el(t, derTLV(classUniversal, tagInteger,
			data))); !errors.Is(err, ErrInteger) {
			t.Errorf("%#v was read with error %v, want ErrInteger", data, err)
		}
	}
	if _, err := derInteger(el(t, derTLV(classUniversal, tagOctetString,
		[]byte{5}))); !errors.Is(err, ErrTag) {
		t.Error("an OCTET STRING was read as an INTEGER")
	}
}

// The message types and service classes a rule is written with, read back from
// the names an operator types.
func TestTheNamesARuleIsWrittenWithRoundTripHere(t *testing.T) {
	for _, c := range []struct {
		name string
		want MsgType
	}{
		{"as-req", MsgASReq},
		{"AS-REQ", MsgASReq},
		{"tgs-req", MsgTGSReq},
		{"ap-req", MsgAPReq},
		// The short forms an operator is likely to write.
		{"as", MsgASReq},
		{"asreq", MsgASReq},
		{"tgs", MsgTGSReq},
		{"ap", MsgAPReq},
		// kpasswd is the AP-REQ a password change arrives as, named for what
		// an operator is configuring rather than for the message.
		{"kpasswd", MsgAPReq},
		// Underscores are read as hyphens, because a configuration written
		// either way means the same thing.
		{"as_req", MsgASReq},
	} {
		got, ok := MsgTypeOf(c.name)
		if !ok || got != c.want {
			t.Errorf("MsgTypeOf(%q) = %v, %v, want %v", c.name, got, ok, c.want)
		}
	}
	// A number is not a name here: the types a proxy carries are three, and
	// naming one by its wire value would be a rule nobody can read.
	for _, name := range []string{"", "as-reqest", "krb-safe", "10", "999999"} {
		if got, ok := MsgTypeOf(name); ok {
			t.Errorf("MsgTypeOf(%q) = %v, which is not a type a proxy carries", name, got)
		}
	}
	// A service principal's class is its first component, which is what a
	// `services` list names: `MSSQLSvc` covers every instance in the realm.
	for _, c := range []struct {
		princ Principal
		want  string
	}{
		{svc("host", "dc1.corp.example"), "host"},
		{svc("MSSQLSvc", "db1.corp.example:1433"), "MSSQLSvc"},
		{user("bob"), "bob"},
		{Principal{}, ""},
	} {
		if got := c.princ.Service(); got != c.want {
			t.Errorf("%v has service class %q, want %q", c.princ.Parts, got, c.want)
		}
	}
}
