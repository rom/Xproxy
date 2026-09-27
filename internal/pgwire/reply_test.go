package pgwire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// The server's side of the wire, read back apart and checked against the octets
// the protocol specifies.
//
// A fabricated server's messages have to be the ones a driver expects, and the
// two ways to be sure of that are to read them back with an independent parser
// and to write the bytes out. Both are done here.

// A message's length counts itself and excludes the type byte. Off by one either
// way and the client reads the next message from the wrong offset, which is not
// an error but a client reporting nonsense about a message it never received.
func TestEveryMessageDeclaresItsOwnLengthCorrectly(t *testing.T) {
	for _, tc := range []struct {
		what string
		raw  []byte
		kind byte
	}{
		{"AuthenticationOk", AuthenticationOk(), MsgAuthentication},
		{"an MD5 request", AuthenticationRequest(AuthMD5Password, []byte{1, 2, 3, 4}), MsgAuthentication},
		{"a cleartext request", AuthenticationRequest(AuthCleartextPassword, nil), MsgAuthentication},
		{"ParameterStatus", ParameterStatus("server_version", "15.6"), MsgParameterStatus},
		{"BackendKeyData", BackendKeyData(4242, 99), MsgBackendKeyData},
		{"CommandComplete", CommandComplete("SELECT 3"), MsgCommandComplete},
		{"RowDescription", RowDescription([]Field{Text("a"), Text("b")}), 'T'},
		{"DataRow", DataRow([]*string{Str("x"), nil}), MsgDataRow},
		{"ErrorResponse", ErrorResponse("ERROR", "42501", "no"), MsgErrorResponse},
		{"NoticeResponse", NoticeResponse("NOTICE", "00000", "hello"), 'N'},
		{"ReadyForQuery", ReadyForQuery('I'), MsgReadyForQuery},
		{"EmptyQueryResponse", EmptyQueryResponse(), 'I'},
	} {
		if len(tc.raw) < 5 {
			t.Errorf("%s is %d octets", tc.what, len(tc.raw))
			continue
		}
		if tc.raw[0] != tc.kind {
			t.Errorf("%s starts %q, want %q", tc.what, tc.raw[0], tc.kind)
		}
		declared := binary.BigEndian.Uint32(tc.raw[1:5])
		if want := uint32(len(tc.raw) - 1); declared != want {
			t.Errorf("%s declares %d octets and is %d after its type byte", tc.what, declared, want)
		}
	}
}

// The startup sequence, which a client waits for all of.
func TestTheStartupSequenceIsTheOneAClientWaitsFor(t *testing.T) {
	// AuthenticationOk is message 'R' with a zero code, and nothing else.
	ok := AuthenticationOk()
	if len(ok) != 9 || binary.BigEndian.Uint32(ok[5:]) != 0 {
		t.Errorf("AuthenticationOk is %x", ok)
	}
	// An MD5 request carries four octets of salt, and a request of the wrong
	// length is one no client can answer -- so a short salt is replaced rather
	// than sent.
	md5 := AuthenticationRequest(AuthMD5Password, []byte{1, 2, 3, 4})
	if len(md5) != 13 || binary.BigEndian.Uint32(md5[5:9]) != AuthMD5Password {
		t.Errorf("an MD5 request is %x", md5)
	}
	if got := AuthenticationRequest(AuthMD5Password, []byte{1}); len(got) != 13 {
		t.Errorf("a short salt produced %d octets", len(got))
	}
	// A cleartext request carries no salt.
	if got := AuthenticationRequest(AuthCleartextPassword, []byte{1, 2, 3, 4}); len(got) != 9 {
		t.Errorf("a cleartext request is %d octets", len(got))
	}
	// ParameterStatus is two C strings, so both terminators are there and a NUL
	// in either would truncate the message.
	ps := ParameterStatus("server_version", "15.6")
	body := ps[5:]
	if got := bytes.Count(body, []byte{0}); got != 2 {
		t.Errorf("ParameterStatus has %d terminators: %q", got, body)
	}
	name, rest, _ := bytes.Cut(body, []byte{0})
	value, _, _ := bytes.Cut(rest, []byte{0})
	if string(name) != "server_version" || string(value) != "15.6" {
		t.Errorf("ParameterStatus read back as %q=%q", name, value)
	}
	dirty := ParameterStatus("a\x00b", "c\x00d")
	if got := bytes.Count(dirty[5:], []byte{0}); got != 2 {
		t.Errorf("a NUL in a parameter produced %d terminators: %q", got, dirty[5:])
	}
	// BackendKeyData carries the identifier and the secret, which is what a
	// client needs in order to cancel a query.
	bk := BackendKeyData(4242, 99)
	if binary.BigEndian.Uint32(bk[5:9]) != 4242 || binary.BigEndian.Uint32(bk[9:13]) != 99 {
		t.Errorf("BackendKeyData read back as %x", bk[5:])
	}
	// ReadyForQuery is five octets and the status byte.
	if got := ReadyForQuery('T'); len(got) != 6 || got[5] != 'T' {
		t.Errorf("ReadyForQuery is %x", got)
	}
}

// A row description, read back field by field: this is the message a driver reads
// to decide how to convert every value after it.
func TestARowDescriptionDeclaresTypesADriverCanUse(t *testing.T) {
	fields := []Field{
		Text("name"),
		{Name: "n", OID: OIDInt4, Size: 4, Modifier: -1},
	}
	raw := RowDescription(fields)
	body := raw[5:]
	if n := binary.BigEndian.Uint16(body); int(n) != len(fields) {
		t.Fatalf("the description declares %d columns, want %d", n, len(fields))
	}
	body = body[2:]
	for i, want := range fields {
		name, rest, ok := bytes.Cut(body, []byte{0})
		if !ok {
			t.Fatalf("column %d has no name terminator", i)
		}
		if string(name) != want.Name {
			t.Errorf("column %d is named %q, want %q", i, name, want.Name)
		}
		if len(rest) < 18 {
			t.Fatalf("column %d has %d octets of attributes, want 18", i, len(rest))
		}
		if oid := binary.BigEndian.Uint32(rest[6:10]); oid != want.OID {
			t.Errorf("column %d declares type %d, want %d", i, oid, want.OID)
		}
		if size := int16(binary.BigEndian.Uint16(rest[10:12])); size != want.Size { //nolint:gosec // reading back what was written
			t.Errorf("column %d declares width %d, want %d", i, size, want.Size)
		}
		// The format code is text, which is what the simple query protocol
		// always uses: declaring binary would mean producing binary.
		if format := binary.BigEndian.Uint16(rest[16:18]); format != 0 {
			t.Errorf("column %d declares format %d, want text", i, format)
		}
		body = rest[18:]
	}
	if len(body) != 0 {
		t.Errorf("%d octets left over", len(body))
	}
	// A field with nothing set still has a usable type and width, because a
	// column of type zero is one a driver cannot convert.
	bare := RowDescription([]Field{{Name: "x"}})[5+2:]
	_, rest, _ := bytes.Cut(bare, []byte{0})
	if oid := binary.BigEndian.Uint32(rest[6:10]); oid == 0 {
		t.Error("a field with no type declared type zero")
	}
	// And a usable width: zero octets is not a width any type has, and a driver
	// that read one would expect a fixed-width column of nothing.
	if size := int16(binary.BigEndian.Uint16(rest[10:12])); size != -1 { //nolint:gosec // reading back what was written
		t.Errorf("a field with no width declared %d, want -1", size)
	}
	if mod := int32(binary.BigEndian.Uint32(rest[12:16])); mod != -1 { //nolint:gosec // and likewise
		t.Errorf("a field with no modifier declared %d, want -1", mod)
	}
}

// An authentication request a client can answer, which means one of the right
// length: the four octets of salt are part of an MD5 request and part of nothing
// else.
func TestAnAuthenticationRequestIsOneAClientCanAnswer(t *testing.T) {
	plain := AuthenticationRequest(AuthCleartextPassword, nil)
	if len(plain) != 9 {
		t.Errorf("a cleartext request is %d octets, want 9", len(plain))
	}
	if code := binary.BigEndian.Uint32(plain[5:9]); code != AuthCleartextPassword {
		t.Errorf("a cleartext request carries code %d", code)
	}
	md5 := AuthenticationRequest(AuthMD5Password, []byte{1, 2, 3, 4})
	if len(md5) != 13 {
		t.Fatalf("an MD5 request is %d octets, want 13", len(md5))
	}
	if got := md5[9:13]; !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Errorf("the salt came back as %x", got)
	}
	// A caller who passed the wrong number of octets would otherwise produce a
	// request no client can answer: the length follows the method rather than the
	// caller.
	for _, salt := range [][]byte{nil, {1}, {1, 2, 3, 4, 5}} {
		got := AuthenticationRequest(AuthMD5Password, salt)
		if len(got) != 13 {
			t.Errorf("an MD5 request built from %d octets of salt is %d octets long", len(salt), len(got))
		}
	}
}

// A data row, and the NULL that is not an empty string.
func TestADataRowDistinguishesNullFromEmpty(t *testing.T) {
	raw := DataRow([]*string{Str("abc"), Str(""), nil})
	body := raw[5:]
	if n := binary.BigEndian.Uint16(body); n != 3 {
		t.Fatalf("the row declares %d columns", n)
	}
	body = body[2:]
	// "abc": three octets.
	if n := binary.BigEndian.Uint32(body); n != 3 || string(body[4:7]) != "abc" {
		t.Errorf("the first value is %d octets: %q", n, body[4:])
	}
	body = body[7:]
	// "": zero octets, which is a length of zero and not of -1.
	if n := binary.BigEndian.Uint32(body); n != 0 {
		t.Errorf("an empty string declared %d octets", n)
	}
	body = body[4:]
	// NULL: a length of -1, which a driver reads as absent.
	if n := binary.BigEndian.Uint32(body); n != 0xFFFFFFFF {
		t.Errorf("NULL declared %d octets", n)
	}
	if len(body) != 4 {
		t.Errorf("%d octets after the NULL, want none", len(body)-4)
	}
}

// A whole result set: the description, the rows, and the tag a driver reads the
// row count out of.
func TestAResultSetCarriesItsRowCountInTheTag(t *testing.T) {
	rows := [][]*string{{Str("a")}, {Str("b")}, {nil}}
	raw := ResultSet([]Field{Text("c")}, rows)
	msgs := split(t, raw)
	// One description, three rows, one CommandComplete.
	if len(msgs) != 1+len(rows)+1 {
		t.Fatalf("%d messages", len(msgs))
	}
	if msgs[0][0] != 'T' {
		t.Errorf("the set begins %q", msgs[0][0])
	}
	for i := 1; i <= len(rows); i++ {
		if msgs[i][0] != MsgDataRow {
			t.Errorf("message %d is %q, want a row", i, msgs[i][0])
		}
	}
	last := msgs[len(msgs)-1]
	if last[0] != MsgCommandComplete {
		t.Fatalf("the set ends %q", last[0])
	}
	tag, _, _ := bytes.Cut(last[5:], []byte{0})
	if string(tag) != "SELECT 3" {
		t.Errorf("the tag is %q, want SELECT 3", tag)
	}
	// An empty set is a description and a tag of zero, which is what a query
	// that matched nothing returns -- and not the same thing as an error.
	empty := split(t, ResultSet([]Field{Text("c")}, nil))
	if len(empty) != 2 {
		t.Fatalf("an empty set is %d messages", len(empty))
	}
	tag, _, _ = bytes.Cut(empty[1][5:], []byte{0})
	if string(tag) != "SELECT 0" {
		t.Errorf("an empty set's tag is %q", tag)
	}
	// And a tag carrying a NUL would truncate the message it is in.
	if got := CommandComplete("SELECT\x003"); bytes.Count(got[5:], []byte{0}) != 1 {
		t.Errorf("a tag with a NUL produced %q", got[5:])
	}
}

// A notice is an error's shape with a different type byte, which is how
// PostgreSQL volunteers something that is not a failure.
func TestANoticeIsAnErrorsShapeWithAnotherTypeByte(t *testing.T) {
	e := ErrorResponse("ERROR", "42501", "denied")
	n := NoticeResponse("NOTICE", "00000", "hello")
	if n[0] != 'N' || e[0] != MsgErrorResponse {
		t.Fatalf("types %q and %q", n[0], e[0])
	}
	if !strings.Contains(string(n), "NOTICE") || !strings.Contains(string(n), "hello") {
		t.Errorf("the notice is %q", n)
	}
	// Building a notice must not have changed the error it was built from.
	if e[0] != MsgErrorResponse {
		t.Error("NoticeResponse mutated the error it copied")
	}
}

// split reads a stream of messages, which is a second implementation of the
// framing rather than a reuse of the one under test.
func split(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(raw) > 0 {
		if len(raw) < 5 {
			t.Fatalf("%d octets left, which is less than a header", len(raw))
		}
		n := int(binary.BigEndian.Uint32(raw[1:5]))
		if n < 4 || len(raw) < 1+n {
			t.Fatalf("a message declares %d octets and %d are left", n, len(raw)-1)
		}
		out = append(out, raw[:1+n])
		raw = raw[1+n:]
	}
	return out
}
