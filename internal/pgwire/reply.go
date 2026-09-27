package pgwire

import (
	"encoding/binary"
	"strconv"
)

// Writing a whole server's side, which the file beside this one deliberately did
// not do.
//
// A relay only ever has to refuse, which is an ErrorResponse and a ReadyForQuery.
// A fabricated server has to produce everything: the authentication exchange that
// opens a connection, the parameters it announces, the row descriptions and rows
// of a result set, and the CommandComplete tag that ends one.
//
// Three things about this protocol are easy to get subtly wrong and are handled
// here rather than by each caller.
//
// A message's length field counts itself and excludes the type byte. Off by one
// either way and the client reads the next message from the wrong offset, which
// is not an error but a client that reports nonsense about a message it never
// received.
//
// The startup sequence is fixed and a client waits for all of it:
// AuthenticationOk, then the ParameterStatus messages, then BackendKeyData, then
// ReadyForQuery. A server that skipped BackendKeyData would leave libpq unable to
// cancel a query, and one that skipped ParameterStatus for server_version or
// client_encoding leaves several drivers guessing.
//
// A CommandComplete tag is text a client parses: "SELECT 3" carries the row
// count, "INSERT 0 1" carries the object id and the count. A driver reads the
// number out of it to answer "how many rows did that affect", so the tag is part
// of the answer and not decoration.

// AuthenticationOk tells the client the credential was accepted, which is message
// 'R' with a zero code.
func AuthenticationOk() []byte {
	return []byte{MsgAuthentication, 0, 0, 0, 8, 0, 0, 0, 0}
}

// AuthenticationRequest asks the client for a credential.
//
// salt is the four octets an MD5 request carries and is ignored by the others. A
// request of the wrong length is one no client can answer, so the length follows
// the method rather than the caller.
func AuthenticationRequest(method int32, salt []byte) []byte {
	body := make([]byte, 0, 8)
	body = binary.BigEndian.AppendUint32(body, uint32(method)) //nolint:gosec // one of the constants above
	if method == AuthMD5Password {
		if len(salt) != 4 {
			salt = []byte{0x2f, 0x7b, 0xc1, 0x53}
		}
		body = append(body, salt...)
	}
	return message(MsgAuthentication, body)
}

// ParameterStatus announces one server setting. A client reads server_version
// from here and several drivers will not proceed without client_encoding.
func ParameterStatus(name, value string) []byte {
	body := make([]byte, 0, len(name)+len(value)+2)
	body = append(body, safeText(name)...)
	body = append(body, 0)
	body = append(body, safeText(value)...)
	body = append(body, 0)
	return message(MsgParameterStatus, body)
}

// BackendKeyData is the process identifier and secret a client needs in order to
// cancel a query. A server that omits it leaves libpq unable to cancel, which is
// a difference a driver notices.
func BackendKeyData(pid, secret uint32) []byte {
	body := binary.BigEndian.AppendUint32(nil, pid)
	body = binary.BigEndian.AppendUint32(body, secret)
	return message(MsgBackendKeyData, body)
}

// NoticeResponse is a message the server volunteers without it being an error,
// which is how PostgreSQL says "database does not exist, using template" and the
// like. It is the same shape as ErrorResponse with a different type byte.
func NoticeResponse(severity, code, text string) []byte {
	e := ErrorResponse(severity, code, text)
	out := append([]byte(nil), e...)
	out[0] = 'N'
	return out
}

// CommandComplete ends a statement. The tag is text a driver parses for the row
// count, so "SELECT 3" and "INSERT 0 1" are answers rather than labels.
func CommandComplete(tag string) []byte {
	body := append([]byte(safeText(tag)), 0)
	return message(MsgCommandComplete, body)
}

// SelectTag is the CommandComplete tag of a query that returned rows.
func SelectTag(rows int) string { return "SELECT " + strconv.Itoa(rows) }

// EmptyQueryResponse is what the server answers to a statement with nothing in
// it, which the protocol allows a client to send and which is not an error.
func EmptyQueryResponse() []byte { return []byte{'I', 0, 0, 0, 4} }

// Field is one column of a fabricated result set.
type Field struct {
	Name string
	// OID is the type's object identifier. 25 is text, 23 is int4, 16 is bool,
	// 1184 is timestamptz. A driver converts by this, so a column of numbers
	// declared as text comes back to the application as strings.
	OID uint32
	// Size is the type's declared width in octets, or -1 for a variable-length
	// one. A fixed-width type whose size disagrees with its identifier is a
	// contradiction a driver may act on.
	Size int16
	// Modifier is the type-specific modifier, or -1 for none: the length of a
	// varchar(n), the precision of a numeric.
	Modifier int32
}

// The type identifiers a fabricated result set uses. PostgreSQL has hundreds;
// these are the four that cover a row of strings, numbers, booleans and times.
const (
	OIDBool        uint32 = 16
	OIDInt4        uint32 = 23
	OIDText        uint32 = 25
	OIDName        uint32 = 19
	OIDTimestamptz uint32 = 1184
	OIDOID         uint32 = 26
)

// Text is a variable-length text column, which is what almost every fabricated
// answer is: a version string, a setting, a database name.
func Text(name string) Field {
	return Field{Name: name, OID: OIDText, Size: -1, Modifier: -1}
}

// RowDescription describes the columns of the rows that follow.
func RowDescription(fields []Field) []byte {
	body := binary.BigEndian.AppendUint16(nil, uint16(len(fields))) //nolint:gosec // a column count
	for _, f := range fields {
		oid := f.OID
		if oid == 0 {
			oid = OIDText
		}
		size := f.Size
		if size == 0 {
			size = -1
		}
		mod := f.Modifier
		if mod == 0 {
			mod = -1
		}
		body = append(body, safeText(f.Name)...)
		body = append(body, 0)
		// The table and column this came from: zero for a column that came from
		// an expression rather than a table, which is what every fabricated
		// answer here is.
		body = binary.BigEndian.AppendUint32(body, 0)
		body = binary.BigEndian.AppendUint16(body, 0)
		body = binary.BigEndian.AppendUint32(body, oid)
		body = binary.BigEndian.AppendUint16(body, uint16(size)) //nolint:gosec // -1 is 0xFFFF by design
		body = binary.BigEndian.AppendUint32(body, uint32(mod))  //nolint:gosec // and likewise
		// Format code: 0 is text, which is what the simple query protocol always
		// uses. A fabrication that declared binary would have to produce binary.
		body = binary.BigEndian.AppendUint16(body, 0)
	}
	return message('T', body)
}

// DataRow is one row. A nil element is SQL NULL, which is a length of -1 and not
// an empty string: a driver distinguishes them and an application acts on the
// difference.
func DataRow(values []*string) []byte {
	body := binary.BigEndian.AppendUint16(nil, uint16(len(values))) //nolint:gosec // a column count
	for _, v := range values {
		if v == nil {
			body = binary.BigEndian.AppendUint32(body, 0xFFFFFFFF)
			continue
		}
		body = binary.BigEndian.AppendUint32(body, uint32(len(*v))) //nolint:gosec // bounded by the value
		body = append(body, *v...)
	}
	return message(MsgDataRow, body)
}

// ResultSet is a whole answer: the description, the rows, and the tag.
func ResultSet(fields []Field, rows [][]*string) []byte {
	out := RowDescription(fields)
	for _, r := range rows {
		out = append(out, DataRow(r)...)
	}
	return append(out, CommandComplete(SelectTag(len(rows)))...)
}

// Str is a value for a row, for the common case of one that is not NULL.
func Str(s string) *string { return &s }

// message frames a body with its type byte and its length.
//
// The length counts itself and excludes the type byte, which is the one arithmetic
// in this protocol that is worth doing in a single place: off by one either way
// and the client reads the next message from the wrong offset, which is not an
// error but a client reporting nonsense about a message it never received.
func message(kind byte, body []byte) []byte {
	out := make([]byte, 0, 5+len(body))
	out = append(out, kind)
	out = binary.BigEndian.AppendUint32(out, uint32(4+len(body))) //nolint:gosec // bounded by the body
	return append(out, body...)
}
