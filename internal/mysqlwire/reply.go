package mysqlwire

import "encoding/binary"

// Writing the server's side, which until now this package did not do.
//
// A relay forwards the octets it read and refuses with ErrPacket, so the only
// server packet it ever built was a refusal. A fabricated server has to build all
// of them: the greeting that starts a connection, the OK that ends a command, and
// the column definitions and rows of a result set.
//
// Three things about this protocol make a fabrication easy to get subtly wrong,
// and all three are handled here rather than by each caller.
//
// The sequence number is per *command* and restarts at zero on each one, and a
// client library checks it: a result set is packets 1, 2, 3, … after the query it
// answers, and a gap makes the library report a protocol error rather than the
// rows. So every builder here takes the sequence it is writing at and the caller
// counts.
//
// Lengths are length-encoded integers, which are not the fixed-width fields they
// look like. A string of 250 octets and one of 252 are framed differently, and a
// library reading the second as the first sees the rest of the row as garbage.
//
// And a result set's shape depends on a capability the client negotiated:
// CLIENT_DEPRECATE_EOF replaces the two EOF packets with an OK packet, and a
// client that asked for it and received EOF stops reading.

// The column types a fabricated result set uses. The protocol has forty; these
// are the four that cover a row of strings and numbers.
const (
	TypeLong      byte = 0x03
	TypeLongLong  byte = 0x08
	TypeVarchar   byte = 0x0F
	TypeDatetime  byte = 0x0C
	TypeVarString byte = 0xFD
)

// AppendLenEncInt writes a length-encoded integer.
//
// The thresholds are the protocol's own and they are not powers of two: 251 is
// where the one-octet form stops, because 0xFB through 0xFF are markers. A
// writer that used 255 would produce a value the reader takes for a NULL.
func AppendLenEncInt(b []byte, v uint64) []byte {
	switch {
	case v < 251:
		return append(b, byte(v))
	case v <= 0xFFFF:
		b = append(b, 0xFC)
		return binary.LittleEndian.AppendUint16(b, uint16(v))
	case v <= 0xFFFFFF:
		b = append(b, 0xFD)
		return append(b, byte(v), byte(v>>8), byte(v>>16))
	default:
		b = append(b, 0xFE)
		return binary.LittleEndian.AppendUint64(b, v)
	}
}

// AppendLenEncString writes a length-encoded string.
func AppendLenEncString(b []byte, s string) []byte {
	b = AppendLenEncInt(b, uint64(len(s)))
	return append(b, s...)
}

// GreetingOptions is what a fabricated greeting says about itself.
type GreetingOptions struct {
	// Version is the server version string, which is the first thing a scanner
	// records and what a vulnerability database is indexed by. MySQL puts the
	// suffix after the number, as in "8.0.36-0ubuntu0.22.04.1".
	Version string
	// ThreadID is the connection identifier, which a client echoes in
	// KILL and which appears in the server's own logs.
	ThreadID uint32
	// Salt is the twenty-octet authentication challenge. It must be twenty
	// octets and must not contain a NUL: the protocol splits it into eight and
	// twelve with a NUL between, and a NUL inside either half truncates it.
	Salt []byte
	// Caps is the capability mask offered. CapProtocol41 and
	// CapSecureConnection are not optional in practice -- every client library
	// written this century requires both.
	Caps uint32
	// Charset is the collation identifier: 255 is utf8mb4_0900_ai_ci, which is
	// MySQL 8's default, and 33 is utf8_general_ci, which was 5.7's.
	Charset byte
	// AuthPlugin is the default authentication plugin name.
	AuthPlugin string
}

// Greet builds the server's initial handshake, which is packet 0 of a
// connection and the only packet a server sends unprompted.
func Greet(o GreetingOptions) []byte {
	salt := o.Salt
	if len(salt) != 20 {
		// A challenge of the wrong length is one no client can answer, so the
		// builder produces a usable one rather than a packet that fails at the
		// other end. It is not a secret -- it is a nonce, and the fabrication
		// does not check the answer.
		salt = make([]byte, 20)
		for i := range salt {
			salt[i] = byte('a' + (i*7+3)%26)
		}
	}
	plugin := o.AuthPlugin
	if plugin == "" {
		plugin = "caching_sha2_password"
	}
	caps := o.Caps
	charset := o.Charset
	if charset == 0 {
		charset = 255
	}
	p := make([]byte, 0, 80)
	p = append(p, 10) // protocol version
	p = append(p, safeText(o.Version)...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, o.ThreadID)
	// The first eight octets of the challenge, then the filler NUL that splits
	// it. This is the shape, and it is the reason a NUL inside the salt breaks
	// a client: it cannot tell the filler from the data.
	p = append(p, salt[:8]...)
	p = append(p, 0)
	// The capability mask is split across two 16-bit fields with the charset and
	// the status flags between them, which is the protocol's own layout: the
	// truncation here is the split, not a loss.
	p = binary.LittleEndian.AppendUint16(p, uint16(caps)) //nolint:gosec // the low half, by the protocol's layout
	p = append(p, charset)
	p = binary.LittleEndian.AppendUint16(p, 2)                // status: SERVER_STATUS_AUTOCOMMIT
	p = binary.LittleEndian.AppendUint16(p, uint16(caps>>16)) //nolint:gosec // and the high half
	// The plugin data length: the whole challenge plus its terminating NUL.
	p = append(p, byte(len(salt)+1))
	p = append(p, make([]byte, 10)...) // reserved
	p = append(p, salt[8:]...)
	p = append(p, 0)
	p = append(p, plugin...)
	p = append(p, 0)
	return Frame(0, p)
}

// OKPacket builds an OK, which is how the server ends a command that produced no
// rows.
//
// The status flags carry SERVER_STATUS_AUTOCOMMIT, which is the state a
// connection is in before anything has started a transaction. A library that read
// zero there would believe it was inside one.
func OKPacket(seq byte, affected, insertID uint64, warnings uint16, info string) []byte {
	p := make([]byte, 0, 16+len(info))
	p = append(p, RespOK)
	p = AppendLenEncInt(p, affected)
	p = AppendLenEncInt(p, insertID)
	p = binary.LittleEndian.AppendUint16(p, 2) // SERVER_STATUS_AUTOCOMMIT
	p = binary.LittleEndian.AppendUint16(p, warnings)
	p = append(p, safeText(info)...)
	return Frame(seq, p)
}

// EOFPacket builds an EOF, which ends a column-definition block and a row block
// on a connection that did not negotiate CLIENT_DEPRECATE_EOF.
func EOFPacket(seq byte, warnings uint16) []byte {
	p := make([]byte, 0, 5)
	p = append(p, RespEOF)
	p = binary.LittleEndian.AppendUint16(p, warnings)
	p = binary.LittleEndian.AppendUint16(p, 2) // SERVER_STATUS_AUTOCOMMIT
	return Frame(seq, p)
}

// Column is one column of a fabricated result set.
type Column struct {
	// Name is what the client sees as the column heading, and Table the table it
	// says the column came from. A row with no table is what an expression
	// produces: SELECT 1 has a column and no table.
	Name  string
	Table string
	// Type is one of the Type constants, and Length the display width the
	// server declares. Neither is checked by a client against the values that
	// follow, but a library uses Type to decide how to convert them.
	Type   byte
	Length uint32
	// Flags and Decimals are the column's own attributes; zero is the ordinary
	// case for a nullable string.
	Flags    uint16
	Decimals byte
}

// ColumnDef builds one column definition packet, which is the protocol 4.1 form
// every client library expects.
func ColumnDef(seq byte, c Column) []byte {
	typ := c.Type
	if typ == 0 {
		typ = TypeVarString
	}
	length := c.Length
	if length == 0 {
		length = 255
	}
	p := make([]byte, 0, 64+len(c.Name)+len(c.Table))
	p = AppendLenEncString(p, "def") // catalog
	p = AppendLenEncString(p, "")    // schema
	p = AppendLenEncString(p, c.Table)
	p = AppendLenEncString(p, c.Table) // original table
	p = AppendLenEncString(p, c.Name)
	p = AppendLenEncString(p, c.Name) // original name
	p = append(p, 0x0C)               // the fixed-length fields that follow
	p = binary.LittleEndian.AppendUint16(p, 255)
	p = binary.LittleEndian.AppendUint32(p, length)
	p = append(p, typ)
	p = binary.LittleEndian.AppendUint16(p, c.Flags)
	p = append(p, c.Decimals)
	p = append(p, 0, 0) // filler
	return Frame(seq, p)
}

// RowPacket builds one text-protocol row.
//
// A nil element is SQL NULL, which is 0xFB and not an empty string: a client
// library distinguishes them, and a fabrication that sent "" where it meant NULL
// would be a server whose schema does not match its data.
func RowPacket(seq byte, values []*string) []byte {
	p := make([]byte, 0, 32)
	for _, v := range values {
		if v == nil {
			p = append(p, 0xFB)
			continue
		}
		p = AppendLenEncString(p, *v)
	}
	return Frame(seq, p)
}

// ResultSet builds a whole text result set: the column count, the definitions,
// the rows and the terminators.
//
// deprecateEOF is whether the client negotiated CLIENT_DEPRECATE_EOF, which
// replaces both EOF packets with nothing and an OK respectively. Getting it
// wrong is not a wrong answer but a stalled client: one that asked for the new
// shape and received EOF stops reading where it expected more.
//
// The returned sequence is the next one to use, because a connection's numbering
// continues across the packets of one command.
func ResultSet(seq byte, cols []Column, rows [][]*string, deprecateEOF bool) ([]byte, byte) {
	var out []byte
	count := make([]byte, 0, 4)
	count = AppendLenEncInt(count, uint64(len(cols)))
	out = append(out, Frame(seq, count)...)
	seq++
	for _, c := range cols {
		out = append(out, ColumnDef(seq, c)...)
		seq++
	}
	if !deprecateEOF {
		out = append(out, EOFPacket(seq, 0)...)
		seq++
	}
	for _, r := range rows {
		out = append(out, RowPacket(seq, r)...)
		seq++
	}
	if deprecateEOF {
		out = append(out, OKPacket(seq, 0, 0, 0, "")...)
	} else {
		out = append(out, EOFPacket(seq, 0)...)
	}
	return out, seq + 1
}

// Str is a value for a row, for the common case of one that is not NULL.
func Str(s string) *string { return &s }
