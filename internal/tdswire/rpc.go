package tdswire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Reading the statement out of a dynamic-SQL RPC.
//
// This file is why the kind inspects anything at all. A relay that classified
// only SQLBATCH would be looking at almost nothing on this protocol, because
// every client library that uses parameters -- which is every one written this
// century -- sends `sp_executesql` with the statement as a parameter rather than
// a batch. ADO.NET, JDBC, ODBC, pyodbc and go-mssqldb all do. So a T-SQL
// statement policy that only reads SQLBATCH is a statement policy that inspects
// the `SET` statements a driver emits on connect and nothing an application ever
// runs.
//
// The line this draws is worth being precise about, because ParseRPC deliberately
// does *not* read parameter values: they are the contents of somebody's database
// and a relay that held them would sooner or later put one in a log line. The
// exception is exactly and only the parameter that **is the statement**. In
// `sp_executesql(@stmt, @params, @p1, @p2, ...)`, the first parameter is the
// statement and the rest are its data; the statement is read and the data is
// skipped without ever being decoded.
//
// Which parameter carries the statement is not guessed at either. These six
// procedures have documented signatures in MS-TDS, and the position comes from
// the signature. A procedure with no entry in that table has no statement to
// read, and one whose parameters do not match its signature is refused rather
// than guessed at -- see the type list below.

// ErrParamType is a parameter whose data type this reader does not know.
//
// It is an error rather than a skip. The reader exists to find the statement in
// a call, and a type it cannot measure is a type whose *length* it cannot
// measure -- so it cannot find the parameter after it either, and everything it
// would report about the call would be about the wrong octets. Refusing a call
// it could not read is the same answer the statement classifier gives to a
// statement it cannot name.
var ErrParamType = errors.New("tdswire: unsupported parameter data type")

// The data types that appear in the documented signatures of the procedures
// below: an integer handle, an option flag, and a string.
//
// This is not a general TDS type reader and is not meant to become one. It reads
// the six signatures in stmtParam and refuses anything else, which is a small
// claim that can be true rather than a large one that would be nearly true.
const (
	typeNull      byte = 0x1f
	typeInt1      byte = 0x30
	typeBit       byte = 0x32
	typeInt2      byte = 0x34
	typeInt4      byte = 0x38
	typeInt8      byte = 0x7f
	typeIntN      byte = 0x26
	typeBitN      byte = 0x68
	typeBigVarChr byte = 0xa7
	typeNVarChar  byte = 0xe7
	typeNText     byte = 0x63
)

// stmtParam is the 1-based position of the parameter that carries a statement,
// by procedure name, from the signatures in MS-TDS.
//
// `sp_prepexecrpc` is deliberately absent although its second parameter is a
// string: that string is an RPC call rather than a batch, so classifying it as
// T-SQL would name it `unknown` and refuse every use of the procedure. It is
// absent from the default procedure allow list instead, so allowing it is a
// choice an operator makes knowing the call is not inspected.
var stmtParam = map[string]int{
	"sp_executesql":     1,
	"sp_prepare":        3,
	"sp_prepexec":       3,
	"sp_cursorprepare":  3,
	"sp_cursorprepexec": 4,
	"sp_cursoropen":     2,
}

// StatementParam says which parameter of a procedure carries a statement.
func StatementParam(proc string) (int, bool) {
	n, ok := stmtParam[proc]
	return n, ok
}

// DynamicProcedures is every procedure whose statement this reader can find, for
// a document and an error message.
func DynamicProcedures() []string {
	return []string{"sp_executesql", "sp_prepare", "sp_prepexec",
		"sp_cursorprepare", "sp_cursorprepexec", "sp_cursoropen"}
}

// readStatementParam walks the parameter list to position n and decodes it.
//
// Every parameter before it is measured and stepped over without its value being
// decoded. Measuring is not the same as reading: the length is protocol
// structure and the octets it covers are the caller's data.
func readStatementParam(b []byte, n int) (string, error) {
	i := 0
	for pos := 1; pos <= n; pos++ {
		if pos > MaxRPCParams {
			return "", ErrTooMany
		}
		// B_VARCHAR name: one octet of length in characters.
		if i >= len(b) {
			return "", fmt.Errorf("%w: parameter %d is missing", ErrTruncated, pos)
		}
		nameChars := int(b[i])
		i++
		if i+nameChars*2 > len(b) {
			return "", ErrTruncated
		}
		i += nameChars * 2
		// Status flags.
		if i >= len(b) {
			return "", ErrTruncated
		}
		i++
		if i >= len(b) {
			return "", ErrTruncated
		}
		typ := b[i]
		i++
		val, next, err := paramValue(b, i, typ)
		if err != nil {
			return "", err
		}
		if pos == n {
			st, err := decodeParam(typ, val)
			if err != nil {
				return "", err
			}
			if st == "" {
				// A NULL or empty statement parameter. The call cannot be the
				// one its signature describes, and a relay that let it through
				// as "an empty statement, nothing to decide" would be passing
				// the one message on this protocol that carries arbitrary SQL
				// without having read any.
				return "", fmt.Errorf("%w: an empty statement parameter", ErrTruncated)
			}
			return st, nil
		}
		i = next
	}
	return "", ErrTruncated
}

// paramValue measures one parameter's TYPE_INFO and value, returning the value's
// octets and where the next parameter starts.
func paramValue(b []byte, i int, typ byte) (val []byte, next int, err error) {
	switch typ {
	case typeNull:
		return nil, i, nil
	case typeInt1, typeBit:
		return take(b, i, 1)
	case typeInt2:
		return take(b, i, 2)
	case typeInt4:
		return take(b, i, 4)
	case typeInt8:
		return take(b, i, 8)

	case typeIntN, typeBitN:
		// TYPE_INFO is one octet of maximum length; the value is one octet of
		// actual length and then that many.
		if i >= len(b) {
			return nil, 0, ErrTruncated
		}
		i++
		if i >= len(b) {
			return nil, 0, ErrTruncated
		}
		got := int(b[i])
		i++
		return take(b, i, got)

	case typeNVarChar, typeBigVarChr:
		// TYPE_INFO is a two-octet maximum length and a five-octet collation.
		if i+7 > len(b) {
			return nil, 0, ErrTruncated
		}
		maxLen := int(binary.LittleEndian.Uint16(b[i : i+2]))
		i += 7
		if maxLen == 0xffff {
			// PLP: the form a statement longer than 4000 characters takes, and
			// the reason this reader exists at all rather than reading the
			// short form only.
			return plp(b, i)
		}
		if i+2 > len(b) {
			return nil, 0, ErrTruncated
		}
		got := int(binary.LittleEndian.Uint16(b[i : i+2]))
		i += 2
		if got == 0xffff {
			// NULL.
			return nil, i, nil
		}
		return take(b, i, got)

	case typeNText:
		// TYPE_INFO is a four-octet maximum length and a five-octet collation.
		// The value is a text pointer, a timestamp, and then the data -- the
		// shape an older driver sends a long statement in.
		if i+9 > len(b) {
			return nil, 0, ErrTruncated
		}
		i += 9
		if i >= len(b) {
			return nil, 0, ErrTruncated
		}
		ptr := int(b[i])
		i++
		if ptr == 0 {
			// NULL: no pointer, no timestamp, no data.
			return nil, i, nil
		}
		if i+ptr+8+4 > len(b) {
			return nil, 0, ErrTruncated
		}
		i += ptr + 8
		got := int(binary.LittleEndian.Uint32(b[i : i+4]))
		i += 4
		return take(b, i, got)
	}
	return nil, 0, fmt.Errorf("%w: %#02x", ErrParamType, typ)
}

// plp measures a partially length-prefixed value: a total length, then chunks,
// then a zero-length chunk.
func plp(b []byte, i int) (val []byte, next int, err error) {
	const (
		plpNull    = 0xffffffffffffffff
		plpUnknown = 0xfffffffffffffffe
	)
	if i+8 > len(b) {
		return nil, 0, ErrTruncated
	}
	total := binary.LittleEndian.Uint64(b[i : i+8])
	i += 8
	if total == plpNull {
		return nil, i, nil
	}
	// The declared total is a number the peer chose, so it is used to bound the
	// buffer and never to size it: what is actually read is the chunks.
	if total != plpUnknown && total > uint64(MaxMessage) {
		return nil, 0, fmt.Errorf("%w: %d octets declared", ErrTooLong, total)
	}
	out := make([]byte, 0, 256)
	for {
		if i+4 > len(b) {
			return nil, 0, ErrTruncated
		}
		chunk := int(binary.LittleEndian.Uint32(b[i : i+4]))
		i += 4
		if chunk == 0 {
			return out, i, nil
		}
		if chunk < 0 || i+chunk > len(b) {
			return nil, 0, ErrTruncated
		}
		if len(out)+chunk > MaxMessage {
			return nil, 0, ErrTooLong
		}
		out = append(out, b[i:i+chunk]...)
		i += chunk
		if total != plpUnknown && uint64(len(out)) > total {
			// The chunks say more than the total did. One of the two is wrong
			// and there is no way to tell which, so neither is believed.
			return nil, 0, fmt.Errorf("%w: chunks exceed the declared %d octets",
				ErrTruncated, total)
		}
	}
}

func take(b []byte, i, n int) (val []byte, next int, err error) {
	if n < 0 || i+n > len(b) {
		return nil, 0, ErrTruncated
	}
	return b[i : i+n], i + n, nil
}

// decodeParam turns the statement parameter's octets into text.
//
// A statement must be a string type. An integer in the statement's position
// means the call did not match the signature the position came from, so the
// position itself is not to be trusted -- and a relay that took the next
// plausible-looking parameter instead would be deciding about a statement the
// server may never run.
func decodeParam(typ byte, val []byte) (string, error) {
	switch typ {
	case typeNVarChar, typeNText:
		return UCS2(val)
	case typeBigVarChr:
		return string(val), nil
	}
	return "", fmt.Errorf("%w: %#02x in a statement parameter", ErrParamType, typ)
}
