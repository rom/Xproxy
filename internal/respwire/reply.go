package respwire

import "strconv"

// Writing RESP, which until now this package did not do.
//
// A relay forwards the octets it read and refuses with Error, so it never had to
// build a reply of its own. A fabricated server does: it is the server, and every
// reply it sends it has to encode. These are the five RESP2 types, because a
// fabrication that answered in RESP3 would be a server claiming a protocol
// version the client never asked for.
//
// Two rules hold throughout, and both are about the framing being the only thing
// separating one reply from the next. A simple string and an error are
// line-delimited, so a CR or LF inside one would end it early and the rest would
// be read as another reply -- a reply built out of a string somebody else chose.
// A bulk string is length-delimited and carries any octets at all, which is why
// everything that might contain a peer's own data goes out as one.

// Simple encodes a simple string: "+OK\r\n".
//
// The text is reduced to one line, for the reason above. A caller with anything
// that might contain a newline wants Bulk instead, which can carry it.
func Simple(s string) []byte {
	out := make([]byte, 0, len(s)+3)
	out = append(out, TypeSimpleString)
	out = append(out, oneLine(s)...)
	return append(out, '\r', '\n')
}

// Int encodes an integer: ":1\r\n".
func Int(v int64) []byte {
	out := make([]byte, 0, 24)
	out = append(out, TypeInteger)
	out = strconv.AppendInt(out, v, 10)
	return append(out, '\r', '\n')
}

// Bulk encodes a bulk string: "$3\r\nfoo\r\n".
//
// The length is the framing, so the octets are carried exactly as given --
// newlines, control characters and invalid UTF-8 included. That is what makes
// this the reply to use for anything a client will read as a value.
func Bulk(b []byte) []byte {
	out := make([]byte, 0, len(b)+16)
	out = append(out, TypeBulkString)
	out = strconv.AppendInt(out, int64(len(b)), 10)
	out = append(out, '\r', '\n')
	out = append(out, b...)
	return append(out, '\r', '\n')
}

// BulkString is Bulk for a string.
func BulkString(s string) []byte { return Bulk([]byte(s)) }

// NilBulk encodes the null bulk string, "$-1\r\n", which is how RESP2 says a key
// does not exist. It is not the same reply as an empty string, and a client
// library distinguishes them.
func NilBulk() []byte { return []byte{TypeBulkString, '-', '1', '\r', '\n'} }

// NilArray encodes the null array, "*-1\r\n": no reply rather than an empty one,
// which is what a blocking command says when it timed out.
func NilArray() []byte { return []byte{TypeArray, '-', '1', '\r', '\n'} }

// Array encodes an array of already-encoded elements.
//
// The elements are encoded, not raw values, because RESP arrays are
// heterogeneous: an element is whatever type it is, and a builder that took
// strings could not produce the nested arrays and mixed types real replies are
// made of.
func Array(elements ...[]byte) []byte {
	return arrayOf(TypeArray, elements)
}

// Map encodes a RESP3 map of already-encoded keys and values, alternating. It
// exists for HELLO 3, which is the one exchange where a client asked for RESP3
// and a RESP2 reply would be the wrong answer to the question it asked.
func Map(pairs ...[]byte) []byte {
	// The count in a map header is the number of *pairs*, not the number of
	// elements, which is the one place RESP3 counts differently from RESP2.
	out := make([]byte, 0, 16)
	out = append(out, TypeMap)
	out = strconv.AppendInt(out, int64(len(pairs)/2), 10)
	out = append(out, '\r', '\n')
	for _, e := range pairs {
		out = append(out, e...)
	}
	return out
}

func arrayOf(marker byte, elements [][]byte) []byte {
	out := make([]byte, 0, 16)
	out = append(out, marker)
	out = strconv.AppendInt(out, int64(len(elements)), 10)
	out = append(out, '\r', '\n')
	for _, e := range elements {
		out = append(out, e...)
	}
	return out
}

// Strings encodes an array of bulk strings, which is the shape of most replies
// that list things: KEYS, a CONFIG GET pair list, CLIENT LIST's siblings.
func Strings(ss ...string) []byte {
	out := make([][]byte, 0, len(ss))
	for _, s := range ss {
		out = append(out, BulkString(s))
	}
	return arrayOf(TypeArray, out)
}
