package pgwire

import (
	"encoding/binary"
	"strings"
)

// What the relay writes itself.
//
// This is deliberately short. A relay that refuses a statement has to say so in
// the protocol the client is speaking, or the client hangs -- and on this
// protocol that means an ErrorResponse followed by a ReadyForQuery, because a
// client in the simple query protocol waits for the second one before it will
// send anything else. Everything else the relay forwards unchanged.

// ErrorResponse builds a backend error message.
//
// severity is "FATAL" to end the connection or "ERROR" to refuse one statement
// and carry on. code is a five-character SQLSTATE: the class matters, because
// clients switch on it. 42501 is insufficient_privilege, which is the truthful
// answer when a relay refuses a statement the role could otherwise have run --
// the client library will report it the way it reports the database's own
// refusals, and an application's existing error handling works.
func ErrorResponse(severity, code, message string) []byte {
	fields := []struct {
		c byte
		v string
	}{
		{'S', severity},
		// V is the non-localised severity, which clients added in 9.6 and
		// which must agree with S.
		{'V', severity},
		{'C', code},
		{'M', safeText(message)},
	}
	n := 4
	for _, f := range fields {
		n += 1 + len(f.v) + 1
	}
	n++ // the terminating zero
	out := make([]byte, 0, 1+n)
	out = append(out, MsgErrorResponse)
	out = binary.BigEndian.AppendUint32(out, uint32(n)) //nolint:gosec // bounded by the message
	for _, f := range fields {
		out = append(out, f.c)
		out = append(out, f.v...)
		out = append(out, 0)
	}
	return append(out, 0)
}

// ReadyForQuery tells the client the relay is willing to hear another statement.
// status is 'I' idle, 'T' in a transaction, 'E' in a failed transaction.
func ReadyForQuery(status byte) []byte {
	return []byte{MsgReadyForQuery, 0, 0, 0, 5, status}
}

// safeText makes a message fit to put in a protocol field.
//
// The strings the relay puts in an error are its own, but they quote things a
// client chose -- a statement's leading keyword, a database name -- and a NUL
// would truncate the field while a newline would split a log line at the other
// end. So the text is clipped and the control characters go.
func safeText(s string) string {
	s = Clip(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// DenyTLS is the single octet a server sends to refuse an SSLRequest.
//
// It exists here so that the one place a relay might send it is named. A relay
// configured to require TLS must never send this: refusing the *request* is how
// a client with sslmode=prefer ends up in the clear, which is the downgrade the
// setting exists to prevent. The refusal for a client that will not use TLS is
// to close the connection, which libpq reports as a failure rather than
// silently continuing.
const DenyTLS = 'N'

// AllowTLS is the single octet that accepts an SSLRequest.
const AllowTLS = 'S'
