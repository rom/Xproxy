// Package pgwire reads the PostgreSQL frontend/backend protocol, version 3.
//
// The protocol is documented in the PostgreSQL manual, part IV chapter 55. It
// is a simple framing -- a type octet, a length, a body -- with three
// irregularities that decide the shape of this package, and each of them is
// where a relay either does its job or quietly fails to.
//
// **The first message a client sends has no type octet.** Every other message
// is type(1) + length(4) + body, but the first is length(4) + code(4) + body,
// and the code says what it is: 196608 is "I am a version 3 client, here are my
// parameters", 80877103 is "may I use TLS", 80877104 is "may I use GSSAPI
// encryption", and 80877102 is "cancel the query running on this backend". A
// reader that assumed the first octet was a type would read the high octet of a
// length as one, which for every message this decade is zero -- and zero is not
// a type, so it would refuse every connection or, worse, guess.
//
// **The encryption negotiation happens in cleartext, and the server may say
// no.** The client sends eight octets asking for TLS and the server answers
// with a single octet: 'S' yes, 'N' no. Then TLS begins on the same connection.
// Nothing signs that octet, so anybody on the path can turn 'S' into 'N' --
// and libpq's default sslmode is `prefer`, which means "ask for TLS and carry
// on in the clear if refused, without telling anybody". So the default
// configuration of the most widely deployed client in the world downgrades
// silently when asked to. That is not a bug in this package's reach to fix, and
// it is exactly what a relay can refuse on a client's behalf: see the
// `require_tls` setting on the kind. MySQL's CLIENT_SSL capability flag and
// TDS's PRELOGIN encryption option are the same shape, and the same answer.
//
// **The same octet means different things in each direction.** 'D' is Describe
// from the client and DataRow from the server; 'S' is Sync and ParameterStatus;
// 'C' is Close and CommandComplete; 'E' is Execute and ErrorResponse; 'H' is
// Flush and CopyOutResponse. A relay that kept one table for both directions
// would read a row of somebody's data as a request to describe a portal. So
// every reader here is told which direction it is reading, and the names are
// separate types.
//
// What this package does not do is parse SQL. It classifies a statement by its
// leading keyword after comments and quoting are stripped (see statement.go),
// which is a different and much smaller claim -- and the policy is built so
// that a statement the classifier cannot name is refused rather than passed.
package pgwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// The startup codes, which take the place of a message type in the first
// message on a connection.
const (
	// Version3 is the only protocol version this relay speaks. Version 2 was
	// removed from the server in PostgreSQL 14 and its startup packet is a
	// different shape; a relay that guessed at it would be forwarding a
	// message it had not read.
	Version3 = 196608
	// SSLRequest asks to start TLS on this connection.
	SSLRequest = 80877103
	// GSSEncRequest asks to start GSSAPI encryption instead.
	GSSEncRequest = 80877104
	// CancelRequest cancels a query running on another connection. It arrives
	// on a connection of its own and the server acts on it with no
	// authentication at all: the whole credential is a backend process
	// identifier and a 32-bit secret the server handed out earlier.
	CancelRequest = 80877102
)

// Bounds on what a peer may say. Every one of these is a number the peer
// chooses, so each is a refusal rather than an allocation.
const (
	// MaxMessage is the largest message body this relay will read. The
	// protocol's own limit is the 4-byte length field, which is two
	// gigabytes; a relay that trusted it would let one message be a memory
	// exhaustion. A megabyte is generous for a statement and small enough
	// that a thousand connections cannot be a denial of service. COPY data
	// is streamed rather than held, and has its own bound.
	MaxMessage = 1 << 20
	// MaxStartupParams bounds the key/value pairs in a startup packet.
	MaxStartupParams = 64
	// MaxParams bounds the parameters in one Bind.
	MaxParams = 1024
	// MaxString clips a peer-chosen string kept for a log line or an asset
	// record. A user name with a control sequence in it is a log injection.
	MaxString = 256
)

// Errors this package returns. Each is a refusal to read, not a refusal to
// serve: the caller decides what to do about a message it cannot read, and on
// this protocol the answer is always to end the connection, because the stream
// is framed and a reader that has lost the framing cannot find the next
// message.
var (
	// ErrShort is a message whose length field says less than the length
	// field itself occupies. A length of 0 or 1 is the classic underflow:
	// it is self-referential, so a reader that subtracted four would either
	// allocate two gigabytes or loop forever on the same four octets.
	ErrShort = errors.New("pgwire: message length is shorter than its own field")
	// ErrTooLong is a message past MaxMessage.
	ErrTooLong = errors.New("pgwire: message is longer than the bound")
	// ErrTruncated is a body that ran out before the fields in it did.
	ErrTruncated = errors.New("pgwire: message ends inside a field")
	// ErrNotTerminated is a string field with no terminating zero. The
	// protocol's strings are C strings; one that runs to the end of the
	// message is a message the relay and the server would read differently,
	// which is the TFTP filename lesson on a different protocol.
	ErrNotTerminated = errors.New("pgwire: string field is not terminated")
	// ErrVersion is a startup packet naming a protocol this relay does not
	// speak.
	ErrVersion = errors.New("pgwire: unsupported protocol version")
	// ErrTooMany is a count past its bound.
	ErrTooMany = errors.New("pgwire: more fields than the bound allows")
)

// Direction says which side of the connection a message came from, because the
// same type octet means different things each way.
type Direction int

// The two directions.
const (
	// FromClient is a frontend message.
	FromClient Direction = iota
	// FromServer is a backend message.
	FromServer
)

// The frontend message types, as the manual names them.
const (
	MsgQuery           byte = 'Q'
	MsgParse           byte = 'P'
	MsgBind            byte = 'B'
	MsgExecute         byte = 'E'
	MsgDescribe        byte = 'D'
	MsgClose           byte = 'C'
	MsgSync            byte = 'S'
	MsgFlush           byte = 'H'
	MsgTerminate       byte = 'X'
	MsgCopyData        byte = 'd'
	MsgCopyDone        byte = 'c'
	MsgCopyFail        byte = 'f'
	MsgFunctionCall    byte = 'F'
	MsgPasswordMessage byte = 'p'
)

// The backend message types this relay needs to recognise. It does not need
// them all: a relay reads the answers for the ones that change what it knows
// -- whether authentication succeeded, what the backend key is, whether a COPY
// is now in progress -- and forwards the rest without claiming to understand
// them, which is honest and is also what keeps it working against a server
// newer than itself.
const (
	MsgAuthentication  byte = 'R'
	MsgBackendKeyData  byte = 'K'
	MsgParameterStatus byte = 'S'
	MsgReadyForQuery   byte = 'Z'
	MsgErrorResponse   byte = 'E'
	MsgCommandComplete byte = 'C'
	MsgDataRow         byte = 'D'
	MsgCopyInResponse  byte = 'G'
	MsgCopyOutResponse byte = 'H'
	MsgCopyBothRespons byte = 'W'
	MsgNegotiateProto  byte = 'v'
)

// The authentication requests a server can make, from the body of an
// Authentication message.
const (
	AuthOK                = 0
	AuthKerberosV5        = 2
	AuthCleartextPassword = 3
	AuthMD5Password       = 5
	AuthSCMCredential     = 6
	AuthGSS               = 7
	AuthGSSContinue       = 8
	AuthSSPI              = 9
	AuthSASL              = 10
	AuthSASLContinue      = 11
	AuthSASLFinal         = 12
)

// AuthName is how a configuration and a log line spell an authentication
// method. The names are the ones the PostgreSQL manual and pg_hba.conf use, so
// that an operator writing a policy writes what they already know.
func AuthName(code int32) string {
	switch code {
	case AuthOK:
		return "ok"
	case AuthKerberosV5:
		return "kerberos"
	case AuthCleartextPassword:
		return "password"
	case AuthMD5Password:
		return "md5"
	case AuthSCMCredential:
		return "scm"
	case AuthGSS, AuthGSSContinue:
		return "gss"
	case AuthSSPI:
		return "sspi"
	case AuthSASL, AuthSASLContinue, AuthSASLFinal:
		return "scram"
	}
	return fmt.Sprintf("unknown_%d", code)
}

// Weak says whether an authentication method sends something an observer can
// reuse.
//
// `password` is the password itself in cleartext: on a connection that is not
// encrypted it is the credential, in the clear, and this relay's whole reason
// for reading the authentication exchange is to be able to refuse that. `md5`
// is unsalted-per-session only in the sense that the salt is per connection --
// the stored verifier is md5(password+username), so the hash *is* the
// password-equivalent, and anybody who reads the server's table can
// authenticate without cracking anything. PostgreSQL has deprecated it since
// version 10, when SCRAM arrived, and it is still the default in an
// unfortunate number of deployed configurations.
//
// `scram` (SCRAM-SHA-256, RFC 7677) and the Kerberos family are not weak.
func Weak(code int32) bool {
	switch code {
	case AuthCleartextPassword, AuthMD5Password, AuthSCMCredential:
		return true
	}
	return false
}

// Startup is the first message on a connection, whichever of the four shapes
// it took.
type Startup struct {
	// Code is the raw code: Version3, SSLRequest, GSSEncRequest or
	// CancelRequest.
	Code int32
	// Params are the key/value pairs of a version 3 startup packet, in the
	// order they were sent. A map would lose that order, and the order is
	// what a relay writes back when it forwards the packet.
	Params []Param
	// PID and Secret are the two fields of a CancelRequest.
	PID, Secret int32
}

// Param is one startup parameter.
type Param struct{ Key, Value string }

// Get returns a parameter's value.
func (s *Startup) Get(key string) string {
	for _, p := range s.Params {
		if p.Key == key {
			return p.Value
		}
	}
	return ""
}

// User is the role the client is asking to be. It is required: a version 3
// startup packet without it is one the server will refuse, and a relay that
// let it through would be deciding about a connection with no identity in it.
func (s *Startup) User() string { return s.Get("user") }

// Database is the database the client asked for, which defaults to the user
// name when the parameter is absent -- a default a policy has to apply itself,
// because "the database is empty so no rule matched" would be a rule that
// never fires on the commonest connection string there is.
func (s *Startup) Database() string {
	if db := s.Get("database"); db != "" {
		return db
	}
	return s.User()
}

// Replication says the client asked for a replication connection, and which
// kind.
//
// This is the single most dangerous startup parameter there is, and it is a
// *parameter* rather than a command: `replication=true` (or `on`, or `1`, or
// `yes`) opens a physical replication stream, which is a byte-for-byte copy of
// every database on the server including the role passwords, and
// `replication=database` opens a logical one. A policy that inspected only
// statements would never see either, because no statement is involved -- the
// connection simply becomes a firehose. It is off by default here.
func (s *Startup) Replication() (mode string, on bool) {
	v := strings.ToLower(s.Get("replication"))
	switch v {
	case "", "false", "off", "0", "no":
		return v, false
	}
	return v, true
}

// ParseStartup reads the first message on a connection.
//
// The caller has already read the four length octets and hands them in with the
// rest, because the length is how it knew how much to read.
func ParseStartup(b []byte) (*Startup, error) {
	if len(b) < 8 {
		return nil, ErrShort
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n < 8 {
		return nil, ErrShort
	}
	if n > MaxMessage {
		return nil, ErrTooLong
	}
	if n != len(b) {
		return nil, ErrTruncated
	}
	// The code, the process identifier and the secret are signed 32-bit
	// integers in the protocol itself, so the whole unsigned range is a value
	// the peer may legitimately send and reinterpreting it is the correct read.
	s := &Startup{Code: int32(binary.BigEndian.Uint32(b[4:8]))} //nolint:gosec // a signed protocol field
	body := b[8:]
	switch s.Code {
	case SSLRequest, GSSEncRequest:
		// Both are exactly eight octets. A request with a body is not one of
		// these, whatever its code says, and forwarding it would mean
		// forwarding octets the relay has not read.
		if len(body) != 0 {
			return nil, ErrTruncated
		}
		return s, nil
	case CancelRequest:
		if len(body) != 8 {
			return nil, ErrTruncated
		}
		s.PID = int32(binary.BigEndian.Uint32(body[:4]))     //nolint:gosec // a signed protocol field
		s.Secret = int32(binary.BigEndian.Uint32(body[4:8])) //nolint:gosec // a signed protocol field
		return s, nil
	case Version3:
		params, err := parseParams(body)
		if err != nil {
			return nil, err
		}
		s.Params = params
		return s, nil
	}
	return nil, fmt.Errorf("%w: %d", ErrVersion, s.Code)
}

// parseParams reads the NUL-terminated key/value pairs of a startup packet,
// which end with an empty key.
func parseParams(b []byte) ([]Param, error) {
	var out []Param
	for len(b) > 0 {
		if b[0] == 0 {
			// The terminator. Anything after it is not a parameter, and is
			// not read: a message with trailing rubbish is one the server
			// would read differently, so it is refused rather than trimmed.
			if len(b) != 1 {
				return nil, ErrTruncated
			}
			return out, nil
		}
		key, rest, err := cstring(b)
		if err != nil {
			return nil, err
		}
		val, rest2, err := cstring(rest)
		if err != nil {
			return nil, err
		}
		if len(out) >= MaxStartupParams {
			return nil, ErrTooMany
		}
		out = append(out, Param{Key: key, Value: val})
		b = rest2
	}
	// Ran off the end without the empty key. The server would refuse this,
	// and a relay that accepted it would be forwarding a packet it had
	// completed on the sender's behalf.
	return nil, ErrNotTerminated
}

// cstring reads one NUL-terminated string and returns the rest.
func cstring(b []byte) (string, []byte, error) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], nil
		}
	}
	return "", nil, ErrNotTerminated
}

// Message is one framed message after the startup exchange.
type Message struct {
	// Type is the type octet, which means different things per Direction.
	Type byte
	// Dir is which side sent it.
	Dir Direction
	// Body is the message body, without the type octet or the length.
	Body []byte
}

// Name is how a log line and a configuration spell this message.
//
// The direction decides, because five octets are used both ways. A name is
// given even to a type this relay does not otherwise understand, so that a
// refusal can say what it refused.
func (m Message) Name() string {
	if m.Dir == FromServer {
		switch m.Type {
		case MsgAuthentication:
			return "authentication"
		case MsgBackendKeyData:
			return "backend_key_data"
		case MsgParameterStatus:
			return "parameter_status"
		case MsgReadyForQuery:
			return "ready_for_query"
		case MsgErrorResponse:
			return "error_response"
		case MsgCommandComplete:
			return "command_complete"
		case MsgDataRow:
			return "data_row"
		case MsgCopyInResponse:
			return "copy_in_response"
		case MsgCopyOutResponse:
			return "copy_out_response"
		case MsgCopyBothRespons:
			return "copy_both_response"
		case MsgNegotiateProto:
			return "negotiate_protocol_version"
		}
		return fmt.Sprintf("backend_%q", m.Type)
	}
	switch m.Type {
	case MsgQuery:
		return "query"
	case MsgParse:
		return "parse"
	case MsgBind:
		return "bind"
	case MsgExecute:
		return "execute"
	case MsgDescribe:
		return "describe"
	case MsgClose:
		return "close"
	case MsgSync:
		return "sync"
	case MsgFlush:
		return "flush"
	case MsgTerminate:
		return "terminate"
	case MsgCopyData:
		return "copy_data"
	case MsgCopyDone:
		return "copy_done"
	case MsgCopyFail:
		return "copy_fail"
	case MsgFunctionCall:
		return "function_call"
	case MsgPasswordMessage:
		return "password_message"
	}
	return fmt.Sprintf("frontend_%q", m.Type)
}

// QueryText is the statement of a Query message.
func (m Message) QueryText() (string, error) {
	if m.Type != MsgQuery || m.Dir != FromClient {
		return "", fmt.Errorf("pgwire: not a query")
	}
	s, _, err := cstring(m.Body)
	return s, err
}

// ParseMsg is the contents of a Parse message: a prepared statement's name and
// the statement itself.
type ParseMsg struct {
	Name      string
	Statement string
	// ParamTypes is how many parameter types the client declared. The values
	// themselves are object identifiers and are not interesting; the count is,
	// because it is a number the client chose.
	ParamTypes int
}

// ReadParse reads a Parse message.
//
// This is the message a policy on this protocol most needs to read. Every
// modern driver uses the extended query protocol -- Parse, then Bind, then
// Execute -- and sends no Query message at all, so a relay that inspected only
// Query would be inspecting nothing on a connection from anything written this
// century.
func (m Message) ReadParse() (*ParseMsg, error) {
	if m.Type != MsgParse || m.Dir != FromClient {
		return nil, fmt.Errorf("pgwire: not a parse")
	}
	name, rest, err := cstring(m.Body)
	if err != nil {
		return nil, err
	}
	stmt, rest, err := cstring(rest)
	if err != nil {
		return nil, err
	}
	if len(rest) < 2 {
		return nil, ErrTruncated
	}
	n := int(binary.BigEndian.Uint16(rest[:2]))
	if n > MaxParams {
		return nil, ErrTooMany
	}
	// The declared count must match what is there. A count that claims more
	// object identifiers than the message carries is a message the server
	// reads differently, and this is the shape every length-prefixed
	// injection takes.
	if len(rest[2:]) != n*4 {
		return nil, ErrTruncated
	}
	return &ParseMsg{Name: name, Statement: stmt, ParamTypes: n}, nil
}

// BindMsg is the contents of a Bind message.
type BindMsg struct {
	Portal    string
	Statement string
	// Params is how many parameter values were supplied.
	Params int
}

// ReadBind reads a Bind message far enough to say which prepared statement it
// is binding and how many values it carries. The values themselves are the
// query's data and are deliberately not kept: a relay that held them would be
// holding the contents of somebody's database in memory and, worse, would put
// them in a log line.
func (m Message) ReadBind() (*BindMsg, error) {
	if m.Type != MsgBind || m.Dir != FromClient {
		return nil, fmt.Errorf("pgwire: not a bind")
	}
	portal, rest, err := cstring(m.Body)
	if err != nil {
		return nil, err
	}
	stmt, rest, err := cstring(rest)
	if err != nil {
		return nil, err
	}
	if len(rest) < 2 {
		return nil, ErrTruncated
	}
	formats := int(binary.BigEndian.Uint16(rest[:2]))
	if formats > MaxParams {
		return nil, ErrTooMany
	}
	rest = rest[2:]
	if len(rest) < formats*2+2 {
		return nil, ErrTruncated
	}
	rest = rest[formats*2:]
	n := int(binary.BigEndian.Uint16(rest[:2]))
	if n > MaxParams {
		return nil, ErrTooMany
	}
	return &BindMsg{Portal: portal, Statement: stmt, Params: n}, nil
}

// AuthRequest is the code in a backend Authentication message.
func (m Message) AuthRequest() (int32, error) {
	if m.Type != MsgAuthentication || m.Dir != FromServer {
		return 0, fmt.Errorf("pgwire: not an authentication message")
	}
	if len(m.Body) < 4 {
		return 0, ErrTruncated
	}
	// A signed 32-bit integer in the protocol itself, so the whole unsigned
	// range is a value the server may legitimately send.
	return int32(binary.BigEndian.Uint32(m.Body[:4])), nil //nolint:gosec // a signed protocol field
}

// BackendKey is the process identifier and secret of a BackendKeyData message,
// which are the whole of what a CancelRequest has to present.
func (m Message) BackendKey() (pid, secret int32, err error) {
	if m.Type != MsgBackendKeyData || m.Dir != FromServer {
		return 0, 0, fmt.Errorf("pgwire: not backend key data")
	}
	if len(m.Body) != 8 {
		return 0, 0, ErrTruncated
	}
	// Both are signed 32-bit integers in the protocol itself.
	return int32(binary.BigEndian.Uint32(m.Body[:4])), //nolint:gosec // a signed protocol field
		int32(binary.BigEndian.Uint32(m.Body[4:8])), nil //nolint:gosec // a signed protocol field
}

// ErrorField is one field of an ErrorResponse or NoticeResponse.
type ErrorField struct {
	Code byte
	Val  string
}

// ReadError reads the fields of an ErrorResponse. The relay needs the SQLSTATE
// and the message: the first says what class of failure it was, which is what
// an authentication failure is recognised by, and the second is what an
// operator reads.
func (m Message) ReadError() ([]ErrorField, error) {
	if m.Dir != FromServer || (m.Type != MsgErrorResponse && m.Type != 'N') {
		return nil, fmt.Errorf("pgwire: not an error or notice")
	}
	var out []ErrorField
	b := m.Body
	for len(b) > 0 {
		if b[0] == 0 {
			return out, nil
		}
		code := b[0]
		val, rest, err := cstring(b[1:])
		if err != nil {
			return nil, err
		}
		if len(out) >= MaxStartupParams {
			return nil, ErrTooMany
		}
		out = append(out, ErrorField{Code: code, Val: val})
		b = rest
	}
	return nil, ErrNotTerminated
}

// SQLState is the five-character SQLSTATE of an error, or the empty string.
func SQLState(fields []ErrorField) string {
	for _, f := range fields {
		if f.Code == 'C' {
			return f.Val
		}
	}
	return ""
}

// ErrorText is the primary message of an error, clipped.
func ErrorText(fields []ErrorField) string {
	for _, f := range fields {
		if f.Code == 'M' {
			return Clip(f.Val)
		}
	}
	return ""
}

// Clip bounds a peer-chosen string for a log line or a record.
//
// The cut is on a rune boundary. A string sliced mid-rune is invalid UTF-8, and
// everything downstream mangles it: a JSON log writer replaces the broken octets,
// a terminal draws a replacement character, and a comparison against a policy's
// spelling stops matching. Cutting short is the harmless failure; cutting into a
// character is not.
func Clip(s string) string {
	if len(s) <= MaxString {
		return s
	}
	cut := MaxString
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
