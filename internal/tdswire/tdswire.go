// Package tdswire reads the Tabular Data Stream protocol, which is how
// Microsoft SQL Server is spoken to. The specification is MS-TDS.
//
// This is the third database protocol in a row whose encryption negotiation
// happens in cleartext, and the third to get the same answer.
//
// PostgreSQL asks with eight octets and believes one unsigned octet back. MySQL
// sets a capability bit and believes the server's advertised flags. TDS has a
// PRELOGIN message with an ENCRYPTION option whose four values are the whole
// negotiation: 0 off, 1 on, 2 not supported, 3 required. The client sends its
// preference, the server answers with its own, and the pair decides. Nothing
// signs any of it, so anything on the path rewrites the server's answer to
// ENCRYPT_NOT_SUP and a client that asked for ENCRYPT_OFF -- which is the
// default for a great deal of deployed software -- carries on in the clear. The
// relay answers the PRELOGIN itself rather than forwarding the question, for
// exactly the reason the other two do.
//
// Two things about TDS are its own, and both are worth stating plainly.
//
// **The password in LOGIN7 is not encrypted. It is obfuscated.** Each octet is
// XORed with 0xA5 and has its nibbles swapped. That is the whole transformation,
// it is fixed, it has no key, and it has been documented since the protocol was
// published -- so a LOGIN7 that crosses an unencrypted connection has disclosed
// the password to anybody who was listening, and calling the scheme anything
// other than "an encoding" would be a lie. This package can decode it and
// deliberately does not: see Deobfuscate's comment.
//
// **The interesting operations arrive as RPC rather than as SQL.** A SQLBATCH
// message carries T-SQL as UCS-2 text, which the statement classifier can read.
// But an RPC message names a stored procedure by identifier or by name, and two
// of those names matter more than any statement: `sp_executesql`, which is
// dynamic SQL wearing a procedure call, and `xp_cmdshell`, which runs a command
// on the host as the service account. A relay that classified only SQLBATCH
// would miss both, and every client library that uses parameters sends RPC.
package tdswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The packet types, from the MS-TDS header.
const (
	// TypeSQLBatch carries T-SQL text as UCS-2.
	TypeSQLBatch byte = 0x01
	// TypeLogin is the pre-TDS7 login, which this relay does not speak.
	TypeLogin byte = 0x02
	// TypeRPC is a remote procedure call.
	TypeRPC byte = 0x03
	// TypeTabularResult is the server's answer.
	TypeTabularResult byte = 0x04
	// TypeAttention cancels the request in flight.
	TypeAttention byte = 0x06
	// TypeBulkLoad is a bulk insert's data stream.
	TypeBulkLoad byte = 0x07
	// TypeFedAuthToken carries a federated authentication token.
	TypeFedAuthToken byte = 0x08
	// TypeTransactionManager begins, commits or rolls back.
	TypeTransactionManager byte = 0x0e
	// TypeLogin7 is the TDS 7.0 and later login.
	TypeLogin7 byte = 0x10
	// TypeSSPI carries a Windows authentication blob.
	TypeSSPI byte = 0x11
	// TypePreLogin is the negotiation, including the encryption option.
	TypePreLogin byte = 0x12
)

// TypeName is how a configuration and a log line spell a packet type.
func TypeName(t byte) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type_%#02x", t)
}

var typeNames = map[byte]string{
	TypeSQLBatch: "sql_batch", TypeLogin: "login", TypeRPC: "rpc",
	TypeTabularResult: "tabular_result", TypeAttention: "attention",
	TypeBulkLoad: "bulk_load", TypeFedAuthToken: "fedauth_token",
	TypeTransactionManager: "transaction_manager", TypeLogin7: "login7",
	TypeSSPI: "sspi", TypePreLogin: "prelogin",
}

// TypeOf reads a packet type the way a configuration writes it.
func TypeOf(name string) (byte, bool) {
	want := strings.ToLower(strings.TrimSpace(name))
	for t, n := range typeNames {
		if n == want {
			return t, true
		}
	}
	return 0, false
}

// TypeNames is every type a configuration may name.
func TypeNames() []string {
	return []string{"sql_batch", "rpc", "bulk_load", "transaction_manager",
		"attention", "sspi", "fedauth_token", "prelogin", "login7", "login"}
}

// DefaultTypes is the allow list a relay uses when the configuration names none:
// what a client library sends, and nothing else.
//
// `login` (the pre-TDS7 shape) is absent because it is a different message
// entirely and this relay does not read it -- forwarding one would mean
// forwarding octets it had not understood. `bulk_load` is absent because a bulk
// insert is a job rather than something an application connection does by
// accident, and because its data stream is not SQL and carries no policy.
func DefaultTypes() []byte {
	return []byte{TypeSQLBatch, TypeRPC, TypeTransactionManager, TypeAttention,
		TypeSSPI, TypeFedAuthToken, TypePreLogin, TypeLogin7}
}

// The status flags in the packet header.
const (
	// StatusNormal is a packet that is not the last of its message.
	StatusNormal byte = 0x00
	// StatusEOM marks the last packet of a message.
	StatusEOM byte = 0x01
	// StatusIgnore asks the server to discard the message.
	StatusIgnore byte = 0x02
	// StatusResetConnection asks for the session to be reset before the
	// message runs, which is what a connection pool sends when it hands a
	// connection to a different caller.
	StatusResetConnection         byte = 0x08
	StatusResetConnectionSkipTran byte = 0x10
)

// Bounds. Every one is a number a peer chooses.
const (
	// HeaderLen is the fixed packet header: type, status, length, SPID,
	// PacketID, Window.
	HeaderLen = 8
	// MinPacketLen is the smallest a length field may claim. The length
	// *includes* the header, so anything below it is a packet shorter than its
	// own header -- and subtracting eight from it underflows.
	MinPacketLen = HeaderLen
	// MaxPacketLen is the largest the two-octet length can express.
	MaxPacketLen = 0xffff
	// MaxMessage is the ceiling on a message reassembled across packets. The
	// protocol has none: a sender may chain 64 KiB packets for ever.
	MaxMessage = 64 << 20
	// DefaultMaxMessage is what a listener uses when the configuration names
	// no bound.
	DefaultMaxMessage = 4 << 20
	// MaxString clips a peer-chosen string for a log line or a record.
	MaxString = 256
	// MaxPreLoginOptions bounds the option table in a PRELOGIN.
	MaxPreLoginOptions = 32
	// MaxRPCParams bounds the parameters of one RPC.
	MaxRPCParams = 1024
)

// Errors this package returns.
var (
	ErrShort     = errors.New("tdswire: packet length is shorter than its own header")
	ErrTooLong   = errors.New("tdswire: message is longer than the bound")
	ErrTruncated = errors.New("tdswire: message ends inside a field")
	ErrTooMany   = errors.New("tdswire: more fields than the bound allows")
	// ErrVersion is a login shape this relay does not speak.
	ErrVersion = errors.New("tdswire: unsupported login version")
	// ErrOdd is a UCS-2 field with an odd number of octets, which cannot be
	// one: a reader that dropped the stray octet would read a different string
	// from the server's.
	ErrOdd = errors.New("tdswire: UCS-2 field has an odd length")
)

// The PRELOGIN option tokens.
const (
	PreLoginVersion    byte = 0x00
	PreLoginEncryption byte = 0x01
	PreLoginInstOpt    byte = 0x02
	PreLoginThreadID   byte = 0x03
	PreLoginMARS       byte = 0x04
	PreLoginTraceID    byte = 0x05
	PreLoginFedAuth    byte = 0x06
	PreLoginNonce      byte = 0x07
	PreLoginTerminator byte = 0xff
)

// The ENCRYPTION option's four values, which are the whole negotiation.
const (
	// EncryptOff means "I would rather not", and it is what a great deal of
	// deployed software sends. A server that answers EncryptOff too leaves the
	// login -- and the obfuscated password in it -- in the clear.
	EncryptOff byte = 0x00
	// EncryptOn means "let us".
	EncryptOn byte = 0x01
	// EncryptNotSup means "I cannot". This is the value an attacker on the path
	// rewrites the server's answer to, because a client that asked for
	// EncryptOff and hears EncryptNotSup proceeds unencrypted without
	// complaint.
	EncryptNotSup byte = 0x02
	// EncryptReq means "I will not continue without it". A client that sends
	// this is a client the downgrade cannot touch, which is what this relay
	// makes every client look like.
	EncryptReq byte = 0x03
	// EncryptClientCertOn and EncryptClientCertReq are the certificate-bound
	// variants added later.
	EncryptClientCertOn  byte = 0x80
	EncryptClientCertReq byte = 0x83
)

// EncryptName is how a log line spells an encryption value.
func EncryptName(v byte) string {
	switch v {
	case EncryptOff:
		return "off"
	case EncryptOn:
		return "on"
	case EncryptNotSup:
		return "not_supported"
	case EncryptReq:
		return "required"
	case EncryptClientCertOn:
		return "client_cert_on"
	case EncryptClientCertReq:
		return "client_cert_required"
	}
	return fmt.Sprintf("unknown_%#02x", v)
}

// Encrypted says whether a negotiated value means the connection will be
// protected.
//
// Only `on` and `required` do, and the certificate-bound variants of each. `off`
// and `not_supported` both mean plaintext -- which is the point worth being
// careful about, because "off" reads like a preference and "not supported" reads
// like a capability, and the wire consequence of the two is identical.
func Encrypted(v byte) bool {
	switch v {
	case EncryptOn, EncryptReq, EncryptClientCertOn, EncryptClientCertReq:
		return true
	}
	return false
}

// PreLogin is a parsed PRELOGIN message.
type PreLogin struct {
	// Encryption is the ENCRYPTION option's value, or EncryptNotSup when the
	// option was absent -- which is how an old client says nothing at all, and
	// which means plaintext either way.
	Encryption byte
	// HasEncryption says the option was actually present, so a relay can tell
	// "asked for off" from "did not ask".
	HasEncryption bool
	// Instance is the INSTOPT string, which names a named instance.
	Instance string
	// Version is the VERSION option's six octets, when present.
	Version []byte
	// FedAuth says the client offered federated authentication.
	FedAuth bool
	// MARS says the client offered multiple active result sets.
	MARS bool
	// Options is every option token seen, in order, so a relay can rebuild the
	// message it read rather than one it invented.
	Options []PreLoginOption
}

// PreLoginOption is one entry of the option table.
type PreLoginOption struct {
	Token byte
	Value []byte
}

// ParsePreLogin reads a PRELOGIN message body.
//
// The message is an option table -- token, offset, length, each big-endian --
// followed by the values, terminated by 0xff. Both the offsets and the lengths
// are chosen by the peer, so each is checked against the body rather than
// trusted: an offset past the end, or a length that runs past it, is a message
// the relay and the server would read differently.
func ParsePreLogin(b []byte) (*PreLogin, error) {
	p := &PreLogin{Encryption: EncryptNotSup}
	i := 0
	for {
		if i >= len(b) {
			// Ran off the end without a terminator. A server would refuse
			// this, and a relay that accepted it would be completing a message
			// on the sender's behalf.
			return nil, ErrTruncated
		}
		token := b[i]
		if token == PreLoginTerminator {
			break
		}
		if i+5 > len(b) {
			return nil, ErrTruncated
		}
		off := int(binary.BigEndian.Uint16(b[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(b[i+3 : i+5]))
		if off < 0 || length < 0 || off > len(b) || off+length > len(b) {
			return nil, ErrTruncated
		}
		if len(p.Options) >= MaxPreLoginOptions {
			return nil, ErrTooMany
		}
		// A token that appears twice is refused. The table is a set of distinct
		// options by design, and a repeated one means the relay and the server
		// could read different values: whichever wins depends on whether a
		// reader keeps the first or the last. On the ENCRYPTION option that is
		// the entire negotiation, so it is the one field where disagreeing
		// silently would be worst -- and the general rule is cheaper than the
		// special case.
		for _, seen := range p.Options {
			if seen.Token == token {
				return nil, fmt.Errorf("%w: option %#02x appears twice", ErrTruncated, token)
			}
		}
		val := b[off : off+length]
		p.Options = append(p.Options, PreLoginOption{Token: token, Value: val})
		switch token {
		case PreLoginEncryption:
			if length < 1 {
				return nil, ErrTruncated
			}
			p.Encryption, p.HasEncryption = val[0], true
		case PreLoginInstOpt:
			p.Instance = Clip(strings.TrimRight(string(val), "\x00"))
		case PreLoginVersion:
			p.Version = val
		case PreLoginFedAuth:
			p.FedAuth = length > 0 && val[0] != 0
		case PreLoginMARS:
			p.MARS = length > 0 && val[0] != 0
		}
		i += 5
	}
	return p, nil
}

// BuildPreLogin encodes an option table.
//
// The relay needs this to answer a PRELOGIN itself and to rewrite the encryption
// option in one it forwards. Rebuilding rather than editing in place is
// deliberate here, unlike the MySQL greeting: a TDS option table is
// offset-based, so changing one value's length would move every value after it,
// and an in-place edit would have to be a rewrite anyway.
func BuildPreLogin(opts []PreLoginOption) []byte {
	// The table is five octets per option plus the terminator.
	head := len(opts)*5 + 1
	out := make([]byte, 0, head+64)
	off := head
	for _, o := range opts {
		out = append(out, o.Token)
		out = binary.BigEndian.AppendUint16(out, uint16(off))          //nolint:gosec // bounded by the message
		out = binary.BigEndian.AppendUint16(out, uint16(len(o.Value))) //nolint:gosec // bounded
		off += len(o.Value)
	}
	out = append(out, PreLoginTerminator)
	for _, o := range opts {
		out = append(out, o.Value...)
	}
	return out
}

// WithEncryption returns the option table with the ENCRYPTION option set to v,
// adding it when it was absent.
//
// This is how the relay makes every client look like one that sent
// ENCRYPT_REQ: the downgrade works by rewriting an answer, and a client whose
// *request* says "required" cannot be talked out of it.
func (p *PreLogin) WithEncryption(v byte) []PreLoginOption {
	out := make([]PreLoginOption, 0, len(p.Options)+1)
	found := false
	for _, o := range p.Options {
		if o.Token == PreLoginEncryption {
			out = append(out, PreLoginOption{Token: o.Token, Value: []byte{v}})
			found = true
			continue
		}
		out = append(out, o)
	}
	if !found {
		// The specification says the option table is in ascending token order,
		// and some servers enforce it, so a *new* option is inserted in its
		// place rather than appended.
		//
		// The order of the options the client sent is otherwise preserved,
		// including when it was not ascending. Sorting the whole table would
		// mean the relay normalising somebody else's message beyond what the
		// policy asked for -- and a server that refuses an unsorted table would
		// have refused the client's own.
		out = append(out, PreLoginOption{Token: PreLoginEncryption, Value: []byte{v}})
		for i := len(out) - 1; i > 0 && out[i-1].Token > out[i].Token; i-- {
			out[i-1], out[i] = out[i], out[i-1]
		}
	}
	return out
}

// Login7 is the parsed identity of a TDS 7 login.
type Login7 struct {
	TDSVersion uint32
	// Hostname, User, Database, AppName, ServerName and Library are the
	// strings a client sends about itself. All are UCS-2 on the wire and all
	// are peer-chosen, so all are clipped.
	Hostname   string
	User       string
	Database   string
	AppName    string
	ServerName string
	Library    string
	Language   string
	// HasPassword says a password field was present and non-empty. Its
	// *contents* are deliberately not kept: see Deobfuscate.
	HasPassword bool
	// Integrated says the login uses Windows authentication rather than a
	// password, which is the SSPI blob rather than the password field.
	Integrated bool
}

// ParseLogin7 reads a LOGIN7 message body far enough to know who is connecting.
//
// The message is a fixed header of offsets and lengths followed by the variable
// data, and each offset is a number the client chose -- so each is checked
// against the body. The specification counts the lengths of the string fields in
// *characters* rather than octets, which is the mistake to avoid: a reader that
// treated them as octets would read half of every string and a different name
// from the one the server reads.
func ParseLogin7(b []byte) (*Login7, error) {
	// Length (4), TDSVersion (4), PacketSize (4), ClientProgVer (4), ClientPID
	// (4), ConnectionID (4), OptionFlags1-3 (3), TypeFlags (1), ClientTimeZone
	// (4), ClientLCID (4) = 36, then the offset/length table.
	const fixed = 36
	if len(b) < fixed+4 {
		return nil, ErrTruncated
	}
	l := &Login7{TDSVersion: binary.LittleEndian.Uint32(b[4:8])}
	// OptionFlags2 bit 7 (0x80) is fIntSecurity: integrated security, where the
	// credential is an SSPI blob rather than the password field.
	l.Integrated = b[25]&0x80 != 0

	// The offset/length pairs, in the order the specification lists them.
	type field struct {
		name string
		dst  *string
	}
	fields := []field{
		{"hostname", &l.Hostname},
		{"username", &l.User},
		{"password", nil}, // read for presence only
		{"appname", &l.AppName},
		{"servername", &l.ServerName},
		{"extension", nil},
		{"library", &l.Library},
		{"language", &l.Language},
		{"database", &l.Database},
	}
	pos := fixed
	for _, f := range fields {
		if pos+4 > len(b) {
			return nil, ErrTruncated
		}
		off := int(binary.LittleEndian.Uint16(b[pos : pos+2]))
		// The length is in characters, and each character is two octets.
		chars := int(binary.LittleEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		octets := chars * 2
		if off < 0 || octets < 0 || off > len(b) || off+octets > len(b) {
			return nil, ErrTruncated
		}
		if f.dst == nil {
			if f.name == "password" {
				l.HasPassword = octets > 0
			}
			continue
		}
		s, err := UCS2(b[off : off+octets])
		if err != nil {
			return nil, err
		}
		*f.dst = Clip(s)
	}
	if l.TDSVersion != 0 && l.TDSVersion < 0x70000000 {
		// Below TDS 7.0 the login is the TypeLogin message rather than this
		// one, and a version field claiming otherwise is a message the relay
		// has not understood.
		return nil, fmt.Errorf("%w: TDS version %#x", ErrVersion, l.TDSVersion)
	}
	return l, nil
}

// Deobfuscate reverses the LOGIN7 password encoding: swap the nibbles, then XOR
// with 0xA5.
//
// It exists so that this package can state what the encoding is, and it is
// deliberately not called by the relay. Reversing it would mean the relay held a
// plaintext password in memory and one careless log line away from disk, in
// exchange for nothing: the relay has no use for the password's value, only for
// whether one crossed an unencrypted connection. That question is answered by
// Login7.HasPassword.
//
// Its real purpose is to be testable, so that the claim "this is an encoding and
// not encryption" is demonstrated rather than asserted in a comment.
func Deobfuscate(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		c = c>>4 | c<<4
		out[i] = c ^ 0xa5
	}
	return out
}

// Obfuscate applies the encoding, for the test that round-trips it.
func Obfuscate(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		c ^= 0xa5
		out[i] = c>>4 | c<<4
	}
	return out
}

// RPC is a parsed RPC message: what procedure a client asked for.
type RPC struct {
	// Name is the procedure's name, when it was named by name.
	Name string
	// ProcID is the well-known procedure identifier, when it was named by
	// number. The two forms are not interchangeable in a policy: a client
	// calling Sp_ExecuteSql by number is calling the same thing as one naming
	// it, and a relay that only matched the name would miss it.
	ProcID uint16
	// ByID says the procedure was named by number.
	ByID bool
	// Statement is the T-SQL this call carries, when the procedure is one whose
	// signature puts a statement in a parameter -- sp_executesql and the
	// prepare family. It is empty for every other procedure, and HasStatement
	// says which case it is.
	//
	// This is the only parameter value this package ever decodes, and the
	// reason is that it is not data: it is the statement, and without it a
	// T-SQL policy would be inspecting the SET statements a driver emits on
	// connect and nothing an application ever runs. See rpc.go.
	Statement    string
	HasStatement bool
}

// The well-known procedure identifiers, from MS-TDS. Only the ones a policy has
// an opinion about are named.
const (
	SpCursor          uint16 = 1
	SpCursorOpen      uint16 = 2
	SpCursorPrepare   uint16 = 3
	SpCursorExecute   uint16 = 4
	SpCursorPrepExec  uint16 = 5
	SpCursorUnprepare uint16 = 6
	SpCursorFetch     uint16 = 7
	SpCursorOption    uint16 = 8
	SpCursorClose     uint16 = 9
	// SpExecuteSql is dynamic SQL wearing a procedure call. It is the single
	// most important thing in this file: every client library that uses
	// parameters sends it, so a relay that classified only SQLBATCH would be
	// inspecting almost nothing.
	SpExecuteSql  uint16 = 10
	SpPrepare     uint16 = 11
	SpExecute     uint16 = 12
	SpPrepExec    uint16 = 13
	SpPrepExecRpc uint16 = 14
	SpUnprepare   uint16 = 15
)

// ProcName is how a log line and a configuration spell a procedure identifier.
func ProcName(id uint16) string {
	if n, ok := procNames[id]; ok {
		return n
	}
	return fmt.Sprintf("proc_%d", id)
}

var procNames = map[uint16]string{
	SpCursor: "sp_cursor", SpCursorOpen: "sp_cursoropen",
	SpCursorPrepare: "sp_cursorprepare", SpCursorExecute: "sp_cursorexecute",
	SpCursorPrepExec: "sp_cursorprepexec", SpCursorUnprepare: "sp_cursorunprepare",
	SpCursorFetch: "sp_cursorfetch", SpCursorOption: "sp_cursoroption",
	SpCursorClose: "sp_cursorclose", SpExecuteSql: "sp_executesql",
	SpPrepare: "sp_prepare", SpExecute: "sp_execute", SpPrepExec: "sp_prepexec",
	SpPrepExecRpc: "sp_prepexecrpc", SpUnprepare: "sp_unprepare",
}

// Procedure is the procedure a client asked for, by whichever form it used,
// lower-cased so a policy compares one spelling.
//
// The two naming forms collapse here on purpose. `sp_executesql` called by name
// and procedure identifier 10 are the same call, and a policy that matched only
// the string would be bypassed by a client library that uses the number -- which
// most of them do.
func (r *RPC) Procedure() string {
	if r.ByID {
		return ProcName(r.ProcID)
	}
	// Clipped *after* lowering, not before. Lower-casing can make a UTF-8
	// string longer -- U+0130 becomes two runes -- so a name clipped at parse
	// time can come back past the bound, and this is the value that reaches a
	// log line.
	return Clip(strings.ToLower(r.Name))
}

// ParseRPC reads an RPC message body far enough to name the procedure.
//
// The body begins with an optional stream header block (ALL_HEADERS), then a
// name length in characters or the 0xffff marker introducing a procedure
// identifier.
func ParseRPC(b []byte) (*RPC, error) {
	rest := skipAllHeaders(b)
	if len(rest) < 2 {
		return nil, ErrTruncated
	}
	n := binary.LittleEndian.Uint16(rest[:2])
	r := &RPC{}
	if n == 0xffff {
		// A procedure identifier follows.
		if len(rest) < 4 {
			return nil, ErrTruncated
		}
		r.ProcID = binary.LittleEndian.Uint16(rest[2:4])
		r.ByID = true
		rest = rest[4:]
	} else {
		if n == 0 {
			// An RPC that names no procedure is not one. A relay that accepted
			// it would hand the policy an empty name to match against, and a
			// policy matching on the procedure would have nothing to decide
			// about while the server happily ran whatever it made of the rest.
			return nil, fmt.Errorf("%w: an rpc with no procedure name", ErrTruncated)
		}
		octets := int(n) * 2
		if 2+octets > len(rest) {
			return nil, ErrTruncated
		}
		name, err := UCS2(rest[2 : 2+octets])
		if err != nil {
			return nil, err
		}
		if name == "" {
			return nil, fmt.Errorf("%w: an rpc with an empty procedure name", ErrTruncated)
		}
		// A NUL inside the name is refused for the reason the TFTP kind refuses
		// one inside a filename: it is a character that truncates a string
		// somewhere downstream, so the relay and the server would be deciding
		// about different names, and a decision about a name the server will not
		// see is not a decision.
		if strings.ContainsRune(name, 0) {
			return nil, fmt.Errorf("%w: a NUL inside a procedure name", ErrTruncated)
		}
		r.Name = Clip(name)
		rest = rest[2+octets:]
	}
	// Option flags (2), then the parameters. The parameter *values* are the
	// query's data and are deliberately not read: a relay that held them would
	// be holding the contents of somebody's database, and would put them in a
	// log line.
	//
	// The one exception is the parameter that *is* the statement, on the six
	// procedures whose documented signature has one. Reading it is the
	// difference between a policy that inspects what applications run and one
	// that inspects almost nothing, because a client library that uses
	// parameters sends sp_executesql rather than a batch.
	at, ok := StatementParam(r.Procedure())
	if !ok {
		return r, nil
	}
	if len(rest) < 2 {
		// A dynamic-SQL call with no parameter list at all. It cannot be the
		// call its signature describes, and refusing it is cheaper than
		// deciding about a statement that is not there.
		return nil, fmt.Errorf("%w: %s with no parameters", ErrTruncated, r.Procedure())
	}
	st, err := readStatementParam(rest[2:], at)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Procedure(), err)
	}
	r.Statement, r.HasStatement = st, true
	return r, nil
}

// skipAllHeaders steps over the ALL_HEADERS block that precedes a SQLBATCH or
// RPC body, when there is one.
//
// The block is a four-octet total length followed by headers. It is optional and
// there is no flag saying whether it is present, so this reads it only when the
// length is plausible -- a value that would run past the body, or one too small
// to be a header block, means there is no block and the body starts here. That
// is the specification's own rule and it is the sort of ambiguity that makes a
// reader guess; guessing wrong in the safe direction means reading a name from
// slightly the wrong place and failing to match a policy, which is a refusal
// rather than a pass.
func skipAllHeaders(b []byte) []byte {
	if len(b) < 4 {
		return b
	}
	// Compared in 64 bits: the declared total is a peer's four octets and the
	// body's length is an int, and narrowing either to meet the other is how a
	// bounds check gets skipped on the value that was chosen to skip it.
	total := binary.LittleEndian.Uint32(b[:4])
	if total < 4 || uint64(total) > uint64(len(b)) {
		return b
	}
	return b[total:]
}

// SQLText is the T-SQL of a SQLBATCH message.
func SQLText(b []byte) (string, error) {
	return UCS2(skipAllHeaders(b))
}

// UCS2 decodes a little-endian UTF-16 string.
//
// An odd length is refused rather than truncated. A reader that dropped the
// stray octet would read a different string from the server's, and on this
// protocol the string in question is a procedure name or a statement.
func UCS2(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", ErrOdd
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	s := string(utf16.Decode(u))
	if !utf8.ValidString(s) {
		// utf16.Decode always produces valid UTF-8, replacing what it cannot
		// decode, so this is belt and braces rather than a real path -- and it
		// is cheap insurance against a future change here.
		return "", ErrTruncated
	}
	return s, nil
}

// ToUCS2 encodes a string as little-endian UTF-16, for what the relay writes.
func ToUCS2(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u)*2)
	for _, c := range u {
		out = binary.LittleEndian.AppendUint16(out, c)
	}
	return out
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
