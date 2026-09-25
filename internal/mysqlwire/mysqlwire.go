// Package mysqlwire reads the MySQL client/server protocol, as MySQL and
// MariaDB speak it.
//
// PostgreSQL's dangerous operations are statements. MySQL's are **commands**,
// and that one difference is the whole reason this package exists rather than a
// second copy of the PostgreSQL one.
//
// After the handshake, every message from the client begins with a one-octet
// command code, and several of those codes are things a SQL policy would never
// see because no SQL is involved:
//
//   - COM_SHUTDOWN (8) shuts the server down. One octet.
//   - COM_BINLOG_DUMP (18), COM_BINLOG_DUMP_GTID (30) and COM_REGISTER_SLAVE
//     (21) open a replication stream, which is every change to every database.
//   - COM_TABLE_DUMP (19) dumps a whole table.
//   - COM_PROCESS_KILL (12) kills another connection.
//   - COM_DEBUG (13) writes the server's internal state to its error log.
//   - COM_CHANGE_USER (17) re-authenticates mid-connection as somebody else,
//     which is an identity change a relay must notice or its entire user policy
//     applies only to the first message.
//   - COM_SET_OPTION (27) can switch CLIENT_MULTI_STATEMENTS on *after* the
//     handshake, so refusing that capability in the handshake alone is not
//     enough -- this is the detail that makes a capability policy real rather
//     than decorative.
//
// Two more things decide the shape of this package.
//
// **The encryption negotiation is a capability flag.** The client sets
// CLIENT_SSL in its handshake response, sends only the first 32 octets, does the
// TLS handshake, and then sends the whole response again. Nothing signs the
// server's greeting, so anything on the path can clear CLIENT_SSL from the
// server's advertised capabilities and the client will not ask. This is
// PostgreSQL's SSLRequest problem with a different encoding, and it gets the
// same answer: the relay decides, not the octets.
//
// **The server can ask the client for a file.** With CLIENT_LOCAL_FILES agreed,
// a server answers `LOAD DATA LOCAL INFILE` by sending a packet that names a
// path, and the client opens it and sends the contents. A hostile or
// compromised server asks for /etc/passwd, a private key, or the application's
// own configuration, and a client with local_infile on -- which several drivers
// default to -- obeys. The relay is the only place this can be refused on the
// client's behalf, because the client's own setting is exactly what the attack
// relies on being wrong.
package mysqlwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Bounds. Every one is a number a peer chooses.
const (
	// MaxPayload is the largest single packet payload the protocol can
	// express: the length is three octets. A payload of exactly this length
	// means "more follows", which is how a larger message is sent.
	MaxPayload = 1<<24 - 1
	// MaxMessage is the ceiling on a reassembled message across continuation
	// packets: the protocol itself has none at all, since a sender may chain
	// 16 MiB packets for ever, so a relay that trusted it would let one
	// message be a memory exhaustion.
	//
	// It is deliberately larger than MaxPayload, because a bound below one
	// packet would refuse every message that legitimately needs a
	// continuation -- a bulk insert or a long statement. The *policy* default
	// (max_message_bytes on the listener) is much lower; this is the number no
	// configuration may exceed.
	MaxMessage = 64 << 20
	// DefaultMaxMessage is what a listener uses when the configuration names
	// no bound. A megabyte is generous for a statement and small enough that a
	// thousand connections cannot be a denial of service.
	DefaultMaxMessage = 1 << 20
	// MaxString clips a peer-chosen string kept for a log line or a record.
	MaxString = 256
	// MaxAttrs bounds the connection attributes a client may send.
	MaxAttrs = 64
)

// Errors this package returns.
var (
	// ErrTruncated is a packet or field that ended before it should have.
	ErrTruncated = errors.New("mysqlwire: message ends inside a field")
	// ErrTooLong is a reassembled message past MaxMessage.
	ErrTooLong = errors.New("mysqlwire: message is longer than the bound")
	// ErrNotTerminated is a NUL-terminated string with no terminator. One that
	// ran to the end of the packet is a field the relay and the server would
	// read differently.
	ErrNotTerminated = errors.New("mysqlwire: string field is not terminated")
	// ErrProtocol is a greeting this relay cannot read.
	ErrProtocol = errors.New("mysqlwire: unsupported protocol version")
	// ErrSequence is a packet whose sequence number is not the next one. The
	// protocol numbers packets so that a reassembled message is the one the
	// sender framed, and a relay that ignored it could be fed a message
	// assembled from two.
	ErrSequence = errors.New("mysqlwire: packet out of sequence")
	// ErrTooMany is a count past its bound.
	ErrTooMany = errors.New("mysqlwire: more fields than the bound allows")
)

// The capability flags, from the protocol documentation. Only the ones a policy
// or a reader needs are named; the rest travel untouched.
const (
	CapLongPassword  uint32 = 1 << 0
	CapFoundRows     uint32 = 1 << 1
	CapLongFlag      uint32 = 1 << 2
	CapConnectWithDB uint32 = 1 << 3
	CapNoSchema      uint32 = 1 << 4
	CapCompress      uint32 = 1 << 5
	CapODBC          uint32 = 1 << 6
	// CapLocalFiles is the one that lets a server ask the client for a file.
	CapLocalFiles  uint32 = 1 << 7
	CapIgnoreSpace uint32 = 1 << 8
	CapProtocol41  uint32 = 1 << 9
	CapInteractive uint32 = 1 << 10
	// CapSSL is the encryption negotiation, such as it is.
	CapSSL              uint32 = 1 << 11
	CapIgnoreSigpipe    uint32 = 1 << 12
	CapTransactions     uint32 = 1 << 13
	CapReserved         uint32 = 1 << 14
	CapSecureConnection uint32 = 1 << 15
	// CapMultiStatements lets one COM_QUERY carry several statements separated
	// by semicolons, which is how every injection ending in `; DROP TABLE` is
	// delivered. It is off in the protocol's own default and on in several
	// client libraries.
	CapMultiStatements           uint32 = 1 << 16
	CapMultiResults              uint32 = 1 << 17
	CapPSMultiResults            uint32 = 1 << 18
	CapPluginAuth                uint32 = 1 << 19
	CapConnectAttrs              uint32 = 1 << 20
	CapPluginAuthLenEnc          uint32 = 1 << 21
	CapExpiredPasswords          uint32 = 1 << 22
	CapSessionTrack              uint32 = 1 << 23
	CapDeprecateEOF              uint32 = 1 << 24
	CapOptionalResultSetMetadata uint32 = 1 << 25
	CapZstdCompression           uint32 = 1 << 26
	CapSSLVerifyCert             uint32 = 1 << 30
	CapRemember                  uint32 = 1 << 31
)

// CapName is how a configuration and a log line spell a capability.
func CapName(bit uint32) string {
	switch bit {
	case CapLocalFiles:
		return "local_files"
	case CapSSL:
		return "ssl"
	case CapMultiStatements:
		return "multi_statements"
	case CapMultiResults:
		return "multi_results"
	case CapCompress, CapZstdCompression:
		return "compress"
	case CapConnectAttrs:
		return "connect_attrs"
	case CapPluginAuth:
		return "plugin_auth"
	case CapConnectWithDB:
		return "connect_with_db"
	case CapNoSchema:
		return "no_schema"
	case CapInteractive:
		return "interactive"
	}
	return fmt.Sprintf("bit_%d", trailingZeros(bit))
}

func trailingZeros(v uint32) int {
	for i := 0; i < 32; i++ {
		if v&(1<<uint(i)) != 0 {
			return i
		}
	}
	return -1
}

// CapOf reads a capability the way a configuration writes it.
func CapOf(name string) (uint32, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "local_files":
		return CapLocalFiles, true
	case "ssl":
		return CapSSL, true
	case "multi_statements":
		return CapMultiStatements, true
	case "multi_results":
		return CapMultiResults, true
	case "compress":
		return CapCompress, true
	case "connect_attrs":
		return CapConnectAttrs, true
	case "plugin_auth":
		return CapPluginAuth, true
	case "connect_with_db":
		return CapConnectWithDB, true
	case "no_schema":
		return CapNoSchema, true
	case "interactive":
		return CapInteractive, true
	}
	return 0, false
}

// CapNames is every capability a configuration may name.
func CapNames() []string {
	return []string{"ssl", "local_files", "multi_statements", "multi_results",
		"compress", "connect_attrs", "plugin_auth", "connect_with_db",
		"no_schema", "interactive"}
}

// DangerousCaps are the capabilities whose presence changes what the rest of the
// connection can do, and which a relay therefore has an opinion about.
func DangerousCaps() []uint32 {
	return []uint32{CapLocalFiles, CapMultiStatements, CapCompress, CapZstdCompression}
}

// The command codes.
const (
	ComSleep            byte = 0x00
	ComQuit             byte = 0x01
	ComInitDB           byte = 0x02
	ComQuery            byte = 0x03
	ComFieldList        byte = 0x04
	ComCreateDB         byte = 0x05
	ComDropDB           byte = 0x06
	ComRefresh          byte = 0x07
	ComShutdown         byte = 0x08
	ComStatistics       byte = 0x09
	ComProcessInfo      byte = 0x0a
	ComConnect          byte = 0x0b
	ComProcessKill      byte = 0x0c
	ComDebug            byte = 0x0d
	ComPing             byte = 0x0e
	ComTime             byte = 0x0f
	ComDelayedInsert    byte = 0x10
	ComChangeUser       byte = 0x11
	ComBinlogDump       byte = 0x12
	ComTableDump        byte = 0x13
	ComConnectOut       byte = 0x14
	ComRegisterSlave    byte = 0x15
	ComStmtPrepare      byte = 0x16
	ComStmtExecute      byte = 0x17
	ComStmtSendLongData byte = 0x18
	ComStmtClose        byte = 0x19
	ComStmtReset        byte = 0x1a
	ComSetOption        byte = 0x1b
	ComStmtFetch        byte = 0x1c
	ComDaemon           byte = 0x1d
	ComBinlogDumpGTID   byte = 0x1e
	ComResetConnection  byte = 0x1f
	ComClone            byte = 0x20
)

// CommandName is how a configuration and a log line spell a command. The names
// are the protocol's own, lower-cased and without the COM_ prefix, so an
// operator writing a policy writes what they can look up.
func CommandName(c byte) string {
	if n, ok := commandNames[c]; ok {
		return n
	}
	return fmt.Sprintf("command_%#02x", c)
}

var commandNames = map[byte]string{
	ComSleep: "sleep", ComQuit: "quit", ComInitDB: "init_db", ComQuery: "query",
	ComFieldList: "field_list", ComCreateDB: "create_db", ComDropDB: "drop_db",
	ComRefresh: "refresh", ComShutdown: "shutdown", ComStatistics: "statistics",
	ComProcessInfo: "process_info", ComConnect: "connect",
	ComProcessKill: "process_kill", ComDebug: "debug", ComPing: "ping",
	ComTime: "time", ComDelayedInsert: "delayed_insert",
	ComChangeUser: "change_user", ComBinlogDump: "binlog_dump",
	ComTableDump: "table_dump", ComConnectOut: "connect_out",
	ComRegisterSlave: "register_slave", ComStmtPrepare: "stmt_prepare",
	ComStmtExecute: "stmt_execute", ComStmtSendLongData: "stmt_send_long_data",
	ComStmtClose: "stmt_close", ComStmtReset: "stmt_reset",
	ComSetOption: "set_option", ComStmtFetch: "stmt_fetch",
	ComDaemon: "daemon", ComBinlogDumpGTID: "binlog_dump_gtid",
	ComResetConnection: "reset_connection", ComClone: "clone",
}

// CommandOf reads a command the way a configuration writes it.
func CommandOf(name string) (byte, bool) {
	want := strings.ToLower(strings.TrimSpace(name))
	for c, n := range commandNames {
		if n == want {
			return c, true
		}
	}
	return 0, false
}

// CommandNames is every command a configuration may name, in a useful order:
// the ordinary ones first, then the administrative ones, then the replication
// ones.
func CommandNames() []string {
	return []string{
		"query", "stmt_prepare", "stmt_execute", "stmt_send_long_data",
		"stmt_close", "stmt_reset", "stmt_fetch", "init_db", "ping", "quit",
		"statistics", "reset_connection", "set_option", "field_list",
		"change_user", "create_db", "drop_db", "refresh", "process_info",
		"process_kill", "debug", "shutdown", "clone", "table_dump",
		"binlog_dump", "binlog_dump_gtid", "register_slave",
	}
}

// DefaultCommands is the allow list a relay uses when the configuration names
// none: everything an application driver sends, and nothing administrative.
//
// The absences are the point. `shutdown` stops the server; `debug` writes its
// internals to a log; `process_kill` ends somebody else's query; the three
// replication commands are a copy of every change to every database;
// `table_dump` is a whole table in one command; `create_db` and `drop_db`
// predate the DDL statements and bypass any statement policy; and `field_list`
// is deprecated and historically injectable through its wildcard argument.
func DefaultCommands() []byte {
	return []byte{ComQuery, ComStmtPrepare, ComStmtExecute, ComStmtSendLongData,
		ComStmtClose, ComStmtReset, ComStmtFetch, ComInitDB, ComPing, ComQuit,
		ComStatistics, ComResetConnection, ComSetOption, ComChangeUser}
}

// The authentication plugins.
const (
	// AuthNative is mysql_native_password: a SHA-1 challenge-response. The
	// stored verifier is SHA1(SHA1(password)), so it is not a cleartext leak,
	// and SHA-1 with a 20-octet server nonce is weak rather than broken.
	AuthNative = "mysql_native_password"
	// AuthCachingSHA2 is caching_sha2_password, the default since MySQL 8.0
	// and the right answer. On a connection that is *not* encrypted its first
	// authentication does a full RSA exchange; on one that is, it sends the
	// password in the clear inside TLS, which is why this plugin and
	// require_tls belong together.
	AuthCachingSHA2 = "caching_sha2_password"
	// AuthSHA256 is sha256_password, its predecessor.
	AuthSHA256 = "sha256_password"
	// AuthClearText is mysql_clear_password: the password, in the clear, with
	// nothing over it but whatever transport security exists. It is meant for
	// PAM and LDAP back ends and it is only ever safe inside TLS.
	AuthClearText = "mysql_clear_password"
	// AuthOld is mysql_old_password, the pre-4.1 scramble. It is broken: the
	// hash is 16 hexadecimal digits of a homebrew function, and it was removed
	// from the server in 5.7.
	AuthOld = "mysql_old_password"
	// AuthGSSAPI and AuthLDAP are the enterprise plugins.
	AuthGSSAPI  = "authentication_ldap_sasl_client"
	AuthWindows = "authentication_windows_client"
)

// WeakAuth says whether a plugin puts something on the wire that an observer can
// reuse, or that is broken outright.
//
// mysql_clear_password is the password itself. mysql_old_password is the pre-4.1
// scramble, which is trivially reversible and was removed from the server in
// 5.7 -- a client still offering it is a client from another decade.
//
// mysql_native_password is deliberately *not* here. Its challenge-response does
// not disclose a reusable secret on the wire, and it is still what an enormous
// amount of deployed software uses; calling it weak would make this setting one
// operators turn off wholesale, which is worse than what it buys.
func WeakAuth(plugin string) bool {
	switch plugin {
	case AuthClearText, AuthOld:
		return true
	}
	return false
}

// AuthPlugins is every plugin name a configuration may reasonably name.
func AuthPlugins() []string {
	return []string{AuthCachingSHA2, AuthNative, AuthSHA256, AuthClearText,
		AuthOld, AuthGSSAPI, AuthWindows}
}

// Greeting is the server's initial handshake packet.
type Greeting struct {
	// Protocol is 10 for everything this decade. 9 is the pre-4.0 handshake,
	// a different shape, and refused rather than guessed at.
	Protocol byte
	Version  string
	ConnID   uint32
	Caps     uint32
	Charset  byte
	Status   uint16
	Plugin   string
}

// Offers says whether the server advertised a capability.
func (g *Greeting) Offers(cap uint32) bool { return g.Caps&cap != 0 }

// ParseGreeting reads the server's handshake.
func ParseGreeting(b []byte) (*Greeting, error) {
	if len(b) < 1 {
		return nil, ErrTruncated
	}
	g := &Greeting{Protocol: b[0]}
	if g.Protocol == 0xff {
		// An error packet instead of a greeting, which is what a server sends
		// when it refuses the connection outright -- too many connections, or
		// the client's address is not allowed.
		return nil, fmt.Errorf("%w: the server answered an error", ErrProtocol)
	}
	if g.Protocol != 10 {
		return nil, fmt.Errorf("%w: handshake version %d", ErrProtocol, g.Protocol)
	}
	rest := b[1:]
	ver, rest, err := cstring(rest)
	if err != nil {
		return nil, err
	}
	g.Version = Clip(ver)
	// connection id (4), auth-plugin-data-part-1 (8), filler (1),
	// capability_flags_1 (2), character_set (1), status_flags (2),
	// capability_flags_2 (2), auth_plugin_data_len (1), reserved (10).
	if len(rest) < 4+8+1+2+1+2+2+1+10 {
		return nil, ErrTruncated
	}
	g.ConnID = binary.LittleEndian.Uint32(rest[:4])
	low := binary.LittleEndian.Uint16(rest[13:15])
	g.Charset = rest[15]
	g.Status = binary.LittleEndian.Uint16(rest[16:18])
	high := binary.LittleEndian.Uint16(rest[18:20])
	g.Caps = uint32(low) | uint32(high)<<16
	dataLen := int(rest[20])
	rest = rest[31:]
	// auth-plugin-data-part-2 is at least 13 octets when there is one.
	part2 := 0
	if g.Caps&CapSecureConnection != 0 {
		part2 = dataLen - 8
		if part2 < 13 {
			part2 = 13
		}
		if part2 > len(rest) {
			return nil, ErrTruncated
		}
		rest = rest[part2:]
	}
	if g.Caps&CapPluginAuth != 0 {
		// The plugin name is NUL-terminated, except that some server versions
		// omit the terminator on the last field. Reading to the end is what
		// the reference client does, so a relay that refused would refuse
		// real servers.
		if name, _, err := cstring(rest); err == nil {
			g.Plugin = Clip(name)
		} else {
			g.Plugin = Clip(strings.TrimRight(string(rest), "\x00"))
		}
	}
	return g, nil
}

// Login is the client's handshake response.
type Login struct {
	Caps      uint32
	MaxPacket uint32
	Charset   byte
	User      string
	Database  string
	Plugin    string
	// Attrs are the connection attributes: the client's program name, version,
	// process id and whatever else its driver chose to send. They are
	// peer-chosen strings and are clipped.
	Attrs map[string]string
	// SSLOnly says this was the short form a client sends before its TLS
	// handshake: the first 32 octets and nothing else. The full response
	// follows inside TLS.
	SSLOnly bool
}

// Wants says whether the client asked for a capability.
func (l *Login) Wants(cap uint32) bool { return l.Caps&cap != 0 }

// ParseLogin reads the client's handshake response.
//
// A response with CapSSL set and nothing after the fixed header is the short
// form: the client is about to start TLS and will send the whole thing again.
// Reading it as a truncated full response would refuse every TLS client there
// is.
func ParseLogin(b []byte) (*Login, error) {
	if len(b) < 32 {
		return nil, ErrTruncated
	}
	l := &Login{
		Caps:      binary.LittleEndian.Uint32(b[:4]),
		MaxPacket: binary.LittleEndian.Uint32(b[4:8]),
		Charset:   b[8],
	}
	if l.Caps&CapProtocol41 == 0 {
		// The pre-4.1 response is a different shape. A relay that read it as
		// a 4.1 one would be deciding about fields that are not there.
		return nil, fmt.Errorf("%w: the client did not offer protocol 4.1", ErrProtocol)
	}
	rest := b[32:]
	if len(rest) == 0 {
		if l.Caps&CapSSL == 0 {
			return nil, ErrTruncated
		}
		l.SSLOnly = true
		return l, nil
	}
	user, rest, err := cstring(rest)
	if err != nil {
		return nil, err
	}
	l.User = Clip(user)
	// The authentication response, whose length encoding depends on the
	// capabilities. Its contents are a credential and are deliberately not
	// kept: a relay that held one would be holding somebody's password
	// verifier, and would put its length in a log line.
	switch {
	case l.Caps&CapPluginAuthLenEnc != 0:
		n, adv, err := lenEncInt(rest)
		if err != nil {
			return nil, err
		}
		rest = adv
		if uint64(len(rest)) < n {
			return nil, ErrTruncated
		}
		rest = rest[n:]
	case l.Caps&CapSecureConnection != 0:
		if len(rest) < 1 {
			return nil, ErrTruncated
		}
		n := int(rest[0])
		if len(rest) < 1+n {
			return nil, ErrTruncated
		}
		rest = rest[1+n:]
	default:
		if _, rest, err = cstring(rest); err != nil {
			return nil, err
		}
	}
	if l.Caps&CapConnectWithDB != 0 {
		db, adv, err := cstring(rest)
		if err != nil {
			return nil, err
		}
		l.Database, rest = Clip(db), adv
	}
	if l.Caps&CapPluginAuth != 0 {
		p, adv, err := cstring(rest)
		if err != nil {
			return nil, err
		}
		l.Plugin, rest = Clip(p), adv
	}
	if l.Caps&CapConnectAttrs != 0 {
		attrs, err := parseAttrs(rest)
		if err != nil {
			return nil, err
		}
		l.Attrs = attrs
	}
	return l, nil
}

// parseAttrs reads the connection attributes, which are length-encoded
// key/value pairs inside a length-encoded blob.
func parseAttrs(b []byte) (map[string]string, error) {
	total, rest, err := lenEncInt(b)
	if err != nil {
		return nil, err
	}
	if uint64(len(rest)) < total {
		return nil, ErrTruncated
	}
	rest = rest[:total]
	out := map[string]string{}
	for len(rest) > 0 {
		k, adv, err := lenEncString(rest)
		if err != nil {
			return nil, err
		}
		v, adv2, err := lenEncString(adv)
		if err != nil {
			return nil, err
		}
		if len(out) >= MaxAttrs {
			return nil, ErrTooMany
		}
		out[Clip(k)] = Clip(v)
		rest = adv2
	}
	return out, nil
}

// ChangeUser is the contents of a COM_CHANGE_USER, which re-authenticates a
// connection as somebody else without opening a new one.
type ChangeUser struct {
	User     string
	Database string
	Plugin   string
}

// ReadChangeUser reads a COM_CHANGE_USER payload, which begins after the command
// octet.
//
// A relay that did not read this would have a user and database policy that
// applied to the first message of a connection and nothing after it.
func ReadChangeUser(payload []byte, caps uint32) (*ChangeUser, error) {
	user, rest, err := cstring(payload)
	if err != nil {
		return nil, err
	}
	cu := &ChangeUser{User: Clip(user)}
	switch {
	case caps&CapSecureConnection != 0:
		if len(rest) < 1 {
			return nil, ErrTruncated
		}
		n := int(rest[0])
		if len(rest) < 1+n {
			return nil, ErrTruncated
		}
		rest = rest[1+n:]
	default:
		if _, rest, err = cstring(rest); err != nil {
			return nil, err
		}
	}
	db, rest, err := cstring(rest)
	if err != nil {
		return nil, err
	}
	cu.Database = Clip(db)
	// A character set (2) follows, then the plugin name when the capability is
	// agreed. A payload that stops here is still a valid change-user.
	if len(rest) < 2 {
		return cu, nil
	}
	rest = rest[2:]
	if caps&CapPluginAuth != 0 && len(rest) > 0 {
		if p, _, err := cstring(rest); err == nil {
			cu.Plugin = Clip(p)
		}
	}
	return cu, nil
}

// SetOptionMultiStatements says whether a COM_SET_OPTION payload is switching
// multi-statement support on.
//
// This is the detail that makes a capability policy real. Refusing
// CLIENT_MULTI_STATEMENTS in the handshake is not enough, because COM_SET_OPTION
// turns it on afterwards: the payload is a two-octet value, 0 for on and 1 for
// off. A relay that policed only the handshake would have a policy a client
// lifts with one command.
func SetOptionMultiStatements(payload []byte) (on, readable bool) {
	if len(payload) < 2 {
		return false, false
	}
	switch binary.LittleEndian.Uint16(payload[:2]) {
	case 0: // MYSQL_OPTION_MULTI_STATEMENTS_ON
		return true, true
	case 1: // MYSQL_OPTION_MULTI_STATEMENTS_OFF
		return false, true
	}
	return false, false
}

// The server's answer packet kinds, by first octet.
const (
	// RespOK is an OK packet.
	RespOK byte = 0x00
	// RespEOF is an EOF packet, or a length-encoded integer prefix; context
	// decides, which is one of this protocol's uglier corners.
	RespEOF byte = 0xfe
	// RespErr is an error packet.
	RespErr byte = 0xff
	// RespLocalInfile is the packet that asks the *client* to open a path and
	// send its contents. It is the whole reason the local_files capability
	// matters, and a relay that did not recognise it would be forwarding a
	// file request as if it were data.
	RespLocalInfile byte = 0xfb
)

// LocalInfilePath is the path a server asked the client for, or "" when this is
// not that packet.
func LocalInfilePath(payload []byte) (string, bool) {
	if len(payload) < 1 || payload[0] != RespLocalInfile {
		return "", false
	}
	// The rest of the packet is the filename, not NUL-terminated.
	return Clip(string(payload[1:])), true
}

// ErrorPacket is a server error.
type ErrorPacket struct {
	Code  uint16
	State string
	Text  string
}

// ReadError reads an error packet.
func ReadError(payload []byte, caps uint32) (*ErrorPacket, error) {
	if len(payload) < 3 || payload[0] != RespErr {
		return nil, fmt.Errorf("mysqlwire: not an error packet")
	}
	e := &ErrorPacket{Code: binary.LittleEndian.Uint16(payload[1:3])}
	rest := payload[3:]
	if caps&CapProtocol41 != 0 {
		if len(rest) < 6 || rest[0] != '#' {
			return nil, ErrTruncated
		}
		e.State = string(rest[1:6])
		rest = rest[6:]
	}
	e.Text = Clip(string(rest))
	return e, nil
}

// cstring reads one NUL-terminated string.
func cstring(b []byte) (string, []byte, error) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], nil
		}
	}
	return "", nil, ErrNotTerminated
}

// lenEncInt reads a length-encoded integer.
//
// The encoding is the protocol's own: one octet below 0xfb is the value;
// 0xfc means two octets follow, 0xfd three, 0xfe eight. 0xfb is NULL in a row
// and must not appear as a length here, and reading it as one is how a reader
// ends up with a length of zero where the sender meant "absent".
func lenEncInt(b []byte) (uint64, []byte, error) {
	if len(b) < 1 {
		return 0, nil, ErrTruncated
	}
	switch v := b[0]; {
	case v < 0xfb:
		return uint64(v), b[1:], nil
	case v == 0xfc:
		if len(b) < 3 {
			return 0, nil, ErrTruncated
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), b[3:], nil
	case v == 0xfd:
		if len(b) < 4 {
			return 0, nil, ErrTruncated
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, b[4:], nil
	case v == 0xfe:
		if len(b) < 9 {
			return 0, nil, ErrTruncated
		}
		n := binary.LittleEndian.Uint64(b[1:9])
		if n > MaxMessage {
			return 0, nil, ErrTooLong
		}
		return n, b[9:], nil
	}
	// 0xfb is NULL and 0xff is an error marker; neither is a length.
	return 0, nil, ErrTruncated
}

// lenEncString reads a length-encoded string.
func lenEncString(b []byte) (string, []byte, error) {
	n, rest, err := lenEncInt(b)
	if err != nil {
		return "", nil, err
	}
	if uint64(len(rest)) < n {
		return "", nil, ErrTruncated
	}
	return string(rest[:n]), rest[n:], nil
}

// Clip bounds a peer-chosen string for a log line or a record.
func Clip(s string) string {
	if len(s) <= MaxString {
		return s
	}
	return s[:MaxString] + "..."
}
