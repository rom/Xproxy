// Package respwire reads the Redis serialization protocol, for the redis relay
// kind.
//
// RESP is the simplest protocol in this project and the one whose *policy* needs
// the most care, because Redis has no schema, no statement grammar and almost no
// structure for a relay to reason about. A command is an array of opaque byte
// strings. There is nothing to classify by shape the way a SQL statement can be
// classified: the first element is a command name and the rest are arguments
// whose meaning depends entirely on which name it was.
//
// So the policy this package serves is built on the two things that *are*
// structural.
//
// The first is the command name, which is an allow list, defaulting to what an
// application uses. The absences are the whole point, and it is worth writing out
// why each one is dangerous, because on this protocol "administrative" and
// "remote code execution" are closer together than anywhere else:
//
//	CONFIG SET dir + dbfilename    writes a file of the attacker's choosing
//	                               anywhere the server can write. Pointed at
//	                               ~/.ssh/authorized_keys or a cron directory it
//	                               is remote code execution, and it has been
//	                               used that way for a decade.
//	REPLICAOF / SLAVEOF            makes this server a replica of one the
//	                               attacker controls, which replaces its whole
//	                               dataset -- and on an unpatched server the
//	                               master can load a module.
//	MODULE LOAD                    loads a shared object. It is the direct form
//	                               of the same thing.
//	EVAL / EVALSHA / FUNCTION      a Lua interpreter inside the database.
//	DEBUG                          has subcommands that crash the server, and
//	                               DEBUG OBJECT leaks addresses.
//	MIGRATE                        moves a key to another server, which is
//	                               egress with a key name attached.
//	FLUSHALL / FLUSHDB             deletes everything, unrecoverably.
//	SHUTDOWN                       stops the server; with NOSAVE it loses data.
//	SAVE / BGSAVE / BGREWRITEAOF   writes a file, and blocks.
//	KEYS / RANDOMKEY / SCAN        KEYS is O(n) on the *single* thread that
//	                               serves everybody, so one KEYS * on a large
//	                               instance is a denial of service that looks
//	                               like a slow query.
//	SUBSCRIBE / MONITOR            MONITOR streams every command every client
//	                               sends, including the arguments -- which is
//	                               every value written to the database.
//	SCRIPT / ACL / CLIENT / CLUSTER administration of the thing enforcing the
//	                               policy.
//
// The second is the key. A command's keys are at positions the command's own
// signature fixes, so a key prefix policy is possible and is the closest thing
// this protocol has to the database-and-table boundary the SQL kinds leave to
// GRANT. It is bounded honestly: this package knows where the keys are for the
// commands in its table and says so for the rest, and a relay that guessed would
// enforce a prefix policy on the wrong argument.
//
// Two bounds matter more here than in most parsers, because both are integers the
// client chooses and both are multiplied by the reader:
//
//	*<count>\r\n      how many elements follow
//	$<length>\r\n     how many octets the next one is
//
// A reader that trusted either would allocate what a single small message asked
// for. Both are checked against a bound before anything is allocated, and the
// running total of a whole command is bounded too -- because a thousand elements
// of a megabyte each is a bound met a thousand times and a gigabyte held.
package respwire

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The RESP type markers. RESP2 has five; RESP3 adds seven more, which a relay
// must be able to name even though a client rarely sends them: the server speaks
// them after HELLO 3, and a relay that could not read the server's side could
// not tell a reply from the start of another command.
const (
	// TypeSimpleString is "+OK\r\n".
	TypeSimpleString byte = '+'
	// TypeError is "-ERR ...\r\n".
	TypeError byte = '-'
	// TypeInteger is ":1\r\n".
	TypeInteger byte = ':'
	// TypeBulkString is "$3\r\nfoo\r\n", and "$-1\r\n" for a null.
	TypeBulkString byte = '$'
	// TypeArray is "*2\r\n" followed by two elements, and "*-1\r\n" for a null.
	TypeArray byte = '*'

	// RESP3, from HELLO 3 onwards.
	TypeNull       byte = '_'
	TypeDouble     byte = ','
	TypeBoolean    byte = '#'
	TypeBlobError  byte = '!'
	TypeVerbatim   byte = '='
	TypeBigNumber  byte = '('
	TypeMap        byte = '%'
	TypeSet        byte = '~'
	TypeAttribute  byte = '|'
	TypePush       byte = '>'
	TypeStreamedAg byte = '?'
)

// Bounds. Every one of them is a number a peer chooses.
const (
	// MaxElements bounds the element count of one array. Redis itself refuses
	// past 1024*1024 in an inline request and accepts more in a multibulk; this
	// is the relay's own ceiling, and a command with more elements than this is
	// not a command any client library sends.
	MaxElements = 1024 * 1024
	// MaxBulk bounds one bulk string. Redis's own limit is 512 MiB, which is
	// also the maximum value size.
	MaxBulk = 512 << 20
	// MaxMessage bounds a whole reassembled command, which is the bound that
	// actually matters: a count under MaxElements of strings each under MaxBulk
	// multiplies to far more than either.
	MaxMessage = 512 << 20
	// DefaultMaxMessage and DefaultMaxBulk are what a listener uses when the
	// configuration names no bound. A megabyte value is a large one for a cache;
	// an estate that stores more raises it deliberately.
	DefaultMaxMessage = 8 << 20
	DefaultMaxBulk    = 1 << 20
	// DefaultMaxElements bounds a pipeline's array, which for an ordinary
	// command is single digits.
	DefaultMaxElements = 1024
	// MaxInline bounds an inline command, the space-separated form a human
	// types into telnet. Redis's own limit is 64 KiB.
	MaxInline = 64 << 10
	// MaxString clips a peer-chosen string for a log line or a record.
	MaxString = 256
)

// Errors this package returns.
var (
	// ErrProtocol is a message that is not RESP at all. It is the one a relay
	// answers with -ERR, because it is what the server would answer.
	ErrProtocol = errors.New("respwire: not a RESP message")
	// ErrTooLong is a declared length past a bound.
	ErrTooLong = errors.New("respwire: message is longer than the bound")
	// ErrTooMany is more elements than the bound allows.
	ErrTooMany = errors.New("respwire: more elements than the bound allows")
	// ErrTruncated is a message that ends inside a field.
	ErrTruncated = errors.New("respwire: message ends inside a field")
	// ErrInline is an inline command where a multibulk was required.
	ErrInline = errors.New("respwire: inline command")
)

// Command is one client command: a name and its arguments.
type Command struct {
	// Name is the command, upper-cased, because Redis matches it without regard
	// to case and a policy that held two spellings would match neither
	// reliably.
	Name string
	// Sub is the subcommand, upper-cased, for the commands where the
	// subcommand is the whole of what matters -- CONFIG SET is not CONFIG GET,
	// and a policy that could only say CONFIG would have to refuse both or
	// neither.
	Sub string
	// Args is every element after the name, including the subcommand. The
	// values are the caller's data; only the ones a policy needs -- the keys --
	// are ever turned into strings, and the rest are measured and left alone.
	Args [][]byte
	// Inline says the command arrived in the space-separated form rather than
	// as a multibulk array.
	Inline bool
	// Raw is the octets as they arrived, for forwarding unchanged. A relay that
	// re-encoded would be forwarding a message it had built rather than the one
	// the client sent.
	Raw []byte
}

// String names the command for a log line: the name, and the subcommand where
// there is one.
func (c *Command) String() string {
	if c.Sub != "" {
		return c.Name + " " + c.Sub
	}
	return c.Name
}

// Reader reads commands from a client.
type Reader struct {
	br  *bufio.Reader
	max int
	// maxBulk and maxElements bound one string and one array.
	maxBulk, maxElements int
	// buf accumulates the raw octets of the message being read.
	buf []byte
}

// NewReader makes a reader bounded at max reassembled octets per command.
func NewReader(r io.Reader, max, maxBulk, maxElements int) *Reader {
	if max <= 0 || max > MaxMessage {
		max = DefaultMaxMessage
	}
	if maxBulk <= 0 || maxBulk > MaxBulk {
		maxBulk = DefaultMaxBulk
	}
	if maxBulk > max {
		// A bulk bound above the message bound is not a bound: the message
		// check would fire first and the configured value would never apply,
		// which reads in a log as the wrong limit refusing the request.
		maxBulk = max
	}
	if maxElements <= 0 || maxElements > MaxElements {
		maxElements = DefaultMaxElements
	}
	return &Reader{br: bufio.NewReaderSize(r, 16<<10), max: max,
		maxBulk: maxBulk, maxElements: maxElements, buf: make([]byte, 0, 4096)}
}

// Next reads one command.
//
// Both forms are read. A multibulk array is what every client library sends; the
// inline form is what a human sends through netcat, and what a great many
// exploitation scripts send because it is easier to write -- so a relay that read
// only the array form would be blind to exactly the traffic it exists to refuse.
func (rd *Reader) Next() (*Command, error) {
	rd.buf = rd.buf[:0]
	first, err := rd.br.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] != TypeArray {
		return rd.inline()
	}
	n, err := rd.count(TypeArray, rd.maxElements)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		// A null or empty array is not a command. Redis ignores it; a relay
		// that forwarded it would be forwarding something no policy decided
		// about, and one that treated it as a command would have an empty name.
		return nil, fmt.Errorf("%w: an array of %d elements is not a command", ErrProtocol, n)
	}
	c := &Command{Args: make([][]byte, 0, n-1)}
	for i := 0; i < n; i++ {
		b, err := rd.bulk()
		if err != nil {
			return nil, err
		}
		if i == 0 {
			if !validName(string(b)) {
				return nil, fmt.Errorf("%w: %q is not a command name",
					ErrProtocol, Clip(string(b)))
			}
			c.Name = upper(string(b))
			continue
		}
		c.Args = append(c.Args, b)
	}
	if takesSub(c.Name) && len(c.Args) > 0 {
		c.Sub = upper(Clip(string(c.Args[0])))
	}
	c.Raw = append([]byte(nil), rd.buf...)
	return c, nil
}

// count reads a "*<n>\r\n" or "$<n>\r\n" header.
func (rd *Reader) count(want byte, bound int) (int, error) {
	line, err := rd.line()
	if err != nil {
		return 0, err
	}
	if len(line) < 1 || line[0] != want {
		return 0, fmt.Errorf("%w: expected %q, got %q", ErrProtocol, string(want), first(line))
	}
	n, err := strconv.Atoi(string(line[1:]))
	if err != nil {
		return 0, fmt.Errorf("%w: %q is not a count", ErrProtocol, Clip(string(line[1:])))
	}
	// Checked *before* anything is sized by it, which is the whole point: the
	// number arrived from the network and the next statement would otherwise
	// allocate it.
	if n > bound {
		return 0, fmt.Errorf("%w: %d past the bound of %d", ErrTooMany, n, bound)
	}
	if n < -1 {
		// -1 is the protocol's null; anything below it is a length that means
		// nothing, and a reader that treated it as zero would be completing a
		// message on the sender's behalf.
		return 0, fmt.Errorf("%w: a count of %d", ErrProtocol, n)
	}
	return n, nil
}

// bulk reads one bulk string element.
func (rd *Reader) bulk() ([]byte, error) {
	n, err := rd.count(TypeBulkString, rd.maxBulk)
	if err != nil {
		return nil, err
	}
	if n < 0 {
		// A null inside a command. Redis refuses one, and a relay that turned
		// it into an empty argument would shift every argument after it -- so
		// the key a prefix policy checked would be the wrong one.
		return nil, fmt.Errorf("%w: a null element inside a command", ErrProtocol)
	}
	if len(rd.buf)+n+2 > rd.max {
		return nil, fmt.Errorf("%w: %d octets", ErrTooLong, len(rd.buf)+n+2)
	}
	b := make([]byte, n+2) // the value and its CRLF
	if _, err := io.ReadFull(rd.br, b); err != nil {
		return nil, err
	}
	if b[n] != '\r' || b[n+1] != '\n' {
		return nil, fmt.Errorf("%w: a bulk string not ended by CRLF", ErrProtocol)
	}
	// Only the value and its terminator: line has already recorded the "$n\r\n"
	// header. Appending it again here would put it in twice, and Raw is what the
	// relay forwards -- so the server would receive a command the relay never
	// decided about, out of octets the relay itself invented.
	rd.buf = append(rd.buf, b...)
	return b[:n], nil
}

// line reads one CRLF-terminated line and records it in the raw buffer.
func (rd *Reader) line() ([]byte, error) {
	line, err := rd.br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			// A line longer than the read buffer. On this protocol a header
			// line is a handful of octets, so this is not a large message: it
			// is a sender that never sent a newline.
			return nil, fmt.Errorf("%w: a header line longer than %d octets", ErrTooLong, 16<<10)
		}
		return nil, err
	}
	if len(rd.buf)+len(line) > rd.max {
		return nil, fmt.Errorf("%w: %d octets", ErrTooLong, len(rd.buf)+len(line))
	}
	rd.buf = append(rd.buf, line...)
	if len(line) < 2 || line[len(line)-2] != '\r' {
		// A bare LF. Redis accepts one in an inline command and not in a
		// header, and this reader does not accept one in a header either:
		// treating it as a terminator would mean the relay and the server
		// disagreed about where the header ended.
		return nil, fmt.Errorf("%w: a line not ended by CRLF", ErrProtocol)
	}
	return line[:len(line)-2], nil
}

// inline reads the space-separated form.
//
// This is the form a human types and the form most exploitation scripts send,
// because it needs no length arithmetic. Reading it is not a convenience: a relay
// that refused it outright would be refused by nobody's application but would
// also have no idea what the inline traffic said, and a relay that ignored it
// would pass it straight through.
func (rd *Reader) inline() (*Command, error) {
	line, err := rd.br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("%w: an inline command longer than %d octets",
				ErrTooLong, 16<<10)
		}
		return nil, err
	}
	if len(line) > MaxInline {
		return nil, fmt.Errorf("%w: an inline command of %d octets", ErrTooLong, len(line))
	}
	rd.buf = append(rd.buf, line...)
	text := strings.TrimRight(string(line), "\r\n")
	fields := strings.Fields(text)
	if len(fields) == 0 {
		// Redis ignores an empty inline line. A relay must not forward it as a
		// command, and must not treat it as end of stream either.
		return nil, fmt.Errorf("%w: an empty inline command", ErrProtocol)
	}
	if !validName(fields[0]) {
		return nil, fmt.Errorf("%w: %q is not a command name", ErrProtocol, Clip(fields[0]))
	}
	c := &Command{Inline: true, Name: upper(fields[0])}
	for _, f := range fields[1:] {
		c.Args = append(c.Args, []byte(f))
	}
	if takesSub(c.Name) && len(c.Args) > 0 {
		c.Sub = upper(Clip(string(c.Args[0])))
	}
	c.Raw = append([]byte(nil), rd.buf...)
	return c, nil
}

// validName says whether a string can be a Redis command name.
//
// The alphabet is ASCII letters, digits, and the three punctuation marks a module
// uses: `JSON.SET`, `bf.add`, `ft.search`, `graph.QUERY`. Nothing else can be a
// command, so a name containing anything else is refused rather than carried.
//
// The point is not that such a name would be *allowed* -- it would match no entry
// in any allow list, so the policy refuses it either way. The point is that the
// name reaches a log line, a counter label and a shadow-mode report, and octets
// that are not text have no business in any of the three. Refusing at the reader
// means every later stage can assume it has a name.
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

func first(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return string(b[:1])
}

// upper folds a command name.
//
// ASCII only, and deliberately: strings.ToUpper would map the Turkish dotless i
// to a different letter under some locales' rules and, more to the point, can
// change a string's length. Redis compares command names with an ASCII-only
// fold, so this is the comparison the server makes rather than a more thorough
// one that would disagree with it.
func upper(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		b.WriteByte(c)
	}
	return b.String()
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

// Error encodes an error reply, which is how a relay refuses in the protocol the
// client is speaking.
//
// The message is sanitised first. An error reply is a single line and the
// terminator is the framing, so a CR or LF inside the text would end the reply
// early and the rest would be read as another one -- a reply the relay did not
// mean to send, built out of a string the client chose. That is response
// splitting, with a Redis client library on the receiving end.
func Error(kind, msg string) []byte {
	// A client library reads the first word as the error kind, so a blank one
	// leaves it with nothing to switch on -- and "-   " is a reply no library
	// parses. Blank rather than merely empty, because a caller passing a space
	// meant the same thing as passing nothing.
	kind = upper(strings.Map(keepKind, kind))
	if kind == "" {
		kind = "ERR"
	}
	out := make([]byte, 0, len(kind)+len(msg)+8)
	out = append(out, TypeError)
	out = append(out, kind...)
	out = append(out, ' ')
	out = append(out, oneLine(Clip(msg))...)
	return append(out, '\r', '\n')
}

// keepKind reduces an error kind to the alphabet a client library expects of one:
// letters and digits, which is what every kind Redis itself sends is made of.
func keepKind(r rune) rune {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return r
	}
	return -1
}

// oneLine replaces anything that would end a line with a space.
func oneLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\r', '\n', 0:
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
