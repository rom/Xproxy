// Package syslog reads and writes syslog messages: the RFC 5424 format,
// the older RFC 3164 one that most of the world still sends, and the
// two framings RFC 6587 defines for carrying either over TCP.
//
// A relay that forwards syslog without reading it is a pipe. The
// reason to read it is that almost every field is written by the sender
// and believed by the collector: the host name, the facility, the
// severity, the time. A message claiming to be auth.emerg from another
// machine costs nothing to send, and a message carrying a newline in
// its text becomes two records in any collector that frames on
// newlines. So this package parses, and the relay re-emits what it
// parsed in one canonical form — which is the only way the record a
// collector stores is the record the relay decided about.
package syslog

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Facility and severity names, as every syslog configuration spells
// them.
var (
	Facilities = []string{
		"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
		"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "console", "cron2",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
	}
	Severities = []string{
		"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
	}
)

// FacilityNumber and SeverityNumber map a name to its number.
func FacilityNumber(name string) (int, bool) { return index(Facilities, name) }

// SeverityNumber maps a severity name to its number.
func SeverityNumber(name string) (int, bool) { return index(Severities, name) }

func index(list []string, name string) (int, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for i, s := range list {
		if s == name {
			return i, true
		}
	}
	return 0, false
}

// FacilityName and SeverityName are the reverse, for logs and policy
// decisions.
func FacilityName(n int) string {
	if n < 0 || n >= len(Facilities) {
		return strconv.Itoa(n)
	}
	return Facilities[n]
}

// SeverityName is the reverse of SeverityNumber.
func SeverityName(n int) string {
	if n < 0 || n >= len(Severities) {
		return strconv.Itoa(n)
	}
	return Severities[n]
}

var (
	// ErrMalformed is a message this package will not guess at.
	ErrMalformed = errors.New("syslog: malformed message")
	// ErrTooLarge is a message over the configured bound, on a stream
	// that cannot be resynced: a counted frame says how many octets
	// follow, and refusing to read them leaves the reader at an offset
	// nobody knows. The caller ends the connection.
	ErrTooLarge = errors.New("syslog: message too large")
	// ErrOversizeSkipped is the same bound on a delimited stream, where
	// the reader skipped to the next line ending and is at a message
	// boundary again. The message is lost and the connection is not:
	// one sender writing one long line should not cost every record
	// behind it.
	ErrOversizeSkipped = errors.New("syslog: message too large, skipped to the next")
)

// The nil value RFC 5424 section 6 uses for a field the sender has
// nothing to put in.
const Nil = "-"

// Message is one syslog record, in the shape RFC 5424 gives it. A
// message that arrived as RFC 3164 has been mapped onto the same
// fields, because a relay with two internal shapes is a relay with two
// sets of rules.
type Message struct {
	Facility int
	Severity int
	// Version is 1 for RFC 5424 and 0 for a message that arrived in the
	// older format, which is worth knowing when deciding what to trust.
	Version   int
	Timestamp time.Time
	// HasTimestamp says the sender gave one. RFC 3164 timestamps carry
	// no year and no zone, so one that was reconstructed is marked
	// rather than presented as what the sender said.
	HasTimestamp bool
	Hostname     string
	AppName      string
	ProcID       string
	MsgID        string
	// Structured is the structured data as it arrived, unparsed beyond
	// its framing, plus what the relay adds.
	Structured []SDElement
	Message    string
}

// SDElement is one structured data element: an ID and its parameters.
type SDElement struct {
	ID     string
	Params []SDParam
}

// SDParam is one name and value inside an element.
type SDParam struct {
	Name  string
	Value string
}

// Priority is the PRI value: facility times eight plus severity.
func (m Message) Priority() int { return m.Facility*8 + m.Severity }

// Parse reads one message, in either format. The format is decided by
// what follows the priority: a version digit and a space is RFC 5424,
// anything else is read as RFC 3164.
func Parse(b []byte) (Message, error) {
	s := string(b)
	if !strings.HasPrefix(s, "<") {
		return Message{}, fmt.Errorf("%w: no priority", ErrMalformed)
	}
	end := strings.IndexByte(s, '>')
	if end < 2 || end > 4 {
		return Message{}, fmt.Errorf("%w: priority", ErrMalformed)
	}
	pri, err := strconv.Atoi(s[1:end])
	if err != nil || pri < 0 || pri > 191 {
		// 191 is facility 23, severity 7. Above it there is no facility
		// to name, and a relay that invents one is a relay whose
		// facility filter means nothing.
		return Message{}, fmt.Errorf("%w: priority out of range", ErrMalformed)
	}
	rest := s[end+1:]
	m := Message{Facility: pri / 8, Severity: pri % 8}
	// RFC 5424 begins with a version, which is 1 and is followed by a
	// space. Nothing in RFC 3164 can look like that: its timestamp
	// starts with a month name.
	if len(rest) > 1 && rest[0] == '1' && rest[1] == ' ' {
		m.Version = 1
		return parse5424(m, rest[2:])
	}
	return parse3164(m, rest)
}

// parse5424 reads the fields RFC 5424 section 6 defines, in order.
func parse5424(m Message, s string) (Message, error) {
	fields := make([]string, 0, 6)
	for i := 0; i < 6; i++ {
		f, rest, ok := strings.Cut(s, " ")
		if !ok {
			if i == 5 {
				// The structured data is the last field when there is
				// no message after it.
				f, rest = s, ""
			} else {
				return Message{}, fmt.Errorf("%w: only %d header fields", ErrMalformed, i)
			}
		}
		fields = append(fields, f)
		s = rest
		if i == 4 {
			break
		}
	}
	if len(fields) < 5 {
		return Message{}, fmt.Errorf("%w: short header", ErrMalformed)
	}
	if fields[0] != Nil {
		ts, err := time.Parse(time.RFC3339Nano, fields[0])
		if err != nil {
			return Message{}, fmt.Errorf("%w: timestamp %q", ErrMalformed, clip(fields[0]))
		}
		m.Timestamp, m.HasTimestamp = ts, true
	}
	m.Hostname = unnil(fields[1])
	m.AppName = unnil(fields[2])
	m.ProcID = unnil(fields[3])
	m.MsgID = unnil(fields[4])

	sd, msg, err := splitStructured(s)
	if err != nil {
		return Message{}, err
	}
	m.Structured = sd
	m.Message = strings.TrimPrefix(msg, "\ufeff") // the BOM RFC 5424 puts before UTF-8 text
	if err := m.check(); err != nil {
		return Message{}, err
	}
	return m, nil
}

// splitStructured reads the structured data at the front of s and
// returns it with whatever follows.
func splitStructured(s string) ([]SDElement, string, error) {
	if s == "" {
		return nil, "", nil
	}
	if strings.HasPrefix(s, Nil) {
		rest := s[1:]
		return nil, strings.TrimPrefix(rest, " "), nil
	}
	var out []SDElement
	for strings.HasPrefix(s, "[") {
		el, rest, err := parseElement(s)
		if err != nil {
			return nil, "", err
		}
		out = append(out, el)
		s = rest
		if len(out) > 32 {
			return nil, "", fmt.Errorf("%w: too many structured data elements", ErrMalformed)
		}
	}
	return out, strings.TrimPrefix(s, " "), nil
}

// parseElement reads one "[id name="value" ...]" group. The escaping is
// RFC 5424 section 6.3.3: inside a value, ", ] and \ are backslash
// escaped, and nothing else is.
func parseElement(s string) (SDElement, string, error) {
	s = s[1:] // the opening bracket
	id, rest, ok := cutAny(s, " ]")
	if !ok || id == "" {
		return SDElement{}, "", fmt.Errorf("%w: structured data id", ErrMalformed)
	}
	el := SDElement{ID: id}
	if strings.HasPrefix(rest, "]") {
		return el, rest[1:], nil
	}
	s = rest
	for {
		if strings.HasPrefix(s, "]") {
			return el, s[1:], nil
		}
		name, rest, ok := strings.Cut(s, "=")
		if !ok {
			return SDElement{}, "", fmt.Errorf("%w: structured data parameter", ErrMalformed)
		}
		if !strings.HasPrefix(rest, `"`) {
			return SDElement{}, "", fmt.Errorf("%w: structured data value is not quoted", ErrMalformed)
		}
		var v strings.Builder
		i := 1
		for {
			if i >= len(rest) {
				return SDElement{}, "", fmt.Errorf("%w: unterminated structured data value", ErrMalformed)
			}
			c := rest[i]
			if c == '\\' && i+1 < len(rest) {
				n := rest[i+1]
				if n == '"' || n == ']' || n == '\\' {
					v.WriteByte(n)
					i += 2
					continue
				}
			}
			if c == '"' {
				i++
				break
			}
			v.WriteByte(c)
			i++
		}
		el.Params = append(el.Params, SDParam{Name: strings.TrimSpace(name), Value: v.String()})
		if len(el.Params) > 64 {
			return SDElement{}, "", fmt.Errorf("%w: too many structured data parameters", ErrMalformed)
		}
		s = strings.TrimPrefix(rest[i:], " ")
	}
}

func cutAny(s, chars string) (string, string, bool) {
	i := strings.IndexAny(s, chars)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

// parse3164 reads the older format: an optional timestamp and host,
// then a tag and the text. It is deliberately forgiving about what
// arrives and strict about what comes out, because the format itself is
// a description of what implementations happened to do.
func parse3164(m Message, s string) (Message, error) {
	// "Mmm dd hh:mm:ss", fifteen octets, with the day space padded.
	if len(s) >= 16 && s[15] == ' ' {
		if ts, err := time.Parse(time.Stamp, s[:15]); err == nil {
			// The year is not in the message. Taking the current one is
			// what every implementation does, and it is marked as
			// reconstructed rather than presented as the sender's.
			now := time.Now()
			m.Timestamp = time.Date(now.Year(), ts.Month(), ts.Day(),
				ts.Hour(), ts.Minute(), ts.Second(), 0, time.UTC)
			m.HasTimestamp = true
			s = s[16:]
			// The host follows the timestamp, when there is one.
			if host, rest, ok := strings.Cut(s, " "); ok && host != "" {
				m.Hostname, s = host, rest
			}
		}
	}
	// "tag[pid]:" or "tag:" at the front of the text, which is where
	// the application name lives in this format.
	if i := strings.IndexAny(s, ":["); i > 0 && i < 48 {
		name := s[:i]
		if isTagName(name) {
			rest := s[i:]
			m.AppName = name
			if strings.HasPrefix(rest, "[") {
				if j := strings.IndexByte(rest, ']'); j > 1 {
					m.ProcID = rest[1:j]
					rest = rest[j+1:]
				}
			}
			s = strings.TrimPrefix(rest, ":")
			s = strings.TrimPrefix(s, " ")
		}
	}
	m.Message = s
	if err := m.check(); err != nil {
		return Message{}, err
	}
	return m, nil
}

func isTagName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == '/':
		default:
			return false
		}
	}
	return true
}

// check refuses what cannot be re-emitted honestly. A NUL or a line
// ending inside a field is the injection this format is prone to: a
// collector that frames on newlines reads one message as two, and the
// second one says whatever the sender wanted it to say.
func (m Message) check() error {
	for _, f := range []string{m.Hostname, m.AppName, m.ProcID, m.MsgID} {
		if strings.ContainsAny(f, "\x00\r\n ") {
			return fmt.Errorf("%w: a header field contains a space or a line ending", ErrMalformed)
		}
	}
	if strings.ContainsRune(m.Message, 0) {
		return fmt.Errorf("%w: NUL in the message", ErrMalformed)
	}
	if !utf8.ValidString(m.Message) {
		return fmt.Errorf("%w: the message is not UTF-8", ErrMalformed)
	}
	return nil
}

func unnil(s string) string {
	if s == Nil {
		return ""
	}
	return s
}

func clip(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "..."
}
