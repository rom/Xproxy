// Package ftp holds the protocol pieces an FTP-aware proxy needs:
// reading commands and replies with hard bounds, and reading and
// writing the address negotiations that decide where the data
// connection goes.
//
// FTP is two connections. The control connection carries commands, and
// every transfer happens on a second connection whose address one side
// announces to the other. A proxy that reads only the control
// connection has read the instructions and none of the transfers, and
// one that passes the announced address through has told the client to
// go round it. The addresses are therefore the part of this package
// that matters most: they are parsed, and they are written again by the
// proxy rather than forwarded.
//
// Nothing here talks to a network. The session that does lives in the
// proxy; keeping the parsing separate is what makes the awkward cases —
// a bare LF inside an argument, a reply continued over forty lines, a
// PASV reply with a port nobody should be sent to — testable without an
// FTP server.
package ftp

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The bounds this package starts from. RFC 959 sets 512 for a command
// line, which was written before path names were long; the default here
// is larger and configurable, and the point of the bound is that there
// is one.
const (
	// MaxCommandLine is the default command line limit including CRLF.
	MaxCommandLine = 4096
	// MaxReplyLines bounds a multi-line reply. No command has a
	// legitimate answer anywhere near this long, so a server sending
	// more is either broken or spending the proxy's memory.
	MaxReplyLines = 100
)

var (
	// ErrLineTooLong is a line over the bound. The rest of it would be
	// read as a command of its own, so the session answers and stops
	// rather than reading on.
	ErrLineTooLong = errors.New("ftp: line too long")
	// ErrBareNewline is a line ended by LF without the CR. Accepting it
	// is how one command becomes two: the proxy sees the argument, the
	// target sees a second command inside it.
	ErrBareNewline = errors.New("ftp: bare newline")
	// ErrBareCR is a CR that is not followed by LF, the same
	// disagreement in the other direction.
	ErrBareCR = errors.New("ftp: bare carriage return")
	// ErrTelnet is an IAC sequence in the control stream. RFC 959
	// allows them and almost nothing sends them; a proxy that does not
	// interpret them exactly as the target does is a proxy whose policy
	// does not hold, so they are refused rather than guessed at.
	ErrTelnet = errors.New("ftp: telnet command in the control stream")
	// ErrBadReply is a reply that is not three digits and a separator.
	ErrBadReply = errors.New("ftp: malformed reply")
	// ErrTooManyReplyLines is a reply continued past MaxReplyLines.
	ErrTooManyReplyLines = errors.New("ftp: reply has too many lines")
	// ErrBadAddress is an address negotiation that does not parse.
	ErrBadAddress = errors.New("ftp: malformed address")
)

// Reader reads CRLF-terminated lines with a hard bound.
type Reader struct {
	br  *bufio.Reader
	max int
}

// NewReader returns a Reader over r bounded to max octets per line
// including the CRLF. The buffer is that size, so a line that does not
// fit is refused rather than grown into.
func NewReader(r *bufio.Reader, max int) *Reader {
	if max < 64 {
		max = 64
	}
	return &Reader{br: r, max: max}
}

// Buffered is what has been read from the connection and not consumed.
// After a command whose reply changes how the stream is read — AUTH TLS
// above all — anything buffered was sent before the peer could have
// seen the answer.
func (r *Reader) Buffered() int { return r.br.Buffered() }

// ReadLine reads one line without its CRLF.
func (r *Reader) ReadLine() ([]byte, error) {
	line, err := r.br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		// The buffer filled before a line ending arrived, so the reader
		// is somewhere in the middle of a line; skip to the end of it,
		// or the rest would be read as a command of its own.
		r.discardLine()
		return nil, ErrLineTooLong
	case err == nil && len(line) > r.max:
		// A whole line, but a longer one than the bound allows. The
		// reader is already at the next line, so there is nothing to
		// skip: discarding here would swallow the command after it.
		return nil, ErrLineTooLong
	case err != nil:
		return nil, err
	}
	body := line[:len(line)-1]
	if n := len(body); n > 0 && body[n-1] == '\r' {
		body = body[:n-1]
	} else {
		return nil, ErrBareNewline
	}
	for _, b := range body {
		switch b {
		case '\r':
			return nil, ErrBareCR
		case 0xff: // IAC
			return nil, ErrTelnet
		}
	}
	return append([]byte(nil), body...), nil
}

func (r *Reader) discardLine() {
	for n := 0; n < 1<<20; n++ {
		b, err := r.br.ReadByte()
		if err != nil || b == '\n' {
			return
		}
	}
}

// Command is one parsed client command: the verb uppercased, and the
// argument with the single separating space removed.
type Command struct {
	Verb string
	Arg  string
}

// ParseCommand reads a command line. The verb is uppercased because FTP
// verbs are case insensitive and a policy that is not would be a policy
// spelled around.
func ParseCommand(line []byte) (Command, error) {
	s := string(line)
	if s == "" {
		return Command{}, fmt.Errorf("ftp: empty command")
	}
	verb, arg, found := strings.Cut(s, " ")
	if !found {
		verb = s
	}
	for _, r := range verb {
		if r < 'A' || (r > 'Z' && r < 'a') || r > 'z' {
			return Command{}, fmt.Errorf("ftp: %q is not a verb", clip(verb, 16))
		}
	}
	if len(verb) == 0 || len(verb) > 8 {
		return Command{}, fmt.Errorf("ftp: %q is not a verb", clip(verb, 16))
	}
	if strings.ContainsRune(arg, 0) {
		return Command{}, fmt.Errorf("ftp: NUL in the argument")
	}
	return Command{Verb: strings.ToUpper(verb), Arg: arg}, nil
}

// Format renders a command for the wire.
func (c Command) Format() []byte {
	if c.Arg == "" {
		return []byte(c.Verb + "\r\n")
	}
	return []byte(c.Verb + " " + c.Arg + "\r\n")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Reply is one server reply, which may have arrived over several lines.
type Reply struct {
	Code  int
	Lines []string
}

// Text is the reply's first line, which is the part a client shows.
func (rep Reply) Text() string {
	if len(rep.Lines) == 0 {
		return ""
	}
	return rep.Lines[0]
}

// ReadReply reads a reply, following the RFC 959 section 4.2
// continuation rule: "NNN-" opens a group and the same code with a
// space closes it.
func ReadReply(r *Reader) (Reply, error) {
	line, err := r.ReadLine()
	if err != nil {
		return Reply{}, err
	}
	code, sep, text, err := splitReply(line)
	if err != nil {
		return Reply{}, err
	}
	rep := Reply{Code: code, Lines: []string{text}}
	if sep == ' ' {
		return rep, nil
	}
	for {
		if len(rep.Lines) >= MaxReplyLines {
			return Reply{}, ErrTooManyReplyLines
		}
		line, err := r.ReadLine()
		if err != nil {
			return Reply{}, err
		}
		// A continuation line may be anything at all; only a line that
		// repeats the code with a space ends the group.
		if c, s, t, err := splitReply(line); err == nil && c == code && s == ' ' {
			rep.Lines = append(rep.Lines, t)
			return rep, nil
		}
		rep.Lines = append(rep.Lines, string(line))
	}
}

func splitReply(line []byte) (code int, sep byte, text string, err error) {
	if len(line) < 4 {
		return 0, 0, "", ErrBadReply
	}
	for i := 0; i < 3; i++ {
		if line[i] < '0' || line[i] > '9' {
			return 0, 0, "", ErrBadReply
		}
	}
	code = int(line[0]-'0')*100 + int(line[1]-'0')*10 + int(line[2]-'0')
	if code < 100 || code > 599 {
		return 0, 0, "", ErrBadReply
	}
	sep = line[3]
	if sep != ' ' && sep != '-' {
		return 0, 0, "", ErrBadReply
	}
	return code, sep, string(line[4:]), nil
}

// Format renders a reply for the wire, with the continuation marks a
// multi-line reply needs.
func (rep Reply) Format() []byte {
	if len(rep.Lines) == 0 {
		return []byte(fmt.Sprintf("%03d \r\n", rep.Code))
	}
	var b strings.Builder
	for i, l := range rep.Lines {
		sep := "-"
		if i == len(rep.Lines)-1 {
			sep = " "
		}
		// A line the proxy writes cannot carry a line ending of its
		// own: that would end the reply where the proxy did not mean
		// to and let the rest be read as another one.
		b.WriteString(fmt.Sprintf("%03d%s%s\r\n", rep.Code, sep, sanitise(l)))
	}
	return []byte(b.String())
}

// Line builds a single-line reply.
func Line(code int, text string) []byte {
	return Reply{Code: code, Lines: []string{text}}.Format()
}

// sanitise removes what would end a line early or confuse the reply
// structure. It is applied to every line this package writes, because
// some of them carry text that came from somewhere else.
func sanitise(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, s)
}

// ParsePASV reads the address out of a 227 reply. The format is not
// delimited: RFC 959 puts the six numbers in a parenthesised list
// somewhere in free text, and servers have put them in several
// different sentences, so the numbers are found rather than the
// sentence parsed.
// The address in a passive reply is advisory and this proxy replaces
// it with the address it is already connected to, so the leniency here
// is deliberate: servers behind NAT really do advertise 0.0.0.0, and
// refusing them would break transfers for no gain. Anything that acts
// on an address parsed from the wire goes through peerAddress first --
// ParsePORT and ParseEPRT do.
func ParsePASV(text string) (netip.AddrPort, error) {
	first := strings.IndexByte(text, '(')
	last := strings.LastIndexByte(text, ')')
	var body string
	switch {
	case first >= 0 && last > first:
		body = text[first+1 : last]
	default:
		// Some servers leave the brackets out, and one old family
		// writes "=10,0,0,1,4,1". Take the numeric tail rather than
		// guessing at the sentence in front of it.
		i := len(text)
		for i > 0 {
			c := text[i-1]
			if (c >= '0' && c <= '9') || c == ',' || c == ' ' {
				i--
				continue
			}
			break
		}
		body = text[i:]
	}
	parts := strings.Split(body, ",")
	if len(parts) != 6 {
		return netip.AddrPort{}, ErrBadAddress
	}
	var n [6]int
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 0 || v > 255 {
			return netip.AddrPort{}, ErrBadAddress
		}
		n[i] = v
	}
	addr := netip.AddrFrom4([4]byte{byte(n[0]), byte(n[1]), byte(n[2]), byte(n[3])})
	port := n[4]<<8 | n[5]
	if port == 0 {
		return netip.AddrPort{}, ErrBadAddress
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil //nolint:gosec // bounded above
}

// FormatPASV writes the six numbers a 227 reply carries. Only IPv4 can
// be spelled this way, which is what EPSV exists for.
func FormatPASV(ap netip.AddrPort) (string, bool) {
	a := ap.Addr().Unmap()
	if !a.Is4() {
		return "", false
	}
	b := a.As4()
	p := ap.Port()
	return fmt.Sprintf("%d,%d,%d,%d,%d,%d", b[0], b[1], b[2], b[3], p>>8, p&0xff), true
}

// ParseEPSV reads the port out of a 229 reply (RFC 2428 section 3): a
// parenthesised group delimited by a character the server chooses, with
// the first two fields empty because the address is the control
// connection's.
func ParseEPSV(text string) (int, error) {
	open := strings.IndexByte(text, '(')
	close := strings.LastIndexByte(text, ')')
	if open < 0 || close <= open+4 {
		return 0, ErrBadAddress
	}
	body := text[open+1 : close]
	d := body[0]
	fields := strings.Split(body, string(d))
	// The delimiter opens and closes the group, so a well formed body
	// splits into five fields: "", "", "", port, "".
	if len(fields) != 5 || fields[0] != "" || fields[4] != "" {
		return 0, ErrBadAddress
	}
	port, err := strconv.Atoi(fields[3])
	if err != nil || port < 1 || port > 65535 {
		return 0, ErrBadAddress
	}
	return port, nil
}

// FormatEPSV writes the parenthesised group of a 229 reply.
func FormatEPSV(port int) string { return fmt.Sprintf("(|||%d|)", port) }

// ParsePORT reads the address a client announces for active mode.
//
// Unlike a passive reply, this address is acted on: it is where the
// proxy will open a data connection. So it also has to be an address a
// peer can have. The session checks it against the client's own on top
// of this, and both checks exist because either alone is one caller
// away from being forgotten.
func ParsePORT(arg string) (netip.AddrPort, error) {
	ap, err := ParsePASV(strings.TrimSpace(arg))
	if err != nil {
		return netip.AddrPort{}, err
	}
	return peerAddress(ap)
}

// peerAddress refuses what cannot be the other end of a connection:
// the unspecified address, a multicast group, and anything carrying an
// interface zone, which names an interface on this host rather than a
// place on the network. A parser that hands one of these back is a
// parser whose next caller has a bug waiting.
func peerAddress(ap netip.AddrPort) (netip.AddrPort, error) {
	a := ap.Addr()
	if a.Zone() != "" {
		return netip.AddrPort{}, ErrBadAddress
	}
	u := a.Unmap()
	if !u.IsValid() || u.IsUnspecified() || u.IsMulticast() || ap.Port() == 0 {
		return netip.AddrPort{}, ErrBadAddress
	}
	if u.Is4() && u.As4() == [4]byte{255, 255, 255, 255} {
		return netip.AddrPort{}, ErrBadAddress
	}
	return ap, nil
}

// FormatPORT writes a PORT argument.
func FormatPORT(ap netip.AddrPort) (string, bool) { return FormatPASV(ap) }

// ParseEPRT reads an EPRT argument (RFC 2428 section 2):
// "|proto|address|port|", with a delimiter the client chooses.
func ParseEPRT(arg string) (netip.AddrPort, error) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 8 {
		return netip.AddrPort{}, ErrBadAddress
	}
	d := arg[0]
	fields := strings.Split(arg, string(d))
	if len(fields) != 5 || fields[0] != "" || fields[4] != "" {
		return netip.AddrPort{}, ErrBadAddress
	}
	addr, err := netip.ParseAddr(fields[2])
	if err != nil {
		return netip.AddrPort{}, ErrBadAddress
	}
	switch fields[1] {
	case "1":
		if !addr.Unmap().Is4() {
			return netip.AddrPort{}, ErrBadAddress
		}
	case "2":
		if addr.Unmap().Is4() {
			return netip.AddrPort{}, ErrBadAddress
		}
	default:
		return netip.AddrPort{}, ErrBadAddress
	}
	port, err := strconv.Atoi(fields[3])
	if err != nil || port < 1 || port > 65535 {
		return netip.AddrPort{}, ErrBadAddress
	}
	return peerAddress(netip.AddrPortFrom(addr, uint16(port))) //nolint:gosec // bounded above
}

// FormatEPRT writes an EPRT argument.
func FormatEPRT(ap netip.AddrPort) string {
	proto := "1"
	a := ap.Addr().Unmap()
	if !a.Is4() {
		proto = "2"
	}
	return fmt.Sprintf("|%s|%s|%d|", proto, a.String(), ap.Port())
}

// PathArg reports whether a verb's argument is a path the policy
// decides on, and whether the command changes the server.
//
// The table is the vocabulary: a verb that is not in it is one whose
// argument the proxy cannot read, and a policy cannot be applied to an
// argument nobody understands.
var (
	// Paths are the verbs whose argument names a file or a directory.
	Paths = map[string]bool{
		"RETR": true, "STOR": true, "STOU": true, "APPE": true,
		"DELE": true, "RNFR": true, "RNTO": true, "MKD": true, "XMKD": true,
		"RMD": true, "XRMD": true, "CWD": true, "XCWD": true,
		"LIST": true, "NLST": true, "MLSD": true, "MLST": true,
		"SIZE": true, "MDTM": true, "STAT": true,
	}
	// Writes are the verbs that change the server. A read-only policy
	// refuses every one of them.
	Writes = map[string]bool{
		"STOR": true, "STOU": true, "APPE": true, "DELE": true,
		"RNFR": true, "RNTO": true, "MKD": true, "XMKD": true,
		"RMD": true, "XRMD": true, "SITE": true, "ALLO": true,
	}
	// Transfers are the verbs that open a data connection.
	Transfers = map[string]bool{
		"RETR": true, "STOR": true, "STOU": true, "APPE": true,
		"LIST": true, "NLST": true, "MLSD": true,
	}
	// Uploads are the transfers whose bytes travel towards the server,
	// which are the ones a size bound and a rule set read.
	Uploads = map[string]bool{"STOR": true, "STOU": true, "APPE": true}
	// Secret are the verbs whose argument is a credential. A session
	// recording keeps the command and drops the argument: a recording
	// an operator cannot safely keep is one that gets turned off.
	Secret = map[string]bool{"PASS": true, "ACCT": true}
)

// Known is every verb this proxy is willing to relay. A verb outside it
// is refused: the whole point of terminating FTP is that the proxy
// knows what it is passing on, and a command whose effect it cannot
// name is a command it cannot hold to a policy.
var Known = map[string]bool{
	"USER": true, "PASS": true, "ACCT": true, "QUIT": true, "NOOP": true,
	"SYST": true, "FEAT": true, "OPTS": true, "TYPE": true, "MODE": true,
	"STRU": true, "PWD": true, "XPWD": true, "CDUP": true, "XCUP": true,
	"CWD": true, "XCWD": true, "PASV": true, "EPSV": true, "PORT": true,
	"EPRT": true, "RETR": true, "STOR": true, "STOU": true, "APPE": true,
	"DELE": true, "RNFR": true, "RNTO": true, "MKD": true, "XMKD": true,
	"RMD": true, "XRMD": true, "LIST": true, "NLST": true, "MLSD": true,
	"MLST": true, "SIZE": true, "MDTM": true, "STAT": true, "ABOR": true,
	"REST": true, "ALLO": true, "SITE": true, "HELP": true,
	"AUTH": true, "PBSZ": true, "PROT": true, "CCC": true,
}
