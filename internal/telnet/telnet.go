// Package telnet reads the NVT protocol of RFC 854 and its options.
//
// Telnet is a byte stream with commands escaped into it. Everything
// that is not an IAC sequence is data; an IAC (255) begins a command,
// and IAC IAC is one literal 255. That is the whole of the framing,
// and it is why a proxy that does not parse it cannot tell a window
// size negotiation from the characters a person typed -- which it has
// to, both to record the session as it was seen and to decide which
// options a client may turn on.
//
// The parser is a state machine because a command can be split across
// reads: a two-byte DO arriving one byte per packet is ordinary on a
// slow link, and a subnegotiation is any length at all.
package telnet

import "fmt"

// The commands of RFC 854 section 2.
const (
	IAC  = 255 // interpret as command
	DONT = 254
	DO   = 253
	WONT = 252
	WILL = 251
	SB   = 250 // subnegotiation begins
	GA   = 249 // go ahead
	EL   = 248 // erase line
	EC   = 247 // erase character
	AYT  = 246 // are you there
	AO   = 245 // abort output
	IP   = 244 // interrupt process
	BRK  = 243 // break
	DM   = 242 // data mark
	NOP  = 241
	SE   = 240 // subnegotiation ends
)

// The options this proxy can name. An option outside this table is
// still parsed -- the framing does not depend on knowing it -- but a
// policy cannot say anything about it by name, so one that is not
// listed is refused rather than passed on: an option whose effect the
// proxy cannot name is one it cannot hold to a policy.
const (
	OptBinary       = 0  // RFC 856
	OptEcho         = 1  // RFC 857
	OptSuppressGA   = 3  // RFC 858
	OptStatus       = 5  // RFC 859
	OptTimingMark   = 6  // RFC 860
	OptTerminalType = 24 // RFC 1091
	OptEndOfRecord  = 25 // RFC 885
	OptNAWS         = 31 // RFC 1073, window size
	OptTerminalSpd  = 32 // RFC 1079
	OptFlowControl  = 33 // RFC 1372
	OptLinemode     = 34 // RFC 1184
	OptXDisplay     = 35 // RFC 1096
	OptEnviron      = 36 // RFC 1408
	OptAuth         = 37 // RFC 2941
	OptEncrypt      = 38 // RFC 2946
	OptNewEnviron   = 39 // RFC 1572
)

// optionNames is what an operator writes in a configuration.
var optionNames = map[byte]string{
	OptBinary: "binary", OptEcho: "echo", OptSuppressGA: "suppress-go-ahead",
	OptStatus: "status", OptTimingMark: "timing-mark", OptTerminalType: "terminal-type",
	OptEndOfRecord: "end-of-record", OptNAWS: "naws", OptTerminalSpd: "terminal-speed",
	OptFlowControl: "flow-control", OptLinemode: "linemode", OptXDisplay: "x-display",
	OptEnviron: "environ", OptAuth: "authentication", OptEncrypt: "encryption",
	OptNewEnviron: "new-environ",
}

var optionByName = func() map[string]byte {
	m := make(map[string]byte, len(optionNames))
	for b, n := range optionNames {
		m[n] = b
	}
	return m
}()

// OptionName is the name of an option, or its number when the proxy
// has no name for it.
func OptionName(o byte) string {
	if n, ok := optionNames[o]; ok {
		return n
	}
	return fmt.Sprintf("option-%d", o)
}

// OptionByName looks a name up, for reading a configuration.
func OptionByName(s string) (byte, bool) {
	o, ok := optionByName[s]
	return o, ok
}

// Named reports whether this proxy has a name for an option, which is
// what a policy can speak about.
func Named(o byte) bool { _, ok := optionNames[o]; return ok }

// CommandName is a command's name, for logs.
func CommandName(c byte) string {
	switch c {
	case DO:
		return "DO"
	case DONT:
		return "DONT"
	case WILL:
		return "WILL"
	case WONT:
		return "WONT"
	case SB:
		return "SB"
	case SE:
		return "SE"
	case GA:
		return "GA"
	case NOP:
		return "NOP"
	case DM:
		return "DM"
	case BRK:
		return "BRK"
	case IP:
		return "IP"
	case AO:
		return "AO"
	case AYT:
		return "AYT"
	case EC:
		return "EC"
	case EL:
		return "EL"
	case IAC:
		return "IAC"
	}
	return fmt.Sprintf("command-%d", c)
}

// Kind classifies what the parser found.
type Kind int

const (
	// Data is ordinary bytes, with IAC IAC already reduced to one 255.
	Data Kind = iota
	// Negotiate is WILL, WONT, DO or DONT and its option.
	Negotiate
	// Subneg is a complete subnegotiation: its option and its payload,
	// with IAC IAC reduced.
	Subneg
	// Command is one of the commands that carry no option.
	Command
)

// Event is one thing the parser found. Data and Payload alias the
// parser's own buffer and are valid until the next call to Feed, which
// is the same contract the rest of this proxy's readers keep.
type Event struct {
	Kind Kind
	// Cmd is WILL, WONT, DO or DONT for Negotiate, and the command
	// byte for Command.
	Cmd byte
	// Opt is the option for Negotiate and Subneg.
	Opt byte
	// Data is the bytes for Data, and the payload for Subneg.
	Data []byte
}

// state is where the parser is in a command.
type state int

const (
	stData state = iota
	stIAC
	stOption     // after WILL/WONT/DO/DONT, waiting for the option
	stSubOpt     // after SB, waiting for the option
	stSubData    // inside a subnegotiation payload
	stSubDataIAC // an IAC inside a subnegotiation payload
)

// Parser reads one direction of a telnet stream.
type Parser struct {
	st  state
	cmd byte
	opt byte
	// sub accumulates a subnegotiation payload. It is bounded: a peer
	// that sends IAC SB and then never sends IAC SE would otherwise
	// grow it without end, and there is no subnegotiation this proxy
	// passes on that is anywhere near this size.
	sub    []byte
	maxSub int
	// data collects the run of ordinary bytes between commands, so a
	// caller gets one Data event per Feed rather than one per byte.
	data []byte
}

// MaxSubnegotiation is the default bound on one subnegotiation.
const MaxSubnegotiation = 4096

// NewParser returns a parser. maxSub bounds one subnegotiation; zero
// takes MaxSubnegotiation.
func NewParser(maxSub int) *Parser {
	if maxSub <= 0 {
		maxSub = MaxSubnegotiation
	}
	return &Parser{maxSub: maxSub, data: make([]byte, 0, 4096)}
}

// ErrSubnegotiationTooLong is returned when a peer's subnegotiation
// passes the bound.
var ErrSubnegotiationTooLong = fmt.Errorf("telnet: subnegotiation longer than the bound")

// Feed parses b and calls emit for each event, in order. Emit's error
// stops the parse and is returned. What is left half-read stays in the
// parser for the next call.
func (p *Parser) Feed(b []byte, emit func(Event) error) error {
	p.data = p.data[:0]
	flush := func() error {
		if len(p.data) == 0 {
			return nil
		}
		err := emit(Event{Kind: Data, Data: p.data})
		p.data = p.data[:0]
		return err
	}
	for _, c := range b {
		switch p.st {
		case stData:
			if c == IAC {
				p.st = stIAC
				continue
			}
			p.data = append(p.data, c)
		case stIAC:
			switch c {
			case IAC:
				// A literal 255 in the data.
				p.data = append(p.data, IAC)
				p.st = stData
			case WILL, WONT, DO, DONT:
				p.cmd, p.st = c, stOption
			case SB:
				p.st = stSubOpt
			default:
				if err := flush(); err != nil {
					return err
				}
				if err := emit(Event{Kind: Command, Cmd: c}); err != nil {
					return err
				}
				p.st = stData
			}
		case stOption:
			if err := flush(); err != nil {
				return err
			}
			if err := emit(Event{Kind: Negotiate, Cmd: p.cmd, Opt: c}); err != nil {
				return err
			}
			p.st = stData
		case stSubOpt:
			p.opt, p.sub, p.st = c, p.sub[:0], stSubData
		case stSubData:
			if c == IAC {
				p.st = stSubDataIAC
				continue
			}
			if len(p.sub) >= p.maxSub {
				return ErrSubnegotiationTooLong
			}
			p.sub = append(p.sub, c)
		case stSubDataIAC:
			switch c {
			case IAC:
				if len(p.sub) >= p.maxSub {
					return ErrSubnegotiationTooLong
				}
				p.sub = append(p.sub, IAC)
				p.st = stSubData
			case SE:
				if err := flush(); err != nil {
					return err
				}
				if err := emit(Event{Kind: Subneg, Opt: p.opt, Data: p.sub}); err != nil {
					return err
				}
				p.st = stData
			default:
				// An IAC inside a subnegotiation followed by anything
				// else is not something RFC 854 defines. Ending the
				// subnegotiation and reading the byte as a command is
				// what an implementation that guesses would do, and
				// guessing is how a proxy and a target come to disagree
				// about where a command ends.
				return fmt.Errorf("telnet: IAC %s inside a subnegotiation", CommandName(c))
			}
		}
	}
	return flush()
}

// Negotiation renders WILL, WONT, DO or DONT.
func Negotiation(cmd, opt byte) []byte { return []byte{IAC, cmd, opt} }

// EscapeData renders data with every 255 doubled, which is what puts
// arbitrary bytes into a telnet stream without one of them becoming a
// command.
func EscapeData(b []byte) []byte {
	n := 0
	for _, c := range b {
		if c == IAC {
			n++
		}
	}
	if n == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+n)
	for _, c := range b {
		out = append(out, c)
		if c == IAC {
			out = append(out, IAC)
		}
	}
	return out
}

// Subnegotiation renders IAC SB opt payload IAC SE.
func Subnegotiation(opt byte, payload []byte) []byte {
	out := []byte{IAC, SB, opt}
	out = append(out, EscapeData(payload)...)
	return append(out, IAC, SE)
}

// Refusal is the answer that declines what a peer offered or asked
// for: a WILL is declined with DONT, a DO with WONT. A command that is
// not a negotiation has no refusal, and returns false.
func Refusal(cmd, opt byte) ([]byte, bool) {
	switch cmd {
	case WILL, WONT:
		return Negotiation(DONT, opt), true
	case DO, DONT:
		return Negotiation(WONT, opt), true
	}
	return nil, false
}

// NAWS reads a window size subnegotiation (RFC 1073): two 16 bit
// values, width then height.
func NAWS(payload []byte) (cols, rows int, ok bool) {
	if len(payload) < 4 {
		return 0, 0, false
	}
	return int(payload[0])<<8 | int(payload[1]), int(payload[2])<<8 | int(payload[3]), true
}
