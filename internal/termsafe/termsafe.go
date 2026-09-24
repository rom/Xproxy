// Package termsafe renders a recorded terminal session without handing
// the reviewer's terminal to whoever was recorded.
//
// A session recording is the bytes the session showed, which is what
// makes it a useful record and what makes replaying it dangerous. A
// terminal is an interpreter, and those bytes are a program for it. Some
// of what it will do on request reaches outside the window the replay is
// drawn in:
//
//   - OSC 52 writes the reviewer's clipboard. A recorded session can put
//     anything there and wait for it to be pasted.
//   - OSC 0 and 2 set the window title, OSC 7 the working directory, OSC
//     8 a hyperlink whose text and target need not agree.
//   - The device reports -- DA, DSR, DECRQSS, the window manipulation
//     sequences -- make the terminal *write back* on its input. In a
//     shell, what a terminal writes on its input is a command line. This
//     is the one that turns reading a log into running one.
//   - CSI t resizes and moves the reviewer's window; the mouse and focus
//     reporting modes make it send on every movement.
//   - Bidirectional overrides and zero width characters make what is on
//     the screen disagree with what is in the file, which is the whole
//     of the Trojan Source class.
//
// So a replay path filters. Plain keeps the text and drops every
// sequence, which is what somebody reading a session wants. Safe keeps
// the sequences that draw inside the window -- colour, cursor movement,
// erasing -- and writes the rest out in a form a terminal will not act
// on, so the reviewer sees that the session sent one rather than being
// quietly subjected to it or quietly not told.
//
// Nothing here is a bound on what may be recorded. The recording holds
// what happened, because a record an operator cannot trust is not a
// record; this is what stands between the record and the person reading
// it.
package termsafe

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Mode is how much of a session's own drawing survives.
type Mode int

const (
	// Plain keeps text, newlines and tabs and drops every escape
	// sequence: what the session said, with none of how it looked. A
	// carriage return becomes a newline and a backspace is dropped,
	// because both are ways to overwrite what was already shown.
	Plain Mode = iota
	// Safe keeps the sequences that draw inside the window and encodes
	// the ones that reach outside it.
	Safe
)

// maxSequence bounds a sequence in progress. A real one is a few dozen
// bytes; an OSC 52 with a payload is the longest, and a kilobyte of it
// is already a clipboard nobody typed. Past the bound the filter gives
// up on the sequence, emits what it has in encoded form and returns to
// text, which is the behaviour that cannot be used to make it hold an
// unbounded amount of somebody else's session.
const maxSequence = 4096

// state is where the escape grammar has got to.
type state int

const (
	ground state = iota
	afterESC
	inCSI
	inString  // OSC, DCS, APC, PM or SOS, until ST or BEL
	stringESC // an ESC inside a string, which may begin the ST
	charset   // a character set designator, whose second byte follows
)

// Filter rewrites a terminal stream on its way to a reviewer.
//
// It is a state machine rather than a search for patterns because a
// sequence arrives in whatever pieces the file was written in, and one
// split across two writes is exactly the one a filter that matched on
// whole strings would pass through.
type Filter struct {
	w    io.Writer
	mode Mode
	st   state
	// seq is the sequence being read, from its ESC onward.
	seq []byte
	// err is the first write error, after which everything is dropped.
	err error
}

// New returns a filter writing to w.
func New(w io.Writer, m Mode) *Filter { return &Filter{w: w, mode: m} }

// Write filters p. It always reports len(p) consumed, because what the
// filter removed is not a short write to its caller.
func (f *Filter) Write(p []byte) (int, error) {
	for i := 0; i < len(p); {
		i += f.step(p[i:])
		if f.err != nil {
			return len(p), f.err
		}
	}
	return len(p), nil
}

// Flush deals with a sequence the stream ended in the middle of, which
// is either a truncated recording or a peer that meant to leave one
// there.
func (f *Filter) Flush() error {
	if f.st != ground && len(f.seq) > 0 {
		f.encode(f.seq)
		f.seq = f.seq[:0]
	}
	f.st = ground
	return f.err
}

// step advances the machine over at least one byte and reports how many
// it consumed: one, except for a whole multi-byte character in text.
func (f *Filter) step(rest []byte) int {
	b := rest[0]
	switch f.st {
	case ground:
		return f.ground(b, rest)
	case afterESC:
		f.afterESC(b)
	case inCSI:
		f.csi(b)
	case inString:
		f.str(b)
	case stringESC:
		f.stringESC(b)
	case charset:
		// The second byte of a designator, which draws nothing outside
		// the window.
		f.seq = append(f.seq, b)
		f.pass(f.seq)
		f.seq, f.st = f.seq[:0], ground
	}
	return 1
}

func (f *Filter) ground(b byte, rest []byte) int {
	switch {
	case b == 0x1b:
		f.seq = append(f.seq[:0], b)
		f.st = afterESC
	case b == '\n', b == '\t':
		f.out([]byte{b})
	case b == '\r':
		if f.mode == Plain {
			// A carriage return with no newline overwrites the line that
			// is already there, which is how text is hidden from a
			// reader rather than from a terminal.
			f.out([]byte{'\n'})
			break
		}
		f.out([]byte{b})
	case b == 0x08:
		if f.mode == Safe {
			f.out([]byte{b})
		}
	case b < 0x20 || b == 0x7f:
		// Every other C0 byte and DEL: a bell, a form feed, a shift
		// into the line drawing set. None of them is text.
		f.encode([]byte{b})
	case b < 0x80:
		f.out([]byte{b})
	default:
		return f.character(rest)
	}
	return 1
}

// character reads one multi-byte character and decides about it. This is
// where the ones that make the screen disagree with the file are caught:
// a bidirectional override, a zero width joiner, a byte order mark in
// the middle of a line.
func (f *Filter) character(rest []byte) int {
	r, size := utf8.DecodeRune(rest)
	if r == utf8.RuneError && size == 1 {
		// Not UTF-8 at all. It is encoded rather than passed on, since a
		// terminal in another encoding may act on it.
		f.encode(rest[:1])
		return 1
	}
	switch {
	case r >= 0x80 && r <= 0x9f:
		// The C1 controls, whose 8 bit forms a terminal may still act
		// on: 0x9b is CSI.
		f.encodeRune(r)
	case deceptive(r):
		f.encodeRune(r)
	default:
		f.out(rest[:size])
	}
	return size
}

// deceptive reports whether a character changes what the screen shows
// without being visible itself.
func deceptive(r rune) bool {
	switch {
	case r >= 0x202a && r <= 0x202e: // the bidirectional embeddings and overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // the bidirectional isolates
		return true
	case r >= 0x200b && r <= 0x200f: // zero width spaces, joiners and marks
		return true
	case r == 0x061c: // arabic letter mark
		return true
	case r == 0xfeff: // a byte order mark anywhere but the start
		return true
	case r == 0x2028 || r == 0x2029: // line and paragraph separators
		return true
	}
	return false
}

func (f *Filter) afterESC(b byte) {
	f.seq = append(f.seq, b)
	switch b {
	case '[':
		f.st = inCSI
	case ']', 'P', '^', '_', 'X':
		// OSC, DCS, PM, APC, SOS. Every one of them is a string whose
		// meaning is a vendor's, and the two that matter most -- the
		// clipboard and the title -- are OSC.
		f.st = inString
	case '(', ')', '*', '+', '-', '.', '/':
		f.st = charset
	case '7', '8', '=', '>', 'M', 'D', 'E', 'H', 'c':
		// Save and restore the cursor, the keypad modes, index and
		// reverse index, the tab stop, and a full reset. All of them
		// act on the window and nothing else.
		f.pass(f.seq)
		f.seq, f.st = f.seq[:0], ground
	default:
		f.encode(f.seq)
		f.seq, f.st = f.seq[:0], ground
	}
	f.bound()
}

func (f *Filter) csi(b byte) {
	f.seq = append(f.seq, b)
	// Parameter and intermediate bytes; the final byte is 0x40 to 0x7e.
	if b >= 0x30 && b <= 0x3f || b >= 0x20 && b <= 0x2f {
		f.bound()
		return
	}
	if b >= 0x40 && b <= 0x7e {
		if csiSafe(f.seq) {
			f.pass(f.seq)
		} else {
			f.encode(f.seq)
		}
		f.seq, f.st = f.seq[:0], ground
		return
	}
	// Not a CSI byte at all: the sequence was never one.
	f.encode(f.seq)
	f.seq, f.st = f.seq[:0], ground
}

func (f *Filter) str(b byte) {
	f.seq = append(f.seq, b)
	switch b {
	case 0x07: // BEL ends an OSC
		f.encode(f.seq)
		f.seq, f.st = f.seq[:0], ground
	case 0x1b:
		f.st = stringESC
	default:
		f.bound()
	}
}

func (f *Filter) stringESC(b byte) {
	f.seq = append(f.seq, b)
	if b == '\\' { // ST
		f.encode(f.seq)
		f.seq, f.st = f.seq[:0], ground
		return
	}
	// An ESC inside a string that was not an ST: still the string.
	f.st = inString
	f.bound()
}

// bound gives up on a sequence that has outgrown anything real.
func (f *Filter) bound() {
	if len(f.seq) < maxSequence {
		return
	}
	f.encode(f.seq)
	f.seq, f.st = f.seq[:0], ground
}

// out writes bytes the filter accepted.
func (f *Filter) out(b []byte) {
	if f.err != nil {
		return
	}
	if _, err := f.w.Write(b); err != nil {
		f.err = err
	}
}

// pass writes a sequence the filter accepted, or drops it in Plain: the
// point of Plain is that nothing draws.
func (f *Filter) pass(b []byte) {
	if f.mode == Plain {
		return
	}
	f.out(b)
}

// encode writes a sequence in a form no terminal acts on. In Plain it is
// dropped instead, because somebody reading a session wants the text and
// not a transcript of its escape sequences.
//
// The form is deliberately the one a person can read back and recognise:
// ESC as \e, other control bytes as \xNN, printable bytes as
// themselves. Nothing in it is an escape, which is the property that
// matters -- an encoding that still contained one would be a longer way
// of forwarding the attack.
func (f *Filter) encode(b []byte) {
	if f.mode == Plain {
		return
	}
	var out strings.Builder
	out.Grow(len(b) * 2)
	for _, c := range b {
		switch {
		case c == 0x1b:
			out.WriteString(`\e`)
		case c < 0x20 || c == 0x7f || c >= 0x80:
			fmt.Fprintf(&out, `\x%02x`, c)
		case c == '\\':
			out.WriteString(`\\`)
		default:
			out.WriteByte(c)
		}
	}
	f.out([]byte(out.String()))
}

// encodeRune writes one character in the form a person can look up.
func (f *Filter) encodeRune(r rune) {
	if f.mode == Plain {
		return
	}
	f.out([]byte(fmt.Sprintf(`\u%04x`, r)))
}

// csiSafe reports whether a CSI sequence only draws inside the window.
//
// The distinction is not how dangerous a sequence looks but whether it
// can reach outside the replay: the reviewer's clipboard, their window
// geometry, their title bar, or -- the one that matters most -- their
// terminal's input. A sequence the terminal answers puts bytes on the
// input of whatever is reading it, and in a shell that is a command
// line.
func csiSafe(seq []byte) bool {
	if len(seq) < 3 {
		return false
	}
	final := seq[len(seq)-1]
	params := seq[2 : len(seq)-1]
	switch final {
	// Cursor movement, positioning, scrolling and tab stops.
	case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'Z', 'd', 'e', 'f', 'a', 'S', 'T':
		return plainParams(params)
	// Erasing and editing what is on the screen.
	case 'J', 'K', 'L', 'M', 'P', 'X', '@':
		return plainParams(params)
	// Colour and attributes, the scrolling region, saving and restoring
	// the cursor.
	case 'm', 'r', 's', 'u':
		return plainParams(params)
	// The mode sets. A private one is read out below, because some of
	// them make the terminal send rather than draw.
	case 'h', 'l':
		return modeSafe(params)
	}
	// Everything else, which is where the reports live: c (device
	// attributes), n (device status), t (window manipulation), q with an
	// intermediate (DECRQSS), p (request mode). Each of them is answered
	// by the terminal on its own input.
	return false
}

// plainParams reports whether a parameter string is only digits and
// separators -- no private marker, which is what distinguishes a
// standard sequence from a vendor's.
func plainParams(params []byte) bool {
	for _, c := range params {
		if (c < '0' || c > '9') && c != ';' && c != ':' {
			return false
		}
	}
	return true
}

// The private modes a replay may set, by number. Each one changes how
// the window is drawn. What is not here is what makes the terminal
// *send*: the mouse reporting modes (1000 to 1006, 1015, 1016), focus
// reporting (1004) and bracketed paste (2004) all make a terminal write
// on its input when the reviewer moves a mouse, changes window or
// pastes, which during a replay is noise at best and a way to get bytes
// into a shell at worst.
var safeModes = map[string]bool{
	"1":    true, // application cursor keys
	"4":    true, // insert mode
	"5":    true, // reverse video
	"6":    true, // origin mode
	"7":    true, // auto wrap
	"12":   true, // cursor blink
	"25":   true, // cursor visibility
	"47":   true, // the old alternate screen
	"1047": true,
	"1048": true,
	"1049": true, // the alternate screen and the cursor with it
	"2026": true, // synchronised output
}

// modeSafe reads a mode set or reset. The standard modes (no "?") only
// change how text is laid out; the private ones are checked by number.
func modeSafe(params []byte) bool {
	if len(params) == 0 {
		return true
	}
	if params[0] != '?' {
		return plainParams(params)
	}
	for _, n := range strings.Split(string(params[1:]), ";") {
		if !safeModes[n] {
			return false
		}
	}
	return true
}

// Filtered returns s with the same policy applied, for the places that
// hold a whole string rather than a stream: a log field, a session name,
// a title a reviewer is shown.
func Filtered(s string, m Mode) string {
	var out strings.Builder
	f := New(&out, m)
	_, _ = f.Write([]byte(s))
	_ = f.Flush()
	return out.String()
}
