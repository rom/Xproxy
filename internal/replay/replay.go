// Package replay reads a session recording and turns it into something
// a person can look at.
//
// The proxy records three shapes of session into one container
// (internal/asciicast): a terminal, which a player writes to a terminal;
// an RFB stream, which is a picture nobody can see without decoding it;
// and an RDP stream, whose graphics this project deliberately does not
// decode. Until now the last two were files an operator could keep and
// not read, and "a decoder can be written against this file afterwards"
// was a promise rather than a program. This package is the program.
//
// Two rules shape it. It never executes what it reads: a recording is
// bytes a client and a server chose, so every path here is a parser with
// bounds and the terminal path filters escape sequences through
// internal/termsafe rather than handing them to the reviewer's terminal.
// And it says what it could not decode rather than showing a plausible
// picture: a rectangle in an encoding this package does not implement
// leaves the framebuffer alone and is counted, because an investigation
// that cannot tell "nothing happened there" from "we did not read it" is
// worse off than one told the truth.
package replay

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/asciicast"
	"github.com/rom/xproxy/internal/recenc"
)

// Kind is what a recording holds, taken from the header the proxy wrote
// rather than guessed from the bytes.
type Kind string

const (
	// KindTerminal is a session of text: ssh, telnet, ftp.
	KindTerminal Kind = "terminal"
	// KindRFB is the server-to-client stream of a VNC session.
	KindRFB Kind = "rfb"
	// KindRDP is the desktop-to-client stream of an RDP session.
	KindRDP Kind = "rdp"
)

// Event is one recorded event, with the direction resolved.
type Event struct {
	At    time.Duration
	Kind  string // asciicast.Output, Input, Resize or Marker
	Data  []byte
	Index int
}

// Recording is an opened file: its header, what it holds, and the events
// in order.
type Recording struct {
	Header asciicast.Header
	Kind   Kind
	// Path is the file, for the messages.
	Path string

	rd *asciicast.Reader
	f  *os.File
	n  int
}

// MaxEvents bounds how many events one recording is read for. A file the
// proxy wrote is bounded by max_file_bytes, but a file handed to this
// tool is whatever somebody has on disk.
const MaxEvents = 5_000_000

// ErrEncrypted says the file is an encrypted recording and no key was
// given. It is a different answer from "this file makes no sense": the
// caller has the right file and is missing the key.
var ErrEncrypted = errors.New("the recording is encrypted: give the key it was written under")

// Open reads the header and decides what the file holds. An encrypted
// recording returns ErrEncrypted rather than a parse error.
func Open(path string) (*Recording, error) { return OpenKeyed(path, nil) }

// OpenKeyed opens a recording that may be encrypted at rest. A nil key
// reads a plain recording as before; a key is used only where the file is
// one, so a caller may pass one it does not need.
func OpenKeyed(path string, key []byte) (*Recording, error) {
	f, err := os.Open(path) //nolint:gosec // the recording an operator asked to read is the argument
	if err != nil {
		return nil, err
	}
	src, err := Plaintext(f, key)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	rd, err := asciicast.NewReader(src)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Recording{Header: rd.Header, Kind: kindOf(rd.Header), Path: path, rd: rd, f: f}, nil
}

// Plaintext returns the recording's own bytes, decrypting where the file
// is an encrypted one. It is exported because xproxyctl reads recordings
// through internal/asciicast directly and needs the same decision made
// the same way.
//
// The decision is the magic at the start of the file and not the name:
// a file renamed by whoever archived it is still what it is.
func Plaintext(r io.Reader, key []byte) (io.Reader, error) {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(recenc.Magic))
	switch {
	case err != nil && !errors.Is(err, io.EOF):
		return nil, err
	case !recenc.Looks(head):
		return br, nil
	case len(key) == 0:
		return nil, ErrEncrypted
	}
	return recenc.NewReader(br, key)
}

// Close releases the file.
func (r *Recording) Close() error { return r.f.Close() }

// kindOf reads the protocol out of the header the recorder wrote. A
// recording with no protocol named is a terminal, which is what every
// recording was before the graphical gates existed.
func kindOf(h asciicast.Header) Kind {
	switch h.Env["XPROXY_PROTOCOL"] {
	case "rfb":
		return KindRFB
	case "rdp":
		return KindRDP
	}
	return KindTerminal
}

// Next returns the next event.
func (r *Recording) Next() (Event, error) {
	if r.n >= MaxEvents {
		return Event{}, fmt.Errorf("replay: more than %d events in %s", MaxEvents, r.Path)
	}
	ev, err := r.rd.Next()
	if err != nil {
		return Event{}, err
	}
	r.n++
	return Event{At: ev.At, Kind: ev.Kind, Data: []byte(ev.Data), Index: r.n}, nil
}

// Each calls fn for every event until the end of the file.
func (r *Recording) Each(fn func(Event) error) error {
	for {
		ev, err := r.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
}

// PixelFormat reads the sixteen octets of RFC 6143 section 7.4 out of
// the header, which the vnc gateway writes as hex so a player never has
// to guess. A recording without it is read with the format below, and
// the caller is told.
func (r *Recording) PixelFormat() (pf [16]byte, ok bool) {
	s := r.Header.Env["XPROXY_PIXEL_FORMAT"]
	if len(s) != 32 {
		return DefaultPixelFormat, false
	}
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return DefaultPixelFormat, false
		}
		pf[i] = byte(v)
	}
	return pf, true
}

// DefaultPixelFormat is 32 bits, little endian, true colour, 8 bits each
// of red, green and blue at the usual shifts: what a viewer asks for
// unless it says otherwise. It is the assumption a recording without a
// recorded format is read under, and the reader says so.
var DefaultPixelFormat = [16]byte{
	32, 24, 0, 1, // bits per pixel, depth, big endian, true colour
	0, 255, 0, 255, 0, 255, // red, green, blue maxima
	16, 8, 0, // shifts
	0, 0, 0, // padding
}

// Describe is the one line a tool prints before anything else: what this
// file is, who it was, and how long it ran.
func (r *Recording) Describe(events int, span time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", r.Path, r.Kind)
	if t := r.Header.Title; t != "" {
		fmt.Fprintf(&b, " %q", t)
	}
	if r.Kind != KindTerminal && r.Header.Width > 0 {
		fmt.Fprintf(&b, " %dx%d", r.Header.Width, r.Header.Height)
	}
	if v := r.Header.Env["XPROXY_RFB"]; v != "" {
		fmt.Fprintf(&b, " %s", v)
	}
	if v := r.Header.Env["XPROXY_SECURITY"]; v != "" {
		fmt.Fprintf(&b, " security=%s", v)
	}
	fmt.Fprintf(&b, ", %d events over %s", events, span.Round(time.Millisecond))
	return b.String()
}
