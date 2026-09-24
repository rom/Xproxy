// Package asciicast writes terminal recordings in the asciicast v2
// format: a JSON header line followed by one JSON array per event.
//
// The format is chosen because a recording nobody can play is a
// recording nobody reads. asciicast v2 is what asciinema records and
// plays, what asciinema-player renders in a browser, and what several
// other tools read; it is line oriented, so a recording cut short by a
// crash or a bound still plays up to where it stops, and it is text, so
// the usual tools work on it.
//
// What it is not is a transcript. A terminal session is a stream of
// control sequences, and what the person saw is what a terminal makes
// of them. The file holds the stream; reading it means replaying it.
package asciicast

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// Version is the format version written.
const Version = 2

// Header is the first line of a recording.
type Header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp,omitempty"`
	Title     string            `json:"title,omitempty"`
	Command   string            `json:"command,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// EnvEncoding is the header field that says how the event data is
// written, and EncodingBase64 is the one value it can take.
//
// A terminal session is text, so its events are written as the JSON
// strings they are. A protocol stream is not: a pixel, a length or a
// checksum is any byte at all, and JSON cannot hold a byte that is not
// valid UTF-8 -- it becomes the replacement character, which is
// irreversible. A recording of a graphical session written that way is a
// file nobody can decode afterwards, whatever player they write. So a
// recorder whose stream is binary says so in the header and writes the
// data base64, and every reader here decodes it. It is no longer a file
// an ordinary asciicast player can show, which is true of these
// recordings anyway: they need a player that speaks the protocol.
const (
	EnvEncoding    = "XPROXY_ENCODING"
	EncodingBase64 = "base64"
)

// Event kinds. Output is what the session printed, Input what was
// typed, Resize a new terminal size and Marker a note the recorder
// itself adds.
const (
	Output = "o"
	Input  = "i"
	Resize = "r"
	Marker = "m"
)

// Writer serialises events. It is safe for concurrent use: the two
// directions of a session are copied by different goroutines and both
// are recorded.
type Writer struct {
	mu    sync.Mutex
	w     io.Writer
	start time.Time
	// carry holds the bytes of a character that a read ended in the
	// middle of. Terminal output is read in whatever sizes the network
	// produced, so a multi-byte character is regularly split across two
	// of them; writing each half on its own would put two replacement
	// characters in the file where the session had one character.
	carry map[string][]byte
	err   error
	// b64 writes the data of o and i events as base64, for a stream of
	// bytes rather than of text. It comes from the header, so the file
	// says how to read itself.
	b64 bool
}

// NewWriter writes the header and returns a writer for the events.
// Times are measured from now, which is when the session started.
func NewWriter(w io.Writer, h Header) (*Writer, error) {
	h.Version = Version
	if h.Width <= 0 {
		h.Width = 80
	}
	if h.Height <= 0 {
		h.Height = 24
	}
	if h.Timestamp == 0 {
		h.Timestamp = time.Now().Unix()
	}
	line, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(append(line, '\n')); err != nil {
		return nil, err
	}
	return &Writer{w: w, start: time.Now(), carry: map[string][]byte{},
		b64: h.Env[EnvEncoding] == EncodingBase64}, nil
}

// Event records bytes of one kind. The data is the session's, not this
// package's: in a text recording it is written as the JSON string it is,
// and bytes that are not valid UTF-8 become the replacement character,
// which is the most a text format can say about them. In a binary
// recording -- one whose header names the base64 encoding -- it is
// written as base64 and nothing is lost, because a protocol stream has
// no character boundaries to preserve and no reader that wants them.
func (w *Writer) Event(kind string, data []byte) error {
	if w == nil || len(data) == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if w.b64 {
		return w.write(kind, base64.StdEncoding.EncodeToString(data))
	}
	if c := w.carry[kind]; len(c) > 0 {
		data = append(append([]byte(nil), c...), data...)
		w.carry[kind] = nil
	}
	use, rest := splitRune(data)
	if len(rest) > 0 {
		w.carry[kind] = append([]byte(nil), rest...)
	}
	if len(use) == 0 {
		return nil
	}
	return w.write(kind, string(use))
}

// Resized records a new terminal size, which a player uses to change
// the geometry mid-recording rather than clipping what follows.
func (w *Writer) Resized(cols, rows int) error {
	if w == nil || cols <= 0 || rows <= 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	return w.write(Resize, strconv.Itoa(cols)+"x"+strconv.Itoa(rows))
}

// Mark records a note of the recorder's own, which is how a file says
// something the session did not print: that it was cut at a bound, for
// instance.
func (w *Writer) Mark(text string) error {
	if w == nil || text == "" {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	return w.write(Marker, text)
}

// Flush writes out a character that the stream ended in the middle of,
// as the replacement character, so the last bytes of a session are not
// silently dropped by the carry.
func (w *Writer) Flush() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	for _, kind := range []string{Output, Input} {
		if c := w.carry[kind]; len(c) > 0 {
			w.carry[kind] = nil
			if err := w.write(kind, string(c)); err != nil {
				return err
			}
		}
	}
	return nil
}

// write emits one event line. json.Marshal does the escaping, which is
// the part that has to be right: a session can print anything, and a
// quote or a control character written raw would end the line early and
// make the rest of the recording unreadable.
func (w *Writer) write(kind, data string) error {
	text, err := json.Marshal(data)
	if err != nil {
		w.err = err
		return err
	}
	line := fmt.Sprintf("[%.6f, %q, %s]\n", time.Since(w.start).Seconds(), kind, text)
	if _, err := io.WriteString(w.w, line); err != nil {
		w.err = err
		return err
	}
	return nil
}

// splitRune returns the bytes that end on a character boundary and the
// bytes of a character the data stops in the middle of.
func splitRune(b []byte) (use, rest []byte) {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if !utf8.RuneStart(b[i]) {
			continue
		}
		if utf8.FullRune(b[i:]) {
			return b, nil
		}
		return b[:i], b[i:]
	}
	return b, nil
}
