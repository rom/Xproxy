package asciicast

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Reading a recording back.
//
// Nothing in the proxy reads these files; an operator does, and what an
// operator has otherwise is a player that writes the recorded bytes
// straight to their terminal. That is a session's own output
// interpreted by the reviewer's terminal, which is the attack this
// reader exists to make avoidable: with the events in hand the bytes can
// be filtered on the way out. See internal/termsafe.

// maxLine bounds one event line. The writer splits its own output, so a
// line this long is not one this project wrote.
const maxLine = 8 << 20

// Event is one line of a recording.
type Event struct {
	// At is when it happened, from the start of the session.
	At time.Duration
	// Kind is Output, Input, Resize or Marker.
	Kind string
	// Data is the bytes the session carried, or the text of a marker, or
	// the "COLSxROWS" of a resize.
	Data string
}

// Reader reads a recording's header and then its events.
type Reader struct {
	// Header is the first line, read by NewReader.
	Header Header
	sc     *bufio.Scanner
	n      int
	// b64 decodes the data of o and i events, for a recording of a
	// protocol stream. The header says which kind of file this is.
	b64 bool
}

// NewReader reads the header. A file whose first line is not one is
// refused here rather than producing events nobody can place.
func NewReader(r io.Reader) (*Reader, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("asciicast: the file is empty")
	}
	var h Header
	if err := json.Unmarshal(sc.Bytes(), &h); err != nil {
		return nil, fmt.Errorf("asciicast: the first line is not a header: %w", err)
	}
	if h.Version != Version {
		return nil, fmt.Errorf("asciicast: version %d, expected %d", h.Version, Version)
	}
	return &Reader{Header: h, sc: sc, b64: h.Env[EnvEncoding] == EncodingBase64}, nil
}

// Next returns the next event, or io.EOF at the end.
//
// A line that does not parse ends the reading with an error naming which
// one, rather than being skipped: a recording is a record, and a reader
// that quietly dropped part of one would be worse than one that stopped.
func (r *Reader) Next() (Event, error) {
	for {
		if !r.sc.Scan() {
			if err := r.sc.Err(); err != nil {
				return Event{}, err
			}
			return Event{}, io.EOF
		}
		r.n++
		line := r.sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var raw []any
		if err := json.Unmarshal(line, &raw); err != nil {
			return Event{}, fmt.Errorf("asciicast: line %d: %w", r.n+1, err)
		}
		if len(raw) != 3 {
			return Event{}, fmt.Errorf("asciicast: line %d: %d fields, want 3", r.n+1, len(raw))
		}
		at, ok := raw[0].(float64)
		if !ok {
			return Event{}, fmt.Errorf("asciicast: line %d: the time is not a number", r.n+1)
		}
		kind, ok := raw[1].(string)
		if !ok {
			return Event{}, fmt.Errorf("asciicast: line %d: the kind is not a string", r.n+1)
		}
		data, ok := raw[2].(string)
		if !ok {
			return Event{}, fmt.Errorf("asciicast: line %d: the data is not a string", r.n+1)
		}
		if r.b64 && (kind == Output || kind == Input) {
			// A binary recording's data is base64. A line that is not
			// decodable is a damaged file, and saying so is better than
			// handing a caller bytes it never held.
			b, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return Event{}, fmt.Errorf("asciicast: line %d: the data is not base64: %w", r.n+1, err)
			}
			data = string(b)
		}
		return Event{At: time.Duration(at * float64(time.Second)), Kind: kind, Data: data}, nil
	}
}
