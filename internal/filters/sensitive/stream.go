package sensitive

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// ErrBlocked is the read error a streamed body ends with when the
// filter blocks it: the transfer is cut, since the head of the message
// has already been forwarded.
var ErrBlocked = errors.New("sensitive_data: body blocked")

// hold is how many bytes a streaming scan keeps back between chunks so a
// value split across two reads is still seen whole; values longer than
// this (a very long token) may be missed at a boundary.
const hold = 4096

// encodingOf returns the body's content encoding when the filter can
// decode it: "" for identity, one of gzip, deflate, br or zstd, and
// ok=false for anything else (or a partial body).
func encodingOf(h http.Header) (string, bool) {
	if h.Get("Content-Range") != "" {
		return "", false
	}
	enc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding")))
	switch enc {
	case "", "identity":
		return "", true
	case "gzip", "x-gzip":
		return "gzip", true
	case "deflate":
		return "deflate", true
	case "br":
		return "br", true
	case "zstd":
		return "zstd", true
	}
	return "", false
}

// decoder wraps r in the decompressor for enc.
func decoder(enc string, r io.Reader) (io.ReadCloser, error) {
	switch enc {
	case "gzip":
		return gzip.NewReader(r)
	case "deflate":
		// HTTP deflate is zlib wrapped in practice; a raw stream is rare
		// and refused here, which leaves the body unscanned.
		return zlib.NewReader(r)
	case "br":
		return io.NopCloser(brotli.NewReader(r)), nil
	case "zstd":
		d, err := zstd.NewReader(r, zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	}
	return io.NopCloser(r), nil
}

// decode decompresses data up to limit bytes; ok is false when the
// decoded body is larger than that.
func decode(enc string, data []byte, limit int64) ([]byte, bool, error) {
	rc, err := decoder(enc, bytes.NewReader(data))
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rc.Close() }()
	out, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, false, err
	}
	return out, int64(len(out)) <= limit, nil
}

// streamScanner scans a body as it flows, holding back the tail of each
// chunk until the next arrives. In mask mode the emitted bytes are the
// masked text; in block mode the first finding ends the stream with
// ErrBlocked.
type streamScanner struct {
	src       io.ReadCloser
	in        *instance
	direction string // request or response
	where     string
	mask      bool
	block     bool
	chunk     []byte
	pending   []byte
	out       []byte
	eof       bool
	err       error
	found     int
	closed    bool
}

func (s *streamScanner) Read(p []byte) (int, error) {
	for len(s.out) == 0 && s.err == nil && !s.eof {
		if s.chunk == nil {
			s.chunk = make([]byte, 32<<10)
		}
		n, err := s.src.Read(s.chunk)
		if n > 0 {
			s.pending = append(s.pending, s.chunk[:n]...)
		}
		switch {
		case errors.Is(err, io.EOF):
			s.eof = true
		case err != nil:
			s.err = err
		}
		s.flush(s.eof)
	}
	if len(s.out) > 0 {
		n := copy(p, s.out)
		s.out = s.out[n:]
		return n, nil
	}
	if s.err != nil {
		return 0, s.err
	}
	s.finish()
	return 0, io.EOF
}

// flush scans what can be emitted: everything on EOF, otherwise, once
// at least two holds are pending, all but the last hold bytes, so every
// scanned piece is at least hold bytes long whatever the source's read
// sizes.
func (s *streamScanner) flush(all bool) {
	var text []byte
	switch {
	case all:
		text, s.pending = s.pending, nil
	case len(s.pending) >= 2*hold:
		cut := len(s.pending) - hold
		text = s.pending[:cut]
		s.pending = append([]byte(nil), s.pending[cut:]...)
	default:
		return
	}
	if len(text) == 0 {
		return
	}
	scanned, f := s.in.g.scanText(string(text), s.direction == "request", s.mask)
	s.in.record(s.where, f)
	s.found += f.n
	if s.block && f.n > 0 {
		s.err = ErrBlocked
		s.in.blockedStream(s.direction)
		return
	}
	if s.mask {
		s.out = append(s.out, scanned...)
	} else {
		s.out = append(s.out, text...)
	}
}

// finish counts the outcome once the stream ended cleanly.
func (s *streamScanner) finish() {
	if s.closed {
		return
	}
	s.closed = true
	s.in.outcome(s.direction, s.found, s.mask)
}

func (s *streamScanner) Close() error {
	if !s.closed && s.err == nil {
		s.finish()
	}
	return s.src.Close()
}
