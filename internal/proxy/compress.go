package proxy

import (
	"bufio"
	"compress/gzip"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/rom/xproxy/internal/config"
)

// encoder is what the three content encodings have in common.
type encoder interface {
	io.WriteCloser
	Flush() error
	Reset(w io.Writer)
}

// compressPolicy is the compiled compression section for one route.
type compressPolicy struct {
	encodings []string // server preference order
	level     int      // gzip
	brLevel   int
	zstdLevel int
	minBytes  int
	types     map[string]bool // media types without parameters
	pools     map[string]*sync.Pool
}

func newCompressPolicy(c *config.Compression) *compressPolicy {
	p := &compressPolicy{encodings: c.Encodings, level: c.Level, brLevel: 4, zstdLevel: c.ZstdLevel, minBytes: c.MinBytes,
		types: make(map[string]bool, len(c.Types)), pools: map[string]*sync.Pool{}}
	if c.BrotliLevel != nil {
		p.brLevel = *c.BrotliLevel
	}
	if len(p.encodings) == 0 {
		p.encodings = []string{"gzip"}
	}
	for _, t := range c.Types {
		p.types[strings.ToLower(t)] = true
	}
	for _, e := range p.encodings {
		p.pools[e] = &sync.Pool{}
	}
	return p
}

// writer returns a pooled encoder for enc writing to w.
func (p *compressPolicy) writer(enc string, w io.Writer) encoder {
	pool := p.pools[enc]
	if pool != nil {
		if e, ok := pool.Get().(encoder); ok {
			e.Reset(w)
			return e
		}
	}
	switch enc {
	case "br":
		return brotli.NewWriterLevel(w, p.brLevel)
	case "zstd":
		z, _ := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.EncoderLevel(p.zstdLevel)), zstd.WithEncoderConcurrency(1)) // options validated
		return z
	default:
		gz, _ := gzip.NewWriterLevel(w, p.level) // level validated
		return gz
	}
}

// release returns an encoder to its pool.
func (p *compressPolicy) release(enc string, e encoder) {
	e.Reset(nil)
	if pool := p.pools[enc]; pool != nil {
		pool.Put(e)
	}
}

// negotiate picks the content encoding for r: the acceptable encoding
// with the highest quality, ties broken by the server's order; "" when
// the client accepts none of the offered ones.
func (p *compressPolicy) negotiate(r *http.Request) string {
	q := acceptEncodings(r)
	if len(q) == 0 {
		return ""
	}
	best, bestQ := "", 0.0
	for _, e := range p.encodings {
		v, ok := q[e]
		if !ok {
			if v, ok = q["*"]; !ok {
				continue
			}
		}
		if v > bestQ {
			best, bestQ = e, v
		}
	}
	return best
}

// acceptEncodings parses Accept-Encoding into encoding to quality
// (x-gzip counts as gzip); a missing header yields nil.
func acceptEncodings(r *http.Request) map[string]float64 {
	ae := r.Header.Get("Accept-Encoding")
	if ae == "" {
		return nil
	}
	out := map[string]float64{}
	for _, part := range strings.Split(ae, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if name == "x-gzip" {
			name = "gzip"
		}
		q := 1.0
		for _, kv := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					q = f
				}
			}
		}
		out[name] = q
	}
	return out
}

func (p *compressPolicy) eligibleType(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return p.types[mt]
}

// wantsGzip reports whether the client accepts gzip (listed, or "*",
// with a non-zero quality).
func wantsGzip(r *http.Request) bool {
	q := acceptEncodings(r)
	if v, ok := q["gzip"]; ok {
		return v > 0
	}
	return q["*"] > 0
}

// compressWriter compresses eligible responses with gzip. The decision is
// made when the header is committed: the status must carry a body, no
// encoding or range may be present, `no-transform` is honoured, the media
// type must be listed and a known length must reach min_bytes. Without a
// known length the body is held up to min_bytes before deciding, and a
// flush decides at once (streamed responses are compressed when the type
// matches). Vary: Accept-Encoding is added for every eligible type so
// caches keep the variants apart, and a strong ETag becomes weak.
type compressWriter struct {
	http.ResponseWriter
	pol       *compressPolicy
	status    int
	committed bool // header sent to the underlying writer
	pending   bool // eligible but undecided (unknown length)
	compress  bool
	encoding  string // negotiated content encoding
	gz        encoder
	buf       []byte
	raw       int64
	hijacked  bool
	closed    bool
}

func newCompressWriter(w http.ResponseWriter, pol *compressPolicy, encoding string) *compressWriter {
	return &compressWriter{ResponseWriter: w, pol: pol, encoding: encoding}
}

func (w *compressWriter) Header() http.Header { return w.ResponseWriter.Header() }

func (w *compressWriter) WriteHeader(code int) {
	if w.committed || w.pending {
		return
	}
	w.status = code
	h := w.Header()
	bodyless := code < 200 || code == http.StatusNoContent || code == http.StatusNotModified || code == http.StatusPartialContent
	if bodyless || h.Get("Content-Encoding") != "" || h.Get("Content-Range") != "" ||
		strings.Contains(strings.ToLower(h.Get("Cache-Control")), "no-transform") || !w.pol.eligibleType(h.Get("Content-Type")) {
		w.commit()
		return
	}
	h.Add("Vary", "Accept-Encoding")
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n < int64(w.pol.minBytes) {
			w.commit()
			return
		}
		w.start()
		return
	}
	w.pending = true
}

// commit sends the header as it is.
func (w *compressWriter) commit() {
	if w.committed {
		return
	}
	w.committed = true
	w.pending = false
	w.ResponseWriter.WriteHeader(w.status)
}

// start switches to the negotiated encoding and sends the header.
func (w *compressWriter) start() {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Encoding", w.encoding)
	if et := h.Get("ETag"); et != "" && !strings.HasPrefix(et, "W/") {
		h.Set("ETag", "W/"+et)
	}
	w.compress = true
	w.gz = w.pol.writer(w.encoding, w.ResponseWriter)
	w.commit()
}

func (w *compressWriter) Write(p []byte) (int, error) {
	if !w.committed && !w.pending {
		w.WriteHeader(http.StatusOK)
	}
	w.raw += int64(len(p))
	if w.pending {
		w.buf = append(w.buf, p...)
		if len(w.buf) >= w.pol.minBytes {
			w.start()
			if _, err := w.gz.Write(w.buf); err != nil {
				return 0, err
			}
			w.buf = nil
		}
		return len(p), nil
	}
	if w.compress {
		return w.gz.Write(p)
	}
	return w.ResponseWriter.Write(p)
}

// flushPending resolves an undecided response: compress when streaming
// is wanted, else send what is buffered as it is with its length.
func (w *compressWriter) flushPending(compress bool) error {
	if !w.pending {
		return nil
	}
	if compress {
		w.start()
		_, err := w.gz.Write(w.buf)
		w.buf = nil
		return err
	}
	if w.Header().Get("Content-Length") == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(w.buf)))
	}
	w.commit()
	_, err := w.ResponseWriter.Write(w.buf)
	w.buf = nil
	return err
}

func (w *compressWriter) Flush() {
	if !w.committed && !w.pending {
		w.WriteHeader(http.StatusOK)
	}
	_ = w.flushPending(true)
	if w.compress {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Close finishes the response: an undecided small body goes out as it is,
// a compressed one gets its trailer. Safe to call more than once.
func (w *compressWriter) Close() {
	if w.closed || w.hijacked {
		return
	}
	w.closed = true
	if !w.committed && !w.pending {
		return // nothing was written; the handler's status stands
	}
	_ = w.flushPending(false)
	if w.compress {
		_ = w.gz.Close()
		w.pol.release(w.encoding, w.gz)
		w.gz = nil
	}
}

func (w *compressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	c, rw, err := h.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return c, rw, err
}

func (w *compressWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
