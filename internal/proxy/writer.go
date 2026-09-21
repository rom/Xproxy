package proxy

import (
	"bufio"
	"net"
	"net/http"
)

// responseWriter records status and byte count for access logging. It
// exposes Unwrap so that http.ResponseController can reach Flush and Hijack
// on the underlying writer (needed for WebSocket and streaming).
type responseWriter struct {
	http.ResponseWriter
	status   int
	bytes    int64
	wrote    bool
	hijacked bool
	// st is the request state once created (error pages need the route).
	st *reqState
	// guard wraps the connection when the route inspects WebSocket
	// frames. It is set before the reverse proxy runs, because the
	// hijack happens inside it.
	guard func(net.Conn) net.Conn
}

func (w *responseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *responseWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	c, rw, err := h.Hijack()
	if err == nil {
		w.hijacked = true
		if !w.wrote {
			w.status = http.StatusSwitchingProtocols
			w.wrote = true
		}
		// This is the seam where an upgraded connection stops being a
		// request and becomes a byte stream. A route with a WebSocket
		// guard gets a connection that parses the frames going past in
		// both directions; without one the connection is handed over
		// as it always was.
		if w.guard != nil {
			c = w.guard(c)
		}
	}
	return c, rw, err
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Status returns the recorded status, defaulting to 200 if the handler
// wrote a body without an explicit status, or 0 if nothing was written.
func (w *responseWriter) Status() int {
	if !w.wrote {
		return 0
	}
	return w.status
}
