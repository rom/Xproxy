package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// gRPC-web (application/grpc-web, grpc-web+proto, grpc-web-text,
// grpc-web-text+proto) is gRPC for browsers over HTTP/1.1 or HTTP/2
// without trailers: the request is a gRPC request with a different
// content type (base64 encoded in the text variants) and the response
// carries the trailers as a final frame with the high bit of the flag
// byte set. Routes with grpc.web translate both directions so the
// upstream sees plain gRPC.

// isGRPCWeb reports a gRPC-web request by its content type.
func isGRPCWeb(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc-web")
}

// isGRPCWebPreflight reports a CORS preflight for a gRPC-web call.
func isGRPCWebPreflight(r *http.Request) bool {
	if r.Method != http.MethodOptions || r.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	h := strings.ToLower(r.Header.Get("Access-Control-Request-Headers"))
	return strings.Contains(h, "x-grpc-web") || strings.Contains(h, "grpc-timeout")
}

// grpcWebText reports the base64 variant.
func grpcWebText(ct string) bool { return strings.HasPrefix(ct, "application/grpc-web-text") }

// grpcWebToGRPC maps the web content type to the gRPC one the upstream
// expects (the +proto suffix is kept).
func grpcWebToGRPC(ct string) string {
	suffix := ""
	if i := strings.IndexByte(ct, '+'); i >= 0 {
		suffix = ct[i:]
	}
	return "application/grpc" + suffix
}

// grpcWebRequest rewrites the outbound request of a gRPC-web call.
func grpcWebRequest(out *http.Request, ct string) {
	out.Header.Set("Content-Type", grpcWebToGRPC(ct))
	out.Header.Set("TE", "trailers")
	out.Header.Del("X-Grpc-Web")
	out.Header.Del("Content-Length")
	out.ContentLength = -1
	if grpcWebText(ct) && out.Body != nil {
		out.Body = &b64Body{rc: out.Body}
	}
}

// grpcWebTextLimit bounds a text mode request body (the route's body
// limit applies as well).
const grpcWebTextLimit = 64 << 20

// b64Body decodes a grpc-web-text request body on first read. Clients
// send one padded base64 chunk per frame, so the body is split at the
// padding and each chunk decoded on its own.
type b64Body struct {
	rc      io.ReadCloser
	decoded *bytes.Reader
	err     error
}

func (b *b64Body) Read(p []byte) (int, error) {
	if b.decoded == nil && b.err == nil {
		raw, err := io.ReadAll(io.LimitReader(b.rc, grpcWebTextLimit+1))
		switch {
		case err != nil:
			b.err = err
		case len(raw) > grpcWebTextLimit:
			b.err = errors.New("grpc-web-text body too large")
		default:
			if out, derr := decodeGRPCWebText(raw); derr != nil {
				b.err = derr
			} else {
				b.decoded = bytes.NewReader(out)
			}
		}
	}
	if b.err != nil {
		return 0, b.err
	}
	return b.decoded.Read(p)
}

func (b *b64Body) Close() error { return b.rc.Close() }

// decodeGRPCWebText decodes a concatenation of padded base64 chunks.
func decodeGRPCWebText(raw []byte) ([]byte, error) {
	var out []byte
	for len(raw) > 0 {
		// A chunk ends after its padding, or at the end of the input.
		end := len(raw)
		if i := bytes.IndexByte(raw, '='); i >= 0 {
			end = i
			for end < len(raw) && raw[end] == '=' {
				end++
			}
		}
		chunk := bytes.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' {
				return -1
			}
			return r
		}, raw[:end])
		raw = raw[end:]
		if len(chunk) == 0 {
			continue
		}
		enc := base64.StdEncoding
		if len(chunk)%4 != 0 && !bytes.HasSuffix(chunk, []byte("=")) {
			enc = base64.RawStdEncoding
		}
		dec, err := enc.DecodeString(string(chunk))
		if err != nil {
			return nil, err
		}
		out = append(out, dec...)
	}
	return out, nil
}

// grpcWebResponse rewrites the upstream response for the web client:
// the content type goes back to the web variant and the body gains the
// trailer frame when the upstream's trailers arrive.
func grpcWebResponse(resp *http.Response, ct string) {
	resp.Header.Set("Content-Type", ct)
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Header.Del("Trailer")
	body := &grpcWebBody{rc: resp.Body, resp: resp, text: grpcWebText(ct)}
	// Trailers-only responses carry the status in the headers already;
	// the frame repeats it so every client finds it in the body too.
	resp.Body = body
}

// grpcWebBody streams data frames (base64 encoded whole frames in text
// mode) and appends the trailer frame at the end.
type grpcWebBody struct {
	rc   io.ReadCloser
	resp *http.Response
	text bool

	buf     bytes.Buffer // encoded output not yet read by the client
	pending []byte       // raw input not yet forming a whole frame (text mode)
	eof     bool
	done    bool
	failed  bool // an upstream frame exceeded maxGRPCWebFrame
}

// maxGRPCWebFrame bounds one gRPC message buffered in text mode; the
// length prefix is a raw uint32 from the upstream and must not size a
// buffer on its own.
const maxGRPCWebFrame = 4 << 20

func (b *grpcWebBody) Read(p []byte) (int, error) {
	if b.failed && b.buf.Len() == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	for b.buf.Len() == 0 && !b.done {
		if b.eof {
			b.finish()
			break
		}
		chunk := make([]byte, 32<<10)
		n, err := b.rc.Read(chunk)
		if n > 0 {
			b.ingest(chunk[:n])
		}
		if err != nil {
			b.eof = true
			if err != io.EOF {
				// A broken upstream stream: no trailer frame, the client
				// sees an incomplete response.
				b.done = true
				return b.buf.Read(p)
			}
		}
	}
	if b.buf.Len() == 0 && b.done {
		return 0, io.EOF
	}
	return b.buf.Read(p)
}

// ingest appends upstream data: as is in binary mode, whole frames
// encoded in text mode.
func (b *grpcWebBody) ingest(data []byte) {
	if !b.text {
		b.buf.Write(data)
		return
	}
	b.pending = append(b.pending, data...)
	for len(b.pending) >= 5 {
		size := int(binary.BigEndian.Uint32(b.pending[1:5]))
		if size > maxGRPCWebFrame {
			b.failed, b.done, b.pending = true, true, nil
			return
		}
		if len(b.pending) < 5+size {
			break
		}
		b.encode(b.pending[:5+size])
		b.pending = b.pending[5+size:]
	}
}

func (b *grpcWebBody) encode(frame []byte) {
	enc := base64.NewEncoder(base64.StdEncoding, &b.buf)
	_, _ = enc.Write(frame)
	_ = enc.Close()
}

// finish flushes a partial frame (text mode) and appends the trailer
// frame built from the response trailers, or from the headers of a
// trailers-only response.
func (b *grpcWebBody) finish() {
	b.done = true
	if b.text && len(b.pending) > 0 {
		b.encode(b.pending)
		b.pending = nil
	}
	trailers := http.Header{}
	for k, v := range b.resp.Trailer {
		trailers[k] = v
	}
	if trailers.Get("Grpc-Status") == "" {
		if st := b.resp.Header.Get("Grpc-Status"); st != "" {
			trailers.Set("Grpc-Status", st)
			if m := b.resp.Header.Get("Grpc-Message"); m != "" {
				trailers.Set("Grpc-Message", m)
			}
		}
	}
	if len(trailers) == 0 {
		return
	}
	keys := make([]string, 0, len(trailers))
	for k := range trailers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var payload bytes.Buffer
	for _, k := range keys {
		for _, v := range trailers[k] {
			payload.WriteString(strings.ToLower(k))
			payload.WriteString(": ")
			payload.WriteString(v)
			payload.WriteString("\r\n")
		}
	}
	frame := make([]byte, 5, 5+payload.Len())
	frame[0] = 0x80
	binary.BigEndian.PutUint32(frame[1:5], uint32(payload.Len())) //nolint:gosec // bounded trailer block
	frame = append(frame, payload.Bytes()...)
	if b.text {
		b.encode(frame)
	} else {
		b.buf.Write(frame)
	}
}

func (b *grpcWebBody) Close() error { return b.rc.Close() }

// grpcWebCORS adds the response headers for an allowed origin.
func grpcWebCORS(h http.Header, origin string) {
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Expose-Headers", "grpc-status, grpc-message, grpc-status-details-bin")
}

// grpcWebOriginAllowed matches the request origin against the route's
// list ("*" allows any).
func grpcWebOriginAllowed(origins []string, origin string) (string, bool) {
	if origin == "" {
		return "", false
	}
	for _, o := range origins {
		if o == "*" {
			return "*", true
		}
		if strings.EqualFold(o, origin) {
			return origin, true
		}
	}
	return "", false
}

// writeGRPCWebStatus answers a gRPC-web client with a trailers-only
// style response: HTTP 200 and the status in the headers, which every
// gRPC-web client understands.
func writeGRPCWebStatus(rw *responseWriter, r *http.Request, status int) {
	code, name := grpcCode(status)
	h := rw.Header()
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/grpc-web+proto"
	}
	h.Set("Content-Type", ct)
	h.Set("Grpc-Status", strconv.Itoa(code))
	h.Set("Grpc-Message", url.PathEscape(name+": proxy "+strconv.Itoa(status)+" "+http.StatusText(status)))
	h.Set("Cache-Control", "no-store")
	h.Del("Content-Length")
	rw.WriteHeader(http.StatusOK)
}

// grpcWebPreflight answers a CORS preflight for a gRPC-web route.
func (s *Server) grpcWebPreflight(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute) {
	origin, ok := grpcWebOriginAllowed(cr.cfg.GRPC.WebOrigins, r.Header.Get("Origin"))
	if !ok {
		st.denied = "cors"
		s.plainStatus(rw, r, http.StatusForbidden)
		return
	}
	h := rw.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
		h.Set("Access-Control-Allow-Headers", req)
	} else {
		h.Set("Access-Control-Allow-Headers", "content-type, x-grpc-web, x-user-agent, grpc-timeout")
	}
	h.Set("Access-Control-Max-Age", "600")
	rw.WriteHeader(http.StatusNoContent)
}
