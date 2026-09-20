package proxy

import (
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// isGRPC reports a gRPC request by its content type (application/grpc,
// application/grpc+proto, application/grpc-web is not gRPC).
func isGRPC(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+")
}

// grpcCode maps a proxy status to the gRPC status a client expects
// (gRPC over HTTP/2 mapping from the gRPC core documentation).
func grpcCode(status int) (int, string) {
	switch status {
	case http.StatusBadRequest:
		return 3, "INVALID_ARGUMENT"
	case http.StatusUnauthorized:
		return 16, "UNAUTHENTICATED"
	case http.StatusForbidden:
		return 7, "PERMISSION_DENIED"
	case http.StatusNotFound:
		return 12, "UNIMPLEMENTED"
	case http.StatusTooManyRequests, http.StatusRequestEntityTooLarge, http.StatusRequestURITooLong:
		return 8, "RESOURCE_EXHAUSTED"
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return 14, "UNAVAILABLE"
	case http.StatusGatewayTimeout:
		return 4, "DEADLINE_EXCEEDED"
	default:
		if status >= 500 {
			return 13, "INTERNAL"
		}
		return 2, "UNKNOWN"
	}
}

// writeGRPCStatus answers a gRPC request the proxy could not forward: a
// trailers-only response (HTTP 200, grpc-status and grpc-message in the
// headers, no body) with the proxy's own status in the message.
func writeGRPCStatus(rw *responseWriter, status int) {
	code, name := grpcCode(status)
	h := rw.Header()
	h.Set("Content-Type", "application/grpc")
	h.Set("Grpc-Status", strconv.Itoa(code))
	h.Set("Grpc-Message", url.PathEscape(name+": proxy "+strconv.Itoa(status)+" "+http.StatusText(status)))
	h.Set("Cache-Control", "no-store")
	h.Del("Content-Length")
	rw.WriteHeader(http.StatusOK)
}

// parseGRPCTimeout reads the grpc-timeout header (an integer and a unit
// H, M, S, m, u or n). Zero means absent or invalid.
func parseGRPCTimeout(v string) time.Duration {
	if len(v) < 2 || len(v) > 9 {
		return 0
	}
	n, err := strconv.Atoi(v[:len(v)-1])
	if err != nil || n < 0 {
		return 0
	}
	var unit time.Duration
	switch v[len(v)-1] {
	case 'H':
		unit = time.Hour
	case 'M':
		unit = time.Minute
	case 'S':
		unit = time.Second
	case 'm':
		unit = time.Millisecond
	case 'u':
		unit = time.Microsecond
	case 'n':
		unit = time.Nanosecond
	default:
		return 0
	}
	if int64(n) > int64(math.MaxInt64)/int64(unit) {
		return 0 // would overflow: treated as absent, never as a negative deadline
	}
	return time.Duration(n) * unit
}

// grpcStatusBody records the gRPC status of an upstream response once
// its trailers are available (at end of body), so the access log can
// carry it. Trailers-only responses carry the status in the headers.
type grpcStatusBody struct {
	io.ReadCloser
	resp *http.Response
	set  func(code string)
	done bool
}

func (b *grpcStatusBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && !b.done {
		b.done = true
		b.set(b.resp.Trailer.Get("Grpc-Status"))
	}
	return n, err
}

// grpcStatusOf returns the status already visible in the headers of a
// trailers-only response, or "".
func grpcStatusOf(resp *http.Response) string {
	return resp.Header.Get("Grpc-Status")
}
