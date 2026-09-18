package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/rom/xproxy/internal/upstream"
)

// errNoEndpoint is returned when a pool has no available endpoint.
var errNoEndpoint = errors.New("no available upstream endpoint")

// pickInfo travels in the request context from the handler to the
// transport and back: the handler supplies the hash key and affinity cookie,
// the transport records the chosen endpoint and any cookie to set.
type pickInfo struct {
	hashKey string
	cookie  string

	mu        sync.Mutex
	endpoint  *upstream.Endpoint
	setCookie string
	attempts  int
}

type pickKey struct{}

func withPick(ctx context.Context, p *pickInfo) context.Context {
	return context.WithValue(ctx, pickKey{}, p)
}

func pickFrom(ctx context.Context) *pickInfo {
	p, _ := ctx.Value(pickKey{}).(*pickInfo)
	return p
}

// poolTransport is the http.RoundTripper handed to httputil.ReverseProxy.
// It chooses an endpoint per attempt and retries connection failures on a
// different endpoint for requests that are safe to replay.
type poolTransport struct {
	pool    *upstream.Pool
	retries int
}

func (t *poolTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pi := pickFrom(req.Context())
	if pi == nil {
		pi = &pickInfo{}
	}
	exclude := map[*upstream.Endpoint]bool{}
	maxAttempts := 1
	if replayable(req) {
		maxAttempts = t.retries + 1
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		e, cookie := t.pool.Pick(pi.hashKey, pi.cookie, exclude)
		if e == nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errNoEndpoint
		}
		pi.mu.Lock()
		pi.endpoint = e
		pi.attempts = attempt + 1
		if cookie != "" {
			pi.setCookie = cookie
		}
		pi.mu.Unlock()

		out := req.Clone(req.Context())
		out.URL.Scheme = t.pool.Scheme
		out.URL.Host = e.Address
		t.pool.Begin(e)
		resp, err := t.pool.RoundTripper().RoundTrip(out)
		if err != nil {
			t.pool.End(e, isConnError(err))
			lastErr = err
			if req.Context().Err() != nil || !isConnError(err) {
				return nil, err
			}
			exclude[e] = true
			continue
		}
		// Count 503 as a passive failure signal; other statuses are the
		// application's business.
		failed := resp.StatusCode == http.StatusServiceUnavailable
		resp.Body = &endBody{ReadCloser: resp.Body, done: func() { t.pool.End(e, failed) }}
		return resp, nil
	}
	return nil, lastErr
}

// replayable reports whether a request may be sent to a second endpoint
// after a connection failure without risking a duplicated side effect.
func replayable(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		return false
	}
	return req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0
}

// isConnError reports whether err happened before any response byte was
// received, meaning the endpoint (not the request) is at fault.
func isConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return false
}

// endBody calls done exactly once when the body is closed.
type endBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (b *endBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.done)
	return err
}
