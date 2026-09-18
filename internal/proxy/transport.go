package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

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
	// statusRetries counts responses discarded under retry_on.
	statusRetries int
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
	// retryOn lists the statuses retried on another endpoint.
	retryOn []string
}

// retryStatus reports whether a response status is in the retry_on list.
func (t *poolTransport) retryStatus(code int) bool {
	if len(t.retryOn) == 0 {
		return false
	}
	for _, on := range t.retryOn {
		switch on {
		case "5xx":
			if code >= 500 && code <= 599 {
				return true
			}
		default:
			if n, err := strconv.Atoi(on); err == nil && n == code {
				return true
			}
		}
	}
	return false
}

// circuitOpenError carries the remaining open time for Retry-After.
type circuitOpenError struct{ retryAfter time.Duration }

func (e *circuitOpenError) Error() string { return upstream.ErrCircuitOpen.Error() }
func (e *circuitOpenError) Unwrap() error { return upstream.ErrCircuitOpen }

func (t *poolTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	pi := pickFrom(req.Context())
	if pi == nil {
		pi = &pickInfo{}
	}
	var done func(bool)
	if b := t.pool.Breaker(); b != nil {
		var wait time.Duration
		if done, wait = b.Allow(); done == nil {
			return nil, &circuitOpenError{retryAfter: wait}
		}
	}
	resp, err := t.roundTrip(req, pi)
	if done != nil {
		switch {
		case err != nil:
			// Timeouts and connection errors are the upstream's; a client
			// cancel or a missing endpoint is not an outcome.
			if isConnError(err) || errors.Is(err, context.DeadlineExceeded) && req.Context().Err() == nil {
				done(false)
			}
		default:
			done(resp.StatusCode != http.StatusServiceUnavailable && !t.retryStatus(resp.StatusCode))
		}
	}
	return resp, err
}

func (t *poolTransport) roundTrip(req *http.Request, pi *pickInfo) (*http.Response, error) {
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
		// A status in retry_on is a failed attempt: the body is dropped,
		// the endpoint marked, and the next endpoint tried while the
		// budget lasts. The last attempt's response is returned as it is.
		if attempt+1 < maxAttempts && t.retryStatus(resp.StatusCode) && t.hasAlternative(pi, exclude, e) {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			t.pool.End(e, true)
			pi.mu.Lock()
			pi.statusRetries++
			pi.mu.Unlock()
			exclude[e] = true
			continue
		}
		// Count 503 (and every retry_on status) as a passive failure
		// signal; other statuses are the application's business.
		failed := resp.StatusCode == http.StatusServiceUnavailable || t.retryStatus(resp.StatusCode)
		resp.Body = &endBody{ReadCloser: resp.Body, done: func() { t.pool.End(e, failed) }}
		return resp, nil
	}
	return nil, lastErr
}

// hasAlternative reports whether another endpoint could take the retry;
// without one the response in hand is better than a synthetic error.
func (t *poolTransport) hasAlternative(pi *pickInfo, exclude map[*upstream.Endpoint]bool, cur *upstream.Endpoint) bool {
	exclude[cur] = true
	next, _ := t.pool.Pick(pi.hashKey, pi.cookie, exclude)
	delete(exclude, cur)
	return next != nil
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
