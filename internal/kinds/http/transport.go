package http

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/h3"
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
	// canary is the request's mode under the pool's canary policy.
	canary upstream.CanaryMode
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
	// hedge, when set, sends staggered copies of a slow idempotent request
	// to other endpoints and keeps the first usable response.
	hedge *hedgePolicy
}

// hedgePolicy is the compiled upstream hedge configuration.
type hedgePolicy struct {
	delay time.Duration
	max   int
}

// newPoolTransport builds the RoundTripper for a pool, compiling its retry
// and hedge policy.
func newPoolTransport(pool *upstream.Pool) *poolTransport {
	t := &poolTransport{pool: pool, retries: *pool.Cfg.Retries, retryOn: pool.Cfg.RetryOn}
	if h := pool.Cfg.Hedge; h != nil {
		t.hedge = &hedgePolicy{delay: h.Delay.D(), max: h.Max}
	}
	return t
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
	t.pool.BeginRequest()
	defer t.pool.EndRequest()
	var resp *http.Response
	var err error
	if t.hedge != nil && replayable(req) {
		resp, err = t.hedged(req, pi)
	} else {
		resp, err = t.roundTrip(req, pi)
	}
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
	// holdingRetry is true while this iteration runs against a retry slot
	// reserved from the pool's budget; it is freed once the attempt returns.
	holdingRetry := false
	defer func() {
		if holdingRetry {
			t.pool.ReleaseRetry()
		}
	}()
	for attempt := 0; attempt < maxAttempts; attempt++ {
		e, cookie := t.pool.Pick(pi.hashKey, pi.cookie, exclude, pi.canary)
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

		resp, ttfb, err := t.oneAttempt(req, e)
		if holdingRetry {
			t.pool.ReleaseRetry()
			holdingRetry = false
		}
		if err != nil {
			t.pool.End(e, isConnError(err), ttfb)
			lastErr = err
			if req.Context().Err() != nil || !isConnError(err) {
				return nil, err
			}
			// Another endpoint may take the retry, budget permitting.
			if attempt+1 >= maxAttempts || !t.pool.AllowRetry() {
				return nil, err
			}
			holdingRetry = true
			exclude[e] = true
			continue
		}
		// A status in retry_on is a failed attempt: the body is dropped,
		// the endpoint marked, and the next endpoint tried while the
		// budget lasts. The last attempt's response is returned as it is.
		if attempt+1 < maxAttempts && t.retryStatus(resp.StatusCode) && t.hasAlternative(pi, exclude, e) && t.pool.AllowRetry() {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			t.pool.End(e, true, ttfb)
			pi.mu.Lock()
			pi.statusRetries++
			pi.mu.Unlock()
			holdingRetry = true
			exclude[e] = true
			continue
		}
		// Count 503 (and every retry_on status) as a passive failure
		// signal; other statuses are the application's business.
		failed := resp.StatusCode == http.StatusServiceUnavailable || t.retryStatus(resp.StatusCode)
		done := func() { t.pool.End(e, failed, ttfb) }
		// A 101 response's body is the connection itself: the transport
		// hands back an io.ReadWriteCloser so the caller can splice both
		// directions. Wrapping it in a plain ReadCloser is how an
		// upgrade turns into "101 switching protocols response with
		// non-writable body" three layers up, so the wrapper keeps the
		// write half when there is one.
		if rw, ok := resp.Body.(io.ReadWriteCloser); ok {
			resp.Body = &endBodyRW{ReadWriteCloser: rw, done: done}
		} else {
			resp.Body = &endBody{ReadCloser: resp.Body, done: done}
		}
		return resp, nil
	}
	return nil, lastErr
}

// oneAttempt sends req to a single endpoint and returns the raw response,
// the time to first byte and any transport error. It handles the HTTP/3 to
// TCP fallback but no retry or budget logic; the caller accounts for the
// endpoint via pool.End. The endpoint is marked in flight (pool.Begin)
// before the round trip.
func (t *poolTransport) oneAttempt(req *http.Request, e *upstream.Endpoint) (*http.Response, time.Duration, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme = t.pool.Scheme
	// A socket endpoint wears a synthetic authority here; the pool's
	// dialler is what turns it back into a path.
	out.URL.Host = e.URLHost()
	// With max_connection_age set, the connection this request is given
	// is remembered so that an aged one can be closed when the exchange
	// on it is over. The trace is the only way to learn which
	// connection a request got, and the end of the response body is the
	// only point at which closing it disturbs nothing.
	var got net.Conn
	if t.pool.Cfg.MaxConnectionAge > 0 {
		out = out.WithContext(httptrace.WithClientTrace(out.Context(), &httptrace.ClientTrace{
			GotConn: func(i httptrace.GotConnInfo) { got = i.Conn },
		}))
	}
	t.pool.Begin(e)
	t0 := time.Now()
	resp, err := t.pool.RoundTripper().RoundTrip(out)
	if err != nil && t.pool.H3Fallback() && h3.IsTransportError(err) && req.Context().Err() == nil {
		// QUIC failed before a response (UDP blocked, handshake timeout):
		// the same endpoint over TCP.
		if retry, ok := t.tcpRetry(req, e.Address); ok {
			t.pool.H3Fallbacks.Add(1)
			resp, err = t.pool.TCPRoundTripper().RoundTrip(retry)
		}
	}
	if resp != nil && got != nil && resp.ProtoMajor == 1 && t.pool.AgedOut(got) {
		// One exchange at a time on this connection, so the body's close
		// is the moment it is between exchanges.
		resp.Body = &retireOnClose{ReadCloser: resp.Body, pool: t.pool, conn: got}
	}
	return resp, time.Since(t0), err
}

// retireOnClose closes an upstream connection that has outlived
// max_connection_age once the response on it has been read. Closing at
// the age itself would cut whatever exchange was running; closing here
// means the connection is simply not reused.
type retireOnClose struct {
	io.ReadCloser
	pool *upstream.Pool
	conn net.Conn
}

func (r *retireOnClose) Close() error {
	err := r.ReadCloser.Close()
	r.pool.Retire(r.conn)
	return err
}

// hasAlternative reports whether another endpoint could take the retry;
// without one the response in hand is better than a synthetic error.
func (t *poolTransport) hasAlternative(pi *pickInfo, exclude map[*upstream.Endpoint]bool, cur *upstream.Endpoint) bool {
	exclude[cur] = true
	next, _ := t.pool.Pick(pi.hashKey, pi.cookie, exclude, pi.canary)
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

// endBodyRW is endBody for a response whose body is writable: an
// upgraded connection. It forwards CloseWrite as well, which is how
// httputil.ReverseProxy half-closes one direction of a WebSocket.
type endBodyRW struct {
	io.ReadWriteCloser
	once sync.Once
	done func()
}

func (b *endBodyRW) Close() error {
	err := b.ReadWriteCloser.Close()
	b.once.Do(b.done)
	return err
}

func (b *endBodyRW) CloseWrite() error {
	if cw, ok := b.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// tcpRetry rebuilds the outbound request for the TCP transport; a body
// that cannot be replayed makes the retry impossible.
func (t *poolTransport) tcpRetry(req *http.Request, address string) (*http.Request, bool) {
	out := req.Clone(req.Context())
	out.URL.Scheme = t.pool.Scheme
	out.URL.Host = address
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, false
		}
		b, err := req.GetBody()
		if err != nil {
			return nil, false
		}
		out.Body = b
	}
	return out, true
}
