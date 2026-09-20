package proxy

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/rom/xproxy/internal/upstream"
)

// hedgeResult carries one attempt's outcome back to the hedging loop.
type hedgeResult struct {
	resp   *http.Response
	err    error
	e      *upstream.Endpoint
	ttfb   time.Duration
	cancel context.CancelFunc // cancels this attempt's context
}

// hedged sends staggered copies of an idempotent request to distinct
// endpoints and returns the first usable response, cancelling the rest.
// The first copy is free; each extra copy (on the hedge timer or to replace
// a failed attempt) is gated by the pool's retry budget and its own
// endpoint. It is only entered for replayable requests.
//
// Only this goroutine launches attempts, receives results and touches the
// exclude and cancels maps, so no lock guards them; the worker goroutines
// only run one attempt and report back.
func (t *poolTransport) hedged(req *http.Request, pi *pickInfo) (*http.Response, error) {
	parent := req.Context()
	exclude := map[*upstream.Endpoint]bool{}
	cancels := map[*upstream.Endpoint]context.CancelFunc{}
	results := make(chan hedgeResult, t.hedge.max+1)
	attempts := 0
	inFlight := 0

	// launch starts one attempt on the next endpoint. Extra copies (isRetry)
	// take a slot from the retry budget, released when the attempt returns.
	launch := func(isRetry bool) bool {
		if isRetry && !t.pool.AllowRetry() {
			return false
		}
		e, cookie := t.pool.Pick(pi.hashKey, pi.cookie, exclude, pi.canary)
		if e == nil {
			if isRetry {
				t.pool.ReleaseRetry()
			}
			return false
		}
		exclude[e] = true
		attempts++
		pi.mu.Lock()
		pi.endpoint = e
		pi.attempts = attempts
		if cookie != "" {
			pi.setCookie = cookie
		}
		pi.mu.Unlock()
		actx, acancel := context.WithCancel(parent)
		cancels[e] = acancel
		inFlight++
		go func() {
			//nolint:bodyclose // the winning body is closed by the caller via endBody; losers are closed in drainLosers/drop.
			resp, ttfb, err := t.oneAttempt(req.WithContext(actx), e)
			if isRetry {
				t.pool.ReleaseRetry()
			}
			results <- hedgeResult{resp: resp, err: err, e: e, ttfb: ttfb, cancel: acancel}
		}()
		return true
	}

	if !launch(false) {
		return nil, errNoEndpoint
	}

	// win returns r as the answer: it cancels and drains the losers still in
	// flight and wires the winner's cleanup into its body.
	win := func(r hedgeResult) *http.Response {
		t.cancelLosers(cancels)
		go t.drainLosers(results, inFlight)
		failed := r.resp.StatusCode == http.StatusServiceUnavailable
		e := r.e
		r.resp.Body = &endBody{ReadCloser: r.resp.Body, done: func() {
			t.pool.End(e, failed, r.ttfb)
			r.cancel()
		}}
		return r.resp
	}

	timer := time.NewTimer(t.hedge.delay)
	defer timer.Stop()
	var fallback *hedgeResult // best retry_on response held for want of a winner
	var lastErr error
	drop := func(r *hedgeResult) {
		if r == nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(r.resp.Body, 64<<10))
		_ = r.resp.Body.Close()
		t.pool.End(r.e, true, r.ttfb)
		r.cancel()
		pi.mu.Lock()
		pi.statusRetries++
		pi.mu.Unlock()
	}

	for {
		select {
		case <-parent.Done():
			t.cancelLosers(cancels)
			go t.drainLosers(results, inFlight)
			drop(fallback)
			return nil, parent.Err()

		case <-timer.C:
			if attempts <= t.hedge.max {
				launch(true)
			}
			// Once every permitted copy is out there is nothing left for
			// the timer to do; let the results drive the loop from here.
			if attempts <= t.hedge.max {
				timer.Reset(t.hedge.delay)
			}

		case r := <-results:
			inFlight--
			delete(cancels, r.e)
			if r.err == nil && !t.retryStatus(r.resp.StatusCode) {
				drop(fallback)
				return win(r), nil
			}
			if r.err != nil {
				t.pool.End(r.e, isConnError(r.err), r.ttfb)
				lastErr = r.err
			} else {
				// A retry_on status: hold the newest as a fallback, dropping
				// any older one, in case no better answer arrives.
				drop(fallback)
				rr := r
				fallback = &rr
			}
			// A failed attempt tries to bring in a replacement at once rather
			// than wait out the hedge timer.
			launchedNew := false
			if attempts <= t.hedge.max {
				launchedNew = launch(true)
			}
			if !launchedNew && inFlight == 0 {
				if fallback != nil {
					return t.returnFallback(*fallback), nil
				}
				if lastErr != nil {
					return nil, lastErr
				}
				return nil, errNoEndpoint
			}
		}
	}
}

// returnFallback hands back a held retry_on response as the final answer.
func (t *poolTransport) returnFallback(r hedgeResult) *http.Response {
	e := r.e
	r.resp.Body = &endBody{ReadCloser: r.resp.Body, done: func() {
		t.pool.End(e, true, r.ttfb)
		r.cancel()
	}}
	return r.resp
}

// cancelLosers cancels every attempt still tracked in cancels.
func (t *poolTransport) cancelLosers(cancels map[*upstream.Endpoint]context.CancelFunc) {
	for _, c := range cancels {
		c()
	}
}

// drainLosers consumes the results of the n attempts still outstanding,
// accounting for their endpoints and closing their bodies.
func (t *poolTransport) drainLosers(results <-chan hedgeResult, n int) {
	for i := 0; i < n; i++ {
		r := <-results
		if r.err != nil {
			t.pool.End(r.e, isConnError(r.err), r.ttfb)
			r.cancel()
			continue
		}
		failed := r.resp.StatusCode == http.StatusServiceUnavailable || t.retryStatus(r.resp.StatusCode)
		_, _ = io.Copy(io.Discard, io.LimitReader(r.resp.Body, 64<<10))
		_ = r.resp.Body.Close()
		t.pool.End(r.e, failed, r.ttfb)
		r.cancel()
	}
}
