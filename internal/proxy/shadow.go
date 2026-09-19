package proxy

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
)

// Traffic shadowing with response diffing. When a mirror route sets diff,
// the live response is summarised as it streams to the client (status,
// selected headers, body length and a digest of the first bytes) without
// buffering it, and the shadow copy's response is summarised the same way.
// The mirror goroutine compares the two and reports the outcome, so a new
// backend can be validated against the current one under real traffic.

// respSummary is a comparable digest of a response.
type respSummary struct {
	status  int
	headers map[string]string
	length  int64
	digest  [32]byte
}

// shadowState carries the live response summary from the request goroutine
// to the mirror goroutine. done is closed once the live summary is final.
type shadowState struct {
	diff *shadowDiff
	done chan struct{}
	live respSummary
	once sync.Once
}

func newShadowState(d *shadowDiff) *shadowState {
	return &shadowState{diff: d, done: make(chan struct{})}
}

// captureLive records the live response's status and selected headers, then
// wraps its body so the digest and length are computed as the client reads.
// A body-less response is finalised at once.
func (sh *shadowState) captureLive(resp *http.Response) {
	sh.live.status = resp.StatusCode
	sh.live.headers = selectHeaders(resp.Header, sh.diff.headers)
	if resp.Body == nil || resp.Body == http.NoBody {
		sh.finish(0, emptyDigest())
		return
	}
	resp.Body = &shadowLiveBody{ReadCloser: resp.Body, sh: sh, h: sha256.New(), max: sh.diff.maxBody}
}

func (sh *shadowState) finish(length int64, digest [32]byte) {
	sh.once.Do(func() {
		sh.live.length = length
		sh.live.digest = digest
		close(sh.done)
	})
}

// shadowLiveBody hashes the first max bytes of the live body and counts its
// length as the client reads, then finalises the summary on EOF or Close.
type shadowLiveBody struct {
	io.ReadCloser
	sh  *shadowState
	h   hash.Hash
	n   int64
	max int64
}

func (b *shadowLiveBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		hashUpTo(b.h, b.n, int64(n), b.max, p)
		b.n += int64(n)
	}
	if err != nil {
		var d [32]byte
		copy(d[:], b.h.Sum(nil))
		b.sh.finish(b.n, d)
	}
	return n, err
}

func (b *shadowLiveBody) Close() error {
	err := b.ReadCloser.Close()
	var d [32]byte
	copy(d[:], b.h.Sum(nil))
	b.sh.finish(b.n, d)
	return err
}

// hashUpTo writes the portion of buf that still falls within the first max
// bytes (given already counts bytes already hashed) to h.
func hashUpTo(h hash.Hash, already, n, max int64, buf []byte) {
	if already >= max {
		return
	}
	take := n
	if already+take > max {
		take = max - already
	}
	h.Write(buf[:take])
}

func emptyDigest() [32]byte { return sha256.Sum256(nil) }

// selectHeaders copies the listed header values (canonical names) into a map.
func selectHeaders(h http.Header, names []string) map[string]string {
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		out[n] = h.Get(n)
	}
	return out
}

// summarise reads body to its end (bounded), returning its length and the
// digest of its first max bytes. It always drains and closes the body.
func summarise(body io.ReadCloser, max int64) respSummary {
	defer func() { _, _ = io.Copy(io.Discard, body); _ = body.Close() }()
	h := sha256.New()
	var n int64
	buf := make([]byte, 32<<10)
	const hardCap = 64 << 20 // bound the work for an unexpectedly large body
	for n < hardCap {
		r, err := body.Read(buf)
		if r > 0 {
			hashUpTo(h, n, int64(r), max, buf)
			n += int64(r)
		}
		if err != nil {
			break
		}
	}
	var s respSummary
	s.length = n
	copy(s.digest[:], h.Sum(nil))
	return s
}

// reportDiff compares the shadow response with the live one, counts the
// outcome and logs a sampled share of the differences.
func (s *Server) reportDiff(d *shadowDiff, st *reqState, shadow respSummary) {
	live := st.shadow.live
	result, detail := "match", ""
	switch {
	case live.status != shadow.status:
		result = "status"
		detail = fmt.Sprintf("live=%d shadow=%d", live.status, shadow.status)
		s.stats.MirrorDiffStatus.Add(1)
	case headerDiff(live.headers, shadow.headers) != "":
		result = "header"
		detail = headerDiff(live.headers, shadow.headers)
		s.stats.MirrorDiffHeader.Add(1)
	case live.length != shadow.length || live.digest != shadow.digest:
		result = "body"
		detail = fmt.Sprintf("live_len=%d shadow_len=%d", live.length, shadow.length)
		s.stats.MirrorDiffBody.Add(1)
	default:
		s.stats.MirrorDiffMatch.Add(1)
	}
	if result != "match" && sampledPct(d.sample) {
		s.logs.Error.Info("mirror diff", "request_id", st.id, "route", st.route, "result", result, "detail", detail)
	}
}

// headerDiff returns a description of the first differing header, or "".
func headerDiff(live, shadow map[string]string) string {
	for name, lv := range live {
		if sv := shadow[name]; sv != lv {
			return fmt.Sprintf("%s: live=%q shadow=%q", name, lv, sv)
		}
	}
	return ""
}

// sampledPct reports whether an event falls in a percentage sample.
func sampledPct(pct int) bool {
	switch {
	case pct >= 100:
		return true
	case pct <= 0:
		return false
	default:
		return rand.IntN(100) < pct //nolint:gosec // sampling, not security
	}
}
