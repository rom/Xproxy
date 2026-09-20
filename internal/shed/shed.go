// Package shed implements adaptive load shedding by priority class
// (docs/AMR.md, AMR-022).
//
// The load level is the larger of two signals: the in-flight ratio
// (admitted requests over the concurrency ceiling) and the latency level
// (how far the recent upstream time-to-first-byte exceeds the target,
// reaching 1 at twice the target). Latency is averaged over a sliding
// window of fixed buckets, so a period without samples (because everything
// was shed) drains the signal and traffic is admitted again for a fresh
// measurement. Each class is shed while the level is at or above its
// threshold and admitted again only once it falls below threshold minus
// hysteresis.
package shed

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Class is a priority class.
type Class int

// Priority classes in shedding order.
const (
	Low Class = iota
	Normal
	High
	Critical
)

// ParseClass maps a configuration value to a Class.
func ParseClass(s string) Class {
	switch s {
	case "low":
		return Low
	case "high":
		return High
	case "critical":
		return Critical
	default:
		return Normal
	}
}

func (c Class) String() string {
	switch c {
	case Low:
		return "low"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return "normal"
	}
}

const buckets = 20

// Shedder computes the load level and admits requests by class.
type Shedder struct {
	mu     sync.Mutex
	target float64 // seconds
	window time.Duration
	// bucketSpan and maxInflight are written by Reconfigure on a reload
	// and read outside the lock on the request path, so they are
	// atomics: a word-sized read racing a word-sized write is benign in
	// practice and undefined under the Go memory model.
	bucketSpan atomic.Int64 // nanoseconds
	sum        [buckets]float64
	count      [buckets]int64
	stamp      [buckets]int64 // bucket index in absolute terms
	thresholds [3]float64
	hysteresis float64
	retryAfter time.Duration

	inflight    func() int64
	maxInflight atomic.Int64
	shedding    [3]atomic.Bool
	shed        [4]atomic.Uint64
	admitted    atomic.Uint64
	now         func() time.Time
}

// New creates a shedder. inflight reports admitted requests; maxInflight is
// the concurrency ceiling.
func New(cfg *config.Shedding, inflight func() int64, maxInflight int) *Shedder {
	s := &Shedder{inflight: inflight, now: time.Now}
	s.maxInflight.Store(int64(maxInflight))
	s.Reconfigure(cfg, maxInflight)
	return s
}

// Reconfigure applies new thresholds without losing samples.
func (s *Shedder) Reconfigure(cfg *config.Shedding, maxInflight int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.target = cfg.TargetLatency.D().Seconds()
	if cfg.Window.D() != s.window {
		s.window = cfg.Window.D()
		s.bucketSpan.Store(int64(s.window / buckets))
		s.sum = [buckets]float64{}
		s.count = [buckets]int64{}
		s.stamp = [buckets]int64{}
	}
	s.thresholds = [3]float64{cfg.Low, cfg.Normal, cfg.High}
	s.hysteresis = cfg.Hysteresis
	s.retryAfter = cfg.RetryAfter.D()
	s.maxInflight.Store(int64(maxInflight))
}

// Observe records one upstream time to first byte.
func (s *Shedder) Observe(d time.Duration) {
	now := s.now()
	span := s.bucketSpan.Load()
	if span <= 0 {
		return
	}
	idx := now.UnixNano() / span
	i := int(idx % buckets)
	s.mu.Lock()
	if s.stamp[i] != idx {
		s.stamp[i] = idx
		s.sum[i] = 0
		s.count[i] = 0
	}
	s.sum[i] += d.Seconds()
	s.count[i]++
	s.mu.Unlock()
}

// Latency returns the average observed latency inside the window.
func (s *Shedder) Latency() time.Duration {
	now := s.now()
	span := s.bucketSpan.Load()
	if span <= 0 {
		return 0
	}
	idx := now.UnixNano() / span
	s.mu.Lock()
	defer s.mu.Unlock()
	var sum float64
	var n int64
	for i := 0; i < buckets; i++ {
		if idx-s.stamp[i] < buckets {
			sum += s.sum[i]
			n += s.count[i]
		}
	}
	if n == 0 {
		return 0
	}
	return time.Duration(sum / float64(n) * float64(time.Second))
}

// Level returns the current load level in [0, 1].
func (s *Shedder) Level() float64 {
	var inflightLevel float64
	if m := s.maxInflight.Load(); m > 0 {
		inflightLevel = float64(s.inflight()) / float64(m)
	}
	lat := s.Latency().Seconds()
	s.mu.Lock()
	target := s.target
	s.mu.Unlock()
	latencyLevel := 0.0
	if target > 0 && lat > target {
		latencyLevel = (lat - target) / target
	}
	level := max(inflightLevel, latencyLevel)
	return min(max(level, 0), 1)
}

// Admit decides whether a request of class c may proceed. The returned
// level is the load level used for the decision.
func (s *Shedder) Admit(c Class) (ok bool, level float64) {
	level = s.Level()
	if c == Critical {
		s.admitted.Add(1)
		return true, level
	}
	s.mu.Lock()
	th := s.thresholds[c]
	hy := s.hysteresis
	s.mu.Unlock()
	state := &s.shedding[c]
	if state.Load() {
		if level < th-hy {
			state.Store(false)
		}
	} else if level >= th {
		state.Store(true)
	}
	if state.Load() {
		s.shed[c].Add(1)
		return false, level
	}
	s.admitted.Add(1)
	return true, level
}

// RetryAfter returns the advisory delay for shed responses.
func (s *Shedder) RetryAfter() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retryAfter
}

// Snapshot is the management view.
type Snapshot struct {
	Level        float64 `json:"level"`
	LatencyMS    float64 `json:"latency_ms"`
	InFlight     int64   `json:"in_flight"`
	SheddingLow  bool    `json:"shedding_low"`
	SheddingNorm bool    `json:"shedding_normal"`
	SheddingHigh bool    `json:"shedding_high"`
	ShedLow      uint64  `json:"shed_low"`
	ShedNormal   uint64  `json:"shed_normal"`
	ShedHigh     uint64  `json:"shed_high"`
	Admitted     uint64  `json:"admitted"`
}

// Snapshot returns the current state.
func (s *Shedder) Snapshot() Snapshot {
	return Snapshot{
		Level:        s.Level(),
		LatencyMS:    float64(s.Latency().Microseconds()) / 1000,
		InFlight:     s.inflight(),
		SheddingLow:  s.shedding[Low].Load(),
		SheddingNorm: s.shedding[Normal].Load(),
		SheddingHigh: s.shedding[High].Load(),
		ShedLow:      s.shed[Low].Load(),
		ShedNormal:   s.shed[Normal].Load(),
		ShedHigh:     s.shed[High].Load(),
		Admitted:     s.admitted.Load(),
	}
}
