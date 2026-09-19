package metrics

import (
	"math"
	"sync/atomic"
)

// Histogram counts observations into fixed cumulative-free buckets with
// atomic operations; it is safe for concurrent use and never allocates on
// Observe.
type Histogram struct {
	bounds []float64
	counts []atomic.Uint64
	sum    atomic.Uint64 // float64 bits
	count  atomic.Uint64
}

// DurationBuckets are seconds buckets suited to request latency.
var DurationBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// NewHistogram creates a histogram with the given upper bounds (sorted
// ascending).
func NewHistogram(bounds []float64) *Histogram {
	return &Histogram{bounds: bounds, counts: make([]atomic.Uint64, len(bounds))}
}

// Observe records one value.
func (h *Histogram) Observe(v float64) {
	for i, b := range h.bounds {
		if v <= b {
			h.counts[i].Add(1)
			break
		}
	}
	h.count.Add(1)
	for {
		old := h.sum.Load()
		nv := math.Float64bits(math.Float64frombits(old) + v)
		if h.sum.CompareAndSwap(old, nv) {
			return
		}
	}
}

// HistogramSnapshot is an immutable copy for encoding.
type HistogramSnapshot struct {
	Bounds []float64
	Counts []uint64 // per bucket (not cumulative)
	Sum    float64
	Count  uint64
}

// Quantile estimates the q-th quantile (0 < q <= 1) from the buckets by
// linear interpolation inside the bucket that holds it; observations
// above the last bound return that bound. It returns 0 without
// observations.
func (s HistogramSnapshot) Quantile(q float64) float64 {
	if s.Count == 0 || len(s.Bounds) == 0 {
		return 0
	}
	target := q * float64(s.Count)
	var seen uint64
	lower := 0.0
	for i, c := range s.Counts {
		if float64(seen+c) >= target {
			if c == 0 {
				return s.Bounds[i]
			}
			frac := (target - float64(seen)) / float64(c)
			return lower + frac*(s.Bounds[i]-lower)
		}
		seen += c
		lower = s.Bounds[i]
	}
	return s.Bounds[len(s.Bounds)-1]
}

// Snapshot copies the histogram state.
func (h *Histogram) Snapshot() HistogramSnapshot {
	s := HistogramSnapshot{Bounds: h.bounds, Counts: make([]uint64, len(h.bounds))}
	for i := range h.counts {
		s.Counts[i] = h.counts[i].Load()
	}
	s.Sum = math.Float64frombits(h.sum.Load())
	s.Count = h.count.Load()
	return s
}
