package metrics

import (
	"sync"
	"time"
)

// Point is one sample of every series at one instant.
type Point struct {
	Time   time.Time `json:"t"`
	Values []float64 `json:"v"`
}

// Series is a fixed-interval ring buffer of Points for a named set of
// series, filled by a Sampler. Rates are computed by the sampler from
// counter deltas, so points hold per-second values for counters and
// current values for gauges.
type Series struct {
	mu       sync.RWMutex
	names    []string
	interval time.Duration
	points   []Point
	next     int
	full     bool
}

// NewSeries creates a buffer holding retention/interval points.
func NewSeries(names []string, interval, retention time.Duration) *Series {
	n := int(retention / interval)
	if n < 2 {
		n = 2
	}
	return &Series{names: names, interval: interval, points: make([]Point, n)}
}

// Names returns the series names in value order.
func (s *Series) Names() []string { return s.names }

// Interval returns the sampling interval.
func (s *Series) Interval() time.Duration { return s.interval }

// Add appends a point.
func (s *Series) Add(p Point) {
	s.mu.Lock()
	s.points[s.next] = p
	s.next = (s.next + 1) % len(s.points)
	if s.next == 0 {
		s.full = true
	}
	s.mu.Unlock()
}

// Since returns points newer than t in chronological order, at most limit
// (0 for all).
func (s *Series) Since(t time.Time, limit int) []Point {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Point
	n := len(s.points)
	start, count := 0, s.next
	if s.full {
		start, count = s.next, n
	}
	for i := 0; i < count; i++ {
		p := s.points[(start+i)%n]
		if p.Time.After(t) {
			out = append(out, p)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Sampler calls a source at a fixed interval and stores rates and gauges.
type Sampler struct {
	series   *Series
	source   func() Sample
	interval time.Duration
	stop     chan struct{}
	done     chan struct{}
	now      func() time.Time
}

// Sample is what a source returns: monotonically increasing counters (turned
// into per-second rates) and instantaneous gauges, both in the order of the
// names given to NewSampler (counters first, then gauges).
type Sample struct {
	Counters []float64
	Gauges   []float64
}

// NewSampler creates a sampler with counterNames followed by gaugeNames.
func NewSampler(counterNames, gaugeNames []string, interval, retention time.Duration, source func() Sample) *Sampler {
	names := append(append([]string{}, counterNames...), gaugeNames...)
	return &Sampler{series: NewSeries(names, interval, retention), source: source, interval: interval, stop: make(chan struct{}), done: make(chan struct{}), now: time.Now}
}

// Series returns the buffer.
func (s *Sampler) Series() *Series { return s.series }

// Start begins sampling in the background.
func (s *Sampler) Start() {
	go s.loop()
}

// Stop ends sampling.
func (s *Sampler) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
}

func (s *Sampler) loop() {
	defer close(s.done)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	last := s.source()
	lastT := s.now()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		cur := s.source()
		now := s.now()
		s.series.Add(s.point(last, cur, lastT, now))
		last, lastT = cur, now
	}
}

// point turns two samples into a point (exported for tests via Tick).
func (s *Sampler) point(prev, cur Sample, prevT, now time.Time) Point {
	secs := now.Sub(prevT).Seconds()
	if secs <= 0 {
		secs = s.interval.Seconds()
	}
	vals := make([]float64, 0, len(cur.Counters)+len(cur.Gauges))
	for i, c := range cur.Counters {
		d := c
		if i < len(prev.Counters) {
			d = c - prev.Counters[i]
		}
		if d < 0 {
			d = 0 // counter reset
		}
		vals = append(vals, d/secs)
	}
	vals = append(vals, cur.Gauges...)
	return Point{Time: now, Values: vals}
}

// Tick takes one sample synchronously (for tests and for the management
// API's "sample now").
func (s *Sampler) Tick(prev, cur Sample, prevT, now time.Time) {
	s.series.Add(s.point(prev, cur, prevT, now))
}
