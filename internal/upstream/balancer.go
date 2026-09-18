package upstream

import (
	"hash/fnv"
	"sort"
	"sync"
	"time"
)

// balancer chooses among available endpoints. exclude holds endpoints
// already tried for this request (for retries).
type balancer interface {
	pick(eps []*Endpoint, key string, exclude map[*Endpoint]bool, now time.Time) *Endpoint
}

func available(e *Endpoint, exclude map[*Endpoint]bool, now time.Time) bool {
	return e.Available(now) && !exclude[e]
}

// roundRobin cycles through endpoints ignoring weight.
type roundRobin struct {
	mu   sync.Mutex
	next int
}

func (b *roundRobin) pick(eps []*Endpoint, _ string, exclude map[*Endpoint]bool, now time.Time) *Endpoint {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(eps)
	for i := 0; i < n; i++ {
		e := eps[(b.next+i)%n]
		if available(e, exclude, now) {
			b.next = (b.next + i + 1) % n
			return e
		}
	}
	return nil
}

// weighted implements smooth weighted round robin (as in nginx), which
// spreads a weight-3 endpoint's picks evenly rather than in bursts.
type weighted struct {
	mu sync.Mutex
}

func (b *weighted) pick(eps []*Endpoint, _ string, exclude map[*Endpoint]bool, now time.Time) *Endpoint {
	b.mu.Lock()
	defer b.mu.Unlock()
	var best *Endpoint
	total := 0
	for _, e := range eps {
		if !available(e, exclude, now) {
			continue
		}
		e.current += e.Weight
		total += e.Weight
		if best == nil || e.current > best.current {
			best = e
		}
	}
	if best != nil {
		best.current -= total
	}
	return best
}

// leastConn picks the endpoint with the fewest in-flight requests, scaled
// by weight, with round robin among ties.
type leastConn struct {
	mu   sync.Mutex
	next int
}

func (b *leastConn) pick(eps []*Endpoint, _ string, exclude map[*Endpoint]bool, now time.Time) *Endpoint {
	b.mu.Lock()
	defer b.mu.Unlock()
	var best *Endpoint
	var bestScore float64
	n := len(eps)
	for i := 0; i < n; i++ {
		e := eps[(b.next+i)%n]
		if !available(e, exclude, now) {
			continue
		}
		score := float64(e.active.Load()+1) / float64(e.Weight)
		if best == nil || score < bestScore {
			best, bestScore = e, score
		}
	}
	b.next = (b.next + 1) % max(n, 1)
	return best
}

// ring is a consistent hash ring with virtual nodes. A key maps to the same
// endpoint as long as that endpoint is available; when it is not, the walk
// continues clockwise so that only that endpoint's keys move.
type ring struct {
	points []ringPoint
}

type ringPoint struct {
	hash uint32
	ep   *Endpoint
}

const virtualNodes = 128

func newRing(eps []*Endpoint) *ring {
	r := &ring{}
	for _, e := range eps {
		for v := 0; v < virtualNodes*e.Weight; v++ {
			h := fnv.New32a()
			h.Write([]byte(e.Address))
			h.Write([]byte{'#', byte(v), byte(v >> 8), byte(v >> 16)})
			r.points = append(r.points, ringPoint{hash: h.Sum32(), ep: e})
		}
	}
	sort.Slice(r.points, func(i, j int) bool { return r.points[i].hash < r.points[j].hash })
	return r
}

func (r *ring) pick(eps []*Endpoint, key string, exclude map[*Endpoint]bool, now time.Time) *Endpoint {
	if len(r.points) == 0 {
		return nil
	}
	h := fnv.New32a()
	h.Write([]byte(key))
	kh := h.Sum32()
	start := sort.Search(len(r.points), func(i int) bool { return r.points[i].hash >= kh })
	seen := 0
	for i := 0; i < len(r.points) && seen < len(eps); i++ {
		p := r.points[(start+i)%len(r.points)]
		if available(p.ep, exclude, now) {
			return p.ep
		}
		seen++
	}
	// Ring walk found nothing among the first len(eps) distinct points;
	// scan linearly as a last resort.
	for _, e := range eps {
		if available(e, exclude, now) {
			return e
		}
	}
	return nil
}
