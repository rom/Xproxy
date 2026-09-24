package upstream

import (
	"math"
	"math/rand/v2"
	"time"
)

// Two balancers that read what the endpoints are doing rather than only
// counting turns.
//
// least_conn already does some of that, but it scans every endpoint and
// takes the best, which has a failure mode of its own: every proxy in a
// fleet sees the same "best" endpoint at the same moment and they all
// send to it together, so the herd moves from one endpoint to the next.
//
// p2c avoids that by choosing two endpoints at random and taking the
// better of those. One comparison is enough to avoid the worst endpoint,
// and the randomness means two proxies rarely agree on where to send, so
// the load spreads instead of sloshing. It is the default choice for a
// pool whose endpoints are equal and whose load varies.
//
// ewma goes further and reads latency instead of depth: an endpoint that
// is answering slowly gets less work long before it is slow enough to
// fail a health check or be ejected. That is the difference between
// shedding load away from a struggling machine and waiting for it to
// break.

// p2c is power of two choices over the in-flight count, weighted.
type p2c struct{ rnd func(int) int }

func newP2C() *p2c { return &p2c{rnd: rand.IntN} }

func (b *p2c) pick(eps []*Endpoint, _ string, exclude map[*Endpoint]bool, now time.Time) *Endpoint {
	avail := make([]*Endpoint, 0, len(eps))
	for _, e := range eps {
		if available(e, exclude, now) {
			avail = append(avail, e)
		}
	}
	switch len(avail) {
	case 0:
		return nil
	case 1:
		return avail[0]
	}
	i := b.rnd(len(avail))
	j := b.rnd(len(avail) - 1)
	if j >= i {
		j++ // a different endpoint, without rejection sampling
	}
	a, c := avail[i], avail[j]
	if b.load(a, now) <= b.load(c, now) {
		return a
	}
	return c
}

// load is the in-flight count per unit of weight: a weight-3 endpoint
// carrying three requests is as loaded as a weight-1 endpoint carrying
// one.
func (b *p2c) load(e *Endpoint, now time.Time) float64 {
	return float64(e.active.Load()+1) / float64(e.effectiveWeight(now))
}

// ewma weights endpoints by the smoothed time to first byte the pool
// already keeps for outlier detection, times the in-flight count -- the
// product being an estimate of how long a request sent now would take.
//
// An endpoint with no samples yet is treated as the fastest available, so
// a new or recovered endpoint is tried rather than starved by the fact
// that nothing is known about it. Its slow start ramp, where one is
// configured, is what keeps that from being a flood.
type ewma struct{ rnd func(int) int }

func newEWMA() *ewma { return &ewma{rnd: rand.IntN} }

func (b *ewma) pick(eps []*Endpoint, _ string, exclude map[*Endpoint]bool, now time.Time) *Endpoint {
	var best *Endpoint
	bestCost := math.Inf(1)
	ties := 0
	for _, e := range eps {
		if !available(e, exclude, now) {
			continue
		}
		cost := b.cost(e, now)
		switch {
		case cost < bestCost:
			best, bestCost, ties = e, cost, 1
		case cost == bestCost:
			// Among endpoints nothing distinguishes -- which is every
			// endpoint of a quiet pool, all at cost zero -- pick
			// uniformly, or the first one would take everything.
			ties++
			if b.rnd(ties) == 0 {
				best = e
			}
		}
	}
	return best
}

// cost estimates the time a request sent to e now would take: the
// smoothed latency times the queue it would join. An endpoint with no
// latency sample costs nothing, so it is tried.
func (b *ewma) cost(e *Endpoint, now time.Time) float64 {
	lat := e.latencyNS()
	if lat <= 0 {
		return 0
	}
	return lat * float64(e.active.Load()+1) / float64(e.effectiveWeight(now))
}
