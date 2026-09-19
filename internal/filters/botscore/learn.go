package botscore

import (
	"math"
	"sort"
	"sync"
)

// Learning mode. When enabled, a bot_score filter records the distribution
// of scores it computes per route without acting on it, and the management
// API turns that into per-endpoint baselines and suggested challenge and
// deny thresholds. An operator watches the suggestions, then sets
// challenge_at and deny_at deliberately, so a threshold is tuned to the
// route's real traffic rather than guessed.

const maxLearnRoutes = 4096

// baseline is the score histogram of one route. Scores are 0..100, kept in
// eleven ten-wide buckets (the last holds exactly 100).
type baseline struct {
	count   int64
	buckets [11]int64
	max     int
}

func (b *baseline) add(score int) {
	b.count++
	idx := score / 10
	if idx > 10 {
		idx = 10
	}
	b.buckets[idx]++
	if score > b.max {
		b.max = score
	}
}

// percentile returns the upper bound of the bucket at fraction p, so it is
// a conservative (rounded-up to the next ten) estimate of the percentile.
func (b *baseline) percentile(p float64) int {
	if b.count == 0 {
		return 0
	}
	target := int64(math.Ceil(p * float64(b.count)))
	var cum int64
	for i := 0; i <= 10; i++ {
		cum += b.buckets[i]
		if cum >= target {
			if hi := (i + 1) * 10; hi < 100 {
				return hi
			}
			return 100
		}
	}
	return 100
}

// shareAtLeast is the fraction of samples scoring at or above threshold.
func (b *baseline) shareAtLeast(threshold int) float64 {
	if b.count == 0 || threshold <= 0 {
		return 0
	}
	var n int64
	for i := 0; i <= 10; i++ {
		// Bucket i covers scores [i*10, i*10+9], except bucket 10 which is
		// exactly 100. Count a bucket when its whole range is >= threshold.
		if i*10 >= threshold {
			n += b.buckets[i]
		}
	}
	return float64(n) / float64(b.count)
}

// learnReg holds the live scorers running in learning mode.
var learnReg = struct {
	mu      sync.Mutex
	scorers map[*scorer]struct{}
}{scorers: map[*scorer]struct{}{}}

func registerLearn(s *scorer) {
	learnReg.mu.Lock()
	learnReg.scorers[s] = struct{}{}
	learnReg.mu.Unlock()
}

// Close unregisters the scorer when its generation is torn down.
func (s *scorer) Close() error {
	learnReg.mu.Lock()
	delete(learnReg.scorers, s)
	learnReg.mu.Unlock()
	return nil
}

// recordBaseline adds one observed score for a route.
func (s *scorer) recordBaseline(route string, score int) {
	if route == "" {
		route = "-"
	}
	s.lmu.Lock()
	b := s.routes[route]
	if b == nil {
		if len(s.routes) >= maxLearnRoutes {
			s.lmu.Unlock()
			return
		}
		b = &baseline{}
		s.routes[route] = b
	}
	b.add(score)
	s.lmu.Unlock()
}

// Report is the management view of learning-mode baselines.
type Report struct {
	Enabled bool             `json:"enabled"`
	Filters []FilterBaseline `json:"filters"`
}

// FilterBaseline is one bot_score filter's baselines and its current
// thresholds.
type FilterBaseline struct {
	Filter      string             `json:"filter"`
	ChallengeAt int                `json:"challenge_at"`
	DenyAt      int                `json:"deny_at"`
	Endpoints   []EndpointBaseline `json:"endpoints"`
}

// EndpointBaseline is one route's score distribution and suggestions.
type EndpointBaseline struct {
	Route              string  `json:"route"`
	Samples            int64   `json:"samples"`
	P50                int     `json:"p50"`
	P95                int     `json:"p95"`
	P99                int     `json:"p99"`
	Max                int     `json:"max"`
	SuggestChallengeAt int     `json:"suggest_challenge_at"`
	SuggestDenyAt      int     `json:"suggest_deny_at"`
	WouldChallengePct  float64 `json:"would_challenge_pct"`
	WouldDenyPct       float64 `json:"would_deny_pct"`
}

// Status returns the baselines of every learning-mode bot_score filter,
// listing up to top routes per filter by sample count.
func Status(top int) Report {
	learnReg.mu.Lock()
	scorers := make([]*scorer, 0, len(learnReg.scorers))
	for s := range learnReg.scorers {
		scorers = append(scorers, s)
	}
	learnReg.mu.Unlock()

	rep := Report{Enabled: len(scorers) > 0}
	for _, s := range scorers {
		fb := FilterBaseline{Filter: s.name, ChallengeAt: s.cfg.ChallengeAt, DenyAt: s.cfg.DenyAt}
		s.lmu.Lock()
		for route, b := range s.routes {
			eb := EndpointBaseline{
				Route: route, Samples: b.count,
				P50: b.percentile(0.50), P95: b.percentile(0.95), P99: b.percentile(0.99), Max: b.max,
			}
			eb.SuggestDenyAt, eb.SuggestChallengeAt = suggestThresholds(eb.P95, eb.P99)
			eb.WouldChallengePct = round1(b.shareAtLeast(s.cfg.ChallengeAt) * 100)
			eb.WouldDenyPct = round1(b.shareAtLeast(s.cfg.DenyAt) * 100)
			fb.Endpoints = append(fb.Endpoints, eb)
		}
		s.lmu.Unlock()
		sort.Slice(fb.Endpoints, func(i, j int) bool { return fb.Endpoints[i].Samples > fb.Endpoints[j].Samples })
		if top > 0 && len(fb.Endpoints) > top {
			fb.Endpoints = fb.Endpoints[:top]
		}
		rep.Filters = append(rep.Filters, fb)
	}
	sort.Slice(rep.Filters, func(i, j int) bool { return rep.Filters[i].Filter < rep.Filters[j].Filter })
	return rep
}

// suggestThresholds proposes a deny threshold above the bulk of traffic
// (the 99th percentile) and a challenge threshold at the 95th, kept below
// deny. Both stay within 10..100.
func suggestThresholds(p95, p99 int) (denyAt, challengeAt int) {
	denyAt = clampThreshold(p99)
	if denyAt < 20 {
		denyAt = 20 // never suggest denying almost everything
	}
	challengeAt = clampThreshold(p95)
	if challengeAt >= denyAt {
		challengeAt = denyAt - 10
	}
	if challengeAt < 10 {
		challengeAt = 10
	}
	return denyAt, challengeAt
}

func clampThreshold(v int) int {
	if v < 10 {
		return 10
	}
	if v > 100 {
		return 100
	}
	return v
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
