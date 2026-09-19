package waf

import (
	"hash/fnv"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/config"
)

// Behavioural anomaly detection looks at clients rather than requests.
// The rules and the CRS anomaly score decide whether one request looks
// like an attack; this tracker decides whether a client behaves unlike
// the rest of the population over a window: it sends far more requests,
// trips rules or receives errors far more often, or spreads its
// requests over far more distinct paths (scanning) than its peers.
//
// Every WAF protected request is attributed to its client address in a
// sharded table. When the window ends, each client with at least
// min_requests becomes a feature vector; the population's mean and
// variance per feature form the baseline (an exponentially weighted
// average over windows, so the baseline follows slow drift but not one
// burst). A client whose largest positive z-score against the previous
// baseline reaches the threshold is flagged and its next requests are
// logged, challenged or blocked, until a later window scores it normal
// or it stays away for three windows.

const (
	anomalyShards   = 64
	anomalyFeatures = 4
	// maxClientPaths bounds the distinct paths remembered per client.
	maxClientPaths = 64
	// minPopulation is the number of scored clients a window needs before
	// anyone is compared against the others.
	minPopulation = 8
	// baselineWeight is the share of the newest window in the baseline.
	baselineWeight = 0.3
	// flagWindows is how many windows a flag survives without a verdict.
	flagWindows = 3
	// maxReportedFlags bounds the flagged clients listed in the report.
	maxReportedFlags = 100
)

// featureNames name the vector positions; featureFloor is the smallest
// standard deviation used per feature, so that a homogeneous population
// does not turn tiny differences into large z-scores.
var (
	featureNames = [anomalyFeatures]string{"rate", "match_ratio", "error_ratio", "path_spread"}
	featureFloor = [anomalyFeatures]float64{0.5, 0.05, 0.05, 0.05}
)

type anomalyConfig struct {
	enabled     bool
	window      time.Duration
	minRequests int
	threshold   float64
	action      string
	maxClients  int
}

// anomaly is the tracker; one lives in Stats for the process lifetime.
type anomaly struct {
	now func() time.Time
	cfg atomic.Pointer[anomalyConfig]

	windowStart atomic.Int64
	rollMu      sync.Mutex
	shards      [anomalyShards]anomalyShard
	clients     atomic.Int64
	dropped     bound.Notice

	baseline atomic.Pointer[baseline]
	flags    sync.Map // client -> *flag
	flagged  atomic.Int64

	windows      atomic.Uint64
	flaggedTotal atomic.Uint64
	acted        atomic.Uint64
}

type anomalyShard struct {
	mu      sync.Mutex
	clients map[string]*clientWindow
}

// clientWindow is one client's counters in the current window.
type clientWindow struct {
	requests uint64
	matched  uint64
	errors   uint64
	paths    map[string]struct{}
}

// baseline is the population statistics per feature.
type baseline struct {
	mean     [anomalyFeatures]float64
	variance [anomalyFeatures]float64
	windows  int
	// scored is the number of clients scored in the last window.
	scored int
}

// flag is a flagged client.
type flag struct {
	client  string
	score   float64
	feature string
	value   float64
	mean    float64
	since   time.Time
	expires time.Time
}

func (a *anomaly) init(now func() time.Time) {
	a.now = now
	a.windowStart.Store(now().UnixNano())
	for i := range a.shards {
		a.shards[i].clients = map[string]*clientWindow{}
	}
}

// configure applies a generation's settings.
func (a *anomaly) configure(c *config.WAFAnomaly) {
	if c == nil || !c.Enabled {
		a.cfg.Store(&anomalyConfig{})
		return
	}
	a.cfg.Store(&anomalyConfig{enabled: true, window: c.Window.D(), minRequests: c.MinRequests, threshold: c.Threshold,
		action: c.Action, maxClients: c.MaxClients})
}

func (a *anomaly) config() *anomalyConfig {
	if c := a.cfg.Load(); c != nil {
		return c
	}
	return &anomalyConfig{}
}

// reset clears the window, the baseline and the flags.
func (a *anomaly) reset() {
	a.rollMu.Lock()
	defer a.rollMu.Unlock()
	a.clear()
	a.baseline.Store(nil)
	a.flags.Range(func(k, _ any) bool { a.flags.Delete(k); return true })
	a.flagged.Store(0)
	a.windows.Store(0)
	a.flaggedTotal.Store(0)
	a.acted.Store(0)
	a.windowStart.Store(a.now().UnixNano())
}

func (a *anomaly) clear() {
	for i := range a.shards {
		sh := &a.shards[i]
		sh.mu.Lock()
		sh.clients = map[string]*clientWindow{}
		sh.mu.Unlock()
	}
	a.clients.Store(0)
}

func shardOf(client string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(client))
	return int(h.Sum32() % anomalyShards)
}

// lookup returns the flag of a client, nil when it is not flagged (or
// the flag expired).
func (a *anomaly) lookup(client string) *flag {
	c := a.config()
	if !c.enabled {
		return nil
	}
	v, ok := a.flags.Load(client)
	if !ok {
		return nil
	}
	f := v.(*flag)
	if a.now().After(f.expires) {
		if _, loaded := a.flags.LoadAndDelete(client); loaded {
			a.flagged.Add(-1)
		}
		return nil
	}
	return f
}

// observe attributes one finished request to its client.
func (a *anomaly) observe(client, path string, matched, errored bool, now time.Time) {
	c := a.config()
	if !c.enabled {
		return
	}
	if now.Sub(time.Unix(0, a.windowStart.Load())) >= c.window {
		a.maybeRoll(c, now)
	}
	sh := &a.shards[shardOf(client)]
	sh.mu.Lock()
	cw := sh.clients[client]
	if cw == nil {
		if a.clients.Load() >= int64(c.maxClients) {
			sh.mu.Unlock()
			a.dropped.Hit(nil, "waf anomaly tracker full; further clients are not scored this window", "table", "waf_anomaly", "max", c.maxClients)
			return
		}
		cw = &clientWindow{paths: map[string]struct{}{}}
		sh.clients[client] = cw
		a.clients.Add(1)
	}
	cw.requests++
	if matched {
		cw.matched++
	}
	if errored {
		cw.errors++
	}
	if len(cw.paths) < maxClientPaths {
		cw.paths[path] = struct{}{}
	}
	sh.mu.Unlock()
}

func (a *anomaly) maybeRoll(c *anomalyConfig, now time.Time) {
	a.rollMu.Lock()
	defer a.rollMu.Unlock()
	start := time.Unix(0, a.windowStart.Load())
	if now.Sub(start) < c.window {
		return
	}
	a.roll(c, now, now.Sub(start))
	a.windowStart.Store(now.UnixNano())
}

// sample is one client's feature vector.
type sample struct {
	client   string
	features [anomalyFeatures]float64
}

// features turns a client's window into its vector.
func (cw *clientWindow) features(elapsed time.Duration) [anomalyFeatures]float64 {
	n := float64(cw.requests)
	minutes := math.Max(elapsed.Minutes(), 1.0/60)
	return [anomalyFeatures]float64{
		math.Log2(1 + n/minutes),
		float64(cw.matched) / n,
		float64(cw.errors) / n,
		float64(len(cw.paths)) / math.Min(n, maxClientPaths),
	}
}

// roll closes the window: scores the clients against the baseline,
// updates the baseline and clears the table. Called with rollMu held.
func (a *anomaly) roll(c *anomalyConfig, now time.Time, elapsed time.Duration) {
	var samples []sample
	for i := range a.shards {
		sh := &a.shards[i]
		sh.mu.Lock()
		for client, cw := range sh.clients {
			if cw.requests >= uint64(c.minRequests) { //nolint:gosec // validated positive
				samples = append(samples, sample{client: client, features: cw.features(elapsed)})
			}
		}
		sh.clients = map[string]*clientWindow{}
		sh.mu.Unlock()
	}
	a.clients.Store(0)
	a.windows.Add(1)
	a.expire(now)
	if len(samples) < minPopulation {
		return
	}
	var mean, variance [anomalyFeatures]float64
	for _, s := range samples {
		for i, x := range s.features {
			mean[i] += x
		}
	}
	for i := range mean {
		mean[i] /= float64(len(samples))
	}
	for _, s := range samples {
		for i, x := range s.features {
			d := x - mean[i]
			variance[i] += d * d
		}
	}
	for i := range variance {
		variance[i] /= float64(len(samples))
	}
	prev := a.baseline.Load()
	if prev != nil {
		for _, s := range samples {
			a.score(c, prev, s, now)
		}
	}
	next := &baseline{windows: 1, scored: len(samples)}
	if prev == nil {
		next.mean, next.variance = mean, variance
	} else {
		next.windows = prev.windows + 1
		for i := range mean {
			next.mean[i] = (1-baselineWeight)*prev.mean[i] + baselineWeight*mean[i]
			next.variance[i] = (1-baselineWeight)*prev.variance[i] + baselineWeight*variance[i]
		}
	}
	a.baseline.Store(next)
}

// score compares one client with the baseline and flags or clears it.
func (a *anomaly) score(c *anomalyConfig, b *baseline, s sample, now time.Time) {
	best, bestI := 0.0, -1
	for i, x := range s.features {
		sd := math.Max(math.Sqrt(b.variance[i]), featureFloor[i])
		z := (x - b.mean[i]) / sd
		if z > best {
			best, bestI = z, i
		}
	}
	if bestI < 0 || best < c.threshold {
		if _, loaded := a.flags.LoadAndDelete(s.client); loaded {
			a.flagged.Add(-1)
		}
		return
	}
	f := &flag{client: s.client, score: best, feature: featureNames[bestI], value: s.features[bestI], mean: b.mean[bestI],
		since: now, expires: now.Add(time.Duration(flagWindows) * c.window)}
	if v, ok := a.flags.Load(s.client); ok {
		f.since = v.(*flag).since
		a.flags.Store(s.client, f)
		return
	}
	a.flags.Store(s.client, f)
	a.flagged.Add(1)
	a.flaggedTotal.Add(1)
}

// expire drops flags whose client has not been scored for flagWindows.
func (a *anomaly) expire(now time.Time) {
	a.flags.Range(func(k, v any) bool {
		if now.After(v.(*flag).expires) {
			if _, loaded := a.flags.LoadAndDelete(k); loaded {
				a.flagged.Add(-1)
			}
		}
		return true
	})
}

// AnomalyReport is the management view of the detector.
type AnomalyReport struct {
	Enabled     bool    `json:"enabled"`
	Window      string  `json:"window,omitempty"`
	MinRequests int     `json:"min_requests,omitempty"`
	Threshold   float64 `json:"threshold,omitempty"`
	Action      string  `json:"action,omitempty"`
	// Clients is the number tracked in the current window; Dropped counts
	// clients the full table could not track.
	Clients    int    `json:"clients"`
	MaxClients int    `json:"max_clients,omitempty"`
	Dropped    uint64 `json:"dropped,omitempty"`
	// Windows counts closed windows; Scored is the number of clients the
	// last closed window compared.
	Windows uint64 `json:"windows"`
	Scored  int    `json:"scored"`
	// Flagged is the number of clients currently flagged; FlaggedTotal
	// counts flags raised since the last reset and Acted the requests of
	// flagged clients logged, challenged or blocked.
	Flagged      int               `json:"flagged"`
	FlaggedTotal uint64            `json:"flagged_total"`
	Acted        uint64            `json:"acted"`
	Baseline     []FeatureBaseline `json:"baseline,omitempty"`
	Top          []ClientAnomaly   `json:"top"`
}

// FeatureBaseline is the population statistic of one feature.
type FeatureBaseline struct {
	Feature string  `json:"feature"`
	Mean    float64 `json:"mean"`
	StdDev  float64 `json:"stddev"`
}

// ClientAnomaly is one flagged client.
type ClientAnomaly struct {
	Client  string    `json:"client"`
	Score   float64   `json:"score"`
	Feature string    `json:"feature"`
	Value   float64   `json:"value"`
	Mean    float64   `json:"mean"`
	Since   time.Time `json:"since"`
	Expires time.Time `json:"expires"`
}

func (a *anomaly) report() *AnomalyReport {
	c := a.config()
	rep := &AnomalyReport{Enabled: c.enabled, Top: []ClientAnomaly{}}
	if !c.enabled {
		return rep
	}
	rep.Window, rep.MinRequests, rep.Threshold, rep.Action, rep.MaxClients = c.window.String(), c.minRequests, c.threshold, c.action, c.maxClients
	rep.Clients = int(a.clients.Load())
	rep.Dropped = a.dropped.Total()
	rep.Windows = a.windows.Load()
	rep.Flagged = int(a.flagged.Load())
	rep.FlaggedTotal = a.flaggedTotal.Load()
	rep.Acted = a.acted.Load()
	if b := a.baseline.Load(); b != nil {
		rep.Scored = b.scored
		for i, name := range featureNames {
			rep.Baseline = append(rep.Baseline, FeatureBaseline{Feature: name, Mean: round(b.mean[i]), StdDev: round(math.Sqrt(b.variance[i]))})
		}
	}
	now := a.now()
	a.flags.Range(func(_, v any) bool {
		f := v.(*flag)
		if now.After(f.expires) {
			return true
		}
		rep.Top = append(rep.Top, ClientAnomaly{Client: f.client, Score: round(f.score), Feature: f.feature, Value: round(f.value), Mean: round(f.mean), Since: f.since, Expires: f.expires})
		return true
	})
	sort.Slice(rep.Top, func(i, j int) bool {
		if rep.Top[i].Score != rep.Top[j].Score {
			return rep.Top[i].Score > rep.Top[j].Score
		}
		return rep.Top[i].Client < rep.Top[j].Client
	})
	if len(rep.Top) > maxReportedFlags {
		rep.Top = rep.Top[:maxReportedFlags]
	}
	return rep
}

func round(f float64) float64 { return math.Round(f*1000) / 1000 }
