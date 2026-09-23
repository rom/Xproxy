package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/h3"
	"github.com/rom/xproxy/internal/tlsconf"
)

// Pool is a named, load balanced set of endpoints with a shared transport.
type Pool struct {
	Name      string
	Cfg       *config.Upstream
	Transport *http.Transport
	// h2c carries HTTP/2 without TLS when the upstream sets h2c.
	h2c *http.Transport
	// h3 carries HTTP/3 when the upstream sets h3; H3Fallbacks counts
	// requests retried over TCP after a QUIC failure.
	h3          *h3.ClientTransport
	H3Fallbacks atomic.Uint64
	Scheme      string

	// eps is the current endpoint set; discovery replaces it atomically.
	eps       atomic.Pointer[[]*Endpoint]
	epMu      sync.Mutex // set changes and index allocation
	nextIndex int
	bal       atomic.Pointer[balHolder]
	aff       *affinity
	// clientCert is the reloadable mTLS client certificate, or nil.
	clientCert *tlsconf.ClientReloadable
	log        *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup
	now    func() time.Time
	// hcSem bounds health probes in flight (HealthCheck.MaxConcurrent).
	hcSem chan struct{}
	// hcTransport carries probes: the pool transport with keep_alive, or a
	// dedicated one that opens a fresh connection per probe.
	hcTransport *http.Transport
	// hcBodyRE is the compiled health_check.body_regex.
	hcBodyRE *regexp.Regexp
	// breaker, gate and canary are nil when not configured.
	breaker *Breaker
	gate    *Gate
	canary  *canaryState
	// budget bounds retries against live traffic; nil without a configured
	// retry_budget.
	budget *retryBudget
	// disc is nil without a discovery section; hcCtx is the health check
	// context once Start ran, used for endpoints added later.
	disc  *discoverer
	hcCtx context.Context
	// randFloat feeds the slow start admission; tests replace it.
	randFloat func() float64
}

// balHolder wraps the balancer interface for atomic replacement.
type balHolder struct{ b balancer }

// endpoints returns the current endpoint set (read only).
func (p *Pool) endpoints() []*Endpoint {
	if e := p.eps.Load(); e != nil {
		return *e
	}
	return nil
}

func (p *Pool) balancer() balancer { return p.bal.Load().b }

// newBalancer builds the configured balancer for eps.
func (p *Pool) newBalancer(eps []*Endpoint) balancer {
	switch p.Cfg.Balancer {
	case "weighted":
		return &weighted{}
	case "least_conn":
		return &leastConn{}
	case "hash":
		return newRing(eps)
	default:
		return &roundRobin{}
	}
}

// newEndpoint creates an endpoint with a pool-unique index. Caller holds
// epMu.
func (p *Pool) newEndpoint(address string, weight int, canary, discovered bool) *Endpoint {
	ep := &Endpoint{Address: address, Weight: weight, Canary: canary, Discovered: discovered, index: p.nextIndex, slowStart: p.Cfg.SlowStart.D()}
	if path, ok := SocketPath(address); ok {
		ep.socket, ep.urlHost = path, urlAuthority(path)
	}
	p.nextIndex++
	// Without active checks every endpoint starts healthy. With checks,
	// endpoints start healthy too so that a restart does not drop all
	// traffic until the first probe; the first failed probe ejects.
	ep.healthy.Store(true)
	return ep
}

// setDiscovered replaces the discovered endpoints with specs, keeping the
// static ones and the objects (and statistics) of addresses that stay.
// New endpoints start a slow start ramp and, once Start ran, a health
// loop; removed ones lose their loop. Returns the numbers added and
// removed.
func (p *Pool) setDiscovered(specs []endpointSpec) (added, removed int) {
	p.epMu.Lock()
	defer p.epMu.Unlock()
	now := p.now()
	old := p.endpoints()
	byAddr := map[string]*Endpoint{}
	for _, e := range old {
		byAddr[e.Address] = e
	}
	next := make([]*Endpoint, 0, len(old)+len(specs))
	keep := map[*Endpoint]bool{}
	for _, e := range old {
		if !e.Discovered {
			next = append(next, e)
			keep[e] = true
		}
	}
	for _, sp := range specs {
		if e, ok := byAddr[sp.address]; ok {
			if !keep[e] {
				e.Weight, e.Canary = sp.weight, sp.canary
				next = append(next, e)
				keep[e] = true
			}
			continue
		}
		e := p.newEndpoint(sp.address, sp.weight, sp.canary, true)
		e.startRamp(now)
		next = append(next, e)
		keep[e] = true
		added++
		if p.hcCtx != nil && p.Cfg.HealthCheck != nil {
			p.startHealthLoop(e)
		}
	}
	for _, e := range old {
		if !keep[e] {
			removed++
			if e.cancel != nil {
				e.cancel()
			}
		}
	}
	if added+removed == 0 {
		return 0, 0
	}
	p.eps.Store(&next)
	if p.Cfg.Balancer == "hash" {
		p.bal.Store(&balHolder{b: newRing(next)})
	}
	if c := p.canary; c != nil {
		n := 0
		for _, e := range next {
			if e.Canary {
				n++
			}
		}
		c.count = n
	}
	return added, removed
}

// startHealthLoop launches the probe loop of one endpoint under the pool's
// health context.
func (p *Pool) startHealthLoop(e *Endpoint) {
	ctx, cancel := context.WithCancel(p.hcCtx)
	e.cancel = cancel
	p.wg.Add(1)
	go p.healthLoop(ctx, e)
}

// Breaker returns the circuit breaker, or nil.
func (p *Pool) Breaker() *Breaker { return p.breaker }

// Gate returns the concurrency gate, or nil.
func (p *Pool) Gate() *Gate { return p.gate }

// Status returns the pool level management view.
func (p *Pool) Status() PoolStatus {
	now := p.now()
	eps := p.endpoints()
	st := PoolStatus{Name: p.Name, Balancer: p.Cfg.Balancer, Endpoints: len(eps), Protocol: "tcp", H3Fallbacks: p.H3Fallbacks.Load()}
	switch {
	case p.h3 != nil:
		st.Protocol = "h3"
	case p.h2c != nil:
		st.Protocol = "h2c"
	}
	if p.Cfg.SlowStart > 0 {
		st.SlowStart = p.Cfg.SlowStart.D().String()
	}
	if p.disc != nil {
		st.Discovery = p.disc.status()
	}
	for _, e := range eps {
		if e.Available(now) {
			st.Available++
		}
		st.Active += e.active.Load()
	}
	if p.breaker != nil {
		c := p.breaker.Status()
		st.Circuit = &c
	}
	if p.gate != nil {
		q := p.gate.Status()
		st.Queue = &q
	}
	if c := p.canary; c != nil {
		st.Canary = &CanaryStatus{Header: c.header, Cookie: c.cookie, Percent: c.percent, Endpoints: c.count,
			Requests: c.requests.Load(), Fallbacks: c.fallbacks.Load()}
	}
	return st
}

// NewPool builds a pool from configuration. Call Start to begin health
// checks and Stop to release resources.
func NewPool(cfg *config.Upstream, log *slog.Logger) (*Pool, error) {
	p := &Pool{Name: cfg.Name, Cfg: cfg, Scheme: cfg.Scheme, log: log.With("upstream", cfg.Name), now: time.Now, randFloat: rand.Float64}
	eps := make([]*Endpoint, 0, len(cfg.Endpoints))
	for _, e := range cfg.Endpoints {
		eps = append(eps, p.newEndpoint(e.Address, e.Weight, e.Canary, false))
	}
	p.eps.Store(&eps)
	p.bal.Store(&balHolder{b: p.newBalancer(eps)})
	if cfg.Discovery != nil {
		p.disc = newDiscoverer(cfg.Discovery, p)
	}
	if cfg.CircuitBreaker != nil {
		p.breaker = newBreaker(cfg.CircuitBreaker, p.now)
	}
	if b := cfg.RetryBudget; b != nil {
		p.budget = newRetryBudget(b.Percent, b.MinConcurrency)
	}
	if c := cfg.Canary; c != nil {
		cs := &canaryState{header: http.CanonicalHeaderKey(c.Header), cookie: c.Cookie, percent: c.Percent,
			fallback: c.Fallback == nil || *c.Fallback, values: map[string]bool{}}
		for _, v := range c.Values {
			cs.values[v] = true
		}
		for _, e := range eps {
			if e.Canary {
				cs.count++
			}
		}
		p.canary = cs
	}
	if cfg.MaxConcurrent > 0 {
		size, timeout := 0, time.Duration(0)
		if cfg.Queue != nil {
			size, timeout = cfg.Queue.Size, cfg.Queue.Timeout.D()
		}
		p.gate = newGate(cfg.MaxConcurrent, size, timeout)
	}
	if cfg.Affinity != nil {
		a, err := newAffinity(cfg.Affinity.CookieName, cfg.Affinity.TTL.D(), cfg.Affinity.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", cfg.Name, err)
		}
		p.aff = a
	}
	var tc *tls.Config
	if cfg.Scheme == "https" {
		var err error
		tc, p.clientCert, err = tlsconf.Client(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", cfg.Name, err)
		}
	}
	dialer := &net.Dialer{Timeout: cfg.Timeouts.Connect.D(), KeepAlive: 30 * time.Second}
	// A socket endpoint's URL carries a synthetic authority, so the
	// dialler is the one place that knows a request is going to a path
	// rather than to a host. Anything that is not a known authority is
	// dialled as it arrives, which is every ordinary endpoint.
	sockets := map[string]string{}
	for _, e := range cfg.Endpoints {
		if path, ok := SocketPath(e.Address); ok {
			sockets[urlAuthority(path)] = path
		}
	}
	dial := dialer.DialContext
	if len(sockets) > 0 {
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			if path, ok := sockets[address]; ok {
				return dialer.DialContext(ctx, "unix", path)
			}
			return dialer.DialContext(ctx, network, address)
		}
	}
	p.Transport = &http.Transport{
		Proxy:                  nil, // never honour HTTP_PROXY from the environment
		DialContext:            dial,
		TLSClientConfig:        tc,
		ForceAttemptHTTP2:      cfg.Scheme == "https",
		MaxIdleConns:           cfg.MaxIdleConnsPerHost * max(len(cfg.Endpoints), 1),
		MaxIdleConnsPerHost:    cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:        cfg.Timeouts.Idle.D(),
		TLSHandshakeTimeout:    cfg.Timeouts.Connect.D(),
		ResponseHeaderTimeout:  cfg.Timeouts.ResponseHeader.D(),
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true, // pass encodings through untouched
	}
	if cfg.H3 {
		p.h3 = h3.NewClientTransport(h3.ClientOptions{TLS: tc, Handshake: cfg.Timeouts.Connect.D(), Idle: cfg.Timeouts.Idle.D(), ResponseHeader: cfg.Timeouts.ResponseHeader.D()})
	}
	if cfg.H2C {
		// Prior knowledge HTTP/2 over plain TCP: the same transport
		// settings with only the unencrypted HTTP/2 protocol enabled.
		t := p.Transport.Clone()
		t.Protocols = new(http.Protocols)
		t.Protocols.SetUnencryptedHTTP2(true)
		t.HTTP2 = &http.HTTP2Config{SendPingTimeout: cfg.Timeouts.Connect.D(), PingTimeout: cfg.Timeouts.Connect.D()}
		p.h2c = t
	}
	if hc := cfg.HealthCheck; hc != nil {
		if hc.KeepAlive || cfg.H3 {
			p.hcTransport = p.Transport
		} else {
			t := p.Transport.Clone()
			t.DisableKeepAlives = true
			t.MaxIdleConns = 0
			t.MaxIdleConnsPerHost = 0
			p.hcTransport = t
		}
	}
	return p, nil
}

// Start launches active health checking and discovery if configured.
// With discovery the first resolution runs synchronously (bounded by the
// discovery timeout) so that the pool serves discovered endpoints from
// its first request.
func (p *Pool) Start() {
	if p.Cfg.HealthCheck == nil && p.disc == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.hcCtx = ctx
	if p.Cfg.HealthCheck != nil {
		p.hcSem = make(chan struct{}, max(p.Cfg.HealthCheck.MaxConcurrent, 1))
		if re := p.Cfg.HealthCheck.BodyRegex; re != "" {
			p.hcBodyRE = regexp.MustCompile(re) // validated
		}
		p.epMu.Lock()
		for _, e := range p.endpoints() {
			p.startHealthLoop(e)
		}
		p.epMu.Unlock()
	}
	if p.disc != nil {
		p.disc.once(ctx)
		p.wg.Add(1)
		go p.disc.run(ctx)
	}
}

// StopChecks ends health checking without touching the transport, so a
// superseded generation stops probing at once while its in-flight requests
// finish.
func (p *Pool) StopChecks() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}

// Stop ends health checks and closes idle connections. Only idle ones:
// the HTTP/3 transport used to be closed outright, which cut every
// exchange still running on it — a long gRPC or SSE stream over h3 —
// when a reload retired the generation that built the pool, while the
// TCP transports beside it dropped only what was unused.
func (p *Pool) Stop() {
	p.StopChecks()
	p.Transport.CloseIdleConnections()
	if p.h2c != nil {
		p.h2c.CloseIdleConnections()
	}
	if p.h3 != nil {
		p.h3.CloseIdleConnections()
	}
}

// Close releases everything the pool holds, in-flight exchanges
// included. It is for process shutdown, where the exchanges have
// already been drained.
func (p *Pool) Close() {
	p.Stop()
	if p.h3 != nil {
		_ = p.h3.Close()
	}
}

// RoundTripper is the transport requests use: HTTP/3 when the upstream
// sets h3, HTTP/2 cleartext when it sets h2c, the ordinary transport
// otherwise.
func (p *Pool) RoundTripper() http.RoundTripper {
	switch {
	case p.h3 != nil:
		return p.h3
	case p.h2c != nil:
		return p.h2c
	}
	return p.Transport
}

// TCPRoundTripper is the TCP transport, the fallback of an h3 pool.
func (p *Pool) TCPRoundTripper() http.RoundTripper {
	if p.h2c != nil {
		return p.h2c
	}
	return p.Transport
}

// H3 reports whether the pool speaks HTTP/3 to its endpoints.
func (p *Pool) H3() bool { return p.h3 != nil }

// H3Fallback reports whether a QUIC failure is retried over TCP.
func (p *Pool) H3Fallback() bool {
	return p.h3 != nil && (p.Cfg.H3Fallback == nil || *p.Cfg.H3Fallback)
}

// H3TLS returns the client TLS configuration of an https pool (nil for
// http), for WebTransport dials.
func (p *Pool) H3TLS() *tls.Config { return p.Transport.TLSClientConfig }

// ReloadClientCertificate re-reads the upstream client certificate, if
// any, and drops idle connections so new ones present it.
func (p *Pool) ReloadClientCertificate() error {
	if p.clientCert == nil {
		return nil
	}
	if err := p.clientCert.Load(); err != nil {
		return fmt.Errorf("upstream %s: %w", p.Name, err)
	}
	p.Transport.CloseIdleConnections()
	if p.h3 != nil {
		p.h3.CloseIdleConnections()
	}
	return nil
}

// Endpoints returns the current endpoints (read only snapshot).
func (p *Pool) Endpoints() []*Endpoint { return p.endpoints() }

// byIndex finds an endpoint by its pool-unique index.
func (p *Pool) byIndex(eps []*Endpoint, i int) *Endpoint {
	for _, e := range eps {
		if e.index == i {
			return e
		}
	}
	return nil
}

// AffinityCookie returns the affinity cookie name, or "".
func (p *Pool) AffinityCookie() string {
	if p.aff == nil {
		return ""
	}
	return p.aff.cookie
}

// Pick selects an endpoint. hashKey feeds the hash balancer; cookie is the
// affinity cookie value from the request, if any. exclude lists endpoints
// already tried; mode applies the canary policy (CanaryAny without one).
// The second result is a fresh cookie value to set on the response, or
// "" when none is needed.
func (p *Pool) Pick(hashKey, cookie string, exclude map[*Endpoint]bool, mode CanaryMode) (*Endpoint, string) {
	now := p.now()
	eps := p.endpoints()
	if p.aff != nil && cookie != "" {
		if i := p.aff.verify(cookie, now); i >= 0 {
			if e := p.byIndex(eps, i); e != nil && available(e, exclude, now) {
				return e, ""
			}
		}
	}
	bal := p.balancer()
	e := bal.pick(eps, hashKey, p.canaryExclude(mode, exclude), now)
	if e == nil && mode != CanaryAny && p.canary != nil && p.canary.fallback {
		// The selected side is empty: the other side takes the request.
		p.canary.fallbacks.Add(1)
		e = bal.pick(eps, hashKey, exclude, now)
	}
	if e == nil {
		return nil, ""
	}
	e = p.slowStartAdmit(bal, eps, e, hashKey, exclude, mode, now)
	if e.Canary && p.canary != nil {
		p.canary.requests.Add(1)
	}
	if p.aff != nil {
		return e, p.aff.issue(e.index, now)
	}
	return e, ""
}

// slowStartAdmit applies the slow start ramp to balancers that do not
// weigh endpoints (round robin, hash): a ramping endpoint keeps a pick
// with probability ramp, otherwise the balancer picks again among the
// others, at most twice; when nothing else is available it keeps it.
func (p *Pool) slowStartAdmit(bal balancer, eps []*Endpoint, e *Endpoint, hashKey string, exclude map[*Endpoint]bool, mode CanaryMode, now time.Time) *Endpoint {
	if p.Cfg.SlowStart <= 0 || p.Cfg.Balancer == "weighted" || p.Cfg.Balancer == "least_conn" {
		return e
	}
	for tries := 0; tries < 2; tries++ {
		f := e.ramp(now)
		if f >= 1 || p.randFloat() < f {
			return e
		}
		ex := make(map[*Endpoint]bool, len(exclude)+tries+1)
		for k, v := range exclude {
			ex[k] = v
		}
		ex[e] = true
		alt := bal.pick(eps, hashKey, p.canaryExclude(mode, ex), now)
		if alt == nil {
			return e
		}
		e = alt
	}
	return e
}

// Begin marks a request in flight on e.
func (p *Pool) Begin(e *Endpoint) {
	e.active.Add(1)
	e.requests.Add(1)
}

// End records the outcome of a request on e. A failure is a transport level
// error or a 5xx if the outlier policy counts those. latency is the time
// to the response headers (or to the failure); 0 records no sample.
func (p *Pool) End(e *Endpoint, failed bool, latency time.Duration) {
	e.active.Add(-1)
	oe := p.Cfg.OutlierEjection
	if latency > 0 && oe != nil && (oe.LatencyThreshold > 0 || oe.LatencyFactor > 0) {
		p.observeLatency(e, latency)
	}
	if !failed {
		e.failures.Store(0)
		return
	}
	e.errors.Add(1)
	if oe == nil {
		return
	}
	if n := e.failures.Add(1); n >= int64(oe.ConsecutiveFailures) {
		if p.eject(e, "failures") {
			e.failures.Store(0)
		}
	}
}

// eject takes e out of rotation for the base time times its ejection
// count (capped at ten), within max_ejection_percent.
func (p *Pool) eject(e *Endpoint, why string) bool {
	oe := p.Cfg.OutlierEjection
	if !p.canEject() {
		return false
	}
	e.ejections.Add(1)
	mult := int64(min(e.ejections.Load(), 10)) //nolint:gosec // capped at 10
	until := p.now().Add(oe.BaseEjectionTime.D() * time.Duration(mult))
	e.ejectedNS.Store(until.UnixNano())
	if e.slowStart > 0 {
		e.readyNS.Store(until.UnixNano()) // ramp from the moment the ejection ends
	}
	e.resetLatency() // judged afresh when it returns
	p.log.Warn("endpoint ejected", "endpoint", e.Address, "reason", why, "until", until)
	return true
}

// observeLatency folds a sample into the endpoint's moving average and
// ejects the endpoint when it is slow by the absolute threshold or
// relative to the other endpoints of the pool.
func (p *Pool) observeLatency(e *Endpoint, d time.Duration) {
	oe := p.Cfg.OutlierEjection
	avg, n := e.observeLatency(d)
	if n < int64(oe.LatencyMinSamples) || e.ejectedNS.Load() > p.now().UnixNano() {
		return
	}
	slow := oe.LatencyThreshold > 0 && avg > float64(oe.LatencyThreshold)
	ref := 0.0
	if !slow && oe.LatencyFactor > 0 {
		ref = p.peerLatency(e)
		slow = ref > 0 && avg > oe.LatencyFactor*ref
	}
	if slow && p.eject(e, "latency") {
		e.latencyEjections.Add(1)
		p.log.Warn("endpoint slow", "endpoint", e.Address, "latency_ms", math.Round(avg/1e6), "peers_ms", math.Round(ref/1e6))
	}
}

// peerLatency is the mean smoothed latency of the other endpoints that
// have samples (0 when none): the reference for latency_factor, which
// the outlier itself does not move.
func (p *Pool) peerLatency(e *Endpoint) float64 {
	var sum float64
	var n int
	for _, o := range p.endpoints() {
		if o == e || o.latencySamples.Load() == 0 {
			continue
		}
		sum += o.latencyNS()
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// canEject checks the max_ejection_percent bound.
func (p *Pool) canEject() bool {
	oe := p.Cfg.OutlierEjection
	now := p.now()
	eps := p.endpoints()
	ejected := 0
	for _, e := range eps {
		if e.ejectedNS.Load() > now.UnixNano() {
			ejected++
		}
	}
	return (ejected+1)*100 <= oe.MaxEjectionPercent*len(eps) || oe.MaxEjectionPercent == 100
}

// Stats returns a snapshot for the management API.
func (p *Pool) Stats() []Stats {
	now := p.now()
	eps := p.endpoints()
	out := make([]Stats, 0, len(eps))
	for _, e := range eps {
		out = append(out, e.stats(now))
	}
	return out
}
