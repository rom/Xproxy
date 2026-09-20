// Package botscore is a built-in filter kind that classifies clients as
// automation from what they send and how they behave, and acts on a score:
// log it, challenge the client, or deny.
//
//	filters:
//	  - name: bots
//	    kind: bot_score
//	    options:
//	      challenge_at: 50            # serve the browser challenge from this score (needs a challenge section)
//	      deny_at: 80                 # deny (403) from this score
//	      header: X-Bot-Score         # forward the score to the upstream (default none)
//	      ja4_deny: [t13d0000h2_...]  # fingerprints scored 100
//	      ja4_allow: [t13d1516h2_...] # fingerprints scored 0 (monitoring, partners)
//	      window: 60s                 # behaviour window per client address
//	      weights: {ua_bot: 40, ...}  # override a signal's weight
//
// Signals (default weights): automation_markers 45 (the challenge script
// saw WebDriver or another automation marker when the client solved its
// challenge), device_shared 25 (the client's device identifier arrived
// from device_addresses or more addresses in the window: one tool behind
// a proxy pool), ua_bot 40 (an automation user agent),
// ua_missing 30, browser_headers_missing 25 (a browser user agent without
// Accept or Accept-Language), fingerprint_mismatch 35 (a browser user
// agent on a connection whose TLS hello does not look like a browser's),
// error_rate 30 (more than half of recent requests were 4xx or denied),
// path_spread 15 (many distinct paths in the window), regular_interval 20
// (machine-like request timing), high_rate 15 (more than rate_per_window
// requests in the window), honeypot_marked 40 (the client touched a
// honeypot route on this node or, in a cluster, on a peer). The score is
// the capped sum.
package botscore

import (
	"context"
	"errors"
	"fmt"
	"github.com/rom/xproxy/internal/bound"
	"math"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

// Config is the options schema.
type Config struct {
	ChallengeAt   int            `json:"challenge_at"`
	DenyAt        int            `json:"deny_at"`
	LogAt         int            `json:"log_at"`
	Header        string         `json:"header"`
	JA4Deny       []string       `json:"ja4_deny"`
	JA4Allow      []string       `json:"ja4_allow"`
	Window        string         `json:"window"`
	RatePerWindow int            `json:"rate_per_window"`
	Weights       map[string]int `json:"weights"`
	Reason        string         `json:"reason"`
	// DeviceAddresses is how many distinct client addresses one device
	// identifier must appear from within the window before device_shared
	// fires. Default 5.
	DeviceAddresses int `json:"device_addresses"`
	// Learn records the per-route score distribution without acting on it,
	// so `xproxyctl botscore` can suggest thresholds from real traffic.
	Learn   bool `json:"learn"`
	window  time.Duration
	weights map[string]int
}

var defaultWeights = map[string]int{
	"ua_bot": 40, "ua_missing": 30, "browser_headers_missing": 25, "fingerprint_mismatch": 35,
	"error_rate": 30, "path_spread": 15, "regular_interval": 20, "high_rate": 15, "honeypot_marked": 40,
	"automation_markers": 45, "device_shared": 25,
}

// botUA matches user agents of common automation; a match is a strong
// signal but not a verdict on its own unless the deny threshold says so.
var botUA = regexp.MustCompile(`(?i)\b(curl|wget|python-requests|python-urllib|go-http-client|java/|libwww|scrapy|httpclient|okhttp|axios|node-fetch|undici|aiohttp|httpx|masscan|zgrab|nikto|sqlmap|nmap|headlesschrome|phantomjs|selenium|puppeteer|playwright|bot|crawler|spider)\b`)

var browserUA = regexp.MustCompile(`(?i)\b(chrome|firefox|safari|edg|opera|mozilla)\b`)

func parse(opts filter.Options) (*Config, error) {
	c := Config{ChallengeAt: 0, DenyAt: 0, LogAt: 30, Window: "60s", RatePerWindow: 300, DeviceAddresses: 5}
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.DeviceAddresses < 2 || c.DeviceAddresses > 10000 {
		errs = append(errs, errors.New("device_addresses: must be between 2 and 10000"))
	}
	for name, v := range map[string]int{"challenge_at": c.ChallengeAt, "deny_at": c.DenyAt, "log_at": c.LogAt} {
		if v < 0 || v > 100 {
			errs = append(errs, fmt.Errorf("%s: must be between 0 and 100 (0 disables)", name))
		}
	}
	if c.ChallengeAt > 0 && c.DenyAt > 0 && c.ChallengeAt >= c.DenyAt {
		errs = append(errs, errors.New("challenge_at must be below deny_at"))
	}
	d, err := time.ParseDuration(c.Window)
	if err != nil || d < 5*time.Second || d > time.Hour {
		errs = append(errs, errors.New("window: must be a duration between 5s and 1h"))
	}
	c.window = d
	if c.RatePerWindow < 1 {
		errs = append(errs, errors.New("rate_per_window: must be positive"))
	}
	if h := c.Header; h != "" && strings.ContainsAny(h, " :\r\n") {
		errs = append(errs, fmt.Errorf("header: %q is not a header name", h))
	}
	c.weights = make(map[string]int, len(defaultWeights))
	for k, v := range defaultWeights {
		c.weights[k] = v
	}
	for k, v := range c.Weights {
		if _, ok := defaultWeights[k]; !ok {
			errs = append(errs, fmt.Errorf("weights: unknown signal %q", k))
			continue
		}
		if v < 0 || v > 100 {
			errs = append(errs, fmt.Errorf("weights.%s: must be between 0 and 100", k))
		}
		c.weights[k] = v
	}
	for _, list := range [][]string{c.JA4Deny, c.JA4Allow} {
		for _, f := range list {
			if len(f) < 10 || len(f) > 64 {
				errs = append(errs, fmt.Errorf("ja4 fingerprint %q has an unexpected length", f))
			}
		}
	}
	return &c, errors.Join(errs...)
}

// history is the recent behaviour of one client address.
type history struct {
	times   []time.Time
	errors  int
	total   int
	paths   map[string]struct{}
	updated time.Time
}

const (
	maxClients      = 65536
	maxTimes        = 32
	maxPathsTracked = 64
)

type scorer struct {
	name     string
	cfg      *Config
	ja4Deny  map[string]bool
	ja4Allow map[string]bool
	now      func() time.Time

	mu      sync.Mutex
	clients map[netip.Addr]*history
	devices map[string]*deviceHistory // device identifier -> addresses seen
	full    bound.Notice
	devFull bound.Notice

	// learn and routes hold the learning-mode per-route baselines.
	learn  bool
	lmu    sync.Mutex
	routes map[string]*baseline
}

// deviceHistory is the set of addresses one device identifier came from
// within the window.
type deviceHistory struct {
	addrs   map[netip.Addr]struct{}
	updated time.Time
}

const maxDevices = 65536

func (s *scorer) Name() string { return s.name }

func (s *scorer) Begin(_ context.Context, info *filter.Info) filter.Instance {
	return &instance{s: s, info: *info}
}

type instance struct {
	s       *scorer
	info    filter.Info
	score   int
	signals []string
}

// Request scores the request; behaviour is updated with the outcome in
// Response and End.
func (in *instance) Request(r *http.Request) filter.Verdict {
	s := in.s
	cfg := s.cfg
	add := func(signal string) {
		in.score += cfg.weights[signal]
		in.signals = append(in.signals, signal)
	}
	ua := r.UserAgent()
	switch {
	case s.ja4Allow[in.info.JA4]:
		in.signals = append(in.signals, "ja4_allow")
		in.score = 0
	case s.ja4Deny[in.info.JA4]:
		in.signals = append(in.signals, "ja4_deny")
		in.score = 100
	default:
		switch {
		case ua == "":
			add("ua_missing")
		case botUA.MatchString(ua):
			add("ua_bot")
		case browserUA.MatchString(ua):
			if r.Header.Get("Accept") == "" || r.Header.Get("Accept-Language") == "" {
				add("browser_headers_missing")
			}
			if in.info.TLS && in.info.JA4 != "" && !browserLikeHello(in.info) {
				add("fingerprint_mismatch")
			}
		}
		// Behaviour over the window for this address.
		s.mu.Lock()
		h := s.observe(in.info.ClientIP, in.info.Path)
		total, errs, paths := h.total, h.errors, len(h.paths)
		regular := regularInterval(h.times)
		shared := s.observeDevice(in.info.DeviceID, in.info.ClientIP)
		s.mu.Unlock()
		if len(in.info.Automation) > 0 {
			add("automation_markers")
		}
		if shared {
			add("device_shared")
		}
		if in.info.HoneypotMarked {
			add("honeypot_marked")
		}
		if total >= 10 && errs*2 > total {
			add("error_rate")
		}
		if paths >= 50 {
			add("path_spread")
		}
		if regular {
			add("regular_interval")
		}
		if total > cfg.RatePerWindow {
			add("high_rate")
		}
	}
	if in.score > 100 {
		in.score = 100
	}
	if s.learn {
		s.recordBaseline(in.info.Route, in.score)
	}
	if cfg.Header != "" {
		r.Header.Set(cfg.Header, strconv.Itoa(in.score))
	}
	if cfg.DenyAt > 0 && in.score >= cfg.DenyAt {
		return filter.Verdict{Deny: true, Status: http.StatusForbidden, Reason: cfg.Reason, Detail: in.detail(), Attrs: in.attrs()}
	}
	if cfg.ChallengeAt > 0 && in.score >= cfg.ChallengeAt && !in.info.ChallengeVerified {
		return filter.Verdict{Deny: true, Challenge: true, Status: http.StatusForbidden, Reason: cfg.Reason, Detail: in.detail(), Attrs: in.attrs()}
	}
	return filter.Continue
}

func (in *instance) detail() string {
	return "score " + strconv.Itoa(in.score) + " (" + strings.Join(in.signals, ",") + ")"
}

func (in *instance) attrs() []any {
	out := []any{"bot_score", in.score, "bot_signals", strings.Join(in.signals, ","), "ja4", in.info.JA4}
	if in.info.DeviceID != "" {
		out = append(out, "device", in.info.DeviceID)
	}
	return out
}

// Response records error outcomes for the behaviour window.
func (in *instance) Response(resp *http.Response) filter.Verdict {
	if resp.StatusCode >= 400 {
		in.s.mu.Lock()
		if h := in.s.clients[in.info.ClientIP]; h != nil {
			h.errors++
		}
		in.s.mu.Unlock()
	}
	return filter.Continue
}

func (in *instance) End() []any {
	if in.score < in.s.cfg.LogAt || in.s.cfg.LogAt == 0 {
		return nil
	}
	return []any{"bot_score", in.score, "bot_signals", strings.Join(in.signals, ",")}
}

// observe records a request and returns the client's history; caller
// holds the lock. Windows older than the configured window are reset.
func (s *scorer) observe(ip netip.Addr, path string) *history {
	now := s.now()
	h := s.clients[ip]
	if h == nil || now.Sub(h.updated) > s.cfg.window {
		if h == nil {
			if len(s.clients) >= maxClients {
				s.full.Hit(nil, "bot score client table full; the oldest histories are evicted", "table", "bot_score_clients", "filter", s.name, "max", maxClients)
				s.evict(now)
			}
			h = &history{}
			s.clients[ip] = h
		}
		h.times, h.errors, h.total = h.times[:0], 0, 0
		h.paths = make(map[string]struct{}, 8)
	}
	h.updated = now
	h.total++
	if len(h.times) >= maxTimes {
		copy(h.times, h.times[1:])
		h.times = h.times[:maxTimes-1]
	}
	h.times = append(h.times, now)
	if len(h.paths) < maxPathsTracked {
		h.paths[path] = struct{}{}
	}
	return h
}

// observeDevice records the address behind a device identifier and
// reports whether the identifier has come from device_addresses or more
// addresses in the window; caller holds the lock.
func (s *scorer) observeDevice(device string, ip netip.Addr) bool {
	if device == "" {
		return false
	}
	now := s.now()
	d := s.devices[device]
	if d == nil || now.Sub(d.updated) > s.cfg.window {
		if d == nil {
			if len(s.devices) >= maxDevices {
				s.devFull.Hit(nil, "bot score device table full; stale devices are evicted", "table", "bot_score_devices", "filter", s.name, "max", maxDevices)
				for k, dh := range s.devices {
					if now.Sub(dh.updated) > s.cfg.window {
						delete(s.devices, k)
					}
				}
				if len(s.devices) >= maxDevices {
					return false
				}
			}
			d = &deviceHistory{}
			s.devices[device] = d
		}
		d.addrs = make(map[netip.Addr]struct{}, 2)
	}
	d.updated = now
	if len(d.addrs) < 4096 {
		d.addrs[ip] = struct{}{}
	}
	return len(d.addrs) >= s.cfg.DeviceAddresses
}

// evict drops the stalest quarter of the clients; caller holds the lock.
func (s *scorer) evict(now time.Time) {
	type kv struct {
		ip netip.Addr
		at time.Time
	}
	all := make([]kv, 0, len(s.clients))
	for ip, h := range s.clients {
		if now.Sub(h.updated) > s.cfg.window {
			delete(s.clients, ip)
			continue
		}
		all = append(all, kv{ip, h.updated})
	}
	if len(s.clients) < maxClients {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for _, e := range all[:len(all)/4] {
		delete(s.clients, e.ip)
	}
}

// regularInterval reports machine-like timing: at least eight requests
// whose inter-arrival times vary by less than a tenth of their mean.
func regularInterval(times []time.Time) bool {
	if len(times) < 8 {
		return false
	}
	var sum float64
	gaps := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		g := times[i].Sub(times[i-1]).Seconds()
		gaps = append(gaps, g)
		sum += g
	}
	mean := sum / float64(len(gaps))
	if mean < 0.05 { // bursts are not "regular"
		return false
	}
	var v float64
	for _, g := range gaps {
		v += (g - mean) * (g - mean)
	}
	return math.Sqrt(v/float64(len(gaps)))/mean < 0.1
}

// browserLikeHello: browsers offer ALPN with h2 and a dozen or more cipher
// suites with SNI; scripted TLS stacks often offer none of that.
func browserLikeHello(info filter.Info) bool {
	hasH2 := false
	for _, p := range info.ALPN {
		if p == "h2" {
			hasH2 = true
		}
	}
	if !hasH2 {
		return false
	}
	// JA4 encodes the cipher count in characters 5 and 6 (t13d1516h2...).
	if len(info.JA4) >= 6 {
		if n, err := strconv.Atoi(info.JA4[4:6]); err == nil && n < 10 {
			return false
		}
	}
	return true
}

func init() {
	filter.Register(filter.Kind{
		Name:        "bot_score",
		Description: "Score clients as automation from user agent, headers, TLS fingerprint and behaviour; log, challenge or deny.",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			if c.Reason == "" {
				c.Reason = name
			}
			s := &scorer{name: name, cfg: c, ja4Deny: map[string]bool{}, ja4Allow: map[string]bool{}, now: time.Now, clients: map[netip.Addr]*history{}, devices: map[string]*deviceHistory{}}
			for _, f := range c.JA4Deny {
				s.ja4Deny[f] = true
			}
			for _, f := range c.JA4Allow {
				s.ja4Allow[f] = true
			}
			if c.Learn {
				s.learn = true
				s.routes = map[string]*baseline{}
				registerLearn(s)
			}
			return s, nil
		},
	})
}
