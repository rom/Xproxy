// Package apiabuse is a built-in filter kind that watches what a caller
// does with an API rather than what it sends: how many objects it asks
// for, whether it is walking their identifiers, and how often the answer
// is "not yours".
//
// The rules a WAF carries and the schemas an OpenAPI description carries
// both judge one request. Every request below is valid on its own -- the
// right method, the right path, an authenticated caller, a well formed
// identifier -- and the attack is the sequence:
//
//	GET /api/orders/1041   200
//	GET /api/orders/1042   403
//	GET /api/orders/1043   403
//	GET /api/orders/1044   200   <- somebody else's order
//
// That is broken object level authorisation, the first item on the OWASP
// API Security Top 10, and it is invisible to anything that looks at one
// request at a time. What it is visible in is the shape of the sequence,
// which is what this counts, per caller and per endpoint, over a window:
//
//   - objects: how many distinct identifiers the caller touched. A person
//     reads their own orders; a script reads everybody's.
//
//   - sequential: whether the numeric identifiers are consecutive. A
//     catalogue of ten thousand read in order is a scrape, and it is a
//     different fact from having read ten thousand things.
//
//   - refused: the share of those lookups the upstream answered 401, 403
//     or 404 with. Probing for objects that are not yours looks exactly
//     like this, and nothing else does.
//
//     filters:
//
//   - name: abuse
//     kind: api_abuse
//     options:
//     window: 5m
//     max_objects: 200
//     sequential: {min: 20, density: 0.8}
//     refused: {min_requests: 20, share: 0.5}
//     action: challenge
//
// The caller is the authenticated identity when the filter chain
// established one and the client address otherwise, which is why this
// filter belongs after the identity filters in the chain: an API abused
// through one account is one caller, whatever addresses it arrives from.
package apiabuse

import (
	"container/list"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/netutil"
)

// Signals this filter can raise. Each is a fact about a sequence, and
// each is named after what was observed rather than after what it might
// mean: "enumeration" is a caller that touched many objects, and whether
// that is a scraper or a busy dashboard is the operator's to say.
const (
	SignalEnumeration = "enumeration"
	SignalSequential  = "sequential"
	SignalRefused     = "refused"
)

// Actions a signal may take.
const (
	ActionLog       = "log"
	ActionChallenge = "challenge"
	ActionBlock     = "block"
)

// Bounds. A subject is a caller and an endpoint; the identifiers of one
// are held as a set, because counting distinct things is the whole
// question. Both are bounded, and the oldest subject is dropped rather
// than the newest refused: a table full of scrapers must not stop this
// filter noticing the next one.
const (
	defaultMaxSubjects = 8192
	maxObjectsHeld     = 1024
	maxIDLen           = 128
)

// config is the compiled options.
type config struct {
	window     time.Duration
	maxObjects int
	seqMin     int
	seqDensity float64
	refMin     int
	refShare   float64
	action     string
	maxSubject int
	// paths, when set, limits the filter to request paths under one of
	// these prefixes.
	paths []string
}

// Filter is the api_abuse filter.
type Filter struct {
	name string
	cfg  config
	now  func() time.Time

	mu       sync.Mutex
	subjects map[string]*subject
	lru      *list.List
	// Counters, read by Status.
	Requests, Flagged, Blocked, Challenged, Dropped atomic.Uint64
}

// subject is one caller on one endpoint within the window.
type subject struct {
	key      string
	started  time.Time
	requests int
	refused  int
	// objects are the identifiers seen, bounded; overflow is counted so
	// the distinct count is never silently wrong.
	objects  map[string]struct{}
	overflow int
	// numeric range, for the sequential signal.
	numeric int
	lowest  int64
	highest int64
	signals map[string]bool
	elem    *list.Element
}

// New builds a filter from options.
func New(name string, opts filter.Options) (*Filter, error) {
	cfg, err := parse(opts)
	if err != nil {
		return nil, err
	}
	f := &Filter{name: name, cfg: cfg, now: time.Now,
		subjects: map[string]*subject{}, lru: list.New()}
	register(f)
	return f, nil
}

func (f *Filter) Name() string { return "api_abuse:" + f.name }

// Begin starts one request.
func (f *Filter) Begin(_ context.Context, info *filter.Info) filter.Instance {
	return &instance{f: f, info: info}
}

// instance is one request's view.
type instance struct {
	f    *Filter
	info *filter.Info
	// key is the subject this request counted against, empty when the
	// request is outside the configured paths.
	key      string
	id       string
	verdict  string
	observed bool
}

// Request decides whether this caller has already been flagged, and
// records what the request asks for.
func (in *instance) Request(r *http.Request) filter.Verdict {
	f := in.f
	if !f.covers(r.URL.Path) {
		return filter.Continue
	}
	template := netutil.PathTemplate(r.URL.Path)
	id := lastVariable(r.URL.Path, template)
	in.key = f.subjectKey(r, in.info, template)
	in.id = id
	f.Requests.Add(1)

	signals := f.observe(in.key, id, false)
	if len(signals) == 0 {
		return filter.Continue
	}
	in.verdict = strings.Join(signals, ",")
	f.Flagged.Add(1)
	switch f.cfg.action {
	case ActionBlock:
		f.Blocked.Add(1)
		return filter.Verdict{Deny: true, Status: http.StatusForbidden, Reason: "api_abuse",
			Detail: in.verdict, Attrs: []any{"api_abuse", in.verdict, "endpoint", template}}
	case ActionChallenge:
		f.Challenged.Add(1)
		return filter.Verdict{Deny: true, Status: http.StatusForbidden, Reason: "api_abuse",
			Detail: in.verdict, Challenge: true, Attrs: []any{"api_abuse", in.verdict, "endpoint", template}}
	}
	return filter.Continue
}

// Response records what the upstream said about the object, which is the
// other half of the probing signal: an identifier that does not belong to
// this caller is refused, and a caller doing that repeatedly is the shape
// the filter exists to see.
func (in *instance) Response(resp *http.Response) filter.Verdict {
	if in.key == "" || resp == nil {
		return filter.Continue
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		in.f.observe(in.key, "", true)
		in.observed = true
	}
	return filter.Continue
}

// End reports what was seen, for the access log.
func (in *instance) End() []any {
	if in.verdict == "" {
		return nil
	}
	return []any{"api_abuse", in.verdict}
}

// covers reports whether a path is in scope.
func (f *Filter) covers(path string) bool {
	if len(f.cfg.paths) == 0 {
		return true
	}
	for _, p := range f.cfg.paths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// subjectKey is the caller and the endpoint: the authenticated identity
// when there is one, the client address otherwise. An API abused through
// one account is one caller however many addresses it comes from, and an
// unauthenticated endpoint still has an address to count.
func (f *Filter) subjectKey(r *http.Request, info *filter.Info, template string) string {
	who := ""
	if id := filter.IdentityFrom(r.Context()); id != nil {
		who = id.Any()
	}
	if who == "" && info != nil {
		who = info.ClientIP.String()
	}
	return who + "\x00" + r.Method + "\x00" + template
}

// observe records one request or one refusal against a subject and
// returns the signals that are over their thresholds. A refusal is
// counted without an identifier, because the identifier was counted when
// the request went out.
func (f *Filter) observe(key, id string, refusal bool) []string {
	if key == "" {
		return nil
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.subjects[key]
	switch {
	case s == nil:
		if refusal {
			// The window turned over between the request and its answer;
			// there is nothing left to attribute it to.
			return nil
		}
		s = &subject{key: key, started: now, objects: map[string]struct{}{}, signals: map[string]bool{}}
		f.subjects[key] = s
		s.elem = f.lru.PushBack(s)
		f.evictLocked()
	case now.Sub(s.started) >= f.cfg.window:
		// A fresh window: the counts start again, and so do the signals.
		// A caller stays flagged only while the window it was flagged in
		// is the current one, which is what makes the flag a statement
		// about now rather than about this morning.
		*s = subject{key: key, started: now, objects: map[string]struct{}{}, signals: map[string]bool{}, elem: s.elem}
		f.lru.MoveToBack(s.elem)
	default:
		f.lru.MoveToBack(s.elem)
	}
	if refusal {
		s.refused++
	} else {
		s.requests++
		f.countObject(s, id)
	}
	return f.signalsLocked(s)
}

// countObject records one identifier. Everything here is about
// *distinct* identifiers: a caller re-reading its own order fifty times
// has touched one object, and counting that as fifty would make an
// ordinary page refresh look like a walk.
func (f *Filter) countObject(s *subject, id string) {
	if id == "" || len(id) > maxIDLen {
		// No identifier, or one no API issues: a collection endpoint, or
		// something this is not going to reason about.
		return
	}
	if _, seen := s.objects[id]; seen {
		return
	}
	if len(s.objects) >= maxObjectsHeld {
		// Past the bound the distinct count becomes a lower bound, and
		// the overflow keeps it right rather than the count quietly
		// stopping. A caller this far past any threshold has already
		// raised whatever it was going to raise.
		s.overflow++
		return
	}
	s.objects[id] = struct{}{}
	if n, err := strconv.ParseInt(id, 10, 64); err == nil {
		if s.numeric == 0 || n < s.lowest {
			s.lowest = n
		}
		if s.numeric == 0 || n > s.highest {
			s.highest = n
		}
		s.numeric++
	}
}

// signalsLocked evaluates the thresholds and returns the signals that
// are newly or still over them.
func (f *Filter) signalsLocked(s *subject) []string {
	var out []string
	raise := func(name string) {
		s.signals[name] = true
		out = append(out, name)
	}
	if f.cfg.maxObjects > 0 && len(s.objects)+s.overflow > f.cfg.maxObjects {
		raise(SignalEnumeration)
	} else if s.signals[SignalEnumeration] {
		out = append(out, SignalEnumeration)
	}
	if f.cfg.seqMin > 0 && s.numeric >= f.cfg.seqMin {
		span := s.highest - s.lowest + 1
		if span > 0 && float64(len(s.objects))/float64(span) >= f.cfg.seqDensity {
			raise(SignalSequential)
		} else if s.signals[SignalSequential] {
			out = append(out, SignalSequential)
		}
	} else if s.signals[SignalSequential] {
		out = append(out, SignalSequential)
	}
	if f.cfg.refMin > 0 && s.requests >= f.cfg.refMin {
		if float64(s.refused)/float64(s.requests) >= f.cfg.refShare {
			raise(SignalRefused)
		} else if s.signals[SignalRefused] {
			out = append(out, SignalRefused)
		}
	} else if s.signals[SignalRefused] {
		out = append(out, SignalRefused)
	}
	return out
}

// evictLocked drops the oldest subjects past the bound.
func (f *Filter) evictLocked() {
	for len(f.subjects) > f.cfg.maxSubject {
		front := f.lru.Front()
		if front == nil {
			return
		}
		old := f.lru.Remove(front).(*subject)
		delete(f.subjects, old.key)
		f.Dropped.Add(1)
	}
}

// lastVariable is the value of the last path segment the template folded
// into a placeholder: the object this request is about. A path with no
// variable segment has no object, and nothing is counted for it.
func lastVariable(path, template string) string {
	p := strings.Split(path, "/")
	t := strings.Split(template, "/")
	for i := min(len(t), len(p)) - 1; i >= 0; i-- {
		if t[i] == "*" {
			return p[i]
		}
	}
	return ""
}

// Status is the management view of one filter.
type Status struct {
	Name     string `json:"name"`
	Subjects int    `json:"subjects"`
	// Objects is the identifiers held across every subject, and
	// Overflowed the ones a full subject could only count. Together they
	// say how much this filter is holding and whether any caller went
	// past what it holds per endpoint.
	Objects    int    `json:"objects"`
	Overflowed int    `json:"overflowed"`
	Requests   uint64 `json:"requests"`
	Flagged    uint64 `json:"flagged"`
	Blocked    uint64 `json:"blocked"`
	Challenged uint64 `json:"challenged"`
	Dropped    uint64 `json:"dropped"`
}

// Status reports the counters.
func (f *Filter) Status() Status {
	f.mu.Lock()
	n := len(f.subjects)
	objects, overflowed := 0, 0
	for _, s := range f.subjects {
		objects += len(s.objects)
		overflowed += s.overflow
	}
	f.mu.Unlock()
	return Status{Name: f.name, Subjects: n, Objects: objects, Overflowed: overflowed,
		Requests: f.Requests.Load(), Flagged: f.Flagged.Load(),
		Blocked: f.Blocked.Load(), Challenged: f.Challenged.Load(), Dropped: f.Dropped.Load()}
}

// Options is the filter's configuration as written.
type Options struct {
	// Window is the observation period. Default 5m.
	Window string `json:"window"`
	// MaxObjects is how many distinct identifiers a caller may touch on
	// one endpoint in the window. Default 200; 0 turns the signal off.
	MaxObjects *int `json:"max_objects"`
	// MaxSubjects bounds the (caller, endpoint) pairs tracked at once.
	// Default 8192; the oldest is dropped, and the drops are counted.
	MaxSubjects *int `json:"max_subjects"`
	// Sequential is the consecutive-identifier signal.
	Sequential *struct {
		// Min is how many numeric identifiers are needed before the
		// density is judged at all. Default 20; 0 turns it off.
		Min *int `json:"min"`
		// Density is distinct identifiers over the span they cover:
		// 1.0 is a perfect walk, 0.8 one with gaps. Default 0.8.
		Density *float64 `json:"density"`
	} `json:"sequential"`
	// Refused is the "not yours" signal.
	Refused *struct {
		// MinRequests is how many requests are needed before the share
		// is judged. Default 20; 0 turns it off.
		MinRequests *int `json:"min_requests"`
		// Share is the fraction of them answered 401, 403 or 404 that
		// raises the signal. Default 0.5.
		Share *float64 `json:"share"`
	} `json:"refused"`
	// Action is log (default), challenge or block.
	Action string `json:"action"`
	// Paths limits the filter to request paths under one of these
	// prefixes. Empty means every path on the route.
	Paths []string `json:"paths"`
}

// parse reads and checks the options.
func parse(opts filter.Options) (config, error) {
	var o Options
	c := config{window: 5 * time.Minute, maxObjects: 200, seqMin: 20, seqDensity: 0.8,
		refMin: 20, refShare: 0.5, action: ActionLog, maxSubject: defaultMaxSubjects}
	if err := opts.Decode(&o); err != nil {
		return c, err
	}
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if o.Window != "" {
		d, err := time.ParseDuration(o.Window)
		switch {
		case err != nil:
			fail("window: %v", err)
		case d < time.Second || d > 24*time.Hour:
			fail("window: must be between 1s and 24h")
		default:
			c.window = d
		}
	}
	count := func(name string, p *int, dst *int, minimum, maximum int) {
		if p == nil {
			return
		}
		if *p != 0 && (*p < minimum || *p > maximum) {
			fail("%s: must be 0 (off) or between %d and %d", name, minimum, maximum)
			return
		}
		*dst = *p
	}
	count("max_objects", o.MaxObjects, &c.maxObjects, 1, 1_000_000)
	if o.MaxSubjects != nil {
		if *o.MaxSubjects < 16 || *o.MaxSubjects > 1_000_000 {
			fail("max_subjects: must be between 16 and 1000000")
		} else {
			c.maxSubject = *o.MaxSubjects
		}
	}
	share := func(name string, p *float64, dst *float64) {
		if p == nil {
			return
		}
		if *p <= 0 || *p > 1 {
			fail("%s: must be between 0 and 1", name)
			return
		}
		*dst = *p
	}
	if s := o.Sequential; s != nil {
		count("sequential.min", s.Min, &c.seqMin, 2, 1_000_000)
		share("sequential.density", s.Density, &c.seqDensity)
	}
	if r := o.Refused; r != nil {
		count("refused.min_requests", r.MinRequests, &c.refMin, 1, 1_000_000)
		share("refused.share", r.Share, &c.refShare)
	}
	if o.Action != "" {
		switch o.Action {
		case ActionLog, ActionChallenge, ActionBlock:
			c.action = o.Action
		default:
			fail("action: must be log, challenge or block")
		}
	}
	c.paths = o.Paths
	for _, p := range c.paths {
		if !strings.HasPrefix(p, "/") {
			fail("paths: %q must start with /", p)
		}
	}
	if c.maxObjects == 0 && c.seqMin == 0 && c.refMin == 0 {
		fail("every signal is off, so the filter would watch and say nothing")
	}
	if len(errs) > 0 {
		return c, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return c, nil
}

func init() {
	filter.Register(filter.Kind{
		Name: "api_abuse",
		Description: "Watches what a caller does with an API over a window: how many distinct objects it asks for, " +
			"whether their identifiers are consecutive, and how often the answer was that the object is not theirs.",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			return New(name, opts)
		},
	})
}
