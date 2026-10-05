// Package flow is a built-in filter kind that enforces the order of a
// business flow: a step may be reached only by a caller that has already
// been seen at the steps it depends on.
//
// It is the other half of cross-request detection. The api_abuse filter
// watches the *shape* of a sequence -- how many objects, how consecutive,
// how often refused -- and answers questions nobody wrote down. This one
// answers a question somebody did write down: the application has a flow,
// and a request that arrives out of that flow is not a request the
// application meant to serve.
//
//	POST /api/cart/items        -> 200
//	POST /api/checkout/address  -> 200
//	POST /api/checkout/pay      -> 200
//
// against
//
//	POST /api/checkout/pay      -> 200   <- paid for a cart nobody filled
//
// Every one of those requests is valid on its own: the right method, the
// right path, a well formed body, an authenticated caller. A WAF sees
// nothing, an OpenAPI schema sees nothing, a rate limit sees nothing, and
// a positive security policy sees nothing, because each request is
// individually permitted. What is wrong is the order, and the order is
// only visible across requests.
//
// This is OWASP API Security Top 10 API6:2023, unrestricted access to
// sensitive business flows, and it is the same control the modbus kind
// spells `require_before` -- select before operate. A plant will not let a
// valve be driven without the select that precedes it; an application
// should not let a payment be taken without the cart that precedes it.
//
//	filters:
//	  - name: checkout
//	    kind: flow
//	    options:
//	      window: 30m
//	      action: alert
//	      flows:
//	        - name: checkout
//	          steps:
//	            - {name: cart,    methods: [POST], paths: [/api/cart]}
//	            - {name: address, methods: [POST], paths: [/api/checkout/address], after: [cart]}
//	            - {name: pay,     methods: [POST], paths: [/api/checkout/pay], after: [address], once: true}
//
// # The caller
//
// The caller is the authenticated identity when the filter chain has
// established one and the client address otherwise, which is why this
// filter belongs *after* the identity filters in the chain. A flow
// followed through one account is one caller whatever addresses it
// arrives from, and -- the part that matters more -- a flow keyed on an
// address would let one NAT gateway's cart satisfy another user's payment.
//
// # What it cannot see
//
// Two limits, and both are the operator's to weigh rather than this
// filter's to hide.
//
// The state is this process's. Behind two relays, a caller whose cart
// step landed on one and whose payment arrives at the other looks exactly
// like a caller who skipped the cart, and enforcing would refuse a
// legitimate payment. Run one relay in the path of a flow, or run this as
// `alert` and read the events.
//
// The state starts empty. Every caller mid-flow when the relay starts,
// reloads its runtime generation, or is deployed for the first time has
// no recorded earlier step. `alert` is the default for that reason, and
// the documentation says to leave it there until the events are quiet.
package flow

import (
	"container/list"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/filter"
)

// Actions a finding may take. log is the default, deliberately: the flow is
// declared rather than learned, so refusing is honest -- but a flow declared
// slightly wrong refuses real customers, and the relay cannot see the steps a
// caller took before it was in the path.
const (
	ActionLog       = "log"
	ActionChallenge = "challenge"
	ActionBlock     = "block"
)

// Reasons a step is refused, named after what was observed.
const (
	// ReasonOutOfOrder is a step whose dependency was never seen.
	ReasonOutOfOrder = "out_of_order"
	// ReasonRepeated is a once-only step reached a second time.
	ReasonRepeated = "repeated"
)

// Bounds.
const (
	defaultMaxCallers = 65536
	defaultWindow     = 30 * time.Minute
	maxFlows          = 64
	maxSteps          = 64
)

// step is one compiled step of a flow.
type step struct {
	name string
	// methods is the set of methods this step matches; empty matches any.
	methods map[string]bool
	// paths are the prefixes it matches. At least one is required: a step
	// that matched every path would put every request in the flow.
	paths []string
	// after are the indices of the steps that must have been seen. Empty
	// makes this an entry step, which is always allowed and is what starts
	// a caller's flow.
	after []int
	// once refuses a second visit. Off by default: a step reached twice is
	// usually a customer who pressed the button again after a timeout, and
	// the second press is the one that works.
	once bool
}

// compiled is one flow.
type compiled struct {
	name  string
	steps []step
}

// config is the compiled options.
type config struct {
	window     time.Duration
	action     string
	maxCallers int
	flows      []compiled
}

// Filter is the flow filter.
type Filter struct {
	name string
	cfg  config
	now  func() time.Time

	mu      sync.Mutex
	callers map[string]*caller
	lru     *list.List
	// Counters, read by Status.
	Requests, Steps, Flagged, Blocked, Challenged, Dropped atomic.Uint64
}

// caller is what one caller has been seen doing, per flow.
type caller struct {
	key  string
	seen []flowState
	elem *list.Element
	last time.Time
}

// flowState is one caller's progress through one flow: when each step was last
// seen, and how many times. A step outside the window counts as unseen, which is
// what makes the window a window rather than a memory.
type flowState struct {
	at    []time.Time
	count []int
}

// New builds a filter from options.
func New(name string, opts filter.Options) (*Filter, error) {
	cfg, err := parse(opts)
	if err != nil {
		return nil, err
	}
	f := &Filter{name: name, cfg: cfg, now: time.Now,
		callers: map[string]*caller{}, lru: list.New()}
	register(f)
	return f, nil
}

func (f *Filter) Name() string { return "flow:" + f.name }

// Begin starts one request.
func (f *Filter) Begin(_ context.Context, info *filter.Info) filter.Instance {
	return &instance{f: f, info: info}
}

type instance struct {
	f    *Filter
	info *filter.Info
	// detail is what was found, for the access log.
	detail string
}

// finding is one step refused.
type finding struct {
	flow, step, reason string
	// missing is the dependency that was not seen, for out_of_order.
	missing string
}

func (fi finding) detail() string {
	d := fi.flow + "." + fi.step + " " + fi.reason
	if fi.missing != "" {
		d += " (" + fi.missing + ")"
	}
	return d
}

// Request decides whether this request's step may be taken.
func (in *instance) Request(r *http.Request) filter.Verdict {
	f := in.f
	fl, st := f.match(r)
	if fl < 0 {
		// Not a step of any flow. The filter says nothing about traffic the
		// operator did not describe, which is what keeps it from becoming a
		// second, accidental positive security policy.
		return filter.Continue
	}
	f.Requests.Add(1)
	key := callerKey(r, in.info)
	fi := f.take(key, fl, st)
	if fi == nil {
		f.Steps.Add(1)
		return filter.Continue
	}
	f.Flagged.Add(1)
	in.detail = fi.detail()
	attrs := []any{"flow", fi.flow, "step", fi.step, "flow_reason", fi.reason}
	if fi.missing != "" {
		attrs = append(attrs, "missing_step", fi.missing)
	}
	switch f.cfg.action {
	case ActionBlock:
		f.Blocked.Add(1)
		return filter.Verdict{Deny: true, Status: http.StatusConflict, Reason: "flow",
			Detail: in.detail, Attrs: attrs}
	case ActionChallenge:
		if in.info.ChallengeVerified {
			// Already verified, so there is nothing to ask for. Returning a
			// challenge verdict to a client that holds one makes the handler
			// resume the chain on every request from it, which is work with no
			// decision in it -- and it is how a satisfied challenge used to be
			// a way past the rest of the chain. botscore has always guarded
			// this; these two did not.
			return filter.Continue
		}
		f.Challenged.Add(1)
		return filter.Verdict{Deny: true, Status: http.StatusConflict, Reason: "flow",
			Detail: in.detail, Challenge: true, Attrs: attrs}
	}
	return filter.Continue
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

// End reports what was found, for the access log.
func (in *instance) End() []any {
	if in.detail == "" {
		return nil
	}
	return []any{"flow", in.detail}
}

// match finds the flow and step this request is, or -1.
//
// The first match wins, and a step matches on method and path prefix. A request
// that matches two steps of two flows is described by the first, which is the
// order the operator wrote them in: making it match both would mean one request
// advancing two flows, and an operator who wants that writes two filters.
func (f *Filter) match(r *http.Request) (int, int) {
	for i := range f.cfg.flows {
		for j := range f.cfg.flows[i].steps {
			if f.cfg.flows[i].steps[j].matches(r) {
				return i, j
			}
		}
	}
	return -1, -1
}

func (s *step) matches(r *http.Request) bool {
	if len(s.methods) > 0 && !s.methods[r.Method] {
		return false
	}
	for _, p := range s.paths {
		if pathUnder(r.URL.Path, p) {
			return true
		}
	}
	return false
}

// pathUnder is a prefix match on whole path segments, so /api/cartridge is not
// under /api/cart. A prefix match on raw bytes would put a neighbouring
// endpoint inside somebody's flow.
func pathUnder(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	return rest == "" || rest[0] == '/' || strings.HasSuffix(prefix, "/")
}

// callerKey is the authenticated identity when the chain established one and
// the client address otherwise.
//
// The address is the fallback and not the default on purpose: a flow keyed on an
// address lets one NAT gateway's cart satisfy another user's payment, so an
// estate that means to enforce a flow puts the identity filters before this one.
func callerKey(r *http.Request, info *filter.Info) string {
	if id := filter.IdentityFrom(r.Context()); id != nil {
		if who := id.Any(); who != "" {
			return "id:" + who
		}
	}
	if info != nil {
		return "addr:" + info.ClientIP.String()
	}
	return ""
}

// take records the step and reports why it may not be taken.
//
// The step is recorded either way. A refused step that was not recorded would be
// refused again on every retry, and a caller who genuinely lost their earlier
// step -- to a restart, to the other relay in the pair -- could never get
// through: the flow would be permanently broken for them rather than broken once.
func (f *Filter) take(key string, fl, st int) *finding {
	if key == "" {
		return nil
	}
	now := f.now()
	cut := now.Add(-f.cfg.window)
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.callers[key]
	if c == nil {
		if len(f.callers) >= f.cfg.maxCallers {
			// The oldest goes rather than the newest being refused: a table
			// full of callers must not turn this filter into one that refuses
			// whoever arrives next.
			f.evictLocked()
		}
		c = &caller{key: key, seen: make([]flowState, len(f.cfg.flows))}
		for i := range c.seen {
			n := len(f.cfg.flows[i].steps)
			c.seen[i] = flowState{at: make([]time.Time, n), count: make([]int, n)}
		}
		f.callers[key] = c
		c.elem = f.lru.PushBack(c)
	} else {
		f.lru.MoveToBack(c.elem)
	}
	c.last = now
	state := &c.seen[fl]
	s := &f.cfg.flows[fl].steps[st]

	var out *finding
	switch {
	case s.once && state.count[st] > 0 && state.at[st].After(cut):
		out = &finding{flow: f.cfg.flows[fl].name, step: s.name, reason: ReasonRepeated}
	default:
		for _, dep := range s.after {
			if state.at[dep].After(cut) {
				continue
			}
			out = &finding{flow: f.cfg.flows[fl].name, step: s.name,
				reason: ReasonOutOfOrder, missing: f.cfg.flows[fl].steps[dep].name}
			break
		}
	}
	state.at[st] = now
	state.count[st]++
	return out
}

// evictLocked drops the least recently seen caller.
func (f *Filter) evictLocked() {
	e := f.lru.Front()
	if e == nil {
		return
	}
	c, _ := e.Value.(*caller)
	f.lru.Remove(e)
	if c != nil {
		delete(f.callers, c.key)
	}
	f.Dropped.Add(1)
}

// Callers is how many callers are held, for the status view.
func (f *Filter) Callers() int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.callers)
}

// Options is the filter's configuration.
type Options struct {
	// Window is how long a step counts as taken. Default 30m. It has to be
	// at least as long as a real caller takes over the whole flow: a
	// window shorter than that refuses the customer who went to make a cup
	// of tea between the address and the payment.
	Window string `json:"window"`
	// Action is log (the default), challenge or block.
	Action string `json:"action"`
	// MaxCallers bounds the callers tracked at once. Default 65536; past
	// it the least recently seen is dropped and the drops are counted.
	MaxCallers *int `json:"max_callers"`
	// Flows are the flows to enforce.
	Flows []struct {
		Name  string `json:"name"`
		Steps []struct {
			Name    string   `json:"name"`
			Methods []string `json:"methods"`
			Paths   []string `json:"paths"`
			After   []string `json:"after"`
			Once    bool     `json:"once"`
		} `json:"steps"`
	} `json:"flows"`
}

func parse(opts filter.Options) (config, error) {
	var o Options
	c := config{window: defaultWindow, action: ActionLog, maxCallers: defaultMaxCallers}
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
	if o.Action != "" {
		switch o.Action {
		case ActionLog, ActionChallenge, ActionBlock:
			c.action = o.Action
		default:
			fail("action: must be log, challenge or block")
		}
	}
	if o.MaxCallers != nil {
		if *o.MaxCallers < 16 || *o.MaxCallers > 10_000_000 {
			fail("max_callers: must be between 16 and 10000000")
		} else {
			c.maxCallers = *o.MaxCallers
		}
	}
	if len(o.Flows) == 0 {
		fail("flows: at least one is required, or the filter would watch nothing")
	}
	if len(o.Flows) > maxFlows {
		fail("flows: at most %d", maxFlows)
	}
	names := map[string]bool{}
	for i, fo := range o.Flows {
		where := fmt.Sprintf("flows[%d]", i)
		if fo.Name == "" {
			fail("%s.name: required", where)
		} else if names[fo.Name] {
			fail("%s.name: %q is used twice", where, fo.Name)
		}
		names[fo.Name] = true
		cf := compiled{name: fo.Name}
		if len(fo.Steps) == 0 {
			fail("%s.steps: at least one is required", where)
		}
		if len(fo.Steps) > maxSteps {
			fail("%s.steps: at most %d", where, maxSteps)
		}
		// The step names first, so that after can be resolved against every
		// step of the flow and not only the ones written above it.
		index := map[string]int{}
		for j, so := range fo.Steps {
			at := fmt.Sprintf("%s.steps[%d]", where, j)
			switch {
			case so.Name == "":
				fail("%s.name: required", at)
			case index[so.Name] != 0 || (j > 0 && so.Name == fo.Steps[0].Name):
				fail("%s.name: %q is used twice in this flow", at, so.Name)
			}
			index[so.Name] = j
		}
		for j, so := range fo.Steps {
			at := fmt.Sprintf("%s.steps[%d]", where, j)
			cs := step{name: so.Name, once: so.Once}
			if len(so.Methods) > 0 {
				cs.methods = map[string]bool{}
				for _, m := range so.Methods {
					up := strings.ToUpper(m)
					if up != m {
						fail("%s.methods: %q must be upper case", at, m)
					}
					cs.methods[up] = true
				}
			}
			if len(so.Paths) == 0 {
				fail("%s.paths: at least one is required, because a step matching every path "+
					"would put every request into this flow", at)
			}
			for _, p := range so.Paths {
				if !strings.HasPrefix(p, "/") {
					fail("%s.paths: %q must start with /", at, p)
				}
			}
			cs.paths = so.Paths
			for _, dep := range so.After {
				k, ok := index[dep]
				switch {
				case !ok:
					fail("%s.after: %q is not a step of this flow", at, dep)
				case k == j:
					fail("%s.after: a step cannot depend on itself", at)
				case k > j:
					// A step may only depend on one written above it. A cycle,
					// or a forward dependency, is a flow no caller can ever
					// complete -- and it would look like an attack on every
					// legitimate request.
					fail("%s.after: %q is written below this step, so nothing could ever reach it", at, dep)
				default:
					cs.after = append(cs.after, k)
				}
			}
			cf.steps = append(cf.steps, cs)
		}
		// No check that the flow has an entry step: the first step cannot have
		// one. Its only candidate dependencies are itself, which fails above,
		// and a step written below it, which fails above too -- so a flow that
		// validates always has a first step with nothing before it.
		c.flows = append(c.flows, cf)
	}
	if len(errs) > 0 {
		return c, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return c, nil
}

func init() {
	filter.Register(filter.Kind{
		Name: "flow",
		Description: "Enforces the order of a business flow: a step may be reached only by a caller already seen " +
			"at the steps it depends on, which is the one thing a per-request policy cannot see.",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			return New(name, opts)
		},
	})
}
