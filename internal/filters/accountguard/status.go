package accountguard

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Classes and actions in a fixed order, so counters and metrics always
// carry every combination.
var (
	Classes = []string{"login", "register", "reset", "cart", "scrape", "custom"}
	Actions = []string{"log", "delay", "challenge", "captcha", "block"}
)

// counters are process wide: they survive reloads and cover every
// account_guard filter of every generation.
type counterSet struct {
	actions    map[string]*atomic.Uint64 // class|action
	blocks     atomic.Uint64
	campaigns  atomic.Uint64
	disposable atomic.Uint64
	automation atomic.Uint64
	events     atomic.Uint64 // counted failures or requests
}

var counters = func() *counterSet {
	c := &counterSet{actions: map[string]*atomic.Uint64{}}
	for _, cl := range Classes {
		for _, a := range Actions {
			c.actions[cl+"|"+a] = &atomic.Uint64{}
		}
	}
	return c
}()

func countAction(class, action string) {
	if c, ok := counters.actions[class+"|"+action]; ok {
		c.Add(1)
	}
}

// ActionCount is one class and action counter.
type ActionCount struct {
	Class  string `json:"class"`
	Action string `json:"action"`
	Count  uint64 `json:"count"`
}

// Counters is the process wide counter snapshot.
type Counters struct {
	Actions    []ActionCount `json:"actions"`
	Events     uint64        `json:"events"`
	Blocks     uint64        `json:"blocks"`
	Campaigns  uint64        `json:"campaigns"`
	Disposable uint64        `json:"disposable"`
	Automation uint64        `json:"automation"`
}

// Snapshot returns the counters since the process started.
func Snapshot() Counters {
	out := Counters{Events: counters.events.Load(), Blocks: counters.blocks.Load(), Campaigns: counters.campaigns.Load(), Disposable: counters.disposable.Load(), Automation: counters.automation.Load()}
	for _, cl := range Classes {
		for _, a := range Actions {
			out.Actions = append(out.Actions, ActionCount{Class: cl, Action: a, Count: counters.actions[cl+"|"+a].Load()})
		}
	}
	return out
}

// registry holds the live guards for the status view.
var registry = struct {
	mu     sync.Mutex
	guards map[*guard]struct{}
}{guards: map[*guard]struct{}{}}

func register(g *guard) {
	registry.mu.Lock()
	registry.guards[g] = struct{}{}
	registry.mu.Unlock()
}

// Close unregisters the guard when its generation is torn down.
func (g *guard) Close() error {
	registry.mu.Lock()
	delete(registry.guards, g)
	registry.mu.Unlock()
	return nil
}

// BlockView is one active block.
type BlockView struct {
	// Kind is ip, account, pair or device; Key the address, the account
	// hash, address|hash or the device identifier.
	Kind  string    `json:"kind"`
	Key   string    `json:"key"`
	By    string    `json:"by"`
	Until time.Time `json:"until"`
}

// EndpointStatus is the live state of one endpoint.
type EndpointStatus struct {
	Name          string      `json:"name"`
	Class         string      `json:"class"`
	Count         string      `json:"count"`
	Window        string      `json:"window"`
	Paths         []string    `json:"paths"`
	TrackedIPs    int         `json:"tracked_ips"`
	TrackedAccts  int         `json:"tracked_accounts"`
	TrackedPairs  int         `json:"tracked_pairs"`
	TrackedDevs   int         `json:"tracked_devices"`
	ActiveBlocks  int         `json:"active_blocks"`
	WindowEvents  int         `json:"window_events"`
	WindowIPs     int         `json:"window_ips"`
	Campaign      bool        `json:"campaign"`
	CampaignUntil *time.Time  `json:"campaign_until,omitempty"`
	Distributed   bool        `json:"distributed"`
	Blocks        []BlockView `json:"blocks,omitempty"`
}

// GuardStatus is the live state of one account_guard filter.
type GuardStatus struct {
	Filter    string           `json:"filter"`
	Endpoints []EndpointStatus `json:"endpoints"`
}

// Report is the management view (GET /v1/accounts).
type Report struct {
	Enabled  bool          `json:"enabled"`
	Guards   []GuardStatus `json:"guards"`
	Counters Counters      `json:"counters"`
}

// Status returns the live state of every account_guard filter with up to
// top active blocks per endpoint, soonest expiring last.
func Status(top int) Report {
	registry.mu.Lock()
	guards := make([]*guard, 0, len(registry.guards))
	for g := range registry.guards {
		guards = append(guards, g)
	}
	registry.mu.Unlock()
	sort.Slice(guards, func(i, j int) bool { return guards[i].name < guards[j].name })
	rep := Report{Enabled: len(guards) > 0, Counters: Snapshot(), Guards: []GuardStatus{}}
	for _, g := range guards {
		gs := GuardStatus{Filter: g.name}
		now := g.now()
		for i := range g.cfg.Endpoints {
			ep := &g.cfg.Endpoints[i]
			gs.Endpoints = append(gs.Endpoints, ep.status(now, top))
		}
		rep.Guards = append(rep.Guards, gs)
	}
	return rep
}

func (e *Endpoint) status(now time.Time, top int) EndpointStatus {
	t := e.table
	t.mu.Lock()
	defer t.mu.Unlock()
	st := EndpointStatus{Name: e.Name, Class: e.Class, Count: "requests", Window: e.window.String(), Paths: e.Paths,
		TrackedIPs: len(t.ips), TrackedAccts: len(t.accounts), TrackedPairs: len(t.pairs), TrackedDevs: len(t.devices), Distributed: e.Distributed != nil}
	if e.failures {
		st.Count = "failures"
	}
	if e.Distributed != nil && now.Sub(t.cStart) <= e.window {
		st.WindowEvents, st.WindowIPs = t.cEvents, len(t.cIPs)
	}
	if now.Before(t.campaignUntil) {
		until := t.campaignUntil
		st.Campaign, st.CampaignUntil = true, &until
	}
	collect := func(kind string, m map[string]*entry) {
		for k, en := range m {
			if now.Before(en.blockedUntil) {
				st.ActiveBlocks++
				st.Blocks = append(st.Blocks, BlockView{Kind: kind, Key: k, By: en.blockedBy, Until: en.blockedUntil})
			}
		}
	}
	collect("ip", t.ips)
	collect("account", t.accounts)
	collect("pair", t.pairs)
	collect("device", t.devices)
	sort.Slice(st.Blocks, func(i, j int) bool { return st.Blocks[i].Until.After(st.Blocks[j].Until) })
	if top >= 0 && len(st.Blocks) > top {
		st.Blocks = st.Blocks[:top]
	}
	return st
}
