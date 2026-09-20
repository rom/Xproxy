package sensitive

import (
	"sort"
	"sync"
	"sync/atomic"
)

// Process wide counters across every sensitive_data filter and every
// configuration generation.
var (
	findingsMu sync.Mutex
	kindCounts = map[string]*atomic.Uint64{} // kind -> findings
	actions    = map[string]*atomic.Uint64{} // direction|action -> messages
)

// Directions and Outcomes name the action counters in a fixed order.
var (
	Directions = []string{"request", "response"}
	Outcomes   = []string{"logged", "masked", "blocked", "unscannable"}
)

func init() {
	for _, k := range builtinNames {
		kindCounts[k] = &atomic.Uint64{}
	}
	for _, d := range Directions {
		for _, o := range Outcomes {
			actions[d+"|"+o] = &atomic.Uint64{}
		}
	}
}

func countFinding(kind string, n int) {
	findingsMu.Lock()
	c, ok := kindCounts[kind]
	if !ok {
		if len(kindCounts) >= 256 {
			findingsMu.Unlock()
			return
		}
		c = &atomic.Uint64{}
		kindCounts[kind] = c
	}
	findingsMu.Unlock()
	c.Add(uint64(n)) //nolint:gosec // findings are bounded per message
}

func countAction(direction, outcome string) {
	if c, ok := actions[direction+"|"+outcome]; ok {
		c.Add(1)
	}
}

// KindCount is findings of one kind.
type KindCount struct {
	Kind  string `json:"kind"`
	Count uint64 `json:"count"`
}

// ActionCount is messages of one direction and outcome.
type ActionCount struct {
	Direction string `json:"direction"`
	Outcome   string `json:"outcome"`
	Count     uint64 `json:"count"`
}

// Counters is the snapshot exposed to metrics and the management API.
type Counters struct {
	Findings []KindCount   `json:"findings"`
	Actions  []ActionCount `json:"actions"`
}

// Snapshot returns the counters since the process started, kinds sorted.
func Snapshot() Counters {
	var out Counters
	findingsMu.Lock()
	for k, c := range kindCounts {
		out.Findings = append(out.Findings, KindCount{Kind: k, Count: c.Load()})
	}
	findingsMu.Unlock()
	sort.Slice(out.Findings, func(i, j int) bool { return out.Findings[i].Kind < out.Findings[j].Kind })
	for _, d := range Directions {
		for _, o := range Outcomes {
			out.Actions = append(out.Actions, ActionCount{Direction: d, Outcome: o, Count: actions[d+"|"+o].Load()})
		}
	}
	return out
}
