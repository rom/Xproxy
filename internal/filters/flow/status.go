package flow

import (
	"sort"
	"sync"
)

// registry holds the live filters so the data plane can report them without a
// handle on the generation that built them. A filter joins in New and leaves in
// Close, which the generation calls when it is torn down: a status view that kept
// reporting a filter a reload removed would be reporting a filter no request
// reaches.
var registry = struct {
	mu      sync.Mutex
	filters map[*Filter]struct{}
}{filters: map[*Filter]struct{}{}}

func register(f *Filter) {
	registry.mu.Lock()
	registry.filters[f] = struct{}{}
	registry.mu.Unlock()
}

// Close unregisters the filter when its generation is torn down.
func (f *Filter) Close() error {
	registry.mu.Lock()
	delete(registry.filters, f)
	registry.mu.Unlock()
	return nil
}

// Status reports the counters.
type Status struct {
	Name string `json:"name"`
	// Flows is how many flows this filter enforces, and Callers how many
	// callers it is holding progress for.
	Flows   int `json:"flows"`
	Callers int `json:"callers"`
	// Requests is the requests that matched a step, Steps the ones allowed
	// through it, and Flagged the ones that were out of order or repeated.
	Requests uint64 `json:"requests"`
	Steps    uint64 `json:"steps"`
	Flagged  uint64 `json:"flagged"`
	Blocked  uint64 `json:"blocked"`
	// Challenged is the flagged requests sent to the browser challenge.
	Challenged uint64 `json:"challenged"`
	// Dropped is the callers the bound turned out of the table. A number
	// that climbs means the flows are being followed by more callers at
	// once than max_callers holds, and a caller dropped mid-flow arrives
	// at its next step looking like one that skipped a step.
	Dropped uint64 `json:"dropped"`
}

// Status reports the counters.
func (f *Filter) Status() Status {
	f.mu.Lock()
	n := len(f.callers)
	f.mu.Unlock()
	return Status{Name: f.name, Flows: len(f.cfg.flows), Callers: n,
		Requests: f.Requests.Load(), Steps: f.Steps.Load(), Flagged: f.Flagged.Load(),
		Blocked: f.Blocked.Load(), Challenged: f.Challenged.Load(), Dropped: f.Dropped.Load()}
}

// Statuses reports every live flow filter, by name.
func Statuses() []Status {
	registry.mu.Lock()
	live := make([]*Filter, 0, len(registry.filters))
	for f := range registry.filters {
		live = append(live, f)
	}
	registry.mu.Unlock()
	out := make([]Status, 0, len(live))
	for _, f := range live {
		out = append(out, f.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
