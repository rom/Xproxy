package apiabuse

import (
	"sort"
	"sync"
)

// registry holds the live filters so the data plane can report them
// without a handle on the generation that built them. A filter joins in
// New and leaves in Close, which the generation calls when it is torn
// down: a status view that kept reporting a filter a reload removed
// would be reporting a filter no request reaches.
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

// Statuses reports every live api_abuse filter, by name.
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
