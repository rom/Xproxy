package filter

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/intel"
)

// APIVersion is the version of the middleware contract in this package.
// It changes only when Filter, Instance, Info, Verdict or Kind change
// incompatibly; additive changes (new optional fields, new optional
// interfaces) keep the version. See docs/EXTENDING.md.
const APIVersion = 1

// Kind is a registered filter type. Configuration refers to it by Name
// under `filters[].kind`; Validate runs at configuration load and New once
// per configuration generation.
type Kind struct {
	// Name is a lower-case identifier ([a-z0-9_]).
	Name string
	// Description is one line for `xproxyctl filters` and the docs.
	Description string
	// Validate checks the options and returns every problem it can find
	// as one error. It must not depend on runtime state; whatever it
	// accepts, New must accept too.
	Validate func(opts Options) error
	// New builds the filter for one generation. name is the configured
	// instance name (also used as the deny reason unless the verdict sets
	// one). Filters holding resources implement Closer.
	New func(name string, opts Options, env Env) (Filter, error)
	// BuffersBody says the filter may hold a whole request body in
	// memory. A route with one of these charges the process-wide
	// buffered-body budget for the life of the request, because the
	// per-address connection limit multiplied by the body limit is
	// otherwise the only ceiling: 256 connections at 10 MiB is 2.5 GiB
	// of heap from one address, sent slowly inside read_timeout.
	BuffersBody bool
}

// BuffersBody reports whether a registered filter kind may hold a whole
// request body in memory.
func BuffersBody(name string) bool {
	k, ok := Lookup(name)
	return ok && k.BuffersBody
}

// Env is what the data plane hands a filter at construction.
type Env struct {
	// Log is the error stream, already tagged with the filter name.
	Log *slog.Logger
	// Events is the node's event bus, on which a filter shares facts
	// with the other nodes of a cluster (a revoked session) and learns
	// theirs. Publish is a no-op and Subscribe never fires when the proxy
	// runs alone. Nil in test harnesses that do not provide one.
	Events Events
	// Intel returns the imported threat-intelligence lists, or nil when
	// the configuration has none. It is a function rather than the set
	// itself because the set is replaced on a reload and its entries are
	// re-read under the filter's feet: a filter holding the set it was
	// built with would go on matching a feed nobody publishes any more.
	//
	// A filter that reads a payload -- the upload guard -- asks the hash
	// lists about its digest. Nil in test harnesses that provide none.
	Intel func() *intel.Set
}

// Event is one fact shared between nodes: Kind names it and selects the
// subscribers, Key identifies the subject, Until is when it stops
// mattering. Both strings are bounded (128 and 512 bytes); longer events
// are dropped.
type Event struct {
	Kind  string
	Key   string
	Until time.Time
}

// Events is the event bus a filter receives in Env.
type Events interface {
	// Publish shares an event with every peer. It never blocks and never
	// delivers the event back to local subscribers.
	Publish(e Event)
	// Subscribe registers fn for events of one kind arriving from peers.
	// fn runs on the cluster's receive goroutine and must return quickly.
	// Subscriptions live as long as the generation that built the filter.
	Subscribe(kind string, fn func(e Event))
}

// Closer is implemented by filters that hold resources (files, sockets,
// goroutines). Close runs when the generation that built the filter is
// torn down, after its in-flight requests have finished.
type Closer interface {
	Close() error
}

var (
	regMu sync.RWMutex
	kinds = map[string]Kind{}
)

// Register adds a kind. It panics on an invalid or duplicate name, which
// surfaces at process start (kinds register from init functions).
func Register(k Kind) {
	if !kindNameOK(k.Name) {
		panic(fmt.Sprintf("filter: invalid kind name %q", k.Name))
	}
	if k.Validate == nil || k.New == nil {
		panic(fmt.Sprintf("filter: kind %q needs Validate and New", k.Name))
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := kinds[k.Name]; dup {
		panic(fmt.Sprintf("filter: kind %q registered twice", k.Name))
	}
	kinds[k.Name] = k
}

func kindNameOK(n string) bool {
	if n == "" || len(n) > 32 {
		return false
	}
	for i, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r == '_' && i > 0, r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// Lookup returns a registered kind.
func Lookup(name string) (Kind, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	k, ok := kinds[name]
	return k, ok
}

// Kinds returns the registered kinds sorted by name.
func Kinds() []Kind {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Kind, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ErrUnknownKind is wrapped by Validate errors for an unregistered kind.
var ErrUnknownKind = errors.New("unknown filter kind")

// KindNames lists the registered kind names, for error messages.
func KindNames() []string {
	ks := Kinds()
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.Name
	}
	return out
}
