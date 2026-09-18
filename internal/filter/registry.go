package filter

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
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
}

// Env is what the data plane hands a filter at construction.
type Env struct {
	// Log is the error stream, already tagged with the filter name.
	Log *slog.Logger
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
