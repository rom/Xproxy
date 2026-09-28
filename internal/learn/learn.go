// Package learn is the machinery a learning mode needs, without the protocol.
//
// Learning mode exists because nobody knows what an estate's traffic actually
// is. The drawings say what it was meant to be; the traffic says what the
// integrator left behind. A policy written from the drawings refuses half of it
// on the first shift, which is how a security control gets turned off and stays
// off. So a listener in learning mode records what crosses it and writes a
// proposal an engineer reads, argues with and adopts.
//
// Every kind's learning mode is the same underneath: a bounded table of
// subjects, a periodic write of the report and one more at shutdown, and the
// counters that say a run quietly stopped learning. What differs is what a
// subject is, what is worth remembering about it, and how the proposal reads in
// that protocol's own vocabulary -- so those three are the caller's, and
// everything else is here.
package learn

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
)

// DefaultInterval is how often the report is rewritten when no interval is
// given, and DefaultMax how many subjects the table holds.
const (
	DefaultInterval = 5 * time.Minute
	DefaultMax      = 8192
)

// Subject is one row of the report: what identified it and what was seen of it.
// Obs is a copy taken under the lock, so a renderer may read it freely.
type Subject[K comparable, V any] struct {
	Key K
	Obs V
}

// Stats are the numbers a report puts in its own header, because a learning run
// that stopped learning is worse than one that says so.
type Stats struct {
	// Observed is how many events were recorded, Dropped how many subjects the
	// bound could not hold.
	Observed, Dropped uint64
	// Subjects is how many the table holds now.
	Subjects int
}

// Options describe one learning run.
type Options[K comparable, V any] struct {
	// Kind names the protocol, for the temporary file's prefix and the error
	// messages -- "modbus learn: ..." is what an operator reads.
	Kind string
	// Listener is the listener's name, which the report's header carries.
	Listener string
	// Path is where the report is written. Empty writes nothing, which is how
	// a run that only counts is configured.
	Path string
	// Interval is how often the report is rewritten. Zero means
	// DefaultInterval.
	Interval time.Duration
	// Max bounds the table. Zero means DefaultMax.
	Max int
	// Render writes the report. It is called with the subjects in Less order
	// and without the lock held, so it may take its time.
	Render func(listener string, subjects []Subject[K, V], st Stats) string
	// Less orders the subjects, so that two runs over the same traffic produce
	// the same file and a diff between them means something.
	Less func(a, b K) bool
	// Clone deep-copies an observation. It is required of any V with a slice,
	// map or pointer field: the report is rendered outside the lock, and a
	// shallow copy would leave the renderer reading a slice that a concurrent
	// append is still writing to. Nil means V has no such field.
	Clone func(V) V
}

// Run is one listener's learning run.
type Run[K comparable, V any] struct {
	opt Options[K, V]

	mu   sync.Mutex
	seen map[K]*V
	// order is insertion order, so the bound drops the oldest subject rather
	// than a random one: the first thing a run saw is the thing it has had
	// longest to tell you about.
	order []K

	// Dropped counts the subjects the bound could not hold, Observed the
	// events recorded, and Writes and Failures how the report itself is
	// faring.
	Dropped, Observed atomic.Uint64
	Writes, Failures  atomic.Uint64

	stop chan struct{}
	once sync.Once
	// running is the report loop, and what Stop waits for. It is an
	// acceptgroup rather than a bare WaitGroup because Start and Stop are
	// called from the listener's own lifecycle: a shutdown that arrives before
	// serve reached Start would Wait at zero and then be Added to.
	running acceptgroup.Group
}

// New prepares a run. The report is written on the interval and at shutdown.
func New[K comparable, V any](o Options[K, V]) *Run[K, V] {
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.Max <= 0 {
		o.Max = DefaultMax
	}
	return &Run[K, V]{opt: o, seen: map[K]*V{}, stop: make(chan struct{})}
}

// Start runs the periodic write. onError hears about a report that could not be
// written, because a learning run whose file is not there is a week nobody gets
// back.
func (r *Run[K, V]) Start(onError func(error)) {
	if r == nil {
		return
	}
	if !r.running.Enter() {
		// Stopped before it started.
		return
	}
	go func() {
		defer r.running.Leave()
		t := time.NewTicker(r.opt.Interval)
		defer t.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-t.C:
				if err := r.Write(); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}

// Stop ends the loop and writes the report one last time.
func (r *Run[K, V]) Stop() error {
	if r == nil {
		return nil
	}
	var err error
	r.once.Do(func() {
		close(r.stop)
		r.running.Close()
		r.running.Wait(context.Background())
		err = r.Write()
	})
	return err
}

// Observe records one event against a subject. fn is called with the
// observation to update and whether this is the first event for it, under the
// table's lock, so it must not block.
//
// A subject the bound has no room for is counted and dropped rather than
// evicting a subject that is still being written to.
func (r *Run[K, V]) Observe(key K, fn func(v *V, first bool)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.seen[key]
	if !ok {
		if len(r.seen) >= r.opt.Max {
			r.Dropped.Add(1)
			return
		}
		o = new(V)
		r.seen[key] = o
		r.order = append(r.order, key)
	}
	r.Observed.Add(1)
	fn(o, !ok)
}

// ObserveExisting updates a subject only if the table already holds it, and
// says whether it did.
//
// It is for an event that belongs to a subject other than the one it arrived
// as: an answer that says something about the request it answers. Creating the
// subject from the answer alone would invent one the run never saw asked for.
func (r *Run[K, V]) ObserveExisting(key K, fn func(v *V)) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.seen[key]
	if !ok {
		return false
	}
	fn(o)
	return true
}

// Subjects is how many subjects the table holds.
func (r *Run[K, V]) Subjects() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

// Report renders what was learned. The snapshot is taken under the lock and the
// rendering is done outside it.
func (r *Run[K, V]) Report() string {
	if r == nil || r.opt.Render == nil {
		return ""
	}
	r.mu.Lock()
	subjects := make([]Subject[K, V], 0, len(r.seen))
	for _, k := range r.order {
		o, ok := r.seen[k]
		if !ok {
			continue
		}
		v := *o
		if r.opt.Clone != nil {
			v = r.opt.Clone(v)
		}
		subjects = append(subjects, Subject[K, V]{Key: k, Obs: v})
	}
	st := Stats{Observed: r.Observed.Load(), Dropped: r.Dropped.Load(), Subjects: len(r.seen)}
	r.mu.Unlock()

	if r.opt.Less != nil {
		sort.SliceStable(subjects, func(i, j int) bool {
			return r.opt.Less(subjects[i].Key, subjects[j].Key)
		})
	}
	return r.opt.Render(r.opt.Listener, subjects, st)
}

// Write renders the report and replaces the file atomically, so that a reader
// sees one whole report or the previous one and never half of either.
func (r *Run[K, V]) Write() error {
	if r == nil || r.opt.Path == "" {
		return nil
	}
	body := r.Report()
	dir := filepath.Dir(r.opt.Path)
	tmp, err := os.CreateTemp(dir, "."+r.opt.Kind+"-learn-*")
	if err != nil {
		r.Failures.Add(1)
		return r.errf(err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		r.Failures.Add(1)
		return r.errf(err)
	}
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		r.Failures.Add(1)
		return r.errf(err)
	}
	if err := tmp.Close(); err != nil {
		r.Failures.Add(1)
		return r.errf(err)
	}
	if err := os.Rename(name, r.opt.Path); err != nil {
		r.Failures.Add(1)
		return r.errf(err)
	}
	r.Writes.Add(1)
	return nil
}

func (r *Run[K, V]) errf(err error) error {
	return fmt.Errorf("%s learn: %w", r.opt.Kind, err)
}

// Header is the part of a report every kind writes the same way: what was
// watched, when it was written, how much was seen, and whether the bound was
// reached.
func Header(kind, listener string, st Stats, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s traffic observed by listener %q.\n", kind, listener)
	fmt.Fprintf(&b, "# Written %s. %d events, %d subjects",
		now.UTC().Format(time.RFC3339), st.Observed, st.Subjects)
	if st.Dropped > 0 {
		fmt.Fprintf(&b, ", %d subjects dropped at the bound (raise learn.max_subjects)", st.Dropped)
	}
	b.WriteString(".\n")
	return b.String()
}

// Sanitise makes a string safe to write into the report unquoted: a client
// name, a path or an identifier arrives off the network, and a report is a file
// somebody pastes into a configuration.
func Sanitise(s string) string {
	s = strings.Map(func(ch rune) rune {
		switch {
		case ch < 0x20, ch == 0x7f:
			return -1
		case ch == '\'', ch == '"', ch == '\\':
			return -1
		default:
			return ch
		}
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
