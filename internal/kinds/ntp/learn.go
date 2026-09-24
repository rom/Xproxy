package ntp

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/rom/xproxy/internal/ntp"
)

// Learning mode exists because nobody knows what asks a plant's time
// server for the time.
//
// The inventory says what is on the network. The traffic says what is
// actually polling, in which version, in which mode, how often, and
// whether any of it is authenticated -- and the answer is always a few
// devices nobody could name. Run this for a week and the file is the
// allow list, the version profile and the mode profile, written out ready
// to paste.
//
// A learning run decides nothing unless it is told to, and validation
// warns while it is not: a listener left in learning mode is a listener
// with no policy, and that should be a choice somebody made in writing.

// maxPolls bounds the poll intervals remembered per subject.
const maxPolls = 8

type subjectKey struct {
	client  string
	version uint8
	mode    string
}

type observation struct {
	first, last   time.Time
	packets       uint64
	denied        uint64
	nts           bool
	authenticated bool
	keyIDs        map[uint32]bool
	strata        map[uint8]bool
	// polls are the intervals seen between this subject's packets,
	// rounded to a second: what a device's poll actually is rather than
	// what its manual says.
	polls    []int
	lastSeen time.Time
}

// Learner records what crosses the listener.
type Learner struct {
	path     string
	interval time.Duration
	max      int
	listener string

	mu    sync.Mutex
	seen  map[subjectKey]*observation
	order []subjectKey

	Dropped, Observed atomic.Uint64
	Writes, Failures  atomic.Uint64

	stop chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

// NewLearner prepares a learner.
func NewLearner(listener, path string, interval time.Duration, max int) *Learner {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if max <= 0 {
		max = 8192
	}
	return &Learner{path: path, interval: interval, max: max, listener: listener,
		seen: map[subjectKey]*observation{}, stop: make(chan struct{})}
}

// Start runs the periodic write.
func (l *Learner) Start(onError func(error)) {
	if l == nil {
		return
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		t := time.NewTicker(l.interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				if err := l.Write(); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}

// Stop ends the loop and writes the report one last time.
func (l *Learner) Stop() error {
	if l == nil {
		return nil
	}
	var err error
	l.once.Do(func() {
		close(l.stop)
		l.wg.Wait()
		err = l.Write()
	})
	return err
}

// Observe records one request and what was decided about it.
func (l *Learner) Observe(r request, d Decision, now time.Time) {
	if l == nil {
		return
	}
	key := subjectKey{client: r.client.Addr().String(), version: r.pkt.Version, mode: r.pkt.Mode.String()}
	l.mu.Lock()
	defer l.mu.Unlock()
	o := l.seen[key]
	if o == nil {
		if len(l.seen) >= l.max {
			oldest := l.order[0]
			l.order = l.order[1:]
			delete(l.seen, oldest)
			l.Dropped.Add(1)
		}
		o = &observation{first: now, keyIDs: map[uint32]bool{}, strata: map[uint8]bool{}}
		l.seen[key] = o
		l.order = append(l.order, key)
	}
	if !o.lastSeen.IsZero() {
		if gap := int(now.Sub(o.lastSeen).Round(time.Second).Seconds()); gap > 0 && len(o.polls) < maxPolls {
			o.polls = append(o.polls, gap)
		}
	}
	o.lastSeen, o.last = now, now
	o.packets++
	if !d.Allow {
		o.denied++
	}
	if n := r.pkt.NTS(); n.Present {
		o.nts = true
	}
	if r.pkt.HasMAC {
		o.authenticated = true
		o.keyIDs[r.pkt.KeyID] = true
	}
	o.strata[r.pkt.Stratum] = true
	l.Observed.Add(1)
}

// Write renders the report and replaces the file atomically.
func (l *Learner) Write() error {
	if l == nil || l.path == "" {
		return nil
	}
	body := l.Report()
	tmp := filepath.Join(filepath.Dir(l.path), "."+filepath.Base(l.path)+".tmp")
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		l.Failures.Add(1)
		return err
	}
	if err := os.Rename(tmp, l.path); err != nil {
		l.Failures.Add(1)
		_ = os.Remove(tmp)
		return err
	}
	l.Writes.Add(1)
	return nil
}

// Report renders what was learned: a description of the traffic, and
// under it the three lists a policy is made of.
func (l *Learner) Report() string {
	l.mu.Lock()
	keys := make([]subjectKey, 0, len(l.seen))
	for k := range l.seen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.client != b.client {
			return a.client < b.client
		}
		if a.version != b.version {
			return a.version < b.version
		}
		return a.mode < b.mode
	})
	snap := make([]observation, 0, len(keys))
	for _, k := range keys {
		snap = append(snap, *l.seen[k])
	}
	dropped, observed := l.Dropped.Load(), l.Observed.Load()
	l.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "# NTP traffic observed by listener %q.\n", l.listener)
	fmt.Fprintf(&b, "# Written %s. %d packets, %d subjects", time.Now().UTC().Format(time.RFC3339), observed, len(keys))
	if dropped > 0 {
		fmt.Fprintf(&b, ", %d subjects dropped at the bound (raise learn.max_subjects)", dropped)
	}
	b.WriteString(".\n#\n")
	b.WriteString("# A subject is a client, a protocol version and a mode. Read it, decide what\n")
	b.WriteString("# the estate ought to be asking, and paste the lists at the end under\n")
	b.WriteString("# the listener's ntp section.\n\n")
	b.WriteString("observed:\n")
	clients := map[string]bool{}
	versions := map[uint8]bool{}
	modes := map[string]bool{}
	for i, k := range keys {
		o := snap[i]
		clients[k.client] = true
		versions[k.version] = true
		modes[k.mode] = true
		fmt.Fprintf(&b, "  - client: %s\n", k.client)
		fmt.Fprintf(&b, "    version: %d\n", k.version)
		fmt.Fprintf(&b, "    mode: %s\n", k.mode)
		fmt.Fprintf(&b, "    packets: %d\n", o.packets)
		if o.denied > 0 {
			fmt.Fprintf(&b, "    denied_by_policy: %d\n", o.denied)
		}
		fmt.Fprintf(&b, "    nts_fields: %t\n", o.nts)
		fmt.Fprintf(&b, "    authenticated: %t\n", o.authenticated)
		if len(o.keyIDs) > 0 {
			fmt.Fprintf(&b, "    key_ids: [%s]\n", joinUint32(o.keyIDs))
		}
		if len(o.polls) > 0 {
			fmt.Fprintf(&b, "    poll_seconds: [%s]\n", joinInts(o.polls))
		}
		fmt.Fprintf(&b, "    first_seen: %s\n", o.first.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "    last_seen: %s\n", o.last.UTC().Format(time.RFC3339))
	}
	if len(keys) == 0 {
		b.WriteString("  []\n")
	}
	b.WriteString("\n# A policy permitting exactly what was observed.\n")
	b.WriteString("allow_clients: [")
	b.WriteString(strings.Join(hostPrefixes(clients), ", "))
	b.WriteString("]\n")
	fmt.Fprintf(&b, "versions: [%s]\n", joinUint8(versions))
	fmt.Fprintf(&b, "modes: [%s]\n", joinStrings(modes))
	return b.String()
}

// Subjects is how many subjects are held, for the status view.
func (l *Learner) Subjects() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}

func hostPrefixes(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for a := range in {
		if strings.Contains(a, ":") {
			out = append(out, a+"/128")
			continue
		}
		out = append(out, a+"/32")
	}
	sort.Strings(out)
	return out
}

func joinUint8(in map[uint8]bool) string {
	vals := make([]int, 0, len(in))
	for v := range in {
		vals = append(vals, int(v))
	}
	sort.Ints(vals)
	return joinInts(vals)
}

func joinUint32(in map[uint32]bool) string {
	vals := make([]int, 0, len(in))
	for v := range in {
		vals = append(vals, int(v))
	}
	sort.Ints(vals)
	return joinInts(vals)
}

func joinInts(vals []int) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ", ")
}

func joinStrings(in map[string]bool) string {
	out := make([]string, 0, len(in))
	for s := range in {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// unused keeps the wire import honest when the report grows.
var _ = wire.MinVersion
