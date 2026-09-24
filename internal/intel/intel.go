// Package intel holds imported threat intelligence: lists of client
// addresses and TLS fingerprints somebody else attributed, with what to
// do about a match.
//
// It is deliberately a different thing from the ban list beside it. A ban
// is earned here: this proxy watched a client do something and decided.
// A list is imported -- a feed of scanner networks, of exit nodes, of
// addresses seen attacking somebody else -- and it says nothing about
// what the client did *here*. That difference is why the two are
// configured separately and why the actions differ: a list whose
// provenance an operator cannot check should usually challenge rather
// than block, since a feed with one wrong line is an outage nobody can
// explain from the logs.
//
// Everything about a list is therefore explicit: where it came from, how
// many entries it holds, when it was last read, and how many requests it
// has matched. A list that cannot be read at load is a load error rather
// than a list that silently matches nothing -- the failure mode that
// makes an imported list worse than none.
package intel

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kinds of list.
const (
	KindCIDR = "cidr" // client addresses and networks
	KindJA4  = "ja4"  // TLS client fingerprints
)

// Actions a match may take.
const (
	ActionLog       = "log"       // record it and serve the request
	ActionChallenge = "challenge" // make the client prove it is a browser
	ActionBlock     = "block"     // refuse it
)

// MaxEntries bounds one list. A feed larger than this is a feed this
// proxy would hold in memory per generation and match on every request,
// so it is refused with the number rather than loaded halfway.
const MaxEntries = 1 << 20

// List is one imported list.
type List struct {
	Name   string
	Kind   string
	Action string
	// File is where the entries came from.
	File string
	// Hits counts the requests this list matched.
	Hits atomic.Uint64

	// entries, guarded by the Set's lock.
	nets  []netip.Prefix
	exact map[string]struct{}
	// read state, so a reload only re-reads what changed.
	modTime time.Time
	size    int64
	count   int
	read    time.Time
}

// Hit is what a match says: which list, and what it asks for.
type Hit struct {
	List   string
	Action string
	Kind   string
}

// Set is the configured lists, in order. The order is the policy: the
// first list that matches decides, so a narrow allowance cannot be
// written after the broad list it was meant to soften.
type Set struct {
	mu    sync.RWMutex
	lists []*List
	// Matches counts requests that matched any list, Reloads the files
	// re-read since start.
	Matches, Reloads atomic.Uint64
	// The refresh loop, started at most once and stopped at most once.
	startOnce, stopOnce sync.Once
	done                chan struct{}
	refreshing          bool
}

// ListStatus is one list in the status view.
type ListStatus struct {
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Action  string    `json:"action"`
	File    string    `json:"file"`
	Entries int       `json:"entries"`
	Hits    uint64    `json:"hits"`
	Read    time.Time `json:"read"`
}

// Spec is one list as configured. The package takes its own shape rather
// than the configuration's, so a translator or a test can build a set
// without the config package.
type Spec struct {
	Name, Kind, Action, File string
}

// New reads every list. A file that cannot be read, or an entry that
// cannot be parsed, fails here: an imported list that silently matches
// nothing is worse than no list, because the operator believes it works.
func New(specs []Spec) (*Set, error) {
	s := &Set{}
	for _, sp := range specs {
		l := &List{Name: sp.Name, Kind: sp.Kind, Action: sp.Action, File: sp.File}
		if l.Kind == "" {
			l.Kind = KindCIDR
		}
		if l.Action == "" {
			l.Action = ActionLog
		}
		if err := s.read(l); err != nil {
			return nil, fmt.Errorf("threat_intel list %q: %w", l.Name, err)
		}
		s.lists = append(s.lists, l)
	}
	return s, nil
}

// read loads a list's file into it.
func (s *Set) read(l *List) error {
	f, err := os.Open(l.File) //nolint:gosec // a configured path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	var (
		nets  []netip.Prefix
		exact map[string]struct{}
		n     int
	)
	if l.Kind == KindJA4 {
		exact = map[string]struct{}{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		// A feed is a file somebody else writes, so the comment forms in
		// use are all tolerated; what is not tolerated is an entry that
		// cannot be read.
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") || strings.HasPrefix(text, "//") {
			continue
		}
		if i := strings.IndexAny(text, " \t#"); i > 0 {
			text = strings.TrimSpace(text[:i])
		}
		if n++; n > MaxEntries {
			return fmt.Errorf("more than %d entries", MaxEntries)
		}
		switch l.Kind {
		case KindJA4:
			if len(text) > 128 {
				return fmt.Errorf("line %d: %q is too long for a fingerprint", line, text)
			}
			exact[text] = struct{}{}
		default:
			p, err := parsePrefix(text)
			if err != nil {
				return fmt.Errorf("line %d: %q: %w", line, text, err)
			}
			nets = append(nets, p)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	l.nets, l.exact, l.count = nets, exact, n
	l.modTime, l.size, l.read = info.ModTime(), info.Size(), time.Now()
	s.mu.Unlock()
	return nil
}

// parsePrefix reads an address or a network, the two forms every feed of
// addresses is written in.
func parsePrefix(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		// Kept as written, host bits and all: Contains compares only the
		// prefix bits, so "10.1.2.3/8" and "10.0.0.0/8" match the same
		// addresses, and feeds are written both ways.
		return netip.ParsePrefix(text)
	}
	a, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, errors.New("not an address or a network")
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Match reports the first list that covers this client. An address is
// matched against the cidr lists and a fingerprint against the ja4 ones,
// in the order they were configured.
func (s *Set) Match(ip netip.Addr, ja4 string) (Hit, bool) {
	if s == nil {
		return Hit{}, false
	}
	ip = ip.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range s.lists {
		switch l.Kind {
		case KindJA4:
			// A client with no fingerprint -- a plaintext listener --
			// cannot match: an empty line is never an entry, so the
			// empty string is never in the map.
			if _, ok := l.exact[ja4]; !ok {
				continue
			}
		default:
			if !ip.IsValid() || !covers(l.nets, ip) {
				continue
			}
		}
		l.Hits.Add(1)
		s.Matches.Add(1)
		return Hit{List: l.Name, Action: l.Action, Kind: l.Kind}, true
	}
	return Hit{}, false
}

// covers reports whether any prefix contains the address. The lists are
// held as written rather than as a trie: a feed is tens of thousands of
// prefixes, the scan is linear in that, and a trie is a second structure
// to keep correct for a gain nobody has measured here. The bound on
// entries is what keeps the scan honest.
func covers(nets []netip.Prefix, ip netip.Addr) bool {
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Reload re-reads the lists whose file changed, and reports how many
// were re-read. A file that has become unreadable keeps the entries
// already loaded: a feed that is being rewritten in place must not empty
// the policy for the moment it takes.
func (s *Set) Reload() (int, error) {
	if s == nil {
		return 0, nil
	}
	s.mu.RLock()
	lists := make([]*List, len(s.lists))
	copy(lists, s.lists)
	s.mu.RUnlock()
	changed := 0
	var firstErr error
	for _, l := range lists {
		info, err := os.Stat(l.File)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s.mu.RLock()
		same := info.ModTime().Equal(l.modTime) && info.Size() == l.size
		s.mu.RUnlock()
		if same {
			continue
		}
		if err := s.read(l); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("threat_intel list %q: %w", l.Name, err)
			}
			continue
		}
		changed++
		s.Reloads.Add(1)
	}
	return changed, firstErr
}

// Status reports every list.
func (s *Set) Status() []ListStatus {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ListStatus, 0, len(s.lists))
	for _, l := range s.lists {
		out = append(out, ListStatus{Name: l.Name, Kind: l.Kind, Action: l.Action,
			File: l.File, Entries: l.count, Hits: l.Hits.Load(), Read: l.read})
	}
	return out
}

// Len is the number of lists.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.lists)
}

// Refresh re-reads changed files every interval until Stop. A feed is a
// file somebody else's cron job rewrites, so the alternative is an
// operator reloading the proxy to pick up a list that changed on its own
// schedule. onError is called with what a failed re-read said; the
// entries already loaded stay in force.
func (s *Set) Refresh(interval time.Duration, onError func(error)) {
	if s == nil || interval <= 0 || len(s.lists) == 0 {
		return
	}
	s.startOnce.Do(func() {
		s.done = make(chan struct{})
		s.mu.Lock()
		s.refreshing = true
		s.mu.Unlock()
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-s.done:
					return
				case <-t.C:
					if _, err := s.Reload(); err != nil && onError != nil {
						onError(err)
					}
				}
			}
		}()
	})
}

// Refreshing reports whether the refresh loop is running, which is what
// a status view answers "are these lists being watched" with.
func (s *Set) Refreshing() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refreshing
}

// Stop ends the refresh loop. It is safe to call on a set that never
// started one, and twice.
func (s *Set) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.refreshing = false
		s.mu.Unlock()
		if s.done != nil {
			close(s.done)
		}
	})
}
