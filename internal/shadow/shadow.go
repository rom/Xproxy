// Package shadow is the ledger of refusals that did not happen.
//
// A policy nobody dares turn on is not a control. Every estate this proxy
// is deployed in has the same problem: somebody writes an allow list, a
// command policy, a register range or a topic policy, and then cannot
// switch it on, because the one thing nobody knows is what it would break
// at three in the morning. So the policy stays in a branch, or goes in at
// a weekend with somebody watching, or goes in with everything allowed.
//
// Shadow mode is the answer the WAF has had for years, generalised: the
// policy is evaluated on real traffic, every decision is recorded, and
// nothing is refused. After a week the ledger says exactly which rule
// would have refused what, how often, and with what -- and an operator
// turns enforcement on knowing the answer instead of guessing it.
//
// Three rules shape it. The ledger is bounded, because what it keys on --
// a reason, a rule name, a sample of what was asked for -- comes off the
// network. It keeps counts and the first and last time rather than every
// event, because a week of a plant's Modbus traffic is millions of frames
// and the operator's question is "what would this have broken", not "show
// me every frame". And it never holds what a refusal would have refused
// *for integrity*: a malformed frame, a failed authentication, a ban, a
// rate limit and a bound are refused in shadow mode too, because
// forwarding them means acting on bytes the code could not read or
// admitting somebody who did not authenticate, which is not a policy
// question at all.
package shadow

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// MaxEntries bounds the ledger: distinct (kind, listener, reason, rule)
// combinations. A policy has tens of rules and a listener has one kind,
// so a ledger this size means something else is wrong -- and growing
// without limit would make the tool that finds a problem into one.
const MaxEntries = 4096

// MaxSample bounds the remembered example of what was asked for.
const MaxSample = 160

// Entry is one thing a policy would have refused, as a report shows it.
type Entry struct {
	Kind     string `json:"kind"`
	Listener string `json:"listener"`
	Reason   string `json:"reason"`
	// Rule is the rule that decided, where the policy has named rules.
	Rule string `json:"rule,omitempty"`
	// Sample is one example of what was asked for, clipped. It came off
	// the network, so whatever prints it filters it.
	Sample string `json:"sample,omitempty"`
	Count  uint64 `json:"count"`
	First  string `json:"first"`
	Last   string `json:"last"`
}

type key struct {
	kind, listener, reason, rule string
}

type record struct {
	count       uint64
	first, last time.Time
	sample      string
}

// Ledger holds what every listener in shadow mode would have refused.
type Ledger struct {
	mu   sync.Mutex
	max  int
	byID map[key]*record
	// Recorded counts every would-be refusal, Dropped the ones the bound
	// refused to remember: a report that silently stopped counting would
	// be worse than one that says it is full.
	Recorded, Dropped atomic.Uint64
}

// NewLedger returns an empty ledger. max of 0 is MaxEntries.
func NewLedger(max int) *Ledger {
	if max <= 0 || max > MaxEntries {
		max = MaxEntries
	}
	return &Ledger{max: max, byID: map[key]*record{}}
}

// Record adds one decision a policy made and did not enforce. It is safe
// on a nil ledger, which is what a daemon has before anything is
// configured.
func (l *Ledger) Record(kind, listener, reason, rule, sample string) {
	if l == nil || reason == "" {
		return
	}
	if len(sample) > MaxSample {
		sample = sample[:MaxSample]
	}
	now := time.Now()
	k := key{kind: kind, listener: listener, reason: reason, rule: rule}
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.byID[k]; r != nil {
		r.count++
		r.last = now
		if r.sample == "" {
			r.sample = sample
		}
		l.Recorded.Add(1)
		return
	}
	if len(l.byID) >= l.max {
		l.Dropped.Add(1)
		return
	}
	l.byID[k] = &record{count: 1, first: now, last: now, sample: sample}
	l.Recorded.Add(1)
}

// Report is what every listener in shadow mode would have refused, most
// frequent first: the order an operator reads it in, because the rule at
// the top is the one to look at before enforcement goes on.
func (l *Ledger) Report() []Entry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	out := make([]Entry, 0, len(l.byID))
	for k, r := range l.byID {
		out = append(out, Entry{Kind: k.kind, Listener: k.listener, Reason: k.reason, Rule: k.rule,
			Sample: r.sample, Count: r.count,
			First: r.first.UTC().Format(time.RFC3339), Last: r.last.UTC().Format(time.RFC3339)})
	}
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Listener != out[j].Listener {
			return out[i].Listener < out[j].Listener
		}
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

// Status is the ledger's own totals, for the status view.
type Status struct {
	// Entries is how many distinct things would have been refused,
	// Recorded how many times in total, Dropped how many the bound
	// refused to remember, and Full says the report is not complete.
	Entries  int    `json:"entries"`
	Recorded uint64 `json:"recorded"`
	Dropped  uint64 `json:"dropped"`
	Full     bool   `json:"full"`
}

// Status reports the totals.
func (l *Ledger) Status() Status {
	if l == nil {
		return Status{}
	}
	l.mu.Lock()
	n := len(l.byID)
	l.mu.Unlock()
	return Status{Entries: n, Recorded: l.Recorded.Load(), Dropped: l.Dropped.Load(), Full: n >= l.max}
}

// Reset empties the ledger, which is what an operator does after fixing a
// policy so the next week's report is about the new one.
func (l *Ledger) Reset() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.byID = map[key]*record{}
	l.mu.Unlock()
	l.Recorded.Store(0)
	l.Dropped.Store(0)
}
