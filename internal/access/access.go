// Package access is just-in-time access to a bastion: a session is opened
// against a grant that somebody asked for, somebody else approved, and that
// stops being valid by itself.
//
// A bastion with standing access is a bastion whose accounts are as valuable as
// the machines behind it. The keys are in the estate all the time, so an
// attacker who reaches a key, a laptop or a session reaches production at a
// moment of their choosing. What this package holds instead is the other
// arrangement: nobody may open a session unless there is a live grant naming
// them, the listener and the target; the grant has an end; and a second person
// had to agree to it.
//
// Three rules carry that, and each of them exists because leaving it out is how
// the arrangement is usually defeated:
//
//   - **Four eyes.** A grant is in force only once enough people have approved
//     it, and neither the person who asked nor the person who gains the access
//     may be one of them. An approval flow where the requester can approve is
//     paperwork, not control.
//   - **A time box.** Every grant carries an end, bounded by what the policy
//     allows an approver to give. Access that has to be taken away by somebody
//     remembering to take it away is standing access with extra steps.
//   - **A written record.** Every request, approval, denial, revocation and use
//     is appended to a ledger that carries a hash chain, so the trail an
//     investigation reads is one an editor cannot quietly change.
//
// The decisions here are deliberately about *admission*: whether a session may
// begin, and by when it must end. What the session may then do stays with the
// listener's own policy -- a grant is permission to be there, not permission to
// do anything in particular.
package access

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Refusal reasons, in the spelling the listeners' counters and the ban list
// use. They are separate reasons rather than one "denied" because an operator
// answering a call needs to know which: a session refused because nobody
// approved yet is a process problem, and one refused because the window closed
// is the arrangement working.
const (
	ReasonNoGrant  = "no_grant"
	ReasonPending  = "grant_pending"
	ReasonEarly    = "grant_not_yet"
	ReasonExpired  = "grant_expired"
	ReasonDenied   = "grant_denied"
	ReasonRevoked  = "grant_revoked"
	ReasonSpent    = "grant_spent"
	ReasonNoTarget = "grant_wrong_target"
)

// A State is where a grant stands. It is computed from the record and the
// clock rather than stored, so a grant cannot be left in a state its own
// fields contradict -- an "active" row whose window closed an hour ago is the
// kind of thing an approval system is judged by.
type State string

const (
	// Pending is asked for and not yet approved by enough people.
	Pending State = "pending"
	// Scheduled is approved, with its window still ahead.
	Scheduled State = "scheduled"
	// Active is approved and inside its window, with uses left.
	Active State = "active"
	// Spent has used up its uses.
	Spent State = "spent"
	// Expired reached the end of its window.
	Expired State = "expired"
	// Denied was refused by an approver.
	Denied State = "denied"
	// Revoked was withdrawn, which may happen mid-window.
	Revoked State = "revoked"
)

var (
	// ErrUnknownGrant is an id no record names.
	ErrUnknownGrant = errors.New("access: no such grant")
	// ErrSelfApproval is an approval by the person who asked or by the person
	// who gains the access.
	ErrSelfApproval = errors.New("access: an approval may not come from the requester or the subject")
	// ErrDuplicateApproval is a second approval from one approver. Four eyes
	// means two people, not one person twice.
	ErrDuplicateApproval = errors.New("access: this approver has already approved")
	// ErrNotOpen is an approval, denial or use of a grant that is finished.
	ErrNotOpen = errors.New("access: the grant is no longer open")
	// ErrTooMany is a request beyond max_open.
	ErrTooMany = errors.New("access: too many open grants")
)

// Policy is what the estate allows a grant to be. It comes from the
// configuration and is applied when a request is made rather than when it is
// used: an approver cannot be asked to notice that a window is too long.
type Policy struct {
	// Approvals is how many approvals a grant needs *in addition to* the
	// request. 1 is four eyes: the person who asked and one other.
	Approvals int
	// MaxDuration bounds the window a grant may cover.
	MaxDuration time.Duration
	// MaxLead bounds how far ahead of now a window may start, so that an
	// approval today cannot be a key for next quarter.
	MaxLead time.Duration
	// MaxUses bounds the sessions one grant may open; 0 is as many as the
	// window allows.
	MaxUses int
	// MaxOpen bounds the grants that may be pending or in force at once. It
	// is a bound on this process rather than on the estate's process: a
	// request queue nobody drains is how an approval system becomes a
	// rubber stamp.
	MaxOpen int
	// MaxWorkOrder bounds the window a work order may cover; 0 is the
	// package default of thirty days. It is separate from MaxDuration
	// because the two measure different things: a grant is a window
	// somebody is admitted through and is short by design, while a work
	// order is how long the work lasts and a plant shutdown is a fortnight.
	MaxWorkOrder time.Duration
	// SelfApproval lets the requester approve their own request. It exists
	// because a single-operator estate that cannot make a grant at all
	// would simply turn the requirement off, and an explicit, logged,
	// warned-about opt-in is better than that. It is never the default.
	SelfApproval bool
}

// Decision is one person's act on a grant.
type Decision struct {
	By   string    `json:"by"`
	At   time.Time `json:"at"`
	Note string    `json:"note,omitempty"`
}

// A Grant is one ask for access and everything that happened to it.
type Grant struct {
	ID string `json:"id"`
	// Subject is the authenticated name that may connect: the SSH principal
	// or login, the RDP or telnet user. It is who the access is *for*,
	// which is not always who asked.
	Subject string `json:"subject"`
	// Listener is the listener the grant is on, and Target the host:port
	// behind it. A grant is not a key to the estate: it names one door.
	Listener string `json:"listener"`
	Target   string `json:"target"`
	// Reason is what an investigation reads first. It is required, because
	// a trail of approvals with no reasons in it answers nothing.
	Reason string `json:"reason"`
	// By is who asked, At when.
	By string    `json:"by"`
	At time.Time `json:"at"`
	// NotBefore and Expires are the window.
	NotBefore time.Time `json:"not_before"`
	Expires   time.Time `json:"expires"`
	// MaxUses is the sessions this grant may open, 0 for as many as the
	// window allows; Uses counts those opened.
	MaxUses int `json:"max_uses,omitempty"`
	Uses    int `json:"uses,omitempty"`
	// Approvals are the people who agreed, Refusal the one who did not and
	// Revocation the one who took it back.
	Approvals  []Decision `json:"approvals,omitempty"`
	Refusal    *Decision  `json:"refusal,omitempty"`
	Revocation *Decision  `json:"revocation,omitempty"`
	// NeedApprovals is the approvals this grant was created needing. It is
	// stored on the grant rather than read from the policy at decision
	// time, so that loosening the configuration does not retroactively
	// bring a half-approved grant into force -- and so that the record of
	// what was required is the record, not today's setting.
	NeedApprovals int `json:"need_approvals"`
}

// State computes where the grant stands at a moment.
func (g *Grant) State(now time.Time) State {
	switch {
	case g.Revocation != nil:
		return Revoked
	case g.Refusal != nil:
		return Denied
	case len(g.Approvals) < g.NeedApprovals:
		// A request nobody approved before its window closed is expired
		// rather than pending: it cannot come into force any more, and
		// leaving it in the queue would hide the ones that still can.
		if !now.Before(g.Expires) {
			return Expired
		}
		return Pending
	case !now.Before(g.Expires):
		return Expired
	case g.MaxUses > 0 && g.Uses >= g.MaxUses:
		return Spent
	case now.Before(g.NotBefore):
		return Scheduled
	}
	return Active
}

// Open says whether the grant can still change: a pending or in-force grant is
// open, and a finished one is history.
func (g *Grant) Open(now time.Time) bool {
	switch g.State(now) {
	case Pending, Scheduled, Active:
		return true
	}
	return false
}

// refusal maps a state to the reason a listener records. Only the states a
// session can be refused in appear; Active is not a refusal.
func refusal(s State) string {
	switch s {
	case Pending:
		return ReasonPending
	case Scheduled:
		return ReasonEarly
	case Spent:
		return ReasonSpent
	case Denied:
		return ReasonDenied
	case Revoked:
		return ReasonRevoked
	default:
		return ReasonExpired
	}
}

// approvedBy says whether somebody has already approved.
func (g *Grant) approvedBy(who string) bool {
	return slices.ContainsFunc(g.Approvals, func(d Decision) bool { return equalName(d.By, who) })
}

// equalName compares two identities as an operator writes them: trimmed, and
// case-insensitively, because "Alice" approving what "alice" asked for is one
// person and must not pass for two.
func equalName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// Request is what a caller asks for. The ledger fills in the identity fields it
// is entitled to fill in and refuses the rest.
type Request struct {
	Subject   string
	Listener  string
	Target    string
	Reason    string
	By        string
	NotBefore time.Time
	Expires   time.Time
	MaxUses   int
}

// check validates a request against the policy, at the moment it is made.
func (p Policy) check(r Request, now time.Time) error {
	for _, f := range []struct{ name, val string }{
		{"subject", r.Subject}, {"listener", r.Listener}, {"target", r.Target},
		{"reason", r.Reason}, {"by", r.By},
	} {
		if strings.TrimSpace(f.val) == "" {
			return fmt.Errorf("access: %s is required", f.name)
		}
	}
	if r.Expires.Before(now) || r.Expires.Equal(now) {
		return errors.New("access: the window has already closed")
	}
	if !r.NotBefore.IsZero() && !r.Expires.After(r.NotBefore) {
		return errors.New("access: the window ends before it starts")
	}
	start := r.NotBefore
	if start.IsZero() {
		start = now
	}
	if p.MaxDuration > 0 && r.Expires.Sub(start) > p.MaxDuration {
		return fmt.Errorf("access: the window is longer than max_duration %s", p.MaxDuration)
	}
	if p.MaxLead > 0 && start.Sub(now) > p.MaxLead {
		return fmt.Errorf("access: the window starts further ahead than max_lead %s", p.MaxLead)
	}
	if r.MaxUses < 0 {
		return errors.New("access: max_uses must not be negative")
	}
	if p.MaxUses > 0 && (r.MaxUses == 0 || r.MaxUses > p.MaxUses) {
		return fmt.Errorf("access: max_uses must be between 1 and %d", p.MaxUses)
	}
	return nil
}
