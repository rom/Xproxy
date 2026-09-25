package access

import (
	"log/slog"
	"time"
)

// A Guard is one listener's side of the ledger: it knows the listener's name,
// whether that listener requires a grant, and what to do when the daemon has no
// ledger at all.
//
// It exists so that a gate kind's wiring is three lines rather than a paragraph
// repeated five times -- and so that the fail-closed case is written once. A
// listener told to require grants by a daemon with no ledger refuses every
// session: the alternative is a listener that was configured to check and does
// not, which is the failure mode this whole arrangement is against. Validation
// refuses that configuration first, so it should be unreachable; a guard that
// depends on validation having run is a guard.
type Guard struct {
	ledger   *Ledger
	listener string
	log      *slog.Logger
}

// NewGuard builds a listener's guard. A nil result means this listener does not
// require a grant, so a kind can hold a *Guard and check it for nil.
//
// The ledger may be nil even when require is true, which is the case above: the
// guard is built anyway and refuses everything, because a listener that was
// asked to check must not serve as if it had.
func NewGuard(l *Ledger, listener string, require bool, log *slog.Logger) *Guard {
	if !require {
		return nil
	}
	if l == nil && log != nil {
		log.Error("listener requires an access grant and this daemon has no access ledger; every session will be refused",
			"listener", listener)
	}
	return &Guard{ledger: l, listener: listener, log: log}
}

// Admit is the decision for one session: the grant that allows it, or the
// reason it is refused. targets are what the session could reach -- the
// upstream pool's name and the addresses in it.
func (g *Guard) Admit(subject string, targets []string) (*Grant, string) {
	if g == nil {
		return nil, ""
	}
	if g.ledger == nil {
		return nil, ReasonNoGrant
	}
	return g.ledger.Admit(subject, g.listener, targets)
}

// An Admission is what a gate does with the ledger's answer: the grant, the
// reason when there is none, and the one machine the grant names when it names
// one rather than the pool.
type Admission struct {
	Grant *Grant
	// Reason is empty when the session may open.
	Reason string
	// Pinned is the endpoint address the dial must use, empty when the grant
	// covers the whole pool. A grant for one machine that let the balancer
	// choose would be access to whichever machine the pool felt like.
	Pinned string
}

// Check is the whole decision for a gate: the subject, the pool it would dial
// and the addresses in that pool.
//
// It is here rather than in each kind because the pin is easy to forget and
// impossible to notice: a listener that ignored it would pass every test that
// only has one machine behind it.
func (g *Guard) Check(subject, pool string, addrs []string) Admission {
	if g == nil {
		return Admission{}
	}
	targets := append([]string{pool}, addrs...)
	grant, reason := g.Admit(subject, targets)
	if reason != "" {
		return Admission{Reason: reason}
	}
	a := Admission{Grant: grant}
	if grant != nil && !equalName(grant.Target, pool) {
		a.Pinned = grant.Target
	}
	return a
}

// Use records that a grant opened this session. It is called once the session
// is admitted, so that a connection refused for its own reasons afterwards does
// not spend somebody's window; a failure to record is logged rather than
// returned, because the session is already running and closing it over a
// bookkeeping error would be the wrong trade.
func (g *Guard) Use(grant *Grant, session string) {
	if g == nil || g.ledger == nil || grant == nil {
		return
	}
	if err := g.ledger.Use(grant.ID, session); err != nil && g.log != nil {
		g.log.Warn("access grant use not recorded", "listener", g.listener, "grant", grant.ID, "err", err.Error())
	}
}

// CloseAtExpiry closes a session when its window ends, and returns the stop to
// defer. Without a grant it does nothing and the stop is a no-op, so a kind
// writes one line either way.
//
// A timer rather than a check on the next byte: a session that goes quiet at
// 17:55 must still be gone at 18:00, and a gateway that only notices when the
// next packet arrives leaves an idle shell open for as long as the operator
// leaves the window open.
func CloseAtExpiry(g *Grant, closeSession func()) (stop func()) {
	if g == nil || closeSession == nil {
		return func() {}
	}
	t := time.AfterFunc(time.Until(g.Expires), closeSession)
	return func() { t.Stop() }
}

// Deadline is when a session under this grant must end, or the zero time when
// there is no grant. A gate takes the earlier of this and its own session
// timeout, so a window closing ends the session that is running rather than
// only the next one somebody opens.
func Deadline(grant *Grant, own time.Time) time.Time {
	if grant == nil {
		return own
	}
	if own.IsZero() || grant.Expires.Before(own) {
		return grant.Expires
	}
	return own
}
