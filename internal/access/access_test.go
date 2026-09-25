package access

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// ledger is a memory-only ledger with a clock a test drives.
func ledger(t *testing.T, pol Policy) (*Ledger, *time.Time) {
	t.Helper()
	l, err := Open("", pol)
	if err != nil {
		t.Fatal(err)
	}
	now := t0
	l.SetClockForTest(func() time.Time { return now })
	t.Cleanup(func() { _ = l.Close() })
	return l, &now
}

func fourEyes() Policy {
	return Policy{Approvals: 1, MaxDuration: 4 * time.Hour, MaxLead: 24 * time.Hour, MaxOpen: 16}
}

func ask(t *testing.T, l *Ledger, subject, by string) *Grant {
	t.Helper()
	g, err := l.Request(Request{Subject: subject, Listener: "bastion", Target: "db-1:22",
		Reason: "incident 4711", By: by, Expires: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The shape of the thing: nobody gets in until somebody else has agreed, and
// then only within the window.
func TestASessionNeedsAGrantSomebodyElseApproved(t *testing.T) {
	l, now := ledger(t, fourEyes())
	g := ask(t, l, "alice", "alice")

	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonPending {
		t.Errorf("before approval: %q, want %q", reason, ReasonPending)
	}
	if _, err := l.Approve(g.ID, "bob", "spoke to alice"); err != nil {
		t.Fatal(err)
	}
	got, reason := l.Admit("alice", "bastion", []string{"db-1:22"})
	if got == nil {
		t.Fatalf("after approval: refused with %q", reason)
	}
	if got.ID != g.ID {
		t.Errorf("admitted under %s, want %s", got.ID, g.ID)
	}

	// And the window ends by itself.
	*now = t0.Add(time.Hour + time.Second)
	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonExpired {
		t.Errorf("after the window: %q, want %q", reason, ReasonExpired)
	}
}

// Four eyes is two people. The person who asked and the person who gains the
// access are both refused as approvers -- without that the feature is a form to
// fill in.
func TestNeitherTheRequesterNorTheSubjectMayApprove(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	// Asked by a colleague on alice's behalf, so requester and subject are
	// different people and each has to be refused on its own.
	g, err := l.Request(Request{Subject: "alice", Listener: "bastion", Target: "db-1:22",
		Reason: "incident 4711", By: "carol", Expires: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"carol", "alice", "CAROL", " Alice "} {
		if _, err := l.Approve(g.ID, who, ""); !errors.Is(err, ErrSelfApproval) {
			t.Errorf("approval by %q: %v, want ErrSelfApproval", who, err)
		}
	}
	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonPending {
		t.Errorf("after the refused approvals: %q, want %q", reason, ReasonPending)
	}
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	if g, _ := l.Admit("alice", "bastion", []string{"db-1:22"}); g == nil {
		t.Error("a colleague's approval did not let it in")
	}
}

// One person approving twice is one person. A policy asking for two approvals
// is asking for two people.
func TestOneApproverCannotCountTwice(t *testing.T) {
	pol := fourEyes()
	pol.Approvals = 2
	l, _ := ledger(t, pol)
	g := ask(t, l, "alice", "alice")
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(g.ID, "BOB", ""); !errors.Is(err, ErrDuplicateApproval) {
		t.Errorf("second approval by the same person: %v, want ErrDuplicateApproval", err)
	}
	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonPending {
		t.Errorf("one approval against a policy of two: %q, want %q", reason, ReasonPending)
	}
	if _, err := l.Approve(g.ID, "carol", ""); err != nil {
		t.Fatal(err)
	}
	if g, _ := l.Admit("alice", "bastion", []string{"db-1:22"}); g == nil {
		t.Error("two approvals did not let it in")
	}
}

// A grant names one door. The subject, the listener and the target all have to
// match, and a grant for the wrong target says so rather than saying there is
// no grant: the difference is what an operator does next.
func TestAGrantIsForOneSubjectListenerAndTarget(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g := ask(t, l, "alice", "alice")
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ subject, listener, target, want string }{
		{"alice", "bastion", "db-1:22", ""},
		{"alice", "bastion", "db-2:22", ReasonNoTarget},
		{"alice", "jump", "db-1:22", ReasonNoGrant},
		{"eve", "bastion", "db-1:22", ReasonNoGrant},
	} {
		got, reason := l.Admit(c.subject, c.listener, []string{c.target})
		if reason != c.want || (c.want == "" && got == nil) {
			t.Errorf("%s on %s to %s: %q, want %q", c.subject, c.listener, c.target, reason, c.want)
		}
	}
}

// The window is applied when the request is made, not left to an approver to
// notice: an approver asked to check arithmetic is an approver who approves.
func TestThePolicyBoundsTheWindowAtRequestTime(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	cases := map[string]Request{
		"longer than max_duration": {Expires: t0.Add(5 * time.Hour)},
		"further ahead than max_lead": {NotBefore: t0.Add(48 * time.Hour),
			Expires: t0.Add(49 * time.Hour)},
		"already closed":             {Expires: t0.Add(-time.Minute)},
		"closes at this very moment": {Expires: t0},
		"ends before it starts": {NotBefore: t0.Add(time.Hour),
			Expires: t0.Add(30 * time.Minute)},
		"negative uses": {Expires: t0.Add(time.Hour), MaxUses: -1},
	}
	for name, r := range cases {
		r.Subject, r.Listener, r.Target, r.Reason, r.By = "alice", "bastion", "db-1:22", "incident", "carol"
		if _, err := l.Request(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// And each identity field is required, because a trail of approvals
	// with no reasons in it answers nothing.
	for _, missing := range []string{"subject", "listener", "target", "reason", "by"} {
		r := Request{Subject: "alice", Listener: "bastion", Target: "db-1:22", Reason: "incident", By: "carol",
			Expires: t0.Add(time.Hour)}
		switch missing {
		case "subject":
			r.Subject = "  "
		case "listener":
			r.Listener = ""
		case "target":
			r.Target = ""
		case "reason":
			r.Reason = " "
		case "by":
			r.By = ""
		}
		_, err := l.Request(r)
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("without %s: %v", missing, err)
		}
	}
}

// A window that has not opened yet is not a refusal to fix by re-approving: the
// reason says so.
func TestAWindowAheadOfNowIsNotYet(t *testing.T) {
	l, now := ledger(t, fourEyes())
	g, err := l.Request(Request{Subject: "alice", Listener: "bastion", Target: "db-1:22", Reason: "change 9",
		By: "carol", NotBefore: t0.Add(30 * time.Minute), Expires: t0.Add(90 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonEarly {
		t.Errorf("before the window opens: %q, want %q", reason, ReasonEarly)
	}
	*now = t0.Add(time.Hour)
	if g, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); g == nil {
		t.Errorf("inside the window: %q", reason)
	}
}

// Revocation takes effect at once, including on a grant that is in force, and
// is not something four eyes slows down: taking access away is not the decision
// the requirement exists to guard.
func TestRevocationEndsAGrantThatIsInForce(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g := ask(t, l, "alice", "alice")
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Revoke(g.ID, "dave", "laptop stolen"); err != nil {
		t.Fatal(err)
	}
	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonRevoked {
		t.Errorf("after revocation: %q, want %q", reason, ReasonRevoked)
	}
	// And a revoked grant is finished: it cannot be approved back to life.
	if _, err := l.Approve(g.ID, "erin", ""); !errors.Is(err, ErrNotOpen) {
		t.Errorf("approving a revoked grant: %v, want ErrNotOpen", err)
	}
}

// A denial is recorded rather than left as a request that quietly expires, and
// it is final.
func TestADenialIsFinal(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g := ask(t, l, "alice", "alice")
	if _, err := l.Deny(g.ID, "bob", "no change window"); err != nil {
		t.Fatal(err)
	}
	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonDenied {
		t.Errorf("after a denial: %q, want %q", reason, ReasonDenied)
	}
	if _, err := l.Approve(g.ID, "carol", ""); !errors.Is(err, ErrNotOpen) {
		t.Errorf("approving a denied grant: %v, want ErrNotOpen", err)
	}
	v, ok := l.Get(g.ID)
	if !ok || v.State != Denied || v.Refusal == nil || v.Refusal.Note != "no change window" {
		t.Errorf("the denial is not in the record: %+v", v)
	}
}

// max_uses is spent by use rather than by time, which is what makes a one-shot
// grant one shot. Admit does not spend it: a connection refused afterwards for
// its own reasons must not consume somebody's window.
func TestAUseIsSpentWhenTheListenerSaysItIs(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g, err := l.Request(Request{Subject: "alice", Listener: "bastion", Target: "db-1:22", Reason: "one look",
		By: "carol", Expires: t0.Add(time.Hour), MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	// Two admissions in a row, neither of which spends the grant.
	for i := range 2 {
		if got, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); got == nil {
			t.Fatalf("admission %d: %q", i, reason)
		}
	}
	if err := l.Use(g.ID, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonSpent {
		t.Errorf("after the one use: %q, want %q", reason, ReasonSpent)
	}
	if err := l.Use(g.ID, "sess-2"); !errors.Is(err, ErrNotOpen) {
		t.Errorf("using a spent grant: %v, want ErrNotOpen", err)
	}
}

// The deadline is what makes the window bite on a session that is already open:
// a gate sets it on the connection, so a window closing ends the session that
// is running rather than only the next one somebody opens.
func TestTheDeadlineIsTheEndOfTheWindow(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g := ask(t, l, "alice", "alice")
	if got := l.Deadline(g.ID); !got.Equal(t0.Add(time.Hour)) {
		t.Errorf("deadline %s, want %s", got, t0.Add(time.Hour))
	}
	if got := l.Deadline("nothing"); !got.IsZero() {
		t.Errorf("deadline of an unknown grant: %s, want the zero time", got)
	}
}

// A queue nobody drains is how an approval system becomes a rubber stamp, so
// the open grants are bounded -- and the bound counts open ones only, so a
// closed grant does not hold a place for ever.
func TestOpenGrantsAreBounded(t *testing.T) {
	pol := fourEyes()
	pol.MaxOpen = 2
	l, _ := ledger(t, pol)
	a := ask(t, l, "alice", "carol")
	b := ask(t, l, "bob", "carol")
	if _, err := l.Request(Request{Subject: "dave", Listener: "bastion", Target: "db-1:22", Reason: "third",
		By: "carol", Expires: t0.Add(time.Hour)}); !errors.Is(err, ErrTooMany) {
		t.Errorf("a third open grant: %v, want ErrTooMany", err)
	}
	if _, err := l.Deny(a.ID, "bob", "not now"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Request(Request{Subject: "dave", Listener: "bastion", Target: "db-1:22", Reason: "third",
		By: "carol", Expires: t0.Add(time.Hour)}); err != nil {
		t.Errorf("after one closed: %v", err)
	}
	if b == nil {
		t.Fatal("unreachable")
	}
}

// A request that nobody approved before its window closed is expired rather
// than pending: it cannot come into force any more, and leaving it in the queue
// would hide the ones that still can.
func TestAnUnapprovedRequestExpiresRatherThanWaitingForEver(t *testing.T) {
	l, now := ledger(t, fourEyes())
	g := ask(t, l, "alice", "carol")
	*now = t0.Add(2 * time.Hour)
	v, ok := l.Get(g.ID)
	if !ok || v.State != Expired {
		t.Errorf("state %q, want %q", v.State, Expired)
	}
	if _, err := l.Approve(g.ID, "bob", ""); !errors.Is(err, ErrNotOpen) {
		t.Errorf("approving it afterwards: %v, want ErrNotOpen", err)
	}
	// And it no longer counts against the bound.
	if n := l.openCount(*now); n != 0 {
		t.Errorf("%d open grants, want 0", n)
	}
}

// Self-approval exists for the estate with one operator, where the alternative
// is turning the requirement off altogether. It is never the default, and when
// it is on the trail still says who approved.
func TestSelfApprovalIsAnExplicitOptIn(t *testing.T) {
	pol := fourEyes()
	pol.SelfApproval = true
	l, _ := ledger(t, pol)
	g := ask(t, l, "alice", "alice")
	if _, err := l.Approve(g.ID, "alice", "sole operator"); err != nil {
		t.Fatalf("with self_approval on: %v", err)
	}
	if got, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); got == nil {
		t.Errorf("refused: %q", reason)
	} else if len(got.Approvals) != 1 || got.Approvals[0].By != "alice" {
		t.Errorf("the trail does not name the approver: %+v", got.Approvals)
	}
	// Even then, one person still cannot count twice.
	if _, err := l.Approve(g.ID, "alice", ""); !errors.Is(err, ErrDuplicateApproval) {
		t.Errorf("a second approval by the same person: %v", err)
	}
}

// Loosening the policy must not bring a half-approved grant into force: what
// was required when it was asked for is what it needs, and the record says so.
func TestTheApprovalsARequestNeededAreFixedWhenItIsMade(t *testing.T) {
	pol := fourEyes()
	pol.Approvals = 2
	l, _ := ledger(t, pol)
	g := ask(t, l, "alice", "carol")
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	// The estate decides one approval is enough from now on.
	l.pol.Approvals = 1
	if _, reason := l.Admit("alice", "bastion", []string{"db-1:22"}); reason != ReasonPending {
		t.Errorf("after loosening the policy: %q, want %q", reason, ReasonPending)
	}
	if v, _ := l.Get(g.ID); v.NeedApprovals != 2 {
		t.Errorf("the grant needs %d approvals, want the 2 it was made with", v.NeedApprovals)
	}
}

// The counters are what an operator watches: a listener turning sessions away
// for want of a grant looks the same from outside as one that is down.
func TestTheCountersSeparateTheReasons(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g := ask(t, l, "alice", "carol")
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	if err := l.Use(g.ID, "sess"); err != nil {
		t.Fatal(err)
	}
	l.Admit("eve", "bastion", []string{"db-1:22"})
	l.Admit("alice", "bastion", []string{"db-2:22"})
	s := l.Stats()
	if s.Requests != 1 || s.Approvals != 1 || s.Uses != 1 {
		t.Errorf("counters %+v", s)
	}
	if s.Refusals[ReasonNoGrant] != 1 || s.Refusals[ReasonNoTarget] != 1 {
		t.Errorf("refusals %+v", s.Refusals)
	}
	// A copy, so a caller cannot edit the ledger's own counters.
	s.Refusals[ReasonNoGrant] = 99
	if l.Stats().Refusals[ReasonNoGrant] != 1 {
		t.Error("Stats handed out the ledger's own map")
	}
}

// An unknown id is not an error a caller can confuse with a refusal.
func TestAnUnknownGrantIsNotFound(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	for _, err := range []error{
		mustErr(l.Approve("nope", "bob", "")),
		mustErr(l.Deny("nope", "bob", "")),
		mustErr(l.Revoke("nope", "bob", "")),
		l.Use("nope", "sess"),
	} {
		if !errors.Is(err, ErrUnknownGrant) {
			t.Errorf("%v, want ErrUnknownGrant", err)
		}
	}
	if _, ok := l.Get("nope"); ok {
		t.Error("Get found a grant that does not exist")
	}
}

// An approval with no approver is not an approval: the trail would carry an
// agreement nobody made.
func TestAnActOfNobodyIsRefused(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g := ask(t, l, "alice", "carol")
	if _, err := l.Approve(g.ID, "  ", ""); err == nil {
		t.Error("an approval by nobody was accepted")
	}
	if _, err := l.Deny(g.ID, "", ""); err == nil {
		t.Error("a denial by nobody was accepted")
	}
	if _, err := l.Revoke(g.ID, "", ""); err == nil {
		t.Error("a revocation by nobody was accepted")
	}
}

// mustErr keeps the table above readable: the grant a call returns is not what
// is being asserted on.
func mustErr(_ *Grant, err error) error { return err }

// A gate offers what the session could reach: the pool's name and the addresses
// in it. A grant naming the pool covers any of them, and a grant naming one
// machine covers that machine and says so, which is how the gate knows to pin
// the dial rather than let the balancer choose.
func TestAGrantNamesEitherThePoolOrOneMachine(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	candidates := []string{"prod-db", "db-1:22", "db-2:22"}

	pool, err := l.Request(Request{Subject: "alice", Listener: "bastion", Target: "prod-db",
		Reason: "any of them", By: "carol", Expires: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(pool.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	g, reason := l.Admit("alice", "bastion", candidates)
	if g == nil {
		t.Fatalf("a grant on the pool did not admit: %q", reason)
	}
	if g.Target != "prod-db" {
		t.Errorf("the grant names %q, want the pool", g.Target)
	}

	one, err := l.Request(Request{Subject: "dave", Listener: "bastion", Target: "db-2:22",
		Reason: "that machine", By: "carol", Expires: t0.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(one.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	g, reason = l.Admit("dave", "bastion", candidates)
	if g == nil {
		t.Fatalf("a grant on one endpoint did not admit: %q", reason)
	}
	if g.Target != "db-2:22" {
		t.Errorf("the grant names %q, want the one machine it was asked for", g.Target)
	}
	// And that grant does not follow the pool to another machine.
	if _, reason := l.Admit("dave", "bastion", []string{"prod-db", "db-1:22"}); reason != ReasonNoTarget {
		t.Errorf("a grant for db-2 reached db-1: %q", reason)
	}
}

// A listener told to require a grant by a daemon that has no ledger refuses
// every session. The alternative is a listener that was configured to check and
// does not, which is the failure this whole arrangement is against; validation
// refuses that configuration first, and the guard does not depend on validation
// having run.
func TestAGuardWithNoLedgerRefusesEverything(t *testing.T) {
	g := NewGuard(nil, "bastion", true, nil)
	if g == nil {
		t.Fatal("a listener that requires a grant got no guard")
	}
	if _, reason := g.Admit("alice", []string{"prod-db"}); reason != ReasonNoGrant {
		t.Errorf("%q, want %q", reason, ReasonNoGrant)
	}
	// And it does not panic on the calls a session would make anyway.
	g.Use(nil, "sess")
	g.Use(&Grant{ID: "nope"}, "sess")
}

// A listener that does not require a grant gets no guard, and the nil guard
// admits: a kind holds one field and writes no conditionals.
func TestNoGuardAdmits(t *testing.T) {
	var g *Guard
	if NewGuard(nil, "bastion", false, nil) != nil {
		t.Error("a listener that requires nothing got a guard")
	}
	grant, reason := g.Admit("alice", []string{"prod-db"})
	if grant != nil || reason != "" {
		t.Errorf("a nil guard refused: %v %q", grant, reason)
	}
	g.Use(nil, "sess")
}

// The guard is the ledger with one listener's name filled in, and Use spends
// through it.
func TestTheGuardIsTheLedgerForOneListener(t *testing.T) {
	l, _ := ledger(t, fourEyes())
	g, err := l.Request(Request{Subject: "alice", Listener: "bastion", Target: "db-1:22", Reason: "one look",
		By: "carol", Expires: t0.Add(time.Hour), MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Approve(g.ID, "bob", ""); err != nil {
		t.Fatal(err)
	}
	guard := NewGuard(l, "bastion", true, nil)
	got, reason := guard.Admit("alice", []string{"prod-db", "db-1:22"})
	if got == nil {
		t.Fatalf("refused: %q", reason)
	}
	guard.Use(got, "sess-1")
	if _, reason := guard.Admit("alice", []string{"db-1:22"}); reason != ReasonSpent {
		t.Errorf("after the use: %q, want %q", reason, ReasonSpent)
	}
	// A guard for another listener does not see it.
	other := NewGuard(l, "jump", true, nil)
	if _, reason := other.Admit("alice", []string{"db-1:22"}); reason != ReasonNoGrant {
		t.Errorf("another listener saw the grant: %q", reason)
	}
}

// The session's deadline is the earlier of the window's end and whatever the
// listener already meant to allow, so neither bound is lost.
func TestTheDeadlineTakesTheEarlierBound(t *testing.T) {
	g := &Grant{Expires: t0.Add(time.Hour)}
	for name, c := range map[string]struct{ own, want time.Time }{
		"no bound of its own": {time.Time{}, g.Expires},
		"a later bound":       {t0.Add(2 * time.Hour), g.Expires},
		"an earlier bound":    {t0.Add(30 * time.Minute), t0.Add(30 * time.Minute)},
	} {
		if got := Deadline(g, c.own); !got.Equal(c.want) {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	if got := Deadline(nil, t0); !got.Equal(t0) {
		t.Errorf("without a grant: %s, want the listener's own bound", got)
	}
}

// CloseAtExpiry is the other half of the time box, for a kind whose session is
// a pair of sockets rather than a connection with a deadline: the window ending
// closes it, even if it has been idle since it opened.
func TestCloseAtExpiryClosesTheSession(t *testing.T) {
	closed := make(chan struct{})
	stop := CloseAtExpiry(&Grant{Expires: time.Now().Add(30 * time.Millisecond)}, func() { close(closed) })
	defer stop()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Error("the window closed and the session did not")
	}

	// Stopping it before the window ends leaves the session alone, which is
	// what the deferred stop is for when a session ends first.
	again := make(chan struct{})
	CloseAtExpiry(&Grant{Expires: time.Now().Add(time.Hour)}, func() { close(again) })()
	select {
	case <-again:
		t.Error("a stopped timer closed the session")
	default:
	}
	// And without a grant there is nothing to stop.
	CloseAtExpiry(nil, func() { t.Error("a session with no grant was closed") })()
	CloseAtExpiry(&Grant{}, nil)()
}
