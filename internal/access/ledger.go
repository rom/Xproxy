package access

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Record kinds, as they appear in the ledger file.
const (
	kindRequest = "request"
	kindApprove = "approve"
	kindDeny    = "deny"
	kindRevoke  = "revoke"
	kindUse     = "use"
	// kindEngineering is an engineering operation a listener recognised. It is
	// in this file rather than only in the security log because the log rotates
	// and this trail is hash-chained: "who downloaded to that controller, when,
	// under whose approval" is a question an audit asks a year later, and the
	// answer has to be one nobody could quietly edit.
	kindEngineering = "engineering"
	// kindWorkOrder is a change reference somebody filed against a device, and
	// kindWorkOrderClosed is somebody closing it before its window ran out.
	// They are in this file because "was that download filed, and by whom" is
	// the same question as "was it approved, and by whom", asked of an estate
	// that has not got as far as approvals -- and an answer somebody could
	// edit afterwards would be worth nothing in either case.
	kindWorkOrder       = "work_order"
	kindWorkOrderClosed = "work_order_closed"
)

// maxRecords bounds a replay. A ledger is an audit trail and grows without
// end, so at some point the operator archives it; the load says so rather than
// reading an unbounded file into memory or, worse, reading part of it and
// serving the result.
const maxRecords = 1 << 20

// maxRecordBytes bounds one line. The fields are short and an operator's note
// is not an essay; a line longer than this is a file that is not this file.
const maxRecordBytes = 64 << 10

// recordBound is the replay bound in force.
func (l *Ledger) recordBound() int {
	if l.maxRecords > 0 {
		return l.maxRecords
	}
	return maxRecords
}

// A record is one line of the ledger. The hash chain is what makes the trail
// worth keeping: each record covers the previous record's hash, so removing or
// editing a line breaks every line after it, and the break is found at load
// rather than by whoever is reading the trail after an incident.
type record struct {
	Seq   int64     `json:"seq"`
	At    time.Time `json:"at"`
	Kind  string    `json:"kind"`
	ID    string    `json:"id"`
	Actor string    `json:"actor,omitempty"`
	Note  string    `json:"note,omitempty"`
	// Grant is carried by a request record only.
	Grant *Grant `json:"grant,omitempty"`
	// Session is carried by a use record: which session this grant opened,
	// so a recording can be tied to the approval that allowed it.
	Session string `json:"session,omitempty"`
	// Listener, Proto, Class and Refusal are carried by an engineering record:
	// which listener saw the operation, on which protocol, what class of
	// engineering it was, and -- when there was no grant open for it -- the
	// reason the ledger gave.
	Listener string `json:"listener,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Class    string `json:"class,omitempty"`
	Refusal  string `json:"refusal,omitempty"`
	// Order is carried by a work order record, and Work by an engineering
	// record: the reference the operation happened under, where one was on
	// file. Both are omitted when absent, so a trail written before work
	// orders existed hashes to exactly what it hashed to before.
	Order *WorkOrder `json:"work_order,omitempty"`
	Work  string     `json:"work_order_ref,omitempty"`
	// Prev is the previous record's Hash, and Hash covers this record with
	// Hash itself empty.
	Prev string `json:"prev"`
	Hash string `json:"hash"`
}

// Stats is the management view's counters.
type Stats struct {
	Requests    uint64 `json:"requests"`
	Approvals   uint64 `json:"approvals"`
	Denials     uint64 `json:"denials"`
	Revocations uint64 `json:"revocations"`
	Uses        uint64 `json:"uses"`
	// Engineering counts the engineering operations written to this trail,
	// which is the number an audit starts from.
	Engineering uint64 `json:"engineering"`
	// EngineeringFiled is the subset that happened under a work order on file.
	// The difference between the two is the list somebody works through.
	EngineeringFiled uint64 `json:"engineering_filed"`
	// WorkOrders counts the filings, WorkOrdersClosed the ones somebody closed
	// early. A reference filed twice counts twice: extending a window is an
	// act, and the trail records acts.
	WorkOrders       uint64 `json:"work_orders"`
	WorkOrdersClosed uint64 `json:"work_orders_closed"`
	// Refusals counts sessions turned away, by reason.
	Refusals map[string]uint64 `json:"refusals,omitempty"`
}

// A Ledger is the grants and the file they are written to.
//
// One process owns one ledger file, held with an exclusive lock: two daemons
// appending to one trail would interleave their chains, and a trail whose chain
// does not verify is worth nothing at the only moment it is read. The lock says
// so at start rather than leaving it to be discovered later.
type Ledger struct {
	pol  Policy
	path string
	// maxRecords bounds a replay; 0 is the package default. A field rather
	// than the constant alone so that a test can reach the bound without
	// writing a million records.
	maxRecords int

	mu    sync.Mutex
	byID  map[string]*Grant
	order []string
	// orders are the work orders by reference, orderRefs the order they were
	// first filed in. A reference filed again replaces the record and keeps
	// its place, because extending a work order is not a new work order.
	orders    map[string]*WorkOrder
	orderRefs []string
	f         *os.File
	w         *bufio.Writer
	seq       int64
	prev      string
	stats     Stats

	// now is the clock, replaced in tests.
	now func() time.Time
}

// Open reads a ledger, verifies its chain and holds it for appending. A missing
// file is an empty ledger; a file that does not verify is an error, because a
// trail that may have been edited must not be presented as one that was not.
func Open(path string, pol Policy) (*Ledger, error) {
	l := &Ledger{pol: pol, path: path, byID: map[string]*Grant{}, now: time.Now}
	if path == "" {
		// A memory-only ledger, for a test or for an estate that keeps its
		// trail elsewhere. It is warned about by the configuration, not
		// here.
		return l, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("access ledger: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // the path is the operator's own configuration
	if err != nil {
		return nil, fmt.Errorf("access ledger: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("access ledger %s: held by another process: %w", path, err)
	}
	if err := l.replay(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 2); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("access ledger: %w", err)
	}
	l.f, l.w = f, bufio.NewWriter(f)
	return l, nil
}

// Close flushes and releases the file.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.w.Flush()
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f, l.w = nil, nil
	return err
}

// SetClockForTest replaces the clock.
func (l *Ledger) SetClockForTest(f func() time.Time) { l.now = f }

// replay reads the file, checks the chain and rebuilds the grants.
func (l *Ledger) replay(f *os.File) error {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxRecordBytes)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		n++
		if n > l.recordBound() {
			return fmt.Errorf("access ledger %s: more than %d records; archive it and start a new one", l.path, l.recordBound())
		}
		var r record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return fmt.Errorf("access ledger %s: record %d: %w", l.path, n, err)
		}
		if r.Prev != l.prev {
			return fmt.Errorf("access ledger %s: record %d does not follow the previous one; the trail has been edited", l.path, n)
		}
		if got := hashOf(r); got != r.Hash {
			return fmt.Errorf("access ledger %s: record %d does not match its hash; the trail has been edited", l.path, n)
		}
		if err := l.apply(r); err != nil {
			return fmt.Errorf("access ledger %s: record %d: %w", l.path, n, err)
		}
		l.prev, l.seq = r.Hash, r.Seq
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("access ledger %s: %w", l.path, err)
	}
	return nil
}

// apply folds one record into the state. It is the same path a live append
// takes, so a replayed ledger and a running one cannot drift.
func (l *Ledger) apply(r record) error {
	if r.Kind == kindRequest {
		if r.Grant == nil {
			return errors.New("a request record with no grant")
		}
		if _, dup := l.byID[r.Grant.ID]; dup {
			return fmt.Errorf("a second request for grant %s", r.Grant.ID)
		}
		g := *r.Grant
		l.byID[g.ID] = &g
		l.order = append(l.order, g.ID)
		l.stats.Requests++
		return nil
	}
	if r.Kind == kindWorkOrder || r.Kind == kindWorkOrderClosed {
		return l.applyWorkOrder(r)
	}
	if r.Kind == kindEngineering {
		// An engineering record names a grant only when one was open, and
		// stands on its own when none was: the operation happened either way,
		// and that is exactly what the trail is for.
		l.stats.Engineering++
		if r.Work != "" {
			l.stats.EngineeringFiled++
		}
		return nil
	}
	g := l.byID[r.ID]
	if g == nil {
		return fmt.Errorf("%s of unknown grant %s", r.Kind, r.ID)
	}
	d := Decision{By: r.Actor, At: r.At, Note: r.Note}
	switch r.Kind {
	case kindApprove:
		g.Approvals = append(g.Approvals, d)
		l.stats.Approvals++
	case kindDeny:
		g.Refusal = &d
		l.stats.Denials++
	case kindRevoke:
		g.Revocation = &d
		l.stats.Revocations++
	case kindUse:
		g.Uses++
		l.stats.Uses++
	default:
		return fmt.Errorf("unknown record kind %q", r.Kind)
	}
	return nil
}

// hashOf is the record's hash: the previous hash and the record itself, with
// the hash field empty so that it covers everything but itself.
func hashOf(r record) string {
	r.Hash = ""
	body, err := json.Marshal(r)
	if err != nil {
		// The struct is plain data; a failure here is not reachable, and
		// returning a hash that cannot match is the safe answer anyway.
		return ""
	}
	sum := sha256.Sum256(append([]byte(r.Prev), body...))
	return hex.EncodeToString(sum[:])
}

// append writes one record and only then applies it. The caller holds the
// mutex.
//
// That order is the point. A grant that is in force in memory but not on disk
// is a grant nobody approved after the next restart, and an approval the caller
// was told about but that was never written is worse than one that was refused.
// So the write, the flush and the sync happen first, and a failure leaves the
// ledger exactly as it was and says so.
//
// apply cannot fail here: every live record is built in this package with a
// known kind, a fresh unique id for a request and an id checked under this same
// mutex for everything else. The error is returned rather than ignored because
// a future record kind that does not hold to that must not do so quietly.
func (l *Ledger) append(r record) error {
	r.Seq, r.Prev = l.seq+1, l.prev
	r.Hash = hashOf(r)
	if l.w != nil {
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := l.w.Write(append(line, '\n')); err != nil {
			return err
		}
		if err := l.w.Flush(); err != nil {
			return err
		}
		// A grant that was approved and not written is a grant that
		// disappears on a crash, and one that was revoked and not written
		// is worse: the revocation is the record that has to survive.
		if err := l.f.Sync(); err != nil {
			return err
		}
	}
	if err := l.apply(r); err != nil {
		return err
	}
	l.seq, l.prev = r.Seq, r.Hash
	return nil
}

// newID is a grant identifier: random, because an identifier an operator can
// guess is an identifier an operator can approve by mistake.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Request records an ask for access.
func (l *Ledger) Request(r Request) (*Grant, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if err := l.pol.check(r, now); err != nil {
		return nil, err
	}
	if l.pol.MaxOpen > 0 && l.openCount(now) >= l.pol.MaxOpen {
		return nil, ErrTooMany
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	nb := r.NotBefore
	if nb.IsZero() {
		nb = now
	}
	uses := r.MaxUses
	if uses == 0 && l.pol.MaxUses > 0 {
		uses = l.pol.MaxUses
	}
	g := &Grant{
		ID: id, Subject: strings.TrimSpace(r.Subject), Listener: strings.TrimSpace(r.Listener),
		Target: strings.TrimSpace(r.Target), Reason: strings.TrimSpace(r.Reason), By: strings.TrimSpace(r.By),
		At: now, NotBefore: nb, Expires: r.Expires, MaxUses: uses,
		NeedApprovals: max(l.pol.Approvals, 0),
	}
	if err := l.append(record{At: now, Kind: kindRequest, ID: g.ID, Actor: g.By, Grant: g}); err != nil {
		return nil, err
	}
	return l.copyOf(g), nil
}

// openCount counts the grants that are pending or in force. The caller holds
// the mutex.
func (l *Ledger) openCount(now time.Time) int {
	n := 0
	for _, id := range l.order {
		if l.byID[id].Open(now) {
			n++
		}
	}
	return n
}

// Approve records one person's agreement.
//
// It refuses an approval from the requester or the subject, and a second
// approval from somebody who has already approved. Those two checks are the
// whole of four eyes: without them the feature is a form to fill in.
func (l *Ledger) Approve(id, approver, note string) (*Grant, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	g, err := l.open(id, now)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(approver) == "" {
		return nil, errors.New("access: an approval needs an approver")
	}
	if !l.pol.SelfApproval && (equalName(approver, g.By) || equalName(approver, g.Subject)) {
		return nil, ErrSelfApproval
	}
	if g.approvedBy(approver) {
		return nil, ErrDuplicateApproval
	}
	if err := l.append(record{At: now, Kind: kindApprove, ID: g.ID, Actor: strings.TrimSpace(approver), Note: note}); err != nil {
		return nil, err
	}
	return l.copyOf(g), nil
}

// Deny refuses a request. An approver who has seen enough to say no says it
// here, so that the trail carries the refusal rather than a request that
// silently expired.
func (l *Ledger) Deny(id, approver, note string) (*Grant, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	g, err := l.open(id, now)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(approver) == "" {
		return nil, errors.New("access: a denial needs an approver")
	}
	if err := l.append(record{At: now, Kind: kindDeny, ID: g.ID, Actor: strings.TrimSpace(approver), Note: note}); err != nil {
		return nil, err
	}
	return l.copyOf(g), nil
}

// Revoke withdraws a grant, including one that is in force. Anybody who can
// reach the management API may revoke: taking access away is not the decision
// four eyes exists to slow down.
func (l *Ledger) Revoke(id, actor, note string) (*Grant, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	g, err := l.open(id, now)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(actor) == "" {
		return nil, errors.New("access: a revocation needs an actor")
	}
	if err := l.append(record{At: now, Kind: kindRevoke, ID: g.ID, Actor: strings.TrimSpace(actor), Note: note}); err != nil {
		return nil, err
	}
	return l.copyOf(g), nil
}

// find resolves an identifier: the whole one, or an unambiguous prefix of at
// least four characters. The caller holds the mutex.
//
// A prefix because an operator reads an identifier off a table and types it into
// an approval, and thirty-two hex characters is a transcription error waiting to
// happen. Ambiguity is refused rather than resolved to the first match: the one
// thing worse than mistyping a grant's id is approving somebody else's.
func (l *Ledger) find(id string) (*Grant, error) {
	id = strings.TrimSpace(id)
	if g := l.byID[id]; g != nil {
		return g, nil
	}
	if len(id) < 4 {
		return nil, ErrUnknownGrant
	}
	var found *Grant
	for k, g := range l.byID {
		if strings.HasPrefix(k, id) {
			if found != nil {
				return nil, fmt.Errorf("%w: %q matches more than one grant", ErrUnknownGrant, id)
			}
			found = g
		}
	}
	if found == nil {
		return nil, ErrUnknownGrant
	}
	return found, nil
}

// open finds a grant that can still change. The caller holds the mutex.
func (l *Ledger) open(id string, now time.Time) (*Grant, error) {
	g, err := l.find(id)
	if err != nil {
		return nil, err
	}
	if !g.Open(now) {
		return nil, fmt.Errorf("%w: %s", ErrNotOpen, g.State(now))
	}
	return g, nil
}

// Admit is the runtime decision: may this subject open a session on this
// listener to one of these targets, and until when.
//
// A gate passes what the session could reach: the upstream pool's name, which a
// grant uses to mean "any machine in it", and the addresses of the endpoints in
// it, which a grant uses to name one machine. The grant that matches says which,
// so a grant for one endpoint pins the dial to that endpoint rather than letting
// the balancer choose.
//
// It returns the grant that allows it, or the reason the nearest grant does
// not. It does not count a use -- a listener that has decided to admit calls
// Use, so a connection refused later for its own reasons does not spend
// somebody's window.
func (l *Ledger) Admit(subject, listener string, targets []string) (*Grant, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var near string
	for i := len(l.order) - 1; i >= 0; i-- {
		g := l.byID[l.order[i]]
		if !equalName(g.Subject, subject) || !equalName(g.Listener, listener) {
			continue
		}
		if !slices.ContainsFunc(targets, func(t string) bool { return equalName(g.Target, t) }) {
			// A grant for this subject on this listener but another
			// target: worth naming, because "wrong target" is the
			// mistake an operator makes and "no grant" would send them
			// looking for the wrong thing.
			if near == "" {
				near = ReasonNoTarget
			}
			continue
		}
		if g.State(now) == Active {
			return l.copyOf(g), ""
		}
		// Keep the most telling reason among the grants that match: a
		// pending one is more useful to report than one that expired last
		// week.
		if r := refusal(g.State(now)); near == "" || near == ReasonNoTarget || near == ReasonExpired {
			near = r
		}
	}
	if near == "" {
		near = ReasonNoGrant
	}
	l.countRefusal(near)
	return nil, near
}

// countRefusal records a refusal reason. The caller holds the mutex.
func (l *Ledger) countRefusal(reason string) {
	if l.stats.Refusals == nil {
		l.stats.Refusals = map[string]uint64{}
	}
	l.stats.Refusals[reason]++
}

// Use records that a grant opened a session, which is what makes max_uses
// durable: a restart must not refill a one-shot grant.
func (l *Ledger) Use(id, session string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	g, err := l.find(id)
	if err != nil {
		return err
	}
	if g.State(now) != Active {
		return fmt.Errorf("%w: %s", ErrNotOpen, g.State(now))
	}
	return l.append(record{At: now, Kind: kindUse, ID: g.ID, Session: session})
}

// An EngineeringRecord is one engineering operation, as it is written to the
// trail.
type EngineeringRecord struct {
	At time.Time
	// Kind is the listener kind, Listener its name.
	Kind, Listener string
	// Subject is the identity the operation was attributed to: the protocol's
	// own where it has one, and the client address where it has none.
	Subject string
	// Class is the engineering class, Detail the operation in the protocol's
	// own words.
	Class, Detail string
	// Grant is the identifier of the grant that covered it, empty when none
	// was open.
	Grant string
	// Refusal is the ledger's reason when no grant covered it, empty when one
	// did. It is recorded whether or not the listener refused the operation:
	// "this happened outside every approved window" is the fact, and what was
	// done about it is the listener's configuration.
	Refusal string
	// WorkOrder is the reference on file for the device at the time, empty
	// when there was none. It is not an approval and does not change the
	// refusal; it is the answer to "was anybody expecting this".
	WorkOrder string
}

// Engineering writes one engineering operation to the trail.
//
// It is an append and nothing else: no grant is spent, no state changes, and a
// record with no grant is as valid as one with. The error is returned so a
// caller can log it, and every caller here logs rather than refusing the
// operation -- the operation has already happened, and a relay whose
// bookkeeping decided the process would be the wrong trade.
func (l *Ledger) Engineering(e EngineeringRecord) error {
	if l == nil {
		return nil
	}
	at := e.At
	l.mu.Lock()
	defer l.mu.Unlock()
	if at.IsZero() {
		at = l.now()
	}
	return l.append(record{At: at, Kind: kindEngineering, ID: e.Grant,
		Actor: e.Subject, Note: e.Detail, Listener: e.Listener,
		Proto: e.Kind, Class: e.Class, Refusal: e.Refusal, Work: e.WorkOrder})
}

// Deadline is when a session opened under this grant must end. A gate sets it
// on the connection, so that a window closing ends the session that is running
// rather than only the next one somebody opens.
func (l *Ledger) Deadline(id string) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	if g := l.byID[strings.TrimSpace(id)]; g != nil {
		return g.Expires
	}
	return time.Time{}
}

// View is a grant with its computed state, for the management API.
type View struct {
	Grant
	State State `json:"state"`
}

// Grants lists the grants, newest first.
func (l *Ledger) Grants() []View {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	out := make([]View, 0, len(l.order))
	for i := len(l.order) - 1; i >= 0; i-- {
		g := l.byID[l.order[i]]
		out = append(out, View{Grant: *l.copyOf(g), State: g.State(now)})
	}
	return out
}

// Get returns one grant.
func (l *Ledger) Get(id string) (View, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	g, err := l.find(id)
	if err != nil {
		return View{}, false
	}
	return View{Grant: *l.copyOf(g), State: g.State(l.now())}, true
}

// Stats returns the counters.
func (l *Ledger) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	if l.stats.Refusals != nil {
		s.Refusals = make(map[string]uint64, len(l.stats.Refusals))
		for k, v := range l.stats.Refusals {
			s.Refusals[k] = v
		}
	}
	return s
}

// copyOf hands out a copy: a caller holding a pointer into the ledger would be
// reading fields another approval is writing. The caller holds the mutex.
func (l *Ledger) copyOf(g *Grant) *Grant {
	c := *g
	c.Approvals = append([]Decision(nil), g.Approvals...)
	if g.Refusal != nil {
		d := *g.Refusal
		c.Refusal = &d
	}
	if g.Revocation != nil {
		d := *g.Revocation
		c.Revocation = &d
	}
	return &c
}
