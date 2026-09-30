package access

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// A work order is the change reference somebody filed before touching a
// device, and nothing more than that.
//
// It is deliberately not a grant, and the difference between the two is the
// point of having both. A grant is requested, approved by somebody else,
// bounded in time and in uses, and can refuse: it is an authorisation. A work
// order is one person writing a reference down -- "WO-2026-0481, replacing the
// drive on line 1" -- against a device, for a window. Nobody approves it,
// nothing checks it against the maintenance system, and **it never permits
// anything that was not already permitted**. A listener with
// `engineering.require_grant` refuses an operation with no grant whatever work
// orders are open; a work order cannot open a door.
//
// What it changes is the tone. An engineering operation on that device while a
// work order is open is reported as expected work; the same operation with
// nothing filed is reported as an operation nobody wrote down. Both are
// reported, both are in the trail, and the difference is one attribute and one
// counter -- which is exactly the difference an operations centre needs to
// triage a week of OT engineering.
//
// That is worth having because the alternative in most plants is nothing. An
// estate that cannot yet run four-eyes approval on every program download can
// still file the reference its maintenance system already issues, and then the
// weekly report separates the engineering somebody filed from the engineering
// nobody did. The second list is short, and it is the one worth reading.
type WorkOrder struct {
	// Reference is the maintenance system's own identifier, and the key: one
	// record per reference, and filing the same reference again replaces the
	// window rather than leaving two of them open.
	Reference string `json:"reference"`
	// Device is what the work is on, in the words the relay will see: an
	// upstream pool name, an endpoint address or a device address. An
	// operation matches when any of the targets its listener knows equals
	// this, compared literally -- no prefixes and no wildcards, because a
	// work order that quietly covered a neighbouring device would be worse
	// than one that covered nothing.
	Device string `json:"device"`
	// Listener narrows it to one listener. Empty is every listener that
	// reaches the device, which is the common case: the work is on the
	// controller, not on a port.
	Listener string `json:"listener,omitempty"`
	// Note is what the work is, By who filed it and At when.
	Note string    `json:"note,omitempty"`
	By   string    `json:"by"`
	At   time.Time `json:"at"`
	// NotBefore and Expires are the window. An end is required: a work order
	// with none is the one somebody opens during a shutdown and nobody ever
	// closes, after which every download on that device reads as expected.
	NotBefore time.Time `json:"not_before"`
	Expires   time.Time `json:"expires"`
	// Closed is whoever closed it before its window ran out.
	Closed *Decision `json:"closed,omitempty"`
}

// Work order states, which are the grant states minus every state that
// involves an approval, because there is no approval.
const (
	// OrderOpen is in force now.
	OrderOpen = "open"
	// OrderScheduled is filed for a window that has not started.
	OrderScheduled = "scheduled"
	// OrderExpired is a window that has run out.
	OrderExpired = "expired"
	// OrderClosed is one somebody closed early.
	OrderClosed = "closed"
)

// Open reports whether this work order covers now.
func (w *WorkOrder) Open(now time.Time) bool {
	return w != nil && w.Closed == nil && !now.Before(w.NotBefore) && now.Before(w.Expires)
}

// State is where the work order stands at a moment.
func (w *WorkOrder) State(now time.Time) string {
	switch {
	case w.Closed != nil:
		return OrderClosed
	case !now.Before(w.Expires):
		return OrderExpired
	case now.Before(w.NotBefore):
		return OrderScheduled
	}
	return OrderOpen
}

// Covers reports whether this work order is the one for an operation on a
// listener against a set of targets.
func (w *WorkOrder) Covers(listener string, targets []string, now time.Time) bool {
	if !w.Open(now) {
		return false
	}
	if w.Listener != "" && w.Listener != listener {
		return false
	}
	for _, t := range targets {
		if t != "" && t == w.Device {
			return true
		}
	}
	return false
}

// WorkOrderView is a work order with its computed state, for the management
// API and the interface.
type WorkOrderView struct {
	WorkOrder
	State string `json:"state"`
}

// maxWorkOrders bounds the table. A work order is filed by a person over the
// control socket, so this is not a bound on anything a client does; it is the
// bound that stops a broken automation from filling memory with them. Past it
// filing is refused and says so, rather than dropping the oldest -- a work
// order that vanished would be one whose engineering then read as unfiled.
const maxWorkOrders = 4096

// defaultMaxWorkOrder is how long a work order may cover when the
// configuration does not say. Thirty days is a plant shutdown; longer than
// that and it is not a work order, it is a policy change.
const defaultMaxWorkOrder = 30 * 24 * time.Hour

// ErrTooManyWorkOrders is returned when the table is full.
var ErrTooManyWorkOrders = errors.New("too many work orders are on file")

// FileWorkOrder records a work order. Filing the same reference again replaces
// it, which is what an operator means by extending one.
func (l *Ledger) FileWorkOrder(w WorkOrder) (WorkOrderView, error) {
	if l == nil {
		return WorkOrderView{}, errors.New("this daemon has no access ledger, so there is nowhere to file a work order")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	w.Reference = strings.TrimSpace(w.Reference)
	w.Device = strings.TrimSpace(w.Device)
	w.Listener = strings.TrimSpace(w.Listener)
	w.Note = strings.TrimSpace(w.Note)
	w.By = strings.TrimSpace(w.By)
	if err := l.checkWorkOrder(&w, now); err != nil {
		return WorkOrderView{}, err
	}
	if _, known := l.orders[w.Reference]; !known && len(l.orders) >= maxWorkOrders {
		return WorkOrderView{}, ErrTooManyWorkOrders
	}
	w.At = now
	w.Closed = nil
	if err := l.append(record{At: now, Kind: kindWorkOrder, ID: w.Reference,
		Actor: w.By, Note: w.Note, Order: &w}); err != nil {
		return WorkOrderView{}, err
	}
	return WorkOrderView{WorkOrder: w, State: w.State(now)}, nil
}

// checkWorkOrder is what a filing has to say. The caller holds the mutex.
func (l *Ledger) checkWorkOrder(w *WorkOrder, now time.Time) error {
	switch {
	case w.Reference == "":
		return errors.New("reference: a work order with no reference is not a work order")
	case len(w.Reference) > 128:
		return errors.New("reference: longer than 128 characters")
	case w.Device == "":
		return errors.New("device: name the device the work is on")
	case len(w.Device) > 256:
		return errors.New("device: longer than 256 characters")
	case w.By == "":
		return errors.New("by: say who filed it")
	case len(w.Note) > 1024:
		return errors.New("note: longer than 1024 characters")
	}
	if w.NotBefore.IsZero() {
		w.NotBefore = now
	}
	if w.Expires.IsZero() {
		return errors.New("expires: a work order with no end is one nobody closes")
	}
	if !w.Expires.After(w.NotBefore) {
		return errors.New("expires: not after the window starts")
	}
	maxD := l.pol.MaxWorkOrder
	if maxD <= 0 {
		maxD = defaultMaxWorkOrder
	}
	if d := w.Expires.Sub(w.NotBefore); d > maxD {
		return fmt.Errorf("expires: %s is longer than max_work_order (%s)", d, maxD)
	}
	if l.pol.MaxLead > 0 && w.NotBefore.Sub(now) > l.pol.MaxLead {
		return fmt.Errorf("not_before: further ahead than max_lead (%s)", l.pol.MaxLead)
	}
	return nil
}

// CloseWorkOrder ends one early. The work is finished, so the next download on
// that device is unfiled again -- which is the whole reason closing exists.
func (l *Ledger) CloseWorkOrder(reference, by, note string) (WorkOrderView, error) {
	if l == nil {
		return WorkOrderView{}, errors.New("this daemon has no access ledger")
	}
	reference = strings.TrimSpace(reference)
	by = strings.TrimSpace(by)
	if by == "" {
		return WorkOrderView{}, errors.New("by: say who closed it")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.orders[reference]
	if w == nil {
		return WorkOrderView{}, fmt.Errorf("no work order %q is on file", reference)
	}
	if w.Closed != nil {
		return WorkOrderView{}, fmt.Errorf("work order %q was already closed by %s", reference, w.Closed.By)
	}
	now := l.now()
	if err := l.append(record{At: now, Kind: kindWorkOrderClosed, ID: reference,
		Actor: by, Note: strings.TrimSpace(note)}); err != nil {
		return WorkOrderView{}, err
	}
	return WorkOrderView{WorkOrder: *l.orders[reference], State: OrderClosed}, nil
}

// WorkOrders lists them, most recently filed first.
func (l *Ledger) WorkOrders() []WorkOrderView {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	out := make([]WorkOrderView, 0, len(l.orderRefs))
	for i := len(l.orderRefs) - 1; i >= 0; i-- {
		w := l.orders[l.orderRefs[i]]
		if w == nil {
			continue
		}
		c := *w
		out = append(out, WorkOrderView{WorkOrder: c, State: c.State(now)})
	}
	return out
}

// WorkOrderFor is the work order covering an operation, or nil.
//
// Where more than one covers it -- a device named by pool and by address, two
// references filed for one shutdown -- the one expiring soonest is returned, so
// that the event names the work order that is actually about to end rather than
// whichever happened to be filed last.
func (l *Ledger) WorkOrderFor(listener string, targets []string) *WorkOrder {
	if l == nil || len(targets) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var best *WorkOrder
	for _, ref := range l.orderRefs {
		w := l.orders[ref]
		if !w.Covers(listener, targets, now) {
			continue
		}
		if best == nil || w.Expires.Before(best.Expires) {
			best = w
		}
	}
	if best == nil {
		return nil
	}
	c := *best
	return &c
}

// OpenWorkOrders counts the ones in force now, for a status view.
func (l *Ledger) OpenWorkOrders() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	n := 0
	for _, ref := range l.orderRefs {
		if l.orders[ref].Open(now) {
			n++
		}
	}
	return n
}

// applyWorkOrder folds a work order record into the state. The caller holds
// the mutex, and this is the same path a replay takes.
func (l *Ledger) applyWorkOrder(r record) error {
	if l.orders == nil {
		l.orders = map[string]*WorkOrder{}
	}
	switch r.Kind {
	case kindWorkOrder:
		if r.Order == nil {
			return errors.New("a work order record with no work order")
		}
		w := *r.Order
		if _, known := l.orders[w.Reference]; !known {
			l.orderRefs = append(l.orderRefs, w.Reference)
		}
		l.orders[w.Reference] = &w
		l.stats.WorkOrders++
		return nil
	case kindWorkOrderClosed:
		w := l.orders[r.ID]
		if w == nil {
			return fmt.Errorf("closing unknown work order %s", r.ID)
		}
		w.Closed = &Decision{By: r.Actor, At: r.At, Note: r.Note}
		l.stats.WorkOrdersClosed++
		return nil
	}
	return fmt.Errorf("not a work order record: %s", r.Kind)
}
