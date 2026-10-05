package engineering

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/config"
)

// Guard is one listener's engineering side: what it recognises, what it
// requires a work order for, and where it writes what happened.
//
// A nil Guard reports nothing and requires nothing, so a kind holds one
// unconditionally and every method below tolerates nil.
type Guard struct {
	p        Policy
	kind     string
	listener string
	grants   *access.Guard
	ledger   *access.Ledger
	log      *slog.Logger
}

// FromConfig compiles a listener's `engineering` block.
//
// An absent block still returns a Guard: an engineering operation is worth an
// event whether or not anybody asked for a work order, and a relay that stayed
// quiet about a program download until it was configured to speak would be one
// whose logs did not have the download in them. `enabled: false` is how an
// operator says otherwise.
//
// require is passed to the access guard rather than read from the block twice,
// so a listener that requires grants on a daemon with no ledger fails closed the
// way the gate kinds do.
func FromConfig(c *config.Engineering, kind, listener string, led *access.Ledger, log *slog.Logger) (*Guard, error) {
	if c != nil && c.Enabled != nil && !*c.Enabled {
		return nil, nil
	}
	g := &Guard{kind: kind, listener: listener, ledger: led, log: log}
	if c == nil {
		// Report, require nothing, and write to the ledger where there is one:
		// the record is the half of this that costs nothing to have.
		g.p.Ledger = led != nil
		return g, nil
	}
	g.p.RequireGrant = c.RequireGrant
	switch c.Action {
	case "", "deny":
		g.p.Deny = c.RequireGrant
	case "alert":
		g.p.Deny = false
	default:
		return nil, fmt.Errorf("engineering action %q: alert or deny", c.Action)
	}
	if len(c.Classes) > 0 {
		g.p.Classes = make(map[Class]bool, len(c.Classes))
		for _, s := range c.Classes {
			g.p.Classes[Class(s)] = true
		}
	}
	g.p.Ledger = led != nil && (c.Ledger == nil || *c.Ledger)
	if err := g.p.Check(); err != nil {
		return nil, err
	}
	if c.RequireGrant {
		g.grants = access.NewGuard(led, listener, true, log)
	}
	return g, nil
}

// Policy is the compiled block, for a status view and for the tests.
func (g *Guard) Policy() Policy {
	if g == nil {
		return Policy{}
	}
	return g.p
}

// On reports whether engineering operations are reported at all.
func (g *Guard) On() bool { return g != nil }

// Handler is what a kind does with a recognised operation. Every field is
// optional, and the caller does the refusing: only it knows what a refusal
// means in its protocol.
type Handler struct {
	// Report records the operation itself: the security event with the class
	// and the detail, the counter, the fact in the correlation window. It is
	// called for every recognised operation, allowed or not.
	//
	// grant is the approval it happened under, order the work order on file
	// for the device. They are two different facts and either may be nil: a
	// grant says somebody authorised this, a work order says somebody was
	// expecting it, and an operation can have one, both or neither.
	Report func(op Operation, grant *access.Grant, order *access.WorkOrder)
	// Ungranted records an operation that happened outside every approved
	// window on a listener that does not require one. It is an alert, not a
	// refusal -- and a quieter one when a work order was on file, which is
	// the whole reason order is here.
	Ungranted func(op Operation, reason string, order *access.WorkOrder)
	// Refused is the refusal's own bookkeeping, for the listeners that require
	// a work order.
	Refused func(op Operation, reason string)
	// Would records what enforcing would have cost, for a listener in shadow
	// mode or a learning run.
	Would func(op Operation, reason string)
}

// Decide is the whole decision for one operation: the reason to refuse it, or
// "" to carry it.
//
// targets are what a grant would have to name: the upstream pool and, where the
// kind knows them, the addresses in it. subject is the identity to ask the
// ledger about, which is the operation's own where it has one and the client
// address where the protocol has no identity at all.
func (g *Guard) Decide(op Operation, subject, pool string, addrs []string, enforcing bool, h Handler) string {
	if g == nil {
		return ""
	}
	if op.Subject == "" {
		op.Subject = subject
	}
	// The ledger's answer, where there is a ledger to ask. It is asked even
	// when this listener requires nothing, because "this download happened
	// outside every approved window" is the alert an estate wants first.
	var grant *access.Grant
	var order *access.WorkOrder
	reason := ""
	targets := append([]string{pool}, addrs...)
	if g.ledger != nil {
		grant, reason = g.ledger.Admit(subject, g.listener, targets)
		// The work order is asked for whatever the grant said, and it does
		// not change the answer. It names the *device*, not the actor, so
		// this is a different question from the one above: "was anybody
		// expecting work on that controller", not "is this person allowed".
		order = g.ledger.WorkOrderFor(g.listener, targets)
	}
	if h.Report != nil {
		h.Report(op, grant, order)
	}
	g.record(op, grant, order, reason)
	if reason == "" {
		return ""
	}
	if !g.p.Covers(op.Class) || !g.p.Deny {
		// Not a class this listener requires a work order for, or a listener
		// that only wants to be told. Either way the operation goes on and the
		// alert is the product.
		if h.Ungranted != nil {
			h.Ungranted(op, ReasonUngranted, order)
		}
		return ""
	}
	if !enforcing {
		if h.Would != nil {
			h.Would(op, ReasonNoGrant)
		}
		return ""
	}
	if h.Refused != nil {
		h.Refused(op, ReasonNoGrant)
	}
	return ReasonNoGrant
}

// record writes the operation to the access ledger, where the block asks for
// it. A failure is not returned: the operation has happened either way, and a
// relay that refused a download because it could not write the record down
// would be one whose bookkeeping decided the process.
func (g *Guard) record(op Operation, grant *access.Grant, order *access.WorkOrder, refusal string) {
	if g == nil || !g.p.Ledger || g.ledger == nil {
		return
	}
	id := ""
	if grant != nil {
		id = grant.ID
	}
	ref := ""
	if order != nil {
		ref = order.Reference
	}
	if err := g.ledger.Engineering(access.EngineeringRecord{
		At:        time.Now(),
		Kind:      g.kind,
		Listener:  g.listener,
		Subject:   op.Subject,
		Class:     string(op.Class),
		Detail:    op.String(),
		Grant:     id,
		Refusal:   refusal,
		WorkOrder: ref,
	}); err != nil && g.log != nil {
		g.log.Warn("engineering operation not recorded", "listener", g.listener,
			"class", string(op.Class), "err", err.Error())
	}
}

// Severity is the tone an engineering event is reported in: notice where a
// work order was on file for the device, warning where none was.
//
// It is one word in the event rather than a log level, because the level a
// security record is written at decides whether a collector keeps it. An
// estate whose syslog threshold is warning would have *dropped* the notices,
// and the whole point of filing a work order is that the record still exists
// -- quieter, not absent. So both are warnings to the logging system and the
// difference is a field anything can filter on.
func Severity(order *access.WorkOrder) string {
	if order != nil {
		return "notice"
	}
	return "warning"
}
