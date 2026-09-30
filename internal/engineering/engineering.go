// Package engineering is the class of event a plant's own tooling produces,
// and the machinery that ties it to an approved work order.
//
// # Why it is a class of its own
//
// Every OT kind here already refuses what a policy does not grant, and that is
// the right answer for a command: a breaker either may be operated by this
// client or may not. Engineering is different in kind, not in degree. A program
// download, a CPU stop, a protection setting written, a firmware image pushed:
// these are legitimate, necessary, and the operations an estate is actually
// compromised through. They are also rare, planned, and done by people who
// filed a change -- which means the useful question is not "may this client do
// it" but "is there an approved work order open for it right now".
//
// A relay that answered only the first question ends up with two bad options: a
// rule that allows downloads, which allows them at three in the morning from a
// laptop nobody knows about; or a rule that denies them, which the plant turns
// off on the first commissioning day. The work order is the missing term.
//
// # What it does
//
// Every engineering operation this relay recognises is reported as its own
// event, whatever the policy said about it: a security event with the class, the
// detail in the protocol's own words, the point and the identity; a counter; a
// fact in the cross-listener window, which is shared with the sibling daemons;
// and, where the daemon has one, a line in the access ledger's hash-chained
// record -- so "who downloaded what, when, under which work order" has an answer
// that is not a person's memory.
//
// Where a listener asks for it, an operation with no open grant is refused. And
// where the daemon has a ledger and the listener does not require one, the
// operation is *alerted* rather than refused: an engineering action outside
// every approved window is worth telling somebody about even when the policy
// allows it, which is the whole point of having the ledger at all.
//
// # Where it applies
//
// The just-in-time machinery was built for the bastions -- ssh, rdp, vnc,
// telnet, ftp -- where a session is the unit of access. This package is what
// makes it cover the plant, where a *request* is the unit: one Modbus
// connection carries reads all day and one UMAS program write at four in the
// afternoon, and only the second needs a work order.
package engineering

import (
	"fmt"
	"sort"
	"strings"
)

// Class is what an engineering operation is. The names are the same on every
// protocol, because an operations centre asking "was anything downloaded to a
// controller this week" is not asking about a protocol.
type Class string

// The classes this project recognises.
const (
	// ClassProgramDownload is control logic written into a device: an S7 block
	// download, a UMAS program write, an MMS domain download.
	ClassProgramDownload Class = "program_download"
	// ClassProgramUpload is control logic read out of one, which is how a
	// plant's process knowledge leaves the site.
	ClassProgramUpload Class = "program_upload"
	// ClassModeChange is a controller moved between run, program and stop.
	ClassModeChange Class = "mode_change"
	// ClassRestart is a device restarted or reset.
	ClassRestart Class = "restart"
	// ClassConfiguration is a setting rather than a command: an MMS $CF$ or
	// $SG$ write, an IEC 104 parameter, an OPC UA node-management call.
	ClassConfiguration Class = "configuration"
	// ClassFirmware is a firmware or boot image moved to a device.
	ClassFirmware Class = "firmware"
	// ClassMethodCall is a method the object model exposes for the purpose: an
	// OPC UA Call, which is the one service on that protocol that runs
	// something rather than reading or writing it.
	ClassMethodCall Class = "method_call"
	// ClassFileTransfer is a file moved onto or off a device over the control
	// protocol itself.
	ClassFileTransfer Class = "file_transfer"
)

// Classes is every class, sorted, for validation and for a view that lists
// them.
func Classes() []Class {
	out := []Class{ClassConfiguration, ClassFileTransfer, ClassFirmware,
		ClassMethodCall, ClassModeChange, ClassProgramDownload,
		ClassProgramUpload, ClassRestart}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Known reports whether a name is a class this project has.
func Known(s string) bool {
	for _, c := range Classes() {
		if Class(s) == c {
			return true
		}
	}
	return false
}

// The reasons an engineering decision reports. They reach the security log, the
// refusal counters and internal/attack's table, so they are stable and the same
// on every kind.
const (
	// ReasonNoGrant is the refusal: this listener requires an approved work
	// order for the class and there is none open.
	ReasonNoGrant = "engineering_no_grant"
	// ReasonUngranted is the alert on a listener that does not require one:
	// the operation happened, and it happened outside every approved window.
	ReasonUngranted = "engineering_ungranted"
)

// Reason is the event name a recognised operation is reported under:
// `engineering_program_download`, which is what a SIEM filters on.
func Reason(c Class) string { return "engineering_" + string(c) }

// Reasons is every reason this package can report, for a test or a view that
// has to enumerate them.
func Reasons() []string {
	out := []string{ReasonNoGrant, ReasonUngranted}
	for _, c := range Classes() {
		out = append(out, Reason(c))
	}
	return out
}

// Operation is one engineering action a kind recognised in its own traffic.
type Operation struct {
	Class Class
	// Detail is the protocol's own words for it: "download block DB12",
	// "$CF$ write", "stop cpu". It goes in the log and in the ledger.
	Detail string
	// Point is what it was done to, where the protocol names one.
	Point string
	// Subject is the identity the estate knows, where the protocol has one: an
	// OPC UA user, an MMS association, a CoAP security name. Empty on the
	// protocols with no identity at all, where the caller passes the client
	// address instead.
	Subject string
}

// String is the operation in one line, for a ledger entry and a log detail.
func (o Operation) String() string {
	parts := make([]string, 0, 3)
	parts = append(parts, string(o.Class))
	if o.Detail != "" {
		parts = append(parts, o.Detail)
	}
	if o.Point != "" {
		parts = append(parts, o.Point)
	}
	return strings.Join(parts, " ")
}

// Policy is a listener's compiled `engineering` block.
type Policy struct {
	// RequireGrant refuses an operation in Classes with no open grant.
	RequireGrant bool
	// Deny says the refusal is enforced rather than alerted. It is separate
	// from RequireGrant because "tell me when a download happens outside a
	// window" is the step every estate takes before "refuse it", and a block
	// that could not express the first would be turned off rather than tried.
	Deny bool
	// Classes are the classes a grant is required for. Empty means every
	// class, which is what an operator who wrote `require_grant: true` and
	// nothing else meant.
	Classes map[Class]bool
	// Ledger says every recognised operation is written to the access
	// ledger's own record, not only to the security log. Default true where
	// the daemon has a ledger: the log rotates and the ledger is
	// hash-chained, and an engineering record is the one an audit asks for.
	Ledger bool
}

// Covers reports whether a grant is required for this class.
func (p Policy) Covers(c Class) bool {
	if !p.RequireGrant {
		return false
	}
	if len(p.Classes) == 0 {
		return true
	}
	return p.Classes[c]
}

// Check fills in the defaults and refuses a policy that cannot work.
func (p *Policy) Check() error {
	for c := range p.Classes {
		if !Known(string(c)) {
			return fmt.Errorf("engineering class %q: not one this project recognises", c)
		}
	}
	if len(p.Classes) > 0 && !p.RequireGrant {
		return fmt.Errorf("engineering: classes named without require_grant, so nothing would be asked of them")
	}
	return nil
}
