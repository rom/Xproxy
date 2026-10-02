package tacacs

import (
	"context"
	"net/netip"
	"strings"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/textsafe"
)

// Engineering on TACACS+: a configuration command.
//
// Device administration is engineering activity, and saying so is the
// judgement this file makes. A `configure terminal` on a core router at
// three in the morning is the same kind of event as a PLC download -- a
// change to infrastructure the estate depends on, made by a person, outside
// or inside an approved window -- and this is the only listener in the
// project that can see one. So the same machinery applies: the operation is
// reported as its own class of event, it is matched against the work orders
// on file, and with `require_grant` it is refused when no approved grant is
// open for it.
//
// What is *not* engineering is a `show`. Every device in an estate is
// looked at constantly by monitoring, by scripts and by people, and a class
// that included those would be a class nobody reads. The classification
// below therefore names the four things that change a device and leaves
// everything else out, which means it will miss a vendor's own spelling of
// a change -- and that is the right failure: a missed report is a gap in a
// record, where a report on every `show interfaces` is a record nobody
// opens.

// engineeringOf classifies one command.
func engineeringOf(req Request) (engineering.Operation, bool) {
	if req.Command == "" {
		return engineering.Operation{}, false
	}
	words := strings.Fields(strings.ToLower(req.Command))
	if len(words) == 0 {
		return engineering.Operation{}, false
	}
	point := req.Port
	if point == "" {
		point = req.Client.String()
	}
	op := func(c engineering.Class) (engineering.Operation, bool) {
		return engineering.Operation{Class: c, Detail: req.Command, Point: point,
			Subject: req.User}, true
	}
	switch words[0] {
	case "reload", "reboot", "restart":
		// The device is going away and coming back, which is the one command
		// on this list whose effect is immediate and total.
		return op(engineering.ClassRestart)
	case "configure", "config", "conf":
		return op(engineering.ClassConfiguration)
	case "copy", "upload", "download", "archive":
		// A file moving to or from the device: a configuration leaving, an
		// image arriving. Which of the two it is depends on the arguments,
		// and `copy running-config tftp:` is a configuration leaving the
		// estate whichever way a reader counts it.
		if anyWord(words, "flash:", "bootflash:", "slot0:", "disk0:", "harddisk:") {
			return op(engineering.ClassFirmware)
		}
		return op(engineering.ClassFileTransfer)
	case "write", "save":
		// `write memory` makes the running configuration survive a reboot,
		// and `write erase` removes it. Both are configuration.
		return op(engineering.ClassConfiguration)
	case "request", "set", "delete", "edit", "commit", "rollback":
		// Junos and the platforms that follow its grammar: `set`, `delete`
		// and `edit` are configuration, `commit` applies it, and `request
		// system reboot` is a restart -- which the first word cannot tell
		// apart, so the arguments decide.
		if words[0] == "request" && anyWord(words, "reboot", "halt", "power-off") {
			return op(engineering.ClassRestart)
		}
		if words[0] == "request" && anyWord(words, "software", "system", "add") {
			return op(engineering.ClassFirmware)
		}
		return op(engineering.ClassConfiguration)
	case "upgrade", "install", "boot":
		return op(engineering.ClassFirmware)
	}
	return engineering.Operation{}, false
}

func anyWord(words []string, want ...string) bool {
	for _, w := range words {
		for _, v := range want {
			if strings.Contains(w, v) {
				return true
			}
		}
	}
	return false
}

// decideEngineering reports one engineering operation and says whether to
// carry the command.
func (t *server) decideEngineering(c *conn, req Request) string {
	if !t.engineering.On() {
		return ""
	}
	e, ok := engineeringOf(req)
	if !ok {
		return ""
	}
	subject := req.User
	if subject == "" {
		subject = c.ip.String()
	}
	return t.engineering.Decide(e, subject, t.c.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(e engineering.Operation, grant *access.Grant, order *access.WorkOrder) {
				t.reportEngineering(c.ip, e, grant, order)
			},
			Ungranted: func(e engineering.Operation, reason string, order *access.WorkOrder) {
				t.engineeringOutside(c.ip, reason, e, order)
			},
			Would: func(e engineering.Operation, reason string) {
				t.host.Counters().WouldRefuse("tacacs", reason)
				t.host.Shadow().Record("tacacs", t.name, reason, "engineering", e.String())
			},
			Refused: func(e engineering.Operation, reason string) {
				t.deny(c.ip, reason, e.String())
			},
		})
}

func (t *server) reportEngineering(ip netip.Addr, e engineering.Operation,
	grant *access.Grant, order *access.WorkOrder) {
	t.host.Counters().Engineering("tacacs", string(e.Class))
	t.host.ObserveFact(ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "tacacs", Listener: t.name,
		Detail: e.String(),
	})
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "tacacs",
		"class", string(e.Class), "command", textsafe.Clip64(e.Detail)}
	if e.Subject != "" {
		attrs = append(attrs, "user", textsafe.Clip64(e.Subject))
	}
	if e.Point != "" {
		attrs = append(attrs, "port", textsafe.Clip64(e.Point))
	}
	if grant != nil {
		attrs = append(attrs, "grant", grant.ID, "grant_reason", textsafe.Clip64(grant.Reason))
	}
	// The work order on file for the device, and the tone that follows from
	// it: a work order is not an approval and permits nothing, it says
	// somebody was expecting work here.
	attrs = append(attrs, "severity", engineering.Severity(order))
	if order != nil {
		t.host.Counters().EngineeringFiled("tacacs", string(e.Class))
		attrs = append(attrs, "work_order", order.Reference,
			"work_order_by", textsafe.Clip64(order.By))
	}
	t.host.Logs().SecurityEvent(context.Background(), "engineering",
		engineering.Reason(e.Class), attrs...)
}

// engineeringOutside records an operation that happened outside every
// approved window on a listener that does not require one. The command was
// carried; what is counted is that nobody had approved it.
func (t *server) engineeringOutside(ip netip.Addr, reason string,
	op engineering.Operation, order *access.WorkOrder) {
	t.host.Counters().EngineeringOutside("tacacs", string(op.Class), reason)
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", ip.String(), "proto", "tacacs",
		"reason", reason, "class", string(op.Class),
		"command", textsafe.Clip64(op.Detail)}
	if op.Subject != "" {
		a = append(a, "user", textsafe.Clip64(op.Subject))
	}
	a = append(a, "severity", engineering.Severity(order))
	if order != nil {
		a = append(a, "work_order", order.Reference,
			"work_order_by", textsafe.Clip64(order.By))
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "tacacs_"+reason, a...)
}
