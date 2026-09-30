package mms

import (
	"context"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/textsafe"
)

// Engineering on IEC 61850 MMS, where the object names say which writes are
// engineering and which are the control room doing its job.
//
//	domain services         download, upload of a domain's content   program_download / upload
//	$CF$ write              a device's configuration                 configuration
//	$SG$, $SE$ write        a protection relay's setting groups      configuration
//	file services           SCL, COMTRADE, firmware images           file_transfer
//
// A $CO$ write is *not* engineering: that is a breaker being operated, which is
// the control room's own work and is what the policy's rules are for. A $SP$
// setpoint is not either. The line is the same as on every other kind: this
// changes what the device *is*, not what the process is doing.
//
// The setting groups are the case that makes this worth having on this protocol.
// A protection relay's trip characteristic is a handful of numbers in $SG$, and
// changing them is a legitimate engineering act that also happens to be the most
// effective way to disable protection on a substation without sending a single
// command anybody would call a command.

// engineeringOf classifies one request.
func engineeringOf(m *wire.Message, ops []Operation) (engineering.Operation, bool) {
	if m == nil || !m.HasService {
		return engineering.Operation{}, false
	}
	svc := m.Service
	out := engineering.Operation{Detail: svc.String()}
	switch svc.Class() {
	case wire.ClassDomain:
		if svc.Changes() {
			out.Class = engineering.ClassProgramDownload
		} else {
			out.Class = engineering.ClassProgramUpload
		}
	case wire.ClassFile:
		out.Class = engineering.ClassFileTransfer
	default:
		// Not a domain or a file service, so it is engineering only if what it
		// wrote was a configuration or a setting.
		if !svc.Changes() {
			return engineering.Operation{}, false
		}
		for _, op := range ops {
			if !op.Write || !op.Name.Parsed {
				continue
			}
			switch op.Name.FC {
			case wire.FCConfig, wire.FCSettingGroup, wire.FCSettingEdit:
				out.Class = engineering.ClassConfiguration
				out.Point = op.Name.Key()
				out.Detail = svc.String() + " " + string(op.Name.FC)
				return out, true
			}
		}
		return engineering.Operation{}, false
	}
	if len(ops) > 0 {
		out.Point = ops[0].Name.Key()
	}
	return out, true
}

// decideEngineering reports one engineering operation and says whether to carry
// it.
func (t *server) decideEngineering(c *conn, m *wire.Message, ops []Operation) string {
	if !t.engineering.On() {
		return ""
	}
	op, ok := engineeringOf(m, ops)
	if !ok {
		return ""
	}
	a := c.assoc()
	// This protocol has an identity -- the association's own -- so the work
	// order can name a person rather than an address.
	subject := a.Identity()
	if subject == "" {
		subject = c.ip.String()
	}
	op.Subject = subject
	return t.engineering.Decide(op, subject, t.mc.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(op engineering.Operation, grant *access.Grant) {
				t.reportEngineering(c, op, grant)
			},
			Ungranted: func(op engineering.Operation, reason string) {
				t.alertEngineering(c, reason, op)
			},
			Would: func(op engineering.Operation, reason string) {
				t.host.Counters().WouldRefuse("mms", reason)
				t.host.Shadow().Record("mms", t.name, reason, "engineering", op.String())
			},
			Refused: func(op engineering.Operation, reason string) {
				c.refusal()
				t.host.Counters().Refuse("mms", reason)
				t.alertEngineering(c, reason, op)
			},
		})
}

// reportEngineering writes the operation down: its own event, its counter, and a
// fact in the cross-listener window.
func (t *server) reportEngineering(c *conn, op engineering.Operation, grant *access.Grant) {
	t.host.Counters().Engineering("mms", string(op.Class))
	t.host.ObserveFact(c.ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "mms", Listener: t.name,
		Identity: op.Subject, Detail: op.String(),
	})
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"class", string(op.Class), "operation", textsafe.Clip64(op.Detail)}
	if op.Point != "" {
		a = append(a, "object", textsafe.Clip64(op.Point))
	}
	if op.Subject != "" {
		a = append(a, "identity", op.Subject)
	}
	if grant != nil {
		a = append(a, "grant", grant.ID, "work_order", textsafe.Clip64(grant.Reason))
	}
	t.host.Logs().SecurityEvent(context.Background(), "engineering",
		engineering.Reason(op.Class), a...)
}

// alertEngineering is the event for an operation outside every approved window,
// refused or not. It does not reach the ban ladder: an engineer working without
// a filed change is a process problem, and taking the substation's supervision
// away over it would be a worse one.
func (t *server) alertEngineering(c *conn, reason string, op engineering.Operation) {
	if !t.alerts() {
		return
	}
	a := []any{"listener", t.name, "client_ip", c.ip.String(), "proto", "mms",
		"reason", reason, "class", string(op.Class),
		"operation", textsafe.Clip64(op.String())}
	if op.Subject != "" {
		a = append(a, "identity", op.Subject)
	}
	t.host.Logs().SecurityEvent(context.Background(), "alert", "mms_"+reason, a...)
}
