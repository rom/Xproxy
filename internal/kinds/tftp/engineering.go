package tftp

import (
	"context"
	"net/netip"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/correlate"
	"github.com/rom/xproxy/internal/engineering"
	"github.com/rom/xproxy/internal/textsafe"
	wire "github.com/rom/xproxy/internal/tftp"
)

// Engineering on TFTP, which is one operation: a write.
//
// A read is not engineering, and saying so is the whole judgement here. Every
// switch, phone and field device in an estate boots by reading its own
// configuration or firmware over this protocol, thousands of times a week; a
// class that included those would be a class nobody could read. A *write* is the
// other thing: somebody putting an image or a configuration file onto the server
// those devices boot from, which is the step before every one of them runs it.
//
// So a write is reported as `firmware`, whatever the filename says. The path
// classification this kind already does is about hygiene -- a NUL, a traversal, a
// control character -- and it does not say what a file *is*; an image called
// `test.txt` is still what the next device will run.

// engineeringOf classifies one request.
func engineeringOf(op wire.Op, path wire.Path) (engineering.Operation, bool) {
	if op != wire.OpWrite {
		return engineering.Operation{}, false
	}
	return engineering.Operation{Class: engineering.ClassFirmware,
		Detail: "write", Point: path.Name}, true
}

// decideEngineering reports one engineering operation and says whether to carry
// the transfer.
func (t *server) decideEngineering(ip netip.Addr, op wire.Op, path wire.Path) string {
	if !t.engineering.On() {
		return ""
	}
	e, ok := engineeringOf(op, path)
	if !ok {
		return ""
	}
	subject := ip.String()
	return t.engineering.Decide(e, subject, t.m.Upstream, nil, t.enforcing(),
		engineering.Handler{
			Report: func(e engineering.Operation, grant *access.Grant) {
				t.reportEngineering(ip, e, grant)
			},
			Ungranted: func(e engineering.Operation, reason string) {
				t.deny(ip, reason, e.String())
			},
			Would: func(e engineering.Operation, reason string) {
				t.host.Counters().WouldRefuse("tftp", reason)
				t.host.Shadow().Record("tftp", t.cfg.Name, reason, "engineering", e.String())
			},
			Refused: func(e engineering.Operation, reason string) {
				t.deny(ip, reason, e.String())
			},
		})
}

func (t *server) reportEngineering(ip netip.Addr, e engineering.Operation, grant *access.Grant) {
	t.host.Counters().Engineering("tftp", string(e.Class))
	t.host.ObserveFact(ip, correlate.Fact{
		Class: correlate.ClassEngineering, Kind: "tftp", Listener: t.cfg.Name,
		Detail: e.String(),
	})
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "tftp",
		"class", string(e.Class), "operation", e.Detail,
		"file", textsafe.Clip64(e.Point)}
	if grant != nil {
		attrs = append(attrs, "grant", grant.ID, "work_order", textsafe.Clip64(grant.Reason))
	}
	t.host.Logs().SecurityEvent(context.Background(), "engineering",
		engineering.Reason(e.Class), attrs...)
}
