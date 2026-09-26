package tftp

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/assets"
	wire "github.com/rom/xproxy/internal/tftp"
)

// The records a provisioning path is asked for after an incident: which device
// asked for which file, in which direction, how much of it moved, and what was
// refused.
//
// The filename is in every one of them, because on this protocol it is the
// whole of what was asked for -- but it goes through the classifier's Clean
// form rather than raw, so a name with an escape sequence in it cannot write
// its own line in the log it caused.

// refused records a request the policy refused.
func (t *server) refused(ip netip.Addr, op wire.Op, pa wire.Path, mode string, d Decision) {
	c := t.host.Counters()
	if !t.enforcing() && !d.Hard {
		c.TFTPWouldDeny.Add(1)
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up, and a listener in shadow mode
		// that reported refusals it had in fact forwarded would be the one way
		// to defeat that: an operator reading the refusal count of a listener
		// being trialled would see enforcement that is not happening.
		c.WouldRefuse("tftp", d.Reason)
		t.host.Shadow().Record("tftp", t.cfg.Name, d.Reason, d.Rule, op.String()+" "+pa.Clean)
		t.logRequest(ip, op, pa, mode, d, "would_deny")
		return
	}
	c.Refuse("tftp", d.Reason)
	// On the enforced path with the counter above, for the same reason: a
	// filename this relay forwarded was not refused for its shape.
	if isPathReason(d.Reason) {
		c.TFTPPathRefused.Add(1)
	}
	c.TFTPDenied.Add(1)
	t.logRequest(ip, op, pa, mode, d, "deny")
	if !t.alerts() {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "tftp",
		"reason", d.Reason, "op", op.String(), "path_class", pa.Class.String()}
	if pa.Clean != "" {
		attrs = append(attrs, "path", pa.Clean)
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", d.Detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "tftp_"+d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "tftp_denied")
	}
}

// deny records a refusal that is not about a request the policy read: a client
// that may not send, a malformed packet, a bound, a datagram from an address
// that has no part in a transfer. None of these is shadowed.
func (t *server) deny(ip netip.Addr, what, detail string) {
	if !t.alerts() {
		return
	}
	name := what
	if len(name) < 5 || name[:5] != "tftp_" {
		name = "tftp_" + name
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "tftp"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", name, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "tftp_denied")
	}
}

// isPathReason says whether a refusal was about the shape or the place of the
// filename, which is the number that says the path policy is doing something.
func isPathReason(reason string) bool {
	switch reason {
	case "directory_denied", "directory_not_allowed",
		"filename_denied", "filename_not_allowed",
		"filename_too_long", "path_too_deep":
		return true
	}
	return len(reason) > 5 && reason[:5] == "path_"
}

// logRequest writes the line for a request that never became a transfer.
func (t *server) logRequest(ip netip.Addr, op wire.Op, pa wire.Path, mode string, d Decision, decision string) {
	if !t.logTransfers() {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "op", op.String(),
		"path", pa.Clean, "path_class", pa.Class.String(), "mode", mode,
		"decision", decision}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
	}
	t.host.Logs().Access.Info("tftp", attrs...)
}

// observeTransfer tells the estate's inventory what a transfer said.
//
// A device fetching firmware over TFTP is telling the inventory two things at
// once: that it is an embedded device that boots from the network, and which
// image it boots -- which is closer to a model number than anything else a
// passive observer gets.
func (t *server) observeTransfer(x *transfer) {
	t.host.ObserveAsset(assets.Observation{
		Listener: t.cfg.Name, Proto: "tftp", Addr: x.ip,
		BootFile: x.path.Clean,
		// The device asked; the server answered.
		Server: false,
	})
}

// logTransfer writes the line for a finished transfer: which device got which
// file, how much of it, and how it ended. This is the record an estate is
// actually asked for.
func (t *server) logTransfer(x *transfer, reason string) {
	if !t.logTransfers() {
		return
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", x.ip.String(),
		"op", x.op.String(), "path", x.path.Clean, "mode", x.mode,
		"bytes", x.bytes, "packets", x.packets, "block_size", x.block,
		"window", x.window, "server", x.up.String(),
		"duration_ms", time.Since(x.start).Milliseconds()}
	if x.rule != "" {
		attrs = append(attrs, "rule", x.rule)
	}
	if reason != "" {
		attrs = append(attrs, "outcome", reason)
	}
	t.host.Logs().Access.Info("tftp transfer", attrs...)
}
