package bacnet

import (
	"context"
	"errors"
	"net/netip"
	"strconv"

	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records somebody asks for after an incident in a building.
//
// The service, the object and the property -- never the encoded value. A
// BACnet value is a temperature, a setpoint or an enumeration, so the line
// is not drawn where it is on the database kinds for the sake of secrecy:
// it is drawn because a value is an encoded structure this relay does not
// interpret, and a log line full of octets nobody can read is a log line
// nobody uses. What an estate wants to know is who set the setpoint, on
// which object, and whether it was allowed -- and that is what these lines
// say.

// refused records a decision the policy refused.
func (t *server) refused(ip netip.Addr, a *wire.APDU, d Decision, subject string) {
	c := t.host.Counters()
	if !t.enforcing() && !d.Hard {
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up, and a listener in shadow mode
		// that reported refusals it had in fact forwarded would be the one way
		// to defeat that: an operator reading the refusal count of a listener
		// being trialled would see enforcement that is not happening.
		c.WouldRefuse("bacnet", d.Reason)
		t.host.Shadow().Record("bacnet", t.name, d.Reason, d.Rule, subject)
		return
	}
	c.Refuse("bacnet", d.Reason)
	if !t.alertOnDeny {
		return
	}
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "bacnet",
		"reason", d.Reason}
	if a != nil && a.HasService {
		attrs = append(attrs, "service", a.Service.Name())
		if a.HasInvokeID {
			attrs = append(attrs, "invoke_id", int(a.InvokeID))
		}
	}
	if subject != "" {
		attrs = append(attrs, "what", textsafe.Clip64(subject))
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(d.Detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "bacnet_"+d.Reason, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "bacnet_denied")
	}
}

// deny records a refusal that is not about something the policy read: a
// client that may not send here at all, a datagram that is not a message,
// an answer nobody asked for.
func (t *server) deny(ip netip.Addr, reason, detail string) {
	t.host.Counters().Refuse("bacnet", reason)
	if !t.alertOnDeny {
		return
	}
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "bacnet",
		"reason", reason}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip64(detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "bacnet_"+reason, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "bacnet_denied")
	}
}

// malformed records a datagram this relay could not read as a message.
//
// It is counted and logged rather than dropped quietly because on a
// well-known UDP port the two shapes of it are different events: something
// else entirely arriving, which is background noise, and a BACnet message
// that is broken in a particular way, which is somebody working on the
// parser.
func (t *server) malformed(ip netip.Addr, err error) {
	reason := "malformed"
	if isNotBACnet(err) {
		reason = "not_bacnet"
	}
	t.deny(ip, reason, err.Error())
}

func isNotBACnet(err error) bool { return errors.Is(err, wire.ErrNotBACnet) }

// logRequest writes the access line for one allowed request.
func (t *server) logRequest(ip netip.Addr, a *wire.APDU, d Decision) {
	if !t.logRequests {
		return
	}
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "bacnet",
		"pdu", a.Type.String()}
	if a.HasService {
		attrs = append(attrs, "service", a.Service.Name())
		if a.Service.Writes() {
			attrs = append(attrs, "writes", true)
		}
		if p, ok := wire.CommandPriority(*a); ok {
			attrs = append(attrs, "priority", int(p))
		}
	}
	if targets, ok := wire.Targets(*a); ok && len(targets) > 0 {
		attrs = append(attrs, "object", targets[0].Object.String())
		if targets[0].HasProperty {
			attrs = append(attrs, "property", targets[0].Property.String())
		}
		if len(targets) > 1 {
			attrs = append(attrs, "objects", len(targets))
		}
	} else if a.HasService {
		// Said rather than left out: a request whose object this relay did
		// not find is a request whose object rules did not apply, and a
		// reader of the line should be able to see that.
		attrs = append(attrs, "object", "unlocated")
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	t.host.Logs().Access.Info("bacnet request", attrs...)
}

// logNetwork writes the line for a network layer message, which has no
// service and no object but is worth a record of its own: these are the
// routers of an estate talking to each other, and a client sending one is
// doing something unusual by definition.
func (t *server) logNetwork(ip netip.Addr, n wire.NPDU) {
	if !t.logRequests {
		return
	}
	attrs := []any{"listener", t.name, "client_ip", ip.String(), "proto", "bacnet",
		"network_message", n.MessageType.String()}
	if n.HasVendor {
		attrs = append(attrs, "vendor", int(n.VendorID))
	}
	if n.HasDest {
		attrs = append(attrs, "dnet", int(n.DNET))
	}
	t.host.Logs().Access.Info("bacnet network message", attrs...)
}

// logReply writes the line for an answer delivered back to a client.
func (t *server) logReply(e *exchange, a *wire.APDU) {
	if !t.logRequests {
		return
	}
	attrs := []any{"listener", t.name, "client_ip", e.client.String(), "proto", "bacnet",
		"pdu", a.Type.String(), "service", e.service, "device", e.device,
		"invoke_id", int(e.clientID)}
	if a.HasReason {
		attrs = append(attrs, "reason_code", int(a.Reason))
	}
	if e.rule != "" {
		attrs = append(attrs, "rule", e.rule)
	}
	t.host.Logs().Access.Info("bacnet reply", attrs...)
}

// logBroadcastReply writes the line for an unsolicited answer fanned back
// to the clients that broadcast. The count is in the line because it is the
// amplification: one Who-Is, this many answers.
func (t *server) logBroadcastReply(ip netip.Addr, what string, clients int) {
	if !t.logRequests {
		return
	}
	t.host.Logs().Access.Info("bacnet broadcast reply",
		"listener", t.name, "device_ip", ip.String(), "proto", "bacnet",
		"what", textsafe.Clip64(what), "clients", strconv.Itoa(clients))
}
