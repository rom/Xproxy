package coap

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/assets"
	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records a constrained network is asked for afterwards: which client asked
// what of which device, what the device answered, and what the relay refused.
//
// On this protocol the path is the useful field, because the path is the object
// model: "/3311/0/5850" says which light, and "0.03 PUT" says it was being
// switched rather than read. Every value a peer chose goes through textsafe on its
// way to a line -- a path segment, a query part and a boot-style URI are all
// strings a device or a client picked, and a log line is exactly where a control
// character in one does its work.

// refused records a message the policy refused.
func (s *server) refused(ip netip.Addr, m *wire.Message, d Decision, side string) {
	c := s.host.Counters()
	switch d.Reason {
	case "proxying_not_allowed":
		c.CoAPProxyRefused.Add(1)
	case "amplified":
		c.CoAPAmplified.Add(1)
	}
	if !s.enforcing() && !d.Hard {
		c.CoAPWouldDeny.Add(1)
		// Counted only as a would-be refusal, and in a table of its own so that
		// a status view cannot add the two up: an operator reading the refusal
		// count of a listener being trialled would otherwise see enforcement
		// that is not happening.
		c.WouldRefuse("coap", d.Reason)
		s.host.Shadow().Record("coap", s.cfg.Name, d.Reason, d.Rule,
			side+" "+m.Code.String()+" "+textsafe.Clip256(m.Path()))
		s.logMessage(ip, m, d, side, "would_deny", false)
		return
	}
	c.Refuse("coap", d.Reason)
	c.CoAPDenied.Add(1)
	s.logMessage(ip, m, d, side, "deny", false)
	if !s.alerts() {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "proto", "coap",
		"reason", d.Reason, "side", side, "code", m.Code.String(),
		"path", textsafe.Clip256(m.Path())}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip256(d.Detail))
	}
	if d.Answer != 0 {
		attrs = append(attrs, "answered", d.Answer.String())
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", "coap_"+d.Reason, attrs...)
	if bl := s.host.Bans(); bl != nil && ip.IsValid() && !ip.IsUnspecified() {
		bl.Observe(ip, "coap_denied")
	}
}

// deny records a refusal that is not about a message the policy read: a client
// outside the address list, a malformed message, a bound, an answer from an
// address that is not a device. None of these is shadowed.
func (s *server) deny(ip netip.Addr, what, detail string) {
	if !s.alerts() {
		return
	}
	name := what
	if !strings.HasPrefix(name, "coap_") {
		name = "coap_" + name
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "proto", "coap"}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip256(detail))
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", name, attrs...)
	if bl := s.host.Bans(); bl != nil && ip.IsValid() && !ip.IsUnspecified() {
		bl.Observe(ip, "coap_denied")
	}
}

// logMessage writes the access line for one message from the segment.
func (s *server) logMessage(ip netip.Addr, m *wire.Message, d Decision,
	side, decision string, secure bool) {
	if !s.m.LogMessages && decision == "allow" {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "side", side,
		"type", m.Type.String(), "code", m.Code.String(),
		"path", textsafe.Clip256(m.Path()), "decision", decision,
		"secure", secure}
	if q := m.Query(); q != "" {
		attrs = append(attrs, "query", textsafe.Clip256(q))
	}
	if len(m.Token) > 0 {
		attrs = append(attrs, "token", tokenHex(m.Token))
	}
	if n, ok := m.ContentFormat(); ok {
		attrs = append(attrs, "content_format", wire.ContentFormatName(n))
	}
	if len(m.Payload) > 0 {
		attrs = append(attrs, "payload_bytes", len(m.Payload))
	}
	if m.Registering() {
		attrs = append(attrs, "observe", "register")
	}
	if m.Deregistering() {
		attrs = append(attrs, "observe", "deregister")
	}
	if m.Proxying() {
		attrs = append(attrs, "proxying", textsafe.Clip256(proxyDetail(m)))
	}
	if b, ok, err := m.Block1(); ok && err == nil {
		attrs = append(attrs, "block1", b.String())
	}
	if n := m.TransferSize(); n > 0 {
		attrs = append(attrs, "transfer_bytes", n)
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
	}
	s.host.Logs().Access.Info("coap", attrs...)
}

// logReply writes the line for a device's answer, which is the half a device's own
// log does not have: what it told the client, and how large the answer was for the
// question that asked.
func (s *server) logReply(from netip.Addr, m *wire.Message, e *exchange, d Decision) {
	if !s.m.LogMessages {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "device", from.String(), "side", "device",
		"type", m.Type.String(), "code", m.Code.String(),
		"path", textsafe.Clip256(e.path), "client_ip", e.client.Addr().String(),
		"request_bytes", e.size, "response_bytes", len(m.Raw)}
	if e.size > 0 {
		attrs = append(attrs, "factor", len(m.Raw)/max(e.size, 1))
	}
	if n, ok := m.ContentFormat(); ok {
		attrs = append(attrs, "content_format", wire.ContentFormatName(n))
	}
	if b, ok, err := m.Block2(); ok && err == nil {
		attrs = append(attrs, "block2", b.String())
	}
	if v, ok := m.Observe(); ok && e.observing {
		attrs = append(attrs, "notification", v)
	}
	if e.rule != "" {
		attrs = append(attrs, "rule", e.rule)
	}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
	}
	s.host.Logs().Access.Info("coap", attrs...)
}

// observeRequest tells the estate's inventory what a client asked for.
//
// CoAP has no identity to record, so what goes to the inventory is the address and
// the paths it touched -- which on a constrained network is a more useful record
// than it sounds: the paths are the object model, so the set of paths a client
// asked for is a description of what it thinks the device is.
func (s *server) observeRequest(m *wire.Message, from netip.Addr, secure bool) {
	if !m.Code.IsRequest() {
		return
	}
	o := assets.Observation{Listener: s.cfg.Name, Proto: "coap"}
	if from.IsValid() && !from.IsUnspecified() {
		o.Addr = from
	}
	if secure {
		o.UserClass = "dtls"
	}
	s.host.ObserveAsset(o)
}

// observeReply tells the inventory which device answered, which is the half that
// names equipment: a device that answers /.well-known/core has told the estate
// what it is.
func (s *server) observeReply(m *wire.Message, e *exchange, from netip.Addr) {
	if !m.Code.IsSuccess() {
		return
	}
	o := assets.Observation{Listener: s.cfg.Name, Proto: "coap", Server: true}
	if from.IsValid() && !from.IsUnspecified() {
		o.Addr = from
	}
	if n, ok := m.ContentFormat(); ok && n == wire.LinkFormat {
		// The discovery document, which is the device describing itself.
		o.VendorClass = textsafe.Clip256(firstLink(m.Payload))
	}
	_ = e
	s.host.ObserveAsset(o)
}

// firstLink is the first link in an RFC 6690 document, which is enough to say what
// answered without keeping the whole list.
func firstLink(payload []byte) string {
	s := string(payload)
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// tokenHex renders a token for a log line. It is a value a client chose, so it is
// rendered as hexadecimal rather than as text.
func tokenHex(tok []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(tok)*2)
	for _, b := range tok {
		out = append(out, hex[b>>4], hex[b&0x0f])
	}
	return string(out)
}

func itoa(n int) string { return strconv.Itoa(n) }
