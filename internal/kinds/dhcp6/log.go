package dhcp6

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/assets"
	wire "github.com/rom/xproxy/internal/dhcp6"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records a segment's DHCPv6 is asked for after an incident: which
// identifier got which address or prefix, from which server, for how long, and
// what it was told. That last part is the one a DHCPv6 server's own log does not
// have, because the server is the thing being checked.
//
// Every value a peer chose goes through textsafe on its way to a log line. A
// vendor class, a boot URL and a search domain are all strings a client or a
// server picked, and a log line is exactly where a control character in one of
// them does its work.

// refused records a message the policy refused. Which side it came from is
// carried, because "a client asked for something it may not" and "a server
// answered with something it may not" are different events that happen to share
// a counter.
func (s *server) refused(ip netip.Addr, m *wire.Message, d Decision, side string) {
	c := s.host.Counters()
	in := m.Innermost()
	if !s.enforcing() && !d.Hard {
		c.DHCP6WouldDeny.Add(1)
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up: an operator reading the refusal
		// count of a listener being trialled would otherwise see enforcement
		// that is not happening.
		c.WouldRefuse("dhcp6", d.Reason)
		s.host.Shadow().Record("dhcp6", s.cfg.Name, d.Reason, d.Rule,
			side+" "+in.Type.String()+" "+duidOf(m))
		s.logMessage(ip, m, d, side, "would_deny")
		return
	}
	c.Refuse("dhcp6", d.Reason)
	c.DHCP6Denied.Add(1)
	s.logMessage(ip, m, d, side, "deny")
	// The ban ladder hears about this before alert_on_deny can silence the
	// record below: turning the log down is not a decision to stop responding.
	if bl := s.host.Bans(); bl != nil && ip.IsValid() && !ip.IsUnspecified() {
		bl.Observe(ip, "dhcp6_denied")
	}

	if !s.alerts() {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "proto", "dhcp6",
		"reason", d.Reason, "side", side, "message_type", in.Type.String(),
		"duid", duidOf(m)}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip256(d.Detail))
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", "dhcp6_"+d.Reason, attrs...)
}

// deny records a refusal that is not about a message the policy read: a client
// outside the address list, a malformed message, a bound, a reply from an
// address that is not a server. None of these is shadowed.
func (s *server) deny(ip netip.Addr, what, detail string) {
	// The ban ladder hears about this before alert_on_deny can silence the
	// record below: turning the log down is not a decision to stop responding.
	if bl := s.host.Bans(); bl != nil && ip.IsValid() && !ip.IsUnspecified() {
		bl.Observe(ip, "dhcp6_denied")
	}

	if !s.alerts() {
		return
	}
	name := what
	if !strings.HasPrefix(name, "dhcp6_") {
		name = "dhcp6_" + name
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "proto", "dhcp6"}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip256(detail))
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", name, attrs...)
}

// logMessage writes the access line for one message.
func (s *server) logMessage(ip netip.Addr, m *wire.Message, d Decision, side, decision string) {
	if !s.m.LogMessages && decision == "allow" {
		return
	}
	in := m.Innermost()
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "side", side,
		"message_type", in.Type.String(), "duid", duidOf(m),
		"xid", strconv.FormatUint(uint64(in.TransactionID), 16), "decision", decision}
	if n := relayDepth(m); n > 0 {
		attrs = append(attrs, "relay_hops", n)
	}
	if v := vendorClass(in); v != "" {
		attrs = append(attrs, "vendor_class", textsafe.Clip256(v))
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
	}
	if len(d.Strip) > 0 {
		attrs = append(attrs, "stripped", optionList(d.Strip), "stripped_why", stripWhy(d))
	}
	s.host.Logs().Access.Info("dhcp6", attrs...)
}

// logAsks records the options a client asked for and may not have.
func (s *server) logAsks(ip netip.Addr, gone []uint16) {
	if len(gone) == 0 || !s.m.LogMessages {
		return
	}
	s.host.Logs().Access.Info("dhcp6", "listener", s.cfg.Name, "client_ip", ip.String(),
		"side", "client", "decision", "allow", "asks_removed", optionList(gone))
}

// logLease writes the line for an address or a prefix handed out.
//
// This is the record an estate is asked for, and it is the beginning of an asset
// inventory: an identifier, the hardware address inside it where there is one, an
// address, a prefix, a lifetime, and the server that granted it.
func (s *server) logLease(e *exchange, m *wire.Message, from netip.Addr) {
	if !s.logLeases() {
		return
	}
	in := m.Innermost()
	if !in.Type.Assigns() {
		return
	}
	ias, err := in.IAs()
	if err != nil {
		return
	}
	for _, ia := range ias {
		for _, a := range ia.Addresses {
			s.leaseLine(e, in, from, "address", a.Addr.String(), a.Preferred, a.Valid, ia)
		}
		for _, p := range ia.Prefixes {
			s.leaseLine(e, in, from, "prefix", p.Prefix.String(), p.Preferred, p.Valid, ia)
		}
		if ia.Status != nil && ia.Status.Code != wire.StatusSuccess {
			// A refusal from the server is as much a record as a grant: "no
			// addresses available" at three in the morning is the line an
			// operator is looking for.
			s.host.Logs().Access.Info("dhcp6", "listener", s.cfg.Name,
				"duid", duidOf(m), "server", from.String(),
				"association", wire.OptionName(ia.Code), "iaid", ia.IAID,
				"status", wire.StatusName(ia.Status.Code),
				"status_detail", textsafe.Clip256(ia.Status.Message))
		}
	}
}

func (s *server) leaseLine(e *exchange, in *wire.Message, from netip.Addr,
	what, value string, preferred, valid uint32, ia wire.IA) {
	attrs := []any{"listener", s.cfg.Name, "message_type", in.Type.String(),
		"duid", duidOfMessage(in), what, value,
		"association", wire.OptionName(ia.Code), "iaid", ia.IAID,
		"preferred_seconds", preferred, "valid_seconds", valid,
		"server", from.String(), "client_ip", e.client.Addr().String()}
	if d, ok := in.ClientDUID(); ok {
		if mac := d.HardwareAddr(); mac != "" {
			// The one field that ties this device to its DHCPv4 self.
			attrs = append(attrs, "hardware_address", mac)
		}
	}
	if v, ok := in.Get(wire.OptionDNSServers); ok {
		if as, err := wire.Addresses(v); err == nil {
			attrs = append(attrs, "dns", joinAddrs(as))
		}
	}
	if v, ok := in.Get(wire.OptionDomainList); ok {
		if names, err := wire.DomainNames(v); err == nil && len(names) > 0 {
			attrs = append(attrs, "domain_search", textsafe.Clip256(strings.Join(names, ",")))
		}
	}
	if v, ok := in.Get(wire.OptionBootFileURL); ok {
		attrs = append(attrs, "boot_file_url", textsafe.Clip256(string(v)))
	}
	if len(e.asked) > 0 {
		attrs = append(attrs, "asked_for", optionList(codesOf(e.asked)))
	}
	if e.rule != "" {
		attrs = append(attrs, "rule", e.rule)
	}
	s.host.Logs().Access.Info("dhcp6", attrs...)
}

// observeRequest tells the estate's inventory what a client's own request said.
//
// The DUID is what identifies the device, and for the link-layer forms it
// carries the MAC address -- which is what lets a DHCPv6 sighting attach to the
// same device an estate already knows from DHCPv4. That is the whole reason this
// listener is worth having in an inventory rather than just in a log.
func (s *server) observeRequest(m *wire.Message, from netip.Addr) {
	in := m.Innermost()
	o := assets.Observation{
		Listener: s.cfg.Name, Proto: "dhcp6",
		VendorClass: vendorClass(in),
		UserClass:   userClass(in),
	}
	if d, ok := m.ClientDUID(); ok {
		if mac := d.HardwareAddr(); mac != "" {
			if hw, err := parseMAC(mac); err == nil {
				o.Hardware = hw
			}
		}
	}
	if !from.IsUnspecified() {
		o.Addr = from
	}
	s.host.ObserveAsset(o)
}

// observeReply tells the inventory what a server granted.
func (s *server) observeReply(m *wire.Message, e *exchange) {
	in := m.Innermost()
	if !in.Type.Assigns() {
		return
	}
	ias, err := in.IAs()
	if err != nil {
		return
	}
	o := assets.Observation{Listener: s.cfg.Name, Proto: "dhcp6", Server: false}
	if d, ok := in.ClientDUID(); ok {
		if mac := d.HardwareAddr(); mac != "" {
			if hw, err := parseMAC(mac); err == nil {
				o.Hardware = hw
			}
		}
	}
	if v, ok := in.Get(wire.OptionBootFileURL); ok {
		o.BootFile = textsafe.Clip256(string(v))
	}
	for _, ia := range ias {
		for _, a := range ia.Addresses {
			o.Addr = a.Addr
			s.host.ObserveAsset(o)
		}
	}
	if o.Addr.IsValid() {
		return
	}
	// A reply that delegated a prefix and no address still says the device is
	// there, and the client's own address is where it asked from.
	o.Addr = e.client.Addr()
	s.host.ObserveAsset(o)
}

// duidOfMessage is the identifier of one message rather than a chain.
func duidOfMessage(m *wire.Message) string {
	d, ok := m.ClientDUID()
	if !ok {
		return "duid:none"
	}
	return d.String()
}

// parseMAC reads the notation HardwareAddr produces back into octets, for the
// inventory, which keys on the address rather than on its rendering.
func parseMAC(s string) ([]byte, error) {
	parts := strings.Split(s, ":")
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(n))
	}
	return out, nil
}

// codesOf reads an option request list into codes, for the log line.
func codesOf(list []byte) []uint16 {
	out := make([]uint16, 0, len(list)/2)
	for i := 0; i+1 < len(list); i += 2 {
		out = append(out, uint16(list[i])<<8|uint16(list[i+1]))
	}
	return out
}

// optionList renders option codes by name, which is what a log line should
// carry: "dns_servers,boot_file_url" says what happened and "23,59" does not.
func optionList(codes []uint16) string {
	names := make([]string, 0, len(codes))
	for _, c := range codes {
		names = append(names, wire.OptionName(c))
	}
	return strings.Join(names, ",")
}

// stripWhy renders why each option went, in the same order as the list.
func stripWhy(d Decision) string {
	out := make([]string, 0, len(d.Strip))
	for _, c := range d.Strip {
		out = append(out, wire.OptionName(c)+": "+d.StripReason[c])
	}
	return textsafe.Clip256(strings.Join(out, "; "))
}

func joinAddrs(as []netip.Addr) string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	return strings.Join(out, ",")
}
