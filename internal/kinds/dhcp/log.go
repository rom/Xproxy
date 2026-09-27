package dhcp

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/assets"
	wire "github.com/rom/xproxy/internal/dhcp"
	"github.com/rom/xproxy/internal/textsafe"
)

// The records a segment's DHCP is asked for after an incident: which hardware
// address got which address, from which server, for how long, and what it was
// told. That last part is the one an ordinary DHCP server's own log does not
// have, because the server is the thing being checked.
//
// Every value a peer chose goes through textsafe on its way to a log line. A
// vendor class, a host name and a boot filename are all strings a client or a
// server picked, and a log line is exactly where a control character in one of
// them does its work.

// refused records a message the policy refused. Which side it came from is
// carried, because "a client asked for something it may not" and "a server
// answered with something it may not" are different events that happen to share
// a counter.
func (s *server) refused(ip netip.Addr, m *wire.Message, d Decision, side string) {
	c := s.host.Counters()
	if !s.enforcing() && !d.Hard {
		c.DHCPWouldDeny.Add(1)
		// Counted only as a would-be refusal. The two tables are kept apart so
		// that a status view cannot add them up, and a listener in shadow mode
		// that reported refusals it had in fact forwarded would be the one way
		// to defeat that: an operator reading the refusal count of a listener
		// being trialled would see enforcement that is not happening.
		c.WouldRefuse("dhcp", d.Reason)
		s.host.Shadow().Record("dhcp", s.cfg.Name, d.Reason, d.Rule,
			side+" "+m.Type.String()+" "+wire.HardwareAddr(m.CHAddr))
		s.logMessage(ip, m, d, side, "would_deny")
		return
	}
	c.Refuse("dhcp", d.Reason)
	c.DHCPDenied.Add(1)
	s.logMessage(ip, m, d, side, "deny")
	if !s.alerts() {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "proto", "dhcp",
		"reason", d.Reason, "side", side, "message_type", m.Type.String(),
		"hardware_address", wire.HardwareAddr(m.CHAddr)}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip256(d.Detail))
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", "dhcp_"+d.Reason, attrs...)
	if bl := s.host.Bans(); bl != nil && ip.IsValid() && !ip.IsUnspecified() {
		// A client with no address yet sends from 0.0.0.0, and banning that
		// would ban every first-time client on the segment. So the ban list
		// only ever hears about an address that identifies somebody: a rogue
		// server, or a relay agent that is misbehaving.
		bl.Observe(ip, "dhcp_denied")
	}
}

// deny records a refusal that is not about a message the policy read: a client
// outside the address list, a malformed message, a bound, a reply from an
// address that is not a server. None of these is shadowed.
func (s *server) deny(ip netip.Addr, what, detail string) {
	if !s.alerts() {
		return
	}
	name := what
	if !strings.HasPrefix(name, "dhcp_") {
		name = "dhcp_" + name
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "proto", "dhcp"}
	if detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip256(detail))
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", name, attrs...)
	if bl := s.host.Bans(); bl != nil && ip.IsValid() && !ip.IsUnspecified() {
		bl.Observe(ip, "dhcp_denied")
	}
}

// logMessage writes the access line for one message.
func (s *server) logMessage(ip netip.Addr, m *wire.Message, d Decision, side, decision string) {
	if !s.m.LogMessages && decision == "allow" {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "client_ip", ip.String(), "side", side,
		"message_type", m.Type.String(), "hardware_address", wire.HardwareAddr(m.CHAddr),
		"xid", strconv.FormatUint(uint64(m.XID), 16), "decision", decision}
	if v := optText(m, wire.OptHostname); v != "" {
		attrs = append(attrs, "hostname", v)
	}
	if v := optText(m, wire.OptVendorClass); v != "" {
		attrs = append(attrs, "vendor_class", v)
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	if d.Reason != "" {
		attrs = append(attrs, "reason", d.Reason)
	}
	s.host.Logs().Access.Info("dhcp", attrs...)
}

// observeLease tells the estate's inventory what a lease said.
//
// DHCP is the richest source there is: it is the only protocol here that sees a
// hardware address and an address together, which is what lets every other
// listener's address-only sighting attach to the same device. The vendor class
// and the parameter list are what a device says it is; the fact that it asked
// for a boot file at all is closer to what it does.
func (s *server) observeLease(m *wire.Message, from netip.Addr) {
	s.host.ObserveAsset(assets.Observation{
		Listener: s.cfg.Name, Proto: "dhcp", Addr: m.YIAddr, Hardware: m.CHAddr,
		Hostname: optText(m, wire.OptHostname),
		BootFile: bootName(m),
		// The server answered; the device asked.
		Server: false,
	})
	_ = from
}

// observeRequest tells the inventory what a client's own request said, which is
// where the vendor class and the parameter list live: a server's reply does not
// carry either.
func (s *server) observeRequest(m *wire.Message, from netip.Addr) {
	o := assets.Observation{
		Listener: s.cfg.Name, Proto: "dhcp", Hardware: m.CHAddr,
		VendorClass: optText(m, wire.OptVendorClass),
		UserClass:   optText(m, wire.OptUserClass),
		Hostname:    optText(m, wire.OptHostname),
	}
	if !m.CIAddr.IsUnspecified() {
		// A renewing client sends from the address it holds; a booting one has
		// none, and the inventory keys on the hardware address until the lease
		// gives it one.
		o.Addr = m.CIAddr
	} else if !from.IsUnspecified() {
		o.Addr = from
	}
	if v, ok := m.Get(wire.OptParameterList); ok {
		o.Params = append([]uint8(nil), v...)
	}
	s.host.ObserveAsset(o)
}

// logLease writes the line for an address handed out.
//
// This is the record an estate is asked for, and it is the beginning of an asset
// inventory: a hardware address, a vendor, a name it called itself, an address,
// a lease, and the server that granted it.
func (s *server) logLease(e *exchange, m *wire.Message, d Decision, from netip.Addr) {
	if !s.logLeases() {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "message_type", m.Type.String(),
		"hardware_address", wire.HardwareAddr(m.CHAddr),
		"vendor_prefix", wire.OUI(m.CHAddr),
		"address", m.YIAddr.String(), "server", from.String(),
		"client_ip", e.client.Addr().String()}
	if v, ok := m.Get(wire.OptLeaseTime); ok {
		if secs, err := wire.Seconds(v); err == nil {
			attrs = append(attrs, "lease_seconds", secs)
		}
	}
	if d.Bounded {
		attrs = append(attrs, "lease_bounded_to", d.Lease)
	}
	if v := optText(m, wire.OptHostname); v != "" {
		attrs = append(attrs, "hostname", v)
	}
	if v := optText(m, wire.OptVendorClass); v != "" {
		attrs = append(attrs, "vendor_class", v)
	}
	if v, ok := m.Get(wire.OptRouter); ok {
		if as, err := wire.Addresses(v); err == nil {
			attrs = append(attrs, "router", joinAddrs(as))
		}
	}
	if v, ok := m.Get(wire.OptDNS); ok {
		if as, err := wire.Addresses(v); err == nil {
			attrs = append(attrs, "dns", joinAddrs(as))
		}
	}
	if f := bootName(m); f != "" {
		attrs = append(attrs, "boot_file", f)
	}
	if len(e.asked) > 0 {
		attrs = append(attrs, "asked_for", optionList(e.asked))
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	s.host.Logs().Access.Info("dhcp lease", attrs...)
}

// logStripped records that a reply had options removed from it, which is an
// access line rather than a security event only when the option was on a deny
// list an operator wrote. An option removed because it named an address the
// estate does not have is a *finding*, so it is reported as one.
func (s *server) logStripped(e *exchange, m *wire.Message, d Decision) {
	names := make([]string, 0, len(d.Strip))
	finding := false
	for _, code := range d.Strip {
		why := d.StripReason[code]
		names = append(names, wire.OptionName(code)+"("+why+")")
		if why != "denied" && why != "not_allowed" {
			finding = true
		}
	}
	list := strings.Join(names, " ")
	s.host.Logs().Access.Info("dhcp stripped", "listener", s.cfg.Name,
		"hardware_address", wire.HardwareAddr(m.CHAddr),
		"address", m.YIAddr.String(), "options", list,
		"client_ip", e.client.Addr().String())
	if !finding {
		return
	}
	// A reply that named a gateway, a resolver, a boot server or a route the
	// estate does not have is a refusal, not a tidy-up, so it is counted as
	// one: this is the number an operator alerts on.
	s.host.Counters().Refuse("dhcp", "option_stripped")
	if !s.alerts() {
		return
	}
	// A reply that named a gateway, a resolver, a boot server or a route the
	// estate does not have is the shape of the attack this kind exists for --
	// and it is the shape a *compromised real server* has too, which is why it
	// is reported even though the source address was on the server list.
	attrs := []any{"listener", s.cfg.Name, "proto", "dhcp",
		"hardware_address", wire.HardwareAddr(m.CHAddr),
		"options", list}
	if d.Detail != "" {
		attrs = append(attrs, "detail", textsafe.Clip256(d.Detail))
	}
	if d.Rule != "" {
		attrs = append(attrs, "rule", d.Rule)
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", "dhcp_option_stripped", attrs...)
}

// logAsk records the options removed from a client's own parameter list.
func (s *server) logAsk(ip netip.Addr, m *wire.Message, removed []uint8) {
	if !s.m.LogMessages {
		return
	}
	s.host.Logs().Access.Info("dhcp ask trimmed", "listener", s.cfg.Name,
		"client_ip", ip.String(), "hardware_address", wire.HardwareAddr(m.CHAddr),
		"removed", optionList(removed))
}

// optText reads an option as text a log line can carry: the control characters
// out and a bound on the length, because a vendor class is whatever a client
// felt like sending.
func optText(m *wire.Message, code uint8) string {
	v, ok := m.Get(code)
	if !ok {
		return ""
	}
	return textsafe.Clip64(strings.TrimRight(string(v), "\x00"))
}

// bootName is the boot filename from either of the two places it lives.
func bootName(m *wire.Message) string {
	if v := optText(m, wire.OptBootFile); v != "" {
		return v
	}
	return textsafe.Clip64(m.File)
}

// safeName is a peer's string on its way into a refusal's detail.
func safeName(s string) string { return textsafe.Clip64(strings.TrimRight(s, "\x00")) }

func joinAddrs(as []netip.Addr) string {
	parts := make([]string, 0, len(as))
	for _, a := range as {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ",")
}

// optionList renders a list of option codes by name, for a log line an operator
// reads rather than decodes.
func optionList(codes []uint8) string {
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, wire.OptionName(c))
	}
	return strings.Join(parts, ",")
}

// stripDetail names the options that caused a whole reply to be refused, for the
// on_denied_option: deny case.
func stripDetail(d Decision) string {
	parts := make([]string, 0, len(d.Strip))
	for _, c := range d.Strip {
		parts = append(parts, wire.OptionName(c))
	}
	return strings.Join(parts, ",")
}

func itoa(n int) string { return strconv.Itoa(n) }
