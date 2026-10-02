// Package listener names the listener kinds this project implements and
// says which daemon serves each one.
//
// The roster is deliberately a static table rather than a registry that
// fills itself in from whatever was linked. A daemon has to be able to
// tell "that listener is not mine" from "that is not a listener kind at
// all", and it cannot do that from a registry holding only the kinds it
// linked: every foreign kind would read as a typing mistake, and a
// configuration the estate shares would fail to load on two daemons out
// of three.
//
// So every binary knows every kind's name and owner, which costs a few
// hundred bytes, and links only the implementations it serves, which is
// the part that carries the code, the dependencies and the risk.
//
// A few kinds are served by two daemons, because the protocol is run by
// two different estates: syslog, SNMP, TFTP, DHCP and the time gateway
// are how a plant's field equipment is provisioned, timed and watched,
// and they are also how a data centre's servers are. MQTT is there for a
// narrower reason -- Sparkplug B telemetry is a plant's own, and the
// asset inventory collects what one daemon saw, so an estate whose device
// births arrive over MQTT needs them on the same daemon as its Modbus.
// Those kinds are linked into both binaries and the listener says which
// daemon serves it, because a listener is bound once: two daemons reading
// one file and both taking the same port is an outage, not a policy.
package listener

import "sort"

// Role is the daemon that serves a kind.
type Role string

const (
	// RoleEdge is xproxy: the internet-facing data plane. HTTP and
	// TLS, the forward proxy and its interception, MASQUE, DNS, and the
	// two generic layer 4 relays.
	RoleEdge Role = "edge"
	// RoleGate is xgate: interactive access by people. SSH, SFTP, and
	// the remote desktop protocols. Sessions here are recorded, carry
	// a second factor and belong to a named principal.
	RoleGate Role = "gate"
	// RoleRelay is xrelay: machine to machine, between services. SMTP,
	// MQTT, FTP, LDAP, the database wire protocols and the message
	// brokers. No humans, no recordings, and a policy written in the
	// protocol's own terms.
	RoleRelay Role = "relay"
	// RoleOT is xot: the plant. The control protocols -- Modbus,
	// IEC 60870-5-104, S7, IEC 61850 MMS, BACnet, OPC UA, CoAP -- and
	// the infrastructure the field equipment itself speaks for time,
	// provisioning, logging and monitoring.
	//
	// It is a daemon of its own for the reason the first split was
	// made: what a binary links is what an attack has to work with,
	// and the process network's proxy has no business carrying a mail
	// parser, a database wire protocol or a message broker front end.
	// This is the binary that sits at level 3.5, and it holds the
	// protocols that speak to equipment and nothing else.
	RoleOT Role = "ot"
)

// Daemon is the program that serves a role.
func (r Role) Daemon() string {
	switch r {
	case RoleEdge:
		return "xproxy"
	case RoleGate:
		return "xgate"
	case RoleRelay:
		return "xrelay"
	case RoleOT:
		return "xot"
	}
	return string(r)
}

// roster is every kind and the daemons that serve it. The first is the
// one a listener of that kind belongs to when it does not say otherwise;
// where there is a second, a listener may name it in `daemon:`.
var roster = map[string][]Role{
	"http":    {RoleEdge},
	"tcp":     {RoleEdge},
	"udp":     {RoleEdge},
	"forward": {RoleEdge},
	"dns":     {RoleEdge},

	"ssh":    {RoleGate},
	"telnet": {RoleGate},
	"vnc":    {RoleGate},
	"rdp":    {RoleGate},

	"smtp":     {RoleRelay},
	"ftp":      {RoleRelay},
	"ldap":     {RoleRelay},
	"postgres": {RoleRelay},
	"mysql":    {RoleRelay},
	"tds":      {RoleRelay},
	"redis":    {RoleRelay},
	"amqp":     {RoleRelay},

	// The plant's own protocols. Nothing else serves these: a Modbus
	// listener is xot's wherever it is written.
	"modbus": {RoleOT},
	"iec104": {RoleOT},
	"s7":     {RoleOT},
	"mms":    {RoleOT},
	"bacnet": {RoleOT},
	"opcua":  {RoleOT},
	"coap":   {RoleOT},

	// Served by both, because both estates run them. The relay owns them
	// by default, so a configuration written before xot existed means
	// what it meant; a plant's own puts `daemon: xot` on the listener.
	"syslog": {RoleRelay, RoleOT},
	"snmp":   {RoleRelay, RoleOT},
	"tftp":   {RoleRelay, RoleOT},
	"dhcp":   {RoleRelay, RoleOT},
	"dhcp6":  {RoleRelay, RoleOT},
	"ntp":    {RoleRelay, RoleOT},
	"ntske":  {RoleRelay, RoleOT},
	// MQTT is here for Sparkplug B: a plant's telemetry, and one of the
	// richest sources the device inventory has. The broker front end an
	// enterprise runs is xrelay's, which is why xrelay keeps the default.
	"mqtt": {RoleRelay, RoleOT},
	// The two authentication protocols the network equipment speaks. They
	// are shared for the same reason syslog and TFTP are: a plant's
	// switches, routers and firewalls authenticate their administrators
	// against RADIUS and TACACS+ exactly as a data centre's do, and on a
	// TACACS+ listener the engineering grants and the work orders the
	// configuration commands are checked against live on xot.
	"radius": {RoleRelay, RoleOT},
	"tacacs": {RoleRelay, RoleOT},
	// The Kerberos KDC proxy is the edge's by default: MS-KKDCP exists so
	// that a client outside the network can reach a KDC inside it, so the
	// deployment it was designed for is an internet-facing HTTPS endpoint,
	// which is xproxy's job description. An estate that runs one inside its
	// own network, in front of its domain controllers, puts `daemon: xrelay`
	// on the listener.
	"kkdcp": {RoleEdge, RoleRelay},
}

// authorises is every kind that consults the estate's authorisation policy
// (the `authorization` section, internal/authorization).
//
// It is here, beside the roster, for the reason the roster is static: a daemon
// has to be able to say "that kind does not consult the policy" about a kind it
// does not itself serve, because it validates configurations that name one. And
// it is a list of what *does* consult it rather than of what does not, so a kind
// added tomorrow is outside the policy until somebody says otherwise -- which a
// configuration with an authorization section then refuses to load, naming the
// listener, rather than quietly leaving a hole in a policy an operator believes
// covers everything.
var authorises = map[string]bool{
	"http":     true,
	"ssh":      true,
	"telnet":   true,
	"vnc":      true,
	"rdp":      true,
	"ftp":      true,
	"forward":  true,
	"postgres": true,
	"mysql":    true,
	"tds":      true,
	"mqtt":     true,
	"ldap":     true,
	"tcp":      true,
	"udp":      true,
	"modbus":   true,
	"iec104":   true,
	"s7":       true,
	"snmp":     true,
	"tftp":     true,
	"dhcp":     true,
	"dhcp6":    true,
	"coap":     true,
	"opcua":    true,
	"mms":      true,
	"bacnet":   true,
	"ntske":    true,
	"syslog":   true,
	"dns":      true,
	"smtp":     true,
	"redis":    true,
	"amqp":     true,
	"ntp":      true,
	"radius":   true,
	"tacacs":   true,
	"kkdcp":    true,
}

// Authorises reports whether a kind consults the estate's authorisation policy.
func Authorises(kind string) bool { return authorises[kind] }

// AuthorisingKinds are the kinds that consult it, sorted, for a message that
// has to say which ones do.
func AuthorisingKinds() []string {
	out := make([]string, 0, len(authorises))
	for k := range authorises {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RoleOf returns the daemon a listener of this kind belongs to when it
// does not say otherwise, and whether the kind is one this project
// implements at all.
func RoleOf(kind string) (Role, bool) {
	rs, ok := roster[kind]
	if !ok || len(rs) == 0 {
		return "", false
	}
	return rs[0], true
}

// ServedBy are the daemons that carry a kind's code, in the order they
// are worth naming: the one that owns it by default first.
func ServedBy(kind string) []Role {
	rs := roster[kind]
	out := make([]Role, len(rs))
	copy(out, rs)
	return out
}

// Shared reports whether more than one daemon serves a kind, which is
// the case where a listener may name the one it belongs to.
func Shared(kind string) bool { return len(roster[kind]) > 1 }

// RoleByDaemon reads a role from the program name an operator writes.
func RoleByDaemon(daemon string) (Role, bool) {
	for _, r := range Roles() {
		if r.Daemon() == daemon {
			return r, true
		}
	}
	return "", false
}

// Daemons are the programs that serve a kind, by name, for a message
// that has to say where a listener can be run.
func Daemons(kind string) []string {
	rs := roster[kind]
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Daemon())
	}
	return out
}

// Owner is the one daemon that binds a listener: the one it names, or
// the kind's default. It reports false for a kind nobody serves and for
// a listener naming a daemon that does not carry that kind's code --
// both of which validation refuses, naming the kind.
//
// There is exactly one owner per listener, and that is the point of the
// field rather than a consequence of it: a shared estate configuration
// is read by every daemon, so two of them treating one listener as
// theirs would race for the port and one would fail to start.
func Owner(kind, daemon string) (Role, bool) {
	if daemon == "" {
		return RoleOf(kind)
	}
	r, ok := RoleByDaemon(daemon)
	if !ok || !r.Serves(kind) {
		return "", false
	}
	return r, true
}

// Owns reports whether this daemon is the one that binds a listener.
func (r Role) Owns(kind, daemon string) bool {
	o, ok := Owner(kind, daemon)
	return ok && o == r
}

// Kinds are every kind name, sorted. Configuration validation uses it
// so that the list of what a "kind:" may say is written once.
func Kinds() []string {
	out := make([]string, 0, len(roster))
	for k := range roster {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// KindsFor are the kinds one role serves, sorted. It is what a daemon's
// own test compares its linked kinds against, so a kind served by two
// daemons appears in both lists.
func KindsFor(r Role) []string {
	out := make([]string, 0, len(roster))
	for k, rs := range roster {
		for _, kr := range rs {
			if kr == r {
				out = append(out, k)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// OwnedBy are the kinds a role owns by default, sorted: what it serves
// minus what another daemon takes unless a listener says otherwise.
func OwnedBy(r Role) []string {
	out := make([]string, 0, len(roster))
	for k, rs := range roster {
		if len(rs) > 0 && rs[0] == r {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Roles are the roles, in the order they are worth listing: the edge
// faces the internet, the gate faces people, the relay faces services
// and the OT daemon faces the plant.
func Roles() []Role { return []Role{RoleEdge, RoleGate, RoleRelay, RoleOT} }

// Serves reports whether a role carries a kind's code. A kind the roster
// does not know belongs to no role, and is refused by validation long
// before this is asked.
func (r Role) Serves(kind string) bool {
	for _, kr := range roster[kind] {
		if kr == r {
			return true
		}
	}
	return false
}
