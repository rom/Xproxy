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
	// RoleRelay is xrelay: machine to machine and operational
	// technology. Syslog, SMTP, MQTT, FTP. No humans, no recordings,
	// and a policy written in the protocol's own terms.
	RoleRelay Role = "relay"
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
	}
	return string(r)
}

// roster is every kind and its owner.
var roster = map[string]Role{
	"http":    RoleEdge,
	"tcp":     RoleEdge,
	"udp":     RoleEdge,
	"forward": RoleEdge,
	"dns":     RoleEdge,
	"ssh":     RoleGate,
	"telnet":  RoleGate,
	"vnc":     RoleGate,
	"rdp":     RoleGate,
	"smtp":    RoleRelay,
	"mqtt":    RoleRelay,
	"ftp":     RoleRelay,
	"syslog":  RoleRelay,
}

// RoleOf returns the daemon that serves a kind, and whether the kind is
// one this project implements at all.
func RoleOf(kind string) (Role, bool) {
	r, ok := roster[kind]
	return r, ok
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

// KindsFor are the kinds one role serves, sorted.
func KindsFor(r Role) []string {
	out := make([]string, 0, len(roster))
	for k, kr := range roster {
		if kr == r {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Roles are the roles, in the order they are worth listing: the edge
// faces the internet, the gate faces people, the relay faces machines.
func Roles() []Role { return []Role{RoleEdge, RoleGate, RoleRelay} }

// Serves reports whether a role serves a kind. A kind the roster does
// not know belongs to no role, and is refused by validation long before
// this is asked.
func (r Role) Serves(kind string) bool {
	owner, ok := RoleOf(kind)
	return ok && owner == r
}
