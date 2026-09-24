package limits

import (
	"net"
	"net/netip"
	"sync/atomic"
)

// AcceptRate bounds how fast connections are accepted, which is the
// bound a concurrency limit does not give.
//
// max_connections says how many connections may be open at once. It says
// nothing about churn: a client that connects, makes the server do the
// expensive part of a handshake, and disconnects never holds two
// connections and can still cost a core. That is the shape of most
// attacks on an interactive service -- an SSH, RDP, VNC or telnet
// gateway pays for a key exchange or a TLS handshake before it knows who
// is calling -- and of the accidental kind too, where a restarting
// client fleet reconnects in lock-step.
//
// Two bounds, because they answer different attackers:
//
//   - A total rate protects the accept path itself, whatever the traffic
//     is spread across.
//   - A per source rate protects everyone else from one source. It is
//     keyed by a network rather than an address, because a single
//     attacker with a /64 of IPv6 has more addresses than the table
//     could ever hold, and an address bound would be no bound at all.
//     The defaults (a /32 for IPv4, a /64 for IPv6) are the smallest
//     block an operator is normally given.
//
// A refusal is a close immediately after accept, before any bytes are
// read: that is all a listener can do about a connection it has already
// been handed, and it is cheap.
type AcceptRate struct {
	total  *KeyedLimiter // keyed by "" -- one bucket for the listener
	source *KeyedLimiter
	v4, v6 int
	// Rejected counts connections this gate closed.
	Rejected atomic.Uint64
	// OnReject reports each refusal. May be nil.
	OnReject func(addr netip.Addr, reason string)
}

// The reasons a gate refuses, which are the reasons in the log and the
// ones a ban trigger can be written against.
const (
	ReasonRate       = "connection_rate"
	ReasonRateSource = "connection_rate_per_source"
)

// NewAcceptRate builds a gate. A zero rate leaves that half off, so a
// gate with both zero admits everything and callers need not special
// case it. maxKeys bounds the per source table.
func NewAcceptRate(totalPerSecond float64, totalBurst int, sourcePerSecond float64, sourceBurst, v4, v6, maxKeys int) *AcceptRate {
	a := &AcceptRate{v4: v4, v6: v6}
	if totalPerSecond > 0 {
		a.total = NewKeyedLimiter(totalPerSecond, totalBurst, 1)
	}
	if sourcePerSecond > 0 {
		a.source = NewKeyedLimiter(sourcePerSecond, sourceBurst, maxKeys)
	}
	return a
}

// Active reports whether the gate bounds anything.
func (a *AcceptRate) Active() bool { return a != nil && (a.total != nil || a.source != nil) }

// Allow decides one connection. The total bound is consulted first: a
// flood from one source should be refused by its own bound, and a flood
// spread across sources should not spend the table before the total
// bound stops it.
func (a *AcceptRate) Allow(addr netip.Addr) (ok bool, reason string) {
	if !a.Active() {
		return true, ""
	}
	if a.total != nil && !a.total.Allow("") {
		a.reject(addr, ReasonRate)
		return false, ReasonRate
	}
	if a.source != nil && !a.source.Allow(a.key(addr)) {
		a.reject(addr, ReasonRateSource)
		return false, ReasonRateSource
	}
	return true, ""
}

// key is the source's network, or the address itself when it is not one
// this gate can mask (which a Unix socket's peer is not).
func (a *AcceptRate) key(addr netip.Addr) string {
	if !addr.IsValid() {
		return "invalid"
	}
	bits := a.v6
	if addr.Is4() {
		bits = a.v4
	}
	if bits <= 0 {
		return addr.String()
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return addr.String()
	}
	return p.String()
}

func (a *AcceptRate) reject(addr netip.Addr, reason string) {
	a.Rejected.Add(1)
	if a.OnReject != nil {
		a.OnReject(addr, reason)
	}
}

// Wrap returns a listener whose Accept applies the gate, closing what it
// refuses without reading a byte.
func (a *AcceptRate) Wrap(l net.Listener) net.Listener {
	if !a.Active() {
		return l
	}
	return WrapRate(l, func() *AcceptRate { return a })
}

// WrapRate is Wrap with the gate looked up per connection, so a reload
// that replaces the process's gate applies to listeners that were not
// themselves rebuilt. The socket is never re-bound for a rate change.
func WrapRate(l net.Listener, gate func() *AcceptRate) net.Listener {
	return &ratedListener{Listener: l, gate: gate}
}

type ratedListener struct {
	net.Listener
	gate func() *AcceptRate
}

func (l *ratedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		g := l.gate()
		if !g.Active() {
			return conn, nil
		}
		if ok, _ := g.Allow(addrOf(conn)); !ok {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}
