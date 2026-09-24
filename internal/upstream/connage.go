package upstream

import (
	"net"
	"sync/atomic"
	"time"
)

// Max connection age: a bound on how long one upstream connection is
// kept, so that a pool's traffic follows its endpoints instead of
// sticking to whichever ones were there when the connections were made.
// A keep-alive connection can outlive a deploy, a scale-out and an
// endpoint's whole useful life, and every request on it goes where that
// connection goes.
//
// The difficulty is that a connection cannot simply be closed at its
// age: closing one mid-exchange cuts a request that has done nothing
// wrong, and from inside a net.Conn there is no way to tell an exchange
// in progress from an idle connection -- both are a blocked Read.
//
// So the age is not enforced by closing. It marks the connection, and
// the layer that does know where an exchange ends -- the round trip,
// which owns the response body -- closes it once that exchange is over.
// The result is exactly what is wanted: the connection is not reused
// past its age, and nothing in flight is disturbed.
//
// This works for HTTP/1.1, where a connection carries one exchange at a
// time. An HTTP/2 or HTTP/3 connection carries many streams at once, so
// there is no point at which it is "between exchanges", and the bound
// does not apply there; validation says so rather than leaving an
// operator to wonder.
type agedConn struct {
	net.Conn
	born   time.Time
	age    time.Duration
	doomed atomic.Bool
}

// Aged reports whether the connection has outlived the bound.
func (c *agedConn) Aged(now time.Time) bool {
	return c.age > 0 && now.Sub(c.born) >= c.age
}

// Doom marks the connection to be closed at the end of the exchange
// running on it, and reports whether this call was the one that marked
// it -- so a counter is raised once per connection rather than once per
// request that noticed.
func (c *agedConn) Doom() bool { return c.doomed.CompareAndSwap(false, true) }

// Retire closes a connection if it is one of ours and has outlived the
// bound, and reports whether this call retired it. The caller holds it
// until an exchange has finished, which is what makes this safe.
func (p *Pool) Retire(conn net.Conn) bool {
	ac, ok := conn.(*agedConn)
	if !ok || !ac.Aged(p.now()) || !ac.Doom() {
		return false
	}
	_ = ac.Close()
	p.Retired.Add(1)
	return true
}

// AgedOut reports whether a connection has outlived the pool's bound,
// without retiring it.
func (p *Pool) AgedOut(conn net.Conn) bool {
	ac, ok := conn.(*agedConn)
	return ok && ac.Aged(p.now())
}
