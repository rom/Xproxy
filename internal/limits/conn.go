package limits

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// ConnLimiter enforces a global and a per-IP bound on open connections. It
// wraps a net.Listener so that excess connections are closed immediately
// after accept, before any bytes are read or any goroutine is dedicated to
// them beyond the accept loop.
type ConnLimiter struct {
	max      atomic.Int64
	maxPerIP atomic.Int64
	total    atomic.Int64
	mu       sync.Mutex
	perIP    map[netip.Addr]int
	// Rejected counts connections closed by the limiter.
	Rejected atomic.Uint64
	// OnReject is called with the peer address of every rejected
	// connection (for security logging). May be nil.
	OnReject func(addr netip.Addr, reason string)
	// Banned, when set, is consulted for every accepted connection; a true
	// result closes it immediately with reason "banned".
	Banned func(addr netip.Addr) bool
}

// NewConnLimiter creates a limiter with the given bounds.
func NewConnLimiter(max, maxPerIP int) *ConnLimiter {
	c := &ConnLimiter{perIP: make(map[netip.Addr]int)}
	c.SetLimits(max, maxPerIP)
	return c
}

// SetLimits changes the bounds at runtime (used by reload). Existing
// connections are never closed by a lower bound; new ones are refused.
func (c *ConnLimiter) SetLimits(max, maxPerIP int) {
	c.max.Store(int64(max))
	c.maxPerIP.Store(int64(maxPerIP))
}

// Open returns the number of open connections.
func (c *ConnLimiter) Open() int64 { return c.total.Load() }

// Wrap returns a listener whose Accept enforces the limits.
func (c *ConnLimiter) Wrap(l net.Listener) net.Listener {
	return &limitedListener{Listener: l, lim: c}
}

func addrOf(conn net.Conn) netip.Addr {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(ta.IP); ok {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}

// acquire registers a connection. It returns false if a limit is exceeded.
func (c *ConnLimiter) acquire(addr netip.Addr) (ok bool, reason string) {
	if c.total.Add(1) > c.max.Load() {
		c.total.Add(-1)
		return false, "max_connections"
	}
	c.mu.Lock()
	n := c.perIP[addr]
	if int64(n) >= c.maxPerIP.Load() {
		c.mu.Unlock()
		c.total.Add(-1)
		return false, "max_connections_per_ip"
	}
	c.perIP[addr] = n + 1
	c.mu.Unlock()
	return true, ""
}

func (c *ConnLimiter) release(addr netip.Addr) {
	c.mu.Lock()
	if n := c.perIP[addr]; n <= 1 {
		delete(c.perIP, addr)
	} else {
		c.perIP[addr] = n - 1
	}
	c.mu.Unlock()
	c.total.Add(-1)
}

type limitedListener struct {
	net.Listener
	lim *ConnLimiter
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		addr := addrOf(conn)
		if l.lim.Banned != nil && l.lim.Banned(addr) {
			l.lim.Rejected.Add(1)
			if l.lim.OnReject != nil {
				l.lim.OnReject(addr, "banned")
			}
			_ = conn.Close()
			continue
		}
		ok, reason := l.lim.acquire(addr)
		if !ok {
			l.lim.Rejected.Add(1)
			if l.lim.OnReject != nil {
				l.lim.OnReject(addr, reason)
			}
			_ = conn.Close()
			continue
		}
		return &limitedConn{Conn: conn, lim: l.lim, addr: addr}, nil
	}
}

type limitedConn struct {
	net.Conn
	lim  *ConnLimiter
	addr netip.Addr
	once sync.Once
}

func (c *limitedConn) Close() error {
	c.once.Do(func() { c.lim.release(c.addr) })
	return c.Conn.Close()
}
