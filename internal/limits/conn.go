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

// Admit applies the ban check and the connection limits to a new
// connection from addr. On success it returns a release function that
// must be called exactly once when the connection ends; on refusal the
// reason is returned and the rejection is counted and reported.
func (c *ConnLimiter) Admit(addr netip.Addr) (release func(), reason string) {
	if c.Banned != nil && c.Banned(addr) {
		c.reject(addr, "banned")
		return nil, "banned"
	}
	ok, reason := c.acquire(addr)
	if !ok {
		c.reject(addr, reason)
		return nil, reason
	}
	var once sync.Once
	return func() { once.Do(func() { c.release(addr) }) }, ""
}

func (c *ConnLimiter) reject(addr netip.Addr, reason string) {
	c.Rejected.Add(1)
	if c.OnReject != nil {
		c.OnReject(addr, reason)
	}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		release, _ := l.lim.Admit(addrOf(conn))
		if release == nil {
			_ = conn.Close()
			continue
		}
		return &limitedConn{Conn: conn, release: release}, nil
	}
}

type limitedConn struct {
	net.Conn
	release func()
}

func (c *limitedConn) Close() error {
	c.release()
	return c.Conn.Close()
}
