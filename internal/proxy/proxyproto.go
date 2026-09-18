package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/netutil"
)

// proxyHeaderTimeout bounds how long a peer may take to send the header.
const proxyHeaderTimeout = 5 * time.Second

// rekeyer is what the connection limiter's connections implement so the
// per address count can move from the balancer to the real client.
type rekeyer interface {
	Rekey(to netip.Addr) bool
}

// proxyListener accepts connections that start with a PROXY protocol
// header from trusted peers. Parsing is lazy (on the first Read or
// RemoteAddr call, which the HTTP server makes in the connection's own
// goroutine), so the accept loop never waits on a peer.
type proxyListener struct {
	net.Listener
	trusted  func() []netip.Prefix
	onReject func(peer netip.Addr, reason string)
}

func (l *proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &proxyConn{Conn: c, br: bufio.NewReaderSize(c, 4096), l: l}, nil
}

type proxyConn struct {
	net.Conn
	br   *bufio.Reader
	l    *proxyListener
	once sync.Once
	src  net.Addr
	dst  net.Addr
	err  error
}

// parse reads the header once. An untrusted peer's connection is left
// untouched; a trusted peer must send a header or the connection fails.
func (c *proxyConn) parse() {
	c.once.Do(func() {
		peer := addrOf(c.Conn.RemoteAddr().String())
		if !netutil.Contains(c.l.trusted(), peer) {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
		h, err := netutil.ReadProxyHeader(c.br)
		_ = c.SetReadDeadline(time.Time{})
		if err != nil {
			c.err = err
			if c.l.onReject != nil {
				c.l.onReject(peer, "proxy_protocol")
			}
			return
		}
		if h.Local || !h.Src.IsValid() {
			return
		}
		c.src = net.TCPAddrFromAddrPort(h.Src)
		if h.Dst.IsValid() {
			c.dst = net.TCPAddrFromAddrPort(h.Dst)
		}
		if rk, ok := c.Conn.(rekeyer); ok && !rk.Rekey(h.Src.Addr()) {
			c.err = errors.New("connection limit for the client address")
			if c.l.onReject != nil {
				c.l.onReject(h.Src.Addr(), "per_ip_limit")
			}
		}
	})
}

// Read returns io.EOF after a rejected header so that the HTTP server
// closes the connection silently instead of answering the peer with a 400
// (net/http treats EOF as a common read error).
func (c *proxyConn) Read(b []byte) (int, error) {
	c.parse()
	if c.err != nil {
		_ = c.Close()
		return 0, io.EOF
	}
	return c.br.Read(b)
}

func (c *proxyConn) RemoteAddr() net.Addr {
	c.parse()
	if c.src != nil {
		return c.src
	}
	return c.Conn.RemoteAddr()
}

func (c *proxyConn) LocalAddr() net.Addr {
	c.parse()
	if c.dst != nil {
		return c.dst
	}
	return c.Conn.LocalAddr()
}
