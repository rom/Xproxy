// Package h3 serves HTTP/3 over QUIC for a TLS listener (docs/AMR.md,
// AMR-002 and AMR-024). It is the only package that imports quic-go.
//
// Hardening choices:
//
//   - Every new connection passes through the same admission as TCP
//     (ban list, global and per-address connection limits) via
//     Transport.ConnContext; the release runs when the connection's
//     context ends.
//   - Source address validation (Retry) is required for unvalidated
//     addresses by default, so a spoofed Initial costs the sender a round
//     trip before the server allocates connection state.
//   - 0-RTT is disabled (replayable requests are not worth the risk for a
//     proxy in front of arbitrary applications).
//   - Streams per connection, header size and idle timeouts are bounded
//     from the listener limits.
package h3

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
)

// Options configures a server.
type Options struct {
	// Conn is the UDP socket to serve on (socket activated or freshly bound).
	Conn net.PacketConn
	// Port is advertised in Alt-Svc.
	Port int
	// TLS is the listener's server configuration; it is cloned and given
	// the h3 ALPN.
	TLS     *tls.Config
	Handler http.Handler
	Limits  config.Limits
	H3      config.H3
	Limiter *limits.ConnLimiter
	Log     *slog.Logger
}

// Server is one HTTP/3 endpoint.
type Server struct {
	tr   *quic.Transport
	ln   *quic.EarlyListener
	srv  *http3.Server
	log  *slog.Logger
	conn net.PacketConn
}

// New prepares a server. Serve starts it.
func New(o Options) (*Server, error) {
	if o.Conn == nil || o.TLS == nil || o.Handler == nil || o.Limiter == nil {
		return nil, errors.New("h3: incomplete options")
	}
	var resetKey quic.StatelessResetKey
	if _, err := rand.Read(resetKey[:]); err != nil {
		return nil, err
	}
	lim := o.Limiter
	maxConns := int64(o.Limits.MaxConnections)
	always := o.H3.ValidateAddresses != "under_load"
	tr := &quic.Transport{
		Conn:              o.Conn,
		StatelessResetKey: &resetKey,
		VerifySourceAddress: func(net.Addr) bool {
			return always || lim.Open()*4 > maxConns
		},
		ConnContext: func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
			addr := addrOf(info.RemoteAddr)
			release, reason := lim.Admit(addr)
			if release == nil {
				return ctx, fmt.Errorf("refused: %s", reason)
			}
			context.AfterFunc(ctx, release)
			return ctx, nil
		},
	}
	qc := &quic.Config{
		HandshakeIdleTimeout:  o.Limits.ReadHeaderTimeout.D(),
		MaxIdleTimeout:        o.Limits.IdleTimeout.D(),
		MaxIncomingStreams:    int64(o.H3.MaxStreams),
		MaxIncomingUniStreams: 16,
		Allow0RTT:             false,
		KeepAlivePeriod:       0,
	}
	tc := http3.ConfigureTLSConfig(o.TLS.Clone())
	tc.NextProtos = []string{http3.NextProtoH3}
	ln, err := tr.ListenEarly(tc, qc)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("h3 listen: %w", err)
	}
	srv := &http3.Server{
		Port:           o.Port,
		Handler:        o.Handler,
		QUICConfig:     qc,
		MaxHeaderBytes: o.Limits.MaxHeaderBytes,
		IdleTimeout:    o.Limits.IdleTimeout.D(),
		Logger:         o.Log,
	}
	return &Server{tr: tr, ln: ln, srv: srv, log: o.Log, conn: o.Conn}, nil
}

func addrOf(a net.Addr) netip.Addr {
	if ua, ok := a.(*net.UDPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ua.IP); ok {
			return ip.Unmap()
		}
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

// Serve blocks serving connections until Shutdown or Close.
func (s *Server) Serve() error {
	err := s.srv.ServeListener(s.ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed) {
		return nil
	}
	return err
}

// Addr returns the UDP address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// SetAltSvc adds the Alt-Svc header advertising this endpoint.
func (s *Server) SetAltSvc(h http.Header) {
	_ = s.srv.SetQUICHeaders(h)
}

// Shutdown drains gracefully within ctx, then closes the socket.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.srv.Shutdown(ctx)
	_ = s.ln.Close()
	_ = s.tr.Close()
	return err
}

// SocketBufferAdvice returns a note for operators when the UDP receive
// buffer is small; quic-go logs the same condition.
func SocketBufferAdvice() string {
	return "set net.core.rmem_max and wmem_max to at least 7340032 (see deploy/sysctl)"
}
