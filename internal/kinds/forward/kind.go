package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
)

// A forward listener is an explicit proxy for clients that ask it to
// reach somewhere: HTTP CONNECT and absolute-URI requests, SOCKS5 on
// the same port, MASQUE (CONNECT-UDP and CONNECT-IP) over extended
// CONNECT, and optional TLS interception of what it tunnels.
//
// It is an egress control rather than an ingress one. What it decides
// is where a client inside the estate may go, which is a different
// question from what a client outside may ask for, and the reason it is
// a kind of its own rather than a mode of the reverse proxy.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "forward",
		TLS:         true,
		ProxyHeader: true,
		New:         build,
	})
}

func build(su *proxy.Setup) (proxy.Instance, error) {
	lc := su.Config
	f, err := newForwardServer(su.Host, lc)
	if err != nil {
		return nil, err
	}
	ln := su.Net
	if f.socksEnabled() {
		// SOCKS greetings are taken off the accept path before the HTTP
		// server sees them; everything else is handed on.
		ln = &socksListener{Listener: ln, f: f}
	}
	lim := su.Host.Limits()
	srv := &http.Server{
		Handler:           f,
		ReadHeaderTimeout: lim.ReadHeaderTimeout.D(),
		ReadTimeout:       lim.ReadTimeout.D(),
		WriteTimeout:      lim.WriteTimeout.D(),
		IdleTimeout:       lim.IdleTimeout.D(),
		MaxHeaderBytes:    lim.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(su.Host.Logs().Error.Handler(), slog.LevelDebug),
		// Protocol choice stays with TLS ALPN: no automatic h2c.
		TLSNextProto: nil,
	}
	if su.TLS != nil {
		srv.TLSConfig = su.TLS
		ln = tls.NewListener(ln, su.TLS)
	}
	return &instance{f: f, srv: srv, ln: ln}, nil
}

// instance is one forward listener: the policy engine and the HTTP
// server that feeds it.
type instance struct {
	f   *forwardServer
	srv *http.Server
	ln  net.Listener
}

// Serve implements proxy.Instance.
func (i *instance) Serve() {
	if err := serveError(i.srv.Serve(i.ln)); err != nil {
		i.f.host.Logs().Error.Error("forward listener stopped", "listener", i.f.name, "err", err.Error())
	}
}

// serveError is the error Serve should report, or nil for the two ways
// a listener ends on purpose. A stop closes the front before the HTTP
// server is shut down, so whether Serve sees net.ErrClosed from the
// accept or http.ErrServerClosed from the shutdown is a race between
// two goroutines; neither is a failure, and an operator who sees ERROR
// on every reload stops reading the log.
func serveError(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Shutdown implements proxy.Instance: the HTTP server drains, then the
// tunnels it opened are closed.
func (i *instance) Shutdown(ctx context.Context) {
	_ = i.srv.Shutdown(ctx)
	i.f.shutdown(ctx)
}

// Apply implements proxy.Applier: a reload replaces the destination
// policy, the credentials and the bounds where they stand. What it does
// not replace is MASQUE or interception, which hold a tunnel device and
// a signing key: turning those on or off is a listener change.
func (i *instance) Apply(lc config.Listener) error {
	if lc.Forward == nil {
		return nil
	}
	return i.f.apply(lc.Forward)
}

// MasqueStatus implements proxy.MasqueReporter, which is how the
// management view reaches a forward listener without the engine
// importing this package.
func (i *instance) MasqueStatus() *proxy.MasqueStatus {
	m := i.f.masque
	if m == nil {
		return nil
	}
	return &proxy.MasqueStatus{
		UDP: m.udp, IP: m.ip,
		Sessions: m.sessions.Load(), MaxSessions: m.maxSessions,
		UDPTotal: m.udpTotal.Load(), IPTotal: m.ipTotal.Load(),
		Refused: m.refused.Load(), Device: i.f.masqueDeviceName(),
	}
}
