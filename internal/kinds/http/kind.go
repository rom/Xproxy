package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/h3"
	"github.com/rom/xproxy/internal/proxy"
)

func init() {
	proxy.Register(proxy.Kind{
		Name: "http", TLS: true, ProxyHeader: true,
		New: newListener,
	})
}

// instance is one http listener: the HTTP/1.1 and HTTP/2 server on the
// accept socket the engine bound, and, where the listener asked for it,
// an HTTP/3 endpoint on the same port over UDP. Both answer the same
// handler, so a route behaves the same whichever protocol carried it.
type instance struct {
	cfg  config.Listener
	srv  *http.Server
	ln   net.Listener
	tls  bool
	h3   *h3.Server
	logs *slog.Logger
}

func newListener(su *proxy.Setup) (proxy.Instance, error) {
	e, _ := su.Plane.(*engine)
	if e == nil {
		// Unreachable through the engine, which builds the plane from
		// this package's own constructor before it binds a listener; a
		// test host that skipped that gets an answer rather than a nil
		// dereference.
		return nil, errors.New("no http data plane in this process")
	}
	lc := su.Config
	lim := su.Host.Limits()
	in := &instance{cfg: lc, ln: su.Net, tls: su.TLS != nil, logs: su.Host.Logs().Error}
	// The handler reads the listener's own section; in.cfg is a copy,
	// but its tls pointer is the one the engine reloads certificates
	// through, so a reload is visible here without rebinding.
	h := &listenerHandler{srv: e, ln: &in.cfg}
	in.srv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: lim.ReadHeaderTimeout.D(),
		ReadTimeout:       lim.ReadTimeout.D(),
		WriteTimeout:      lim.WriteTimeout.D(),
		IdleTimeout:       lim.IdleTimeout.D(),
		MaxHeaderBytes:    lim.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(su.Host.Logs().Error.Handler(), slog.LevelDebug),
		// Disable automatic h2c and keep protocol choice to TLS ALPN.
		TLSNextProto: nil,
	}
	if lc.H2C {
		// HTTP/2 without TLS (prior knowledge and Upgrade) with the
		// stream and frame bounds of the TLS listeners.
		in.srv.Protocols = new(http.Protocols)
		in.srv.Protocols.SetHTTP1(true)
		in.srv.Protocols.SetUnencryptedHTTP2(true)
		in.srv.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 250, MaxReadFrameSize: 1 << 20}
	}
	if su.TLS == nil {
		return in, nil
	}
	fps := su.Host.Fingerprints()
	in.srv.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateClosed || st == http.StateHijacked {
			fps.Delete(c.RemoteAddr().String())
		}
	}
	in.srv.TLSConfig = su.TLS
	if !hasProto(lc.Protocols, config.ProtocolH2) {
		// Prevent the automatic HTTP/2 configuration.
		in.srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	if !hasProto(lc.Protocols, config.ProtocolH3) {
		return in, nil
	}
	pc, err := su.Packet("")
	if err != nil {
		return nil, fmt.Errorf("h3: %w", err)
	}
	_, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	port, _ := strconv.Atoi(portStr)
	h3srv, err := h3.New(h3.Options{
		Conn: pc, Port: port, TLS: su.TLS, Handler: h, Limits: lim, H3: *lc.H3, WebTransport: lc.H3.WebTransport,
		Limiter: su.Host.ConnLimiter(), Log: su.Host.Logs().Error.With("listener", lc.Name, "proto", "h3"),
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	in.h3 = h3srv
	h.h3 = h3srv
	su.Host.Logs().Error.Info("h3 listener bound", "listener", lc.Name, "address", pc.LocalAddr().String())
	return in, nil
}

func hasProto(ps []config.Protocol, p config.Protocol) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

// Serve accepts until the socket closes, on both transports.
func (in *instance) Serve() {
	if in.h3 != nil {
		go func() {
			if err := in.h3.Serve(); err != nil {
				in.logs.Error("h3 listener stopped", "listener", in.cfg.Name, "err", err.Error())
			}
		}()
	}
	var err error
	if in.tls {
		err = in.srv.ServeTLS(in.ln, "", "")
	} else {
		err = in.srv.Serve(in.ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		in.logs.Error("listener stopped", "listener", in.cfg.Name, "err", err.Error())
	}
}

// Shutdown drains what is in flight on both transports.
func (in *instance) Shutdown(ctx context.Context) {
	if err := in.srv.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		in.logs.Warn("listener shutdown", "listener", in.cfg.Name, "err", err.Error())
	}
	if in.h3 != nil {
		if err := in.h3.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			in.logs.Warn("h3 shutdown", "listener", in.cfg.Name, "err", err.Error())
		}
	}
}

// Addrs adds the HTTP/3 endpoint to the address view: it is a second
// socket on the same port, and a test that asked for port 0 has no
// other way to find it.
func (in *instance) Addrs() map[string]string {
	if in.h3 == nil {
		return nil
	}
	return map[string]string{"udp": in.h3.Addr().String()}
}
