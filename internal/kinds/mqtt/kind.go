package mqtt

import (
	"context"

	"github.com/rom/xproxy/internal/proxy"
)

// MQTT has no in-band upgrade, so implicit TLS is the only mode. The
// session still owns the handshake rather than the socket being wrapped
// in a TLS listener, which keeps the handshake's deadline and its
// logging with the rest of the session.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "mqtt",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
