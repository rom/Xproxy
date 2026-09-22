package smtp

import (
	"context"

	"github.com/rom/xproxy/internal/proxy"
)

// The socket is not wrapped in a TLS listener even for implicit mode:
// STARTTLS has to read cleartext first, so the session decides when the
// handshake happens and owns its deadline.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "smtp",
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
