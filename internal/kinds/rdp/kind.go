package rdp

import (
	"context"

	"github.com/rom/xproxy/internal/proxy"
)

// A Remote Desktop gateway. The socket is wrapped in TLS by this kind
// rather than by the engine, because RDP negotiates its transport
// security inside the protocol: the first exchange is in clear and
// says what follows it.
//
// RDP's whole policy surface is in that connection sequence -- which
// security protocol, which virtual channels exist, who is connecting
// and with what credential -- so a proxy that does not sit in it
// cannot decide any of it, nor record what follows. That is why this
// is a kind rather than a tcp listener.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "rdp",
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
