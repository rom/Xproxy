package ntske

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: ntske listener is NTS key establishment on TCP 4460: TLS with
// the ALPN "ntske/1", relayed to the key establishment servers whose keys
// it is.
//
// It is a separate listener from kind: ntp because it is a separate port,
// a separate transport and a separate security property. A deployment
// that wants NTS runs both, and having to write both down is the point:
// an estate with a time listener and no key establishment listener has
// clients that cannot get cookies, and it is better to see that in the
// configuration than to find it in the logs.
func init() {
	proxy.Register(proxy.Kind{
		Name: "ntske",
		// The terminating side is the key establishment server, so it
		// needs the listener's certificate. The relaying side never
		// terminates a handshake and is handed nil, which is what a
		// listener with no tls section gets anyway.
		TLS:         true,
		ProxyHeader: false,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.NTSKE == nil {
				return nil, fmt.Errorf("listener %s: the ntske section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (s *server) Serve() { s.serve() }

// Shutdown implements proxy.Instance.
func (s *server) Shutdown(ctx context.Context) { s.shutdown(ctx) }
