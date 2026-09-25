package redis

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: redis listener is a relay in front of a Redis or Valkey server.
//
// It is the simplest protocol in the project and the one where a relay earns its
// place fastest, because Redis's own default is no password: an instance that is
// reachable is an instance that is administrable, and `CONFIG SET dir` plus
// `CONFIG SET dbfilename` plus `SAVE` writes a file wherever the server can write.
// A relay in front of it can require authentication the server does not, refuse the
// commands that lead out of the database, and hold a key boundary the server has no
// concept of.
//
// There is no handshake to read and no encryption to negotiate: TLS is either on
// for the port or it is not, which is why this kind has no equivalent of the
// PRELOGIN or SSLRequest dance the three SQL kinds spend most of their handshake
// code on.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "redis",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.Redis == nil {
				return nil, fmt.Errorf("listener %s: the redis section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
