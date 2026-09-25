package mysql

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: mysql listener is a relay in front of a MySQL or MariaDB server.
//
// It is a relay kind for the same reasons the postgres one is, and its handshake
// runs the other way round: the *server* speaks first, advertising its
// capabilities, and the client answers. That order is what makes this kind's
// distinctive move possible -- the relay reads the greeting, clears the
// capability bits the policy denies, and forwards the edited one, so the client
// negotiates against a narrower server than the real one and the application
// still works.
//
// TLS is a capability flag rather than a port or a separate request, so this kind
// terminates the upgrade on both legs independently: the client's TLS ends here
// and the relay starts its own to the server, which is the only way a relay that
// reads the protocol can exist at all.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "mysql",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.MySQL == nil {
				return nil, fmt.Errorf("listener %s: the mysql section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
