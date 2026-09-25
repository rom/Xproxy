package postgres

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: postgres listener is a relay in front of a PostgreSQL server.
//
// It is registered as a relay kind because that is what it is: machine to
// machine, no people at a terminal, no recordings. Its policy is written in the
// protocol's own terms -- who may claim which role and database, which
// authentication methods may cross, which *shapes* of statement are allowed, and
// whether the connection may be in the clear at all.
//
// TLS is both shapes the protocol has, and neither is what TLS usually looks
// like. There is no separate port for an encrypted connection: a client connects
// in the clear and asks, in eight octets, whether it may upgrade. So this kind
// terminates that upgrade itself rather than forwarding the question -- the
// server's answer is precisely the octet an attacker on the path rewrites, and
// libpq's default sslmode carries on in the clear when it says no.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "postgres",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.Postgres == nil {
				return nil, fmt.Errorf("listener %s: the postgres section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
