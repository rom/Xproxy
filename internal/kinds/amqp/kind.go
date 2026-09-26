package amqp

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: amqp listener is a relay in front of a message broker.
//
// It is the only kind here that reads two protocols on one port, because AMQP
// is two protocols: a client picks 0-9-1 or 1.0 in its first eight octets and
// the framing of everything after it follows from that choice. Both are read,
// and one policy decides both.
//
// What makes a relay worth having in front of a broker is that a broker is
// where an estate's data is in transit. Everything that matters passes through
// it -- orders, payments, telemetry, the events that drive other services --
// and the broker's own permission model is a per-user, per-vhost matter
// administered inside the broker. A relay holds the same boundary in the
// estate's configuration, refuses the operations that change the broker
// rather than use it, and can say what a connection named.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "amqp",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.AMQP == nil {
				return nil, fmt.Errorf("listener %s: the amqp section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
