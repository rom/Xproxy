package s7

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: s7 listener is a relay in front of a Siemens PLC.
//
// It is the listener for the protocol with the least security of any in this
// project. S7comm has no transport security, and its optional password
// protects a handful of functions on some CPU families and nothing on others:
// an S7-300 with no password accepts a stop from anybody who can open a socket
// to TCP 102. The equipment cannot be fixed -- a controller in a line is
// replaced on a capital cycle, not a release cycle -- so the boundary has to
// be somewhere else, and this is somewhere else.
//
// The listener takes no TLS section, because the protocol has none to
// negotiate and a certificate here would promise something it cannot do.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "s7",
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.S7 == nil {
				return nil, fmt.Errorf("listener %s: the s7 section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
