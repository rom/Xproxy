package tds

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: tds listener is a relay in front of a Microsoft SQL Server.
//
// It is a relay kind for the same reasons the postgres and mysql ones are, and
// its handshake is the third cleartext encryption negotiation in a row: one
// octet in a PRELOGIN option table, answered by the server, signed by nothing.
// It gets the same answer as the other two -- the relay negotiates with each side
// itself rather than forwarding what it read -- and on this protocol the stakes
// are higher, because a TDS password is XOR 0xa5 with the nibbles swapped and a
// login that crosses in the clear has disclosed a reusable credential.
//
// The one structural oddity is where the TLS handshake lives: inside TDS packets
// until it completes, and then outside them. See tunnel.go.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "tds",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.TDS == nil {
				return nil, fmt.Errorf("listener %s: the tds section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
