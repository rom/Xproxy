package radius

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: radius listener is a RADIUS relay on UDP 1812 and 1813 that
// reads and verifies what it forwards: every request from the network
// equipment, and every answer from the server.
//
// It is a datagram kind and only a datagram kind. RADIUS is UDP, and the
// one standard that puts it on a stream -- RadSec, RFC 6614, inside TLS on
// TCP 2083 -- is a different transport with a different port and a
// different trust model, not a flag on this one. So a listener here that
// bound a TCP port would hold a port nothing speaks on, and one carrying a
// certificate would be promising something the protocol cannot do.
//
// What it does that a packet filter cannot: it holds the shared secret, so
// every packet's integrity is checked before anything is forwarded. That is
// what makes the rest of the policy worth writing -- a relay that filtered
// on attributes it could not authenticate would be filtering on whatever
// the last host on the path chose to put there.
func init() {
	proxy.Register(proxy.Kind{
		Name:     "radius",
		Datagram: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.RADIUS == nil {
				return nil, fmt.Errorf("listener %s: the radius section is required", su.Config.Name)
			}
			pc, err := su.Packet("")
			if err != nil {
				return nil, err
			}
			s, err := newServer(su.Host, su.Config, pc)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			return s, nil
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
