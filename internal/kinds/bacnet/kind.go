package bacnet

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: bacnet listener is a BACnet/IP relay on UDP 47808 that reads
// what it forwards: every request from a client network, and every answer
// from the building.
//
// It is a datagram kind and only a datagram kind. Annex J defines BACnet/IP
// over UDP and nothing else; there is BACnet over MS/TP, over ARCNET and
// over Ethernet, but none of those reaches an IP listener, and there is no
// transport security anywhere in the protocol -- so a listener holding a TCP
// port would hold a port nothing speaks on, and one carrying a certificate
// would be promising something the protocol cannot do.
func init() {
	proxy.Register(proxy.Kind{
		Name:     "bacnet",
		Datagram: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.BACnet == nil {
				return nil, fmt.Errorf("listener %s: the bacnet section is required", su.Config.Name)
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
