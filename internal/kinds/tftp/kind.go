package tftp

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: tftp listener is a TFTP relay on UDP 69: it reads every request,
// decides about it by the address it came from and the path it asked for, and
// bounds what comes back.
//
// It is a datagram kind and only a datagram kind. TFTP has no TCP transport,
// no TLS and no extension that adds either, so a listener that bound a stream
// port would be holding a port nothing can speak on -- and one carrying a
// certificate would be promising something the protocol cannot do.
func init() {
	proxy.Register(proxy.Kind{
		Name:     "tftp",
		Datagram: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.TFTP == nil {
				return nil, fmt.Errorf("listener %s: the tftp section is required", su.Config.Name)
			}
			pc, err := su.Packet("")
			if err != nil {
				return nil, err
			}
			t, err := newServer(su.Host, su.Config, pc)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			return t, nil
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
