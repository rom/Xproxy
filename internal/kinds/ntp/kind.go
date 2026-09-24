package ntp

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: ntp listener is an NTP and NTS security gateway on UDP 123: it
// reads every packet, decides about it in the protocol's own terms, and
// compares the servers behind it with each other.
//
// It is a datagram kind and only a datagram kind, so no TCP port is bound
// and nothing can connect to one and hang. NTS key establishment is TCP
// and is a listener of its own (kind: ntske), because it is a different
// port, a different transport and a different security property -- and
// running one without the other is a deployment somebody should have to
// write down.
func init() {
	proxy.Register(proxy.Kind{
		Name:     "ntp",
		Datagram: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.NTP == nil {
				return nil, fmt.Errorf("listener %s: the ntp section is required", su.Config.Name)
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
func (s *server) Serve() { s.serve() }

// Shutdown implements proxy.Instance.
func (s *server) Shutdown(ctx context.Context) { s.shutdown(ctx) }
