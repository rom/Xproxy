package udp

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: udp listener relays datagrams to an upstream pool without
// looking inside them: the symmetric primitive to kind: tcp, for the
// services whose protocol this proxy has no parser for.
//
// It is the one kind with no accept socket. Datagram is what tells the
// engine that, so no TCP port is bound and nothing can connect to one
// and hang.
func init() {
	proxy.Register(proxy.Kind{
		Name:     "udp",
		Datagram: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.UDP == nil {
				return nil, fmt.Errorf("listener %s: the udp section is required", su.Config.Name)
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
