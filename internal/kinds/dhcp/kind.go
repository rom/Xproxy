package dhcp

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: dhcp listener is a DHCP relay agent on UDP 67 that reads what it
// relays: every request from the segment, and every reply from a server.
//
// It is a datagram kind and only a datagram kind. DHCP has no stream transport
// and no transport security of any kind, so a listener that bound a TCP port
// would hold a port nothing can speak on, and one carrying a certificate would
// be promising something the protocol cannot do.
func init() {
	proxy.Register(proxy.Kind{
		Name:     "dhcp",
		Datagram: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.DHCP == nil {
				return nil, fmt.Errorf("listener %s: the dhcp section is required", su.Config.Name)
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
			if err := s.resolveServers(); err != nil {
				_ = pc.Close()
				return nil, err
			}
			return s, nil
		},
	})
}

// resolveServers fills in the server list from the upstream pool when the
// configuration did not name one.
//
// This is what keeps the rogue-server check from being open by accident. An
// operator who wrote no allow_servers meant "the servers I configured", not
// "anybody", and a relay that read an empty list as "anybody" would have the
// protection switched off in exactly the deployments that did not think about
// it.
func (s *server) resolveServers() error {
	if len(s.policy.servers) > 0 {
		return nil
	}
	pool := s.host.Pool(s.m.Upstream)
	if pool == nil {
		return fmt.Errorf("listener %s: upstream %q has no pool", s.cfg.Name, s.m.Upstream)
	}
	for _, e := range pool.Endpoints() {
		ap, err := netip.ParseAddrPort(e.Address)
		if err != nil {
			// An endpoint named by host rather than by address. The list
			// cannot be derived from it, so the operator is told to write the
			// server list out: guessing would be the wrong kind of helpful on
			// the one check this kind most depends on.
			return fmt.Errorf("listener %s: upstream endpoint %q is not an address, so allow_servers must be set",
				s.cfg.Name, e.Address)
		}
		a := ap.Addr().Unmap()
		s.policy.servers = append(s.policy.servers, netip.PrefixFrom(a, a.BitLen()))
	}
	if len(s.policy.servers) == 0 {
		return fmt.Errorf("listener %s: upstream %q has no endpoints, so no reply could be admitted",
			s.cfg.Name, s.m.Upstream)
	}
	return nil
}

// Serve implements proxy.Instance.
func (s *server) Serve() { s.serve() }

// Shutdown implements proxy.Instance.
func (s *server) Shutdown(ctx context.Context) { s.shutdown(ctx) }
