package coap

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: coap listener is a CoAP relay agent on UDP 5683 that reads what it
// relays: the method, the path and the content format of every request, and the
// size and content format of every answer.
//
// It is a datagram kind. CoAP over TCP, TLS and WebSockets (RFC 8323) is a
// different framing that almost nothing in the field speaks, and a listener that
// held a stream port for it would be holding a port nothing connects to.
func init() {
	proxy.Register(proxy.Kind{
		Name:     "coap",
		Datagram: true,
		// A tls section means DTLS: RFC 7252 s9 puts CoAP inside it on 5684,
		// and a listener without one is NoSec, which is what most of the field
		// runs. The engine builds the *tls.Config as it does for any other
		// listener and this kind translates it, so that the certificates and
		// the client-certificate policy are written where every other
		// listener's are.
		TLS: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.CoAP == nil {
				return nil, fmt.Errorf("listener %s: the coap section is required", su.Config.Name)
			}
			pc, err := su.Packet("")
			if err != nil {
				return nil, err
			}
			s, err := newServer(su.Host, su.Config, pc, su.TLS)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			if err := s.resolveDevices(); err != nil {
				_ = pc.Close()
				return nil, err
			}
			return s, nil
		},
	})
}

// resolveDevices fills in the device list from the upstream pool when the
// configuration did not name one.
//
// This is what keeps the answer check from being open by accident. An operator who
// wrote no allow_servers meant "the devices I configured", not "anybody", and a
// relay that read an empty list as "anybody" would have the check switched off in
// exactly the deployments that did not think about it.
func (s *server) resolveDevices() error {
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
			// An endpoint named by host rather than by address. The list cannot
			// be derived from it, so the operator is told to write it out:
			// guessing would be the wrong kind of helpful on the check that
			// decides which answers this relay carries.
			return fmt.Errorf("listener %s: upstream endpoint %q is not an address, so allow_servers must be set",
				s.cfg.Name, e.Address)
		}
		a := ap.Addr().Unmap()
		s.policy.servers = append(s.policy.servers, netip.PrefixFrom(a, a.BitLen()))
	}
	if len(s.policy.servers) == 0 {
		return fmt.Errorf("listener %s: upstream %q has no endpoints, so no answer could be carried",
			s.cfg.Name, s.m.Upstream)
	}
	return nil
}

// Serve implements proxy.Instance.
func (s *server) Serve() { s.serve() }

// Shutdown implements proxy.Instance.
func (s *server) Shutdown(ctx context.Context) { s.shutdown(ctx) }
