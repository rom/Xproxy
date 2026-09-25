package snmp

import (
	"context"
	"net"

	"github.com/rom/xproxy/internal/proxy"
)

// An snmp listener is a relay in front of the equipment SNMP actually
// manages: switches, routers, printers, uninterruptible supplies and
// building controllers, authenticating with a cleartext community string
// that half an estate has never changed.
//
// It is registered as a relay kind because that is what it is -- machine to
// machine, no people, no recordings, and a policy written in the protocol's
// own terms: the version, the credential, the operation and the object
// identifier subtree.
//
// It takes datagrams and streams at once, because the protocol is used both
// ways and a relay that took only one would be a relay half the estate goes
// around. UDP 161 is what every poller and every agent speaks. TCP is what
// RFC 3430 defines, and RFC 6353's TLS transport runs over it on port
// 10161 -- which is the half of the secure upgrade that faces a management
// station, with plain v2c going on towards a switch whose firmware has
// nothing else.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "snmp",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			var pc net.PacketConn
			if su.Config.SNMP.Transport != "tcp" {
				p, err := su.Packet("")
				if err != nil {
					return nil, err
				}
				pc = p
			}
			t, err := newServer(su.Host, su.Config, pc, su.Net, su.TLS)
			if err != nil {
				if pc != nil {
					_ = pc.Close()
				}
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
