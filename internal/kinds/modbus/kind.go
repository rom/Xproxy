package modbus

import (
	"context"

	"github.com/rom/xproxy/internal/proxy"
)

// A modbus listener is a Modbus relay that reads every frame and decides
// about it: the unit identifier, the function code, the register range,
// the value being written.
//
// It is registered as a relay kind because that is what it is: machine to
// machine, no people, no recordings, and a policy written in the
// protocol's own terms. The listener works in both directions -- fronting
// devices for masters that connect to it, or being the controlled egress
// a plant's masters use to reach devices elsewhere -- and the direction is
// a setting rather than two implementations, because the frames and the
// decisions are the same either way.
//
// TLS on this listener is Modbus/TCP Security (MB-TCP-Security v21): TLS
// with mutual authentication on port 802, and authorisation by the role
// the client certificate carries. That is the one part of Modbus that has
// any security in it, and a relay is where a device that will never speak
// TLS can still be put behind it.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "modbus",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
