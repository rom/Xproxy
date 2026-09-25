package iec104

import (
	"context"

	"github.com/rom/xproxy/internal/proxy"
)

// An iec104 listener is an IEC 60870-5-104 relay that reads every APDU and
// decides about it: which station it names, what it asks for, why, and
// whether the client said so twice.
//
// It is registered as a relay kind because that is what it is: machine to
// machine, no people, no recordings, and a policy written in the protocol's
// own terms. The listener works in both directions -- fronting substations
// for control centres that connect to it, or being the controlled egress a
// control centre uses to reach stations elsewhere -- and the direction is a
// setting rather than two implementations, because the frames and the
// decisions are the same either way.
//
// TLS on this listener is IEC 62351-3: TLS from the first octet, on the
// standard's own port 2404. That is the only security the standard has, and
// a relay is where a substation gateway that will never speak TLS can still
// be put behind it.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "iec104",
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
