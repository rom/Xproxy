package opcua

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: opcua listener is a relay in front of an OPC UA server, on TCP 4840.
//
// It is the first industrial listener in this project whose protocol brought its own
// security, and that changes the job. In front of Modbus or S7comm the relay *is*
// the access control, because the protocol has none. In front of OPC UA the server
// already checks certificates and users, and the relay's job is to be the place
// where an estate's rules about which policies, which applications, which users and
// which nodes are written once and enforced for every server behind it — including
// the ones whose own configuration nobody has reviewed since they were commissioned.
//
// The listener takes **no TLS section**, and that is worth stating because it looks
// like an omission. The `opc.tcp` transport has no TLS: its security is inside the
// protocol, in the secure channel, negotiated per connection with certificates the
// two ends hold. A certificate on this listener would promise something the
// transport cannot do, and terminating the channel would make this relay a man in
// the middle of the one industrial protocol designed to notice — holding the plant's
// private key to do it. So the relay reads what the channel leaves readable and
// says so, which under mode sign is everything and under sign_and_encrypt is the
// envelope.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "opcua",
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.OPCUA == nil {
				return nil, fmt.Errorf("listener %s: the opcua section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
