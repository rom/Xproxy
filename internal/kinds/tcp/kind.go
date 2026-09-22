package tcp

import (
	"context"

	"github.com/rom/xproxy/internal/proxy"
)

// A layer 4 listener routes by the name in a TLS ClientHello without
// terminating the handshake, so the client still verifies the origin's
// own certificate end to end. What it can inspect is what passes in the
// clear -- the handshake, and whatever YARA is given the stream for --
// and what it applies is a destination policy.
//
// With quic it also relays QUIC flows on the same address over UDP,
// routed by the name in the first Initial packet.
func init() {
	proxy.Register(proxy.Kind{
		Name: "tcp",
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			t, err := newServer(su.Host, su.Config, su.Net)
			if err != nil {
				return nil, err
			}
			if su.Config.TCP.QUIC {
				pc, err := su.Packet("")
				if err != nil {
					return nil, err
				}
				t.quic = newQUICRelay(t, pc)
			}
			return t, nil
		},
	})
}

// Serve implements proxy.Instance. The QUIC relay, when there is one,
// shares the listener's address and runs beside it.
func (t *server) Serve() {
	if t.quic != nil {
		go t.quic.serve()
	}
	t.serve()
}

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }

// OpenFlows implements proxy.FlowCounter.
func (t *server) OpenFlows() int {
	if t.quic == nil {
		return 0
	}
	return t.quic.open()
}
