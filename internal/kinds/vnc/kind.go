package vnc

import (
	"context"

	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
)

// A VNC gateway. The socket is wrapped by the engine when the listener
// has a tls section, which is one of the two ways this listener can be
// encrypted towards the client; the other is VeNCrypt, negotiated
// inside RFB, which the session terminates itself.
//
// RFB's whole policy surface is in its handshake -- which security
// type, whether the session is encrypted, what the desktop is called
// -- so a proxy that does not sit in that negotiation cannot decide
// any of it, nor record what follows. That is why this is a kind
// rather than a tcp listener.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "vnc",
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

// MFAGuard implements proxy.MFAHolder, so the control plane can list
// and change the enrolments this listener asks for.
func (t *server) MFAGuard() *mfa.Guard { return t.mfaGuard }
