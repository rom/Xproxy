package telnet

import (
	"context"

	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
)

// A telnet gateway. The socket is wrapped by the engine when the
// listener has a tls section (telnets, as on 992): telnet has no
// in-band upgrade, so unlike ftp or smtp there is nothing for the
// session to negotiate and the handshake belongs outside it.
//
// Telnet's options are commands escaped into the byte stream, so this
// cannot be a tcp listener: without parsing them the proxy cannot tell
// a window size negotiation from the characters a person typed, which
// is what a recording, an option policy and an injected prompt all
// need.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "telnet",
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
