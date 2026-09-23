package ftp

import (
	"context"

	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
)

// Like SMTP, the socket is not wrapped even for implicit mode: AUTH TLS
// has to read cleartext first, so the session owns the handshake and
// its deadline.
//
// FTP is two connections, and the second one is where the transfers
// are. A proxy that reads only the control connection has read the
// instructions and none of the data, so this kind mediates the data
// connection too: it rewrites the addresses either side announces
// rather than forwarding them, which is what keeps a client from being
// told to go around it.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "ftp",
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
