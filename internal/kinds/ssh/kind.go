package ssh

import (
	"context"

	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
)

// SSH carries its own transport security, so there is no TLS here and
// no listener wrapper: the bastion owns the handshake from the first
// byte.
//
// This is the kind the gate is built around. A session here belongs to
// a named principal, is recorded, can be made to carry a second factor,
// and is bounded by a policy written in SSH's own terms -- which
// channels, which requests, which subsystems, which environment
// variables, and which commands. SFTP inside it is mediated request by
// request rather than relayed.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "ssh",
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			return newServer(su.Host, su.Config, su.Net)
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
