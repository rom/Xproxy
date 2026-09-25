package ldap

import (
	"context"

	"github.com/rom/xproxy/internal/proxy"
)

// An ldap listener is a relay in front of a directory: the one service in an
// estate that knows who everybody is, answering the protocol every
// application that has not moved to OIDC still asks with.
//
// It is registered as a relay kind because that is what it is -- machine to
// machine, no people at a terminal, no recordings -- and its policy is
// written in LDAP's own terms: who binds and how, which subtree a request may
// name, which operation it is, and which attributes may cross the relay in
// either direction.
//
// TLS is both shapes the protocol has. LDAPS is TLS from the first octet on
// port 636, which is what almost everything actually uses; StartTLS is the
// extended operation of RFC 4513 on port 389, which this relay terminates
// itself rather than forwarding, because the two legs of the connection are
// separate decisions -- and that is what makes it a secure upgrade for a
// client library nobody can reconfigure.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "ldap",
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
