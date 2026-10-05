package kkdcp

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: kkdcp listener is a Kerberos KDC proxy: it serves HTTPS, unwraps
// the KDC-PROXY-MESSAGE a client POSTs, decides about the Kerberos message
// inside it, speaks TCP to the KDC, and wraps the answer back.
//
// It is the only listener in this project that translates one protocol into
// another, and that is what it is for: Kerberos is UDP and TCP on port 88,
// the places people work from are not on the network the KDC is on, and
// MS-KKDCP is how Windows, MIT and Heimdal all bridge the two. Which makes
// it the one place an estate's Kerberos traffic is inspectable -- every
// field a policy is written about is in the clear, because those fields are
// how the two ends agree what to encrypt.
//
// A tls section is required rather than optional. MS-KKDCP is HTTPS, and
// the message it carries holds a value derived from the user's password.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "kkdcp",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.KKDCP == nil {
				return nil, fmt.Errorf("listener %s: the kkdcp section is required", su.Config.Name)
			}
			if su.TLS == nil {
				return nil, fmt.Errorf("listener %s: a kkdcp listener requires a tls section: "+
					"the protocol is HTTPS and the message it carries holds a value derived from "+
					"the user's password", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
