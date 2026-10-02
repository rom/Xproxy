package tacacs

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: tacacs listener is a TACACS+ relay on TCP 49 that reads what it
// forwards: who logged in to which piece of equipment, which command they
// asked to run, and what privilege the server granted them.
//
// It is the listener in this project where a policy is worth the most per
// line. RADIUS answers "may this user onto the network"; TACACS+ answers
// "may this user run `configure terminal` on this router", one command at a
// time, with the command in the packet. So `commands` is an allow list on
// administrative access to the estate's own infrastructure, enforced
// between the equipment and the server that would otherwise be the only
// thing deciding.
//
// A tls section is allowed and means TACACS+ over TLS, which is the fix for
// everything RFC 8907 §10.3 admits about its MD5 obfuscation. Almost no
// equipment speaks it yet, which is why `refuse_unencrypted` exists as the
// weaker thing it is.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "tacacs",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.TACACS == nil {
				return nil, fmt.Errorf("listener %s: the tacacs section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
