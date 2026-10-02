package pop3

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: pop3 listener is a POP3 relay in front of a mailbox server: the
// older of the two protocols a mail client reads with, and the one still
// configured on the devices and scripts nobody has revisited.
//
// Its policy is written in POP3's own terms -- which commands may be sent,
// which mechanism may carry the password, which identities may be claimed,
// and how much mail one connection may take -- and the last of those is the
// one worth the most: this protocol's whole purpose is to move a mailbox
// somewhere else, so a bound on the octets is a bound on exactly the thing
// an attacker with a password wants.
//
// A tls section serves POP3S from the first octet on port 995, and
// `tls_mode: starttls` terminates RFC 2595's STLS on port 110.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "pop3",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.POP3 == nil {
				return nil, fmt.Errorf("listener %s: the pop3 section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
