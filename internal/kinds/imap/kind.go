package imap

import (
	"context"
	"fmt"

	"github.com/rom/xproxy/internal/proxy"
)

// A kind: imap listener is an IMAP relay in front of a mailbox server: the
// protocol a mail client uses to read what an organisation has received.
//
// It is registered as a relay kind because that is what it is -- a client
// program talking to a server, no interactive session and no recording --
// and its policy is written in IMAP's own terms: which mailboxes exist as
// far as this listener is concerned, which commands may be sent, which
// mechanism may carry the password, and how much of a mailbox one request
// may name.
//
// That last one is the setting worth the most per line. Every other control
// here is about access; `max_fetch_messages` is about volume, and volume is
// what separates a mail client synchronising from an account being emptied.
//
// A tls section serves IMAPS from the first octet on port 993, and
// `tls_mode: starttls` terminates RFC 2595's upgrade on port 143 -- which
// this relay answers itself rather than forwarding, because the two legs of
// the connection are two decisions.
func init() {
	proxy.Register(proxy.Kind{
		Name:        "imap",
		TLS:         true,
		ProxyHeader: true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			if su.Config.IMAP == nil {
				return nil, fmt.Errorf("listener %s: the imap section is required", su.Config.Name)
			}
			return newServer(su.Host, su.Config, su.Net, su.TLS)
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
