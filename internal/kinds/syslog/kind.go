package syslog

import (
	"context"
	"net"

	"github.com/rom/xproxy/internal/proxy"
)

// A syslog relay reads what it forwards. Almost every field in a record
// is written by the sender and believed by the collector, so the relay
// is the one place that can say what a record actually came from, and
// the one place that can stop a message whose text carries a newline
// from becoming two records downstream.
//
// It also takes UDP, because most senders still speak it: a relay that
// took only streams would be a relay half the estate goes around. That
// is what makes it a secure upgrade — a legacy sender keeps sending
// plaintext datagrams, and what leaves here is RFC 5425 over TLS.
func init() {
	proxy.Register(proxy.Kind{
		Name: "syslog",
		TLS:  true,
		New: func(su *proxy.Setup) (proxy.Instance, error) {
			var pc net.PacketConn
			if u := su.Config.Syslog.UDP; u == nil || *u {
				p, err := su.Packet("")
				if err != nil {
					return nil, err
				}
				pc = p
			}
			t, err := newServer(su.Host, su.Config, su.Net, pc, su.TLS)
			if err != nil {
				if pc != nil {
					_ = pc.Close()
				}
				return nil, err
			}
			return t, nil
		},
	})
}

// Serve implements proxy.Instance.
func (t *server) Serve() { t.serve() }

// Shutdown implements proxy.Instance.
func (t *server) Shutdown(ctx context.Context) { t.shutdown(ctx) }
