package dns

import (
	"context"
	"crypto/tls"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/proxy"
)

// A dns listener is a forwarding resolver: a cache, a block list, client
// allow lists, per-client rate limits, DNSSEC validation, and detection
// of data leaving inside the query names.
//
// It takes two shapes. Plain, it answers UDP and TCP on one address,
// because a resolver that took only one of them is a resolver half the
// estate goes around. Encrypted, the TCP side carries DNS over TLS and
// DNS over HTTPS separated by ALPN, optionally with DNS over QUIC on the
// UDP side of the same address and certificate; there is no plain UDP
// then, which is the point of configuring it that way.
func init() {
	proxy.Register(proxy.Kind{
		Name: "dns",
		TLS:  true,
		New:  build,
	})
}

func build(su *proxy.Setup) (proxy.Instance, error) {
	lc := su.Config
	if su.TLS == nil {
		// Plain: UDP beside TCP on the same address.
		pc, err := su.Packet("")
		if err != nil {
			return nil, err
		}
		d, err := newServer(su.Host, lc, pc, su.Net)
		if err != nil {
			_ = pc.Close()
			return nil, err
		}
		return &instance{srv: d}, nil
	}

	// Encrypted: the ALPN separates DNS over TLS from DNS over HTTPS on
	// the one TCP port.
	su.TLS.NextProtos = []string{wire.ALPNDoT, wire.ALPNH2, wire.ALPNHTTP}
	su.Net = tls.NewListener(su.Net, su.TLS)
	d, err := newServer(su.Host, lc, nil, su.Net)
	if err != nil {
		return nil, err
	}
	d.Encrypted = true
	d.DoHPath = lc.DNS.DoHPath
	in := &instance{srv: d}
	if lc.DNS.DoQ {
		// DNS over QUIC shares the address and the certificate; only
		// the transport differs, and the ALPN is what separates it
		// from HTTP/3 on the same port.
		pc, err := su.Packet("doq")
		if err != nil {
			return nil, err
		}
		q, err := wire.NewDoQ(d, pc, su.TLS, su.Host.Limits().IdleTimeout.D(), lc.DNS.MaxInFlight)
		if err != nil {
			_ = pc.Close()
			return nil, err
		}
		in.doq = q
		d.QUIC = true
	}
	return in, nil
}

// instance is a resolver and, where one is configured, its QUIC
// endpoint. They share a policy and a cache and stop together.
type instance struct {
	srv *wire.Server
	doq *wire.DoQServer
}

// Serve implements proxy.Instance.
func (i *instance) Serve() {
	if i.doq != nil {
		i.doq.Serve()
	}
	i.srv.Serve()
}

// Shutdown implements proxy.Instance.
func (i *instance) Shutdown(ctx context.Context) {
	if i.doq != nil {
		_ = i.doq.Close()
	}
	i.srv.Shutdown(ctx)
}

// Apply implements proxy.Applier: a reload replaces the resolver's
// policy where it stands, so the cache survives and nothing bound to
// the socket is dropped for a changed block list.
func (i *instance) Apply(lc config.Listener) error {
	if lc.DNS == nil {
		return nil
	}
	p, err := dnsPolicy(lc.DNS)
	if err != nil {
		return err
	}
	i.srv.Apply(p, lc.DNS.Cache.MaxEntries)
	return nil
}

// Close implements proxy.Closer.
func (i *instance) Close() { i.srv.Close() }

// DNSServer implements proxy.DNSInstance, which is how the status and
// purge views reach a resolver without the engine importing this
// package.
func (i *instance) DNSServer() *wire.Server { return i.srv }
