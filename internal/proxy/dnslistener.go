package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
)

// dnsPolicy compiles a listener configuration into the DNS server's
// reloadable policy.
func dnsPolicy(cfg *config.DNSListener) (*dns.Policy, error) {
	block, err := dns.NewBlockList(cfg.Block)
	if err != nil {
		return nil, err
	}
	if cfg.BlockFile != "" {
		if _, err := block.LoadBlockFile(cfg.BlockFile); err != nil {
			return nil, fmt.Errorf("block_file: %w", err)
		}
	}
	resolver, err := dns.NewResolverTLS(cfg.Upstreams, cfg.Timeout.D(), cfg.UpstreamCAFile)
	if err != nil {
		return nil, err
	}
	// cache is optional in the type; parsing fills it in, but a
	// configuration assembled another way (a translator, a test) may
	// leave it nil, and a nil dereference here would take the process
	// down at bind time rather than report a bad listener.
	cc := cfg.Cache
	if cc == nil {
		cc = &config.DNSCache{}
	}
	p := &dns.Policy{
		Block: block, BlockAction: cfg.BlockAction, SinkholeTTL: 60,
		AllowClients: netutil.ParsePrefixes(cfg.AllowClients),
		Resolver:     resolver,
		MinTTL:       cc.MinTTL.D(), MaxTTL: cc.MaxTTL.D(), NegativeTTL: cc.NegativeTTL.D(),
		LogQueries: cfg.LogQueries,
	}
	if a, err := netip.ParseAddr(cfg.SinkholeIPv4); err == nil {
		b := a.As4()
		p.Sinkhole4 = b[:]
	}
	if a, err := netip.ParseAddr(cfg.SinkholeIPv6); err == nil {
		b := a.As16()
		p.Sinkhole6 = b[:]
	}
	if rl := cfg.RateLimit; rl != nil {
		p.RateLimit = limits.NewKeyedLimiter(rl.QPS, rl.Burst, 65536)
	}
	if d := cfg.DNSSEC; d.IsEnabled() {
		var anchors []dns.TrustAnchor
		lines := append([]string(nil), d.TrustAnchors...)
		if d.TrustAnchorsFile != "" {
			data, err := os.ReadFile(d.TrustAnchorsFile) //nolint:gosec // validated configuration path
			if err != nil {
				return nil, fmt.Errorf("dnssec.trust_anchors_file: %w", err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
					continue
				}
				lines = append(lines, line)
			}
		}
		for _, line := range lines {
			a, err := dns.ParseTrustAnchor(line)
			if err != nil {
				return nil, fmt.Errorf("dnssec: %w", err)
			}
			anchors = append(anchors, a)
		}
		v := dns.NewValidator(resolver, anchors)
		v.MaxLookups = d.MaxLookups
		p.DNSSEC = v
	}
	return p, nil
}

// newDNSServer binds the hooks of a kind: dns listener to the proxy's
// logs and ban list.
func (s *Server) newDNSServer(lc config.Listener, udp net.PacketConn, tcp net.Listener) (*dns.Server, error) {
	p, err := dnsPolicy(lc.DNS)
	if err != nil {
		return nil, err
	}
	hooks := dns.Hooks{
		Access: func(attrs ...any) { s.logs.Access.Info("dns", attrs...) },
		Event: func(client netip.Addr, reason string, verified bool, attrs ...any) {
			if !verified {
				// An unverified datagram: record the fact in aggregate
				// and attribute it to nobody. One record and one ban
				// observation per packet would let a flood fill the
				// disk, drown other clients' records out of the bounded
				// export queues, and drive whatever address it names
				// into the ban list.
				s.dnsUnverified.Hit(s.logs.Error, "dns security events from unverified sources are aggregated",
					append([]any{"reason", reason}, attrs...)...)
				return
			}
			s.logs.SecurityEvent(context.Background(), "deny", reason, append([]any{"client_ip", client.String()}, attrs...)...)
			if bl := s.bans.Load(); bl != nil {
				bl.Observe(client, reason)
			}
		},
		Banned: func(client netip.Addr) bool {
			bl := s.bans.Load()
			return bl != nil && bl.Banned(client)
		},
	}
	return dns.New(lc.Name, udp, tcp, lc.DNS.Cache.MaxEntries, lc.DNS.MaxInFlight, p, hooks), nil
}

// DNS reports the status of every dns listener.
func (s *Server) DNS() []dns.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []dns.Status
	for _, bl := range s.listeners {
		if bl.dns != nil {
			out = append(out, bl.dns.Status())
		}
	}
	return out
}

// PurgeDNS empties the caches of every dns listener and returns the
// number of entries dropped.
func (s *Server) PurgeDNS() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, bl := range s.listeners {
		if bl.dns != nil {
			n += bl.dns.Purge()
		}
	}
	return n
}

// dnsTotals sums listener counters for the stats snapshot.
func (s *Server) dnsTotals(snap *Snapshot) {
	for _, st := range s.DNS() {
		snap.DNSQueries += st.Queries
		snap.DNSCacheHits += st.CacheHits
		snap.DNSBlocked += st.Blocked
		snap.DNSRefused += st.Refused
		snap.DNSDropped += st.Dropped
		snap.DNSServFail += st.ServFail
		snap.DNSCacheEntries += st.CacheEntries
	}
}
