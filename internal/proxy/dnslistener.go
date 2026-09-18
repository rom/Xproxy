package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"

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
	p := &dns.Policy{
		Block: block, BlockAction: cfg.BlockAction, SinkholeTTL: 60,
		AllowClients: netutil.ParsePrefixes(cfg.AllowClients),
		Resolver:     resolver,
		MinTTL:       cfg.Cache.MinTTL.D(), MaxTTL: cfg.Cache.MaxTTL.D(), NegativeTTL: cfg.Cache.NegativeTTL.D(),
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
		Event: func(client netip.Addr, reason string, attrs ...any) {
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
