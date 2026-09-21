package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
)

// compileDNSRecord turns one configured record into its wire form.
func compileDNSRecord(r config.DNSRecord) (dns.LocalRecord, error) {
	out := dns.LocalRecord{Name: r.Name, Type: dns.TypeHTTPS, TTL: 300}
	if r.Type == "svcb" {
		out.Type = dns.TypeSVCB
	}
	if r.TTL > 0 {
		out.TTL = uint32(r.TTL) //nolint:gosec // validated range
	}
	target := r.Target
	if target == "" || target == "." {
		// RFC 9460: the empty target means the owner name.
		target = "."
	}
	out.SVCB = dns.SVCB{Priority: uint16(r.Priority), Target: target} //nolint:gosec // validated range
	for _, name := range sortedParamNames(r.Params) {
		p, err := dns.ParseSVCBParam(name, r.Params[name])
		if err != nil {
			return dns.LocalRecord{}, err
		}
		out.SVCB.Params = append(out.SVCB.Params, p)
	}
	if _, err := out.SVCB.Encode(); err != nil {
		return dns.LocalRecord{}, err
	}
	return out, nil
}

// sortedParamNames keeps the compiled record independent of map order.
func sortedParamNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

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
	// Local records: the discovery set (RFC 9462) and whatever the
	// operator publishes, most usefully an ECH configuration.
	local := make([]dns.LocalRecord, 0, len(cfg.Discovery)+len(cfg.Records))
	if len(cfg.Discovery) > 0 {
		eps := make([]dns.Designated, 0, len(cfg.Discovery))
		ttl := uint32(300)
		for _, d := range cfg.Discovery {
			if d.TTL > 0 {
				ttl = uint32(d.TTL) //nolint:gosec // validated range
			}
			eps = append(eps, dns.Designated{Transport: d.Transport, Name: d.Name,
				Port: d.Port, DoHPath: d.DoHPath, IPv4: d.IPv4, IPv6: d.IPv6})
		}
		recs, err := dns.DiscoveryRecords(eps, ttl)
		if err != nil {
			return nil, fmt.Errorf("discovery: %w", err)
		}
		local = append(local, recs...)
	}
	for i, r := range cfg.Records {
		rec, err := compileDNSRecord(r)
		if err != nil {
			return nil, fmt.Errorf("records[%d]: %w", i, err)
		}
		local = append(local, rec)
	}
	p.Local = dns.NewLocalRecords(local)
	if rl := cfg.RateLimit; rl != nil {
		p.RateLimit = limits.NewKeyedLimiter(rl.QPS, rl.Burst, 65536)
	}
	if td := cfg.TunnelDetection; td != nil {
		tp := dns.TunnelPolicy{
			Window: td.Window.D(), MinQueries: td.MinQueries, MinSignals: td.MinSignals,
			Entropy: td.Entropy, EntropyShare: derefF(td.EntropyShare), MinLabelLength: td.MinLabelLength,
			Distinct: derefI(td.DistinctSubdomains), TXTShare: derefF(td.TXTShare), NXShare: derefF(td.NXDOMAINShare),
			PayloadBytes: derefI64(td.PayloadBytes), Action: td.Action,
			Cooldown: td.Cooldown.D(), MaxTracked: td.MaxTracked,
		}
		if len(td.AllowDomains) > 0 {
			allow, err := dns.NewBlockList(td.AllowDomains)
			if err != nil {
				return nil, fmt.Errorf("tunnel_detection.allow_domains: %w", err)
			}
			tp.Allow = allow
		}
		p.Tunnel = dns.NewDetector(tp)
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
			st := bl.dns.Status()
			if bl.doq != nil {
				st.DoQ = true
			}
			out = append(out, st)
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
		if t := st.Tunnel; t != nil {
			snap.DNSTunnels += t.Detections
			snap.DNSTunnelBlocked += t.Blocked
			snap.DNSTunnelTracked += t.Tracked
		}
	}
}

// derefF, derefI and derefI64 read a setting whose zero value an
// operator may mean: nil is the absent key, which defaults have already
// filled in, so nil here can only mean a configuration assembled
// without them and reads as the signal being off.
func derefF(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func derefI(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func derefI64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
