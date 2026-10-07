package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/intel"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
)

// compileDNSRecord turns one configured record into its wire form.
func compileDNSRecord(r config.DNSRecord) (wire.LocalRecord, error) {
	out := wire.LocalRecord{Name: r.Name, Type: wire.TypeHTTPS, TTL: 300}
	switch r.Type {
	case "svcb":
		out.Type = wire.TypeSVCB
	case "a", "aaaa":
		addr, err := netip.ParseAddr(r.Address)
		if err != nil {
			return wire.LocalRecord{}, fmt.Errorf("address: %q is not an address", r.Address)
		}
		out.Type, out.Addr = wire.TypeA, addr.Unmap()
		if r.Type == "aaaa" {
			out.Type = wire.TypeAAAA
		}
		if r.TTL > 0 {
			out.TTL = uint32(r.TTL) //nolint:gosec // validated range
		}
		// An A record of an IPv6 address (or the reverse) is a record no
		// client can read, so it is a load error rather than a record
		// that is silently skipped at answer time.
		if _, err := out.Rdata(); err != nil {
			return wire.LocalRecord{}, err
		}
		return out, nil
	case "txt", "ptr":
		out.Type, out.Text = wire.TypeTXT, r.Text
		if r.Type == "ptr" {
			out.Type = wire.TypePTR
		}
		if r.TTL > 0 {
			out.TTL = uint32(r.TTL) //nolint:gosec // validated range
		}
		if _, err := out.Rdata(); err != nil {
			return wire.LocalRecord{}, err
		}
		return out, nil
	}
	if r.TTL > 0 {
		out.TTL = uint32(r.TTL) //nolint:gosec // validated range
	}
	target := r.Target
	if target == "" || target == "." {
		// RFC 9460: the empty target means the owner name.
		target = "."
	}
	out.SVCB = wire.SVCB{Priority: uint16(r.Priority), Target: target} //nolint:gosec // validated range
	for _, name := range sortedParamNames(r.Params) {
		p, err := wire.ParseSVCBParam(name, r.Params[name])
		if err != nil {
			return wire.LocalRecord{}, err
		}
		out.SVCB.Params = append(out.SVCB.Params, p)
	}
	if _, err := out.SVCB.Encode(); err != nil {
		return wire.LocalRecord{}, err
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

// compileView turns a view's configuration into the answer set it
// selects. A view with nothing in it is a load error rather than a view
// that quietly does nothing: an operator who wrote the section meant to
// get something for it.
func compileView(vc config.DNSView) (*wire.View, error) {
	v := &wire.View{Name: vc.Name, Clients: netutil.ParsePrefixes(vc.Clients), Action: vc.BlockAction}
	if len(v.Clients) == 0 {
		return nil, errors.New("clients: at least one network is required")
	}
	if len(vc.Records) > 0 {
		recs := make([]wire.LocalRecord, 0, len(vc.Records))
		for i, r := range vc.Records {
			rec, err := compileDNSRecord(r)
			if err != nil {
				return nil, fmt.Errorf("records[%d]: %w", i, err)
			}
			recs = append(recs, rec)
		}
		v.Local = wire.NewLocalRecords(recs)
	}
	if len(vc.Block) > 0 || vc.BlockFile != "" {
		block, err := wire.NewBlockList(vc.Block)
		if err != nil {
			return nil, err
		}
		if vc.BlockFile != "" {
			if _, err := block.LoadBlockFile(vc.BlockFile); err != nil {
				return nil, fmt.Errorf("block_file: %w", err)
			}
		}
		v.Block = block
	}
	if a, err := netip.ParseAddr(vc.SinkholeIPv4); err == nil {
		b := a.As4()
		v.Sinkhole4 = b[:]
	}
	if a, err := netip.ParseAddr(vc.SinkholeIPv6); err == nil {
		b := a.As16()
		v.Sinkhole6 = b[:]
	}
	if v.Local == nil && v.Block == nil && v.Action == "" {
		return nil, errors.New("a view must change something: records, block, block_file or block_action")
	}
	return v, nil
}

// dnsPolicy compiles a listener configuration into the DNS server's
// reloadable policy.
func dnsPolicy(name string, cfg *config.DNSListener) (*wire.Policy, error) {
	block, err := wire.NewBlockList(cfg.Block)
	if err != nil {
		return nil, err
	}
	if cfg.BlockFile != "" {
		if _, err := block.LoadBlockFile(cfg.BlockFile); err != nil {
			return nil, fmt.Errorf("block_file: %w", err)
		}
	}
	resolver, err := wire.NewResolverTLS(cfg.Upstreams, cfg.Timeout.D(), cfg.UpstreamCAFile)
	if err != nil {
		return nil, err
	}
	if cfg.UpstreamResumption != nil {
		resolver.SetSessionResumption(*cfg.UpstreamResumption)
	}
	// cache is optional in the type; parsing fills it in, but a
	// configuration assembled another way (a translator, a test) may
	// leave it nil, and a nil dereference here would take the process
	// down at bind time rather than report a bad listener.
	cc := cfg.Cache
	if cc == nil {
		cc = &config.DNSCache{}
	}
	p := &wire.Policy{
		Block: block, BlockAction: cfg.BlockAction, SinkholeTTL: 60,
		AllowClients: netutil.ParsePrefixes(cfg.AllowClients),
		Resolver:     resolver,
		MinTTL:       cc.MinTTL.D(), MaxTTL: cc.MaxTTL.D(), NegativeTTL: cc.NegativeTTL.D(),
		LogQueries: cfg.LogQueries,
		ServeStale: cc.ServeStale.D(), StaleTTL: cc.StaleTTL.D(),
		Prefetch: cc.Prefetch, PrefetchThreshold: cc.PrefetchThreshold,
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
	local := make([]wire.LocalRecord, 0, len(cfg.Discovery)+len(cfg.Records))
	if len(cfg.Discovery) > 0 {
		eps := make([]wire.Designated, 0, len(cfg.Discovery))
		ttl := uint32(300)
		for _, d := range cfg.Discovery {
			if d.TTL > 0 {
				ttl = uint32(d.TTL) //nolint:gosec // validated range
			}
			eps = append(eps, wire.Designated{Transport: d.Transport, Name: d.Name,
				Port: d.Port, DoHPath: d.DoHPath, IPv4: d.IPv4, IPv6: d.IPv6})
		}
		recs, err := wire.DiscoveryRecords(eps, ttl)
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
	p.Local = wire.NewLocalRecords(local)
	for i, vc := range cfg.Views {
		v, err := compileView(vc)
		if err != nil {
			return nil, fmt.Errorf("views[%d]: %w", i, err)
		}
		p.Views = append(p.Views, v)
	}
	if ds := cfg.DNSSEC; ds != nil && ds.IsEnabled() && ds.AggressiveNSEC {
		entries := ds.NSECEntries
		if entries == 0 {
			entries = 8192
		}
		p.Denials = wire.NewDenials(entries)
	}
	if d := cfg.DNS64; d != nil {
		prefix := d.Prefix
		if prefix == "" {
			prefix = wire.WellKnownPrefix
		}
		pfx, err := netip.ParsePrefix(prefix)
		if err != nil {
			return nil, fmt.Errorf("dns64.prefix: %w", err)
		}
		p.DNS64 = &wire.DNS64{Prefix: pfx.Masked(), Clients: netutil.ParsePrefixes(d.Clients)}
		if d.TTL > 0 {
			p.DNS64.TTL = uint32(d.TTL) //nolint:gosec // validated range
		}
	}
	if rl := cfg.RateLimit; rl != nil {
		p.RateLimit = limits.NewKeyedLimiter(rl.QPS, rl.Burst, 65536)
	}
	if td := cfg.TunnelDetection; td != nil {
		tp := wire.TunnelPolicy{
			Window: td.Window.D(), MinQueries: td.MinQueries, MinSignals: td.MinSignals,
			Entropy: td.Entropy, EntropyShare: derefF(td.EntropyShare), MinLabelLength: td.MinLabelLength,
			Distinct: derefI(td.DistinctSubdomains), TXTShare: derefF(td.TXTShare), NXShare: derefF(td.NXDOMAINShare),
			PayloadBytes: derefI64(td.PayloadBytes), Action: td.Action,
			Cooldown: td.Cooldown.D(), MaxTracked: td.MaxTracked,
		}
		if len(td.AllowDomains) > 0 {
			allow, err := wire.NewBlockList(td.AllowDomains)
			if err != nil {
				return nil, fmt.Errorf("tunnel_detection.allow_domains: %w", err)
			}
			tp.Allow = allow
		}
		p.Tunnel = wire.NewDetector(tp)
	}
	if r := cfg.RPZ; r != nil {
		specs := make([]wire.RPZSpec, 0, len(r.Zones))
		for _, z := range r.Zones {
			specs = append(specs, wire.RPZSpec{Name: z.Name, File: z.File,
				Override: z.Action, IgnoreUnsupported: z.IgnoreUnsupported})
		}
		set, err := wire.NewRPZ(specs)
		if err != nil {
			return nil, err
		}
		p.RPZ = set
	}
	answers, err := answerPolicy(cfg.AnswerPolicy)
	if err != nil {
		return nil, err
	}
	p.Answers = answers
	p.ECS = cfg.ECS
	p.Cookies, p.CookieLifetime = cfg.Cookies, cfg.CookieLifetime.D()
	if d := cfg.DNSSEC; d.IsEnabled() {
		var anchors []wire.TrustAnchor
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
			a, err := wire.ParseTrustAnchor(line)
			if err != nil {
				return nil, fmt.Errorf("dnssec: %w", err)
			}
			anchors = append(anchors, a)
		}
		v := wire.NewValidator(resolver, anchors)
		v.MaxLookups = d.MaxLookups
		p.DNSSEC = v
	}
	if p.Decoy, err = decoy(name, cfg.Deception); err != nil {
		return nil, err
	}
	return p, nil
}

// decoy compiles the fabricated resolver, or nil where the section is absent or
// off.
func decoy(name string, c *config.DNSDeception) (*wire.Decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	o := wire.DecoyOptions{
		Whole: c.Mode == "decoy", Profile: c.Profile, TTL: c.TTL.D(),
		Tripwire: c.Tripwire, Clients: netutil.ParsePrefixes(c.Clients),
		Seed: c.Seed, Name: name, Period: c.Period.D(), MaxClients: c.MaxClients,
	}
	for _, a := range c.Addresses {
		pfx, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, fmt.Errorf("deception.addresses: %q: %w", a, err)
		}
		if pfx.Addr().Is4() {
			o.V4 = pfx
			continue
		}
		o.V6 = pfx
	}
	return wire.NewDecoy(o)
}

// answerPolicy compiles the answer screen: where an upstream answer may
// point, and which names are excused from it.
func answerPolicy(a *config.DNSAnswerPolicy) (*wire.AnswerPolicy, error) {
	if a == nil {
		return nil, nil
	}
	out := &wire.AnswerPolicy{Action: a.Action}
	if a.DenyPrivate == nil || *a.DenyPrivate {
		out.Deny = wire.PrivateRanges()
	}
	out.Deny = append(out.Deny, netutil.ParsePrefixes(a.Deny)...)
	out.Allow = netutil.ParsePrefixes(a.Allow)
	if len(a.AllowNames) > 0 {
		ex, err := wire.NewBlockList(a.AllowNames)
		if err != nil {
			return nil, fmt.Errorf("answer_policy.allow_names: %w", err)
		}
		out.Exempt = ex
	}
	return out, nil
}

// newDNSServer binds the hooks of a kind: dns listener to the proxy's
// logs and ban list.
func newServer(host proxy.Host, lc config.Listener, udp net.PacketConn, tcp net.Listener) (*wire.Server, error) {
	p, err := dnsPolicy(lc.Name, lc.DNS)
	if err != nil {
		return nil, err
	}
	// unverified aggregates the security events that came from a source
	// no round trip has confirmed. One record and one ban observation
	// per datagram would let a flood fill the disk, drown other clients
	// out of the bounded export queues, and drive whatever address it
	// names into the ban list. It belongs to this listener, so one
	// listener's flood does not quieten another's records.
	var unverified bound.Notice
	// alerts says whether a refusal on this listener is worth a security event.
	// The counters and the ban observation do not go through it: this is the record
	// alone, which is what alert_on_deny is named for.
	alerts := lc.DNS.AlertOnDeny == nil || *lc.DNS.AlertOnDeny
	// event is the security-event path, lifted out of the hooks literal because
	// the admission point below has to get exactly the same treatment of an
	// unverified source: a refusal recorded against an address anybody could have
	// written into a datagram is a refusal anybody can have written against a
	// third party.
	event := func(client netip.Addr, reason string, verified bool, attrs ...any) {
		if !verified {
			// An unverified datagram: record the fact in aggregate
			// and attribute it to nobody. One record and one ban
			// observation per packet would let a flood fill the
			// disk, drown other clients' records out of the bounded
			// export queues, and drive whatever address it names
			// into the ban list.
			unverified.Hit(host.Logs().Error, "dns security events from unverified sources are aggregated",
				append([]any{"reason", reason}, attrs...)...)
			return
		}
		// The ban ladder hears about this before alert_on_deny can silence the
		// record below: turning the log down is not a decision to stop responding.
		if bl := host.Bans(); bl != nil {
			bl.Observe(client, reason)
		}

		if !alerts {
			return
		}
		host.Logs().SecurityEvent(context.Background(), "deny", reason, append([]any{"client_ip", client.String()}, attrs...)...)
	}
	hooks := wire.Hooks{
		Access: func(attrs ...any) { host.Logs().Access.Info("dns", attrs...) },
		Event:  event,
		// The estate's two questions about a client with no identity, asked
		// after this listener's own allow_clients.
		//
		// A query names nobody: the protocol carries no identity at all, and the
		// one field that looks like one -- the source address -- is a datagram's
		// unproven claim about itself. So the policy decides on the address, the
		// listener, the pool and the hour, and a rule naming users matches nobody
		// on this kind. Which names a client may resolve is the `dns` policy's
		// own business, along with the RPZ zones and the domain lists.
		//
		// The subject carries no target, because a dns listener has no upstream
		// pool -- it has a list of resolvers -- so there is nothing for a rule's
		// `targets` to name. A rule that wants to talk about where a query may
		// point is talking about a domain, and that belongs to the `dns` policy.
		Admit: func(client netip.Addr, verified bool) string {
			return admit.Client(admit.Deps{
				Lists: host.ThreatIntel(),
				// A behaviour pack holding this address out, where one is.
				Quarantined: host.Packs().Quarantined,
				Policy:      host.Authorization(),
				Logs:        host.Logs(),
				Matched:     func() { host.Counters().ThreatIntelMatched.Add(1) },
				Blocked:     func() { host.Counters().ThreatIntelBlocked.Add(1) },
			}, authorization.Subject{
				Listener: lc.Name,
				Kind:     "dns",
				Client:   client,
				Action:   authorization.ActionConnect,
			}, admit.Gate{
				Shadowing: lc.Shadowing,
				Record: func(reason, rule, detail string) {
					host.Counters().WouldRefuse("dns", reason)
					host.Shadow().Record("dns", lc.Name, reason, rule, detail)
				},
				Deny: func(reason, rule, detail string) {
					attrs := []any{"listener", lc.Name, "proto", "dns", "reason", reason}
					if rule != "" {
						attrs = append(attrs, "rule", rule)
					}
					if detail != "" {
						attrs = append(attrs, "detail", detail)
					}
					event(client, "dns_denied", verified, attrs...)
				},
			})
		},
		Banned: func(client netip.Addr) bool {
			bl := host.Bans()
			return bl != nil && bl.Banned(client)
		},
		Refuse: func(reason string) { host.Counters().Refuse("dns", reason) },
		// The imported threat lists, asked about the name. A domain list is
		// the useful kind here: a machine resolving a name somebody else
		// attributed is worth knowing about whatever its address, and the
		// address question belongs to the ban list, which does not take an
		// unverified datagram's word for who sent it.
		//
		// The event for a list that only logs carries no client address for
		// the same reason: a UDP source is unproven, so the fact is recorded
		// against the name rather than attributed to whoever the packet
		// claims to be from.
		Intel: func(name string) (string, bool) {
			set := host.ThreatIntel()
			if set == nil {
				return "", false
			}
			hit, ok := set.Match(intel.Subject{Domain: name})
			if !ok {
				return "", false
			}
			host.Counters().ThreatIntelMatched.Add(1)
			if hit.Action == intel.ActionBlock {
				host.Counters().ThreatIntelBlocked.Add(1)
				return hit.List, true
			}
			if set.Logs() {
				host.Logs().SecurityEvent(context.Background(), "allow", "threat_intel",
					"listener", lc.Name, "name", name, "list", hit.List, "kind", hit.Kind, "action", hit.Action)
			}
			return hit.List, false
		},
		// Shadow mode: the policy decides, the decision is written down,
		// and the query is answered as if it had been allowed.
		Shadow: func(reason, detail string) bool {
			if !lc.Shadowing() {
				return false
			}
			host.Counters().WouldRefuse("dns", reason)
			host.Shadow().Record("dns", lc.Name, reason, "", detail)
			return true
		},
	}
	startRPZ(host, lc, p)
	return wire.New(lc.Name, udp, tcp, lc.DNS.Cache.MaxEntries, lc.DNS.MaxInFlight, p, hooks), nil
}

// startRPZ watches the policy zone files, so a feed that is rewritten
// takes effect without a reload. A re-read that fails leaves the rules
// already in force and says so in the error log: a feed being replaced
// in place must not empty the policy for the moment that takes.
func startRPZ(host proxy.Host, lc config.Listener, p *wire.Policy) {
	if p.RPZ == nil {
		return
	}
	p.RPZ.Refresh(lc.DNS.RPZ.RefreshInterval(), func(err error) {
		host.Logs().Error.Warn("dns response policy zone could not be re-read; the rules already loaded stay in force",
			"listener", lc.Name, "error", err)
	})
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
