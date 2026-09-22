package http

import (
	"context"
	"hash/fnv"
	"net/netip"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/netutil"
)

// splitWAF rolls block mode out gradually: a share of the clients, and
// every client in the canary prefixes, get the blocking filter; the rest
// get detect mode, which logs what block would have done. The choice is
// a stable function of the client address, so one client sees one
// behaviour and a problem can be reproduced.
type splitWAF struct {
	block, detect filter.Filter
	percent       int
	cidrs         []netip.Prefix
	name          string
}

func newSplitWAF(block, detect filter.Filter, rw *config.RouteWAF) *splitWAF {
	return &splitWAF{block: block, detect: detect, percent: rw.Percent(), cidrs: netutil.ParsePrefixes(rw.BlockCIDRs), name: block.Name() + ":gradual"}
}

func (s *splitWAF) Name() string { return s.name }

// enforced reports whether the client gets block mode.
func (s *splitWAF) enforced(ip netip.Addr) bool {
	if len(s.cidrs) > 0 && netutil.Contains(s.cidrs, ip) {
		return true
	}
	if s.percent <= 0 {
		return false
	}
	if s.percent >= 100 {
		return true
	}
	h := fnv.New32a()
	b := ip.Unmap().As16()
	_, _ = h.Write(b[:])
	return int(h.Sum32()%100) < s.percent
}

func (s *splitWAF) Begin(ctx context.Context, info *filter.Info) filter.Instance {
	if s.enforced(info.ClientIP) {
		return &taggedInstance{Instance: s.block.Begin(ctx, info), enforced: true}
	}
	return &taggedInstance{Instance: s.detect.Begin(ctx, info), enforced: false}
}

// taggedInstance adds the chosen mode to the access log.
type taggedInstance struct {
	filter.Instance
	enforced bool
}

func (t *taggedInstance) End() []any {
	return append(t.Instance.End(), "waf_enforced", t.enforced)
}
