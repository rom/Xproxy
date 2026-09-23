package proxy

import (
	"context"
	"github.com/rom/xproxy/internal/icap"
	"net/netip"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filters/accountguard"
	"github.com/rom/xproxy/internal/filters/botscore"
	"github.com/rom/xproxy/internal/geoip"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/metrics"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/upstream"
)

// A Plane is a listener kind whose listeners share one compiled
// generation rather than each holding their own: one route table, one
// WAF engine, one response cache, one set of rate limiters. There is
// one — the HTTP data plane — and this interface is how the engine
// holds it without importing it.
//
// Everything a Kind needs is in Host and the optional interfaces beside
// it. A Plane needs more, and the list below is exactly how much more:
// it is the coupling between the engine and the data plane it grew out
// of, written down rather than spread across a package boundary that
// does not exist.
type Plane interface {
	// Prepare compiles a generation against what the engine built for
	// the same one. Everything that can fail happens here, before
	// anything is swapped; commit installs it and discard releases what
	// was built.
	Prepare(g Generation) (commit, discard func(), err error)
	// Start begins whatever the live generation runs in the background.
	Start()
	// Stop releases the live generation.
	Stop(ctx context.Context)
	// Snapshot adds the plane's own counters and gauges to a snapshot.
	Snapshot(*Snapshot)
	// Collect emits the plane's metric families.
	Collect(metrics.Collector)
	// PeerEvent applies a cluster peer's event (a honeypot mark, a
	// revoked session): the engine owns the connection, the plane owns
	// the tables the event lands in.
	PeerEvent(e cluster.Event, peer string)
	// RateSource is the cluster's view of this plane's rate limiters.
	// A daemon with no plane shares no rate limits, which is the right
	// answer for one that applies none.
	cluster.RateSource

	PlaneStatus
}

// Generation is one configuration generation as the engine derives it,
// handed to the plane that compiles the rest of it.
type Generation struct {
	Config  *config.Config
	Number  uint64
	Pools   map[string]*upstream.Pool
	Trusted []netip.Prefix
	// ICAP is the scanning services of this generation, by name. The
	// engine builds them because kinds outside the plane use them too.
	ICAP map[string]*icap.Service

	// Retire releases the generation this one supersedes — its upstream
	// pools and the transports they hold. The plane calls it once the
	// last request compiled against the old generation has finished,
	// because only the plane can see them: a pool closed under a
	// streaming response cuts it. It is called at most once, and not at
	// all when the generation is discarded rather than committed. It is
	// nil for the first generation, which supersedes nothing.
	Retire func()
}

// PlaneStatus is the management view of the data plane. The engine's
// own status methods delegate here and answer zero values when this
// binary linked no plane, so `xproxyctl waf` against a bastion reports
// an empty WAF rather than failing.
type PlaneStatus interface {
	WAF(top int) WAFReport
	WAFExclusions() string
	WAFReset()
	Filters() []FilterStatus
	GeoIP() (geoip.Status, bool)
	CacheStats() (cache.Stats, bool)
	PurgeCache(host, prefix string) (int, bool)
	Quotas(top int) QuotaReport
	VirtualPatches() []PatchStatus
	Honeytokens() []HoneytokenStatus
	Deceptions() []DeceiveStatus
	Degradation() []DegradeStatus
	WebSocketGuards() []WSGuardStatus
	Decoys() []string
	HoneypotMarks() []Mark
	HoneypotMarksDropped() uint64
	UnmarkHoneypot(ip netip.Addr) bool
	Maintenance(on *bool) (state, configured bool)
	OriginCheck(upstreamName, host, path string) ([]OriginCheckResult, error)
	Accounts(top int) accountguard.Report
	BotScore(top int) botscore.Report
	APIInventory(view string, top int) apiinv.Report
	// Tracing is the tracer status, nil when tracing is off.
	Tracing() *tracing.Status
}

// Cluster returns the cluster node, or nil when clustering is not
// configured.
func (s *Server) Cluster() *cluster.Node { return s.cluster.Load() }

// newPlane builds the linked data plane, or nil.
var newPlane func(Host) (Plane, error)

// RegisterPlane records the constructor of the data plane this binary
// links. It is called from the plane's own package init, and panics on
// a second one: two data planes in one process would each compile the
// routes and each believe it owned them.
func RegisterPlane(build func(Host) (Plane, error)) {
	if newPlane != nil {
		panic("proxy: a second data plane was registered")
	}
	newPlane = build
}

// Plane is the data plane this binary linked, or nil. The management
// views go through the delegating methods rather than this; it is here
// for the kind that owns the plane, which needs the object itself.
func (s *Server) Plane() Plane { return s.planeOrNil() }

// plane returns the live plane, or nil when this binary linked none.
func (s *Server) planeOrNil() Plane {
	if p := s.plane.Load(); p != nil {
		return *p
	}
	return nil
}

// rateSource routes the cluster's rate limit questions to the plane.
// Without one the node shares nothing, rather than reporting zeroes it
// would then subtract from a limiter that does not exist.
type rateSource struct{ s *Server }

func (r rateSource) Flush(limit int) map[string]map[string]float64 {
	if p := r.s.planeOrNil(); p != nil {
		return p.Flush(limit)
	}
	return nil
}

func (r rateSource) Report(peer, policy string, reports []limits.PeerReport) {
	if p := r.s.planeOrNil(); p != nil {
		p.Report(peer, policy, reports)
	}
}

func (r rateSource) Decide(policy, key string, n float64) (allowed, ok bool) {
	if p := r.s.planeOrNil(); p != nil {
		return p.Decide(policy, key, n)
	}
	return false, false
}

// Event kinds the engine itself publishes and consumes. A data plane's
// filters use their own, and reach them through the bus the plane keeps
// per generation.
const eventTicketKeys = "ticket_keys"

// publishEvent hands an event to the cluster node when there is one.
func (s *Server) publishEvent(e cluster.Event) {
	if node := s.cluster.Load(); node != nil {
		node.PublishEvent(e)
	}
}

// PublishEvent implements Host: a kind shares a fact with the cluster
// without holding the node.
func (s *Server) PublishEvent(e cluster.Event) { s.publishEvent(e) }

// onClusterEvent applies an event a peer sent. The engine answers for
// what it owns — the session ticket keys — and hands everything else
// to the data plane, whose tables the rest of them land in.
func (s *Server) onClusterEvent(e cluster.Event, peer string) {
	if e.Kind == eventTicketKeys {
		if s.tickets != nil && !s.tickets.PeerFingerprint(peer, e.Key) {
			s.ticketMismatch.Hit(s.logs.Error,
				"session ticket keys differ from a peer; tickets will not resume across these nodes (check the shared secret file and clocks)",
				"peer", peer, "peer_fingerprint", e.Key, "fingerprint", s.tickets.Fingerprint())
		}
		return
	}
	if pl := s.planeOrNil(); pl != nil {
		pl.PeerEvent(e, peer)
	}
}
