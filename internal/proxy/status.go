package proxy

import (
	"time"

	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/waf/wafstatus"
)

// The management view of the HTTP data plane.
//
// Most of it is here because it has nowhere else to be: a virtual patch,
// a honeytoken or a route quota is the plane's own invention and the
// engine, the management server and the control tool all speak it.
//
// What is deliberately absent is a type from internal/waf. The
// management API is served by every daemon, and a Coraza type in that
// surface would link the whole rule engine into the SSH bastion and the
// mail relay; the WAF report therefore lives in the leaf package
// internal/waf/wafstatus, which the plane fills in and everyone reads.
// The other data plane packages named here — geoip, icap, apiinv and
// the filters — are leaves the management client links in every daemon
// anyway, so their own types are used rather than copied.

// WAFRoute is one route's WAF assignment.
type WAFRoute struct {
	Route   string `json:"route"`
	Profile string `json:"profile"`
	Mode    string `json:"mode"`
	// BlockPercent is the share of clients in block mode (100 unless
	// the route rolls block mode out gradually); BlockCIDRs are the
	// canary prefixes always in block mode.
	BlockPercent int      `json:"block_percent"`
	BlockCIDRs   []string `json:"block_cidrs,omitempty"`
}

// WAFReport is the state of the web application firewall: what is
// configured, which routes use it, and what the rules have seen.
type WAFReport struct {
	Enabled  bool                      `json:"enabled"`
	Profiles []wafstatus.ProfileStatus `json:"profiles"`
	Routes   []WAFRoute                `json:"routes"`
	wafstatus.Report
}

// FilterStatus is the management view of one middleware instance.
type FilterStatus struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Stage  string `json:"stage"`
	Routes int    `json:"routes"`
	Denied uint64 `json:"denied"`
}

// QuotaReport is the usage view per tenant, route and rate limit policy
// (GET /v1/quotas). Counters are per configuration generation: a reload
// starts them over, as the per route metrics do.
type QuotaReport struct {
	Generated  time.Time      `json:"generated"`
	Generation uint64         `json:"generation"`
	Tenants    []TenantQuota  `json:"tenants"`
	Routes     []RouteQuota   `json:"routes"`
	RateLimits []PolicyQuota  `json:"rate_limits"`
	Upstreams  []UpstreamLoad `json:"upstreams"`
}

// TenantQuota aggregates the routes sharing a tenant label.
type TenantQuota struct {
	Tenant      string `json:"tenant"`
	Routes      int    `json:"routes"`
	Requests    uint64 `json:"requests"`
	Denied      uint64 `json:"denied"`
	RateLimited uint64 `json:"rate_limited"`
	BytesIn     uint64 `json:"bytes_in"`
	BytesOut    uint64 `json:"bytes_out"`
}

// RouteQuota is one route's usage.
type RouteQuota struct {
	Route       string `json:"route"`
	Tenant      string `json:"tenant,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
	Requests    uint64 `json:"requests"`
	Status2xx   uint64 `json:"status_2xx"`
	Status3xx   uint64 `json:"status_3xx"`
	Status4xx   uint64 `json:"status_4xx"`
	Status5xx   uint64 `json:"status_5xx"`
	Denied      uint64 `json:"denied"`
	RateLimited uint64 `json:"rate_limited"`
	BytesIn     uint64 `json:"bytes_in"`
	BytesOut    uint64 `json:"bytes_out"`
	// Latency quantiles in milliseconds, estimated from the route's
	// duration histogram (0 without requests).
	LatencyP50MS float64 `json:"latency_p50_ms"`
	LatencyP95MS float64 `json:"latency_p95_ms"`
	LatencyP99MS float64 `json:"latency_p99_ms"`
}

// PolicyQuota is one rate limit policy's decisions and top consumers.
type PolicyQuota struct {
	Policy string `json:"policy"`
	Key    string `json:"key"`
	// Algorithm is token_bucket (rate, burst) or sliding_window (limit,
	// window); Distributed is approximate or exact.
	Algorithm   string  `json:"algorithm"`
	Distributed string  `json:"distributed"`
	Rate        float64 `json:"rate,omitempty"`
	Burst       int     `json:"burst,omitempty"`
	Limit       int     `json:"limit,omitempty"`
	Window      string  `json:"window,omitempty"`
	Keys        int     `json:"keys"`
	Allowed     uint64  `json:"allowed"`
	Denied      uint64  `json:"denied"`
	// Overflow counts decisions taken without a bucket because the key
	// table was full of active keys (a warning is logged as well).
	Overflow uint64            `json:"overflow,omitempty"`
	Top      []limits.KeyUsage `json:"top"`
}

// UpstreamLoad is one pool's request share.
type UpstreamLoad struct {
	Upstream string `json:"upstream"`
	Requests uint64 `json:"requests"`
	Errors   uint64 `json:"errors"`
	Active   int64  `json:"active"`
}

// PatchStatus is the management view of one virtual patch.
type PatchStatus struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	Action      string    `json:"action"`
	Status      int       `json:"status"`
	Enabled     bool      `json:"enabled"`
	Expired     bool      `json:"expired"`
	Expires     time.Time `json:"expires,omitempty"`
	Hits        uint64    `json:"hits"`
	LastHit     time.Time `json:"last_hit,omitempty"`
	Routes      []string  `json:"routes,omitempty"`
	Hosts       []string  `json:"hosts,omitempty"`
	Paths       []string  `json:"paths,omitempty"`
	Methods     []string  `json:"methods,omitempty"`
}

// HoneytokenStatus is one row of the management view.
type HoneytokenStatus struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Action      string    `json:"action"`
	Match       string    `json:"match"`
	Values      int       `json:"values"`
	Fields      []string  `json:"fields"`
	Hits        uint64    `json:"hits"`
	LastHit     time.Time `json:"last_hit,omitempty"`
}

// DeceiveStatus is one row of the management view.
type DeceiveStatus struct {
	Route  string `json:"route"`
	Status int    `json:"status"`
	Served uint64 `json:"served"`
	Marked bool   `json:"marked,omitempty"`
	Score  int    `json:"bot_score_at,omitempty"`
	Bytes  int    `json:"body_bytes"`
}

// DegradeStatus is one row of the management view.
type DegradeStatus struct {
	Name           string `json:"name"`
	Applied        uint64 `json:"applied"`
	BytesPerSecond int64  `json:"bytes_per_second,omitempty"`
	Delay          string `json:"delay,omitempty"`
	Close          bool   `json:"close,omitempty"`
}

// WSGuardStatus is one route's view in the management API.
type WSGuardStatus struct {
	Route       string `json:"route"`
	Connections uint64 `json:"connections"`
	Messages    uint64 `json:"messages"`
	Violations  uint64 `json:"violations"`
	Closed      uint64 `json:"closed"`
	Action      string `json:"action"`
}

// OriginCheckResult is one endpoint's origin-lock probe.
type OriginCheckResult struct {
	Upstream       string `json:"upstream"`
	Endpoint       string `json:"endpoint"`
	UnsignedStatus int    `json:"unsigned_status,omitempty"`
	SignedStatus   int    `json:"signed_status,omitempty"`
	UnsignedError  string `json:"unsigned_error,omitempty"`
	SignedError    string `json:"signed_error,omitempty"`
	// Verdict is enforced, not_enforced, inconclusive or unreachable.
	Verdict string `json:"verdict"`
}

// Mark is a client that hit a honeypot.
type Mark struct {
	Address string    `json:"address"`
	Route   string    `json:"route"`
	Hits    int       `json:"hits"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Expires time.Time `json:"expires"`
}
