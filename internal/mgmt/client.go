package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/acme"
	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/filters/accountguard"
	"github.com/rom/xproxy/internal/filters/botscore"
	"github.com/rom/xproxy/internal/fleet"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/upstream"
)

// Client talks to the management API over the Unix socket.
type Client struct {
	http *http.Client
}

// NewClient creates a client for the socket at path.
func NewClient(path string) *Client {
	return &Client{http: &http.Client{
		Timeout: 6 * time.Minute,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
			DisableKeepAlives: true,
		},
	}}
}

func (c *Client) do(method, path string, out any) error {
	return c.doBody(method, path, nil, out)
}

func (c *Client) doBody(method, path string, payload any, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var rd io.Reader = http.NoBody
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://xproxy"+path, rd)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("management API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		var r result
		if json.Unmarshal(body, &r) == nil && r.Error != "" {
			return fmt.Errorf("%s", r.Error)
		}
		return fmt.Errorf("management API: HTTP %d", resp.StatusCode)
	}
	switch o := out.(type) {
	case nil:
	case *[]byte:
		*o = body
	default:
		return json.Unmarshal(body, out)
	}
	return nil
}

// Do performs an arbitrary call. payload (if not nil) is sent as JSON; out
// receives the decoded body, or the raw body when it is a *[]byte.
func (c *Client) Do(method, path string, payload, out any) error {
	return c.doBody(method, path, payload, out)
}

// Status fetches /v1/status.
func (c *Client) Status() (*Status, error) {
	var s Status
	return &s, c.do("GET", "/v1/status", &s)
}

// Raw fetches a GET endpoint and returns the body.
func (c *Client) Raw(path string) ([]byte, error) {
	var b []byte
	return b, c.do("GET", path, &b)
}

// Ready fetches the readiness verdict. It is the one call that treats a
// non-2xx answer as an answer rather than an error: /v1/ready reports 503
// when the node should not be carrying traffic, so that an HTTP health
// check that reads neither JSON nor exit codes still works, and a client
// that mistook that for an unreachable daemon would move an address for
// the wrong reason.
func (c *Client) Ready(requireUpstreams, requireUndegraded bool) (*proxy.Readiness, error) {
	q := "/v1/ready?require_upstreams=0&require_undegraded=0"
	if requireUpstreams {
		q = strings.Replace(q, "require_upstreams=0", "require_upstreams=1", 1)
	}
	if requireUndegraded {
		q = strings.Replace(q, "require_undegraded=0", "require_undegraded=1", 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://xproxy"+q, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("management API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 && resp.StatusCode != 503 {
		return nil, fmt.Errorf("management API: HTTP %d", resp.StatusCode)
	}
	var out proxy.Readiness
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Post triggers an action endpoint.
func (c *Client) Post(path string) error {
	return c.do("POST", path, nil)
}

// ClusterStatus fetches /v1/cluster.
func (c *Client) ClusterStatus() (*cluster.Status, error) {
	var st cluster.Status
	return &st, c.do("GET", "/v1/cluster", &st)
}

// APIInventory fetches the inventory view.
func (c *Client) APIInventory(view string, top int) (*apiinv.Report, error) {
	var rep apiinv.Report
	return &rep, c.do("GET", fmt.Sprintf("/v1/api?view=%s&top=%d", url.QueryEscape(view), top), &rep)
}

// Maintenance queries (on nil) or sets the runtime maintenance state.
func (c *Client) Maintenance(on *bool) (*MaintenanceStatus, error) {
	var st MaintenanceStatus
	if on == nil {
		return &st, c.do("GET", "/v1/maintenance", &st)
	}
	return &st, c.doBody("POST", "/v1/maintenance", MaintenanceRequest{On: *on}, &st)
}

// Capture queries (on nil) or sets the runtime packet capture state.
// A non-zero d bounds the recording window.
func (c *Client) Capture(on *bool, d time.Duration) (*capture.Stats, error) {
	var st capture.Stats
	if on == nil {
		return &st, c.do("GET", "/v1/capture", &st)
	}
	req := CaptureRequest{Active: *on}
	if d > 0 {
		req.Duration = d.String()
	}
	return &st, c.doBody("POST", "/v1/capture", req, &st)
}

// BotScore fetches the learning-mode bot_score baselines.
func (c *Client) BotScore(top int) (*botscore.Report, error) {
	var rep botscore.Report
	return &rep, c.do("GET", fmt.Sprintf("/v1/botscore?top=%d", top), &rep)
}

// OriginCheck probes the configured origins directly to verify origin-lock
// enforcement. upstream, host and path are optional filters and overrides.
func (c *Client) OriginCheck(upstream, host, path string) ([]proxy.OriginCheckResult, error) {
	q := url.Values{}
	if upstream != "" {
		q.Set("upstream", upstream)
	}
	if host != "" {
		q.Set("host", host)
	}
	if path != "" {
		q.Set("path", path)
	}
	var res []proxy.OriginCheckResult
	return res, c.do("GET", "/v1/origin-check?"+q.Encode(), &res)
}

// Accounts fetches the account guard view with up to top blocks per
// endpoint.
func (c *Client) Accounts(top int) (*accountguard.Report, error) {
	var rep accountguard.Report
	return &rep, c.do("GET", fmt.Sprintf("/v1/accounts?top=%d", top), &rep)
}

// APISkeleton fetches the inventory view as an OpenAPI skeleton (YAML).
func (c *Client) APISkeleton(view string, top int, title string) ([]byte, error) {
	var b []byte
	return b, c.do("GET", fmt.Sprintf("/v1/api?view=%s&top=%d&format=openapi&title=%s", url.QueryEscape(view), top, url.QueryEscape(title)), &b)
}

// Patches fetches the virtual patches with their counters.
func (c *Client) Patches() ([]proxy.PatchStatus, error) {
	var out []proxy.PatchStatus
	return out, c.do("GET", "/v1/patches", &out)
}

// FleetStatus fetches the fleet agent view.
func (c *Client) FleetStatus() (*fleet.AgentStatus, error) {
	var st fleet.AgentStatus
	return &st, c.do("GET", "/v1/fleet", &st)
}

// Upstreams fetches endpoint statistics per upstream.
func (c *Client) Upstreams() (map[string][]upstream.Stats, error) {
	var out map[string][]upstream.Stats
	return out, c.do("GET", "/v1/upstreams", &out)
}

// Drains fetches the recorded drain and maintenance decisions.
func (c *Client) Drains() (upstream.Decisions, error) {
	var out upstream.Decisions
	return out, c.do("GET", "/v1/drain", &out)
}

// Drain records a decision to stop sending new work to one endpoint of a
// pool, or with an empty address to the whole pool. Nothing is closed.
func (c *Client) Drain(pool, address string, draining bool) (string, error) {
	var res struct {
		Note string `json:"note"`
	}
	err := c.doBody("POST", "/v1/drain", DrainRequest{Pool: pool, Address: address, Drain: draining}, &res)
	return res.Note, err
}

// ACME fetches managed certificate status.
func (c *Client) ACME() ([]acme.CertStatus, error) {
	var out []acme.CertStatus
	return out, c.do("GET", "/v1/acme", &out)
}

// ICAP fetches the status of ICAP services.
// CachePurge removes cached responses for a host (all when "") whose
// path starts with prefix; it returns the number removed.
func (c *Client) CachePurge(host, prefix string) (int, error) {
	var out struct {
		Removed int `json:"removed"`
	}
	err := c.doBody("DELETE", "/v1/cache?host="+url.QueryEscape(host)+"&path="+url.QueryEscape(prefix), nil, &out)
	return out.Removed, err
}

// Filters fetches /v1/filters.
func (c *Client) Filters() (*FiltersView, error) {
	var out FiltersView
	return &out, c.do("GET", "/v1/filters", &out)
}

func (c *Client) ICAP() ([]icap.Status, error) {
	var out []icap.Status
	return out, c.do("GET", "/v1/icap", &out)
}

// Metrics fetches the Prometheus exposition.
func (c *Client) Metrics() ([]byte, error) {
	var b []byte
	return b, c.do("GET", "/metrics", &b)
}

// Series fetches sampled series since the given duration ago.
func (c *Client) Series(since time.Duration, limit int) (*SeriesResponse, error) {
	var out SeriesResponse
	q := "/v1/series?since=" + since.String()
	if limit > 0 {
		q += "&limit=" + strconv.Itoa(limit)
	}
	return &out, c.do("GET", q, &out)
}

// Sessions lists the sessions this daemon is serving now.
func (c *Client) Sessions() ([]sessions.View, error) {
	var out []sessions.View
	return out, c.do("GET", "/v1/sessions", &out)
}

// KillSessions closes one session by id, or every session matching a
// filter, and returns what it closed.
func (c *Client) KillSessions(id, kind, listener, user string) ([]sessions.View, error) {
	q := url.Values{}
	for k, v := range map[string]string{"id": id, "kind": kind, "listener": listener, "user": user} {
		if v != "" {
			q.Set(k, v)
		}
	}
	var out []sessions.View
	return out, c.doBody("DELETE", "/v1/sessions?"+q.Encode(), nil, &out)
}

// AssetQuery is the filter a caller puts on the inventory. Every field is
// optional and an empty query is the whole list.
type AssetQuery struct {
	ID       string // one asset, by identifier, address or hardware address
	Role     string
	Listener string
	Proto    string
	Vendor   string
	New      bool
	Changed  bool
	Top      int
}

func (q AssetQuery) values() url.Values {
	v := url.Values{}
	for k, s := range map[string]string{"id": q.ID, "role": q.Role,
		"listener": q.Listener, "proto": q.Proto, "vendor": q.Vendor} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if q.New {
		v.Set("new", "1")
	}
	if q.Changed {
		v.Set("changed", "1")
	}
	// A count is sent as given, including a nonsense one. The server is
	// where a query is validated, and a client that quietly dropped a bad
	// value would answer a filter the caller did not ask for.
	if q.Top != 0 {
		v.Set("top", strconv.Itoa(q.Top))
	}
	return v
}

// Assets is the device inventory, filtered.
func (c *Client) Assets(q AssetQuery) (*AssetReport, error) {
	var out AssetReport
	return &out, c.do("GET", "/v1/assets?"+q.values().Encode(), &out)
}

// Asset is one device, looked up by whatever a log line happened to carry.
func (c *Client) Asset(key string) (*assets.Asset, error) {
	var out assets.Asset
	return &out, c.do("GET", "/v1/assets?id="+url.QueryEscape(key), &out)
}

// FreezeAssets takes the current inventory as the estate's baseline.
func (c *Client) FreezeAssets() (map[string]any, error) {
	var out map[string]any
	return out, c.doBody("POST", "/v1/assets/baseline", nil, &out)
}

// ThawAssets forgets the baseline.
func (c *Client) ThawAssets() (map[string]any, error) {
	var out map[string]any
	return out, c.doBody("DELETE", "/v1/assets/baseline", nil, &out)
}

// PolicyReport is what the listeners in shadow mode would have refused.
func (c *Client) PolicyReport() (*PolicyReport, error) {
	var out PolicyReport
	return &out, c.do("GET", "/v1/policy", &out)
}

// ResetPolicyReport empties the ledger.
func (c *Client) ResetPolicyReport() error { return c.do("DELETE", "/v1/policy", nil) }

// Bans lists active bans.
func (c *Client) Bans() ([]ban.Entry, error) {
	var out []ban.Entry
	return out, c.do("GET", "/v1/bans", &out)
}

// Ban adds a ban.
func (c *Client) Ban(target, duration, reason string) (*ban.Entry, error) {
	var e ban.Entry
	return &e, c.doBody("POST", "/v1/bans", BanRequest{Target: target, Duration: duration, Reason: reason}, &e)
}

// Unban removes a ban.
func (c *Client) Unban(target string) error {
	return c.do("DELETE", "/v1/bans?target="+url.QueryEscape(target), nil)
}

// MFA lists every listener that asks for a second factor, with who is
// enrolled and what this process remembers about them.
func (c *Client) MFA() ([]proxy.MFAListener, error) {
	var out []proxy.MFAListener
	return out, c.do("GET", "/v1/mfa", &out)
}

// MFAEnrol gives a person a second factor on a listener. What comes
// back can be shown once and never again: the secret, the URI an
// authenticator reads, and the recovery codes.
func (c *Client) MFAEnrol(listener, user, issuer string, digits, period int, algo string) (*MFAEnrolled, error) {
	var out MFAEnrolled
	req := mfaRequest{Listener: listener, User: user, Issuer: issuer,
		Digits: digits, Period: period, Algo: algo}
	return &out, c.doBody("POST", "/v1/mfa/enrol", req, &out)
}

// MFARecovery replaces a person's recovery codes and returns the new
// ones, which is the other thing shown once.
func (c *Client) MFARecovery(listener, user string) (*MFAEnrolled, error) {
	var out MFAEnrolled
	return &out, c.doBody("POST", "/v1/mfa/recovery",
		mfaRequest{Listener: listener, User: user}, &out)
}

// MFARemove takes a person's second factor away.
func (c *Client) MFARemove(listener, user string) error {
	return c.doBody("POST", "/v1/mfa/remove",
		mfaRequest{Listener: listener, User: user}, nil)
}

// MFAUnlock lets a person try again after too many wrong codes.
func (c *Client) MFAUnlock(listener, user string) error {
	return c.doBody("POST", "/v1/mfa/unlock",
		mfaRequest{Listener: listener, User: user}, nil)
}
