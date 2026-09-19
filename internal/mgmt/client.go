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
	"time"

	"github.com/rom/xproxy/internal/acme"
	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/filters/accountguard"
	"github.com/rom/xproxy/internal/fleet"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/proxy"
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
