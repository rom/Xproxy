package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/tlsconf"
)

// Consul as a first-class discovery type rather than a URL to poll.
//
// The difference that earns the type is the blocking query. A Consul
// agent will hold a request open until the answer changes, and hand back
// an index the next request carries; the effect is a long poll, so an
// instance that goes away leaves the pool in about the time Consul takes
// to notice rather than up to a polling interval later. For a load
// balancer that gap is the whole point: a polled registry sends traffic
// to a machine that is already gone for as long as the interval lasts.
//
// Everything else the type does is spelling: building the URL from a
// service name instead of asking an operator to write
// /v1/health/service/name?passing=true, reading the token from a file
// because a token in the configuration is a credential in the management
// API's output and in the history, and defaulting the agent to the local
// one, which is where a Consul deployment puts it.

// consulClient talks to one agent about one service.
type consulClient struct {
	base    string // scheme://host:port
	service string
	query   url.Values
	token   string
	wait    time.Duration
	http    *http.Client
	// index is the Consul index of the last answer, carried into the
	// next request to make it a blocking one. Zero on the first call,
	// which asks for the current state without blocking.
	index atomic.Uint64
}

// newConsulClient builds the client from configuration. It reads the
// token file at build time: a token that cannot be read is a
// configuration error, not something to discover on the first query.
func newConsulClient(cfg config.Discovery) (*consulClient, error) {
	c := cfg.Consul
	if c == nil {
		return nil, fmt.Errorf("discovery type consul needs a consul section")
	}
	scheme := "http"
	tr := &http.Transport{Proxy: nil}
	if c.TLS != nil {
		tc, _, err := tlsconf.Client(c.TLS)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = tc
		scheme = "https"
	}
	cl := &consulClient{
		base:    scheme + "://" + c.Address,
		service: c.Service,
		query:   url.Values{},
		wait:    c.Wait.D(),
		// No per-client timeout: a blocking query is meant to hang, and
		// the bound on one is the context the caller passes.
		http: &http.Client{Transport: tr},
	}
	// Only passing instances. A critical one is in the catalogue and is
	// not somewhere to send traffic, and the whole point of asking
	// Consul rather than DNS is that it knows the difference.
	cl.query.Set("passing", "true")
	if c.Tag != "" {
		cl.query.Set("tag", c.Tag)
	}
	if c.Datacenter != "" {
		cl.query.Set("dc", c.Datacenter)
	}
	if c.AllowStale {
		cl.query.Set("stale", "")
	}
	if c.TokenFile != "" {
		b, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("consul token_file: %w", err)
		}
		cl.token = strings.TrimSpace(string(b))
		if cl.token == "" {
			return nil, fmt.Errorf("consul token_file %s is empty", c.TokenFile)
		}
	}
	return cl, nil
}

// resolve asks the agent. The first call returns the current state at
// once; later calls block until the answer changes or the wait expires,
// which is what makes a change arrive when it happens.
func (c *consulClient) resolve(ctx context.Context, defaultPort, weight int, canary bool) ([]endpointSpec, error) {
	q := url.Values{}
	for k, v := range c.query {
		q[k] = v
	}
	if idx := c.index.Load(); idx > 0 {
		q.Set("index", strconv.FormatUint(idx, 10))
		q.Set("wait", consulWait(c.wait))
	}
	u := c.base + "/v1/health/service/" + url.PathEscape(c.service) + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("X-Consul-Token", c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, registryBodyLimit))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("consul %s: status %d", c.service, resp.StatusCode)
	}
	// The index comes back in a header and is carried into the next
	// query. Consul says to treat an index that goes backwards -- which a
	// server restart produces -- as a reset, or every later query blocks
	// forever against an index that will never be reached.
	if v := resp.Header.Get("X-Consul-Index"); v != "" {
		if idx, err := strconv.ParseUint(v, 10, 64); err == nil {
			if idx < c.index.Load() || idx < 1 {
				idx = 1
			}
			c.index.Store(idx)
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, registryBodyLimit))
	if err != nil {
		return nil, err
	}
	var entries []consulEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("consul %s: %w", c.service, err)
	}
	specs := make([]endpointSpec, 0, len(entries))
	for _, e := range entries {
		// passing=true already filtered, but an entry whose checks say
		// otherwise is not somewhere to send traffic whatever the query
		// asked for: the filter is the agent's and this is ours.
		if !consulPassing(e.Checks) {
			continue
		}
		host := e.Service.Address
		if host == "" {
			host = e.Node.Address
		}
		port := e.Service.Port
		if port == 0 {
			port = defaultPort
		}
		if host == "" || port == 0 {
			continue
		}
		addr := joinHostPort(host, port)
		if !validAddr(addr) {
			continue
		}
		w := e.Service.Weights.Passing
		if w < 1 {
			w = weight
		}
		specs = append(specs, endpointSpec{address: addr, weight: clampWeight(w), canary: canary})
	}
	return specs, nil
}

// consulWait formats the wait the way Consul expects it, in seconds.
func consulWait(d time.Duration) string {
	if d <= 0 {
		d = 5 * time.Minute
	}
	return strconv.Itoa(int(d.Seconds())) + "s"
}
