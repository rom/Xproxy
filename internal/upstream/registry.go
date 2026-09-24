package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
)

// registryBodyLimit bounds the registry response read into memory.
const registryBodyLimit = 4 << 20

// resolveHTTP polls the registry URL and parses its response into endpoint
// specs. The format (list or consul) selects the parser.
func (d *discoverer) resolveHTTP(ctx context.Context) ([]endpointSpec, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.cfg.Name, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range d.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, registryBodyLimit))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry %s: status %d", d.cfg.Name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, registryBodyLimit))
	if err != nil {
		return nil, err
	}
	if d.cfg.Format == "consul" {
		return d.parseConsul(body)
	}
	return d.parseList(body)
}

// listEntry is one endpoint in the generic list format. An entry gives
// either a full address or a host and port; the discovery Port fills in a
// missing port and the discovery Weight a missing weight.
type listEntry struct {
	Address string `json:"address"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	Canary  bool   `json:"canary"`
}

func (d *discoverer) parseList(body []byte) ([]endpointSpec, error) {
	var entries []listEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("registry %s: %w", d.cfg.Name, err)
	}
	specs := make([]endpointSpec, 0, len(entries))
	for _, e := range entries {
		addr := e.Address
		if addr == "" && e.Host != "" {
			port := e.Port
			if port == 0 {
				port = d.cfg.Port
			}
			if port != 0 {
				addr = net.JoinHostPort(e.Host, strconv.Itoa(port))
			}
		}
		if !validAddr(addr) {
			continue
		}
		w := e.Weight
		if w < 1 {
			w = d.cfg.Weight
		}
		specs = append(specs, endpointSpec{address: addr, weight: clampWeight(w), canary: e.Canary || d.cfg.Canary})
	}
	return specs, nil
}

// consulEntry mirrors the parts of a Consul /v1/health/service entry that
// discovery reads.
type consulEntry struct {
	Node struct {
		Address string `json:"Address"`
	} `json:"Node"`
	Service struct {
		Address string `json:"Address"`
		Port    int    `json:"Port"`
		Weights struct {
			Passing int `json:"Passing"`
		} `json:"Weights"`
	} `json:"Service"`
	Checks []struct {
		Status string `json:"Status"`
	} `json:"Checks"`
}

func (d *discoverer) parseConsul(body []byte) ([]endpointSpec, error) {
	var entries []consulEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("registry %s: %w", d.cfg.Name, err)
	}
	specs := make([]endpointSpec, 0, len(entries))
	for _, e := range entries {
		if !consulPassing(e.Checks) {
			continue
		}
		host := e.Service.Address
		if host == "" {
			host = e.Node.Address
		}
		port := e.Service.Port
		if port == 0 {
			port = d.cfg.Port
		}
		if host == "" || port == 0 {
			continue
		}
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		if !validAddr(addr) {
			continue
		}
		w := e.Service.Weights.Passing
		if w < 1 {
			w = d.cfg.Weight
		}
		specs = append(specs, endpointSpec{address: addr, weight: clampWeight(w), canary: d.cfg.Canary})
	}
	return specs, nil
}

// consulPassing reports whether every check on an instance is passing. An
// instance with no checks is treated as passing (registered without health
// checks), matching Consul's own default view.
func consulPassing(checks []struct {
	Status string `json:"Status"`
}) bool {
	for _, c := range checks {
		if c.Status != "passing" {
			return false
		}
	}
	return true
}

// validAddr reports whether addr is a host:port with a numeric port in range.
func validAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// joinHostPort is net.JoinHostPort with a numeric port, which is what
// every registry record carries.
func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func clampWeight(w int) int {
	if w < 1 {
		return 1
	}
	if w > 1000 {
		return 1000
	}
	return w
}
