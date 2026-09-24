package upstream

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// consulAgent is a stand-in for the agent: it answers /v1/health/service
// with whatever the test currently says is healthy, carries an index, and
// records whether each request was a blocking one.
type consulAgent struct {
	srv      *httptest.Server
	mu       chan struct{}
	body     atomic.Pointer[string]
	index    atomic.Uint64
	queries  atomic.Int64
	blocking atomic.Int64
	lastURL  atomic.Pointer[url.URL]
	token    atomic.Pointer[string]
}

func startConsul(t *testing.T, instances ...string) *consulAgent {
	t.Helper()
	a := &consulAgent{mu: make(chan struct{}, 1)}
	a.set(instances...)
	a.index.Store(7)
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.queries.Add(1)
		u := *r.URL
		a.lastURL.Store(&u)
		tok := r.Header.Get("X-Consul-Token")
		a.token.Store(&tok)
		if r.URL.Query().Get("index") != "" {
			a.blocking.Add(1)
		}
		w.Header().Set("X-Consul-Index", fmt.Sprint(a.index.Load()))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(*a.body.Load()))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// set replaces the healthy instances, as "host:port" strings.
func (a *consulAgent) set(instances ...string) {
	entries := make([]map[string]any, 0, len(instances))
	for _, in := range instances {
		host, port, _ := strings.Cut(in, ":")
		var p int
		_, _ = fmt.Sscanf(port, "%d", &p)
		entries = append(entries, map[string]any{
			"Node":    map[string]any{"Address": host},
			"Service": map[string]any{"Address": host, "Port": p, "Weights": map[string]any{"Passing": 1}},
			"Checks":  []map[string]any{{"Status": "passing"}},
		})
	}
	b, _ := json.Marshal(entries)
	s := string(b)
	a.body.Store(&s)
	a.index.Add(1)
}

func (a *consulAgent) addr() string { return strings.TrimPrefix(a.srv.URL, "http://") }

// consulPool builds a pool discovering through the agent.
func consulPool(t *testing.T, a *consulAgent, tweak func(*config.ConsulDiscovery)) *Pool {
	t.Helper()
	c := &config.Upstream{Name: "t", Balancer: "round_robin", Scheme: "http",
		Timeouts:            config.UpstreamTimeout{Connect: config.Duration(time.Second), ResponseHeader: config.Duration(time.Second), Idle: config.Duration(time.Second), Total: config.Duration(time.Second)},
		MaxIdleConnsPerHost: 2,
		Discovery: &config.Discovery{Type: "consul", Interval: config.Duration(50 * time.Millisecond),
			Timeout: config.Duration(2 * time.Second), Weight: 1,
			Consul: &config.ConsulDiscovery{Address: a.addr(), Service: "web", Wait: config.Duration(time.Second)}},
	}
	if tweak != nil {
		tweak(c.Discovery.Consul)
	}
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func eventuallyAddrs(t *testing.T, p *Pool, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := strings.Join(addresses(p), ","); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("endpoints are %v, want %s", addresses(p), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The first query asks for the current state and every later one blocks
// on the index -- which is the whole reason for a Consul type rather than
// a polled URL: the answer arrives when something changes.
func TestConsulUsesBlockingQueries(t *testing.T) {
	a := startConsul(t, "10.0.0.1:8080")
	p := consulPool(t, a, nil)
	p.Start()
	defer p.Stop()
	eventuallyAddrs(t, p, "10.0.0.1:8080")

	deadline := time.Now().Add(5 * time.Second)
	for a.blocking.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no query carried an index: the discovery is polling, not blocking")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The query asks only for passing instances: a critical instance is
	// in the catalogue and is not somewhere to send traffic.
	if u := a.lastURL.Load(); u == nil || u.Query().Get("passing") != "true" {
		t.Fatalf("query was %v, want passing=true", u)
	}
}

// An instance that goes away leaves the pool, and a new one joins it.
func TestConsulFollowsTheService(t *testing.T) {
	a := startConsul(t, "10.0.0.1:8080", "10.0.0.2:8080")
	p := consulPool(t, a, nil)
	p.Start()
	defer p.Stop()
	eventuallyAddrs(t, p, "10.0.0.1:8080,10.0.0.2:8080")
	a.set("10.0.0.2:8080", "10.0.0.3:8080")
	eventuallyAddrs(t, p, "10.0.0.2:8080,10.0.0.3:8080")
}

// The tag, the datacenter and the token reach the agent. The token comes
// from a file because a token in the configuration is a credential in
// the management API's output and in the history.
func TestConsulQueryCarriesTagDatacenterAndToken(t *testing.T) {
	a := startConsul(t, "10.0.0.1:8080")
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := consulPool(t, a, func(c *config.ConsulDiscovery) {
		c.Tag = "prod"
		c.Datacenter = "dc2"
		c.TokenFile = tokenFile
	})
	p.Start()
	defer p.Stop()
	eventuallyAddrs(t, p, "10.0.0.1:8080")
	u := a.lastURL.Load()
	if u == nil || u.Query().Get("tag") != "prod" || u.Query().Get("dc") != "dc2" {
		t.Fatalf("query was %v", u)
	}
	if tok := a.token.Load(); tok == nil || *tok != "s3cr3t" {
		t.Fatalf("token was %v; it must be trimmed of the newline a file ends with", tok)
	}
}

// A token file that cannot be read is a configuration error, not
// something to discover on the first query.
func TestConsulRefusesAnUnreadableTokenFile(t *testing.T) {
	a := startConsul(t, "10.0.0.1:8080")
	c := &config.Upstream{Name: "t", Balancer: "round_robin", Scheme: "http",
		Timeouts:            config.UpstreamTimeout{Connect: config.Duration(time.Second), ResponseHeader: config.Duration(time.Second), Idle: config.Duration(time.Second), Total: config.Duration(time.Second)},
		MaxIdleConnsPerHost: 2,
		Discovery: &config.Discovery{Type: "consul", Interval: config.Duration(time.Second), Timeout: config.Duration(time.Second), Weight: 1,
			Consul: &config.ConsulDiscovery{Address: a.addr(), Service: "web", Wait: config.Duration(time.Second),
				TokenFile: filepath.Join(t.TempDir(), "missing")}},
	}
	if _, err := NewPool(c, nolog); err == nil {
		t.Fatal("a pool with an unreadable token file was built")
	}
}

// An agent that is unreachable is retried on the interval rather than in
// a tight loop: without the pause, a down agent or a 403 would be asked
// again immediately and forever, which is a loop against somebody else's
// machine.
func TestConsulDoesNotSpinOnAFailure(t *testing.T) {
	a := startConsul(t, "10.0.0.1:8080")
	p := consulPool(t, a, nil)
	p.Start()
	defer p.Stop()
	eventuallyAddrs(t, p, "10.0.0.1:8080")
	a.srv.Close() // every later query fails
	before := a.queries.Load()
	time.Sleep(300 * time.Millisecond)
	// With a 50ms interval, six or seven attempts in 300ms is the pause
	// working; hundreds would be a spin.
	if n := a.queries.Load() - before; n > 30 {
		t.Fatalf("%d queries in 300ms against a dead agent", n)
	}
	// And the endpoints are kept: a failed resolution never empties a
	// pool.
	if got := addresses(p); len(got) != 1 {
		t.Fatalf("endpoints after the agent died: %v", got)
	}
}

// An index that goes backwards -- what a Consul server restart produces
// -- must not leave the proxy blocking on an index that will never be
// reached.
func TestConsulResetsAnIndexThatWentBackwards(t *testing.T) {
	a := startConsul(t, "10.0.0.1:8080")
	p := consulPool(t, a, nil)
	p.Start()
	defer p.Stop()
	eventuallyAddrs(t, p, "10.0.0.1:8080")
	a.index.Store(1) // the restart
	a.set("10.0.0.9:8080")
	eventuallyAddrs(t, p, "10.0.0.9:8080")
}
