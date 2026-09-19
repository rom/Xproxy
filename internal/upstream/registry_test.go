package upstream

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func httpDisc(url, format string) *config.Discovery {
	return &config.Discovery{Type: "http", Name: url, Format: format, Port: 8080,
		Interval: config.Duration(time.Hour), Timeout: config.Duration(2 * time.Second), Weight: 1}
}

func TestDiscoveryHTTPList(t *testing.T) {
	var token atomic.Value
	body := `[
		{"address": "10.0.0.1:9000", "weight": 5},
		{"host": "10.0.0.2", "canary": true},
		{"host": "10.0.0.3", "port": 9100},
		{"address": "10.0.0.1:9000"},
		{"address": "garbage"}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token.Store(r.Header.Get("X-Consul-Token"))
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	disc := httpDisc(srv.URL, "list")
	disc.Headers = map[string]string{"X-Consul-Token": "s3cret"}
	u := upstreamCfg(disc)
	u.Canary = &config.Canary{Percent: 10}
	p, err := NewPool(u, dlog)
	if err != nil {
		t.Fatal(err)
	}
	p.ResolveNowForTest()

	got := addresses(p)
	// The bad address is dropped and the duplicate collapsed; the missing
	// port is filled from discovery.port, the explicit one kept.
	if len(got) != 3 || got[0] != "10.0.0.1:9000" || got[1] != "10.0.0.2:8080" || got[2] != "10.0.0.3:9100" {
		t.Fatalf("endpoints %v", got)
	}
	if tok, _ := token.Load().(string); tok != "s3cret" {
		t.Fatalf("auth header not sent: %q", tok)
	}
	for _, e := range p.Endpoints() {
		switch e.Address {
		case "10.0.0.1:9000":
			if e.Weight != 5 {
				t.Fatalf("explicit weight %d", e.Weight)
			}
		case "10.0.0.2:8080":
			if !e.Canary {
				t.Fatal("canary flag lost")
			}
		}
	}
	st := p.Status()
	if st.Discovery == nil || st.Discovery.Type != "http" || st.Discovery.Endpoints != 3 {
		t.Fatalf("status %+v", st.Discovery)
	}
}

func TestDiscoveryHTTPConsul(t *testing.T) {
	body := `[
		{"Node":{"Address":"10.1.0.9"},"Service":{"Address":"10.1.0.1","Port":8500,"Weights":{"Passing":3}},"Checks":[{"Status":"passing"}]},
		{"Node":{"Address":"10.1.0.9"},"Service":{"Address":"","Port":8600,"Weights":{"Passing":1}},"Checks":[{"Status":"passing"}]},
		{"Node":{"Address":"10.1.0.9"},"Service":{"Address":"10.1.0.2","Port":8700},"Checks":[{"Status":"critical"}]}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	p, err := NewPool(upstreamCfg(httpDisc(srv.URL, "consul")), dlog)
	if err != nil {
		t.Fatal(err)
	}
	p.ResolveNowForTest()

	// The failing instance is excluded; a blank service address falls back
	// to the node address; the passing weight is carried over.
	got := addresses(p)
	if len(got) != 2 || got[0] != "10.1.0.1:8500" || got[1] != "10.1.0.9:8600" {
		t.Fatalf("consul endpoints %v", got)
	}
	for _, e := range p.Endpoints() {
		if e.Address == "10.1.0.1:8500" && e.Weight != 3 {
			t.Fatalf("passing weight %d", e.Weight)
		}
	}
}

func TestDiscoveryHTTPFailureKeepsSet(t *testing.T) {
	var fail atomic.Bool
	good := `[{"address":"10.0.0.1:8080"},{"address":"10.0.0.2:8080"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write([]byte(good))
	}))
	defer srv.Close()

	p, err := NewPool(upstreamCfg(httpDisc(srv.URL, "list")), dlog)
	if err != nil {
		t.Fatal(err)
	}
	p.ResolveNowForTest()
	if got := addresses(p); len(got) != 2 {
		t.Fatalf("initial %v", got)
	}
	fail.Store(true)
	p.ResolveNowForTest()
	if got := addresses(p); len(got) != 2 {
		t.Fatalf("failed resolution changed the set: %v", got)
	}
	if st := p.Status(); st.Discovery.Errors != 1 || st.Discovery.LastError == "" {
		t.Fatalf("error not recorded: %+v", st.Discovery)
	}
}
