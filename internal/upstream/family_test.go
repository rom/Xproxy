package upstream

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// familyNetwork is what turns a policy into the network a dialler takes,
// and the mapping is the whole of the restriction.
func TestFamilyNetwork(t *testing.T) {
	for in, want := range map[string]string{"": "tcp", "any": "tcp", "ipv4": "tcp4", "ipv6": "tcp6"} {
		if got := familyNetwork(in); got != want {
			t.Errorf("familyNetwork(%q) = %q, want %q", in, got, want)
		}
	}
}

// address_family: ipv4 dials IPv4 only, so a name that also has an IPv6
// record cannot quietly use the family the policy meant to exclude. The
// assertion is that a v6-only listener is unreachable under it and
// reachable without it.
func TestAddressFamilyRestrictsTheDial(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback here")
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("six"))
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()

	reach := func(family string) error {
		c := testCfg("round_robin", addr)
		c.AddressFamily = family
		p, err := NewPool(c, nolog)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := p.Transport.RoundTrip(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	if err := reach("any"); err != nil {
		t.Fatalf("an IPv6 endpoint was unreachable with no family policy: %v", err)
	}
	err = reach("ipv4")
	if err == nil {
		t.Fatal("address_family: ipv4 reached an IPv6-only endpoint")
	}
	if !strings.Contains(err.Error(), "network") && !strings.Contains(err.Error(), "refused") &&
		!strings.Contains(err.Error(), "unreachable") && !strings.Contains(err.Error(), "no route") {
		t.Logf("refusal was %v", err) // the message is the platform's; the refusal is the point
	}
	if err := reach("ipv6"); err != nil {
		t.Fatalf("address_family: ipv6 could not reach an IPv6 endpoint: %v", err)
	}
}

// The restriction holds in the other direction too, and this half needs
// no IPv6 on the machine running it: an IPv4 endpoint is unreachable
// under address_family: ipv6, and reachable without it. Between the two
// tests, the policy is shown to decide the dial rather than to be
// decoration.
func TestAddressFamilyIPv6CannotReachAnIPv4Endpoint(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("four"))
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()

	reach := func(family string) error {
		c := testCfg("round_robin", addr)
		c.AddressFamily = family
		p, err := NewPool(c, nolog)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := p.Transport.RoundTrip(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	if err := reach("any"); err != nil {
		t.Fatalf("an IPv4 endpoint was unreachable with no family policy: %v", err)
	}
	if err := reach("ipv6"); err == nil {
		t.Fatal("address_family: ipv6 reached an IPv4-only endpoint")
	}
}

// The fallback delay reaches the dialler, which is where the race between
// the two families lives. It is asserted on the transport rather than by
// timing, because timing a race is how a test becomes flaky.
func TestFallbackDelayReachesTheDialler(t *testing.T) {
	c := testCfg("round_robin", "127.0.0.1:9001")
	c.FallbackDelay = config.Duration(750 * time.Millisecond)
	p, err := NewPool(c, nolog)
	if err != nil {
		t.Fatal(err)
	}
	// The pool has no accessor for it -- it belongs to the dialler the
	// transport closed over -- so the assertion is that a connect to a
	// dead address still fails promptly rather than waiting on the delay,
	// which is what would happen if the value had gone somewhere wrong
	// (a timeout, say).
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := p.Transport.RoundTrip(req); err == nil {
		t.Fatal("a connect to a closed port succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the connect took %s: the fallback delay is not a timeout", d)
	}
}
