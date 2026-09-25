// Package proxytest starts a server from a configuration for tests that
// live outside internal/proxy.
//
// A listener kind in its own package is tested the way it is deployed:
// through a real server, over a real socket. That needs the same three
// lines every such test would otherwise repeat, and it needs them
// exported, which is the whole of this package.
package proxytest

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// Start parses a configuration, starts a server from it and stops it
// when the test ends. The logs are discarded; a test that wants to read
// them builds its own.
func Start(t *testing.T, yaml string) *proxy.Server {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	s, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

// Addr is a started server's bound address for a listener, which is how
// a test finds the port when the configuration asked for ":0".
func Addr(t *testing.T, s *proxy.Server, listener string) string {
	t.Helper()
	a, ok := s.Addrs()[listener]
	if !ok {
		t.Fatalf("listener %q did not bind", listener)
	}
	return a
}

// Get performs a GET that does not follow redirects, and returns the
// response and its body. Optional pairs are added as headers; "Host"
// sets the request host rather than a header, which is the one field
// net/http will not take from the header map.
func Get(t *testing.T, url string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Add(hdr[i], hdr[i+1])
		}
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// TryStart parses and builds a server without starting it, and returns the
// error rather than failing the test.
//
// It is for the tests whose subject is that a configuration must *not* load: a
// listener that requires TLS without a certificate, for instance, where the bug
// would be a listener that quietly served plaintext instead.
func TryStart(yaml string) (*proxy.Server, error) {
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		return nil, err
	}
	return proxy.New(cfg, logging.Discard())
}
