package http

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The two-phase reload the data plane and the engine share. The plane
// compiles a generation before any listener is bound and installs it
// only when every one of them is; the engine hands the superseded
// generation's pools back only when the plane's last request on them
// has ended. Both are invisible in a reload that works, and both are
// what a reload that half worked would break.

const planeYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}, {name: second, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "%s"}]
routes:
  - {name: r, upstream: u}
`

// TestReloadThatCannotBindKeepsTheOldRoutes: the plane compiles its
// generation before the listeners are bound, so a bind that fails after
// that has to put it back. If it did not, the routes would already be
// serving a configuration the operator was told had been refused.
func TestReloadThatCannotBindKeepsTheOldRoutes(t *testing.T) {
	a, b := newBackend(t, "a"), newBackend(t, "b")
	s, url := startServer(t, fmt.Sprintf(planeYAML, a.addr()))
	if _, body := get(t, url+"/"); body != "a:/" {
		t.Fatal(body)
	}
	gen := s.Generation()

	// The next configuration routes to b and moves the second listener
	// to an address already in use: the routes are compiled, the bind
	// then fails, and the whole reload is refused.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	next := strings.Replace(fmt.Sprintf(planeYAML, b.addr()),
		`{name: second, address: "127.0.0.1:0"}`,
		`{name: second, address: "`+busy.Addr().String()+`"}`, 1)
	cfg, err := config.Parse([]byte(next))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(cfg); err == nil {
		t.Fatal("a reload that cannot bind its listener was accepted")
	}
	if _, body := get(t, url+"/"); body != "a:/" {
		t.Fatalf("the refused generation's route is being served: %s", body)
	}
	if b.hits.Load() != 0 {
		t.Errorf("the refused generation's upstream took %d requests", b.hits.Load())
	}
	if got := s.Generation(); got != gen {
		t.Errorf("the live generation moved to %d; the reload was refused", got)
	}
	// The plane is still answering for the generation that is serving.
	if n := len(s.Filters()); n != 0 {
		t.Errorf("filters: %d", n)
	}
	if s.Stats().ReloadFailures != 1 {
		t.Errorf("%+v", s.Stats())
	}
}

// TestRequestOnTheOldGenerationSurvivesAReload: a request admitted
// before a reload finishes on the generation it started with, and the
// reload does not wait for it. Both halves matter. The swap is a
// pointer store, so a reload never blocks behind a slow exchange; and
// the superseded generation — its routes, its filters and the engine's
// upstream pools — stays whole until that exchange ends, which is what
// Generation.Retire exists to arrange. A long upload or an SSE stream
// is the case this protects.
func TestRequestOnTheOldGenerationSurvivesAReload(t *testing.T) {
	a, b := newBackend(t, "a"), newBackend(t, "b")
	a.delay = 400 * time.Millisecond
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
  shutdown_timeout: 100ms
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "%s"}]
routes:
  - {name: r, upstream: u}
`
	s, url := startServer(t, fmt.Sprintf(yaml, a.addr()))
	done := make(chan string, 1)
	go func() {
		_, body := get(t, url+"/slow")
		done <- body
	}()
	// Let the request reach the slow backend, then reload onto another
	// upstream: the old pool must stay open until it answers.
	time.Sleep(100 * time.Millisecond)
	cfg, err := config.Parse([]byte(fmt.Sprintf(yaml, b.addr())))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := s.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("the reload waited %s for a request in flight", d)
	}
	select {
	case body := <-done:
		if body != "a:/slow" {
			t.Fatalf("a request admitted before the reload answered %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request never finished")
	}
	// New requests are on the new generation.
	if _, body := get(t, url+"/"); body != "b:/" {
		t.Fatalf("after the reload: %s", body)
	}
}
