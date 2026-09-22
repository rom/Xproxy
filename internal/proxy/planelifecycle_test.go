package proxy

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/metrics"
)

// countingPlane records whether the engine released it. The status and
// rate surfaces are embedded as nil interfaces: this test never reaches
// them, and spelling out twenty-odd methods here would only mean this
// file changes every time one is added.
type countingPlane struct {
	PlaneStatus
	cluster.RateSource
	stopped atomic.Int32
}

func (p *countingPlane) Prepare(Generation) (func(), func(), error) {
	return func() {}, func() {}, nil
}
func (p *countingPlane) Start()                          {}
func (p *countingPlane) Stop(context.Context)            { p.stopped.Add(1) }
func (p *countingPlane) Snapshot(*Snapshot)              {}
func (p *countingPlane) Collect(metrics.Collector)       {}
func (p *countingPlane) PeerEvent(cluster.Event, string) {}

// The engine's runtime holds only the upstream pools since the data
// plane became a kind of its own. The plane holds the rest of a
// generation: the JWKS refreshers, the ICAP pools, the filters. New
// commits the plane before it builds ACME and the cluster node, and a
// failure in either returns no Server at all — so if those paths
// release only the engine runtime, as they could when one runtime held
// everything, the plane's goroutines run on with nobody left to stop
// them.
func TestNewReleasesThePlaneWhenALaterStepFails(t *testing.T) {
	pl := &countingPlane{}
	saved := newPlane
	newPlane = func(Host) (Plane, error) { return pl, nil }
	t.Cleanup(func() { newPlane = saved })

	// A cluster whose certificate and key are files but not a pair:
	// accepted by validation, refused by cluster.New, which runs after
	// the plane is committed.
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	caFile := filepath.Join(dir, "ca.pem")
	for _, f := range []string{certFile, keyFile, caFile} {
		if err := os.WriteFile(f, []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	yaml := `
version: 1
server:
  listeners:
    - name: l
      address: "127.0.0.1:0"
      kind: tcp
      tcp: {default: u}
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
cluster:
  node_id: a
  listen: "127.0.0.1:0"
  peers: ["127.0.0.1:1"]
  tls: {cert_file: ` + certFile + `, key_file: ` + keyFile + `, ca_file: ` + caFile + `}
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Skipf("the configuration no longer reaches cluster.New: %v", err)
	}
	s, err := New(cfg, logging.Discard())
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		t.Fatal("a cluster with a certificate that is not one was accepted")
	}
	if n := pl.stopped.Load(); n != 1 {
		t.Errorf("New failed after committing the plane and stopped it %d times, want 1", n)
	}
}
