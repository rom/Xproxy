package mgmt

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
)

// readyFixture is a proxy with one listener and one pool whose single
// endpoint is a port nothing answers on, so the pool has nothing healthy
// as soon as a health check runs -- and, before one does, has an endpoint
// that has never been checked.
func readyFixture(t *testing.T, a Actions) (*proxy.Server, *Client) {
	t.Helper()
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	sock := filepath.Join(t.TempDir(), "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), a)
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Shutdown(context.Background()) })
	return p, NewClient(sock)
}

// The verdict a check script reads, and the one thing that always counts:
// an operator saying so.
func TestSteppingANodeDownAndBackUp(t *testing.T) {
	_, c := readyFixture(t, Actions{})

	res, err := c.Ready(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Serving {
		t.Fatalf("a fresh node is not serving: %+v", res)
	}
	if res.Listeners != 1 {
		t.Errorf("listeners %d", res.Listeners)
	}

	var down proxy.Readiness
	if err := c.Do("POST", "/v1/ready", ServingRequest{Serving: false, Reason: "kernel update"}, &down); err != nil {
		t.Fatal(err)
	}
	if down.Serving || !down.SteppedDown || down.StepReason != "kernel update" {
		t.Fatalf("step down: %+v", down)
	}
	if down.StepAt.IsZero() {
		t.Error("the step-down was not timed")
	}

	// And the verdict a check script gets afterwards is the refusal, with
	// the reason on it, because the operator's own note is what the next
	// person reading a log needs.
	res, err = c.Ready(false, false)
	if err != nil {
		t.Fatalf("a stepped-down node answered with an error rather than a verdict: %v", err)
	}
	if res.Serving {
		t.Fatal("a stepped-down node says it is serving")
	}
	if len(res.Reasons) == 0 || !strings.Contains(res.Reasons[0], "kernel update") {
		t.Errorf("reasons %v", res.Reasons)
	}

	var up proxy.Readiness
	if err := c.Do("POST", "/v1/ready", ServingRequest{Serving: true}, &up); err != nil {
		t.Fatal(err)
	}
	if !up.Serving || up.SteppedDown {
		t.Fatalf("step up: %+v", up)
	}
	// A reason longer than the field is a refusal rather than a truncation.
	if err := c.Do("POST", "/v1/ready", ServingRequest{Serving: false, Reason: strings.Repeat("x", 300)}, nil); err == nil {
		t.Error("an over-long reason was accepted")
	}
}

// The two judgement calls are opt-in, which is the whole point of them:
// the same node is ready or not depending on what the operator decided
// matters.
func TestTheJudgementCallsAreOptIn(t *testing.T) {
	p, c := readyFixture(t, Actions{Sandbox: func() *sandbox.Status {
		return &sandbox.Status{Enabled: true, Mechanism: []sandbox.Mechanism{
			{Name: "seccomp", State: sandbox.StateApplied},
			{Name: "landlock", State: sandbox.StateUnavailable},
		}}
	}})

	// A pool whose only endpoint is a closed port. Until a health check
	// has run the endpoint counts as healthy, which is the right default
	// -- a node that refuses traffic in the second before its first probe
	// would flap at every start -- so the test drives the state directly.
	p.SetDrain("u", "127.0.0.1:1", true)

	// Neither requirement: the node serves, and says what is wrong anyway.
	res, err := c.Ready(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Serving {
		t.Fatalf("serving without either requirement: %+v", res)
	}
	if len(res.PoolsWithoutEndpoints) != 1 || res.PoolsWithoutEndpoints[0] != "u" {
		t.Errorf("pools %v", res.PoolsWithoutEndpoints)
	}
	if len(res.Degraded) != 1 || !strings.Contains(res.Degraded[0], "landlock") {
		t.Errorf("degraded %v", res.Degraded)
	}
	// Reporting a fault while still serving is the case an alert is for,
	// so the reasons are present on a serving verdict too.
	if len(res.Reasons) != 2 {
		t.Errorf("reasons %v", res.Reasons)
	}

	// Each requirement on its own turns its own fault into a refusal.
	if res, err = c.Ready(true, false); err != nil || res.Serving {
		t.Errorf("require-upstreams: %+v %v", res, err)
	}
	if res, err = c.Ready(false, true); err != nil || res.Serving {
		t.Errorf("require-undegraded: %+v %v", res, err)
	}

	// A node with a healthy endpoint and no sandbox is ready under both.
	p.SetDrain("u", "127.0.0.1:1", false)
	_, c2 := readyFixture(t, Actions{})
	if res, err := c2.Ready(true, true); err != nil || !res.Serving {
		t.Errorf("a sound node under both requirements: %+v %v", res, err)
	}
}

// Load is never a reason, and the sentence a person reads is one sentence.
func TestTheVerdictReadsAsASentence(t *testing.T) {
	r := proxy.Readiness{Serving: true}
	if got := r.WithDegraded(nil, true); !got.Serving || len(got.Reasons) != 0 {
		t.Errorf("no degradation: %+v", got)
	}
	got := r.WithDegraded([]string{"seccomp: failed", "landlock: unavailable"}, false)
	if !got.Serving {
		t.Error("degradation refused without the requirement")
	}
	if len(got.Reasons) != 1 || !strings.Contains(got.Reasons[0], "landlock: unavailable and seccomp: failed") {
		t.Errorf("reasons %v", got.Reasons)
	}
	if got := r.WithDegraded([]string{"seccomp: failed"}, true); got.Serving {
		t.Error("degradation served with the requirement")
	}
}
