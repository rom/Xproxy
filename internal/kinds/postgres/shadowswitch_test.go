package postgres

import (
	"fmt"
	"testing"

	"github.com/rom/xproxy/internal/proxytest"
)

// shadowYAML is the fixture the rest of this package uses with the estate's own
// shadow switch on the listener. It needs its own text because that switch is a
// sibling of `postgres:` rather than a key inside it.
const shadowYAML = `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: postgres
      policy: {mode: shadow}
      postgres:
        upstream: pg
        require_tls: false
        upstream_tls_mode: disable
        read_only: true
logging: {access: {enabled: false}}
upstreams:
  - {name: pg, endpoints: [{address: %q}]}
`

// The listener's own shadow switch works, which it did not.
//
// This kind read only its own monitor_only, so `policy: {mode: shadow}` on a
// postgres listener evaluated the policy and then enforced it -- the one thing a
// trial must not do. Three relays had it the same way (postgres, mysql, tds) and
// redis had it too; the reference documents that switch for every listener, so an
// operator following it got a refused statement where they had asked for a ledger
// entry, and a refusal counter that said enforcement was happening.
func TestTheListenersOwnShadowSwitchIsHonoured(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	s := proxytest.Start(t, fmt.Sprintf(shadowYAML, fake.addr()))
	cl := dial(t, proxytest.Addr(t, s, "db"), "user", "alice")
	_ = cl.waitReady(t)

	if e := cl.query(t, "DELETE FROM users"); e != "" {
		t.Fatalf("a listener in shadow mode refused a soft decision: %s", e)
	}
	st := s.Stats()
	if n := st.Refusals["postgres"]["read_only"]; n != 0 {
		t.Errorf("a listener in shadow mode counted %d refusals it did not make", n)
	}
	if n := st.WouldRefusals["postgres"]["read_only"]; n != 1 {
		t.Errorf("would-refusals %d, want 1: %v", n, st.WouldRefusals["postgres"])
	}
}
