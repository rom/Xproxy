package redis

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/proxytest"
)

// shadowYAML is the same listener as the rest of this file's fixtures with the
// estate's own shadow switch on it, which is a sibling of `redis:` rather than a
// key inside it -- so it needs its own fixture.
const shadowYAML = `
version: 1
server:
  listeners:
    - name: cache
      address: "127.0.0.1:0"
      kind: redis
      policy: {mode: shadow}
      redis:
        upstream: rd
        require_tls: false
        require_auth: false
        default_action: allow
        read_only: true
logging: {access: {enabled: false}}
upstreams:
  - {name: rd, endpoints: [{address: %q}]}
`

// The listener's own shadow switch works, which it did not.
//
// Every other kind reads config.Listener.Shadowing(); this one read only its own
// monitor_only, so `policy: {mode: shadow}` on a redis listener evaluated the
// policy and enforced it -- the one thing a trial must not do. An operator
// following the reference, which documents that switch for every listener, got a
// refused write and a refusal counter where they had asked for a ledger entry.
func TestTheListenersOwnShadowSwitchIsHonoured(t *testing.T) {
	fs := startFake(t, &fakeServer{})
	s := proxytest.Start(t, fmt.Sprintf(shadowYAML, fs.addr()))
	cl := dial(t, proxytest.Addr(t, s, "cache"))

	if got := cl.do(t, "SET", "k", "v"); !strings.HasPrefix(got, "+") {
		t.Fatalf("SET answered %q in shadow mode, want it carried", got)
	}
	if cmds, _ := fs.saw(); strings.Join(cmds, ",") != "SET" {
		t.Errorf("the server saw %v, want the write it would have refused", cmds)
	}
	st := s.Stats()
	if n := st.Refusals["redis"]["read_only"]; n != 0 {
		t.Errorf("a listener in shadow mode counted %d refusals it did not make", n)
	}
	if n := st.WouldRefusals["redis"]["read_only"]; n != 1 {
		t.Errorf("would-refusals %d, want 1: %v", n, st.WouldRefusals["redis"])
	}
}
