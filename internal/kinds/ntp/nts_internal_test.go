package ntp

import (
	"testing"

	wire "github.com/rom/xproxy/internal/ntp"
	ke "github.com/rom/xproxy/internal/ntske"
	"github.com/rom/xproxy/internal/proxytest"
)

// A listener configured to terminate NTS against a key establishment listener
// that is not there refuses every protected packet.
//
// Validation stops that configuration from loading, so this is the belt behind
// the braces -- and it is fail-closed on purpose. A listener asked to verify
// with nothing to verify against must refuse: passing the packet on would be
// telling the client its time was authenticated when nothing had checked, which
// is the one thing this mode exists not to do.
func TestVerifyingWithNoKeySetRefuses(t *testing.T) {
	host, err := proxytest.TryStart(`
version: 1
server:
  listeners:
    - name: time
      address: "127.0.0.1:0"
      kind: ntp
      ntp: {upstream: clocks}
logging: {access: {enabled: false}}
upstreams:
  - {name: clocks, endpoints: [{address: "127.0.0.1:1"}]}
`)
	if err != nil {
		t.Fatal(err)
	}
	term := newTerminator(host, "a-listener-that-is-not-there")

	key := make([]byte, 32)
	p := &wire.Packet{Version: 4, Mode: wire.ModeClient, Transmit: wire.Timestamp(1) << 32}
	uid, err := wire.NTSUniqueIDField()
	if err != nil {
		t.Fatal(err)
	}
	p.Extensions = []wire.Extension{uid, wire.NTSCookieField(make([]byte, 104))}
	raw, err := wire.SealNTS(p.Bytes(), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := wire.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if se, reason := term.verify(pkt); reason != ReasonNoKeys || se != nil {
		t.Fatalf("got %q and %v, want %q and no session", reason, se, ReasonNoKeys)
	}
	// And the answering half refuses too, rather than reaching for a key set
	// that is not there.
	sk := &ke.Keys{C2S: key, S2C: key}
	if _, err := term.answer(&session{keys: sk, cookies: 1}, pkt); err == nil {
		t.Fatal("an answer was built with no key set")
	}
}
