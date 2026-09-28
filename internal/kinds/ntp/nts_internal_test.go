package ntp

import (
	"testing"
	"time"

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

// The cookie pool is bounded. A source that answered every request with a full
// handful of replacements would otherwise grow it without limit -- and the pool
// is memory this relay holds on the source's word.
func TestTheCookiePoolIsBounded(t *testing.T) {
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
	o := &originator{host: host, listener: "time", refreshBelow: 2, now: time.Now}
	key := make([]byte, ke.KeyLen)
	o.keys = &ke.Keys{C2S: key, S2C: key}

	// An answer carrying as many cookies as one exchange may, over and over.
	for i := 0; i < 20; i++ {
		p := &wire.Packet{Version: 4, Mode: wire.ModeServer, Transmit: wire.Timestamp(i+1) << 32}
		var inner []wire.Extension
		for j := 0; j < wire.MaxNTSCookies; j++ {
			inner = append(inner, wire.NTSCookieField(make([]byte, 104)))
		}
		raw, err := wire.SealNTS(p.Bytes(), key, inner)
		if err != nil {
			t.Fatal(err)
		}
		pkt, err := wire.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.verify(pkt, &sourceSession{keys: o.keys}); err != nil {
			t.Fatalf("answer %d: %v", i, err)
		}
	}
	o.mu.Lock()
	held := len(o.cookies)
	o.mu.Unlock()
	if held > cookieTarget*2 {
		t.Fatalf("the pool holds %d cookies after twenty generous answers", held)
	}
	if held == 0 {
		t.Fatal("the pool holds none, so nothing was kept at all")
	}
}

// How many replacements a request asks for. One comes back for the cookie spent
// without asking, so a full pool asks for nothing and a pool that lost answers
// asks for exactly what refills it -- which is what keeps a relay whose answers
// go missing from having to establish keys again.
func TestARequestAsksForWhatRefillsThePool(t *testing.T) {
	key := make([]byte, ke.KeyLen)
	cookie := make([]byte, 104)
	for _, tc := range []struct {
		held int
		want int
	}{
		// held, and what the answer then has to carry to put the pool back at
		// its target: one for the cookie spent, plus a placeholder each for
		// the answers that went missing.
		{cookieTarget, 0},
		{cookieTarget - 1, 1},
		{cookieTarget - 2, 2},
		{3, cookieTarget - 3},
		{1, cookieTarget - 1},
	} {
		o := &originator{refreshBelow: 2, now: time.Now}
		o.keys = &ke.Keys{C2S: key, S2C: key}
		for i := 0; i < tc.held; i++ {
			o.cookies = append(o.cookies, cookie)
		}
		_, placeholders, _, ok := o.take()
		if !ok {
			t.Fatalf("holding %d cookies, none could be spent", tc.held)
		}
		if placeholders != tc.want {
			t.Errorf("holding %d, asked for %d replacements, want %d", tc.held, placeholders, tc.want)
		}
		// The pool ends at its target: what is left, the automatic
		// replacement, and the placeholders.
		if got := len(o.cookies) + 1 + placeholders; got != cookieTarget {
			t.Errorf("holding %d, the answer would leave %d cookies, want %d", tc.held, got, cookieTarget)
		}
		// Never more than one exchange may carry: a request that asked for more
		// would be asking for an answer larger than itself. The bound is a
		// compile-time assertion in the package rather than a runtime clamp, so
		// this is the property that assertion protects.
		if 1+placeholders > wire.MaxNTSCookies {
			t.Errorf("holding %d, asked for %d cookies in all, past the bound of %d",
				tc.held, 1+placeholders, wire.MaxNTSCookies)
		}
	}
	// And an empty pool has nothing to spend, whatever it would like back.
	o := &originator{refreshBelow: 2, now: time.Now}
	o.keys = &ke.Keys{C2S: key, S2C: key}
	if _, _, _, ok := o.take(); ok {
		t.Fatal("a cookie was spent from an empty pool")
	}
}
