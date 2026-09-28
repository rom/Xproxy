package coap

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/config"
)

// The relay test exercises the policy through a socket. These go at it directly,
// for the parts whose interesting cases are the pattern semantics and the
// arithmetic rather than the plumbing.

func compiled(t *testing.T, m *config.CoAPListener) *Policy {
	t.Helper()
	if m.Upstream == "" {
		m.Upstream = "devices"
	}
	p, err := compile(m, time.Now)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// The path pattern semantics, which are the whole of the positive model and the
// easiest thing to get subtly wrong.
//
// Two properties matter. A "*" does not cross a separator, so a pattern is about
// one level unless it says otherwise -- which is what stops "/config/*" from also
// covering "/config/keys/private". And "/..." is the subtree, which path.Match has
// no spelling for and which is the shape an estate actually wants.
func TestThePathPatternsMeanWhatTheySay(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		path    string
		match   bool
	}{
		{"/3303/0/5700", "/3303/0/5700", true},
		{"/3303/0/5700", "/3303/0/5701", false},
		{"/3303/0/5700", "/3303/0/5700/extra", false},

		// One segment, and only one.
		{"/3303/*", "/3303/0", true},
		{"/3303/*", "/3303/", true},
		{"/3303/*", "/3303/0/5700", false},
		{"/config/*", "/config/keys/private", false},

		// The subtree, including the root of it.
		{"/3303/...", "/3303", true},
		{"/3303/...", "/3303/0", true},
		{"/3303/...", "/3303/0/5700", true},
		{"/3303/...", "/3304/0", false},
		// And not a sibling whose name merely starts the same way, which is the
		// off-by-one a prefix comparison would get wrong.
		{"/3303/...", "/33030/0", false},
		{"/33/...", "/330", false},

		// A character class still works for anyone who wants one.
		{"/331[13]/0/5850", "/3311/0/5850", true},
		{"/331[13]/0/5850", "/3312/0/5850", false},

		{"/...", "/anything/at/all", true},
		{"/...", "/", true},
	} {
		t.Run(tc.pattern+" vs "+tc.path, func(t *testing.T) {
			if got := matchPath(tc.pattern, tc.path); got != tc.match {
				t.Errorf("matched %v, wanted %v", got, tc.match)
			}
		})
	}
}

// deny_paths is evaluated before any allow list, including a rule's own, so a
// subtree an estate has excluded stays excluded whatever a rule says.
func TestADeniedPathBeatsEveryAllowList(t *testing.T) {
	p := compiled(t, &config.CoAPListener{
		DenyPaths:  []string{"/config/..."},
		AllowPaths: []string{"/..."},
		Rules: []config.CoAPRule{
			{Name: "everything", Action: "allow", Paths: []string{"/..."}},
		},
	})
	allowed := p.Decide(clientReq(t, wire.GET, "3303", "0", "5700"))
	if !allowed.Allow {
		t.Errorf("an ordinary path was refused: %s %s", allowed.Reason, allowed.Detail)
	}
	denied := p.Decide(clientReq(t, wire.GET, "config", "keys"))
	if denied.Allow || denied.Reason != "path_not_allowed" {
		t.Errorf("allow %v reason %q", denied.Allow, denied.Reason)
	}
}

// The amplification factor and the response bound, which are separate decisions:
// a small answer can still be a large multiple, and a large answer can be
// proportionate.
func TestTheAnswerBoundsAreTwoDecisions(t *testing.T) {
	answer := func(size int) *wire.Message {
		m := &wire.Message{Type: wire.Acknowledgement, Code: wire.Content,
			MessageID: 1, Token: []byte{1}}
		m.Payload = []byte(strings.Repeat("x", size))
		raw, err := wire.Encode(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := wire.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// A factor of four, with no size bound at all.
	factor := compiled(t, &config.CoAPListener{AmplificationFactor: 4})
	// Eight octets of answer for a four-octet question is twice: carried.
	if d := factor.Answer(answer(1), 8, ""); !d.Allow {
		t.Errorf("a proportionate answer was refused: %s %s", d.Reason, d.Detail)
	}
	// A hundred octets for a four-octet question is twenty-five times.
	d := factor.Answer(answer(100), 8, "")
	if d.Allow || d.Reason != "amplified" {
		t.Errorf("allow %v reason %q", d.Allow, d.Reason)
	}
	if !d.Hard {
		t.Error("the amplification bound was not hard, so shadow mode would carry it")
	}

	// A size bound with no factor: the same small answer is fine and a large one
	// is not, whatever the question was.
	size := compiled(t, &config.CoAPListener{MaxResponseBytes: 32})
	if d := size.Answer(answer(1), 4096, ""); !d.Allow {
		t.Errorf("a small answer was refused: %s", d.Reason)
	}
	if d := size.Answer(answer(100), 4096, ""); d.Allow || d.Reason != "response_too_large" {
		t.Errorf("allow %v reason %q", d.Allow, d.Reason)
	}

	// Neither set carries anything, which is the configuration the validator
	// warns about.
	none := compiled(t, &config.CoAPListener{})
	if d := none.Answer(answer(900), 4, ""); !d.Allow {
		t.Errorf("with no bound written down an answer was refused: %s", d.Reason)
	}
	// And a factor with no request size to compare against does not divide by
	// nothing.
	if d := factor.Answer(answer(900), 0, ""); !d.Allow {
		t.Errorf("a factor with no request size refused: %s", d.Reason)
	}
}

// A response whose class is a method: either a confused device or something
// bouncing requests off the relay. Refused hard, so a listener being trialled does
// not forward a request it did not receive from a client.
func TestARequestFromTheAnswerSideIsRefusedHard(t *testing.T) {
	p := compiled(t, &config.CoAPListener{})
	m := &wire.Message{Type: wire.NonConfirmable, Code: wire.PUT, MessageID: 1}
	d := p.Answer(m, 16, "")
	if d.Allow || d.Reason != "request_from_server_side" || !d.Hard {
		t.Errorf("allow %v reason %q hard %v", d.Allow, d.Reason, d.Hard)
	}
	// An empty message from the device is an acknowledgement, and travels.
	if d := p.Answer(&wire.Message{Type: wire.Acknowledgement, MessageID: 2}, 16, ""); !d.Allow {
		t.Errorf("an acknowledgement was refused: %s", d.Reason)
	}
}

// observe logs and keeps looking, so a deny rule written as observe carries and
// the rule after it decides.
func TestAnObserveRuleDecidesNothing(t *testing.T) {
	p := compiled(t, &config.CoAPListener{
		Rules: []config.CoAPRule{
			{Name: "watched", Action: "observe", Paths: []string{"/3311/..."}},
			{Name: "after", Action: "deny", Paths: []string{"/3311/..."}},
		},
	})
	d := p.Decide(clientReq(t, wire.PUT, "3311", "0", "5850"))
	if d.Allow || d.Rule != "after" {
		t.Errorf("allow %v rule %q", d.Allow, d.Rule)
	}
}

// A rule's own narrowing is applied by the rule that matched, not by falling
// through: a request a rule is *about* must be refused by that rule rather than by
// the default, so the logs name the rule an operator would go and read.
func TestARuleRefusesWhatItIsAbout(t *testing.T) {
	no := false
	p := compiled(t, &config.CoAPListener{
		Rules: []config.CoAPRule{{
			Name: "lighting", Action: "allow", Paths: []string{"/3311/..."},
			SecureOnly: true, AllowObserve: &no,
		}},
	})
	// In the clear: refused by the rule, and named.
	d := p.Decide(clientReq(t, wire.PUT, "3311", "0", "5850"))
	if d.Allow || d.Reason != "insecure_not_allowed" || d.Rule != "lighting" {
		t.Errorf("allow %v reason %q rule %q", d.Allow, d.Reason, d.Rule)
	}
	// Inside DTLS: carried.
	secure := clientReq(t, wire.PUT, "3311", "0", "5850")
	secure.secure = true
	if d := p.Decide(secure); !d.Allow {
		t.Errorf("a secure write was refused: %s %s", d.Reason, d.Detail)
	}
	// And the rule's own observe switch decides for its traffic.
	reg := clientReq(t, wire.GET, "3311", "0", "5850")
	reg.secure = true
	reg.msg.Set(wire.OptionObserve, nil)
	if d := p.Decide(reg); d.Allow || d.Reason != "observe_not_allowed" {
		t.Errorf("allow %v reason %q", d.Allow, d.Reason)
	}
}

// The transfer bound takes the larger of what arrived and what was declared, and
// the declaration is the useful one because it is the intent before the transfer.
func TestTheTransferBoundRefusesTheIntent(t *testing.T) {
	p := compiled(t, &config.CoAPListener{
		MaxTransferBytes: 4096,
		Rules:            []config.CoAPRule{{Name: "all", Action: "allow"}},
	})
	// Block zero of sixteen octets, declaring a megabyte to come: refused now.
	r := clientReq(t, wire.PUT, "3303", "0", "5700")
	r.msg.Set(wire.OptionBlock1, []byte{0x08})
	r.msg.Set(wire.OptionSize1, []byte{0x10, 0x00, 0x00})
	d := p.Decide(r)
	if d.Allow || d.Reason != "transfer_too_large" || !d.Hard {
		t.Errorf("allow %v reason %q hard %v", d.Allow, d.Reason, d.Hard)
	}
	// The same first block, declaring something inside the bound: carried.
	ok := clientReq(t, wire.PUT, "3303", "0", "5700")
	ok.msg.Set(wire.OptionBlock1, []byte{0x08})
	ok.msg.Set(wire.OptionSize1, []byte{0x08, 0x00})
	if d := p.Decide(ok); !d.Allow {
		t.Errorf("a transfer inside the bound was refused: %s %s", d.Reason, d.Detail)
	}
}

// The methods a configuration may name, and the ones it may not.
func TestTheMethodListIsCheckedAtCompileTime(t *testing.T) {
	if _, err := compile(&config.CoAPListener{Upstream: "d",
		Methods: []string{"CONNECT"}}, time.Now); err == nil {
		t.Error("a method nobody defined compiled")
	}
	if _, err := compile(&config.CoAPListener{Upstream: "d",
		MessageTypes: []string{"nonsense"}}, time.Now); err == nil {
		t.Error("a message type nobody defined compiled")
	}
	if _, err := compile(&config.CoAPListener{Upstream: "d",
		ContentFormats: []string{"application/nonexistent"}}, time.Now); err == nil {
		t.Error("a media type nobody names compiled")
	}
	// A number is accepted, because the registry grows faster than this table.
	if _, err := compile(&config.CoAPListener{Upstream: "d",
		ContentFormats: []string{"11544"}}, time.Now); err != nil {
		t.Errorf("a numeric content format did not compile: %v", err)
	}
}

// clientReq is a minimal request from the segment.
func clientReq(t *testing.T, code wire.Code, segs ...string) request {
	t.Helper()
	m := &wire.Message{Type: wire.Confirmable, Code: code, MessageID: 0x4242,
		Token: []byte{1, 2}}
	for _, s := range segs {
		m.Add(wire.OptionURIPath, []byte(s))
	}
	return request{from: netip.MustParseAddr("192.0.2.10"), msg: m, at: time.Now()}
}
