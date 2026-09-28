package dhcp6

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dhcp6"
)

// The relay test exercises the policy through a socket, which is what a
// deployment does. These go at it directly, for the decisions whose interesting
// cases are inconvenient to reach that way: the lease arithmetic at its
// boundaries, the prefix bound in both directions, and the rules.

func compiled(t *testing.T, m *config.DHCP6Listener) *Policy {
	t.Helper()
	if m.Upstream == "" {
		m.Upstream = "servers"
	}
	p, err := compile(m, time.Now)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func at(t *testing.T, m *config.DHCP6Listener, now time.Time) *Policy {
	t.Helper()
	if m.Upstream == "" {
		m.Upstream = "servers"
	}
	p, err := compile(m, func() time.Time { return now })
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// The lease bound, including the two values that are not arithmetic: zero,
// which is a withdrawal, and infinity, which is bounded down like any other
// number because an infinite lease is a pool exhausted by every device that ever
// visited.
func TestTheLeaseBoundLeavesAWithdrawalAlone(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		MinLeaseTime: config.Duration(10 * time.Minute),
		MaxLeaseTime: config.Duration(2 * time.Hour),
	})
	for _, tc := range []struct {
		name    string
		valid   uint32
		want    uint32
		bounded bool
	}{
		{"a withdrawal stays a withdrawal", 0, 0, false},
		{"one second is not a withdrawal and comes up", 1, 600, true},
		{"below the floor comes up", 60, 600, true},
		{"the floor exactly is left alone", 600, 600, false},
		{"between the bounds is left alone", 3600, 3600, false},
		{"the ceiling exactly is left alone", 7200, 7200, false},
		{"above the ceiling comes down", 7201, 7200, true},
		{"infinity comes down", ^uint32(0), 7200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, bounded := p.boundLease(tc.valid)
			if got != tc.want || bounded != tc.bounded {
				t.Errorf("%d became %d (bounded %v), wanted %d (bounded %v)",
					tc.valid, got, bounded, tc.want, tc.bounded)
			}
		})
	}
}

// With no bounds written down, nothing is rewritten -- including the values a
// bound would have caught, because an operator who wrote no bound did not ask
// for one.
func TestNoLeaseBoundRewritesNothing(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{})
	for _, valid := range []uint32{0, 1, 3600, ^uint32(0)} {
		if got, bounded := p.boundLease(valid); got != valid || bounded {
			t.Errorf("%d became %d (bounded %v)", valid, got, bounded)
		}
	}
}

// The prefix bound, in both directions and at both ends of the length.
func TestThePrefixBoundHoldsBothEnds(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		PrefixDelegation: &config.DHCP6PrefixPolicy{
			Prefixes:  []string{"2001:db8:aa00::/40"},
			MinLength: 48,
			MaxLength: 56,
		},
	})
	for _, tc := range []struct {
		pfx     string
		allowed bool
		why     string
	}{
		{"2001:db8:aa01::/48", true, "the estate's own, at the short end"},
		{"2001:db8:aa01:100::/56", true, "the estate's own, at the long end"},
		{"2001:db8:aa01::/40", false, "shorter than the estate delegates"},
		{"2001:db8:aa01:100::/64", false, "longer than the estate delegates"},
		{"2001:db8:bb00::/48", false, "the right length, outside the estate"},
		{"::/0", false, "the whole of IPv6, from a server"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			why := p.prefixAllowed(netip.MustParsePrefix(tc.pfx))
			if tc.allowed && why != "" {
				t.Errorf("%s was refused: %s", tc.pfx, why)
			}
			if !tc.allowed && why == "" {
				t.Errorf("%s was allowed", tc.pfx)
			}
		})
	}
}

// ::/0 is refused as a delegation and allowed as a hint, and the two go through
// the same check -- so this is the case that says the exception for a client's
// "any" (RFC 8415 s21.22) did not open the door for a server delegating
// everything. The length bound is what separates them.
func TestTheAnyPrefixIsAHintAndNotADelegation(t *testing.T) {
	// A listener that bounds only the prefixes, which is where the exception
	// lives: a client that does not know its prefix sends ::/0 and is carried.
	hint := compiled(t, &config.DHCP6Listener{
		PrefixDelegation: &config.DHCP6PrefixPolicy{Prefixes: []string{"2001:db8:aa00::/40"}},
	})
	if why := hint.prefixAllowed(netip.MustParsePrefix("::/0")); why != "" {
		t.Errorf("a client's hint of any was refused: %s", why)
	}
	// An estate that wrote a length down has said what it delegates, and then
	// ::/0 is not any length it delegates.
	bounded := compiled(t, &config.DHCP6Listener{
		PrefixDelegation: &config.DHCP6PrefixPolicy{
			Prefixes:  []string{"2001:db8:aa00::/40"},
			MinLength: 56,
		},
	})
	if bounded.prefixAllowed(netip.MustParsePrefix("::/0")) == "" {
		t.Error("a delegation of the whole of IPv6 was allowed")
	}
}

// With no prefixes and no lengths, anything is carried -- which is the
// configuration the validator warns about, and this is what the warning is
// about.
func TestAnUnboundedDelegationCarriesAnything(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{})
	for _, pfx := range []string{"::/0", "2001:db8::/32", "2001:db8::/128"} {
		if why := p.prefixAllowed(netip.MustParsePrefix(pfx)); why != "" {
			t.Errorf("%s was refused with nothing written down: %s", pfx, why)
		}
	}
}

// The options a client may not ask for come out of the list it sent, and an odd
// list is left alone rather than read off the end.
func TestTheAskListIsFiltered(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		DenyRequestedOptions: []string{"captive_portal", "boot_file_url"},
	})
	list := codes(wire.OptionDNSServers, wire.OptionCaptivePortal,
		wire.OptionDomainList, wire.OptionBootFileURL)
	out, gone := p.AskDenied(list)
	if want := codes(wire.OptionDNSServers, wire.OptionDomainList); string(out) != string(want) {
		t.Errorf("the list became %v", codesOf(out))
	}
	if len(gone) != 2 || gone[0] != wire.OptionCaptivePortal || gone[1] != wire.OptionBootFileURL {
		t.Errorf("removed %v", gone)
	}

	// An odd number of octets is not a list of codes. It is left as it is and
	// refused elsewhere: a filter that read it would be reading one octet past
	// the end of a value a peer chose the length of.
	odd := []byte{0, 23, 0}
	if out, gone := p.AskDenied(odd); string(out) != string(odd) || gone != nil {
		t.Errorf("an odd list became %v, removed %v", out, gone)
	}

	// Nothing denied means the list is handed back untouched rather than
	// rebuilt, because a request nobody has a policy about should arrive at the
	// server as the client sent it.
	none := compiled(t, &config.DHCP6Listener{})
	if out, gone := none.AskDenied(list); string(out) != string(list) || gone != nil {
		t.Errorf("with nothing denied the list became %v", codesOf(out))
	}
}

// A rule's own answer policy narrows the listener's, and the rule that matched
// is the one whose policy applies.
func TestARuleNarrowsTheAnswerPolicy(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		AllowResolvers: []string{"2001:db8::53", "2001:db8::54"},
		Rules: []config.DHCP6Rule{
			{Name: "boot", Action: "allow", MessageTypes: []string{"request"},
				AllowResolvers: []string{"2001:db8::53"}},
			{Name: "rest", Action: "allow"},
		},
	})
	reply := func(resolver string) request {
		m := &wire.Message{Type: wire.Reply, TransactionID: 1}
		m.Set(wire.OptionDNSServers, netip.MustParseAddr(resolver).AsSlice())
		return request{from: netip.MustParseAddr("2001:db8::1"), msg: m, at: time.Now()}
	}
	// The listener's list carries both.
	if d := p.Answer(reply("2001:db8::54"), "rest"); len(d.Strip) != 0 {
		t.Errorf("the listener's own resolver was stripped: %v", d.StripReason)
	}
	// The rule's list carries one, and the other goes -- even though the
	// listener allows it.
	d := p.Answer(reply("2001:db8::54"), "boot")
	if len(d.Strip) != 1 || d.Strip[0] != wire.OptionDNSServers {
		t.Fatalf("the rule did not narrow the list: %v", d.StripReason)
	}
	if d := p.Answer(reply("2001:db8::53"), "boot"); len(d.Strip) != 0 {
		t.Errorf("the rule's own resolver was stripped: %v", d.StripReason)
	}
}

// observe logs and keeps looking, which is how a rule is tried on live traffic
// before it decides anything -- so a deny written as observe carries.
func TestAnObserveRuleDecidesNothing(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		Rules: []config.DHCP6Rule{
			{Name: "watched", Action: "observe", MessageTypes: []string{"solicit"}},
			{Name: "after", Action: "deny", MessageTypes: []string{"solicit"}},
		},
	})
	d := p.Decide(clientReq(t, wire.Solicit))
	if d.Allow || d.Rule != "after" {
		t.Errorf("allow %v rule %q: the observe rule should have kept looking", d.Allow, d.Rule)
	}
}

// A rule outside its window does not match, and the rule after it decides.
func TestARulesWindowHolds(t *testing.T) {
	m := &config.DHCP6Listener{
		Rules: []config.DHCP6Rule{{
			Name: "nights", Action: "deny", MessageTypes: []string{"solicit"},
			Schedule: &config.ModbusSchedule{From: "22:00", To: "06:00"},
		}},
	}
	night := time.Date(2026, 3, 4, 23, 30, 0, 0, time.UTC)
	if d := at(t, m, night).Decide(clientReq(t, wire.Solicit)); d.Allow {
		t.Error("the rule did not decide inside its window")
	}
	day := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	if d := at(t, m, day).Decide(clientReq(t, wire.Solicit)); !d.Allow {
		t.Error("the rule decided outside its window")
	}
}

// A rule on the identifier matches the rendering the logs carry, which is the
// point of writing the pattern against that rendering rather than against
// octets nobody can read.
func TestARuleMatchesTheIdentifiersRendering(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		DefaultAction: "deny",
		Rules: []config.DHCP6Rule{{
			Name: "the vendor's fleet", Action: "allow", DUIDs: []string{"ll:00030001aabb*"},
		}},
	})
	ours := clientReq(t, wire.Solicit)
	ours.msg.Set(wire.OptionClientID, duidLL(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01))
	if d := p.Decide(ours); !d.Allow {
		t.Errorf("the fleet was refused: %s %s", d.Reason, d.Detail)
	}
	theirs := clientReq(t, wire.Solicit)
	theirs.msg.Set(wire.OptionClientID, duidLL(0x11, 0x22, 0x33, 0x44, 0x55, 0x66))
	if d := p.Decide(theirs); d.Allow {
		t.Error("a device outside the fleet was allowed by the fleet's rule")
	}
}

// The reply-side direction check, which is the counterpart of the one on the
// client side: a client's message arriving from a server is either a confused
// server or something bouncing traffic back, and it is refused hard so that a
// listener being trialled still refuses it.
func TestAClientsMessageFromTheServerSideIsRefusedHard(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{})
	m := &wire.Message{Type: wire.Solicit, TransactionID: 7}
	d := p.Answer(request{from: netip.MustParseAddr("2001:db8::1"), msg: m, at: time.Now()}, "")
	if d.Allow || d.Reason != "client_message_from_server_side" || !d.Hard {
		t.Errorf("allow %v reason %q hard %v", d.Allow, d.Reason, d.Hard)
	}
}

// An allow list turns the policy inside out, and then an option nobody listed
// goes whether or not it is on any deny list -- while the options that carry the
// message's own meaning stay, because stripping those would be forwarding a
// message that says nothing.
func TestAnAllowListRemovesWhatItDoesNotName(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		AllowOptions: []string{"dns_servers"},
	})
	m := &wire.Message{Type: wire.Reply, TransactionID: 3}
	m.Set(wire.OptionDNSServers, netip.MustParseAddr("2001:db8::53").AsSlice())
	m.Set(wire.OptionDomainList, []byte{2, 'd', 'c', 0})
	m.Set(wire.OptionClientID, duidLL(1, 2, 3, 4, 5, 6))
	m.Set(wire.OptionServerID, duidLL(9, 9, 9, 9, 9, 9))
	m.Options = append(m.Options, iaNA(1, "2001:db8::10", 1800, 3600))

	d := p.Answer(request{from: netip.MustParseAddr("2001:db8::1"), msg: m, at: time.Now()}, "")
	if !d.Allow {
		t.Fatalf("refused: %s %s", d.Reason, d.Detail)
	}
	if len(d.Strip) != 1 || d.Strip[0] != wire.OptionDomainList {
		t.Errorf("stripped %v, wanted only the search list", optionList(d.Strip))
	}
}

// on_denied_option: deny refuses the whole reply rather than forwarding what is
// left, which is a client with no address at all -- so it is a decision an
// operator makes rather than a default.
func TestRefusingTheReplyIsAChoice(t *testing.T) {
	m := func() *wire.Message {
		r := &wire.Message{Type: wire.Reply, TransactionID: 4}
		r.Set(wire.OptionCaptivePortal, []byte("http://nowhere.example/"))
		return r
	}
	req := func() request {
		return request{from: netip.MustParseAddr("2001:db8::1"), msg: m(), at: time.Now()}
	}
	strip := compiled(t, &config.DHCP6Listener{})
	if d := strip.Answer(req(), ""); !d.Allow || len(d.Strip) != 1 {
		t.Errorf("the default did not strip and forward: allow %v strip %v", d.Allow, d.Strip)
	}
	refuse := compiled(t, &config.DHCP6Listener{OnDeniedOption: "deny"})
	d := refuse.Answer(req(), "")
	if d.Allow || d.Reason != "denied_option" {
		t.Errorf("allow %v reason %q", d.Allow, d.Reason)
	}
	if d.Hard {
		// It is the operator's own policy rather than a bound, so a listener
		// being trialled should carry the reply and write down what it would
		// have done.
		t.Error("a denied option was refused hard")
	}
}

// clientReq is a minimal message from the segment, for the rule tests.
func clientReq(t *testing.T, mt wire.MessageType) request {
	t.Helper()
	m := &wire.Message{Type: mt, TransactionID: 0x424242}
	m.Set(wire.OptionClientID, duidLL(1, 2, 3, 4, 5, 6))
	return request{from: netip.MustParseAddr("fe80::1"), msg: m, at: time.Now()}
}

func codes(cs ...uint16) []byte {
	out := make([]byte, 0, len(cs)*2)
	for _, c := range cs {
		out = binary.BigEndian.AppendUint16(out, c)
	}
	return out
}

// A delegation that overlaps the estate's prefix without being inside it: a
// /32 where the estate delegates out of a /40. Containment is the check, not
// overlap -- a prefix that contains the estate's own is not one of the estate's,
// it is a superset of it, and a client routing it would be routing the estate.
func TestADelegationMustBeInsideTheEstatesPrefixAndNotAroundIt(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		PrefixDelegation: &config.DHCP6PrefixPolicy{Prefixes: []string{"2001:db8:aa00::/40"}},
	})
	if why := p.prefixAllowed(netip.MustParsePrefix("2001:db8:aa01::/48")); why != "" {
		t.Errorf("a prefix inside the estate's was refused: %s", why)
	}
	if p.prefixAllowed(netip.MustParsePrefix("2001:db8::/32")) == "" {
		t.Error("a prefix containing the estate's own was allowed")
	}
	if p.prefixAllowed(netip.MustParsePrefix("2001:db8:aa00::/40")) != "" {
		t.Error("the estate's own prefix was refused")
	}
}

// With delegation switched off, an IA_PD is refused whichever side it came
// from: a client asking, and a server offering.
func TestDelegationSwitchedOffRefusesBothSides(t *testing.T) {
	no := false
	p := compiled(t, &config.DHCP6Listener{
		PrefixDelegation: &config.DHCP6PrefixPolicy{Enabled: &no},
	})

	// From a client.
	ask := clientReq(t, wire.Solicit)
	ask.msg.Options = append(ask.msg.Options, iaPD(1, "2001:db8:c000::/56", 1800, 3600))
	if d := p.Decide(ask); d.Allow {
		t.Error("a client asked for a delegation where none is carried and was allowed")
	}

	// From a server, where it is a refusal rather than a strip: there is no
	// useful half of a delegation to keep.
	reply := &wire.Message{Type: wire.Reply, TransactionID: 9}
	reply.Options = append(reply.Options, iaPD(1, "2001:db8:c000::/56", 1800, 3600))
	d := p.Answer(request{from: netip.MustParseAddr("2001:db8::1"), msg: reply, at: time.Now()}, "")
	if d.Allow || d.Reason != "bad_identity_association" {
		t.Errorf("allow %v reason %q detail %q", d.Allow, d.Reason, d.Detail)
	}
	if len(d.Strip) != 0 {
		t.Error("a delegation was stripped rather than refused")
	}
}

// The boot URL pattern, on a listener that carries the option at all. The
// built-in deny list removes it, so an estate that netboots takes it off that
// list and names the images instead -- and this is the check that then applies.
func TestABootURLNobodyListedIsRemoved(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		// The deny list without the boot options on it.
		DenyOptions:   []string{"captive_portal", "sztp_redirect", "unicast"},
		AllowBootURLs: []string{"tftp://[2001:db8::20]/*", "http://boot.example/images/*.efi"},
	})
	reply := func(url string) request {
		m := &wire.Message{Type: wire.Reply, TransactionID: 11}
		m.Set(wire.OptionBootFileURL, []byte(url))
		return request{from: netip.MustParseAddr("2001:db8::1"), msg: m, at: time.Now()}
	}
	for _, url := range []string{
		"tftp://[2001:db8::20]/pxelinux.0",
		"http://boot.example/images/shim.efi",
	} {
		if d := p.Answer(reply(url), ""); len(d.Strip) != 0 {
			t.Errorf("a listed image was removed: %s (%v)", url, d.StripReason)
		}
	}
	for _, url := range []string{
		"tftp://[2001:db8:66::66]/pxelinux.0",
		"http://boot.example/images/../../evil.efi",
		"http://elsewhere.example/images/shim.efi",
	} {
		d := p.Answer(reply(url), "")
		if len(d.Strip) != 1 || d.Strip[0] != wire.OptionBootFileURL {
			t.Errorf("a boot file nobody listed survived: %s (%v)", url, d.StripReason)
		}
	}
}

// A temporary address association is carried by default and refused when an
// estate says it does not want one. Temporary addresses are the privacy
// mechanism of RFC 8415 s6.5, so the default is to carry them: refusing would be
// refusing clients that are doing the right thing.
func TestATemporaryAssociationIsCarriedUnlessItIsSwitchedOff(t *testing.T) {
	ta := func() request {
		m := &wire.Message{Type: wire.Reply, TransactionID: 12}
		v := binary.BigEndian.AppendUint32(nil, 7)
		v = append(v, opt(wire.OptionIAAddr, addrBody("2001:db8::a", 600, 1200))...)
		m.Options = append(m.Options, wire.Option{Code: wire.OptionIATA, Value: v})
		return request{from: netip.MustParseAddr("2001:db8::1"), msg: m, at: time.Now()}
	}
	if d := compiled(t, &config.DHCP6Listener{}).Answer(ta(), ""); !d.Allow {
		t.Errorf("a temporary address was refused by default: %s %s", d.Reason, d.Detail)
	}
	no := false
	off := compiled(t, &config.DHCP6Listener{AllowTemporaryAddresses: &no})
	if d := off.Answer(ta(), ""); d.Allow || d.Reason != "bad_identity_association" {
		t.Errorf("allow %v reason %q", d.Allow, d.Reason)
	}

	// And the same on the request side, where a client *asking* for one is a
	// client asking for the privacy mechanism by name. An IA_TA is four octets
	// of IAID and then its options: unlike IA_NA and IA_PD it carries no
	// renewal times, because a temporary address is not renewed.
	asking := func() request {
		r := clientReq(t, wire.Solicit)
		r.msg.Options = append(r.msg.Options, wire.Option{Code: wire.OptionIATA,
			Value: binary.BigEndian.AppendUint32(nil, 7)})
		return r
	}
	if d := compiled(t, &config.DHCP6Listener{}).Decide(asking()); !d.Allow {
		t.Errorf("a client asking for a temporary address was refused by default: %s %s",
			d.Reason, d.Detail)
	}
	if d := off.Decide(asking()); d.Allow || d.Reason != "request_not_allowed" {
		t.Errorf("allow %v reason %q", d.Allow, d.Reason)
	}
}

// A pattern with a bracketed IPv6 literal in it, which is what an operator
// writes for a boot server and what path.Match would read as a character class
// matching nothing.
func TestABracketedAddressInAPatternIsLiteral(t *testing.T) {
	p := compiled(t, &config.DHCP6Listener{
		DenyOptions:   []string{"captive_portal"},
		AllowBootURLs: []string{"tftp://[2001:db8::20]/*"},
	})
	reply := func(url string) request {
		m := &wire.Message{Type: wire.Reply, TransactionID: 13}
		m.Set(wire.OptionBootFileURL, []byte(url))
		return request{from: netip.MustParseAddr("2001:db8::1"), msg: m, at: time.Now()}
	}
	if d := p.Answer(reply("tftp://[2001:db8::20]/pxelinux.0"), ""); len(d.Strip) != 0 {
		t.Errorf("the estate's own boot server was removed: %v", d.StripReason)
	}
	// And the pattern is still a pattern: the host is fixed, the path is not.
	if d := p.Answer(reply("tftp://[2001:db8:66::66]/pxelinux.0"), ""); len(d.Strip) != 1 {
		t.Errorf("a boot server nobody listed survived: %v", d.StripReason)
	}
	// A character class would have matched any one of those characters as the
	// whole host, so this is the case that says it is not being read as one.
	if d := p.Answer(reply("tftp://2/pxelinux.0"), ""); len(d.Strip) != 1 {
		t.Errorf("the brackets were read as a character class: %v", d.StripReason)
	}

	// The escape still works for anyone who wants a class on purpose.
	esc := compiled(t, &config.DHCP6Listener{
		DenyOptions: []string{"captive_portal"}, AllowBootURLs: []string{`http://boot/v[0-9].efi`},
	})
	if d := esc.Answer(reply("http://boot/v[0-9].efi"), ""); len(d.Strip) != 0 {
		t.Errorf("the literal pattern did not match itself: %v", d.StripReason)
	}
}
