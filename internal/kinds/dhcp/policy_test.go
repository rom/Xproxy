package dhcp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dhcp"
)

func mustCompile(t *testing.T, m *config.DHCPListener) *Policy {
	t.Helper()
	p, err := compile(m, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// msg builds a message the policy can be asked about.
func msg(typ wire.MessageType, set func(*wire.Message)) *wire.Message {
	m := &wire.Message{Op: wire.BootRequest, HType: wire.HTypeEthernet, Type: typ,
		CHAddr: []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
		CIAddr: netip.MustParseAddr("0.0.0.0"),
		GIAddr: netip.MustParseAddr("0.0.0.0")}
	if typ.FromServer() {
		m.Op = wire.BootReply
		m.YIAddr = netip.MustParseAddr("10.20.0.55")
	}
	if set != nil {
		set(m)
	}
	return m
}

func ask(m *wire.Message) request {
	return request{from: netip.MustParseAddr("10.20.0.9"), msg: m, at: time.Now()}
}

// TestTheDefaultsAreTheOnesThatMatter: the answer policy and the server list do
// not depend on a rule existing, which is why the request default is allow.
func TestTheDefaultsAreTheOnesThatMatter(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1"})
	if d := p.Decide(ask(msg(wire.Discover, nil))); !d.Allow {
		t.Fatalf("a discover was refused by default: %s", d.Reason)
	}
	// The lease-query family is not in the default message-type list: it is a
	// relay agent's own diagnostic, and an inventory of every lease to
	// anything else.
	if d := p.Decide(ask(msg(wire.LeaseQuery, nil))); d.Allow {
		t.Error("a lease query was allowed by default")
	}
	// And the built-in deny list strips what carries a configuration.
	answer := msg(wire.Ack, func(m *wire.Message) {
		m.Set(wire.OptRouter, []byte{10, 20, 0, 1})
		m.Set(wire.OptWPAD, []byte("http://x"))
		m.Set(wire.OptClasslessRoute, []byte{0, 10, 20, 0, 9})
		m.Set(wire.OptTFTPServer, []byte{10, 20, 0, 3})
	})
	d := p.Answer(ask(answer), "")
	if !d.Allow {
		t.Fatalf("an ordinary ack was refused: %s", d.Reason)
	}
	stripped := map[uint8]bool{}
	for _, c := range d.Strip {
		stripped[c] = true
	}
	for _, c := range []uint8{wire.OptWPAD, wire.OptClasslessRoute, wire.OptTFTPServer} {
		if !stripped[c] {
			t.Errorf("%s was not stripped by default", wire.OptionName(c))
		}
	}
	if stripped[wire.OptRouter] {
		t.Error("the router was stripped although no gateway list was written")
	}
}

// TestAnAddressListRefusesWhatTheEstateDoesNotHave, which catches a compromised
// real server as well as a rogue one.
func TestAnAddressListRefusesWhatTheEstateDoesNotHave(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		AllowGateways:  []string{"10.20.0.1"},
		AllowResolvers: []string{"10.20.0.2", "10.20.0.3"}})
	for _, c := range []struct {
		what  string
		code  uint8
		value []byte
		strip bool
	}{
		{what: "the estate's own gateway", code: wire.OptRouter, value: []byte{10, 20, 0, 1}},
		{what: "another gateway", code: wire.OptRouter, value: []byte{10, 20, 0, 66}, strip: true},
		{what: "both resolvers", code: wire.OptDNS, value: []byte{10, 20, 0, 2, 10, 20, 0, 3}},
		{what: "one good resolver and one bad", code: wire.OptDNS,
			value: []byte{10, 20, 0, 2, 8, 8, 8, 8}, strip: true},
	} {
		code, value := c.code, c.value
		d := p.Answer(ask(msg(wire.Ack, func(m *wire.Message) { m.Set(code, value) })), "")
		got := false
		for _, s := range d.Strip {
			if s == code {
				got = true
			}
		}
		if got != c.strip {
			t.Errorf("%s: stripped=%v, want %v", c.what, got, c.strip)
		}
	}
	// A malformed address list is not a policy question: a client would read it
	// somehow, and that somewhere is where the two readings differ.
	d := p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
		m.Set(wire.OptDNS, []byte{10, 20, 0})
	})), "")
	if d.Allow || d.Reason != "malformed_option" || !d.Hard {
		t.Fatalf("got allow=%v reason=%q hard=%v", d.Allow, d.Reason, d.Hard)
	}
}

// TestARouteIsAllowedByContainmentAndNotByEquality: an estate that allows
// 10.0.0.0/8 has not allowed a default route.
func TestARouteIsAllowedByContainmentAndNotByEquality(t *testing.T) {
	// deny_options is written out without the route option, because that is
	// what an estate using classless routes does: the route survives the deny
	// list and is then checked against allow_routes.
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		DenyOptions: []string{"wpad_url"}, AllowRoutes: []string{"10.0.0.0/8"}})
	for _, c := range []struct {
		what  string
		value []byte
		strip bool
	}{
		{what: "a route inside the allowed prefix", value: []byte{16, 10, 20, 10, 20, 0, 1}},
		{what: "the allowed prefix itself", value: []byte{8, 10, 10, 20, 0, 1}},
		{what: "a default route", value: []byte{0, 10, 20, 0, 9}, strip: true},
		{what: "a route somewhere else", value: []byte{24, 192, 168, 1, 10, 20, 0, 9}, strip: true},
		// A route *broader* than the allowed prefix, whose network address is
		// inside it: 10.0.0.0/7 covers 10.0.0.0 to 11.255.255.255. Containment
		// of the address alone would admit it, which is the whole difference
		// between comparing prefixes and comparing addresses.
		{what: "a route broader than the allowed prefix", value: []byte{7, 10, 10, 20, 0, 1}, strip: true},
	} {
		value := c.value
		d := p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
			m.Set(wire.OptClasslessRoute, value)
		})), "")
		got := false
		for _, s := range d.Strip {
			if s == wire.OptClasslessRoute {
				got = true
			}
		}
		if got != c.strip {
			t.Errorf("%s: stripped=%v, want %v (detail %q)", c.what, got, c.strip, d.Detail)
		}
	}
}

// TestARuleThatSaysWhatAnOptionMayContainAllowsIt is the turn that makes "the
// build segment may be told a boot server and nothing else may" writable.
func TestARuleThatSaysWhatAnOptionMayContainAllowsIt(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		Rules: []config.DHCPRule{
			{Name: "build", Action: "allow", VendorClasses: []string{"PXEClient*"},
				AllowBootServers: []string{"10.20.0.3"},
				BootFiles:        []string{"pxelinux.0"}},
		}})
	answer := func(m *wire.Message) {
		m.Set(wire.OptTFTPServer, []byte{10, 20, 0, 3})
		m.Set(wire.OptBootFile, []byte("pxelinux.0"))
	}
	// Under the rule the boot options survive.
	d := p.Answer(ask(msg(wire.Ack, answer)), "build")
	if len(d.Strip) != 0 {
		t.Errorf("the rule's own traffic had %v stripped", d.Strip)
	}
	// Without it the listener's built-in deny list applies.
	d = p.Answer(ask(msg(wire.Ack, answer)), "")
	if len(d.Strip) != 2 {
		t.Errorf("outside the rule the boot options were not stripped: %v", d.Strip)
	}
	// A boot server the rule does not name is still refused.
	d = p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
		m.Set(wire.OptTFTPServer, []byte{10, 20, 0, 99})
	})), "build")
	if len(d.Strip) != 1 || d.StripReason[wire.OptTFTPServer] != "address_not_allowed" {
		t.Errorf("a boot server outside the rule's list was carried: %v %v", d.Strip, d.StripReason)
	}
	// And a boot file it does not name refuses the reply, because the boot file
	// is what the machine runs.
	d = p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
		m.Set(wire.OptBootFile, []byte("evil.efi"))
	})), "build")
	if d.Allow || d.Reason != "boot_file_not_allowed" {
		t.Fatalf("got allow=%v reason=%q", d.Allow, d.Reason)
	}
	// A rule's own deny beats its own permission, because a deny somebody wrote
	// is a deny.
	p2 := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		Rules: []config.DHCPRule{
			{Name: "build", Action: "allow", AllowBootServers: []string{"10.20.0.3"},
				DenyOptions: []string{"tftp_server"}},
		}})
	d = p2.Answer(ask(msg(wire.Ack, answer)), "build")
	if d.StripReason[wire.OptTFTPServer] != "denied" {
		t.Errorf("a rule's own deny did not win: %v", d.StripReason)
	}
}

// TestTheBootServerIsCheckedInBothPlacesItLives: option 66 and the siaddr
// header field, because a check that looked at one would have a way round it.
func TestTheBootServerIsCheckedInBothPlacesItLives(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		AllowBootServers: []string{"10.20.0.3"}})
	d := p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
		m.SIAddr = netip.MustParseAddr("10.20.0.99")
	})), "")
	if d.Allow || d.Reason != "boot_server_not_allowed" {
		t.Fatalf("siaddr was not checked: allow=%v reason=%q", d.Allow, d.Reason)
	}
	d = p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
		m.SIAddr = netip.MustParseAddr("10.20.0.3")
	})), "")
	if !d.Allow {
		t.Errorf("an allowed siaddr was refused: %s", d.Reason)
	}
}

// TestAPositiveOptionListKeepsWhatAMessageNeeds.
func TestAPositiveOptionListKeepsWhatAMessageNeeds(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		AllowOptions: []string{"subnet_mask", "router", "dns_servers", "lease_time"}})
	d := p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
		m.Set(wire.OptSubnetMask, []byte{255, 255, 255, 0})
		m.Set(wire.OptServerID, []byte{10, 20, 0, 1})
		m.Set(wire.OptDomainName, []byte("example.com"))
	})), "")
	stripped := map[uint8]bool{}
	for _, c := range d.Strip {
		stripped[c] = true
	}
	if stripped[wire.OptSubnetMask] || stripped[wire.OptServerID] {
		t.Error("a positive list stripped what a message cannot do without")
	}
	if !stripped[wire.OptDomainName] {
		t.Error("an option outside the positive list was carried")
	}
}

// TestTheLeaseBoundsAreNotPolicy: a lease of a year is an address pool
// exhausted by every device that ever visited.
func TestTheLeaseBoundsAreNotPolicy(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		MinLeaseTime: config.Duration(10 * time.Minute),
		MaxLeaseTime: config.Duration(24 * time.Hour)})
	for _, c := range []struct {
		secs, want uint32
		bounded    bool
	}{
		{secs: 3600, want: 0},
		{secs: 31536000, want: 86400, bounded: true},
		{secs: 30, want: 600, bounded: true},
	} {
		secs := c.secs
		d := p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
			m.Set(wire.OptLeaseTime, []byte{byte(secs >> 24), byte(secs >> 16), byte(secs >> 8), byte(secs)})
		})), "")
		if d.Bounded != c.bounded || d.Lease != c.want {
			t.Errorf("%d seconds: bounded=%v lease=%d, want %v %d", c.secs, d.Bounded, d.Lease, c.bounded, c.want)
		}
	}
	// A rule may be tighter.
	p = mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		MaxLeaseTime: config.Duration(24 * time.Hour),
		Rules: []config.DHCPRule{{Name: "guests", Action: "allow",
			MaxLeaseTime: config.Duration(time.Hour)}}})
	d := p.Answer(ask(msg(wire.Ack, func(m *wire.Message) {
		m.Set(wire.OptLeaseTime, []byte{0, 1, 0, 0})
	})), "guests")
	if !d.Bounded || d.Lease != 3600 {
		t.Errorf("the rule's own bound was not applied: bounded=%v lease=%d", d.Bounded, d.Lease)
	}
}

// TestAHardwareAddressListMatchesAVendorPrefix, because nobody lists every
// handset.
func TestAHardwareAddressListMatchesAVendorPrefix(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		Rules: []config.DHCPRule{
			{Name: "phones", Action: "deny", HardwareAddresses: []string{"02:11:22"}},
		}})
	if d := p.Decide(ask(msg(wire.Discover, nil))); d.Allow {
		t.Error("a vendor prefix did not match an address that starts with it")
	}
	other := msg(wire.Discover, func(m *wire.Message) {
		m.CHAddr = []byte{0x02, 0x99, 0x99, 1, 2, 3}
	})
	if d := p.Decide(ask(other)); !d.Allow {
		t.Error("a vendor prefix matched an address that does not start with it")
	}
	// A prefix longer than the address cannot match, rather than reading past
	// the address.
	p = mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		Rules: []config.DHCPRule{{Name: "long", Action: "deny",
			HardwareAddresses: []string{"02:11:22:33:44:55:66:77"}}}})
	if d := p.Decide(ask(msg(wire.Discover, nil))); !d.Allow {
		t.Error("an entry longer than the address matched it")
	}
}

// TestTheClientIdentifierCheckIsAboutTheHardwareFormOnly, because RFC 2132
// explicitly allows any opaque value.
func TestTheClientIdentifierCheckIsAboutTheHardwareFormOnly(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		RequireClientIDMatch: true})
	for _, c := range []struct {
		what  string
		id    []byte
		allow bool
	}{
		{what: "no identifier", id: nil, allow: true},
		{what: "the matching hardware form", id: []byte{1, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, allow: true},
		{what: "another address", id: []byte{1, 0xde, 0xad, 0xbe, 0xef, 0, 1}},
		{what: "an opaque identifier", id: []byte{0xff, 'x', 'y'}, allow: true},
		{what: "one octet", id: []byte{1}, allow: true},
	} {
		id := c.id
		m := msg(wire.Discover, func(m *wire.Message) {
			if id != nil {
				m.Set(wire.OptClientID, id)
			}
		})
		if d := p.Decide(ask(m)); d.Allow != c.allow {
			t.Errorf("%s: allow=%v, want %v (%s)", c.what, d.Allow, c.allow, d.Reason)
		}
	}
}

// TestTheClientListAdmitsTheAddresslessClient, because a client with no address
// yet sends from 0.0.0.0 and that is every first-time client.
func TestTheClientListAdmitsTheAddresslessClient(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		AllowClients: []string{"10.30.0.0/16"}, DenyClients: []string{"10.30.9.0/24"}})
	for addr, want := range map[string]bool{
		"0.0.0.0":   true,
		"10.30.0.5": true,
		"10.30.9.5": false,
		"192.0.2.1": false,
	} {
		if got := p.Client(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
	if p.Client(netip.Addr{}) {
		t.Error("an address that is not one was admitted")
	}
	// The deny list still beats the unspecified address, because a deny
	// somebody wrote is a deny.
	p = mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		DenyClients: []string{"0.0.0.0/32"}})
	if p.Client(netip.MustParseAddr("0.0.0.0")) {
		t.Error("a denied address was admitted")
	}
}

// TestTheServerListIsNotOpenWhenItIsEmpty: an empty list admits nothing, and
// the kind fills it in from the pool rather than reading it as "anybody".
func TestTheServerListIsNotOpenWhenItIsEmpty(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1"})
	if p.Server(netip.MustParseAddr("10.20.0.1")) {
		t.Fatal("an empty server list admitted an address")
	}
	p = mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		AllowServers: []string{"10.20.0.0/24"}})
	if !p.Server(netip.MustParseAddr("10.20.0.1")) || p.Server(netip.MustParseAddr("10.99.0.1")) {
		t.Error("the server list does not decide by network")
	}
}

// TestAskDeniedTrimsTheAskAndNotTheMessage.
func TestAskDeniedTrimsTheAskAndNotTheMessage(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		DenyRequestedOptions: []string{"wpad_url", "252"}})
	in := []byte{wire.OptSubnetMask, wire.OptWPAD, wire.OptRouter}
	out, removed := p.AskDenied(in)
	if len(removed) != 1 || removed[0] != wire.OptWPAD {
		t.Fatalf("removed %v", removed)
	}
	if len(out) != 2 || out[0] != wire.OptSubnetMask || out[1] != wire.OptRouter {
		t.Fatalf("trimmed list %v", out)
	}
	// A list with nothing to remove comes back as it was, rather than being
	// rebuilt: the message the server sees should differ only when the policy
	// said something.
	same, removed := p.AskDenied([]byte{wire.OptRouter})
	if len(removed) != 0 || len(same) != 1 {
		t.Errorf("an untouched list was changed: %v %v", same, removed)
	}
	none := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1"})
	if _, removed := none.AskDenied(in); removed != nil {
		t.Error("a listener with no list removed something")
	}
}

// TestAnObservingRuleDecidesNothing.
func TestAnObservingRuleDecidesNothing(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		DefaultAction: "deny",
		Rules: []config.DHCPRule{
			{Name: "watch", Action: "observe", MessageTypes: []string{"discover"}},
			{Name: "allow-discover", Action: "allow", MessageTypes: []string{"discover"}},
		}})
	d := p.Decide(ask(msg(wire.Discover, nil)))
	if !d.Allow || d.Rule != "allow-discover" {
		t.Fatalf("an observing rule decided: allow=%v rule=%q", d.Allow, d.Rule)
	}
	if d := p.Decide(ask(msg(wire.Request, nil))); d.Allow || d.Reason != "default_deny" {
		t.Fatalf("got allow=%v reason=%q", d.Allow, d.Reason)
	}
}

// TestTheScheduleDecidesWhenASegmentMayBeBuilt.
func TestTheScheduleDecidesWhenASegmentMayBeBuilt(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		DefaultAction: "deny",
		Rules: []config.DHCPRule{{Name: "window", Action: "allow",
			Schedule: &config.ModbusSchedule{From: "01:00", To: "02:00", Timezone: "UTC"}}}})
	inside := ask(msg(wire.Discover, nil))
	inside.at = time.Date(2026, 3, 4, 1, 30, 0, 0, time.UTC)
	if d := p.Decide(inside); !d.Allow {
		t.Fatalf("inside the window: %s", d.Reason)
	}
	outside := inside
	outside.at = time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)
	if d := p.Decide(outside); d.Allow {
		t.Fatal("outside the window it was allowed")
	}
}

// TestADirectionThatDisagreesWithTheTypeIsTheFinding.
func TestADirectionThatDisagreesWithTheTypeIsTheFinding(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1"})
	d := p.Answer(ask(msg(wire.Discover, nil)), "")
	if d.Allow || d.Reason != "wrong_direction" || !d.Hard {
		t.Fatalf("got allow=%v reason=%q hard=%v", d.Allow, d.Reason, d.Hard)
	}
	// A NAK carries no configuration, so there is nothing to check in it.
	if d := p.Answer(ask(msg(wire.Nak, nil)), ""); !d.Allow || len(d.Strip) != 0 {
		t.Errorf("a nak was refused or edited: allow=%v strip=%v", d.Allow, d.Strip)
	}
}

// TestCompileRefusesWhatItCannotUnderstand, rather than ignoring it.
func TestCompileRefusesWhatItCannotUnderstand(t *testing.T) {
	for what, m := range map[string]*config.DHCPListener{
		"allow_clients":     {AllowClients: []string{"not-a-cidr"}},
		"deny_clients":      {DenyClients: []string{"10/8"}},
		"allow_servers":     {AllowServers: []string{"x"}},
		"allow_routes":      {AllowRoutes: []string{"10.0.0.0"}},
		"allow_gateways":    {AllowGateways: []string{"not-an-address"}},
		"allow_gateways v6": {AllowGateways: []string{"2001:db8::1"}},
		"allow_resolvers":   {AllowResolvers: []string{"x"}},
		"allow_boot":        {AllowBootServers: []string{"x"}},
		"message_types":     {MessageTypes: []string{"renew"}},
		"deny_options":      {DenyOptions: []string{"not_an_option"}},
		"deny option 0":     {DenyOptions: []string{"0"}},
		"deny option 255":   {DenyOptions: []string{"end"}},
		"deny the type":     {DenyOptions: []string{"message_type"}},
		"rule clients":      {Rules: []config.DHCPRule{{Name: "r", Clients: []string{"x"}}}},
		"rule routes":       {Rules: []config.DHCPRule{{Name: "r", AllowRoutes: []string{"x"}}}},
		"rule hardware":     {Rules: []config.DHCPRule{{Name: "r", HardwareAddresses: []string{"zz"}}}},
		"rule types":        {Rules: []config.DHCPRule{{Name: "r", MessageTypes: []string{"x"}}}},
		"rule options":      {Rules: []config.DHCPRule{{Name: "r", DenyOptions: []string{"x"}}}},
		"rule gateways":     {Rules: []config.DHCPRule{{Name: "r", AllowGateways: []string{"x"}}}},
		"rule resolvers":    {Rules: []config.DHCPRule{{Name: "r", AllowResolvers: []string{"x"}}}},
		"rule boot":         {Rules: []config.DHCPRule{{Name: "r", AllowBootServers: []string{"x"}}}},
		"rule schedule":     {Rules: []config.DHCPRule{{Name: "r", Schedule: &config.ModbusSchedule{Days: []string{"caturday"}}}}},
	} {
		if _, err := compile(m, time.Now); err == nil {
			t.Errorf("%s: compiled", what)
		}
	}
}

// TestHiddenOptionsAreRefusedAndTheDetailNamesTheEncoding.
func TestHiddenOptionsAreRefusedAndTheDetailNamesTheEncoding(t *testing.T) {
	p := mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1"})
	m := msg(wire.Discover, nil)
	m.Options = append(m.Options, wire.Option{Code: wire.OptVendorClass,
		Value: []byte("abc"), Split: true, Where: wire.InOptions})
	d := p.Decide(ask(m))
	if d.Allow || d.Reason != "hidden_options" || !d.Hard {
		t.Fatalf("got allow=%v reason=%q hard=%v", d.Allow, d.Reason, d.Hard)
	}
	if d.Detail == "" {
		t.Error("the refusal does not say which encoding was used")
	}
	// And it can be turned off for the estate that has such a client.
	no := false
	p = mustCompile(t, &config.DHCPListener{Upstream: "servers", RelayAddress: "10.20.0.1",
		RefuseHiddenOptions: &no})
	if d := p.Decide(ask(m)); !d.Allow {
		t.Errorf("the check could not be turned off: %s", d.Reason)
	}
}
