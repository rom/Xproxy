package dhcp6

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dhcp6"
)

// What is refused when the listener is built, and the pure readers underneath
// the policy.
//
// Every list in this section is compiled once. A name this relay cannot read
// is a list that matches nothing, and on a DHCPv6 relay that is the dangerous
// kind of mistake: the deny lists are what keep a rogue server's options off
// the estate's clients, so one that failed to compile is a relay forwarding
// exactly what it was put there to strip.

func TestEveryListIsCompiledWhenTheListenerIsBuilt(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		m          config.DHCP6Listener
	}{
		{"a client network that is neither", "is not an address or a network",
			config.DHCP6Listener{AllowClients: []string{"not-a-network"}}},
		{"a client deny network that is neither", "is not an address or a network",
			config.DHCP6Listener{DenyClients: []string{"2001:db8::/999"}}},
		{"a server network that is neither", "is not an address or a network",
			config.DHCP6Listener{AllowServers: []string{"over there"}}},
		{"a message type nothing implements", "is not a message type",
			config.DHCP6Listener{MessageTypes: []string{"SOLICITATION"}}},
		{"an option to deny that is not one", "is not an option",
			config.DHCP6Listener{DenyOptions: []string{"not-an-option"}}},
		{"an option to allow that is not one", "is not an option",
			config.DHCP6Listener{AllowOptions: []string{"42x"}}},
		{"a requested option that is not one", "is not an option",
			config.DHCP6Listener{DenyRequestedOptions: []string{"dns-serverz"}}},
		{"a resolver that is not an address", "is not an address",
			config.DHCP6Listener{AllowResolvers: []string{"2001:db8::/64"}}},
		{"a delegation prefix that is neither", "is not an address or a network",
			config.DHCP6Listener{PrefixDelegation: &config.DHCP6PrefixPolicy{
				Prefixes: []string{"nowhere"}}}},

		// And the same lists inside a rule, which is where an exception is
		// written: a rule that compiled to nothing would leave the traffic it
		// was written about to whatever decides underneath it.
		{"a rule's client list", "is not an address or a network",
			config.DHCP6Listener{Rules: []config.DHCP6Rule{
				{Name: "r", Clients: []string{"not-a-network"}}}}},
		{"a rule's message types", "is not a message type",
			config.DHCP6Listener{Rules: []config.DHCP6Rule{
				{Name: "r", MessageTypes: []string{"RENEWAL"}}}}},
		{"a rule's option deny list", "is not an option",
			config.DHCP6Listener{Rules: []config.DHCP6Rule{
				{Name: "r", DenyOptions: []string{"not-an-option"}}}}},
		{"a rule's resolver list", "is not an address",
			config.DHCP6Listener{Rules: []config.DHCP6Rule{
				{Name: "r", AllowResolvers: []string{"a.b.c.d"}}}}},
		{"a rule's schedule", "",
			config.DHCP6Listener{Rules: []config.DHCP6Rule{
				{Name: "r", Schedule: &config.ModbusSchedule{Days: []string{"someday"}}}}}},
	} {
		tc.m.Upstream = "servers"
		_, err := compile(&tc.m, time.Now)
		if err == nil {
			t.Errorf("%s: compiled", tc.name)
			continue
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say what was wrong", tc.name, err)
		}
	}

	// A bare address in a network list is a host route, which is what an
	// operator who wrote one server's address rather than its subnet means,
	// and a rule with no action named allows.
	p := compiled(t, &config.DHCP6Listener{
		AllowServers: []string{"2001:db8::1", "2001:db8:1::/48"},
		Rules:        []config.DHCP6Rule{{Name: "r"}},
	})
	if !p.Server(netip.MustParseAddr("2001:db8::1")) {
		t.Error("a bare address did not become a host route")
	}
	if p.Server(netip.MustParseAddr("2001:db8::2")) {
		t.Error("a host route covered its neighbour")
	}
	if !p.Server(netip.MustParseAddr("2001:db8:1:2::3")) {
		t.Error("the network in the same list was lost")
	}
}

// The client lists, which on a relay are the only thing resembling
// authentication: a DHCPv6 client proves nothing, so where it sent from is
// what there is. Deny is read first, because a deny list an allow list could
// overrule is not a deny list.
func TestTheClientListsAreReadByAddressAndDenyWins(t *testing.T) {
	open := compiled(t, &config.DHCP6Listener{})
	if !open.Client(netip.MustParseAddr("fe80::1")) {
		t.Error("a relay with no client list refused a client")
	}

	p := compiled(t, &config.DHCP6Listener{
		AllowClients: []string{"fe80::/10", "2001:db8:1::/48"},
		DenyClients:  []string{"fe80::dead/128"},
	})
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"fe80::1", true},
		{"2001:db8:1::5", true},
		{"fe80::dead", false},    // on both lists: the deny wins
		{"2001:db8:2::5", false}, // on neither
	} {
		if got := p.Client(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("Client(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	// A reply may come only from a listed server, and with no list nothing
	// is a server: a relay that admitted any source would admit the answer a
	// rogue server on the same segment sent first.
	if open.Server(netip.MustParseAddr("2001:db8::1")) {
		t.Error("a relay with no server list admitted a reply")
	}
}

// A lease time is clamped into the protocol's own range rather than wrapped.
// Both ends matter: a negative duration cannot be sent at all, and anything
// past the 32-bit field is the field's maximum -- which is DHCPv6's own
// spelling of infinity, and is what an operator who wrote a year means.
func TestALeaseTimeIsClampedIntoTheFieldRatherThanWrapped(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want uint32
	}{
		{-time.Hour, 0},
		{0, 0},
		{90 * time.Second, 90},
		{time.Duration(1 << 62), 0xffffffff},
	} {
		if got := leaseSeconds(config.Duration(tc.d)); got != tc.want {
			t.Errorf("%v became %d, want %d", tc.d, got, tc.want)
		}
	}
}

// The text a client or a server sends, rendered for a rule to match and a log
// line to carry.
//
// It is their octets, so anything that is not printable ASCII is replaced: a
// vendor class with a control sequence in it would otherwise be a vendor class
// that moves a terminal's cursor when somebody reads the log, which is how a
// device names itself something an operator's own tooling acts on.
func TestTheTextADeviceSendsIsRenderedSafely(t *testing.T) {
	// A vendor class is an enterprise number and then the text.
	withVendor := &wire.Message{Options: []wire.Option{
		{Code: wire.OptionVendorClass, Value: append([]byte{0, 0, 0x01, 0x37},
			[]byte("MSFT 5.0")...)}}}
	if got := vendorClass(withVendor); got != "MSFT 5.0" {
		t.Errorf("vendorClass = %q", got)
	}
	// Four octets or fewer is the enterprise number and nothing else.
	for _, v := range [][]byte{nil, {0, 0, 0x01}} {
		m := &wire.Message{Options: []wire.Option{{Code: wire.OptionVendorClass, Value: v}}}
		if got := vendorClass(m); got != "" {
			t.Errorf("a vendor class of %d octets read as %q", len(v), got)
		}
	}
	if got := vendorClass(&wire.Message{}); got != "" {
		t.Errorf("a message with no vendor class read as %q", got)
	}

	// A control sequence in the text is replaced rather than carried.
	hostile := &wire.Message{Options: []wire.Option{
		{Code: wire.OptionVendorClass, Value: append([]byte{0, 0, 0, 1},
			[]byte("a\x1b[2Jb\x00c")...)}}}
	if got := vendorClass(hostile); got != "a.[2Jb.c" {
		t.Errorf("a hostile vendor class read as %q", got)
	}

	// A user class is a sequence of length-prefixed strings, and a rule
	// matches the first -- which is what every client that sends one sends.
	user := &wire.Message{Options: []wire.Option{
		{Code: wire.OptionUserClass, Value: append([]byte{0, 6},
			append([]byte("iPXE  "), 0, 3, 'x', 'y', 'z')...)}}}
	if got := userClass(user); got != "iPXE  " {
		t.Errorf("userClass = %q", got)
	}
	// A length that runs off the end is not read as one: the whole value is
	// rendered instead of a slice nobody can take.
	short := &wire.Message{Options: []wire.Option{
		{Code: wire.OptionUserClass, Value: []byte{0, 99, 'a', 'b'}}}}
	if got := userClass(short); got != ".cab" {
		t.Errorf("a user class whose length runs off the end read as %q", got)
	}
	if got := userClass(&wire.Message{}); got != "" {
		t.Errorf("a message with no user class read as %q", got)
	}
}

// The table of requests outstanding towards the servers.
//
// DHCPv6 pairs a reply with its request by a transaction identifier the client
// chose and the identifier it sent, which is all a relay has: there is no
// connection. Two properties follow, and both are here because getting either
// wrong is a reply delivered to the wrong client or an answer dropped.
func TestTheOutstandingTableKeepsAnExchangeForItsSecondAnswer(t *testing.T) {
	now := time.Now()
	var sizes []int
	p := newPending(2, time.Second)
	p.onChange = func(n int) { sizes = append(sizes, n) }

	e := &exchange{xid: 0x0abcde, duid: "duid-1",
		client: netip.MustParseAddrPort("[fe80::1]:546")}
	if !p.add(e, now) {
		t.Fatal("the first request was refused")
	}
	k := key{xid: e.xid, duid: e.duid}

	// An answer does not remove the entry. A DHCPv6 exchange can be answered
	// twice -- a second ADVERTISE from another server behind the same relay --
	// and a table that forgot on the first would drop the second.
	for i := range 2 {
		if got, ok := p.take(k, now); !ok || got != e {
			t.Errorf("answer %d did not pair with the request", i+1)
		}
	}
	// An identifier nobody is waiting on pairs with nothing, which is what a
	// reply from a server that was never asked looks like.
	if _, ok := p.take(key{xid: e.xid, duid: "somebody-else"}, now); ok {
		t.Error("a reply naming a different client was paired with this request")
	}

	// The bound is a refusal, and a retransmission of a request already in the
	// table is not a new one.
	if !p.add(&exchange{xid: 2, duid: "duid-2"}, now) {
		t.Fatal("the second request was refused")
	}
	if p.add(&exchange{xid: 3, duid: "duid-3"}, now) {
		t.Error("a request past the bound was taken")
	}
	if !p.add(&exchange{xid: 2, duid: "duid-2"}, now) {
		t.Error("a retransmission was refused by the bound")
	}

	// The sweep expires what nobody answered and republishes the size, which
	// matters because expiry that only happened when a new request arrived
	// would leave the gauge at whatever the last busy moment said -- and on a
	// quiet segment that is exactly when somebody is looking.
	before := len(sizes)
	p.sweep(now.Add(2 * time.Second))
	if n := p.len(); n != 0 {
		t.Errorf("the sweep left %d outstanding", n)
	}
	if len(sizes) == before || sizes[len(sizes)-1] != 0 {
		t.Errorf("the sweep did not republish the size: %v", sizes)
	}
	// And a sweep with nothing to expire says nothing, so a quiet relay is not
	// writing a gauge that never changes.
	before = len(sizes)
	p.sweep(now.Add(3 * time.Second))
	if len(sizes) != before {
		t.Errorf("a sweep with nothing to do republished: %v", sizes)
	}
}
