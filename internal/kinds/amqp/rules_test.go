package amqp

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/config"
)

// A rule's own lists, the identity decisions, and what will not compile.
//
// A rule here is how one application is given something the estate's default
// does not give it -- the deployment account that may declare a queue, the
// consumer that may read one exchange's traffic -- so each list exists in two
// places and the question is which one is in force. The deny side has to win
// in both directions, because a deny list a rule could be talked out of is
// not a deny list.

func TestEveryListAndScheduleIsCompiledWhenTheListenerIsBuilt(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		c          config.AMQPListener
	}{
		{"a client deny network that is not one", "deny_clients",
			config.AMQPListener{DenyClients: []string{"10.0.0.1"}}},
		{"a method to deny that is not one", "deny_methods",
			config.AMQPListener{DenyMethods: []string{"queue.obliterate"}}},
		{"a performative to deny that is not one", "deny_performatives",
			config.AMQPListener{DenyPerformatives: []string{"detatch"}}},
		{"a method to allow that is not one", "allow_methods",
			config.AMQPListener{AllowMethods: []string{"basic.yeet"}}},
		{"a performative to allow that is not one", "allow_performatives",
			config.AMQPListener{AllowPerformatives: []string{"transfur"}}},
		{"a version nothing implements", "versions",
			config.AMQPListener{Versions: []string{"0.8"}}},

		{"a rule's client list", "rules[0].clients",
			config.AMQPListener{Rules: []config.AMQPRule{
				{Name: "r", Clients: []string{"not-a-network"}}}}},
		{"a rule's method allow list", "rules[0].allow_methods",
			config.AMQPListener{Rules: []config.AMQPRule{
				{Name: "r", AllowMethods: []string{"basic.yeet"}}}}},
		{"a rule's method deny list", "rules[0].deny_methods",
			config.AMQPListener{Rules: []config.AMQPRule{
				{Name: "r", DenyMethods: []string{"queue.obliterate"}}}}},
		{"a rule's performative allow list", "rules[0].allow_performatives",
			config.AMQPListener{Rules: []config.AMQPRule{
				{Name: "r", AllowPerformatives: []string{"transfur"}}}}},
		{"a rule's performative deny list", "rules[0].deny_performatives",
			config.AMQPListener{Rules: []config.AMQPRule{
				{Name: "r", DenyPerformatives: []string{"detatch"}}}}},
		{"a rule's vhost pattern", "rules[0]",
			config.AMQPListener{Rules: []config.AMQPRule{
				{Name: "r", Vhosts: []string{"[unclosed"}}}}},
		{"a rule's schedule", "rules[0].schedule",
			config.AMQPListener{Rules: []config.AMQPRule{
				{Name: "r", Schedule: &config.ModbusSchedule{Days: []string{"someday"}}}}}},
	} {
		tc.c.Upstream = "mq"
		_, err := compile(&tc.c)
		if err == nil {
			t.Errorf("%s: compiled", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not name the list", tc.name, err)
		}
	}

	// And a section naming each of them correctly, including AMQP 1.0, whose
	// messages are performatives rather than methods.
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		Versions:           []string{"0-9-1", "1.0"},
		AllowMethods:       []string{"basic.publish", "basic.consume", "basic.ack"},
		DenyMethods:        []string{"basic.ack"},
		AllowPerformatives: []string{"attach", "transfer", "flow"},
		DenyPerformatives:  []string{"flow"},
		Rules: []config.AMQPRule{{Name: "deploy", Users: []string{"ci"},
			Action: "allow", Vhosts: []string{"/ci*"}}},
	})
	if len(p.rules) != 1 {
		t.Fatalf("rules %+v", p.rules)
	}
}

// Which rule covers a session. The client network and the vhost are the two
// the login name does not imply: the same account from a build runner and from
// a developer's laptop are two different situations, and an exchange name
// means something different in each vhost.
func TestEverySelectorARuleSetsHasToHold(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		Rules: []config.AMQPRule{{Name: "runners", Action: "allow",
			Clients:    []string{"10.9.0.0/24"},
			Users:      []string{"ci"},
			Vhosts:     []string{"/ci"},
			DenyQueues: []string{"payments"},
		}}})
	deliver := []wire.Target{{Kind: wire.KindQueue, Name: "payments"}}

	inside := &Session{IP: netip.MustParseAddr("10.9.0.7"), Version: wire.V091,
		User: "ci", Vhost: "/ci", Secure: true, Authed: true, At: time.Now()}
	if d := p.Delivery(inside, deliver); d.Allow || d.Rule != "runners" {
		t.Errorf("inside every selector: %+v", d)
	}
	for what, change := range map[string]func(*Session){
		"the wrong network": func(s *Session) { s.IP = netip.MustParseAddr("192.0.2.7") },
		"no network at all": func(s *Session) { s.IP = netip.Addr{} },
		"the wrong login":   func(s *Session) { s.User = "someone" },
		"the wrong vhost":   func(s *Session) { s.Vhost = "/" },
	} {
		se := *inside
		change(&se)
		if d := p.Delivery(&se, deliver); !d.Allow {
			t.Errorf("%s was covered anyway: %+v", what, d)
		}
	}
}

// A rule's method and performative lists replace the listener's for the
// traffic it covers, and its deny lists win over the listener's allow lists.
func TestARulesListsReplaceTheListenersForTheTrafficItCovers(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		AllowMethods:       []string{"basic.publish", "basic.consume"},
		AllowPerformatives: []string{"attach", "transfer"},
		Rules: []config.AMQPRule{{
			Name: "consumer-only", Users: []string{"reader"}, Action: "allow",
			AllowMethods:      []string{"basic.consume", "basic.ack"},
			DenyPerformatives: []string{"transfer"},
		}, {
			Name: "no-publishing", Users: []string{"watcher"}, Action: "allow",
			DenyMethods: []string{"basic.publish"},
		}}})

	publish := meth(t, wire.ClassBasic, 40, u16(0), sstr("events"), sstr("k"), bitsOf(false, false))
	ack := meth(t, wire.ClassBasic, 80, u64(1), bitsOf(false))

	reader := sess("reader", "/")
	// The rule's list is the one in force: what it names is carried although
	// the listener does not name it, and what the listener names is refused
	// because the rule does not.
	if d := p.Method(reader, ack); !d.Allow || d.Rule != "consumer-only" {
		t.Errorf("a method the rule names: %+v", d)
	}
	if d := p.Method(reader, publish); d.Allow ||
		d.Reason != "method_not_allowed" || d.Rule != "consumer-only" {
		t.Errorf("a method only the listener names: %+v", d)
	}
	// The rule's performative deny list wins over the listener's allow list.
	if d := p.Performative(reader, perf(t, uint8(wire.PerfTransfer))); d.Allow ||
		d.Reason != "performative_denied" || d.Rule != "consumer-only" {
		t.Errorf("the rule's performative deny list: %+v", d)
	}
	// A rule that denies one method leaves the rest to the listener's list.
	watcher := sess("watcher", "/")
	if d := p.Method(watcher, publish); d.Allow || d.Reason != "method_denied" ||
		d.Rule != "no-publishing" {
		t.Errorf("the rule's method deny list: %+v", d)
	}
	cons := meth(t, wire.ClassBasic, 20, u16(0), sstr("work"), sstr("tag"),
		bitsOf(false, false, false, false), emptyTable())
	if d := p.Method(watcher, cons); !d.Allow {
		t.Errorf("a method the rule says nothing about: %+v", d)
	}
}

// Publishing and consuming are switches rather than lists, so a rule can turn
// one off for the account that should only read without naming every method
// that would do it.
func TestARuleCanTurnPublishingOrConsumingOffOnItsOwn(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		Rules: []config.AMQPRule{
			{Name: "reader", Users: []string{"reader"}, Action: "allow", AllowPublish: no(false)},
			{Name: "writer", Users: []string{"writer"}, Action: "allow", AllowConsume: no(false)},
		}})
	publish := meth(t, wire.ClassBasic, 40, u16(0), sstr("events"), sstr("k"), bitsOf(false, false))
	cons := meth(t, wire.ClassBasic, 20, u16(0), sstr("work"), sstr("tag"),
		bitsOf(false, false, false, false), emptyTable())

	if d := p.Method(sess("reader", "/"), publish); d.Allow ||
		d.Reason != "publish_not_allowed" || d.Rule != "reader" {
		t.Errorf("publishing for the reader: %+v", d)
	}
	if d := p.Method(sess("reader", "/"), cons); !d.Allow {
		t.Errorf("consuming for the reader: %+v", d)
	}
	if d := p.Method(sess("writer", "/"), cons); d.Allow ||
		d.Reason != "consume_not_allowed" || d.Rule != "writer" {
		t.Errorf("consuming for the writer: %+v", d)
	}
	if d := p.Method(sess("writer", "/"), publish); !d.Allow {
		t.Errorf("publishing for the writer: %+v", d)
	}
}

// The bounds a rule can raise: the message size and the methods a connection
// may send before it has authenticated are per-connection costs, and the one
// account that really does send a ten-megabyte message is written down here
// rather than by raising the bound for everybody.
func TestARuleCanRaiseTheBoundsForItsOwnTraffic(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		MaxMessageBytes: 1 << 20, MaxMethods: 100,
		Rules: []config.AMQPRule{{Name: "bulk", Users: []string{"loader"},
			Action: "allow", MaxMessageBytes: 10 << 20, MaxMethods: 5000}}})
	if got := p.MaxMessage(sess("app", "/")); got != 1<<20 {
		t.Errorf("the listener's message bound is %d", got)
	}
	if got := p.MaxMessage(sess("loader", "/")); got != 10<<20 {
		t.Errorf("the rule's message bound is %d", got)
	}
	if got := p.MaxMethods(sess("app", "/")); got != 100 {
		t.Errorf("the listener's method bound is %d", got)
	}
	if got := p.MaxMethods(sess("loader", "/")); got != 5000 {
		t.Errorf("the rule's method bound is %d", got)
	}
}

// The identity decisions, in the order the connection makes them: the address,
// then the transport, then the mechanism, then the name, then the vhost.
//
// The order is the point. Each is decided with what the connection has
// disclosed so far, and the mechanism is decided before the name because the
// name arrives inside the mechanism's own exchange -- so a listener that
// refused a mechanism after reading the name has already taken a password off
// the wire.
func TestTheIdentityDecisionsAreMadeInOrder(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		AllowClients:   []string{"10.0.0.0/8"},
		DenyClients:    []string{"10.0.6.0/24"},
		DenyMechanisms: []string{"ANONYMOUS"},
		DenyUsers:      []string{"guest"},
		AllowVhosts:    []string{"/", "/orders*"},
		DenyVhosts:     []string{"/orders-staging"},
	})

	// The address: on both lists the deny wins, and off the allow list is a
	// refusal before anything else is read.
	for _, tc := range []struct {
		ip    string
		allow bool
	}{
		{"10.0.2.7", true},
		{"10.0.6.7", false}, // on both lists
		{"192.0.2.7", false},
	} {
		se := &Session{IP: netip.MustParseAddr(tc.ip), Secure: true, At: time.Now()}
		if d := p.Connect(se); d.Allow != tc.allow {
			t.Errorf("Connect from %s: %+v", tc.ip, d)
		}
	}
	// A connection with no address this relay could read is in no network.
	if d := p.Connect(&Session{Secure: true, At: time.Now()}); d.Allow {
		t.Errorf("a connection with no address: %+v", d)
	}

	// The mechanism, and the name inside it.
	if d := p.Mechanism("ANONYMOUS"); d.Allow || !d.Hard ||
		d.Reason != "mechanism_not_allowed" {
		t.Errorf("an anonymous login: %+v", d)
	}
	if d := p.Mechanism("PLAIN"); !d.Allow {
		t.Errorf("PLAIN: %+v", d)
	}
	if d := p.User("guest"); d.Allow || d.Reason != "user_not_allowed" {
		t.Errorf("the broker's default account: %+v", d)
	}
	if d := p.User("orders"); !d.Allow {
		t.Errorf("an account on neither list: %+v", d)
	}
	// A mechanism whose identity this relay cannot read is not a name to
	// decide about: the mechanism policy has already decided.
	if d := p.User(""); !d.Allow {
		t.Errorf("a mechanism carrying no name: %+v", d)
	}

	// The vhost, which is the broker's own access boundary. On both lists the
	// deny wins, and off the allow list is refused hard -- an exchange name
	// means something different in each vhost, so there is nothing below here
	// that could decide instead.
	s := sess("orders", "")
	for _, tc := range []struct {
		vhost string
		allow bool
	}{
		{"/", true},
		{"/orders", true},
		{"/orders-staging", false}, // on both lists
		{"/payments", false},
	} {
		d := p.Vhost(s, tc.vhost)
		if d.Allow != tc.allow {
			t.Errorf("Vhost %q: %+v", tc.vhost, d)
		}
		if !d.Allow && !d.Hard {
			t.Errorf("Vhost %q was refused softly", tc.vhost)
		}
	}
}

// A rule can narrow the vhosts its own traffic may open without narrowing the
// listener's list, which is how one account is kept inside one vhost.
func TestARuleCanNarrowTheVhostsItsOwnTrafficMayOpen(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		Rules: []config.AMQPRule{{Name: "ci", Users: []string{"ci"},
			Action: "allow", Vhosts: []string{"/ci*"}}}})
	if d := p.Vhost(sess("ci", "/ci"), "/ci"); !d.Allow {
		t.Errorf("the vhost the rule names: %+v", d)
	}
	// The rule covers this session (its vhost selector holds for the empty
	// vhost) and the vhost being opened is not one it names.
	if d := p.Vhost(sess("ci", ""), "/production"); d.Allow ||
		d.Reason != "vhost_not_allowed" || d.Rule != "ci" {
		t.Errorf("a vhost the rule does not name: %+v", d)
	}
}

// A connection that will not encrypt is refused before the SASL exchange,
// because that exchange is where the password goes: refusing afterwards would
// mean the credential had already crossed in the clear.
func TestAConnectionThatWillNotEncryptIsRefusedBeforeTheCredential(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		RequireTLS: no(true)})
	se := &Session{IP: netip.MustParseAddr("10.0.2.7"), At: time.Now()}
	if d := p.Connect(se); d.Allow || !d.Hard || d.Reason != "tls_required" {
		t.Errorf("a plaintext connection: %+v", d)
	}
	se.Secure = true
	if d := p.Connect(se); !d.Allow {
		t.Errorf("an encrypted connection: %+v", d)
	}
}

// The frame bound at Open, which is AMQP 1.0's own negotiation: a peer
// proposing a frame larger than this listener will buffer is refused rather
// than agreed with and then disappointed.
func TestTheFrameBoundIsDecidedAtOpen(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		MaxFrameBytes: 4096, AllowVhosts: []string{"/"}})
	s := &Session{IP: netip.MustParseAddr("10.0.2.7"), Version: wire.V10,
		Secure: true, Authed: true, At: time.Now()}
	if d := p.Open(s, "/", 4096); !d.Allow {
		t.Errorf("a frame size inside the bound: %+v", d)
	}
	if d := p.Open(s, "/", 1<<20); d.Allow || !d.Hard {
		t.Errorf("a frame size past the bound: %+v", d)
	}
	// And the vhost is decided here too, on the hostname the Open carried.
	if d := p.Open(s, "/payments", 4096); d.Allow || d.Reason != "vhost_not_allowed" {
		t.Errorf("a hostname off the list: %+v", d)
	}
}

// The mechanism and condition names this relay compares are ASCII tokens from
// the protocol, so they are folded without a dependency on the locale: a
// broker that answers "amqp:unauthorized-access" and one that answers
// "AMQP:Unauthorized-Access" are saying the same thing, and a comparison that
// folded by Unicode rules would fold a Turkish dotless i into an ASCII one and
// match a condition nobody sent.
func TestTheProtocolTokensAreFoldedAsASCII(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"PLAIN", "plain", true},
		{"PLAIN", "Plain", true},
		{"amqp:unauthorized-access", "AMQP:UNAUTHORIZED-ACCESS", true},
		{"", "", true},
		{"PLAIN", "PLAI", false},
		{"PLAIN", "PLAIM", false},
		// Not ASCII letters: folded by nothing, so they compare as the octets
		// they are rather than by some other alphabet's rules.
		{"i", "ı", false},
		{"[", "{", false},
	} {
		if got := equalFold(tc.a, tc.b); got != tc.want {
			t.Errorf("equalFold(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
