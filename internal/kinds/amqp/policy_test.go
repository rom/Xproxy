package amqp

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/amqpwire"
	"github.com/rom/xproxy/internal/config"
)

// The policy on its own, before any socket is involved. Every case here is one
// an operator writes in the file, so each is driven through compile() rather
// than by building the struct: a policy that only works when a test builds it
// by hand is a policy nobody can configure.

func compiled(t *testing.T, c *config.AMQPListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func no(v bool) *bool { return &v }

// sess is a session that has got as far as being authenticated, which is where
// most of the policy applies.
func sess(user, vhost string) *Session {
	return &Session{IP: netip.MustParseAddr("10.0.2.7"), Version: wire.V091,
		User: user, Vhost: vhost, Secure: true, Authed: true, At: time.Now()}
}

func meth(t *testing.T, class, id uint16, args ...[]byte) *wire.Method {
	t.Helper()
	payload := append(u16(class), u16(id)...)
	for _, a := range args {
		payload = append(payload, a...)
	}
	m, err := wire.ParseMethod(payload)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The default posture: an application can do its work, and cannot change the
// broker.
func TestTheDefaultAllowsWorkAndNotTopology(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow"})
	s := sess("orders", "/")

	for _, c := range []struct {
		name  string
		m     *wire.Method
		allow bool
	}{
		{"publish", meth(t, wire.ClassBasic, 40, u16(0), sstr("events"), sstr("orders.created"), bitsOf(false, false)), true},
		{"consume", meth(t, wire.ClassBasic, 20, u16(0), sstr("work"), sstr("tag"), bitsOf(false, false, false, false), emptyTable()), true},
		{"ack", meth(t, wire.ClassBasic, 80, u64(1), bitsOf(false)), true},
		{"get", meth(t, wire.ClassBasic, 70, u16(0), sstr("work"), bitsOf(false)), true},
		{"qos", meth(t, wire.ClassBasic, 10, u32(0), u16(10), bitsOf(false)), true},
		{"channel.open", meth(t, wire.ClassChannel, 10, sstr("")), true},
		{"confirm.select", meth(t, wire.ClassConfirm, 10, bitsOf(false)), true},
		// Topology, all of it, off.
		{"queue.declare", meth(t, wire.ClassQueue, 10, u16(0), sstr("work"), bitsOf(false, true, false, false, false), emptyTable()), false},
		{"queue.delete", meth(t, wire.ClassQueue, 40, u16(0), sstr("work"), bitsOf(false, false, false)), false},
		{"queue.purge", meth(t, wire.ClassQueue, 30, u16(0), sstr("work"), bitsOf(false)), false},
		{"queue.bind", meth(t, wire.ClassQueue, 20, u16(0), sstr("work"), sstr("events"), sstr("k"), bitsOf(false), emptyTable()), false},
		{"exchange.declare", meth(t, wire.ClassExchange, 10, u16(0), sstr("events"), sstr("topic"), bitsOf(false, true, false, false, false), emptyTable()), false},
		{"exchange.delete", meth(t, wire.ClassExchange, 20, u16(0), sstr("events"), bitsOf(false, false)), false},
		// And the administrative one.
		{"update-secret", meth(t, wire.ClassConnection, 70, lstr([]byte("new")), sstr("rotated")), false},
	} {
		d := p.Method(s, c.m)
		if d.Allow != c.allow {
			t.Errorf("%s: allow = %v (%s %s), want %v", c.name, d.Allow, d.Reason, d.Detail, c.allow)
		}
	}
}

// The destructive methods are refused even in monitor mode: a purge forwarded
// so that it could be written down is a queue that is empty.
// An observe rule records and decides nothing, so the rules below it still
// decide. A rule that allowed what it covered would make trying one out the way
// to switch off every deny rule under it, which is the opposite of a trial.
func TestAnObserveRuleIsRecordedAndDecidesNothing(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "deny",
		Rules: []config.AMQPRule{{Name: "trial", Users: []string{"app"}, Action: "observe"}}})
	s := sess("app", "/")
	d := p.Method(s, meth(t, wire.ClassBasic, 40, u16(0), sstr("ex"), sstr("rk"), bitsOf(false, false)))
	if d.Allow {
		t.Fatalf("a trial rule decided, by allowing: %+v", d)
	}
	if len(d.Observed) != 1 || d.Observed[0] != "trial" {
		t.Errorf("the rule being tried was not recorded: %+v", d.Observed)
	}
	// And the deny rule under it decides.
	p = compiled(t, &config.AMQPListener{Upstream: "mq", DefaultAction: "allow",
		Rules: []config.AMQPRule{
			{Name: "trial", Users: []string{"app"}, Action: "observe"},
			{Name: "lockdown", Users: []string{"app"}, Action: "deny"},
		}})
	if d := p.Method(s, meth(t, wire.ClassBasic, 40, u16(0), sstr("ex"), sstr("rk"), bitsOf(false, false))); d.Allow || d.Rule != "lockdown" {
		t.Errorf("the trial rule shadowed the deny rule: %+v", d)
	}
}

func TestTheDestructiveMethodsAreNeverShadowed(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", MonitorOnly: true, DefaultAction: "allow"})
	s := sess("orders", "/")
	for _, c := range []struct {
		name string
		m    *wire.Method
		hard bool
	}{
		{"queue.delete", meth(t, wire.ClassQueue, 40, u16(0), sstr("work"), bitsOf(false, false, false)), true},
		{"queue.purge", meth(t, wire.ClassQueue, 30, u16(0), sstr("work"), bitsOf(false)), true},
		{"exchange.delete", meth(t, wire.ClassExchange, 20, u16(0), sstr("events"), bitsOf(false, false)), true},
		// A declare changes the topology and destroys nothing, so a trial
		// run can see it happen -- which is what monitor mode is for.
		{"queue.declare", meth(t, wire.ClassQueue, 10, u16(0), sstr("w"), bitsOf(false, true, false, false, false), emptyTable()), false},
		{"exchange.declare", meth(t, wire.ClassExchange, 10, u16(0), sstr("e"), sstr("topic"), bitsOf(false, true, false, false, false), emptyTable()), false},
	} {
		d := p.Method(s, c.m)
		if d.Allow {
			t.Errorf("%s was allowed", c.name)
			continue
		}
		if d.Hard != c.hard {
			t.Errorf("%s: hard = %v, want %v", c.name, d.Hard, c.hard)
		}
	}
}

// The two arguments that name an exchange nothing else in the method mentions.
// This is the finding the wire package was written for: a policy that checked
// only the declared name would let a client have the broker route to an
// exchange it may not publish to.
func TestTheHiddenExchangeArgumentsAreChecked(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		AllowTopology: true, AllowExchanges: []string{"events", "events.*"},
		AllowQueues: []string{"work"}})
	s := sess("orders", "/")

	// A queue whose dead-letter exchange is inside the policy.
	ok := meth(t, wire.ClassQueue, 10, u16(0), sstr("work"),
		bitsOf(false, true, false, false, false),
		tbl(entryStr("x-dead-letter-exchange", "events.dead")))
	if d := p.Method(s, ok); !d.Allow {
		t.Errorf("a dead-letter exchange inside the policy was refused: %s %s", d.Reason, d.Detail)
	}
	// And one outside it.
	bad := meth(t, wire.ClassQueue, 10, u16(0), sstr("work"),
		bitsOf(false, true, false, false, false),
		tbl(entryStr("x-dead-letter-exchange", "somebody-elses")))
	d := p.Method(s, bad)
	if d.Allow {
		t.Fatal("a queue routed its dead letters to an exchange outside the policy")
	}
	if d.Reason != "exchange_not_allowed" || d.Detail != "somebody-elses" {
		t.Errorf("refusal = %s %q", d.Reason, d.Detail)
	}
	// The alternate exchange of an exchange is the same story.
	alt := meth(t, wire.ClassExchange, 10, u16(0), sstr("events"), sstr("topic"),
		bitsOf(false, true, false, false, false),
		tbl(entryStr("alternate-exchange", "somebody-elses")))
	if d := p.Method(s, alt); d.Allow || d.Reason != "exchange_not_allowed" {
		t.Errorf("an alternate exchange outside the policy: allow=%v %s", d.Allow, d.Reason)
	}
	// A table this relay cannot read is a refusal rather than a guess.
	unreadable := meth(t, wire.ClassQueue, 10, u16(0), sstr("work"),
		bitsOf(false, true, false, false, false),
		tbl(append(sstr("mystery"), 'Z', 0)))
	if d := p.Method(s, unreadable); d.Allow || d.Reason != "arguments_unreadable" {
		t.Errorf("an unreadable table: allow=%v %s", d.Allow, d.Reason)
	}
}

func TestTheNameListsAreGlobsThatDoNotCrossASeparator(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		AllowExchanges: []string{"events"}, AllowRoutingKeys: []string{"orders.*"},
		DenyQueues: []string{"*.internal"}})
	s := sess("orders", "/")
	pub := func(ex, key string) Decision {
		return p.Method(s, meth(t, wire.ClassBasic, 40, u16(0), sstr(ex), sstr(key), bitsOf(false, false)))
	}
	if d := pub("events", "orders.created"); !d.Allow {
		t.Errorf("orders.created was refused: %s", d.Reason)
	}
	// A glob does not cross the separator, which is the distinction a routing
	// key policy is about.
	if d := pub("events", "orders.eu.created"); d.Allow {
		t.Error("orders.eu.created passed a policy of orders.*")
	}
	if d := pub("other", "orders.created"); d.Allow || d.Reason != "exchange_not_allowed" {
		t.Errorf("an exchange outside the list: allow=%v %s", d.Allow, d.Reason)
	}
	// A deny list wins, and matches by pattern too.
	if d := p.Method(s, meth(t, wire.ClassBasic, 20, u16(0), sstr("audit.internal"),
		sstr("t"), bitsOf(false, false, false, false), emptyTable())); d.Allow {
		t.Error("a queue on the deny list was allowed")
	}
	// The default exchange is named by the empty string, and a policy that
	// does not mention it does not allow it.
	if d := pub("", "work"); d.Allow {
		t.Error("the default exchange passed a list that does not name it")
	}
	// Naming it deliberately does.
	p2 := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		AllowExchanges: []string{""}, AllowRoutingKeys: []string{"work"}})
	if d := p2.Method(s, meth(t, wire.ClassBasic, 40, u16(0), sstr(""), sstr("work"),
		bitsOf(false, false))); !d.Allow {
		t.Errorf("the default exchange named in the list was refused: %s", d.Reason)
	}
}

// The broker's own administration nodes, which are how a client reads the
// broker over the connection it publishes on.
func TestTheManagementNodesAreRefusedByDefault(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow"})
	s := sess("orders", "/")
	for _, ex := range []string{"amq.rabbitmq.log", "amq.rabbitmq.trace", "amq.rabbitmq.event"} {
		d := p.Method(s, meth(t, wire.ClassBasic, 20, u16(0), sstr("q"), sstr("t"),
			bitsOf(false, false, false, false), emptyTable()))
		_ = d
		pub := p.Method(s, meth(t, wire.ClassBasic, 40, u16(0), sstr(ex), sstr("k"), bitsOf(false, false)))
		if pub.Allow || pub.Reason != "management_node_denied" {
			t.Errorf("%s: allow=%v %s", ex, pub.Allow, pub.Reason)
		}
		if !pub.Hard {
			t.Errorf("%s: the refusal was shadowable", ex)
		}
	}
	// An ordinary amq. exchange is not management: amq.topic and amq.direct
	// are the broker's built-in exchanges that every application uses.
	if d := p.Method(s, meth(t, wire.ClassBasic, 40, u16(0), sstr("amq.topic"),
		sstr("k"), bitsOf(false, false))); !d.Allow {
		t.Errorf("amq.topic was refused as a management node: %s", d.Reason)
	}
	// And an operator who names one has said so.
	p2 := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		DenyManagementNodes: no(false), AllowExchanges: []string{"amq.rabbitmq.log"}})
	if d := p2.Method(s, meth(t, wire.ClassBasic, 40, u16(0), sstr("amq.rabbitmq.log"),
		sstr("k"), bitsOf(false, false))); !d.Allow {
		t.Errorf("a management exchange named in the list was refused: %s", d.Reason)
	}
}

func TestTheProtocolVersionIsDecidedBeforeAnythingElse(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", Versions: []string{"0-9-1"}})
	hdr := func(b ...byte) wire.Header {
		h, err := wire.ParseHeader(append([]byte("AMQP"), b...))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	for _, c := range []struct {
		name   string
		h      wire.Header
		allow  bool
		reason string
	}{
		{"0-9-1", hdr(0, 0, 9, 1), true, ""},
		{"1.0, not on the list", hdr(0, 1, 0, 0), false, "protocol_version_not_allowed"},
		{"0-8", hdr(1, 1, 8, 0), false, "protocol_version_not_allowed"},
		{"something else entirely", hdr(0, 7, 3, 2), false, "protocol_version_unknown"},
	} {
		d := p.Version(c.h)
		if d.Allow != c.allow || (!c.allow && d.Reason != c.reason) {
			t.Errorf("%s: allow=%v %s, want %v %s", c.name, d.Allow, d.Reason, c.allow, c.reason)
		}
		if !d.Allow && !d.Hard {
			t.Errorf("%s: the refusal was shadowable", c.name)
		}
	}
	// 1.0's TLS identifier asks this relay to negotiate transport security
	// from a first octet. The answer is a TLS port.
	both := compiled(t, &config.AMQPListener{Upstream: "b"})
	if d := both.Version(hdr(2, 1, 0, 0)); d.Allow || d.Reason != "tls_negotiation_refused" {
		t.Errorf("the TLS identifier: allow=%v %s", d.Allow, d.Reason)
	}
	// And the SASL layer of an allowed version is allowed, because that is
	// how a 1.0 connection authenticates at all.
	if d := both.Version(hdr(3, 1, 0, 0)); !d.Allow {
		t.Errorf("the SASL layer was refused: %s", d.Reason)
	}
}

func TestTheMechanismAndTheIdentityAreDecidedSeparately(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", AllowUsers: []string{"orders"}})
	for _, c := range []struct {
		mech  string
		allow bool
	}{{"PLAIN", true}, {"plain", true}, {"EXTERNAL", true}, {"ANONYMOUS", false}, {"", false},
		{"RABBIT-CR-DEMO", false}} {
		if d := p.Mechanism(c.mech); d.Allow != c.allow {
			t.Errorf("mechanism %q: allow=%v, want %v", c.mech, d.Allow, c.allow)
		}
	}
	if d := p.User("orders"); !d.Allow {
		t.Error("the allowed user was refused")
	}
	if d := p.User("admin"); d.Allow {
		t.Error("a user outside the list was allowed")
	}
	// A mechanism whose identity cannot be read is decided on the mechanism
	// alone; a rule about users does not match, and that is not a refusal.
	if d := p.User(""); !d.Allow {
		t.Error("a mechanism with no readable identity was refused as a user")
	}
	// ANONYMOUS is off even when the user list would have admitted the
	// empty identity, because it is the mechanism that is the problem.
	if d := p.Mechanism("ANONYMOUS"); d.Allow || !d.Hard {
		t.Errorf("ANONYMOUS: allow=%v hard=%v", d.Allow, d.Hard)
	}
}

func TestTheNegotiatedBoundsAreDecided(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", MaxFrameBytes: 131072, MaxChannels: 8,
		RequireHeartbeat: true})
	for _, c := range []struct {
		name   string
		ch     uint16
		fr     uint32
		hb     uint16
		allow  bool
		reason string
	}{
		{"the ordinary negotiation", 8, 131072, 60, true, ""},
		{"an unbounded frame size", 8, 0, 60, false, "frame_max_unbounded"},
		{"a frame size over the bound", 8, 1 << 20, 60, false, "frame_max_too_large"},
		// The channel bound is not the negotiation's business: a broker's
		// own default is a channel-max in the thousands and every client
		// echoes it, so this has to pass -- max_channels is enforced by
		// counting the channels that are actually opened.
		{"the channel-max a broker offers", 2047, 131072, 60, true, ""},
		{"unbounded channels", 0, 131072, 60, true, ""},
		{"no heartbeat", 8, 131072, 0, false, "heartbeat_disabled"},
	} {
		d := p.Tune(c.ch, c.fr, c.hb)
		if d.Allow != c.allow || (!c.allow && d.Reason != c.reason) {
			t.Errorf("%s: allow=%v %s, want %v %s", c.name, d.Allow, d.Reason, c.allow, c.reason)
		}
	}
	// And the bound that is enforced is enforced by counting: the ninth
	// channel on a listener that allows eight is refused, whatever the two
	// sides agreed.
	se := &session{channels: map[uint16]bool{}}
	for ch := uint16(1); ch <= 8; ch++ {
		if !se.openChannel(ch, p.MaxChannels()) {
			t.Fatalf("channel %d was refused inside the bound", ch)
		}
	}
	if se.openChannel(9, p.MaxChannels()) {
		t.Error("a ninth channel was opened on a listener that allows eight")
	}

	// Without require_heartbeat, a connection with none is ordinary.
	p2 := compiled(t, &config.AMQPListener{Upstream: "b"})
	if d := p2.Tune(8, 4096, 0); !d.Allow {
		t.Errorf("a heartbeat of zero was refused by default: %s", d.Reason)
	}
}

// A message's own properties: the size before the body, the identity that makes
// it attributable, and the reply queue nothing else names.
func TestTheContentPolicy(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		MaxMessageBytes: 1024, RequireUserID: true, MaxPriority: 4,
		AllowQueues: []string{"replies.*"}})
	s := sess("orders", "/")
	hdr := func(size uint64, props map[string]string, priority uint8) *wire.ContentHeader {
		h := &wire.ContentHeader{BodySize: size, Set: map[string]bool{}}
		for k, v := range props {
			h.Set[k] = true
			switch k {
			case "user_id":
				h.UserID = v
			case "reply_to":
				h.ReplyTo = v
			}
		}
		if priority > 0 {
			h.Set["priority"] = true
			h.Priority = priority
		}
		return h
	}
	if d := p.Content(s, hdr(100, map[string]string{"user_id": "orders"}, 0)); !d.Allow {
		t.Errorf("an ordinary message was refused: %s %s", d.Reason, d.Detail)
	}
	// The size is refused on what the header declared, which is before the
	// body arrives.
	d := p.Content(s, hdr(4096, map[string]string{"user_id": "orders"}, 0))
	if d.Allow || d.Reason != "message_too_large" || !d.Hard {
		t.Errorf("an oversize message: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
	if d := p.Content(s, hdr(10, nil, 0)); d.Allow || d.Reason != "user_id_missing" {
		t.Errorf("a message with no user identifier: allow=%v %s", d.Allow, d.Reason)
	}
	if d := p.Content(s, hdr(10, map[string]string{"user_id": "somebody"}, 0)); d.Allow || d.Reason != "user_id_mismatch" {
		t.Errorf("a message claiming to be somebody else: allow=%v %s", d.Allow, d.Reason)
	}
	if d := p.Content(s, hdr(10, map[string]string{"user_id": "orders"}, 9)); d.Allow || d.Reason != "priority_too_high" {
		t.Errorf("a priority over the bound: allow=%v %s", d.Allow, d.Reason)
	}
	if d := p.Content(s, hdr(10, map[string]string{"user_id": "orders", "reply_to": "replies.abc"}, 0)); !d.Allow {
		t.Errorf("an allowed reply queue was refused: %s", d.Reason)
	}
	d = p.Content(s, hdr(10, map[string]string{"user_id": "orders", "reply_to": "somebody.elses"}, 0))
	if d.Allow || d.Reason != "reply_to_not_allowed" {
		t.Errorf("a reply queue outside the policy: allow=%v %s", d.Allow, d.Reason)
	}
}

// The inbound direction: the deny lists apply and the allow lists do not.
func TestTheInboundDirectionAppliesOnlyTheDenyLists(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		AllowExchanges: []string{"events"}, DenyExchanges: []string{"payroll"}})
	s := sess("orders", "/")
	// A delivery from an exchange the consumer may not name is ordinary: the
	// binding was somebody else's, and requiring it on the allow list would
	// break every consumer.
	if d := p.Delivery(s, []wire.Target{{Kind: wire.KindExchange, Name: "somebody-elses"}}); !d.Allow {
		t.Errorf("an ordinary delivery was refused: %s %s", d.Reason, d.Detail)
	}
	// A delivery from an exchange on the deny list is not.
	d := p.Delivery(s, []wire.Target{{Kind: wire.KindExchange, Name: "payroll"}})
	if d.Allow || d.Reason != "delivery_denied" || !d.Hard {
		t.Errorf("a denied delivery: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
}

// AMQP 1.0: the same policy, decided on the address a link attaches to.
func TestTheOnePolicyDecidesBothVersions(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		AllowExchanges: []string{"events"}, AllowQueues: []string{"work"},
		AllowRoutingKeys: []string{"orders.*"}})
	s := &Session{IP: netip.MustParseAddr("10.0.2.7"), Version: wire.V10,
		User: "orders", Secure: true, Authed: true, At: time.Now()}

	attach := func(role string, address string, dynamic bool) Decision {
		var fields [][]byte
		receiver := role == wire.RoleReceiver
		src, tgt := tgt10("", false), tgt10(address, dynamic)
		if receiver {
			src, tgt = src10(address, dynamic), src10("", false)
		}
		fields = [][]byte{s10("link"), u10(3), bool10(receiver), null10(), null10(), src, tgt}
		return p.Performative(s, perf(t, 0x12, fields...))
	}
	if d := attach(wire.RoleSender, "/exchange/events/orders.created", false); !d.Allow {
		t.Errorf("a sender to an allowed address was refused: %s %s", d.Reason, d.Detail)
	}
	if d := attach(wire.RoleSender, "/exchange/payroll/salaries", false); d.Allow {
		t.Error("a sender to an exchange outside the policy was allowed")
	}
	if d := attach(wire.RoleReceiver, "/queue/work", false); !d.Allow {
		t.Errorf("a receiver from an allowed queue was refused: %s %s", d.Reason, d.Detail)
	}
	if d := attach(wire.RoleReceiver, "/queue/somebody-elses", false); d.Allow {
		t.Error("a receiver from a queue outside the policy was allowed")
	}
	// A dynamic link has no address to check: it asks the broker to make a
	// node, which is how a reply queue is created on this version.
	if d := attach(wire.RoleReceiver, "", true); !d.Allow {
		t.Errorf("a dynamic link was refused: %s %s", d.Reason, d.Detail)
	}
	// The management nodes of this version.
	for _, node := range []string{"$management", "$cbs", "/$management"} {
		if d := attach(wire.RoleSender, node, false); d.Allow || d.Reason != "management_node_denied" {
			t.Errorf("%s: allow=%v %s", node, d.Allow, d.Reason)
		}
	}
	// publish and consume decide an attach, because a sender is publishing.
	pc := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		AllowPublish: no(false)})
	if d := pc.Performative(s, perf(t, 0x12, s10("l"), u10(1), bool10(false), null10(), null10(),
		src10("", false), tgt10("/queue/work", false))); d.Allow || d.Reason != "publish_not_allowed" {
		t.Errorf("a sender with publishing off: allow=%v %s", d.Allow, d.Reason)
	}
}

func TestAnOperationBeforeAuthenticationIsRefused(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow"})
	before := &Session{IP: netip.MustParseAddr("10.0.2.7"), Version: wire.V091,
		Secure: true, At: time.Now()}
	// The handshake is allowed, because without it there is no connection.
	for _, name := range []string{"connection.start-ok", "connection.tune-ok", "connection.close"} {
		class, id, _ := wire.MethodID(name)
		if d := p.Method(before, meth(t, class, id)); !d.Allow && d.Reason == "not_authenticated" {
			t.Errorf("%s was refused before authentication", name)
		}
	}
	// A publish is not.
	d := p.Method(before, meth(t, wire.ClassBasic, 40, u16(0), sstr("events"), sstr("k"), bitsOf(false, false)))
	if d.Allow || d.Reason != "not_authenticated" || !d.Hard {
		t.Errorf("a publish before authentication: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
	// On 1.0 the SASL exchange is what may come first.
	v10 := &Session{IP: netip.MustParseAddr("10.0.2.7"), Version: wire.V10, Secure: true, At: time.Now()}
	if d := p.Performative(v10, perf(t, 0x41, sym10("PLAIN"), bin10([]byte("\x00u\x00p")))); !d.Allow {
		t.Errorf("sasl-init was refused before authentication: %s", d.Reason)
	}
	if d := p.Performative(v10, perf(t, 0x12, s10("l"), u10(1), bool10(false))); d.Allow || d.Reason != "not_authenticated" {
		t.Errorf("an attach before authentication: allow=%v %s", d.Allow, d.Reason)
	}
}

func TestARuleWidensForItsOwnTraffic(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		AllowQueues: []string{"work"},
		Rules: []config.AMQPRule{{
			Name: "deployment", Users: []string{"deploy"},
			AllowTopology: no(true), AllowQueues: []string{"work", "work.*"},
		}},
	})
	declare := meth(t, wire.ClassQueue, 10, u16(0), sstr("work.retry"),
		bitsOf(false, true, false, false, false), emptyTable())
	if d := p.Method(sess("deploy", "/"), declare); !d.Allow {
		t.Errorf("the deployment account could not declare: %s %s", d.Reason, d.Detail)
	}
	if d := p.Method(sess("orders", "/"), declare); d.Allow {
		t.Error("an application account declared a queue")
	}
	// A rule with a schedule closes outside it.
	sched := compiled(t, &config.AMQPListener{Upstream: "b",
		Rules: []config.AMQPRule{{
			Name: "window", Users: []string{"deploy"}, AllowTopology: no(true),
			Schedule: &config.ModbusSchedule{Days: []string{"mon"}, From: "02:00", To: "03:00"},
		}},
	})
	s := sess("deploy", "/")
	s.At = time.Date(2026, 3, 3, 15, 0, 0, 0, time.UTC) // a Tuesday afternoon
	if d := sched.Method(s, declare); d.Allow || d.Reason != "outside_schedule" {
		t.Errorf("outside the window: allow=%v %s", d.Allow, d.Reason)
	}
}

func TestTheDefaultActionDecidesWhenNoRuleMatched(t *testing.T) {
	publish := func(t *testing.T, p *policy) Decision {
		return p.Method(sess("orders", "/"),
			meth(t, wire.ClassBasic, 40, u16(0), sstr("events"), sstr("k"), bitsOf(false, false)))
	}
	deny := compiled(t, &config.AMQPListener{Upstream: "b"})
	if d := publish(t, deny); d.Allow || d.Reason != "no_rule_matched" {
		t.Errorf("with the default deny: allow=%v %s", d.Allow, d.Reason)
	}
	allowAll := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow"})
	if d := publish(t, allowAll); !d.Allow {
		t.Errorf("with the default allow: %s", d.Reason)
	}
}

func TestACompileErrorIsAConfigurationError(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  *config.AMQPListener
		want string
	}{
		{"a method nobody defines", &config.AMQPListener{Upstream: "b",
			AllowMethods: []string{"queue.del"}}, "not an AMQP 0-9-1 method"},
		{"a performative nobody defines", &config.AMQPListener{Upstream: "b",
			AllowPerformatives: []string{"transfers"}}, "not an AMQP 1.0 performative"},
		{"a version nobody defines", &config.AMQPListener{Upstream: "b",
			Versions: []string{"0-10"}}, "not 0-9-1 or 1.0"},
		{"a default action nobody defines", &config.AMQPListener{Upstream: "b",
			DefaultAction: "maybe"}, "not allow or deny"},
		{"a client address that is not one", &config.AMQPListener{Upstream: "b",
			AllowClients: []string{"10.0.0.1"}}, "allow_clients"},
		{"a pattern that cannot compile", &config.AMQPListener{Upstream: "b",
			AllowExchanges: []string{"[a-"}}, "pattern"},
		{"a rule action nobody defines", &config.AMQPListener{Upstream: "b",
			Rules: []config.AMQPRule{{Action: "maybe"}}}, "not allow, deny or observe"},
	} {
		_, err := compile(c.cfg)
		if err == nil {
			t.Errorf("%s: compiled", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestAnUnknownMethodIsRefusedRatherThanForwarded(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow"})
	s := sess("orders", "/")
	if d := p.Method(s, meth(t, 199, 1, []byte{1, 2, 3})); d.Allow || d.Reason != "method_unknown" || !d.Hard {
		t.Errorf("an unknown method: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
	if d := p.Performative(s, perf(t, 0x77, s10("x"))); d.Allow || d.Reason != "performative_unknown" {
		t.Errorf("an unknown performative: allow=%v %s", d.Allow, d.Reason)
	}
}

func TestNoAckCanBeRefused(t *testing.T) {
	p := compiled(t, &config.AMQPListener{Upstream: "b", DefaultAction: "allow",
		AllowNoAck: no(false)})
	s := sess("orders", "/")
	noAck := meth(t, wire.ClassBasic, 20, u16(0), sstr("work"), sstr("t"),
		bitsOf(false, true, false, false), emptyTable())
	if d := p.Method(s, noAck); d.Allow || d.Reason != "no_ack_not_allowed" {
		t.Errorf("a no-ack consume: allow=%v %s", d.Allow, d.Reason)
	}
	acking := meth(t, wire.ClassBasic, 20, u16(0), sstr("work"), sstr("t"),
		bitsOf(false, false, false, false), emptyTable())
	if d := p.Method(s, acking); !d.Allow {
		t.Errorf("an acknowledging consume was refused: %s", d.Reason)
	}
}
