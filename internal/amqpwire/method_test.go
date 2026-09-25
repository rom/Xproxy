package amqpwire

import (
	"reflect"
	"strings"
	"testing"
)

// What each method names is the whole of what an exchange or queue policy
// decides on, so each layout is driven with a frame a client really sends
// and the targets are asserted in full -- a missing target is a name
// nothing checks.
func TestEachMethodNamesWhatAPolicyDecidesOn(t *testing.T) {
	for _, c := range []struct {
		name string
		args []byte
		id   [2]uint16
		want []Target
	}{
		{"exchange.declare", join(short(0), shortstr("events"), shortstr("topic"),
			bits(false, true, false, false, false), table()),
			[2]uint16{ClassExchange, 10},
			[]Target{{KindExchange, "events"}}},
		{"exchange.declare with an alternate exchange", join(short(0), shortstr("events"),
			shortstr("topic"), bits(false, true, false, false, false),
			table(entryS("alternate-exchange", "unrouted"))),
			[2]uint16{ClassExchange, 10},
			[]Target{{KindExchange, "events"}, {KindExchange, "unrouted"}}},
		{"exchange.delete", join(short(0), shortstr("events"), bits(false, false)),
			[2]uint16{ClassExchange, 20},
			[]Target{{KindExchange, "events"}}},
		{"exchange.bind", join(short(0), shortstr("dest"), shortstr("src"),
			shortstr("orders.#"), bits(false), table()),
			[2]uint16{ClassExchange, 30},
			[]Target{{KindExchange, "dest"}, {KindExchange, "src"}, {KindRoutingKey, "orders.#"}}},
		{"queue.declare", join(short(0), shortstr("work"),
			bits(false, true, false, false, false), table()),
			[2]uint16{ClassQueue, 10},
			[]Target{{KindQueue, "work"}}},
		{"queue.declare with a dead letter exchange", join(short(0), shortstr("work"),
			bits(false, true, false, false, false),
			table(entryI("x-max-length", 1000),
				entryS("x-dead-letter-exchange", "dlx"),
				entryS("x-dead-letter-routing-key", "dead"))),
			[2]uint16{ClassQueue, 10},
			[]Target{{KindQueue, "work"}, {KindExchange, "dlx"}, {KindRoutingKey, "dead"}}},
		{"queue.bind", join(short(0), shortstr("work"), shortstr("events"),
			shortstr("orders.created"), bits(false), table()),
			[2]uint16{ClassQueue, 20},
			[]Target{{KindQueue, "work"}, {KindExchange, "events"}, {KindRoutingKey, "orders.created"}}},
		{"queue.purge", join(short(0), shortstr("work"), bits(false)),
			[2]uint16{ClassQueue, 30},
			[]Target{{KindQueue, "work"}}},
		{"queue.delete", join(short(0), shortstr("work"), bits(false, false, false)),
			[2]uint16{ClassQueue, 40},
			[]Target{{KindQueue, "work"}}},
		{"basic.publish", join(short(0), shortstr("events"), shortstr("orders.created"),
			bits(false, false)),
			[2]uint16{ClassBasic, 40},
			[]Target{{KindExchange, "events"}, {KindRoutingKey, "orders.created"}}},
		{"basic.publish to the default exchange", join(short(0), shortstr(""), shortstr("work"),
			bits(false, false)),
			[2]uint16{ClassBasic, 40},
			[]Target{{KindExchange, ""}, {KindRoutingKey, "work"}}},
		{"basic.consume", join(short(0), shortstr("work"), shortstr("tag-1"),
			bits(false, false, false, false), table()),
			[2]uint16{ClassBasic, 20},
			[]Target{{KindQueue, "work"}}},
		{"basic.get", join(short(0), shortstr("work"), bits(true)),
			[2]uint16{ClassBasic, 70},
			[]Target{{KindQueue, "work"}}},
		{"basic.deliver", join(shortstr("tag-1"), longlong(7), bits(false),
			shortstr("events"), shortstr("orders.created")),
			[2]uint16{ClassBasic, 60},
			[]Target{{KindExchange, "events"}, {KindRoutingKey, "orders.created"}}},
		{"basic.get-ok", join(longlong(7), bits(false), shortstr("events"),
			shortstr("orders.created"), long(0)),
			[2]uint16{ClassBasic, 71},
			[]Target{{KindExchange, "events"}, {KindRoutingKey, "orders.created"}}},
		{"basic.return", join(short(312), shortstr("NO_ROUTE"), shortstr("events"),
			shortstr("orders.created")),
			[2]uint16{ClassBasic, 50},
			[]Target{{KindExchange, "events"}, {KindRoutingKey, "orders.created"}}},
		// A method that names none of these nouns says so, which is a
		// different answer from "I could not tell".
		{"basic.ack", join(longlong(7), bits(false)), [2]uint16{ClassBasic, 80}, nil},
		{"channel.open", shortstr(""), [2]uint16{ClassChannel, 10}, nil},
		{"tx.commit", nil, [2]uint16{ClassTx, 20}, nil},
	} {
		m, err := ParseMethod(method(c.id[0], c.id[1], c.args))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := m.Name(); got != c.name && !strings.HasPrefix(c.name, got) {
			t.Errorf("%s was named %q", c.name, got)
		}
		got, known := m.Targets()
		if !known {
			t.Errorf("%s: the layout was not read", c.name)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: targets = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// A method whose arguments do not lay out answers `known` false. This is
// the property the whole policy rests on: a name checked against an allow
// list has to be the name the broker will act on, so half a frame is no
// answer at all.
func TestAMethodThatDoesNotLayOutIsNotGuessedAt(t *testing.T) {
	// The fields a queue.bind's targets are read out of. Every truncation
	// of them is unknown rather than a shorter list of names.
	needed := join(short(0), shortstr("work"), shortstr("events"), shortstr("key"))
	for n := 0; n < len(needed); n++ {
		m, err := ParseMethod(method(ClassQueue, 20, needed[:n]))
		if err != nil {
			t.Fatal(err)
		}
		if _, known := m.Targets(); known {
			t.Errorf("%d octets of a %d octet queue.bind laid out", n, len(needed))
		}
	}
	// A frame with more after those fields than this package reads is not
	// a failure: a broker may add an argument to the end of a method, and
	// a relay that refused the connection over one would be refusing an
	// upgrade rather than an attack. What it read is what it needed.
	m, err := ParseMethod(method(ClassQueue, 20, join(needed, bits(false), table(),
		longstr([]byte("an argument from a later revision")))))
	if err != nil {
		t.Fatal(err)
	}
	if got, known := m.Targets(); !known || len(got) != 3 {
		t.Errorf("a queue.bind with a trailing argument read as %+v, %v", got, known)
	}
	// And a method nobody has heard of is unknown rather than empty.
	m, err = ParseMethod(method(199, 1, []byte{1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	if m.Known() {
		t.Error("class 199 is in the catalogue")
	}
	if _, known := m.Targets(); known {
		t.Error("an unknown method's targets were reported as known")
	}
	if got := m.Name(); got != "199.1" {
		t.Errorf("an unknown method was named %q", got)
	}
}

func TestAMethodFrameShorterThanItsClassIsRefused(t *testing.T) {
	for _, b := range [][]byte{nil, {0}, {0, 10}, {0, 10, 0}} {
		if _, err := ParseMethod(b); err == nil {
			t.Errorf("%d octets were read as a method", len(b))
		}
	}
}

// The identity out of a SASL response, and never the password.
func TestTheIdentityIsReadAndTheSecretIsNot(t *testing.T) {
	for _, c := range []struct {
		name, mech string
		resp       []byte
		want       string
	}{
		{"PLAIN", "PLAIN", []byte("\x00orders\x00hunter2"), "orders"},
		{"PLAIN acting as somebody", "PLAIN", []byte("admin\x00orders\x00hunter2"), "orders"},
		{"PLAIN with no authentication identity", "PLAIN", []byte("admin\x00\x00hunter2"), "admin"},
		{"AMQPLAIN", "AMQPLAIN", join(shortstr("LOGIN"), []byte{'S'}, longstr([]byte("orders")),
			shortstr("PASSWORD"), []byte{'S'}, longstr([]byte("hunter2"))), "orders"},
		{"EXTERNAL", "EXTERNAL", []byte("orders"), "orders"},
		{"EXTERNAL with the certificate deciding", "EXTERNAL", nil, ""},
		{"ANONYMOUS", "ANONYMOUS", []byte("anything"), ""},
		{"a mechanism nobody here reads", "RABBIT-CR-DEMO", []byte("orders"), ""},
	} {
		m, err := ParseMethod(method(ClassConnection, 11,
			table(), shortstr(c.mech), longstr(c.resp), shortstr("en_US")))
		if err != nil {
			t.Fatal(err)
		}
		mech, user, ok := m.Mechanism()
		if !ok {
			t.Errorf("%s: the start-ok was not read", c.name)
			continue
		}
		if mech != c.mech {
			t.Errorf("%s: mechanism = %q", c.name, mech)
		}
		if user != c.want {
			t.Errorf("%s: identity = %q, want %q", c.name, user, c.want)
		}
		// The point of the whole exercise: whatever came back, the
		// password is not in it.
		if strings.Contains(user, "hunter2") {
			t.Errorf("%s: the password came back in the identity", c.name)
		}
	}
}

func TestTheHandshakeFieldsAreRead(t *testing.T) {
	// connection.start: the mechanisms a broker offers.
	m, err := ParseMethod(method(ClassConnection, 10, octet(0), octet(9),
		table(entryS("product", "RabbitMQ")), longstr([]byte("PLAIN AMQPLAIN EXTERNAL")),
		longstr([]byte("en_US"))))
	if err != nil {
		t.Fatal(err)
	}
	mechs, ok := m.Mechanisms()
	if !ok || !reflect.DeepEqual(mechs, []string{"PLAIN", "AMQPLAIN", "EXTERNAL"}) {
		t.Errorf("mechanisms = %v, %v", mechs, ok)
	}

	// connection.tune: the three negotiated bounds.
	m, _ = ParseMethod(method(ClassConnection, 30, short(2047), long(131072), short(60)))
	ch, fr, hb, ok := m.Tune()
	if !ok || ch != 2047 || fr != 131072 || hb != 60 {
		t.Errorf("tune = %d, %d, %d, %v", ch, fr, hb, ok)
	}

	// connection.open: the virtual host.
	m, _ = ParseMethod(method(ClassConnection, 40, shortstr("/orders"), shortstr(""), bits(false)))
	vhost, ok := m.VirtualHost()
	if !ok || vhost != "/orders" {
		t.Errorf("vhost = %q, %v", vhost, ok)
	}

	// connection.close: the broker's own account of why.
	m, _ = ParseMethod(method(ClassConnection, 50, short(403), shortstr("ACCESS_REFUSED - access to exchange 'x' refused"),
		short(ClassBasic), short(40)))
	code, text, class, id, ok := m.CloseReason()
	if !ok || code != 403 || !strings.HasPrefix(text, "ACCESS_REFUSED") || class != ClassBasic || id != 40 {
		t.Errorf("close = %d, %q, %d, %d, %v", code, text, class, id, ok)
	}

	// basic.consume: the acknowledgement mode, which is a policy of its own.
	m, _ = ParseMethod(method(ClassBasic, 20, short(0), shortstr("work"), shortstr("tag-1"),
		bits(false, true, true, false), table()))
	tag, noAck, exclusive, ok := m.Consumer()
	if !ok || tag != "tag-1" || !noAck || !exclusive {
		t.Errorf("consumer = %q, %v, %v, %v", tag, noAck, exclusive, ok)
	}

	// queue.declare and exchange.declare: durability, and the exchange type.
	m, _ = ParseMethod(method(ClassQueue, 10, short(0), shortstr("work"),
		bits(false, true, false, true, false), table()))
	name, passive, durable, excl, autoDelete, ok := m.Queue()
	if !ok || name != "work" || passive || !durable || excl || !autoDelete {
		t.Errorf("queue = %q, %v, %v, %v, %v, %v", name, passive, durable, excl, autoDelete, ok)
	}
	m, _ = ParseMethod(method(ClassExchange, 10, short(0), shortstr("events"),
		shortstr("x-delayed-message"), bits(false, true, false, true, false), table()))
	name, kind, passive, durable, internal, ok := m.Exchange()
	if !ok || name != "events" || kind != "x-delayed-message" || passive || !durable || !internal {
		t.Errorf("exchange = %q, %q, %v, %v, %v, %v", name, kind, passive, durable, internal, ok)
	}

	// And each accessor answers only about its own method.
	m, _ = ParseMethod(method(ClassBasic, 80, longlong(1), bits(false)))
	if _, _, ok := m.Mechanism(); ok {
		t.Error("a basic.ack was read as a start-ok")
	}
	if _, ok := m.VirtualHost(); ok {
		t.Error("a basic.ack was read as a connection.open")
	}
	if _, _, _, ok := m.Tune(); ok {
		t.Error("a basic.ack was read as a tune")
	}
	if _, _, _, ok := m.Consumer(); ok {
		t.Error("a basic.ack was read as a consume")
	}
	if _, _, _, _, ok := m.CloseReason(); ok {
		t.Error("a basic.ack was read as a close")
	}
}
