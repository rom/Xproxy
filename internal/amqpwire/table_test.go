package amqpwire

import (
	"strings"
	"testing"
)

// The field table is where the two exchange names that nothing else
// mentions live, and where a reader that guessed would put a policy on the
// wrong field. Every type code is driven, because skipping one wrong puts
// every entry after it at the wrong offset.
func TestEveryFieldTypeIsSteppedOverExactly(t *testing.T) {
	// A table with one entry of each type this package walks, and the two
	// text entries a policy is about at the end -- so any type skipped by
	// the wrong width loses them.
	entries := [][]byte{
		join(shortstr("bool"), []byte{'t'}, octet(1)),
		join(shortstr("i8"), []byte{'b'}, octet(0xff)),
		join(shortstr("u8"), []byte{'B'}, octet(200)),
		join(shortstr("i16"), []byte{'s'}, short(1000)),
		join(shortstr("u16"), []byte{'u'}, short(1000)),
		join(shortstr("i16spec"), []byte{'U'}, short(1000)),
		join(shortstr("i32"), []byte{'I'}, long(70000)),
		join(shortstr("u32"), []byte{'i'}, long(70000)),
		join(shortstr("i64"), []byte{'l'}, longlong(1<<40)),
		join(shortstr("i64spec"), []byte{'L'}, longlong(1<<40)),
		join(shortstr("float"), []byte{'f'}, long(0x40490fdb)),
		join(shortstr("double"), []byte{'d'}, longlong(0x400921fb54442d18)),
		join(shortstr("decimal"), []byte{'D'}, octet(2), long(31415)),
		join(shortstr("stamp"), []byte{'T'}, longlong(1700000000)),
		join(shortstr("void"), []byte{'V'}),
		join(shortstr("bytes"), []byte{'x'}, longstr([]byte{1, 2, 3})),
		join(shortstr("array"), []byte{'A'}, longstr(join([]byte{'I'}, long(1), []byte{'S'}, longstr([]byte("two"))))),
		entryTable("nested", entryS("inner", "value")),
		entryS("x-dead-letter-exchange", "dlx"),
		entryS("x-dead-letter-routing-key", "dead"),
	}
	m, err := ParseMethod(method(ClassQueue, 10, short(0), shortstr("work"),
		bits(false, true, false, false, false), table(entries...)))
	if err != nil {
		t.Fatal(err)
	}
	got, known := m.Targets()
	if !known {
		t.Fatal("a table of every type was not read")
	}
	want := []Target{{KindQueue, "work"}, {KindExchange, "dlx"}, {KindRoutingKey, "dead"}}
	if len(got) != len(want) {
		t.Fatalf("targets = %+v, want %+v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("target %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A type code nothing defines cannot be skipped, because its length is
// whatever its definition says. The honest answer is that the table is
// unreadable -- which the policy turns into a refusal, rather than acting
// on the entries that happened to come first.
func TestAnUnknownFieldTypeMakesTheTableUnreadable(t *testing.T) {
	m, err := ParseMethod(method(ClassQueue, 10, short(0), shortstr("work"),
		bits(false, true, false, false, false),
		table(entryUnknown("mystery"), entryS("x-dead-letter-exchange", "dlx"))))
	if err != nil {
		t.Fatal(err)
	}
	if _, known := m.Targets(); known {
		t.Error("a table with an undefined type code was read anyway")
	}
}

// A table may hold a table. The nesting is the sender's, so it is bounded:
// without the bound a few dozen octets describe a structure deep enough to
// end the process in the reader.
func TestANestedTableIsBounded(t *testing.T) {
	inner := entryS("leaf", "x")
	for i := 0; i < maxTableDepth+4; i++ {
		inner = entryTable("down", inner)
	}
	m, err := ParseMethod(method(ClassQueue, 10, short(0), shortstr("work"),
		bits(false, true, false, false, false), table(inner)))
	if err != nil {
		t.Fatal(err)
	}
	if _, known := m.Targets(); known {
		t.Error("a table nested past the bound was read")
	}
	// And a table nested inside the bound still is.
	shallow := entryTable("down", entryTable("down", entryS("leaf", "x")))
	m, _ = ParseMethod(method(ClassQueue, 10, short(0), shortstr("work"),
		bits(false, true, false, false, false), table(shallow)))
	if _, known := m.Targets(); !known {
		t.Error("a table two levels deep was refused")
	}
}

func TestATableThatRunsPastItsLengthIsRefused(t *testing.T) {
	// The length says twenty octets; six are there.
	bad := join(long(20), []byte("abcdef"))
	m, err := ParseMethod(method(ClassQueue, 10, short(0), shortstr("work"),
		bits(false, true, false, false, false), bad))
	if err != nil {
		t.Fatal(err)
	}
	if _, known := m.Targets(); known {
		t.Error("a table longer than its own frame was read")
	}
}

func TestTheLoginTableIsReadWithoutItsLength(t *testing.T) {
	// RabbitMQ's AMQPLAIN response is a field table with no outer length.
	b := join(shortstr("LOGIN"), []byte{'S'}, longstr([]byte("orders")),
		shortstr("PASSWORD"), []byte{'S'}, longstr([]byte("hunter2")))
	got, err := LoginTable(b)
	if err != nil {
		t.Fatal(err)
	}
	if got["LOGIN"] != "orders" {
		t.Errorf("LOGIN = %q", got["LOGIN"])
	}
	// The password is in the table, because the table is what the client
	// sent. What matters is that the identity accessor never returns it,
	// which is asserted where that accessor is tested.
	if _, err := LoginTable([]byte{5, 'a'}); err == nil {
		t.Error("a truncated login table was read")
	}
}

// The content header is read for the body size before the body arrives,
// for the user identifier that makes a message attributable, and for the
// reply-to queue nothing else in the publish names.
func TestTheContentHeaderIsReadForWhatAPolicyNeeds(t *testing.T) {
	// content-type, delivery-mode, priority, reply-to, expiration, user-id,
	// app-id: seven flags, in the order the protocol puts the properties.
	flags := uint16(1<<propContentType | 1<<propDeliveryMode | 1<<propPriority |
		1<<propReplyTo | 1<<propExpiration | 1<<propUserID | 1<<propAppID)
	h, err := ParseContentHeader(contentHeader(ClassBasic, 4096, flags,
		shortstr("application/json"), octet(2), octet(4), shortstr("amq.rabbitmq.reply-to.abc"),
		shortstr("60000"), shortstr("orders"), shortstr("order-service")))
	if err != nil {
		t.Fatal(err)
	}
	if h.BodySize != 4096 || h.Class != ClassBasic {
		t.Errorf("header = %+v", h)
	}
	if h.ContentType != "application/json" || h.DeliveryMode != 2 || h.Priority != 4 {
		t.Errorf("properties = %+v", h)
	}
	if h.ReplyTo != "amq.rabbitmq.reply-to.abc" || h.UserID != "orders" || h.AppID != "order-service" {
		t.Errorf("properties = %+v", h)
	}
	if h.Expiration != "60000" {
		t.Errorf("expiration = %q", h.Expiration)
	}
	// An absent user identifier and an empty one are different things: the
	// first is a publisher that did not attribute its message, and a
	// policy that required attribution has to be able to tell.
	bare, err := ParseContentHeader(contentHeader(ClassBasic, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if bare.Set["user_id"] {
		t.Error("a header with no properties reported a user identifier")
	}
	empty, err := ParseContentHeader(contentHeader(ClassBasic, 0, 1<<propUserID, shortstr("")))
	if err != nil {
		t.Fatal(err)
	}
	if !empty.Set["user_id"] || empty.UserID != "" {
		t.Errorf("an empty user identifier read as %+v", empty.Set)
	}
}

func TestAContentHeaderThatDoesNotLayOutIsRefused(t *testing.T) {
	flags := uint16(1<<propContentType | 1<<propReplyTo)
	full := contentHeader(ClassBasic, 10, flags, shortstr("text/plain"), shortstr("reply-queue"))
	for n := 0; n < len(full); n++ {
		if _, err := ParseContentHeader(full[:n]); err == nil {
			t.Errorf("%d octets of a %d octet content header were read", n, len(full))
		}
	}
	// A continuation bit means the properties of a class this relay does
	// not read follow. What it read is kept and the continuation is
	// recorded, rather than the next word being decoded as basic
	// properties.
	h, err := ParseContentHeader(contentHeader(ClassBasic, 1, 1|1<<propContentType,
		shortstr("text/plain"), short(0)))
	if err != nil {
		t.Fatal(err)
	}
	if !h.Set["continued"] || h.ContentType != "text/plain" {
		t.Errorf("a continued header read as %+v", h)
	}
}

func TestTheCatalogueAndTheClassificationsAgree(t *testing.T) {
	// Every method the default allow list names has to be a method this
	// package knows, or the default would refuse a client for a name
	// nothing can match.
	for _, n := range DefaultMethods() {
		if _, _, ok := MethodID(n); !ok {
			t.Errorf("the default list names %q, which is not in the catalogue", n)
		}
	}
	// Every name the classifications speak about is in the catalogue too.
	for _, n := range Names() {
		if !strings.Contains(n, ".") {
			t.Errorf("%q is not a class.method name", n)
		}
		if _, _, ok := MethodID(n); !ok {
			t.Errorf("%q is named by the catalogue and not found in it", n)
		}
	}
	// The destructive set is a subset of the topology one, because
	// deleting and purging are changes to the broker's configuration --
	// and every one of them has to be a real method.
	for _, n := range Names() {
		if Destructive(n) && !Topology(n) {
			t.Errorf("%q is destructive and not topology", n)
		}
	}
	// And the default list allows no topology method at all, which is the
	// whole of what makes it a default worth having.
	for _, n := range DefaultMethods() {
		if Topology(n) {
			t.Errorf("the default list allows %q, which changes the broker's topology", n)
		}
		if Administrative(n) {
			t.Errorf("the default list allows %q, which reaches past the connection", n)
		}
	}
	// The default list does allow an application to do its work.
	for _, n := range []string{"basic.publish", "basic.consume", "basic.ack", "connection.open"} {
		found := false
		for _, d := range DefaultMethods() {
			if d == n {
				found = true
			}
		}
		if !found {
			t.Errorf("the default list does not allow %q, so an application cannot work", n)
		}
	}
	// ANONYMOUS is not a mechanism this listener offers by default: it is a
	// login with no identity, and a relay in front of a broker that
	// accepts one can at least refuse to pass it on.
	for _, m := range SafeMechanisms() {
		if strings.EqualFold(m, "ANONYMOUS") {
			t.Error("ANONYMOUS is in the default mechanism list")
		}
	}
}

// A field table naming the same key twice is unreadable, which makes the method
// a hard refusal rather than a decision made on one of the two values.
//
// This relay reads a table into a map, so a repeat resolves to the last
// instance; a broker parses it into an ordered list and resolves a lookup to the
// first -- RabbitMQ's table_lookup is lists:keysearch, and both the write
// permission check and the dead-lettering go through it. Taking different
// instances is the whole bug: a client names one exchange for the policy to
// check and another for the broker to route to, in the two arguments that send
// data somewhere the connection never mentions again.
func TestARepeatedTableKeyIsRefused(t *testing.T) {
	// queue.declare, whose arguments carry the dead-letter exchange twice: a
	// forbidden name first, and an empty value second so the `!= ""` guard that
	// reads it would skip the check altogether.
	args := join(short(0), shortstr("work"), bits(false, true, false, false, false),
		table(entryS("x-dead-letter-exchange", "secret.payroll"),
			entryS("x-dead-letter-exchange", "")))
	m := &Method{Class: ClassQueue, ID: 10, Args: args}
	if _, known := m.Targets(); known {
		t.Error("a table with a repeated key was read as if it said one thing")
	}

	// And the same table with one entry still reads, so the refusal is about the
	// repeat rather than about the argument.
	ok := join(short(0), shortstr("work"), bits(false, true, false, false, false),
		table(entryS("x-dead-letter-exchange", "secret.payroll")))
	got, known := (&Method{Class: ClassQueue, ID: 10, Args: ok}).Targets()
	if !known {
		t.Fatal("a table with one instance of the key did not read")
	}
	var named bool
	for _, tg := range got {
		if tg.Kind == KindExchange && tg.Name == "secret.payroll" {
			named = true
		}
	}
	if !named {
		t.Errorf("the dead letter exchange was not named as a target: %+v", got)
	}
}

// The same on exchange.declare's alternate-exchange, which is the other
// argument that routes without naming.
func TestARepeatedAlternateExchangeIsRefused(t *testing.T) {
	args := join(short(0), shortstr("myex"), shortstr("topic"),
		bits(false, true, false, false, false),
		table(entryS("alternate-exchange", "secret.ae"), entryS("alternate-exchange", "")))
	if _, known := (&Method{Class: ClassExchange, ID: 10, Args: args}).Targets(); known {
		t.Error("a repeated alternate-exchange was read as if it said one thing")
	}
}
