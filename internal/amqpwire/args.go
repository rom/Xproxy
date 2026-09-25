package amqpwire

import "strings"

// What each method names, and what each method does. This is the part a
// policy is written against.
//
// Two rules run through all of it. A method whose arguments this package
// cannot lay out answers `known` false, and never a name it guessed at:
// the whole value of an exchange or queue allow list is that the name
// checked against it is the name the broker will act on. And nothing here
// returns a secret -- the SASL response is read for the identity in it and
// the password is stepped over, so a refusal can say who tried without any
// code path between the wire and a log line holding the credential.

// Target is something a method names.
//
// The kinds are the nouns of this protocol: an exchange is where a message
// is published, a queue is where it is held, and a routing key is the
// string the broker matches between the two. A policy is written about all
// three, because they are three different boundaries: an application that
// may publish to an exchange is not thereby allowed to bind a queue of its
// own to it, and one that may consume from a queue is not allowed to name
// somebody else's routing key.
type Target struct {
	Kind string
	Name string
}

// The target kinds.
const (
	KindExchange   = "exchange"
	KindQueue      = "queue"
	KindRoutingKey = "routing_key"
)

// Targets is what a method names, and whether this package knows the
// method's layout well enough to say.
//
// A known method that names nothing -- basic.ack, tx.commit,
// channel.open -- returns no targets and `known` true, which is a
// different answer from "this method might name something and I cannot
// tell".
func (m *Method) Targets() ([]Target, bool) {
	if !m.Known() {
		return nil, false
	}
	d := &dec{b: m.Args}
	var out []Target
	add := func(kind, name string) {
		out = append(out, Target{Kind: kind, Name: name})
	}
	switch m.Name() {
	case "exchange.declare":
		d.short() // reserved
		add(KindExchange, d.shortstr())
		d.shortstr() // type
		for i := 0; i < 5; i++ {
			d.bit() // passive, durable, auto-delete, internal, nowait
		}
		// An alternate exchange is where this exchange sends what it
		// could not route, so it is an exchange this method names as
		// surely as the one it declares.
		args := d.table(1)
		if x := args["alternate-exchange"]; x != "" {
			add(KindExchange, x)
		}
	case "exchange.delete":
		d.short()
		add(KindExchange, d.shortstr())
	case "exchange.bind", "exchange.unbind":
		d.short()
		add(KindExchange, d.shortstr()) // destination
		add(KindExchange, d.shortstr()) // source
		add(KindRoutingKey, d.shortstr())
	case "queue.declare":
		d.short()
		add(KindQueue, d.shortstr())
		for i := 0; i < 5; i++ {
			d.bit() // passive, durable, exclusive, auto-delete, nowait
		}
		// A dead-letter exchange is where this queue's rejected and
		// expired messages go. It is the one argument on this protocol
		// that routes data somewhere the connection never mentions
		// again, so it is checked as an exchange the method names.
		args := d.table(1)
		if x := args["x-dead-letter-exchange"]; x != "" {
			add(KindExchange, x)
		}
		if rk := args["x-dead-letter-routing-key"]; rk != "" {
			add(KindRoutingKey, rk)
		}
	case "queue.bind", "queue.unbind":
		d.short()
		add(KindQueue, d.shortstr())
		add(KindExchange, d.shortstr())
		add(KindRoutingKey, d.shortstr())
	case "queue.purge", "queue.delete":
		d.short()
		add(KindQueue, d.shortstr())
	case "basic.publish":
		d.short()
		add(KindExchange, d.shortstr())
		add(KindRoutingKey, d.shortstr())
	case "basic.consume":
		d.short()
		add(KindQueue, d.shortstr())
	case "basic.get":
		d.short()
		add(KindQueue, d.shortstr())
	case "basic.deliver":
		// The broker's own direction: what it is handing over and from
		// where. A relay reads it so an inbound policy can be applied to
		// the reverse leg as well, which is the only way a queue a
		// client was never allowed to name cannot reach it anyway.
		d.shortstr() // consumer-tag
		d.longlong() // delivery-tag
		d.bit()      // redelivered
		add(KindExchange, d.shortstr())
		add(KindRoutingKey, d.shortstr())
	case "basic.get-ok":
		d.longlong()
		d.bit()
		add(KindExchange, d.shortstr())
		add(KindRoutingKey, d.shortstr())
	case "basic.return":
		d.short()    // reply-code
		d.shortstr() // reply-text
		add(KindExchange, d.shortstr())
		add(KindRoutingKey, d.shortstr())
	default:
		// A method in the catalogue that names none of these nouns.
		return nil, true
	}
	if d.done() != nil {
		return nil, false
	}
	return out, true
}

// Mechanism reads a connection.start-ok: which SASL mechanism the client
// chose, and the identity its response carries.
//
// The password is never returned. PLAIN puts the authorisation identity,
// the authentication identity and the password in one field separated by
// zero octets (RFC 4616), and RabbitMQ's own AMQPLAIN puts them in a field
// table under LOGIN and PASSWORD. Both are read for the name and stepped
// over for the secret.
//
// A mechanism whose response this package does not read -- a challenge and
// response exchange, a broker's own plugin -- returns its name with no
// identity, which is the truthful answer: the policy can still decide on
// the mechanism, and a rule about users simply does not match.
func (m *Method) Mechanism() (mech, user string, ok bool) {
	if m.Name() != "connection.start-ok" {
		return "", "", false
	}
	d := &dec{b: m.Args}
	d.table(1) // client-properties
	mech = d.shortstr()
	resp := d.longstr()
	if d.done() != nil {
		return "", "", false
	}
	return mech, identityOf(mech, resp), true
}

// identityOf reads the username out of a SASL response, and nothing else.
func identityOf(mech string, resp []byte) string {
	switch strings.ToUpper(mech) {
	case "PLAIN":
		// authzid NUL authcid NUL passwd. The authentication identity is
		// the second field; the first is who it is acting as, which
		// RabbitMQ leaves empty.
		parts := strings.SplitN(string(resp), "\x00", 3)
		if len(parts) >= 2 && parts[1] != "" {
			return parts[1]
		}
		if len(parts) >= 1 && parts[0] != "" {
			return parts[0]
		}
	case "AMQPLAIN":
		t, err := LoginTable(resp)
		if err != nil {
			return ""
		}
		return t["LOGIN"]
	case "EXTERNAL":
		// The identity is the client certificate's, which this relay has
		// in the handshake rather than here; the response is an optional
		// authorisation identity.
		return string(resp)
	}
	return ""
}

// VirtualHost reads a connection.open.
//
// The virtual host is the broker's own access boundary: a user is granted
// permissions per vhost, and a connection that opens one it has no
// business in is the first thing an allow list should stop -- before the
// exchange and queue names, which mean different things in different
// vhosts.
func (m *Method) VirtualHost() (string, bool) {
	if m.Name() != "connection.open" {
		return "", false
	}
	d := &dec{b: m.Args}
	vhost := d.shortstr()
	if d.done() != nil {
		return "", false
	}
	return vhost, true
}

// Tune reads a connection.tune or tune-ok: the channel bound, the frame
// bound and the heartbeat interval.
//
// All three are negotiated, which is why a relay reads them. Zero means
// "no limit" for the first two and "no heartbeat" for the third, so a
// client can ask for an unbounded number of channels, unbounded frames and
// no liveness checking at all, and a broker that agrees is a broker whose
// bounds came from the client.
func (m *Method) Tune() (channelMax uint16, frameMax uint32, heartbeat uint16, ok bool) {
	switch m.Name() {
	case "connection.tune", "connection.tune-ok":
	default:
		return 0, 0, 0, false
	}
	d := &dec{b: m.Args}
	channelMax = d.short()
	frameMax = d.long()
	heartbeat = d.short()
	if d.done() != nil {
		return 0, 0, 0, false
	}
	return channelMax, frameMax, heartbeat, true
}

// Mechanisms reads a connection.start: the mechanisms the broker offers,
// space separated as the specification puts them.
//
// A relay reads the *offer* so it can refuse a downgrade before the client
// ever sees it: a broker offering ANONYMOUS or PLAIN on a connection that
// is not encrypted is offering the client a way to do the wrong thing.
func (m *Method) Mechanisms() ([]string, bool) {
	if m.Name() != "connection.start" {
		return nil, false
	}
	d := &dec{b: m.Args}
	d.octet() // version-major
	d.octet() // version-minor
	d.table(1)
	mechs := d.longstr()
	if d.done() != nil {
		return nil, false
	}
	return strings.Fields(string(mechs)), true
}

// Consumer reads the consumer tag and the acknowledgement mode of a
// basic.consume.
//
// The no-ack bit is worth a policy: a consumer that takes messages without
// acknowledging them loses whatever was in flight when it died, and a
// queue somebody else depends on is drained by it. A broker cannot tell an
// application that made that choice deliberately from one whose library
// defaulted into it; an operator can.
func (m *Method) Consumer() (tag string, noAck, exclusive, ok bool) {
	if m.Name() != "basic.consume" {
		return "", false, false, false
	}
	d := &dec{b: m.Args}
	d.short()
	d.shortstr() // queue
	tag = d.shortstr()
	d.bit() // no-local
	noAck = d.bit()
	exclusive = d.bit()
	if d.done() != nil {
		return "", false, false, false
	}
	return tag, noAck, exclusive, true
}

// Queue reads the durability and exclusivity of a queue.declare.
func (m *Method) Queue() (name string, passive, durable, exclusive, autoDelete, ok bool) {
	if m.Name() != "queue.declare" {
		return "", false, false, false, false, false
	}
	d := &dec{b: m.Args}
	d.short()
	name = d.shortstr()
	passive = d.bit()
	durable = d.bit()
	exclusive = d.bit()
	autoDelete = d.bit()
	if d.done() != nil {
		return "", false, false, false, false, false
	}
	return name, passive, durable, exclusive, autoDelete, true
}

// Exchange reads the type and durability of an exchange.declare.
//
// The type is a policy point of its own on RabbitMQ, where an exchange
// type can be supplied by a plugin: `x-delayed-message` holds messages,
// `x-random` and `x-consistent-hash` change where they go, and the federation
// and shovel types route to another broker entirely.
func (m *Method) Exchange() (name, kind string, passive, durable, internal, ok bool) {
	if m.Name() != "exchange.declare" {
		return "", "", false, false, false, false
	}
	d := &dec{b: m.Args}
	d.short()
	name = d.shortstr()
	kind = d.shortstr()
	passive = d.bit()
	durable = d.bit()
	d.bit() // auto-delete
	internal = d.bit()
	if d.done() != nil {
		return "", "", false, false, false, false
	}
	return name, kind, passive, durable, internal, true
}

// CloseReason reads a connection.close or channel.close: the code, the
// text, and the method that caused it.
//
// A relay logs it because it is the broker's own account of why a
// connection ended, and because 403 ACCESS_REFUSED on this protocol is the
// broker refusing a permission -- the event an operator most wants
// attributed to a client and a user.
func (m *Method) CloseReason() (code uint16, text string, class, method uint16, ok bool) {
	switch m.Name() {
	case "connection.close", "channel.close":
	default:
		return 0, "", 0, 0, false
	}
	d := &dec{b: m.Args}
	code = d.short()
	text = d.shortstr()
	class = d.short()
	method = d.short()
	if d.done() != nil {
		return 0, "", 0, 0, false
	}
	return code, text, class, method, true
}
