package amqpwire

// What a method does, in the terms a policy is written in.
//
// "Read-only" is not a useful word on a message broker. A consumer changes
// the broker's state -- it takes messages off a queue -- and a publisher
// that only adds is the one doing the least damage. So the classification
// here is by what an operation *reaches*, in four groups that an operator
// can switch on and off independently:
//
// **Topology.** Declaring or deleting an exchange or a queue, and binding
// or unbinding them. This is the broker's configuration, and it is what
// almost every application does not need: a service that publishes to an
// exchange somebody else declared needs no topology methods at all, and a
// client library that declares its own queue on connect is a choice rather
// than a requirement.
//
// **Publishing.** basic.publish, which is the one that puts data in.
//
// **Consuming.** basic.consume and basic.get, which take it out. On a
// broker these are two different privileges and confusing them is how a
// service that was supposed to emit events ends up reading somebody
// else's.
//
// **Destroying.** Deleting an exchange or a queue, or purging one. A queue
// delete takes the messages with it and a purge is nothing but that, so
// these are irreversible in a way nothing else on the protocol is -- which
// is why they are the methods a listener in monitor mode still refuses.

// Topology says whether a method changes the broker's configuration.
func Topology(name string) bool {
	switch name {
	case "exchange.declare", "exchange.delete", "exchange.bind", "exchange.unbind",
		"queue.declare", "queue.delete", "queue.bind", "queue.unbind", "queue.purge":
		return true
	}
	return false
}

// Publishes says whether a method puts a message into the broker.
func Publishes(name string) bool { return name == "basic.publish" }

// Consumes says whether a method takes messages out.
func Consumes(name string) bool {
	switch name {
	case "basic.consume", "basic.get":
		return true
	}
	return false
}

// Destructive says whether a method destroys something that was there.
//
// These are the refusals a listener in monitor mode keeps: a purge
// forwarded so that it could be written down is a queue that is empty. The
// same reasoning the modbus and redis kinds use for a write and for
// FLUSHALL.
func Destructive(name string) bool {
	switch name {
	case "exchange.delete", "queue.delete", "queue.purge":
		return true
	}
	return false
}

// Administrative says whether a method reaches past this connection.
//
// connection.update-secret replaces the credential the connection
// authenticated with, which on a relay that read the identity at the start
// means the connection is now somebody else. basic.recover-async and
// channel.flow act on delivery for everybody on the channel. access.request
// is a 0-8 leftover a modern broker accepts and ignores, and a client
// sending one is a client from before this protocol had the permissions
// model it now has.
func Administrative(name string) bool {
	switch name {
	case "connection.update-secret", "access.request":
		return true
	}
	return false
}

// DefaultMethods is what an application does to a broker when the
// configuration names no allow list: connect, open a channel, publish,
// consume, acknowledge, and close.
//
// The absences are the policy. No exchange or queue may be declared,
// deleted, bound or unbound, nothing may be purged, no credential may be
// replaced -- an application that needs its own topology says so in the
// file, which is a line an operator writes once and a reviewer can see.
//
// The handshake methods are here because without them there is no
// connection: a listener whose default refused connection.start-ok would
// refuse everything, which is not a default, it is a broken listener.
func DefaultMethods() []string {
	return []string{
		// The handshake, in both directions.
		"connection.start", "connection.start-ok",
		"connection.secure", "connection.secure-ok",
		"connection.tune", "connection.tune-ok",
		"connection.open", "connection.open-ok",
		"connection.close", "connection.close-ok",
		"connection.blocked", "connection.unblocked",
		"channel.open", "channel.open-ok",
		"channel.close", "channel.close-ok",
		"channel.flow", "channel.flow-ok",
		// The work.
		"basic.qos", "basic.qos-ok",
		"basic.publish", "basic.return",
		"basic.consume", "basic.consume-ok",
		"basic.cancel", "basic.cancel-ok",
		"basic.deliver", "basic.get", "basic.get-ok", "basic.get-empty",
		"basic.ack", "basic.nack", "basic.reject",
		"basic.recover", "basic.recover-ok",
		// Publisher confirms and transactions, which are how an
		// application makes sure what it sent arrived.
		"confirm.select", "confirm.select-ok",
		"tx.select", "tx.select-ok", "tx.commit", "tx.commit-ok",
		"tx.rollback", "tx.rollback-ok",
	}
}

// SafeMechanisms is the SASL mechanisms a listener allows when the
// configuration names none.
//
// PLAIN is on the list because it is what every broker and client actually
// uses, and because this relay requires TLS by default -- PLAIN inside TLS
// is the ordinary deployment. EXTERNAL is on it because it is the
// certificate-authenticated form, which is better. ANONYMOUS is not,
// because it is a login with no identity: a broker that accepts it has no
// account to attribute anything to, and a relay in front of one can at
// least refuse to pass it on.
func SafeMechanisms() []string { return []string{"PLAIN", "EXTERNAL"} }
