# Syslog — the estate's memory

`kind: syslog`, served by **xrelay** or **xot**, UDP port **514**, TCP **514**, TLS
**6514**.

Logs are the record an incident is reconstructed from, which makes the log path
worth protecting for two different reasons: somebody who can write into it can
plant a story, and somebody who can flood it can bury one.

## On the wire

Two dialects, and almost every estate carries both.

**RFC 3164** — the older one, and the one the specification itself calls a
description of observed behaviour rather than a design. A priority in angle
brackets, a timestamp with no year and no timezone, a hostname, a tag, and free
text:

```
<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick
```

**RFC 5424** — the designed one. A version number, an RFC 3339 timestamp with a
timezone, structured hostname, app-name, procid and msgid fields, **structured
data** as bracketed key-value groups, and an optional BOM-prefixed UTF-8
message:

```
<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [exampleSDID@32473 iut="3"] BOM'su root' failed
```

The priority is a facility (0–23) and a severity (0–7) packed into one number:
`facility * 8 + severity`.

The transports differ in ways that matter:

| Transport | Framing | What it costs |
|-----------|---------|--------------|
| UDP (RFC 5426) | One message per datagram | No delivery guarantee, no order, trivially spoofed source |
| TCP (RFC 6587) | Octet-counted, or newline-delimited | Two framings, and a receiver has to tell them apart |
| TLS (RFC 5425) | Octet-counted only | Authentication and confidentiality, and the framing ambiguity gone |

## What the protocol gives you

Over UDP, nothing at all: no authentication, no integrity, and a source address
that is a single spoofed datagram away from being anybody's. The hostname field
inside the message is free text written by the sender.

Over TLS, real authentication — RFC 5425 specifies mutual certificate
authentication — and it is the only version of this protocol with a trust model.

The other structural problem is the framing. RFC 6587 describes both
octet-counting and non-transparent (newline) framing, and a receiver that
guesses can be made to read one message as several or several as one. That is
log injection: a forged line with a plausible timestamp and hostname, inserted
in the middle of somebody else's message.

## What this listener decides

**Who may send.** A client list, worth more on TCP and TLS than on UDP, and with
TLS client certificates it is a real answer.

**The facility and the severity**, which is how "this sender may log
authentication events and nothing at facility local7" is written, and how a
device that has started logging debug at ten thousand lines a second is bounded.

**The sender**, matched against what the message claims, so a host writing
another host's name into its own log lines is visible.

**The text.** The message is read rather than forwarded blind: the length is
bounded by `max_message_bytes`, `deny_patterns` drops what an estate has decided
not to carry, and **terminal control sequences are removed**, because a log line
is eventually displayed in somebody's terminal and a message carrying an escape
sequence can rewrite what the operator sees — including making an earlier line
disappear.

`redact` goes further: a pattern that matches is replaced, and the message
carries a structured-data element naming the rule that did it. A log path is
where a password typed into the wrong field ends up, and a redaction nobody can
see happened is a redaction nobody can audit.

**One dialect out.** The relay parses whichever dialect arrived and **re-emits
in one**, which is the single most useful thing it does for a collector: the
collector stops guessing, and the framing on the way out is unambiguous. A
message the relay could not parse is **refused and counted** (`malformed`),
because its facility, severity and sender — every field a rule here decides on —
are unknown, and forwarding it would be forwarding something no policy was
applied to. The counter is what makes that visible rather than silent.

**What the sender did not say.** `hostname: observed` replaces the claimed
hostname with the address the message came from; `annotate` keeps both and says
which is which, in a structured-data element carrying the claimed name beside
the observed address. And a message with no timestamp gets the relay's receive
time, because a record nobody can order is a record that cannot be correlated.

**The framing, explicitly.** `framing` decides which RFC 6587 framing the relay
accepts rather than sniffing, which is what closes the injection.

### The imported lists, and the estate's authorisation policy

Syslog does name a host, inside the message, and that name is worth nothing: it is
a field the sender wrote and no part of the protocol checks it, which is why this
relay rewrites it from the address the message actually came from. So two questions
are asked about the sender itself, after this listener's own `allow_senders`:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. The action is `write` rather than `connect`: a
  sender does not open a session with a collector, it delivers records. A rule
  naming `users` matches nobody on this kind, so a rule here is written with
  `networks`, `targets` and `schedule`.

Asked once per connection on a stream and once per datagram on UDP -- not for
every line a connection sends, because a sender that has been admitted should not
be re-asked for each record. Which facilities and severities may reach the
collector stays with this listener's own policy above.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## What it does not do

- **It does not authenticate UDP senders.** It cannot. An estate that needs the
  log path trustworthy runs it over TLS, and this listener will require client
  certificates for it.
- **It does not store.** There is no spool and no queue beyond what is needed to
  relay. The collector is the durable thing; this is the path to it.
- **It does not parse the message body.** The text is bounded and sanitised, not
  interpreted. Field extraction belongs in the collector, which knows the
  estate's applications.
- **It does not deduplicate.** A repeated line is relayed. Suppressing
  repetition is how a real incident — which repeats, by definition — gets
  suppressed, so the bounds here are per sender and per severity instead.
- **It does not rewrite a timestamp the sender gave.** A message with no
  timestamp at all gets the relay's receive time, since a record nobody can order
  cannot be correlated; one that carries a timestamp keeps it, even where the
  relay thinks it is wrong, because a clock disagreement is a fact about the
  estate and hiding it does not fix the clock.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 5424 | The syslog protocol: the structured format, structured data, the severity and facility model |
| RFC 3164 | The BSD syslog protocol — a description of what was already deployed |
| RFC 5425 | TLS transport mapping for syslog, with mutual authentication |
| RFC 5426 | UDP transport mapping |
| RFC 6587 | Transmission of syslog messages over TCP: the two framings |
| RFC 5848 | Signed syslog messages (not implemented: the relay does not re-sign, since a signature it created would attest to nothing about the sender) |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].syslog`](../CONFIG.md#serverlistenerssyslog-kind-syslog)
- A worked configuration: [`examples/logs/syslog.yaml`](../../examples/logs/syslog.yaml)
- Where this proxy's own logs go: [docs/CONFIG.md `## logging`](../CONFIG.md#logging)
