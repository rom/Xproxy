# MQTT — the protocol under the devices

`kind: mqtt`, served by **xrelay**, TCP port **1883** (cleartext) and **8883**
(TLS).

A publish/subscribe protocol designed in 1999 for telemetry over links that
were slow, expensive and unreliable. That origin shows: the fixed header is two
octets, the packet type is four bits, and almost everything is optional. It is
now what most of the world's connected devices speak.

## On the wire

A packet is a two-bit-field first octet, a variable-length remaining-length
field, and then a variable header and payload whose shape depends on the type.

| Packet | What it does |
|--------|-------------|
| `CONNECT` | The client identifier, an optional username and password, the keep-alive, the clean-session flag and an optional **will** |
| `CONNACK` | Whether the broker accepted it, and why not |
| `PUBLISH` | A **topic name**, a QoS in the flags, a retain flag and a payload |
| `SUBSCRIBE` | One or more **topic filters** with a requested QoS each |
| `PUBACK`, `PUBREC`, `PUBREL`, `PUBCOMP` | The QoS 1 and QoS 2 acknowledgement flows |
| `PINGREQ`, `PINGRESP`, `DISCONNECT`, `UNSUBSCRIBE` | Housekeeping |
| `AUTH` | MQTT 5.0 only: extended authentication |

A **topic** is levels separated by `/`. A filter may use `+` for exactly one
level and `#` for the rest, which makes `#` on its own a subscription to
everything the broker carries.

Two versions are in the field. **3.1.1** (also ISO/IEC 20922) is the one most
devices speak. **5.0** adds properties on every packet — session expiry, topic
aliases, subscription identifiers, user properties, reason strings — and
reason codes on the acknowledgements.

Two features are worth naming because they outlive the connection that created
them. A **retained** message stays on the topic and is delivered to every
future subscriber. A **will** is a message the broker publishes when the client
disconnects ungracefully — so a device that never connects again still
publishes, once.

## What the protocol gives you

A username and a password field in `CONNECT`, and nothing that protects them:
they are in the clear unless the transport is TLS. MQTT 5.0's `AUTH` packet
allows SASL-style exchanges, and is not widely used.

What the broker does with the credential is entirely the broker's business. Most
brokers authorise topic by topic, and most deployments do not configure it,
because a fleet of ten thousand devices whose topics were never designed as a
namespace cannot be authorised after the fact.

The client identifier is the other thing. It is chosen by the client, and a
broker uses it as the session key — so a device that adopts another device's
identifier takes over its session.

## What this listener decides

**The version.** `versions` names which of 3.1.1 and 5.0 may be spoken, because
a policy that has only been reviewed against one of them should not silently
accept the other.

**The identity.** `require_auth` refuses a connection with no credential.
`allow_empty_client_id` decides whether a client may let the broker assign one,
and `client_id_pattern` is the line that turns a client identifier into
something a rule can select on — `sensor-*` in one segment, `gw-??-*` in
another.

**The topics, in both directions, separately.** `publish_allow` and
`publish_deny` decide what a client may publish; `subscribe_allow` and
`subscribe_deny` decide what it may subscribe to. They are separate lists
because they are separate permissions: a device that publishes its own telemetry
and subscribes to its own commands needs one narrow pattern in each, and nothing
like the `#` a library will happily send.

`allow_wildcard_subscribe` is the blunt version of the same thing: a listener
that forbids wildcards has said no client may subscribe to a tree.

**Retained messages and wills**, because both persist past the connection.
`allow_retain` is off where an estate does not want a device planting a value
that every future subscriber receives.

**The bounds**: the packet size, the topic length, the number of topic levels,
the payload size, the subscriptions one connection may hold, the maximum QoS
and the keep-alive.

**Sparkplug B**, where it is in use. It is an industrial convention layered on
MQTT — a topic namespace of `spBv1.0/<group>/<message type>/<node>/<device>`
with protobuf payloads — and `sparkplug` makes the relay read the message type
out of the topic, so the node command and device command messages that change
plant are a decision rather than one topic among many.

## What it does not do

- **It does not authenticate against a directory.** The credential is forwarded
  and the *broker* decides. This listener decides which usernames may be tried
  and what a connection may do once the broker accepted it.
- **It does not rewrite topics.** A publication outside the policy is refused,
  not redirected: a device whose telemetry silently arrived on a different topic
  than it sent would be a fault nobody could find.
- **It does not inspect payloads by default.** A payload is bounded by size and,
  for Sparkplug, read for its message type. Anything more belongs in a YARA
  rule or an ICAP service, and is a decision with a cost.
- **It does not persist sessions.** The broker owns session state; this
  listener is a relay and holds only what the current connection needs.
- **It does not fix the client identifier space.** A pattern constrains what may
  be claimed; it cannot tell two devices that both legitimately claim
  `sensor-4` apart.

## Standards

| Document | What it covers |
|----------|----------------|
| MQTT 3.1.1 (OASIS, 2014) / ISO/IEC 20922:2016 | The packet types, the topic and filter syntax, the QoS flows |
| MQTT 5.0 (OASIS, 2019) | Properties, reason codes, the `AUTH` packet, session expiry, topic aliases |
| RFC 8314 | Implicit TLS, the pattern port 8883 follows |
| Sparkplug B (Eclipse Foundation) | The topic namespace and payload convention used on plant |

## See also

- The settings: [docs/CONFIG.md `## mqtt`](../CONFIG.md#mqtt)
- A worked configuration: [`examples/iot/mqtt.yaml`](../../examples/iot/mqtt.yaml)
- The other messaging protocol here: [amqp](amqp.md)
