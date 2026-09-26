# NTP — the thing everything else depends on

`kind: ntp`, served by **xrelay**, UDP port **123**.

Every certificate expiry check, every log correlation, every batch record and
every one-time password depends on the clock. A machine whose clock is wrong by
an hour cannot validate a certificate; one whose clock is wrong by a day cannot
be correlated with anything; one whose clock can be *moved* by an attacker can
be made to accept an expired certificate or replay a token.

And the protocol that sets it is 48 octets over UDP with, in its usual
deployment, nothing protecting it at all.

## On the wire

The packet is fixed: a leap indicator, a version, a **mode**, the stratum, the
poll interval, the precision, the root delay and dispersion, the reference id,
and four 64-bit timestamps — reference, origin, receive and transmit. Then
optional **extension fields** (RFC 7822) and optionally a MAC.

The modes decide what kind of exchange this is:

| Mode | What it is |
|------|-----------|
| 1, 2 | Symmetric active and passive: two peers of equal standing |
| 3, 4 | Client and server: the ordinary case |
| 5 | Broadcast server |
| 6 | **NTP control**, `ntpq`'s mode — the one behind the `monlist` amplification of 2013 |
| 7 | A private, implementation-defined mode |

The versions run 1 to 4 (RFC 5905 is v4), with SNTP (RFC 4330) being the same
packet used more simply. NTPv5 is in draft.

**Authentication** comes in three shapes. The original was a symmetric key with
an MD5 digest. RFC 8573 replaced that with **AES-CMAC**, which is what a plant
with pre-shared keys should be using. And **NTS** (RFC 8915) is the modern
answer: a TLS key establishment on TCP 4460 hands out cookies, and the NTP
packets then carry authenticated extension fields — so the time exchange itself
stays a single UDP round trip while being authenticated.

Mode 6 and mode 7 have no authentication worth the name and produce responses
far larger than their requests, which is why they were the basis of some of the
largest reflection attacks on record.

## What the protocol gives you

In the common deployment: nothing. Plain NTP is unauthenticated UDP, so a
response can be forged by anything on the path, and a server can be
impersonated by anything faster than it.

With AES-CMAC pre-shared keys: integrity and authentication, if the keys are
distributed and rotated, which is the part that makes it a project.

With NTS: the real thing. And NTS's design is careful about the property that
matters — the key establishment is a separate protocol on a separate port so that
the time exchange stays cheap, and the cookies are single-use so an observer
cannot correlate a client across queries.

## What this listener decides

**The versions and the modes**, which is the first and cheapest line. A listener
that admits modes 3 and 4 and nothing else has refused every control query,
every private-mode query and every broadcast — and that is most of this
protocol's attack surface in one setting. `peers` decides the symmetric modes
separately; `allow_manycast` and `manycast_responders` decide the discovery
modes.

**The extension fields.** `extensions` and `max_extensions`: an extension field
is a length-delimited blob a client can put anything in, and NTS's fields are
passed through whole because the relay is not a party to that cryptography.

**The authentication.** `auth` names what is acceptable — including refusing the
MD5 digest in favour of AES-CMAC — and `nts` decides whether NTS-protected
packets are carried.

**Whether the servers agree.** This is the setting with no equivalent in any
other listener here. `quality` compares the answers from several configured
sources against each other, so a server that is *reachable and wrong* is named
— which is the failure mode that matters, because a wrong clock that answers is
invisible to every reachability check an estate has. `change_detection` watches
for a source's answer moving in a way a clock does not, and `holdover` bounds
how long a source that has stopped agreeing is still used.

**The rate, and the amplification.** `rate_limit` per client, and
`prefix_rate_limit` with `rate_prefix_length` for a source *network*, which is
what a distributed reflection run looks like. A rate-limited client is answered
with the protocol's own **kiss-o'-death** — a stratum-0 packet with a `RATE`
reference id — because that is what a well-behaved NTP client already knows how
to back off from. An error would just be retried.

**`interleaved`** decides whether the interleaved mode is carried, and `learn`
watches a running estate to find out what its clients actually ask for before a
policy is written.

## What it does not do

- **It is not a time source.** It does not hold a clock, serve time from one, or
  correct a client's offset. It relays, and it reports when the sources disagree.
- **It does not terminate NTS.** The authenticated extension fields are carried
  whole; the cryptography belongs to the client and the server whose keys they
  are. The key establishment is a separate listener — see [ntske](ntske.md).
- **It does not compute AES-CMAC on behalf of a peer.** The MAC is read for which
  key id and which algorithm; verification belongs to the endpoints.
- **It does not correct a forged timestamp.** It can refuse a source that
  disagrees with its peers; it cannot tell which of two disagreeing sources is
  right without a source of truth of its own.
- **It cannot authenticate plain NTP.** On the plain protocol the client list is
  an address list on UDP. The answer is NTS, and this listener will carry it.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 5905 | NTPv4: the packet format, the modes, the algorithms |
| RFC 5906 | Autokey (not served: its security has not held up) |
| RFC 4330 | SNTPv4 |
| RFC 7822 | The extension field format |
| RFC 8573 | AES-CMAC for NTP, replacing the MD5 digest |
| RFC 8915 | Network Time Security for NTPv4 |
| RFC 7384 | Security requirements of time protocols in packet-switched networks |
| draft-ietf-ntp-ntpv5 | NTPv5, gated behind `allow_version5` |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].ntp`](../CONFIG.md#serverlistenersntp-kind-ntp)
- A worked configuration: [`examples/ot/ntp.yaml`](../../examples/ot/ntp.yaml)
- The key establishment: [ntske](ntske.md)
