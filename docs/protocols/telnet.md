# Telnet — the network virtual terminal

`kind: telnet`, served by **xgate**, TCP port **23**.

Telnet is a cleartext terminal session, and everybody knows it should not be in
use. It is in use: on switches and routers whose management interface predates
SSH, on serial console servers, on mainframe front ends, and on industrial
equipment where the vendor's tooling speaks nothing else.

That is why there is a gate kind for it. The point is not to bless telnet; it is
to put a recorded, authenticated boundary in front of the equipment that has
nothing else.

## On the wire

Almost nothing: a byte stream, plus an option negotiation that interleaves with
it.

`IAC` (255) introduces a command:

| Command | What it does |
|---------|-------------|
| `WILL`, `WONT` | I will / will not use this option |
| `DO`, `DONT` | Please do / do not use this option |
| `SB` … `SE` | Subnegotiation: the option's own parameters |
| `IP`, `AO`, `AYT`, `EC`, `EL`, `GA` | Interrupt process, abort output, are you there, erase character, erase line, go ahead |

The options are where the protocol gets interesting, and several of them are
much more than terminal settings:

| Option | What it is |
|--------|-----------|
| `ECHO` (1), `SGA` (3) | Who echoes, and whether the line turn-taking is suppressed — together these are what makes a session character-at-a-time |
| `TERMINAL-TYPE` (24) | The client's terminal type, as a string the server will look up in terminfo |
| `NAWS` (31) | Window size |
| `NEW-ENVIRON` (39) | **Environment variables** — the client sets variables the server may accept |
| `AUTHENTICATION` (37) | RFC 2941 authentication (Kerberos and others) — rarely implemented |
| `ENCRYPT` (38) | RFC 2946 encryption — rarely implemented, and its history is not good |
| `TN3270E` (40) | The mainframe terminal protocol, a different world inside the same connection |

A subnegotiation is a length-free sequence terminated by `IAC SE`, which means
an unbounded blob in the middle of a terminal stream.

## What the protocol gives you

Nothing. The password is typed into the stream in the clear, character by
character, and anything on the path reads it. RFC 2941 and RFC 2946 exist and are
effectively not deployed.

The two options that are worth knowing about beyond that: `NEW-ENVIRON` lets a
client propose environment variables, and `TERMINAL-TYPE` is a string that ends
up in a terminfo lookup — both are input from the client to something on the
server that was not necessarily written defensively.

## What this listener decides

**Who the person is, and whether they have a second factor.** This is the whole
reason the kind exists. `mfa` puts a real authentication step in front of a
protocol that has none, and the session then belongs to a named principal in the
logs and in the recording — which is more identity than telnet has ever had.

**Which options may be negotiated, in both directions.** `allow_options` and
`deny_options`, and the direction matters: an option the *server* offers and an
option the *client* offers are different decisions. `NEW-ENVIRON` belongs on the
deny list unless something needs it.

**The subnegotiation's size**, with `max_subnegotiation`, because a
subnegotiation has no length field and is terminated by a sequence the sender
controls.

**The session, recorded.** `recording` captures it as asciicast, and the
sanitisation matters more here than anywhere: this is a raw terminal stream, so
a session can contain any escape sequence at all, and a replay is rendered in
somebody's terminal. Every replay path strips the control sequences that would
let a recorded session rewrite what the person reviewing it sees.

**The session's shape**: `max_connections`, and the idle and total timeouts,
because a telnet session on a console server is the kind of thing that stays
open for weeks.

## What it does not do

- **It does not add encryption to the protocol.** A telnet session through this
  gate is still telnet to the device. What the gate adds is that the *person's*
  leg can be authenticated and recorded, and that the cleartext leg is as short
  as the estate's topology allows. If the device can do SSH, use SSH.
- **It does not implement RFC 2941 or RFC 2946.** The options can be refused;
  they are not offered.
- **It does not read TN3270E.** The option is a decision; the mainframe terminal
  protocol inside it is not interpreted.
- **It does not police what is typed.** There is no command structure in telnet
  to parse — it is a character stream. The recording is the control, not a
  filter.
- **It does not translate.** No line-ending rewriting, no character set
  conversion. The stream is the device's.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 854 | The telnet protocol: the NVT, `IAC` and the commands |
| RFC 855 | Telnet option specifications |
| RFC 856 | Binary transmission |
| RFC 857 | The echo option |
| RFC 858 | Suppress go ahead |
| RFC 1073 | Window size (`NAWS`) |
| RFC 1091 | Terminal type |
| RFC 1572 | The environment option (`NEW-ENVIRON`) |
| RFC 2941 | Telnet authentication option |
| RFC 2946 | Telnet data encryption option |
| RFC 1205 | 5250 telnet interface; RFC 2355 covers TN3270E |

## See also

- The settings: [docs/CONFIG.md `## telnet`](../CONFIG.md#telnet)
- A worked configuration: [`examples/bastion/telnet.yaml`](../../examples/bastion/telnet.yaml)
- The protocol to use instead where the equipment allows: [ssh](ssh.md)
- The other interactive protocols: [vnc](vnc.md), [rdp](rdp.md)
