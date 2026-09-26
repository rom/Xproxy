# FTP — two connections, one of them a problem

`kind: ftp`, served by **xrelay**, TCP port **21** (with `AUTH TLS`) and **990**
(implicit FTPS).

FTP is from 1971, and the thing that makes it hard to proxy is structural rather
than historical: a session is **two TCP connections**, and the second one's
address is negotiated in the first, in cleartext, as a decimal string.

## On the wire

A command channel of three- or four-letter commands and three-digit replies.

| Command | What it does |
|---------|-------------|
| `USER`, `PASS`, `ACCT` | The identity, in the clear unless TLS is up |
| `AUTH TLS`, `PBSZ`, `PROT` | RFC 4217: upgrade the control channel, and set the data channel's protection |
| `PORT`, `EPRT` | **Active mode**: the client tells the server where to connect *to it* |
| `PASV`, `EPSV` | **Passive mode**: the server tells the client where to connect |
| `RETR`, `STOR`, `STOU`, `APPE` | Transfer a file, in one of four ways |
| `LIST`, `NLST`, `MLSD`, `MLST` | List a directory, in four different formats |
| `CWD`, `CDUP`, `PWD`, `MKD`, `RMD`, `DELE` | Navigate and change |
| `RNFR`, `RNTO` | Rename, as a two-command sequence with state between them |
| `REST` | Restart a transfer at an offset |
| `TYPE`, `MODE`, `STRU` | ASCII or binary, and the stream modes |
| `FEAT`, `OPTS` | Capability negotiation, including `OPTS UTF8 ON` |
| `CCC` | **Clear Command Channel**: drop back to cleartext after authenticating |

`PORT` is the one that has caused the most trouble over the years: the client
sends `PORT 10,0,0,5,4,210`, and a server that connects wherever it is told is
a port scanner and a data exfiltration path for whoever controls the command
channel. That is the FTP bounce attack, and it is why active mode has to be a
decision.

`CCC` is the other: it exists so that a NAT device can see and rewrite the
`PORT` and `PASV` addresses, and what it does is take an authenticated,
encrypted session and make it cleartext.

## What the protocol gives you

A username and a password, in the clear, unless `AUTH TLS` was used first. With
RFC 4217, real TLS on the control channel and optionally on the data channel —
and the `PROT` command is what decides the second, so a session can be
authenticated over TLS and then transfer its files in the clear.

Beyond that, nothing. There is no integrity on the data channel unless `PROT P`
is set, no per-command authorisation, and the server's own file permissions are
the whole of the access control.

## What this listener decides

**Whether TLS is required**, and — separately — whether the data channel is
protected, because `PROT C` after a `AUTH TLS` is a session that looks encrypted
and transfers in the clear.

**`CCC` is refused**, with reply 534, and it is not configurable. Clearing the
control channel after `AUTH TLS` puts the rest of the session back in the clear
— every path, every filename, every reply — and the reason the command exists is
so that a middlebox can read and rewrite the data-connection addresses. This
listener *is* the middlebox, and it reads those addresses properly instead.

**The data connection, mediated at both ends.** This is the core of the kind.
The relay does not forward a `PORT` or `PASV` address; it terminates the data
connection on both sides, so:

- A `PASV` reply names **this relay's** address and a port from `data_ports`,
  and the relay opens its own connection to the server. The client never learns
  the server's address.
- `allow_active` decides whether `PORT` and `EPRT` are permitted at all, and
  where they are, the relay is the one that connects to the client — so a
  `PORT` naming a third party is a `PORT` naming a machine the relay will not
  connect to.
- `data_address` and `data_ports` make the relay's data side something a
  firewall can be written about, which is the practical problem every FTP
  deployment has.

**The commands**, with `commands`, and `read_only` as one line that refuses
`STOR`, `STOU`, `APPE`, `DELE`, `RMD`, `MKD` and `RNTO`.

**The paths and extensions.** `allow_paths`, `deny_paths`,
`allow_extensions` and `deny_extensions` — with the path tracked through `CWD`
and `CDUP` so a relative filename is resolved the way the server will resolve
it, rather than matched as the string the client typed.

**The content, where an estate wants it.** `yara` runs rules over a transfer and
`icap` hands it to a scanning service, both in the direction that matters: what
arrives in the estate, and what leaves it.

**The session, as an audited thing.** `recording` captures the command channel
for the record, and `mfa` puts a second factor in front of a file transfer
service — which is unusual for FTP and is exactly why it is here: the protocol
has one weak factor and no way to add another.

**The bounds**: the command line length, `max_errors`, `max_file_bytes`,
connections, and the idle, session and data timeouts.

### The estate's own authorisation policy

Above this listener's own policy sits the `authorization` section, which is not
about FTP: it is the one place that says which identity may reach which listener
and target, in the same words for every protocol.

Where it is asked is a fact about the protocol. FTP's greeting comes from the
server, so the target is dialled before anybody has said who they are -- the
login is the first point at which there is a person to decide about, and the
access grant has the same constraint. So the refusal is a 530 on the login: the
target has seen a connection and a login attempt, and no command of the person's
is forwarded.

The `target` is the upstream **pool** name rather than the machine this session
reached, so that a rule reads the same here as on an `ssh` listener; the
per-machine question belongs to the access grant. `principal` and `groups` are
empty.

A refusal is the reason `authorization` (the event `ftp_authorization`, the
counter `xproxy_refusals_total{kind="ftp",reason="authorization"}`). Either
shadow switch -- `policy: {mode: shadow}` on the listener, or `shadow: true` on
the section -- records what it would have refused and admits.

## What it does not do

- **It does not rewrite addresses in a reply it did not construct.** The `PASV`
  reply the client sees is the relay's own, built from `data_address`. A relay
  that patched decimal octets inside somebody else's reply string would be
  guessing at the reply's format, which is how FTP ALG bugs happen.
- **It does not support `MODE B` or `MODE C`.** Block and compressed modes are a
  second framing over the data connection, and a policy applied to one of them
  would be a policy applied to a format almost nothing uses.
- **It does not authenticate.** `USER`/`PASS` are forwarded and the server
  decides; MFA, where configured, is this relay's own additional factor in front
  of that.
- **It does not resolve symlinks on the server.** The path policy is applied to
  the names in the dialogue. A server-side link out of an allowed directory is
  the server's own configuration to fix.
- **It is not SFTP.** Despite the name, SFTP is a subsystem inside SSH and is a
  completely different protocol — see [ssh](ssh.md).

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 959 | The File Transfer Protocol: the commands, the replies, active and passive data connections |
| RFC 2228 | FTP security extensions, including `AUTH`, `PBSZ`, `PROT` and `CCC` |
| RFC 4217 | Securing FTP with TLS — the profile deployments actually use |
| RFC 2428 | `EPRT` and `EPSV`, the IPv6-capable forms |
| RFC 3659 | Extensions: `MLST`, `MLSD`, `SIZE`, `MDTM` and `REST` |
| RFC 2389 | Feature negotiation: `FEAT` and `OPTS` |
| RFC 2640 | Internationalisation: `OPTS UTF8` |
| RFC 1123 §4.1 | The host requirements that tightened FTP's behaviour |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].ftp`](../CONFIG.md#serverlistenersftp-kind-ftp)
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- A worked configuration: [`examples/files/ftp.yaml`](../../examples/files/ftp.yaml)
- The other file transfer protocols here: [ssh](ssh.md) (SFTP),
  [tftp](tftp.md)
