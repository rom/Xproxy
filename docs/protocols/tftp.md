# TFTP — the protocol under provisioning

`kind: tftp`, served by **xrelay** or **xot**, UDP port **69**.

Five packet types, no authentication of any kind, and it is how a switch pulls
its firmware, a machine with no operating system pulls a boot image, and a
telephone pulls its configuration. It was published in 1981 and it is still
load-bearing.

## On the wire

A two-octet opcode, and then almost nothing:

| Opcode | Packet | What it carries |
|--------|--------|-----------------|
| 1 | `RRQ` | A **filename**, a mode, and optional negotiated options |
| 2 | `WRQ` | The same, for a write |
| 3 | `DATA` | A block number and up to 512 octets (or the negotiated block size) |
| 4 | `ACK` | A block number |
| 5 | `ERROR` | A code and a message |
| 6 | `OACK` | The options the server accepted |

The filename and the mode are **NUL-terminated strings**, and the mode is
`netascii`, `octet` or the long-deprecated `mail`.

The extension options (RFC 2347–2349) negotiate `blksize`, `timeout` and
`tsize`. RFC 7440 adds `windowsize`, which lets a server send several blocks
before waiting for an acknowledgement — and multiplies the throughput and the
amplification together.

The transfer mechanics are the part that surprises people: the request goes to
port 69, and then **both ends move to ephemeral ports**. A transfer is a
conversation between exactly two address-and-port pairs, and anything arriving
from a third is not part of it.

## What the protocol gives you

Nothing. There is no user, no password, no token, no transport security, and no
extension that adds one. A server either serves a file to whoever asks or it
does not.

The clients make it worse: a boot ROM and a switch's loader cannot be given a
credential, and will not be gaining one.

## What this listener decides

**The filename, read as a path and refused by class.** This is the heart of the
kind, and the reasoning is worth stating: a *deny list of strings* is a list of
the spellings somebody thought of. It stops `../../etc/shadow` and not
`..\..\etc\shadow`; it stops that and not `/etc/shadow`; it stops that and not
`secret.txt.`, which Windows opens as `secret.txt`. So the name is
**classified**, and the class is what `allow_path_classes` decides:

| Class | What it is |
|-------|-----------|
| `plain` | An ordinary relative name, always allowed |
| `traversal` | A `..` element anywhere in it |
| `absolute` | A leading separator |
| `backslash` | A backslash, which a Windows server reads as a separator and a POSIX one does not |
| `drive` | A drive letter or a UNC prefix |
| `trailing` | A trailing dot or space, which Windows strips before opening the file |
| `non_ascii` | Octets outside ASCII, where the relay and the server may disagree about the encoding |
| `control`, `nul`, `empty` | A control character, a NUL, or no name at all |

The last three **can never be allowed**, and naming one in
`allow_path_classes` is a configuration error rather than a permissive setting.
They do not mean "a path the policy disagrees with"; they mean the relay and the
server are reading **different names**, which is the condition under which no
policy is worth anything.

**The direction, separately, defaulting to read.** A write is how a
configuration leaves an estate and how firmware arrives in it, so `operations`
has to name it.

**The directories and filenames**, once the name is known to be a path: which
subtrees, which patterns, and `max_depth`.

**The mode**, because `netascii` changes line endings and `mail` should not
exist.

**The amplification, by rewriting rather than refusing.** A twenty-octet request
yields a whole file, and `windowsize` multiplies it. So a client asking for a
window of sixty-four against a bound of eight gets its file **at the bound**
rather than an error, because nobody can reconfigure the boot ROM in a switch.
What cannot be lowered is refused — including a server that acknowledges a
larger block size than it was offered, which is the server-side half of the same
problem.

**The two addresses.** Because the protocol moves to an ephemeral port pair, the
relay binds one socket per transfer and accepts datagrams from exactly the
address it is talking to. A datagram from anywhere else is not part of the
transfer and is dropped, which is what stops a third party injecting a block
into somebody else's firmware download.

**The bounds**: the filename length, the transfer size, the block size, the
window size, concurrent transfers overall and per client, and the transfer and
idle timeouts.

### Learning what the traffic is

`learn` records what crosses this listener and writes a proposed policy. Nobody
knows what an estate's TFTP traffic is, and here there is less to go on than
anywhere else: no authentication, no session, no account, so nothing is auditable
in the ordinary sense. A switch fetches its firmware at three in the morning, a
phone fetches a configuration every time it reboots, and the server's own log --
when it has one -- gives an address and a path and says nothing about which of
them were meant to happen.

A subject is one client, one direction and one directory, because `directories`
is the line an engineer argues about. The filenames inside it are listed, and a
`filenames` pattern is proposed only when they generalise: names sharing a small
set of extensions become `firmware/*.bin`, and names that share nothing get no
pattern and a note saying why, because the only pattern that always fits is `*`.

**The amplification bounds are recorded and never proposed.** A request past
`max_window_size` or `max_block_size` is lowered to the bound and still
transfers, so the report sees what was asked for -- and a proposal that turned
that into a rule would have widened, from an observation, the one setting that
stops a twenty-octet request yielding a file to a forged address. They appear as
`window_asked`, `block_size_asked`, `declared_size` and `bytes_moved`, which no
rule uses. `enforce: false` suspends the path, direction and mode policy and
never a bound.

`server_errors` is what the server itself refused -- a file it does not have --
and a subject with nothing but those is not proposed. `path_class` says the name
was not an ordinary relative path; those are recorded and never proposed, because
a class this relay and the server would read differently is not something to
write a rule about. No file contents are recorded. See
[docs/CONFIG.md](../CONFIG.md#serverlistenerstftplearn).

### The imported lists, and the estate's authorisation policy

TFTP names nobody at all -- it has no authentication of any kind, which is most of
why a relay in front of it is worth having. So two questions are asked about the
client itself, after this listener's own `allow_clients` and before a transfer is
started:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. A rule naming `users` matches nobody on this
  kind, so a rule here is written with `networks`, `targets` and `schedule`.

Asked on each request datagram, because the request is all there is: a transfer
runs between two ephemeral ports afterwards and never returns to this socket.
Which paths may be read, and whether writing is allowed at all, stays with this
listener's own policy above.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## What it does not do

- **It does not authenticate, because there is nothing to authenticate.** The
  client list is an address list on UDP. This listener narrows what an
  unauthenticated client can reach; it cannot make the client into somebody.
- **It does not scan file contents.** A firmware image is opaque. YARA over the
  stream is available for the places that want it, and it is a decision with a
  cost.
- **It does not cache.** Each transfer reaches the server.
- **It does not translate `netascii`.** The mode is allowed or refused; the
  relay does not rewrite line endings, because a relay that rewrote a firmware
  image would be corrupting it.
- **It is not a boot server.** It is a relay in front of one, and the server's
  own root, permissions and file set still matter.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 1350 | The TFTP protocol, revision 2: the five packets and the transfer mechanics |
| RFC 2347 | The option extension and `OACK` |
| RFC 2348 | The `blksize` option |
| RFC 2349 | The `timeout` and `tsize` options |
| RFC 7440 | The `windowsize` option |
| RFC 2090 | Multicast TFTP (not served: a transfer with more than two parties has no policy this relay can apply) |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].tftp`](../CONFIG.md#serverlistenerstftp-kind-tftp)
- A worked configuration: [`examples/provisioning/tftp.yaml`](../../examples/provisioning/tftp.yaml)
- The other protocol in a provisioning path: [dhcp](dhcp.md)
