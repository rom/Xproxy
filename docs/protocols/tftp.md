# TFTP — the protocol under provisioning

`kind: tftp`, served by **xrelay**, UDP port **69**.

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
`secret.txt.`, which Windows opens as `secret.txt`. So the name is **classified**
— traversal, absolute, backslash, trailing dot, UNC, device name, control
character, NUL, empty — and the class is refused.

Three of those classes can never be allowed at all: a NUL, a control character
and an empty name. They do not mean "a path the policy disagrees with"; they
mean the relay and the server are reading **different names**, which is the
condition under which no policy is worth anything.

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

- The settings: [docs/CONFIG.md `## tftp`](../CONFIG.md#tftp)
- A worked configuration: [`examples/provisioning/tftp.yaml`](../../examples/provisioning/tftp.yaml)
- The other protocol in a provisioning path: [dhcp](dhcp.md)
