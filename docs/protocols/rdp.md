# RDP — the Windows desktop

`kind: rdp`, served by **xgate**, TCP port **3389**.

RDP is how Windows administration is done, which makes port 3389 the most
attacked port on the internet and RDP credentials the most valuable thing a
phishing run collects. It is also the most complicated protocol in this set: a
connection sequence of a dozen exchanges across four layers before a single
pixel moves.

## On the wire

The stack, bottom to top:

| Layer | What it is |
|-------|-----------|
| **TPKT** | RFC 1006, the same four-octet framing S7comm uses |
| **X.224** | Class 0 transport, whose connection request carries the **negotiation request**: which security protocol the client wants |
| **T.125 MCS** | Multipoint communication: `Connect-Initial`, `Erect Domain`, `Attach User`, and **channel joins** |
| **RDP** | The security exchange, the capability exchange, and then the input, output and virtual channel PDUs |

The **negotiation request** in the X.224 connection request is where the security
of the whole session is decided, in the clear, in one flags field:

| Requested | What happens |
|-----------|-------------|
| `PROTOCOL_RDP` (0) | **Standard RDP Security**: the protocol's own RC4 encryption with an RSA-exchanged key. Deprecated, and the server's public key is signed by a key Microsoft published |
| `PROTOCOL_SSL` (1) | TLS wraps everything from here |
| `PROTOCOL_HYBRID` (2) | **NLA**: TLS, then CredSSP — the credential is authenticated *before* the desktop session is created |
| `PROTOCOL_HYBRID_EX` (8) | NLA with early user authorisation |

NLA is the one that matters. Without it, a connection reaches the login screen —
which means it consumes a session, and it means the login screen is the thing
facing the network. With it, CredSSP (a SPNEGO exchange over TLS, usually
NTLMv2 or Kerberos) authenticates the credential first, and an unauthenticated
connection never creates a session at all.

**Virtual channels** are the part nobody thinks about. A session negotiates
channels by name, and the standard ones include:

| Channel | What it carries |
|---------|----------------|
| `rdpdr` | **Device redirection**: drives, printers, smart cards, serial and parallel ports |
| `cliprdr` | The clipboard, including files |
| `rdpsnd`, `audin` | Audio out and in (the microphone) |
| `drdynvc` | Dynamic virtual channels: a multiplexer, inside which more channels are opened *by name* at any point in a session — decided by `channels.dynamic` |
| `rail` | Remote applications |
| `tsmf`, `urdpdr` | Multimedia and USB redirection |

`rdpdr` with drive redirection means the desktop can read and write the client's
filesystem, and `cliprdr` file transfer means copy and paste moves files. Those
two are the reason a channel policy exists.

### Inside `drdynvc`

`drdynvc` is the one entry above that is not a channel. It is a multiplexer, and
the channels inside it are opened **by name** at any point in a session, by the
*desktop* — the create request travels down to the client, which answers with a
status. A gateway that policed only the static list therefore had a hole of a
specific shape: allowing `drdynvc`, which a current client needs, allowed
everything inside it, including a channel the static list had just refused by
name. `channels.dynamic` is the policy for them.

| Dynamic channel | What it carries |
|-----------------|----------------|
| `Microsoft::Windows::RDS::Graphics` | The **graphics pipeline** (MS-RDPEGFX). A modern session draws through it; without it the client falls back to the slower path or fails |
| `Microsoft::Windows::RDS::DisplayControl` | Resolution and monitor layout changes during a session |
| `Microsoft::Windows::RDS::Geometry` | Window geometry tracking, for multimedia redirection |
| `Microsoft::Windows::RDS::Video::Control::v08.01`, `…::Video::Data::v08.01` | Video redirection |
| `AUDIO_PLAYBACK_DVC`, `AUDIO_INPUT` | Audio out and the microphone, where they ride dynamically rather than on `rdpsnd`/`audin` |
| `rdpdr`, `cliprdr` | Device and clipboard redirection, which a current client opens **here** as well as statically — which is why the static refusal alone was not enough |
| `ECHO`, `echo` | A round-trip measurement |

The names are matched whole and without regard to case. A useful starting point
is the pipeline and display control allowed, and redirection denied:

```yaml
channels:
  allow: [drdynvc]
  dynamic:
    allow: ['Microsoft::Windows::RDS::Graphics', 'Microsoft::Windows::RDS::DisplayControl']
    deny: [rdpdr, cliprdr]
```

## What the protocol gives you

With NLA: a real answer. TLS with a server certificate, and CredSSP binding the
credential to that TLS channel so it cannot be replayed elsewhere. Kerberos
where the estate is domain-joined.

Without NLA: Standard RDP Security, whose RSA key is signed by a key that has
been public for twenty years, which means the server is not authenticated at all
and the session is decryptable by anyone in the path.

And the certificate problem is real even with TLS: most RDP servers present a
self-signed certificate, users click through the warning, and the warning
therefore protects nothing.

## What this listener decides

**Which security protocol the client's leg uses.** `security` names what this
listener will negotiate — and a listener that requires `hybrid` has required NLA,
which means no connection reaches a login screen unauthenticated. This is the
most valuable single line in the section.

**Which the server's leg uses, separately.** `upstream_security` — including
the protocol's own encryption for a host too old for anything else. As with the
vnc kind, the separation is the point: the person's leg can be TLS with NLA while
the relay speaks what the old server supports.

**Whose credential reaches the desktop.** `upstream_user`, `upstream_domain` and
`upstream_password_file`: the person authenticates to the gate, and the gate
presents the account the desktop expects. So the desktop's credential is not
something people know, and a person's access can be withdrawn without changing
it.

**A second factor**, with `mfa`. RDP has no notion of one, and a stolen password
is the whole of the usual attack.

**The channels, by name.** `channels` is the allow list, and the default is the
point: a listener that carries the input and output channels and nothing else has
refused drive redirection, clipboard file transfer, the microphone, printer
redirection and USB redirection in one line. Each of those is a data path in or
out of the estate that does not look like one.

**The devices**, with `devices`, for the finer decision inside `rdpdr`: printers
yes, drives no, smart cards perhaps.

**Recording**, with `recording`, so an administrative session on a domain
controller has a record.

**The connection sequence's shape**, with `max_connections`, and the handshake,
idle and total timeouts — the handshake timeout mattering more here than
elsewhere, because RDP's sequence is long and a client that stalls in the middle
of it is holding resources on both sides.

### The estate's own authorisation policy

Above this listener's own policy sits the `authorization` section, which is not
about RDP: it is the one place that says which identity may reach which listener
and target, in the same words for every protocol.

Where it is asked is a fact about the protocol rather than a choice. RDP carries
the person in one packet, once, and that packet arrives **after** the desktop has
been dialled -- so this gateway cannot refuse before the target is reached, and
neither can the access grant. What it does instead is refuse before the
credential goes any further: the desktop has seen a TCP connection from the
gateway and never the person's name or password, and nobody logged in.

The `target` is the upstream **pool** name rather than the machine this session
happened to reach, so that a rule reads the same here as on an `ssh` listener;
the per-machine question belongs to the access grant, which does check the
machine. `principal` and `groups` are empty.

**What the name is worth here.** The policy is asked before the credential travels, which is the
point: it is what keeps a refused session off the desktop entirely. But it means the account
is the one the client's login *asserts*, and the desktop proves it afterwards. So the
policy narrows what the desktop would have allowed and never widens it: a deny rule is
exact, because refusing a claimed name refuses at least everyone who could have
proved it, while an allow rule keyed on the name is a filter on a claim that
still has to be proven. When the gateway substitutes `upstream_user` and its
password, the desktop cannot prove the client's claimed name; that name is
therefore withheld from the policy unless MFA verified it. It is not an
authenticated grant. A rule that has to
hold whatever a client asserts belongs in `targets` and `networks`, which nobody
can choose for themselves.

A refusal is the reason `authorization` (the event `rdp_authorization`, the
counter `xproxy_refusals_total{kind="rdp",reason="authorization"}`). Either
shadow switch -- `policy: {mode: shadow}` on the listener, or `shadow: true` on
the section -- records what it would have refused and admits.

## What it does not do

- **It does not decode the graphics.** The output PDUs are relayed. Bitmap
  codecs, RemoteFX and the H.264 profiles are video, and a relay that decoded
  them would be a video decoder in the security path.
- **It does not read the desktop's content.** The recording is the record; there
  is no content policy on what is displayed or typed.
- **It does not authenticate CredSSP itself.** The SPNEGO exchange is relayed to
  the server, or the relay presents its own configured credential. There is no
  domain membership in this process.
- **It does not read what a dynamic channel carries.** The channels opened
  inside `drdynvc` are decided **by name** — `channels.dynamic` allows and
  denies them, and a refused one is answered with the status a client with no
  such listener sends. What travels on an allowed one is not inspected: the
  graphics pipeline is a compressed bitstream, and a gateway that claimed to
  police its contents would be claiming to re-implement it.
- **It does not fix the certificate problem for the server.** A client that
  connects directly still sees a self-signed certificate. What this listener can
  do is present a certificate the estate's own trust store validates on the leg
  the person uses.
- **It does not implement RDP gateway (RDG).** That is RDP over HTTPS with its
  own protocol, and it belongs in front of an `http` listener rather than here.

## Standards

| Document | What it covers |
|----------|----------------|
| MS-RDPBCGR | Remote Desktop Protocol: Basic Connectivity and Graphics Remoting — the connection sequence, the negotiation request, Standard RDP Security, the PDUs |
| MS-RDPEGDI | The graphics device interface acceleration extensions |
| MS-RDPEFS | The file system virtual channel (`rdpdr`) |
| MS-RDPECLIP | The clipboard virtual channel (`cliprdr`) |
| MS-RDPEDYC | Dynamic virtual channels (`drdynvc`) |
| MS-CSSP | CredSSP, which NLA uses |
| ITU-T T.125 | The MCS multipoint communication service |
| ITU-T X.224 | The transport protocol whose connection request carries the negotiation |
| RFC 1006 | The TPKT framing |
| RFC 4178 | SPNEGO, which CredSSP negotiates within |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].rdp`](../CONFIG.md#serverlistenersrdp-kind-rdp)
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- A worked configuration: [`examples/bastion/rdp.yaml`](../../examples/bastion/rdp.yaml)
- The other interactive protocols: [ssh](ssh.md), [telnet](telnet.md),
  [vnc](vnc.md)
