# VNC — RFB, the remote framebuffer

`kind: vnc`, served by **xgate**, TCP port **5900** and up.

RFB is a screen, a keyboard and a mouse over a socket. It is the protocol behind
every VNC server, every hypervisor console, and a great deal of industrial HMI
remote access — and its base authentication is a challenge-response with a
**64-bit DES key derived from at most eight characters of password**.

## On the wire

A version handshake in ASCII — `RFB 003.008\n` — and then a security handshake
whose shape depends on the version. From 3.7 the server offers a list of
**security types** and the client picks one:

| Type | What it is |
|------|-----------|
| 1 | **None** — no authentication at all |
| 2 | **VNC Authentication** — DES challenge-response, 8-character key |
| 16 | **Tight** — a vendor tunnel and capability negotiation |
| 18 | **TLS** — an anonymous TLS tunnel, so no server authentication |
| 19 | **VeNCrypt** — a subtype negotiation: `TLSNone`, `TLSVnc`, `TLSPlain`, `X509None`, `X509Vnc`, `X509Plain` |
| 5 | **RA2** / RSA-AES — RealVNC's, with an RSA server key |
| 30, 35 | Apple's variants |

VeNCrypt is the one that matters, because it is the only widely implemented
family with a real server certificate: the `X509*` subtypes authenticate the
server, and `TLS*` subtypes use anonymous Diffie-Hellman, which encrypts and
authenticates nothing.

After security comes initialisation — the framebuffer's width, height and pixel
format, and the desktop name — and then messages:

| Client to server | Server to client |
|-----------------|------------------|
| `SetPixelFormat`, `SetEncodings` | `FramebufferUpdate` — rectangles, each with an **encoding** |
| `FramebufferUpdateRequest` | `SetColourMapEntries` |
| `KeyEvent`, `PointerEvent` | `Bell` |
| `ClientCutText` — the clipboard | `ServerCutText` — the clipboard |

The **encodings** are where the parsing risk is: Raw, CopyRect, RRE, Hextile,
**ZRLE** and **Tight** (both of which are zlib-compressed), and the
pseudo-encodings that change the session itself — `DesktopSize` and
`ExtendedDesktopSize`, cursor shapes, continuous updates. A compressed rectangle
declares its own dimensions, so a rectangle claiming to be larger than the
framebuffer is a decompression writing outside the buffer.

## What the protocol gives you

VNC Authentication: a 16-octet challenge, DES-encrypted with a key made from the
first eight characters of a password, with the bits of each byte reversed
(a historical implementation quirk everybody copied). There is no user — the
password *is* the account — and it is brute-forceable.

VeNCrypt's `X509Plain` gives a username and a password inside TLS with a
validated server certificate, which is a real credential over a real channel.
`TLSVnc` gives the DES exchange inside anonymous TLS, which protects it from
passive observation and not from a machine in the middle.

There is no authorisation model at all. A session either has the desktop or does
not.

## What this listener decides

**Which security type may be used, on each side separately.** `security_types`
and `vencrypt_subtypes` for the client's leg; `upstream_security` for the
server's. That separation is the useful part: the *person* can be required to
use `X509Plain` with a validated certificate, while the relay speaks whatever
the old HMI behind it supports — and the weak leg is as short as the topology
allows.

**Whose credential opens the desktop.** `password_file` is for the client's leg
and `upstream_password_file` for the server's, so the person authenticates with
their own credential and the shared VNC password never leaves the relay. That is
the single most useful thing this kind does: a VNC password is by construction
shared, and this is how it stops being something people know.

**A second factor**, with `mfa`, in front of a protocol whose entire
authentication is eight characters.

**Whether the session can change anything.** `view_only` drops `KeyEvent` and
`PointerEvent`, which is how a shoulder-surfing or training session is served
without giving anyone the mouse.

**The clipboard**, with `clipboard`, in each direction. `ClientCutText` and
`ServerCutText` are a file transfer channel if nobody is looking: a person can
paste a script in, or copy data out, and neither appears in a recording as
anything but a paste.

**The picture's bounds.** `bounds` and `pixel_stream` are the decompression
controls: a rectangle's declared dimensions are checked against the framebuffer
*before* it is decompressed, the decompressed size is bounded, and a ZRLE or
Tight rectangle that does not fit is refused. `allow_resize` decides whether the
desktop-size pseudo-encodings may change the framebuffer underneath that check.

**Recording**, with `recording`, and the session's shape: `max_connections`, and
the handshake, idle and total timeouts.

**SSH tunnelling**, with the `ssh` section, for reaching a VNC server that only
listens on localhost — which is how a well-configured VNC server is usually set
up.

### The estate's own authorisation policy

Above this listener's own policy sits the `authorization` section, which is not
about RFB: it is the one place that says which identity may reach which listener
and target, in the same words for every protocol. This listener asks it after the
client has identified itself and before the desktop is dialled, so a refused
session never reaches a machine.

The `user` it decides about is the plain credential's user or the name the factor
prompt asked for -- so a listener under a policy about people needs a security
type that carries a name (`mslogon2`, or VeNCrypt with a named credential),
exactly as `require_grant` does. The `target` is the upstream **pool** name; the
per-machine question belongs to the access grant. `principal` and `groups` are
empty: RFB gives the gateway neither.

A refusal is the reason `authorization` (the event `vnc_authorization`, the
counter `xproxy_refusals_total{kind="vnc",reason="authorization"}`). Either
shadow switch -- `policy: {mode: shadow}` on the listener, or `shadow: true` on
the section -- records what it would have refused and admits.

## What it does not do

- **It does not re-encode the framebuffer.** Rectangles are bounded and
  validated, not transcoded. A relay that re-encoded video would be a video
  codec with a security boundary attached.
- **It does not read the screen.** There is no OCR, no content policy on what is
  displayed. The recording is the record.
- **It does not implement RA2 / RSA-AES cryptography end to end.** The
  `rsa_key_file` and `upstream_rsa_fingerprint` settings let the relay be a party
  to it; where that is not configured, the type can be refused.
- **It does not turn an unauthenticated server into an authenticated one for the
  server's own sake.** A VNC server reachable directly is still reachable
  directly; this is a gate, and the network path decides what it is worth.
- **It does not police key events.** A `KeyEvent` is a key. There is no command
  structure to parse, which is why `view_only` and recording are the controls.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 6143 | The Remote Framebuffer Protocol: versions 3.3 to 3.8, the security types, the messages and the standard encodings |
| RFB Protocol community specification | The Tight, ZRLE and pseudo-encoding extensions, and the VeNCrypt subtypes |
| RFC 8446 | TLS 1.3, for the VeNCrypt `X509*` subtypes |
| RFC 1950, 1951 | zlib and DEFLATE, which ZRLE and Tight use |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].vnc`](../CONFIG.md#serverlistenersvnc-kind-vnc)
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- A worked configuration: [`examples/bastion/vnc.yaml`](../../examples/bastion/vnc.yaml)
- The other interactive protocols: [ssh](ssh.md), [telnet](telnet.md),
  [rdp](rdp.md)
