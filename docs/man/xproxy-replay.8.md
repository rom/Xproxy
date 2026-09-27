# xproxy-replay

## NAME

xproxy-replay - read and show a recorded session

## SYNOPSIS

`xproxy-replay` [`-summary`] [`-html` *FILE*] [`-png` *DIR*] [`-at` *DURATION*]
[`-every` *N*] [`-max-frames` *N*] [`-speed` *N*] [`-input`] [`-plain`]
[`-verify`] [`-chain-key` *REF*] [`-key` *REF*] [`-force`] *FILE*

## DESCRIPTION

`xproxy-replay` reads a session recording written by `xgate`(8) — the SSH,
telnet, VNC and RDP gateways — or by `xrelay`(8)'s FTP relay, and shows
it.

A recording of a session made of text is replayed to the terminal, with
the escape sequences that reach outside the replay filtered out: a
recording carries whatever the far end sent, and handing that straight to
a reviewer's terminal is the one way reading a recording can hurt.

A recording of a graphical session is a protocol stream rather than a
video, which is the deliberate trade the gateways make: decoding at
capture time would mean implementing every encoding a desktop might
choose and silently losing the rest. This program is the decoder written
against the file afterwards. For RFB (`*.rfb.cast`) it rebuilds the
framebuffer and can write PNG frames or one self-contained page that
plays them. For RDP (`*.rdp.cast`) it reads the framing, the channels and
the marks, and says plainly that the graphics are not decoded rather than
drawing something nobody sent.

Where a recording has an integrity manifest beside it — `xgate`(8) and
`xrelay`(8) write `<recording>.chain` when `recording.integrity` asks for
one — it is checked before anything is replayed, and a recording that does
not match its manifest is not shown. A reviewer about to describe what
they saw in a recording should not have to remember to ask whether the
file is the one the proxy wrote. A recording with no manifest replays as
before.

Where the recording section encrypted the file at rest, the name ends
`.cast.enc` and the bytes on the disk are ciphertext: `-key` is the
reference it was written under, and without it the program says the file
is encrypted rather than failing as though it made no sense.

It opens no sockets, runs nothing, and writes only where it is told.

## OPTIONS

| Option | Description |
|--------|-------------|
| `-summary` | Print what the stream did — every rectangle with its encoding and size, the totals, and every mark — instead of replaying it. |
| `-html` *FILE* | Write one self-contained page that plays the session: the frames, the recorded timing, and the marks beside them. No network, no scripts from anywhere else. |
| `-png` *DIR* | Write one PNG per framebuffer update into a directory that must already exist. |
| `-at` *DURATION* | With `-png`, write only the screen as it was at that point of the session. |
| `-every` *N* | Keep one frame in this many updates. |
| `-max-frames` *N* | Stop after this many frames. Default 2000: a session of ten thousand updates is not a page anything opens. |
| `-speed` *N* | Multiply the recorded timing when replaying a session of text. |
| `-input` | Include what the client sent, where the recording holds it (`recording.input`). |
| `-plain` | Drop every escape sequence rather than keeping the ones that draw. |
| `-verify` | Check the recording against its manifest, print what was found, and stop. The answer says whether the records carried MACs and whether they verified. |
| `-key` *REF* | The key an encrypted recording (`*.cast.enc`) was written under, as an absolute path or `env:NAME`. |
| `-chain-key` *REF* | The integrity key, for a manifest that carries MACs. A vault reference is refused with what to do instead: this program reads no vault. |
| `-force` | Replay a recording whose manifest does not verify. It is no longer the file the proxy wrote, and stderr says so. |
| `-version` | Print the version and exit. |

## ENCODINGS

Decoded: Raw, CopyRect, RRE, CoRRE, Hextile, TRLE and ZRLE, which is what
RFC 6143 specifies, with the desktop-size and last-rect pseudo-encodings
and the two cursor ones read to keep the stream in step.

Not decoded: Tight and the vendors' own. They are not in RFC 6143, Tight
carries JPEG and its own compression streams, and a player that guessed
would be inventing a picture inside an investigation. Such a rectangle
stops the decoding, is counted, and is named in the output.

## EXIT STATUS

0 on success, 1 on an error, 2 on a usage mistake.

## EXAMPLES

Replay a bastion session as it happened:

```
xproxy-replay /var/log/xgate/rec/session-20260101-120000-alice.cast
```

What a VNC session's stream did, without drawing it:

```
xproxy-replay -summary session-20260101-120000-alice.rfb.cast
```

A page a reviewer can open with no network:

```
xproxy-replay -html /tmp/session.html session-20260101-120000-alice.rfb.cast
```

The screen as it was twelve seconds in:

```
xproxy-replay -at 12s -png /tmp/frames session-20260101-120000-alice.rfb.cast
```

## INTEGRITY

Without a key the chain's links and the segment digests are checked,
which catches accidental corruption, a shortened file, and a partial edit
by anybody who did not rebuild every record after the one they changed.
With the key every record also carries an HMAC-SHA256, and then the
records cannot be forged by somebody who has filesystem access and not
the key. It is a MAC and not a signature: whoever can read the key can
forge a record too, so verify somewhere the recording host is not.

Check a recording and its keyed manifest:

```
xproxy-replay -verify -chain-key env:XPROXY_CHAIN_KEY session-...cast
```

On a recording encrypted at rest the manifest covers the ciphertext, so
this answer needs no `-key` at all: an auditor can be given the manifest
key and establish that the file is the one the proxy wrote without being
able to read the session in it.

## ENCRYPTION AT REST

An encrypted recording is a 32-octet header, one AES-256-GCM frame per
chunk and an empty frame that ends it. The file key is derived per
recording from the configured key and a random salt in the header, so two
recordings under one key never share a key stream; each frame's nonce is
its position and its additional data is the header, so a frame cannot be
moved within the file or between files and the header cannot be edited.
Only the key can produce the end frame, so a file cut short has no end and
this program says so rather than replaying a session as though it were
whole. It is a symmetric key: whoever can read it can read every recording
it covers.

## SEE ALSO

`xproxyctl`(8), `xgate`(8), `xrelay`(8), `xproxy.yaml`(5)
