# TACACS+ — the protocol with the commands in it

`kind: tacacs`, served by **xrelay** or **xot**, TCP port **49**.

Where RADIUS answers "may this user onto the network", TACACS+ answers "may
this user, at this privilege level, run `configure terminal` on this router".
It authorises each command separately and the command is in the packet, which
makes it the protocol in this project where a policy is worth the most per
line — and the one where a relay can say something about administrative access
to the estate's own infrastructure that nothing else can.

## On the wire

Twelve octets of header, then a body:

| Field | Size | What it is |
|-------|------|-----------|
| Version | 1 | Major 0xc, minor 0 or 1 |
| Type | 1 | Authentication (1), authorization (2), accounting (3) |
| Sequence number | 1 | 1 for the client's first packet, even for the server's; a session ends rather than wrap past 255 |
| Flags | 1 | `UNENCRYPTED` (0x01) and `SINGLE_CONNECT` (0x04) |
| Session identifier | 4 | Chosen by the client, authenticated by nothing |
| Length | 4 | The body's length |

The body is **obfuscated**, which RFC 8907 §4.5 is careful not to call
encryption: a pad of chained MD5 digests over the session identifier, the
shared key, the version octet and the sequence number, XORed over the body.
§10.3 says plainly that it is "not cryptographically sound".

There are three exchanges and six bodies. Every variable field's length is
declared ahead of it and nothing is NUL-terminated, so every parse is: read the
fixed octets, check the declared lengths add up to exactly the body, cut the
fields out.

The authorization request is the interesting one. It carries the user, the
port, the remote address, and a list of **arguments**:

```
service=shell
cmd=configure
cmd-arg=terminal
cmd-arg=<cr>
```

So the command a policy is written about — `configure terminal` — exists in no
single field. An argument is `attribute=value` when it is mandatory and
`attribute*value` when it is optional, and the difference is load-bearing: a
client that cannot honour a mandatory argument must refuse the whole request,
where an optional one it does not understand is dropped. A server answering
`priv-lvl=15` as mandatory has told the device to apply it.

## What the protocol gives you

A shared key, and MD5 used as a stream cipher.

The pad for a given session identifier and sequence number is fixed, so
identical plaintext at the same offset gives identical ciphertext, and anybody
holding the key reads everything. There is no integrity check at all: the
obfuscation is confidentiality-shaped and nothing signs a packet, so an on-path
attacker with the key can rewrite a reply and a device cannot tell.

The password is in the body. An ASCII login sends it in a CONTINUE packet's
`user_msg` and PAP sends it in the START packet's `data`, which means it is
readable by the key holder on every administrative login in the estate.

Two things the protocol allows that are worth naming:

- **A body may arrive in the clear.** `TAC_PLUS_UNENCRYPTED_FLAG` says so, and
  §4.5 permits it only on a secured transport.
- **A server may redirect the client.** `TAC_PLUS_AUTHEN_STATUS_FOLLOW` hands
  back another server's address, port and *key*, after which the client sends
  its next credential there. The standard deprecates it and says a client
  should treat it as a failure.

TACACS+ over TLS 1.3 is the fix for all of this, and almost no equipment speaks
it yet.

## What this listener decides

**Whether it can read the body at all.** With `secret_file` it reads the user,
the command and the privilege level; without one it reads the header and
forwards the body unexamined. Naming `commands` or `users` with no key is a
load error rather than a setting that silently matches nothing, and
`tacacs_header_only` is the counter that says a command policy is deciding
nothing.

**Which commands may run.** The patterns match the reassembled command line,
word by word and case-insensitively, with an optional trailing `...` meaning
"and anything after". `show ...` covers every show command; a wildcard in the
middle is refused at load, because a pattern whose author and whose reader
disagree about what it covers is worse than no pattern on a protocol that
authorises each command separately. Abbreviations are not expanded: a user may
type `conf t`, and what reaches the server is what the device sends.

The two lists are read differently, and deliberately. An **allow** pattern
covers exactly the words it names, so `show version` is not `show version
detail`: allowing more than was asked for is the unsafe direction, and `...` is
there for when more is meant. A **deny** pattern covers the command it names and
whatever is appended to it, because a device's command line takes suffixes — a
filter, a redirect, an argument — and under the exact reading `deny_commands:
["show running-config"]` matched the spelling an operator would type and missed
`show running-config | include password`, which is the spelling that prints the
device's credentials. Denying more than was asked for is the safe direction on a
list whose purpose is "no router behind this relay accepts this".

`deny_commands` is checked first and no rule overrides it, which is how "allow
`show ...`, deny `show running-config`" is written. A rule's own lists **add to**
the listener's rather than replacing them: both deny lists are checked and both
allow lists have to be satisfied, so a rule narrows and never widens. The other
way round, a rule that carried a deny of its own would have disarmed every
listener-wide deny for the traffic it covered — an estate handing its network
team `reload` by writing them a deny.

**Who is asking, including when nobody said so at the start.** RFC 8907 §5.4.2
lets an ASCII login leave the START's user field empty: the server answers
GETUSER, the device prompts, and the name arrives in the typed text of a
CONTINUE. That is the ordinary shape of `telnet` to a router, and it is the one
place this relay reads a CONTINUE's `user_msg` — the field it otherwise keeps
only the length of, because the typed text is usually a password. Without that
reading, `users`, `deny_users` and the estate's own authorization rules were a
control anybody could step around by leaving one field blank and typing the name
at the prompt.

**Which privilege a reply may grant.** `priv-lvl` in an authorization response
is a mandatory argument and the device must apply it, so the bound is checked
on the server's answer as well as on the request's own field: the first is a
grant and the second only a claim.

**That the body was not in the clear.** `refuse_unencrypted` defaults on. On
bare TCP that flag means an administrative login's user name and password are
on the wire, and it is either a configuration mistake or somebody stripping the
obfuscation.

**That a FOLLOW does not cross.** Default off, and the refusal stands in shadow
mode too: carrying one to see what would have happened sends the next
credential to a host the server named.

**Who the session belongs to.** A CONTINUE packet carries the typed text and
its lengths and nothing else, so the only way to know whose password prompt it
answers is to have remembered the START. The session table holds that, and a
packet whose sequence number repeats or goes backwards is refused rather than
decided twice — the sequence number is this protocol's own replay guard.

**That a configuration command is engineering activity.** A `configure
terminal` on a core router is the same kind of change as a PLC download, so it
is reported as its own class of event, matched against the work orders on file,
and with `require_grant` refused when no approved grant is open. A `show` is
not engineering: every device in an estate is looked at constantly, and a class
that included those is a class nobody reads.

**What the audit trail says.** `log_accounting` writes every accounting record
as its own line: who ran what, on which device, at what privilege level. That
is worth having separately from the TACACS+ server's own copy because it is in
a different place, written by a different program, and whoever has just got
privileged access to the routers does not have it.

## What it does not do

- **It does not keep a password.** The parsed bodies carry the *lengths* of the
  password-bearing fields and there is no accessor that returns one, because a
  relay that had one would be the second place every administrative credential
  in the estate leaks.
- **It does not sign anything.** There is nothing in this protocol to sign
  with. The obfuscation is applied and removed; an on-path attacker with the
  key is not stopped by this relay, and the answer to that is TLS.
- **It does not expand command abbreviations.** Guessing a platform's
  expansions would mean this relay and the device disagreeing about what
  command was run, which is worse than a pattern that does not match.
- **It does not know a vendor's read-only commands.** The behavioural models
  count a command as a change unless its first word is one of the four every
  platform spells the same way, which is the safe direction.
- **It does not authenticate anybody.** The server proves the password and says
  pass or fail. A rule keyed on `users` here is a filter on who may *attempt*
  to log in to the equipment, which is worth having and worth not overstating.
- **It does not split one connection's sessions across servers.** A connection
  is dialled once and every session on it goes to the same server, because the
  session identifier is only unique within one.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 8907 | The TACACS+ protocol: the header, the obfuscation, the three exchanges, the arguments, and §10 on what the obfuscation is not |
| RFC 1492 | The original TACACS, for the lineage (not served: a different protocol with the same first six letters) |
| RFC 8907 §5.2 | The authentication statuses, including the deprecated FOLLOW |
| RFC 8907 §6.1 | The authorization arguments, the mandatory-versus-optional rule, and `priv-lvl` |
| RFC 8907 §7 | Accounting, and the start, stop and watchdog records |
| TACACS+ over TLS 1.3 | The transport that replaces the obfuscation; `require_tls` and `upstream_tls_mode` are how this listener speaks it |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].tacacs`](../CONFIG.md#serverlistenerstacacs-kind-tacacs)
- The work orders a configuration command is matched against:
  [docs/CONFIG.md `access`](../CONFIG.md#access)
- A worked configuration: [`examples/auth/tacacs.yaml`](../../examples/auth/tacacs.yaml)
- The other protocol that authenticates network equipment: [radius](radius.md)
- What the refusals mean to an operations centre: [docs/ATTACK.md](../ATTACK.md)
