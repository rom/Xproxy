# POP3 — the other mailbox protocol

`kind: pop3`, served by **xrelay**, TCP port **110** (with STLS) and **995**
(POP3S).

POP3 is what IMAP replaced, and it is still configured on the things nobody
revisits: the scripts that pull invoices off a mailbox, the multifunction
printers that mail scans and collect bounces, the phone somebody set up in 2014,
the integration that was written before anybody asked which protocol it used.

It is also the protocol whose whole purpose is to move a mailbox somewhere else.
That makes the bound on how much one connection may take the single most
valuable line in a `pop3` listener's configuration — and it makes this kind
worth having in front of a server an estate cannot turn POP3 off on.

## On the wire

POP3 is as small as a protocol gets: a one-line command, a one-line or
many-line reply, three states, fifteen commands. The smallness is where the
traps are.

**A reply is one line or many, and for two commands it depends on the
argument.** `+OK`/`-ERR` is the status; a multi-line reply follows it with lines
of data and ends with a line containing one dot. `RETR 1` is always multi-line,
`STAT` never is — and `LIST` lists the whole mailbox while `LIST 3` answers one
line about message 3. `UIDL` is the same. A relay that guesses wrong reads the
next reply as part of this one, or waits for a terminator that is not coming;
either way the two ends have desynchronised, and on this protocol that means a
client is shown somebody else's mail or none of its own.

**The dot is stuffed.** RFC 1939 §3 says a data line that starts with a dot is
sent with two, so the terminator cannot appear inside a message. A reader that
does not unstuff sees a message end where the sender did not put one — the same
class of ambiguity as SMTP's, and the reason both protocols have a test for it
here.

**The credential is in the second command, in the clear.** `USER bob` names an
identity; `PASS secret` sends the password on the next line. There is no
negotiation in between, nothing to inspect and nothing to downgrade: either the
transport protects it or it has been published. `APOP` is the one alternative
the base protocol offers — an MD5 digest over the timestamp in the server's
greeting and the password — and RFC 5034 adds `AUTH` with SASL mechanisms. An
`AUTH` that names no mechanism is refused: it is a capability query in the shape
of a credential exchange, there is nothing in it for `mechanisms` or
`require_tls` to decide about, and the `+OK` that answers it used to move this
relay's view of the session into the transaction state with nobody logged in.
CAPA is where a client reads the mechanism list.

**The greeting carries a challenge.** The `<1896.697170952@mail.test>` in a POP3
greeting is what an APOP digest is computed over. A relay that invented its own
greeting would make every APOP digest unverifiable, so this one carries the
server's unchanged.

## What the protocol gives you

- **the identity** — `USER`, or the name beside an APOP digest
- **the operation** — fifteen command names, of which `DELE` and `RSET` are the
  only ones that change anything
- **which message** — a number, on `RETR`, `TOP`, `DELE`, `LIST` and `UIDL`
- **how much is leaving** — the octets of each multi-line reply, counted as they
  pass, which is the only measure of volume this protocol offers
- **what the server will do** — the `CAPA` list (RFC 2449), including its SASL
  mechanisms and whether STLS is on offer

What it does not give you is a sequence set, a mailbox name or a search: there is
exactly one mailbox and one message at a time.

## What this listener decides

The same five questions the [imap](imap.md) kind asks, with two differences that
come from the protocol rather than from a choice.

**There is no mailbox list,** because there is one mailbox. What takes its place
is the retrieval bound.

**The credential question is simpler and harsher.** `require_tls` defaults on and
refuses `USER`, `PASS`, `APOP` and a plaintext SASL mechanism on an unencrypted
connection, and the refusal is not shadowable. `tls_mode: starttls` terminates
RFC 2595's STLS here rather than forwarding it — and anything the client
pipelined behind the upgrade is refused, because those octets were written before
the client could have seen the answer and are plaintext to one end and ciphertext
to the other.

**The copying bound is a running total.** `max_retr_bytes` and `max_messages`
count what this connection has already taken, and they are enforced
*mid-transfer* as well as before a command: a bound that only applied to the next
command is one a client walks past one message at a time, and a single `RETR` of
a very large message is a copy of a mailbox by itself. A client that reaches the
message bound before a command is told no and can carry on with everything else;
one that reaches the byte bound inside a message has its connection ended, which
is the honest outcome — a truncated message presented as whole would be worse.

Beyond that: the command lists (`DELE` and `RSET` are the writes a `read_only`
listener refuses), the mechanism list — enforced twice, because a mechanism the
policy refuses is also removed from the `CAPA` list the client reads — the
identities that may be claimed, and the per-user and per-client rules that
narrow all of it. The behavioural models get the account, the command and the
octets, so a client whose daily total has been a megabyte and is now four
hundred is a finding before any configured bound is reached.

The settings are in
[CONFIG.md](../CONFIG.md#serverlistenerspop3-kind-pop3), and the estate-wide
identity rules in [authorization](../CONFIG.md#authorization) apply to the name
a `USER` claims.

## What it does not do

**It does not read messages.** The octets of a `RETR` are counted and copied,
never held or inspected. Content scanning on mail belongs on the SMTP path,
where a message is one object.

**It does not verify an APOP digest.** It cannot: the digest is over the
password, which this relay does not hold. What it does is carry the server's
greeting unchanged so that the digest the client computed verifies at the server
that issued the challenge — and let `mechanisms` refuse APOP outright on a
listener that would rather have SASL.

**It does not translate between POP3 and IMAP.** They are two protocols and this
is a relay, not a gateway.

**It does not hold mailbox state.** No message numbering of its own, no cache,
no deletions remembered across connections. The update state belongs to the
server.

## Standards

| Document | What is implemented |
|----------|---------------------|
| RFC 1939 | POP3: the three states, the command set, the one-line and multi-line reply forms, §3's dot-stuffing |
| RFC 2449 | The CAPA extension, read and narrowed |
| RFC 2595 | STLS on port 110, terminated by this relay rather than forwarded |
| RFC 5034 | The AUTH command and its SASL exchange, carried as credential material without being parsed |
| RFC 4616 | The PLAIN mechanism, recognised as one that carries the password |

## See also

- [IMAP](imap.md) — the larger mailbox protocol, where the bound is a sequence
  set rather than a running total
- [SMTP](smtp.md) — submission and transfer
- [docs/ATTACK.md](../ATTACK.md) — the ATT&CK techniques these refusals carry
