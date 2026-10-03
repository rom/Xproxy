# IMAP — the mailbox

`kind: imap`, served by **xrelay**, TCP port **143** (with STARTTLS) and **993**
(IMAPS).

A mailbox is the most complete record of what an organisation has said and been
told that exists anywhere: every decision, every negotiation, every password
reset, every attachment somebody sent "just so you have a copy". IMAP is the
protocol for reading all of it with one credential, from anywhere, as many times
as you like.

That makes this a different problem from the SMTP relay next door. A submission
proxy sees one message on its way out and can decide about it. An IMAP relay
sees a client that has already authenticated asking for everything that ever
arrived — and the interesting request is not malformed, oversized or strange. It
is `UID FETCH 1:* (BODY[])`, which is what a mail client's first synchronisation
and an emptied account look like, character for character.

## On the wire

IMAP is a line protocol with a tag on every command, and it is stateful in two
ways that both matter to a proxy.

**The command set depends on the state.** RFC 9051 §3 gives a connection four
states — not authenticated, authenticated, selected, logout — and says which
commands belong to each. `LOGIN` is only legal in the first, `SELECT` in the
second, `FETCH` only once a mailbox is open. A client that sends `FETCH` before
`SELECT` is either broken or looking to see what answers.

**A command can end in a literal, and the octets have not arrived yet.** `A1
APPEND INBOX {310}` says the next 310 octets are the argument. A server that
wants them sends a continuation request (`+ go ahead`) first and the client
waits; with RFC 7888's LITERAL+ the client writes `{310+}` and sends them
immediately. A command does not end at a literal either: the rest of the line
follows the octets, and may end in another one, so one command can be a
conversation.

Responses come in three shapes. A **tagged** response (`A1 OK ...`) is the
answer to the command with that tag. An **untagged** one (`* 23 EXISTS`) is data
the server volunteers, at any time, which is what IDLE is made of. A
**continuation request** (`+ ...`) asks for a literal or the next step of a SASL
exchange.

Mailbox names are not plain strings. RFC 3501 §5.1.3 encodes a non-ASCII name in
a modified UTF-7 — `&` starts a base64 run of UTF-16 code units, `-` ends it,
`&-` is a literal ampersand — so `~peter/mail/&U,BTFw-` is one mailbox and
`~peter/mail/台北` is the same one. RFC 9051 allows the UTF-8 spelling directly
once the client has enabled `UTF8=ACCEPT`, which means a policy has to compare
the *decoded* name or it compares nothing.

Both ports are in use everywhere. 993 is TLS from the first octet; 143 with
STARTTLS (RFC 2595) is an upgrade negotiated in the clear, and a client that
never asks for it sends its password in the clear.

## What the protocol gives you

Everything an access policy needs is in the command line, in the clear, before
the server has read it:

- **the identity being claimed** — `LOGIN bob secret`, or the mechanism of an
  `AUTHENTICATE`
- **the operation** — the command name, with the `UID` forms being the same
  operation under a different spelling
- **the mailbox** — once decoded, and for `RENAME` and `COPY` there are two
- **how much is being asked for** — the sequence set of a FETCH, STORE, COPY or
  MOVE, which is the number of messages the request names
- **how much is being written** — the declared size of an APPEND's literal
- **what the server is prepared to do** — the capability list, which says which
  mechanisms exist and whether compression is on offer

What it does not give you is the content: the message bodies are what the
exchange is *for*, and reading them is the mail server's job rather than this
relay's.

## What this listener decides

Five questions, in this order, because the cheapest and least revocable come
first.

**1. Is this a command this relay knows?** An unknown command is refused rather
than forwarded. A relay that carries what it cannot name is a tunnel.

**2. Is it legal in the state the connection is in?** The state table is the
relay's own, so a `FETCH` before a `SELECT` is answered here and the mailbox
never sees it.

**3. Does the credential need a transport it has not got?** `require_tls`
defaults on and refuses `LOGIN`, and `AUTHENTICATE` with PLAIN or LOGIN, on a
connection in the clear. The refusal is **not shadowable**: by the time a policy
could be consulted the password has travelled. On a listener with a certificate
and `tls_mode: starttls` this relay terminates the upgrade itself, which is how
a client nobody can reconfigure gets TLS anyway.

**4. Do the lists admit it?** The command lists, the mailbox lists — compared on
the decoded name, with `*` matching across the hierarchy and `%` within one
level, exactly as IMAP's own `LIST` does — the mechanism list, and the identities
that may be claimed. A rule narrows all of that for a named set of users,
clients and mailboxes.

**5. Are the bounds satisfied?** This is the part worth more than the rest.

`max_fetch_messages` counts what a sequence set **names**, not what comes back,
and refuses before the server reads anything. An open-ended set (`1:*`, `*`) is
refused outright once the bound is set, because the size of that request is the
mailbox's rather than the client's — `allow_open_sets` is the exemption for an
estate whose clients legitimately synchronise everything.

`max_append_bytes` is checked against the **declared** size of a literal,
because LITERAL+ sends the octets without waiting for anybody to agree. A
refused command's octets are then read and dropped rather than left to
desynchronise the connection: the client announced them and is going to send
them whatever it is told.

Two things happen to the server's own answers. The **capability list is
narrowed**: a mechanism the policy will refuse is removed, `LOGINDISABLED` is
added where `LOGIN` would be refused (RFC 3501 §6.2.3 makes that the way a
server says so, and a client that reads it asks for something else instead of
sending a password into a refusal), and `COMPRESS=DEFLATE` goes whenever
`refuse_compression` is on — a deflated connection cannot be inspected, so
advertising it would be an offer to stop. And a **PREAUTH greeting** is refused:
it says the connection is authenticated before anybody claimed an identity,
which would make every later decision here about a name this relay never saw.

The behavioural models get the account, the mailbox, the command and the number
of messages named, which is a richer set than most kinds offer: a finding is
"this account has read its mail the same way every day for a year, and today it
asked for all of it". Unlike the TACACS+ kind's, a finding here reaches the ban
ladder — these clients are people's mail applications, and the cost of being
wrong is a client that reconnects.

The settings are in
[CONFIG.md](../CONFIG.md#serverlistenersimap-kind-imap), and the estate-wide
identity rules in [authorization](../CONFIG.md#authorization) apply to the name
a `LOGIN` claims.

## What it does not do

**It does not read messages.** A FETCH's response carries message bodies and
they are forwarded, counted and not inspected. Content scanning on mail belongs
where the message is one object — the SMTP path, or the mail server's own
filter — rather than on a protocol that delivers arbitrary fragments of
arbitrary messages on request.

**It does not hold a mailbox password or check one.** The server authenticates;
this relay decides which mechanism may be used, by whom, over what transport.

**It does not carry COMPRESS=DEFLATE.** Not a limitation so much as a decision:
see above.

**It does not implement an IMAP server.** There is no cache, no mailbox state of
its own, and nothing it answers out of its own knowledge except a refusal and
the STARTTLS upgrade.

**It does not interpret a FETCH item list or a SEARCH key.** Those are kept
whole and forwarded, because a relay that re-encoded them would be deciding
about one request and sending another.

## Standards

| Document | What is implemented |
|----------|---------------------|
| RFC 9051 | IMAP4rev2: the command set, the four states, the response forms, the literal, the sequence set |
| RFC 3501 | IMAP4rev1, which is what the installed base speaks, including §5.1.3's modified UTF-7 for mailbox names |
| RFC 2595 | STARTTLS on port 143, terminated by this relay rather than forwarded |
| RFC 7888 | LITERAL+ and LITERAL-: the non-synchronising literal, which is why a bound is checked against the declared size |
| RFC 4959 | SASL-IR: an initial response on the AUTHENTICATE line, recognised as a credential and not logged |
| RFC 2177 | IDLE, carried and bounded by `max_idle_duration` |
| RFC 6851 | MOVE, decided about as a write and as a collection |
| RFC 3691 | UNSELECT |
| RFC 2342 | NAMESPACE |
| RFC 2971 | ID |
| RFC 4314 | The ACL commands, decided about as writes |
| RFC 9208 | The quota commands |
| RFC 4978 | COMPRESS=DEFLATE, recognised and refused |

The capability list is read and narrowed rather than interpreted, so an
extension this project has never heard of is advertised as the server sent it
and its commands are refused by name — which is the safe direction.

## See also

- [SMTP](smtp.md) — the other half of mail: submission and transfer
- [POP3](pop3.md) — the smaller mailbox protocol, with the same bound in a
  different shape
- [LDAP](ldap.md) — the directory the mail server probably authenticates against
- [docs/ATTACK.md](../ATTACK.md) — the ATT&CK techniques these refusals carry
