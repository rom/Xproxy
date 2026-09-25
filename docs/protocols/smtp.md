# SMTP — mail

`kind: smtp`, served by **xrelay**, TCP ports **25** (relay), **587**
(submission) and **465** (implicit TLS submission).

Mail is the oldest application protocol still carrying business-critical
traffic, and its security was all added afterwards: a line-oriented command
dialogue from 1982, with authentication, encryption, size limits and status
codes bolted on across forty years of RFCs.

## On the wire

A dialogue of commands and three-digit replies, one per line, CRLF-terminated.

| Command | What it does |
|---------|-------------|
| `EHLO` / `HELO` | Identify the client, and — for `EHLO` — get the server's **capability list** |
| `STARTTLS` | Upgrade this connection to TLS |
| `AUTH` | Authenticate, with a SASL mechanism |
| `MAIL FROM` | The envelope sender, plus parameters like `SIZE` |
| `RCPT TO` | One envelope recipient; repeated |
| `DATA` | Everything after this is the message, until a line containing only `.` |
| `BDAT` | The chunked alternative (RFC 3030), with an explicit length |
| `RSET`, `NOOP`, `QUIT`, `VRFY`, `EXPN` | Housekeeping and the two that enumerate users |

Replies are a three-digit code, and — with RFC 3463 — an *enhanced* status code
that says more precisely what went wrong.

The detail a proxy must get right is **where a message ends**. In `DATA` it is a
line containing a single `.`, with dot-stuffing: a line the sender wrote starting
with `.` has an extra one prepended, and the receiver removes it. A proxy that
gets that wrong either truncates a message or lets the sender end it early and
start injecting commands — which is the classic SMTP smuggling shape, and the
modern version of it turns on **bare newlines**: a lone LF where the protocol
requires CRLF, which different implementations disagree about.

`XCLIENT` (a Postfix extension) is how a proxy tells the real mail server who
the actual client was, so the server's own policy, logging and rate limits still
see the original.

## What the protocol gives you

**STARTTLS**, which works and has one structural weakness: it is advertised in
the `EHLO` response, in the clear, and something on the path can remove it from
the list. A client with `STARTTLS` as opportunistic then continues unencrypted.
Implicit TLS on 465 (RFC 8314) has no such step and is the better answer where
both ends support it.

**SASL AUTH**, with PLAIN and LOGIN being what deployments use — the username
and password, base64-encoded, which is an encoding and not a protection. They
should only be offered after TLS, and the protocol says so, and not every server
enforces it.

What the protocol gives you for *authorisation* is nothing at all on port 25:
a relay accepts mail for its own domains from anybody. Everything an estate does
about that — SPF, DKIM, DMARC, reputation — is above this protocol.

## What this listener decides

**Whether TLS is required**, with `require_tls` and `tls_mode`, so a client
cannot be talked out of it by a stripped capability.

**Which capabilities the client is even offered.** `hide_capabilities` rewrites
the `EHLO` response, which is the right place for a decision like "this listener
does not offer `AUTH` before TLS" or "this listener does not offer `VRFY`" — a
capability the client never sees is one it does not try.

**Whether authentication is required**, with `require_auth`, which is the
difference between a submission service and an open relay.

**The commands.** `commands` names them, so `VRFY` and `EXPN` — which enumerate
an organisation's users — are a decision rather than a default.

**Where a message ends, strictly.** `bare_newlines` decides what happens to a
lone LF: rejected, or the connection ended. This is the SMTP smuggling control,
and the reason it is a setting rather than a fixed behaviour is that some
legitimate senders are genuinely broken, and an operator has to be able to see
that in a log before deciding.

**The bounds**, which on this protocol are unusually load-bearing:
`max_command_line`, `max_text_line`, `max_message_size`, `max_recipients` (the
one that matters for a spam run through a compromised account), `max_messages`
per connection, and `max_errors` — because a client generating error after error
is probing, not sending mail.

**`XCLIENT`**, so the mail server behind this relay still sees the real client
address and its own policy still works. Without it, every message appears to come
from the proxy and every reputation and rate control behind it is blinded.

**`banner` and `hostname`**, because the greeting is the first thing a sender
sees and an estate usually wants its own name in it rather than the software's.

## What it does not do

- **It is not a mail server.** No queue, no spool, no retry, no delivery, no
  mailbox. It is the dialogue and the policy on it.
- **It does not do SPF, DKIM or DMARC.** Those are the mail server's, and they
  need the queue and the DNS this relay does not have.
- **It does not filter content.** The message body is bounded, not read. Content
  scanning belongs in the mail server's own filters, or in an ICAP service.
- **It does not rewrite addresses or headers.** `EHLO` capabilities and the
  `XCLIENT` it adds are the only things it writes into the dialogue.
- **It does not implement DANE or MTA-STS.** Those are about how *this* estate's
  mail reaches somebody else's, which is the sending side's problem.
- **It does not authenticate.** `AUTH` is forwarded and the mail server decides.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 5321 | SMTP: the commands, the replies, the `DATA` termination and dot-stuffing |
| RFC 5322 | The message format `DATA` carries |
| RFC 6409 | Message submission for mail — port 587 and what a submission server must do |
| RFC 3207 | SMTP over TLS: `STARTTLS` |
| RFC 8314 | Cleartext considered obsolete: implicit TLS on 465 |
| RFC 4954 | SMTP service extension for authentication |
| RFC 1870 | The `SIZE` extension |
| RFC 3030 | `BDAT` and binary MIME |
| RFC 3463 | Enhanced mail system status codes |
| RFC 2920 | Command pipelining |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].smtp`](../CONFIG.md#serverlistenerssmtp-kind-smtp)
- A worked configuration: [`examples/mail/submission.yaml`](../../examples/mail/submission.yaml)
