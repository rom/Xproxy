# TDS — SQL Server

`kind: tds`, served by **xrelay**, TCP port **1433**.

The Tabular Data Stream, Microsoft's protocol for SQL Server. Its structure is
unusual among the database protocols here in one important way: **the TLS
handshake is carried inside TDS packets**, so a proxy has to read the protocol
before it can read the encryption, and the negotiation that decides whether
there will be encryption at all happens in the clear.

## On the wire

An 8-octet packet header — type, status, length, SPID, packet id, window —
followed by a payload. A message may span several packets, with the status
byte's EOM bit marking the last.

| Type | Message |
|------|---------|
| 0x12 | `PRELOGIN` — an option table: version, **encryption**, instance name, thread id, MARS, trace id, federated authentication |
| 0x10 | `LOGIN7` — the identity: hostname, **username**, password, **app name**, server name, library, language, **database** |
| 0x01 | `SQLBATCH` — SQL as text |
| 0x03 | `RPC` — a remote procedure call: a **procedure name or id**, flags and parameters |
| 0x07 | Bulk load |
| 0x06 | `ATTENTION` — cancel |
| 0x04 | Tabular result, the server's answer |
| 0x0E | Transaction manager request |
| 0x17 | The TLS handshake, wrapped |

`PRELOGIN`'s encryption option is the one to understand. Each side declares
`ENCRYPT_OFF`, `ENCRYPT_ON`, `ENCRYPT_NOT_SUP` or `ENCRYPT_REQ`, and the
combination decides whether TLS follows — and, historically, whether TLS covers
only the login packet or the whole session. It is one octet, in the clear, and
it decides everything about the confidentiality of what follows.

`LOGIN7` carries the password with a fixed obfuscation — a nibble swap and an
XOR with `0xA5`. It is not encryption and was never claimed to be.

`RPC` matters because `sp_executesql` takes SQL **as a parameter**: a policy that
read only `SQLBATCH` would see a procedure call and miss the statement inside
it.

## What the protocol gives you

TLS, when the negotiation reaches it, and Windows integrated authentication
(NTLM or Kerberos through SSPI) which is genuinely strong where an estate is
domain-joined.

What it also gives you is the negotiation above. A client configured with
"encrypt if the server supports it" — which was the default for many years and
many drivers — will send `LOGIN7` in the clear if something answers
`ENCRYPT_NOT_SUP`. And `LOGIN7` in the clear is a SQL Server password with a
nibble swap on it.

## What this listener decides

**Whether the connection may be unencrypted at all — and the relay answers the
negotiation itself.** This is the important design decision in this kind: the
`PRELOGIN` encryption option is *not* forwarded from the server and relayed
back. The relay decides it, so a client that would have downgraded never sees
the octet that would let it.

**Whether a password may cross in the clear.** `allow_cleartext_password` is the
explicit line, because the `LOGIN7` obfuscation is not encryption.

**The identity from `LOGIN7`.** `allow_users`, `allow_databases` and
`allow_apps` — the app name being how an estate distinguishes its own services,
and therefore a good rule selector. `allow_integrated` decides whether Windows
integrated authentication may be used at all, which on a listener facing a
non-domain network is a decision worth making explicitly.

A login carrying **no user name** is the case worth naming: it means integrated
authentication, and a listener that admitted it without meaning to has admitted
whatever the transport's Windows identity turns out to be.

**The message types.** `allow_types` and `deny_types` name them, so bulk load
and the transaction manager requests are decisions.

**The stored procedures.** `allow_procedures` and `deny_procedures` by name —
`xp_cmdshell` being the obvious one, with `sp_OACreate` and the rest of the OLE
automation procedures behind it.

**The statement shape, in both places it can appear.** The shape policy is
applied to a `SQLBATCH` and to **the SQL inside an `sp_executesql` call**, read
with T-SQL's own lexical rules: bracketed identifiers, nested `/* */` comments,
`N''` literals. `read_only` refuses every writing shape in one line.

**The bounds**: statements, statement size, message size, sessions overall and
per client, and the idle and total session duration.

### The estate's own authorisation policy

Above this relay's own policy sits the `authorization` section, which is not
about SQL Server: it is the one place that says which identity may reach what, in the
same words for every protocol. This relay asks it at the Login7 packet, which is the first place
an account appears, and before it is forwarded, so an account no rule covers
never reaches the server.

The `target` is the upstream **pool** name -- the server is chosen by balancer
after this point -- and the `user` is the account the packet named. Neither a
principal nor groups reaches a rule here: SQL Server gives the relay a name and nothing
it could verify about who holds it, so a rule about a team is a rule listing
accounts, and what may be reached *inside* the server is the `tds` policy's own business,
which is the thing that can say what a database or a statement means.

**What the name is worth here.** The policy is asked before the Login7 packet is forwarded, which is the
point: it is what keeps a refused session off the server entirely. But it means the account
is the one the client's login *asserts*, and the server proves it afterwards. So the
policy narrows what the server would have allowed and never widens it: a deny rule is
exact, because refusing a claimed name refuses at least everyone who could have
proved it, while an allow rule keyed on the name is a filter on a claim that
still has to be proven. It is not an authenticated grant. A rule that has to
hold whatever a client asserts belongs in `targets` and `networks`, which nobody
can choose for themselves.

A refusal is the reason `authorization` -- the event `tds_authorization`, the
counter `xproxy_refusals_total{kind="tds",reason="authorization"}` -- so it reads
like every other refusal this relay makes. Either shadow switch, this listener's
`monitor_only` or the section's own `shadow: true`, records what it would have
refused with the rule that decided and lets the session through; a refusal that
is not enforced is counted only as a would-be refusal, never as one made.

## What it does not do

- **It is not a SQL firewall.** The shape policy names kinds of statement, not
  their effect on your schema.
- **It does not implement MARS.** Multiple Active Result Sets multiplexes
  several logical sessions onto one connection; the `PRELOGIN` option for it is a
  decision rather than something the relay demultiplexes.
- **It does not authenticate integrated logins.** The SSPI exchange is forwarded
  or refused. It is not verified here, and there is no domain membership in this
  process to verify it with.
- **It does not rewrite SQL.** A refused shape is refused.
- **It does not read `RPC` parameters generally.** `sp_executesql`'s statement
  parameter is read because it holds SQL; the rest are data.
- **It does not decrypt an established session's TLS to look inside.** TLS is
  terminated at the listener when the listener is the TLS endpoint, and the
  policy applies to what it then reads.

## Standards

| Document | What it covers |
|----------|----------------|
| MS-TDS (Microsoft Open Specifications) | The Tabular Data Stream protocol: the packet header, `PRELOGIN`, `LOGIN7`, `SQLBATCH`, `RPC`, and the wrapped TLS handshake |
| MS-SSTDS | The TDS variant for SQL Server Azure |
| RFC 4178 | SPNEGO, the negotiation SSPI uses |
| RFC 4559 | SPNEGO-based Kerberos and NTLM HTTP authentication, for the token formats |
| RFC 8446 | TLS 1.3, once `PRELOGIN` has decided there will be TLS |

## See also

- The settings: [docs/CONFIG.md `## tds`](../CONFIG.md#tds)
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- A worked configuration: [`examples/databases/tds.yaml`](../../examples/databases/tds.yaml)
- The other database protocols: [postgres](postgres.md), [mysql](mysql.md),
  [redis](redis.md)
