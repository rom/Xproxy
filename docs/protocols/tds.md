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
- A worked configuration: [`examples/databases/tds.yaml`](../../examples/databases/tds.yaml)
- The other database protocols: [postgres](postgres.md), [mysql](mysql.md),
  [redis](redis.md)
