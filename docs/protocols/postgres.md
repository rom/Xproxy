# PostgreSQL — the frontend/backend protocol

`kind: postgres`, served by **xrelay**, TCP port **5432**.

A well-designed protocol with one structural oddity that decides how a proxy in
front of it has to work: **TLS is not negotiated in TLS's terms**. A client asks
for encryption with a cleartext message, and the server answers with a single
octet.

## On the wire

Every message after the startup is a type octet, a 32-bit length that includes
itself, and a body. Before that, three special messages have no type octet at
all, only a length and a magic version number:

| Startup message | What it asks |
|-----------------|-------------|
| `SSLRequest` (80877103) | Please start TLS. The server answers with `S` or `N` — one octet, in the clear |
| `GSSENCRequest` (80877104) | The same for GSSAPI encryption |
| `CancelRequest` (80877102) | Cancel a running query, on a **separate connection**, identified by a process id and a secret key |
| `StartupMessage` | The real one: parameter pairs including `user`, `database`, `application_name` and `replication` |

Then authentication, which the server chooses:

`AuthenticationOk`, `CleartextPassword`, `MD5Password`, `SASL` (SCRAM-SHA-256),
`GSS`, `SSPI`. Which one a connection gets is `pg_hba.conf`'s decision on the
server.

Then the two query protocols, which is the part a policy is written about:

- **Simple query**: one `Query` message holding SQL as text. It may contain
  several statements separated by semicolons, in one message.
- **Extended query**: `Parse` (name a statement and its SQL), `Bind` (attach
  parameter values), `Describe`, `Execute`, `Sync`. Parameters are sent
  separately from the SQL, which is why it is the one that is actually safe
  against injection.

`COPY` has its own sub-protocol, and `COPY FROM PROGRAM` runs a shell command on
the server. `FunctionCall` is the fast-path interface — calling a function by
OID, bypassing SQL entirely.

## What the protocol gives you

Genuinely good authentication, if it is configured: **SCRAM-SHA-256** (RFC
5802/7677) is a real challenge-response with channel binding available. MD5 is
the legacy option and should not be in use. `CleartextPassword` is what it says.

TLS works, and the weak point is the negotiation: an `SSLRequest` answered with
`N` leaves the client to decide whether to continue in the clear, and the
libpq default `sslmode=prefer` continues. So a client whose connection string
was never reviewed will happily send a password unencrypted if something
upstream says `N`.

The server's own authorisation is roles, grants and row-level security, and it
is good. It is also inside the database, granted by whoever has the rights, and
usually accumulated over years.

## What this listener decides

**Whether the connection may be unencrypted at all.** `require_tls` means an
`SSLRequest` is required and the relay answers it — so a client that would have
continued after an `N` never gets one.

**Which authentication methods may cross.** `allow_auth` names them and
`allow_weak_auth` is the explicit line an operator writes to permit MD5 or
cleartext, so a downgrade is a configured decision rather than a server's
choice.

**The identity, from the startup parameters**: `allow_users`,
`allow_databases`, and `allow_applications` — the last more useful than it
looks, because `application_name` is how an estate tells its own services apart
in `pg_stat_activity`, and a rule keyed on it is a rule per service.

**The statement's *shape*.** This is the part worth explaining. A relay cannot
decide whether a query is safe — that needs the schema, the row-level policy and
the business rules. What it can decide is what *kind* of statement this is:
`select`, `insert`, `update`, `delete`, `create`, `drop`, `alter`, `grant`,
`truncate`, `copy`, `call`, `set`, and so on. So `read_only` becomes one line
that refuses every writing shape, and a reporting listener can be `select` and
`set` and nothing else.

The shape is read from the SQL text with the protocol's own lexical rules —
dollar quoting, standard and nested comments, `E''` escapes — because a shape
read by a simpler lexer is a shape an attacker chooses.

A simple-query message holding several statements is decided **statement by
statement**, since otherwise one allowed shape at the front would carry
everything behind it.

**`COPY`, replication, the fast path and cancels, each on their own.**
`allow_copy` because `COPY FROM PROGRAM` is command execution;
`allow_replication` because a replication connection can stream the whole
database out; `allow_function_call` because the fast-path interface reaches
functions without any SQL for a shape policy to read; and `allow_cancel`
because a cancel arrives on a *separate connection* carrying only a process id
and a secret, and is therefore the one message with no session to attribute.

**The bounds**: statements per session, statement size, message size, sessions
overall and per client, and the session's idle and total duration.

## What it does not do

- **It is not a SQL firewall.** A shape policy says what kind of statement may
  cross. It does not understand your schema, cannot tell a legitimate `UPDATE`
  from a destructive one, and is not a substitute for roles and grants.
- **It does not rewrite SQL.** A statement whose shape is refused is refused; the
  relay does not strip a clause or add a `LIMIT`, because a query that returned
  something other than what was asked is a fault nobody can reason about.
- **It does not inspect `COPY` data or large-object traffic.** Those are decided
  as a whole, allowed or not.
- **It does not authenticate.** The exchange is forwarded and the server's
  `pg_hba.conf` decides. This listener decides which methods and which
  identities may be tried.
- **It does not read the extended protocol's parameter values as SQL.** They are
  parameters; that is the point of the extended protocol.

## Standards

| Document | What it covers |
|----------|----------------|
| PostgreSQL documentation, *Frontend/Backend Protocol* | The message formats, the startup sequence, the two query protocols, `COPY` |
| RFC 5802 | SCRAM, the family SCRAM-SHA-256 belongs to |
| RFC 7677 | SCRAM-SHA-256 and SCRAM-SHA-256-PLUS |
| RFC 5929 | Channel bindings for TLS, which SCRAM-PLUS uses |
| RFC 8446 | TLS 1.3, once the negotiation has decided there will be TLS |

## See also

- The settings: [docs/CONFIG.md `## postgres`](../CONFIG.md#postgres)
- A worked configuration: [`examples/databases/postgres.yaml`](../../examples/databases/postgres.yaml)
- The other database protocols: [mysql](mysql.md), [tds](tds.md), [redis](redis.md)
