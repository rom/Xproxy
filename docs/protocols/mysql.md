# MySQL and MariaDB — the client/server protocol

`kind: mysql`, served by **xrelay**, TCP port **3306**.

The protocol's defining feature, from a proxy's point of view, is that almost
everything about it is **negotiated in the first two packets** — and what the
server offers there decides what the client is even able to ask for.

## On the wire

Every packet is a three-octet length, a one-octet sequence number, and a
payload. Sequence numbers restart at each command, which is how a proxy knows
where a command boundary is.

The handshake:

1. The server speaks first: **`HandshakeV10`** — a version string, a connection
   id, an auth-plugin name, a scramble, and a 32-bit **capability flags** word.
2. The client answers **`HandshakeResponse41`** with the capabilities it accepts,
   the username, the auth response, optionally a database, and optionally
   connection attributes.
3. Authentication may then continue: `AuthSwitchRequest` if the server wants a
   different plugin, and the plugin's own exchange.

TLS is inside that: if the server advertised `CLIENT_SSL` and the client sets
it, the client sends a short response packet and then starts a TLS handshake
*on the same connection* before sending the real one.

Then commands, each a one-octet type:

| Command | What it does |
|---------|-------------|
| `COM_QUERY` | SQL as text |
| `COM_STMT_PREPARE`, `COM_STMT_EXECUTE`, `COM_STMT_CLOSE` | Prepared statements |
| `COM_INIT_DB` | Change the default database |
| `COM_CHANGE_USER` | **Re-authenticate as somebody else on the same connection** |
| `COM_FIELD_LIST`, `COM_STATISTICS`, `COM_PING`, `COM_QUIT` | Housekeeping |
| `COM_BINLOG_DUMP`, `COM_REGISTER_SLAVE` | Replication: stream the whole write history |

Two features deserve special attention. `LOAD DATA LOCAL INFILE` makes the
*server* ask the *client* for a file, which means a malicious or compromised
server can read files off the client's host. And `LOAD DATA INFILE` reads from
the server's filesystem.

## What the protocol gives you

The authentication plugins: `caching_sha2_password` (the modern default, a real
challenge-response), `mysql_native_password` (SHA-1 based, legacy),
`sha256_password`, and `mysql_clear_password` — which is exactly what it sounds
like and exists for PAM and LDAP back ends.

TLS works. The weakness is the same shape as PostgreSQL's: it is opt-in from a
capability flag, and a client library whose default is "use TLS if offered" will
quietly not use it when it is not offered.

`COM_CHANGE_USER` is the interesting one for anything holding a policy: a
connection that authenticated as one user can become another user mid-stream,
and a proxy that decided the identity once at the handshake would be holding a
stale answer for the rest of the session.

## What this listener decides

**The capability bits a client may even see offered.** `deny_capabilities`
rewrites the server's greeting, which is the only place in this listener where a
peer's message is modified — and it is the right place, because a capability the
client never sees is a capability it cannot use. `CLIENT_LOCAL_FILES` is the
one that matters: strip it and the server cannot ask the client for a file,
whatever the server later decides to do.

**Whether the connection may be unencrypted**, with `require_tls`.

**The authentication plugins.** `allow_auth` names them and `allow_weak_auth` is
the explicit line for `mysql_clear_password` and the SHA-1 plugin.

**The identity — and again on `COM_CHANGE_USER`.** `allow_users` and
`allow_databases` are re-checked when the connection changes user, because that
is a new identity on an old socket.

**The commands.** `allow_commands` and `deny_commands` name them by protocol
name, so `COM_BINLOG_DUMP` is a decision an operator makes rather than something
a connection can reach because it was not thought of.

**The statement shape**, read with MySQL's own lexical rules — backtick
identifiers, `#` comments, and the **executable comment** syntax
`/*! ... */` and `/*M! ... */`, which MySQL and MariaDB run as SQL and a naive
comment stripper discards. `read_only` refuses every writing shape in one line.

**`LOAD DATA`, in both forms.** `allow_load` decides whether it may happen at
all, separately from the statement shapes, because the local form reads the
client's disk and the server form reads the server's.

**`allow_programs`**, for the MariaDB and MySQL syntaxes that shell out.

**The bounds**: statements, statement size, packet size, sessions overall and
per client, and the session's idle and total duration.

## What it does not do

- **It is not a SQL firewall**, for the same reasons as the postgres kind: a
  shape policy says what kind of statement may cross, not whether it is safe.
- **It does not rewrite SQL.** The greeting's capability flags are the one thing
  rewritten, and that is documented as such rather than being a general licence.
- **It does not compute authentication.** The plugin exchange is forwarded; the
  server decides whether the credential is right.
- **It does not read prepared-statement parameter values as SQL.** The shape
  comes from the `COM_STMT_PREPARE` text, which is where the SQL is.
- **It does not handle the compressed protocol's payloads as SQL.** Compression
  is a capability, and where it is not stripped the relay decides the commands it
  can read.

## Standards

| Document | What it covers |
|----------|----------------|
| MySQL Internals Manual, *Client/Server Protocol* | The packet framing, `HandshakeV10`, the capability flags, the command set |
| MariaDB Server documentation, *Client/Server Protocol* | The MariaDB extensions and capability bits |
| RFC 8446 | TLS 1.3, once the capability negotiation has decided there will be TLS |

Neither vendor's protocol is an IETF or ISO standard; both are documented by the
project, and the documentation is what this listener is written against.

## See also

- The settings: [docs/CONFIG.md `## mysql`](../CONFIG.md#mysql)
- A worked configuration: [`examples/databases/mysql.yaml`](../../examples/databases/mysql.yaml)
- The other database protocols: [postgres](postgres.md), [tds](tds.md),
  [redis](redis.md)
