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
client never sees is a capability it cannot use. `CLIENT_LOCAL_FILES` is the one
that matters: strip it and the server cannot ask the client for a file, whatever
the server later decides to do.

Stripping a bit from the greeting is not the whole job, though, and this is the
detail that makes the capability policy real rather than decorative:
`COM_SET_OPTION` turns multi-statement support back **on** afterwards. So a
denied capability is enforced there as well as in the greeting — otherwise a
client that never saw `CLIENT_MULTI_STATEMENTS` offered could simply ask for it
one command later.

**Whether the connection may be unencrypted**, with `require_tls`.

**The authentication plugins.** `allow_auth` names them, and `allow_weak_auth` is
the explicit line for the two whose credential an observer can *reuse*:
`mysql_clear_password` (the password itself) and `mysql_old_password` (the
pre-4.1 scramble). `mysql_native_password` is deliberately not in that set —
it is SHA-1 based and dated, but its challenge-response discloses no reusable
secret, and calling it weak would push deployments towards turning the flag on
for the wrong reason.

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

### The estate's own authorisation policy

Above this relay's own policy sits the `authorization` section, which is not
about MySQL: it is the one place that says which identity may reach what, in the
same words for every protocol. This relay asks it at the login packet, which is the first place an
account appears, and before that packet is forwarded, so an account no rule
covers never reaches the server.

The `target` is the upstream **pool** name -- the server is chosen by balancer
after this point -- and the `user` is the account the packet named. Neither a
principal nor groups reaches a rule here: MySQL gives the relay a name and nothing
it could verify about who holds it, so a rule about a team is a rule listing
accounts, and what may be reached *inside* the server is the `mysql` policy's own business,
which is the thing that can say what a database or a statement means.

**What the name is worth here.** The policy is asked before the login packet is forwarded, which is the
point: it is what keeps a refused session off the server entirely. But it means the account
is the one the client's login *asserts*, and the server proves it afterwards. So the
policy narrows what the server would have allowed and never widens it: a deny rule is
exact, because refusing a claimed name refuses at least everyone who could have
proved it, while an allow rule keyed on the name is a filter on a claim that
still has to be proven. It is not an authenticated grant. A rule that has to
hold whatever a client asserts belongs in `targets` and `networks`, which nobody
can choose for themselves.

A refusal is the reason `authorization` -- the event `mysql_authorization`, the
counter `xproxy_refusals_total{kind="mysql",reason="authorization"}` -- so it reads
like every other refusal this relay makes. Either shadow switch, this listener's
`monitor_only` or the section's own `shadow: true`, records what it would have
refused with the rule that decided and lets the session through; a refusal that
is not enforced is counted only as a would-be refusal, never as one made.

**A server that is not there.** `deception` answers as a fabricated MySQL: on a
real listener, where a refusal would otherwise be written; or as a whole listener
with nothing behind it.

The reconnaissance on this protocol is the attack's first half and it is made
entirely of legitimate statements: the version, `SHOW DATABASES`, `@@datadir`,
`@@secure_file_priv`, `SHOW GRANTS`, `mysql.user`. Their answers decide which of
four things the next statement is -- `INTO OUTFILE`, `LOAD_FILE`,
`LOAD DATA LOCAL INFILE`, or `CREATE FUNCTION ... SONAME`. A refusal at the
greeting ends that; answering it says which one they were reaching for.

What takes care is that the answers agree with each other, because that is what a
fingerprinting tool checks: `@@secure_file_priv` NULL and the file statements
refused 1290, `SHOW GRANTS` without `FILE` and `mysql.user` refused 1142, and no
`caching_sha2_password` on a MariaDB version. Three things the fabrication will
not do: ask the client for a file, sleep, or invent rows. See
[docs/DECEPTION.md](../DECEPTION.md#a-mysql-that-is-not-there).

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
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- A worked configuration: [`examples/databases/mysql.yaml`](../../examples/databases/mysql.yaml)
- The other database protocols: [postgres](postgres.md), [tds](tds.md),
  [redis](redis.md)
