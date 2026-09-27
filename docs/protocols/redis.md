# Redis — RESP

`kind: redis`, served by **xrelay**, TCP port **6379**.

The Redis serialization protocol is the simplest protocol in this set, and the
data store behind it is usually the least protected thing in an estate: a cache
that holds session tokens, rate-limit counters, queue payloads and often a great
deal more than anybody intended, reachable with a five-octet command.

## On the wire

RESP is prefix-typed, line-oriented and human-readable.

**RESP2**: `+` a simple string, `-` an error, `:` an integer, `$` a bulk string
with a length, `*` an array with a count. A command is an array of bulk strings:

```
*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$3\r\nabc\r\n
```

**RESP3** (Redis 6+) adds types the client can distinguish without knowing the
command: `%` maps, `~` sets, `#` booleans, `,` doubles, `(` big numbers, `_`
null, `=` verbatim strings, `>` push messages. A connection opts in with
`HELLO 3`.

There is also an **inline** form: a bare line of space-separated words, meant
for `telnet` debugging, accepted by the server, and a completely different
parser to reach the same commands.

The thing a policy needs, and the thing that makes this protocol harder than it
looks, is **where the keys are**. There is no general rule. `GET` takes one key
first. `MSET` alternates keys and values. `ZADD` takes one key and then scores.
`GEORADIUS` has optional `STORE` and `STOREDIST` arguments that each name a key.
`EVAL` takes a script, a count, and then that many keys. `SORT` has a `STORE`
option. `XREAD` has `STREAMS` followed by keys and then ids. So a key policy
needs a table of each command's key positions, and has to know which commands'
key positions depend on an argument it cannot rely on.

## What the protocol gives you

Since Redis 6, an ACL system: users with password hashes, command patterns, key
patterns and channel patterns, configured with `ACL SETUSER`. It is a real
model.

Before Redis 6 there was `requirepass`: one password, shared, sent in the clear
with `AUTH`, and no user at all. A great many deployments are still there — and
a great many more are on a network where `bind 127.0.0.1` was never changed and
nothing needed a password, until the network changed.

TLS arrived in Redis 6 too. Before that, everything was in the clear.

The commands themselves include `FLUSHALL`, `CONFIG SET` (which can change the
persistence file's path and name), `DEBUG`, `SCRIPT`/`EVAL` (arbitrary Lua),
`SLAVEOF`/`REPLICAOF` (make this instance a replica of somewhere else), and
`MODULE LOAD`. Several of those turn a cache into remote code execution.

## What this listener decides

**Whether the connection may be unencrypted**, with `require_tls`.

**Whether a command may arrive before the connection has authenticated**, with
`require_auth` — and the answer is taken from the **server's reply** to `AUTH`
or `HELLO`, not from the client having sent one. A client can send anything; the
server's `+OK` is what makes it a login.

**Which ACL user may be named**, so a listener in front of a shared instance can
be the reason a service uses its own user rather than the default one.

**The commands and subcommands.** `allow_commands` and `deny_commands` by name,
and `allow_subcommands`/`deny_subcommands` because `CONFIG GET` and `CONFIG SET`
are not the same permission, nor are `ACL LIST` and `ACL SETUSER`, nor `CLIENT
LIST` and `CLIENT KILL`.

**The keys, by prefix.** `allow_key_prefixes` and `deny_key_prefixes`, applied
using the command table's key positions — so `MSET`'s alternating keys are all
checked, `EVAL`'s declared keys are all checked, and a `GEORADIUS ... STORE`
destination is checked as a key rather than read as a value.

The commands whose key positions **depend on an option** are refused rather than
guessed at. That is the important decision in this kind: a prefix policy applied
to the wrong argument — a `STORE` option's value read as a value, or a Lua
script's text read as a key — is a policy that passes exactly what it was meant
to stop, and passes it silently.

**The numbered databases**, with `allow_databases`, because `SELECT` moves a
connection to a different keyspace and a prefix policy in one says nothing about
another.

**`read_only`**, one line refusing every writing command, which no rule can
override.

**`allow_inline`**, because the inline form is a second parser reaching the same
commands, and a listener that does not need it should not have it.

**The bounds**: message size, bulk string size, elements in an array, commands
per session, sessions overall and per client, and the idle and total duration.

### The imported lists, and the estate's authorisation policy

Two questions are asked here, at two different moments, and the second is the
interesting one on this kind.

**On the connection**, after this kind's own client list and before the server is
dialled, there is no name: Redis begins with the client's first command, so what is
known is the address, the listener, the pool and the hour.

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, with the `connect` action. A rule naming
  `users` matches nobody at this point, so this is where `networks` belongs.

**And again when the server accepts a credential**, with the `session` action. The
relay already reads the server's answer to an AUTH or HELLO, because "has this
connection authenticated" cannot be answered from the client's side -- a relay that
took the attempt for the answer would treat a wrong password as a login, which is
what `require_auth` exists to prevent. That same answer *proves the name*, so:

- an **allow** rule keyed on `users` here is an authenticated grant, not a filter
  on a claim. That is not true of the `postgres`, `mysql` and `tds` relays, where
  the policy is asked before the server has spoken, and it is worth knowing which
  kind you are writing a rule on.
- the refusal lands later. The server has seen the credential, because that is
  what proved the name, so a refusal here does not keep the session off the server
  the way `postgres`'s does. What it keeps off is every command after it: the
  acceptance is never forwarded and the connection ends, so the client is never
  told it has a login it may not use.

Two asks need two actions, or the second would be answered by whatever rule let
the connection in:

```yaml
authorization:
  rules:
    - {name: staff, allow: true, users: [bob], actions: [session]}
    - {name: floor, allow: true, networks: ["10.0.0.0/8"], actions: [connect]}
```

A listener whose clients never authenticate never reaches the second question, so
there the `connect` rule is the whole policy. Which commands and which keys a
session may touch stays with this listener's own policy above.
The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## What it does not do

- **It does not read Lua.** `EVAL` is allowed or refused as a command; the
  script's own key access is not analysed, because analysing a Lua program from
  outside is not something to be confident about. The declared keys are checked;
  a script that reaches others is why `EVAL` is a decision.
- **It does not replace the ACL.** It holds a second boundary in a reviewed file
  in front of one configured in the instance.
- **It does not track keys across a pipeline for consistency.** Each command is
  decided on its own, which is what a pipeline is.
- **It does not read cluster redirections.** A `MOVED` or `ASK` reply sends the
  client somewhere else, and that destination needs its own listener.
- **It does not proxy pub/sub channels by pattern.** Channels are decided as
  command arguments; the channel patterns of the ACL model are the instance's
  own.
- **It does not authenticate.** `AUTH` is forwarded and the server decides.

## Standards

| Document | What it covers |
|----------|----------------|
| Redis documentation, *RESP protocol spec* | RESP2 and RESP3: the type prefixes, the command form, the inline form |
| Redis documentation, *ACL* | The user, command, key and channel pattern model |
| Redis documentation, *Command reference* (`key_specs`) | Where each command keeps its keys |
| RFC 8446 | TLS 1.3, for the transport |

RESP is documented by the Redis project rather than standardised, and the
project's documentation is what this listener is written against.

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `## redis`](../CONFIG.md#redis)
- A worked configuration: [`examples/databases/redis.yaml`](../../examples/databases/redis.yaml)
- The other database protocols: [postgres](postgres.md), [mysql](mysql.md),
  [tds](tds.md)
