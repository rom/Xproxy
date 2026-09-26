# LDAP — the directory

`kind: ldap`, served by **xrelay**, TCP port **389** (with StartTLS) and **636**
(LDAPS).

The directory is where an estate keeps who everybody is, which groups they are
in, and often what they are allowed to do. An application that can read it can
enumerate the organisation; an application that can write it can grant itself
anything.

## On the wire

BER-encoded ASN.1, and — unusually for a protocol of its age — genuinely
asynchronous: a client may have several operations outstanding, each tagged with
a **message ID**, and the server may interleave their responses.

| Operation | What it does |
|-----------|-------------|
| `bindRequest` | Authenticate. Simple (a DN and a password) or SASL (a mechanism and credentials) |
| `searchRequest` | The one that matters: a **base DN**, a **scope** (base, one level, subtree), a **filter**, and the **attributes** wanted |
| `modifyRequest`, `addRequest`, `delRequest`, `modDNRequest` | Write |
| `compareRequest` | Ask whether an attribute has a value, without reading it |
| `abandonRequest`, `unbindRequest` | Housekeeping |
| `extendedRequest` | Anything else, named by OID — StartTLS, password modify, whoami |

A **filter** is a tree: `(&(objectClass=user)(|(cn=a*)(mail=*@x)))`. It nests to
arbitrary depth and can hold arbitrarily many terms, and `(cn=*a*)` — a leading
wildcard — is a full index scan on most servers.

A **DN** is relative distinguished names separated by commas, and comparing two
DNs correctly means comparing them per RDN with the attribute type's own
matching rule, not as strings: `CN=a, OU=b` and `cn=a,ou=b` are the same entry.

**Controls** ride on any operation, again named by OID: paged results,
server-side sorting, the virtual list view, and — the one worth knowing about —
proxied authorisation, which asks the server to perform the operation as
somebody else.

## What the protocol gives you

A bind, and what it is worth depends entirely on which one.

- **Simple bind** is a DN and a password in the clear. On port 389 with no
  StartTLS, that is a directory credential on the wire.
- **SASL** gives you EXTERNAL (the TLS client certificate), GSSAPI/Kerberos,
  DIGEST-MD5 (deprecated) and others. EXTERNAL and GSSAPI are the ones worth
  having.
- **Anonymous bind** is a bind with an empty DN, and a great many directories
  still allow it to read more than anybody intended.

The server's own access control is real and per-attribute on the better
implementations. It is also administered inside the directory, by the directory
team, and an application's effective reach is usually the union of what several
generations of ACL intended.

## What this listener decides

**Whether the credential may cross in the clear.** `require_tls` and
`tls_mode`, and StartTLS handled as the protocol defines it — with the
distinction that matters: a StartTLS that the relay refuses must not leave the
client thinking the connection was upgraded.

**The bind methods and mechanisms.** `methods` names simple, SASL or anonymous;
`sasl_mechanisms` names which of the SASL mechanisms may be chosen. A listener
that admits only EXTERNAL has said a password never crosses it.

**The bound identity**, which is what the rules select on: a rule for the
application's service account, another for the people's accounts, another for
whatever binds anonymously.

**The naming contexts and subtrees.** `base_dns` says which parts of the tree
this listener reaches at all, compared per RDN rather than as strings, so a DN
spelled with different whitespace or case is still the same subtree.

**The scope**, because `subtree` from the root and `base` on one entry are
different permissions wearing the same operation.

**The attributes, in both directions.** `deny_attributes` names what may not be
requested — and `on_denied_attribute` decides whether the *request* is refused
or the attribute is **stripped from the entries coming back**, which is the
useful setting: an application that asks for the whole entry and does not need
`userPassword` or `unicodePwd` keeps working, without those ever reaching it.

**`read_only`**, one line that refuses `modify`, `add`, `del` and `modDN` for
every client, which no rule can override.

**The filter's shape.** `max_filter_terms`, `max_filter_depth` and
`allow_leading_wildcard`: a filter is a program the directory runs, and a
thousand-term filter or `(cn=*a*)` across a million entries is a denial of
service written as a search. This is the one place a shape bound is the right
tool, because the *semantics* of an arbitrary filter cannot be decided from
outside.

**The extended operations and the controls.** `extended_operations` names which
OIDs may be sent; `deny_controls` names which may ride along — proxied
authorisation belongs on that list unless something genuinely needs it.

**The bounds**: entries returned, outstanding operations, message size, request
rate, and a separate `bind_rate_limit`, because a password-guessing run and a
busy application look completely different in every respect except that both
send LDAP.

### The estate's own authorisation policy

Above this relay's own rules sits the `authorization` section, which is not about
LDAP: it is the one place that says which identity may reach what, in the same
words for every protocol.

This relay asks it **for a bind, and for nothing else**, before the bind is
forwarded. A bind is the only request that names an identity, and refusing one
before it travels matters more here than almost anywhere: a bind that reaches a
directory is a password guess against it, and one that does not is not.

What that leaves out, said plainly because an operator who assumed otherwise
would be wrong: **an anonymous session names nobody**, so no rule about people can
reach it, and what an already-bound session may read or write is the `ldap`
policy's own business -- it is the thing that can say what a search base or an
attribute means. `allow_anonymous` and this listener's `rules` are where those two
decisions belong.

**What the name is worth here.** The DN is the one the bind asserts, and the
directory proves it afterwards -- this relay deliberately waits for the
directory's answer before adopting an identity, because believing the request
would let anyone be anybody by binding with the wrong password. So the policy
narrows what the directory would have allowed and never widens it: a deny rule is
exact, because refusing a claimed DN refuses at least everyone who could have
proved it, while an allow rule keyed on the DN is a filter on a claim the
directory still has to verify.

The `target` is the upstream **pool** name; the directory is chosen by balancer
after this point. A refusal is the reason `authorization`, answered in the
directory's own vocabulary like every other refusal this relay makes, and counted
as `xproxy_refusals_total{kind="ldap",reason="authorization"}`. Either shadow
switch, this listener's `monitor_only` or the section's own `shadow: true`,
records what it would have refused with the rule that decided and forwards the
bind.

## What it does not do

- **It does not replace the directory's access control.** It holds a second
  boundary, in a file that is reviewed with the rest of the estate, in front of
  one administered elsewhere.
- **It does not authenticate.** The bind is forwarded and the directory decides.
  This listener decides which identities may be *tried*, by which method, and
  what each may then do.
- **It does not rewrite a filter.** A filter past the shape bounds is refused,
  not simplified: a search that silently returned a different result set than it
  asked for is worse than an error.
- **It does not understand your schema.** The attribute lists are written against
  the attribute names the directory uses; a relay that inferred sensitivity from
  a name would be guessing about the estate's own data.
- **It does not do referrals.** A referral the server returns is passed to the
  client, which will then connect wherever it points — outside this listener.
  That destination needs its own path.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 4510 | The LDAP technical specification road map |
| RFC 4511 | The protocol: the operations, the message envelope, the asynchronous model |
| RFC 4512 | The directory information models: DNs, schema, the root DSE |
| RFC 4513 | Authentication methods and security mechanisms, including StartTLS |
| RFC 4514 | The string representation of distinguished names |
| RFC 4515 | The string representation of search filters |
| RFC 4517 | Syntaxes and matching rules — how two attribute values compare |
| RFC 4519 | The schema for user applications: the standard attribute types |
| RFC 4370 | Proxied authorisation control |
| RFC 2830 / RFC 4513 §3 | StartTLS |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].ldap`](../CONFIG.md#serverlistenersldap-kind-ldap)
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- A worked configuration: [`examples/directory/ldap.yaml`](../../examples/directory/ldap.yaml)
- LDAP as an *identity source* for HTTP listeners is a filter, not this kind —
  see the `ldap` filter in [docs/CONFIG.md](../CONFIG.md)
