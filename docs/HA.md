# High availability

A proxy is a single point of failure by construction: every request goes
through it. Making that acceptable means two things, and they are not the
same thing.

**Redundancy** is having a second proxy. **Failover** is the second one
taking the traffic when the first stops being fit to carry it. Most estates
get the first right and the second wrong, because the second is the one
where the interesting question lives: *what does "not fit" mean?*

This document is about that question, and about the mechanisms this proxy
gives you to answer it. It is not a keepalived tutorial; it is what a
keepalived configuration has to know about xproxy to be correct.

## What this proxy does and does not do

It does **not** elect a leader, hold a virtual address, or move one. There
is no built-in VRRP, no Raft, no lease. That is deliberate: moving an
address is the job of something that sits below a proxy in the stack
(keepalived, the platform's load balancer, BGP with a route health
injector, a cloud provider's target group), those tools are mature, and an
estate already runs one of them for everything else.

What it does provide is the three things such a tool needs:

| Need | Mechanism |
|------|-----------|
| A verdict it can act on | `xproxyctl ready` (exit code) and `GET /v1/ready` (HTTP status) |
| A way for an operator to take a node out *before* touching it | `xproxyctl ready -step-down "patching"` |
| State that does not have to be rebuilt on the surviving node | the `cluster` section: shared rate limits, bans and events |

And the deployment shapes below, which are about where the state lives.

## The readiness verdict

`xproxyctl ready` exits 0 when this node should be carrying traffic, 1 when
it should not, and **2 when the question could not be asked**. The third
case matters: a check script that treats "I could not reach the management
socket" the same as "the node says no" will move a virtual address because
a socket's permissions changed during an upgrade. Keep them apart.

`GET /v1/ready` answers the same question as an HTTP status — 200 or 503 —
with the reasons in a JSON body, for a load balancer's own health check or
anything that speaks HTTP rather than exit codes.

Four things go into the verdict, and only one of them counts by default:

**An operator stepped the node down.** This always counts. It is the
mechanism to use before any planned work:

```sh
xproxyctl ready -step-down "kernel update"   # the address moves now
# ... do the work, restart, verify ...
xproxyctl ready -step-up
```

Doing it this way means the address moves while the node is still healthy
and can finish the requests it has, instead of moving because the node
died mid-upgrade. The step-down is **not persisted**: a node that has
restarted serves again. That is the safe default for a proxy — a process
that has just started has no idea what an operator decided before it — but
it means a step-down does not survive `systemctl restart`. For a node that
must stay out across restarts, take it out of the balancer's own
configuration, or shut the service down rather than stepping it down.

**No listener is bound.** Always counts, and only happens while starting or
after every listener failed to bind.

**A pool has endpoints configured and none healthy** (`-require-upstreams`).
This is opt-in because whether it should move an address is a judgement
about *your* topology. If both proxies reach the same application servers
over the same network, an upstream outage looks identical from both nodes,
and failing over gains nothing while adding a flap. If the two nodes sit in
different segments, or reach different replicas, it gains everything. Decide
which you are, then set the flag or do not.

**A hardening mechanism did not apply** (`-require-undegraded`). Also
opt-in, for the same reason with a different trade-off: a proxy that could
not install its seccomp filter is still a working proxy, so refusing
traffic over it trades availability for a defence in depth you were not
relying on for correctness. Set it when policy says an unsandboxed node
must not serve; leave it off otherwise, and alert on the state instead.

What is deliberately **not** a reason is load. A busy node that stands
down hands its peer the same traffic and twice the connection churn. Load
is what the balancer in front is for.

## keepalived

The check script is one command, and the exit codes line up with what
keepalived expects:

```
vrrp_script chk_xproxy {
    script  "/usr/bin/xproxyctl ready"
    interval 2
    timeout  2
    fall     2      # two failures before giving up the address
    rise     3      # three successes before taking it back
    weight  -20
}

vrrp_instance VI_1 {
    state           BACKUP
    interface       eth0
    virtual_router_id 51
    priority        100        # 101 on the preferred node
    advert_int      1
    nopreempt                  # do not take the address back on its own
    authentication { auth_type PASS; auth_pass ... }
    virtual_ipaddress { 192.0.2.10/24 }
    track_script { chk_xproxy }
}
```

Four details that are not obvious:

- **`weight -20`, not `weight 0`.** A weighted script lowers the priority
  instead of surrendering the address outright, so a node whose peer is
  also failing keeps serving rather than leaving the address nowhere.
- **`nopreempt` with unequal priorities.** Without it a node that recovers
  takes the address back immediately, which turns one outage into two.
  Take it back deliberately, with a step-down on the other node.
- **The script runs as a user that can open the management socket.** By
  default that is the socket's group; put keepalived's user in it rather
  than widening the socket's mode, and remember the script runs with
  keepalived's environment, not an operator's, so pass `-socket` explicitly
  if the path is not the default.
- **`fall`/`rise` asymmetry is the point.** Give up an address faster than
  you take one back.

A `notify` script is where to hook anything that has to happen on
transition — a log line, a metric, a `ready -step-up` on the node that just
became MASTER.

## Two nodes, one address: what the surviving node does not know

Failing an address over moves the *traffic*. It does not move the state the
refused traffic built up, and that is where a failover quietly weakens the
proxy:

| State | Survives a failover? | How |
|-------|---------------------|-----|
| Rate limit buckets | Yes, with `cluster.share_rate_limits` | peers report consumption; each node refills at the rate minus its peers' (`docs/AMR.md`, AMR-021) |
| Bans | Yes, with `cluster.share_bans` | a ban on one node is a ban on both |
| Honeypot marks, revoked sessions | Yes, with `cluster.share_events` | |
| TLS session tickets | Yes, with a shared `session_tickets` master key | otherwise every resumption on the new node is a full handshake |
| WAF learning, bot-score baselines, API inventory | **No** | each node learns from what it saw; a node that has served nothing has learnt nothing |
| MFA lockout counters | **No** | a locked-out user is locked out on one node |
| Challenge pass cookies | Yes, with `challenge.secret_file` on both nodes | the key is what makes a cookie readable, so the same key means a client keeps its pass |
| Live sessions (SSH, RDP, VNC, FTP) | **No** | a session is a pair of connections; moving an address does not move them, and every session on the failed node is over |
| Recordings of those sessions | On the node that made them | collect them centrally if they are evidence |

So: **turn the cluster section on** if you run more than one node. Two
nodes without it are two proxies with the same configuration and half the
enforcement each — a rate limit of 100/s becomes 200/s across the pair, and
an attacker who is banned on one node is not banned on the other.

The three rows that say No are the honest cost of failover, and the second
of them is the one to plan for: after a failover, the surviving node's WAF
and bot-score baselines are whatever *it* has seen. If it was carrying no
traffic, its learning is empty, and learning mode on a freshly promoted
node will propose exclusions from a few minutes of data. Freeze the
enforcement decisions in configuration (`docs/USAGE.md`, the WAF and
bot_score sections) rather than leaving them to per-node learning, if a
failover must not change how strictly the proxy behaves.

## The four daemons

An estate that runs `xproxy`, `xgate`, `xrelay` and `xot` as separate
daemons (`docs/ARCHITECTURE.md`) has four failure domains, not one, and
they want different treatment:

- **xproxy** (edge: HTTP, forward, DNS) is stateless per request. Two nodes
  behind one address with the cluster section on is the straightforward
  shape.
- **xgate** (bastion: SSH, RDP, VNC, Telnet, FTP) holds long-lived
  sessions. Failover kills them, and no amount of shared state prevents
  that. Two nodes here are about *reducing the window in which a new
  session cannot be opened*, not about surviving a failure mid-session.
  Tell operators that, or they will report it as a bug.
- **xrelay** (messaging and services: SMTP, MQTT, the databases) keeps
  per-connection state and little else, so it behaves like the edge for
  failover purposes; what it does not keep is the MQTT session a broker
  holds, which is the broker's problem and not the relay's.
- **xot** (the plant: Modbus, IEC 104, S7, MMS, BACnet, OPC UA, CoAP,
  and the field infrastructure) is where the state is most awkward,
  because the policy depends on what the relay *saw*. Modbus value
  bounds, the select-before-operate state, the IEC 104 redundancy group's
  view of which connection may carry data, and the Sparkplug birth and
  sequence tables are per node and per what passed through it. A daemon
  promoted mid-shift has seen nothing, so its change-rate and delta rules
  have no baseline: with `on_unknown: refuse` that is an outage, and with
  `on_unknown: allow` it is a gap. Prefer `allow` on a node that may be
  promoted cold, and accept that the first write to each point after a
  failover is unchecked (`docs/CONFIG.md`, the Modbus values section).

Because the daemons share a machine's cluster socket
(`cluster.listen: unix:...`), siblings on one host share their state
without a network hop; siblings across hosts need the networked form with
mutual TLS.

## Active/active

Two nodes both carrying traffic is a different shape from two nodes where
one waits, and it changes three things:

1. **Rate limits become approximate.** With `share_rate_limits` each node
   refills at the configured rate minus its peers' reported consumption,
   which converges but is not exact under a burst. Where a limit must be
   exact — a payment endpoint, a login — set `distributed: exact` on that
   policy, which makes one node the owner of each key by rendezvous
   hashing. That costs a round trip per decision, bounded by
   `cluster.exact_timeout`, after which the node decides locally: an exact
   limit degrades to an approximate one rather than to an outage.
2. **Sticky things need a key, not a node.** Anything the proxy issues to a
   client and later reads back — challenge cookies, OIDC sessions, ticket
   resumption — must be readable on either node, which means the *key* is
   shared configuration (`challenge.secret_file`, the session ticket master
   key, the OIDC cookie key), not per-node state.
3. **The inventory and the learning diverge.** Each node's view of the API
   surface is what it saw. Collect them with the fleet controller
   (`docs/USAGE.md`) rather than reading one node and believing it.

## What to monitor

The readiness verdict is a check, not a monitor. These are the states that
should raise an alert *before* a failover happens:

- `xproxyctl ready` exiting 1 on a node that nobody stepped down.
- Certificate expiry: with `tls.expiry.warn` set, `xproxyctl tls` prints an
  `EXPIRY` line per certificate inside the window, and the security log
  carries one at every load and reload. An expired certificate on both
  nodes is an outage no failover fixes.
- Cluster peers not connected (`xproxyctl cluster`): the pair is sharing
  nothing, so each node is enforcing half.
- A session ticket key mismatch, which `xproxyctl tls tickets` reports per
  peer: resumption across the pair is silently doing full handshakes.
- Generation skew between nodes (`xproxyctl status`): one node is running a
  configuration the other is not, which means a failover changes behaviour.

## See also

- `docs/ARCHITECTURE.md` — the four daemons and what each holds
- `docs/CONFIG.md` — the `cluster`, `tls.expiry` and `session_tickets` keys
- `docs/USAGE.md` — the fleet controller, WAF learning, `xproxyctl`
- `docs/TROUBLESHOOTING.md` — what to collect when a failover went wrong
- `docs/AMR.md` — AMR-021, the approximate distributed rate limit
