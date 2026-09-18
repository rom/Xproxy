# Hardening guide (Fedora)

Host level measures that complement the controls built into xproxy. Items
are ordered by impact. Each has a verification step. SETUP.md covers the
basic installation; this guide assumes it is done.

## 1. Run under the shipped unit, socket activated

The unit runs xproxy as user `xproxy` with an empty capability set, a read
only system view, private `/tmp` and `/dev`, no new privileges, no
writable-and-executable memory, `AF_INET`, `AF_INET6` and `AF_UNIX` only,
and a system call allow list (`@system-service` minus privileged groups).
Sockets are bound by systemd.

Verify:

```sh
systemd-analyze security xproxy.service
systemctl show xproxy.service -p User -p CapabilityBoundingSet -p NoNewPrivileges -p ProtectSystem -p MemoryDenyWriteExecute
```

Do not add `AmbientCapabilities`; if a port below 1024 is needed, add a
`ListenStream` to the socket unit instead.

## 2. SELinux enforcing with the xproxy module

Load the module from `deploy/selinux`, label the paths, add upstream ports
that are not `http_port_t` to `xproxy_upstream_port_t`. Run the domain
permissive during the first day and inspect AVCs, then switch to enforcing.

Verify:

```sh
getenforce                          # Enforcing
ps -eZ | grep xproxy                # system_u:system_r:xproxy_t
ausearch -m AVC -c xproxy -ts today # empty
```

## 3. Kernel network profile

Install `deploy/sysctl/90-xproxy.conf`: SYN cookies, larger SYN and accept
backlogs, quick FIN timeout, no forwarding or redirects, reverse path
filtering, martian logging, larger socket buffers, restricted kernel
pointers and BPF.

Verify: `sysctl net.ipv4.tcp_syncookies net.core.somaxconn`.

## 4. Firewall and per-source connection rate

Allow only 80 and 443 in from the internet, and the management socket is a
file so it needs nothing. Rate limit new connections per source before they
reach user space; this stops the cheapest floods without xproxy spending a
goroutine. Example nftables rules:

```
table inet xproxy {
  set ratelimited { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    tcp dport { 80, 443 } ct state new meter conn_rate { ip saddr limit rate over 50/second burst 100 packets } add @ratelimited { ip saddr } drop
    tcp dport { 80, 443 } ct state new ip saddr @ratelimited drop
    tcp dport { 80, 443 } accept
    udp dport 443 ct state new meter quic_rate { ip saddr limit rate over 50/second burst 100 packets } drop
    udp dport 443 accept
    tcp dport 22 ip saddr 10.0.0.0/8 accept
    # cluster port: peers only
    tcp dport 7946 ip saddr { 10.0.0.2, 10.0.0.3 } accept
  }
}
```

Tune the rate to the site. Verify with `nft list ruleset` and a burst test
from a lab address.

## 5. File permissions and ownership

| Path | Owner | Mode |
|------|-------|------|
| `/etc/xproxy` | `root:xproxy` | `0750` |
| `/etc/xproxy/xproxy.yaml` | `root:xproxy` | `0640` |
| `/etc/xproxy/certs/*` | `root:xproxy` | `0640` |
| `/var/log/xproxy` | `xproxy:xproxy` | `0750` |
| `/var/lib/xproxy` | `xproxy:xproxy` | `0700` |
| `/run/xproxy/mgmt.sock` | `xproxy:xproxy` | `0660` |

xproxy refuses a world writable configuration file. Nothing under
`/etc/xproxy` should be writable by the service user; the unit mounts it
read only.

## 5b. Cluster

Use a dedicated private CA for cluster certificates, never the public web
CA. Set `allowed_names` to the exact node names. Bind `listen` to the
internal interface and restrict the port with nftables to the peers.
Rotate node certificates by installing the new files and restarting one
node at a time; the others keep serving with local limits meanwhile.

## 6. Management access

Only members of the `xproxy` group and root can reach the socket. Keep
that group small; every action is in the audit log with the caller's uid.
Do not expose the socket through a TCP forwarder. For remote administration
use SSH with `xproxyctl`; the 1.0 GUI adds mTLS on a loopback or dedicated
listener.

## 7. Configuration choices that matter

- `trusted_proxies` empty when xproxy is the edge. Never `0.0.0.0/0`.
- `server_header` empty (default).
- `min_version: "1.3"` when clients allow it.
- `client_auth: require` for machine facing hosts.
- Per route `max_body_bytes` on endpoints that never take large bodies.
- `rate_limits` on authentication and search endpoints, `tarpit` on login.
- `allow_cidrs` on administrative paths.
- `request_headers.remove: [Cookie]` on routes to third party or API
  upstreams that do not need session cookies.
- Response security headers (`Strict-Transport-Security`,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Content-Security-Policy`) set per route as in the example configuration.
- `websocket: true` only where needed.
- `https` with `ca_file` to upstreams that cross a network boundary.

## 8. Logging and retention

Ship the security and audit streams off the host by listing `syslog`
(`tcp+tls` with a pinned CA) or `journald` in their sinks, so a
compromised service account cannot rewrite history. Turn on
`logging.redaction` for the access stream when addresses and user agents
are not needed in clear text; `hash` mode keeps per-client correlation
without storing the address. Rotate access logs daily with the shipped
logrotate configuration and keep them according to your retention policy.
Set `logging.level: info` in production; `debug` includes upstream error
details.

## 9. Resource limits

The unit sets `LimitNOFILE=1048576`. Keep `max_connections` below that
minus upstream connections and file handles. `max_concurrent_requests`
should be set to what the upstream fleet can serve with acceptable latency;
xproxy rejecting early is cheaper than upstreams timing out.

## 10. Updates

Track releases; `govulncheck` runs in CI for every commit. Rebuild with the
current Go toolchain for standard library fixes, restart with
`systemctl restart xproxy.service` (socket activation keeps the port open).

## Verification checklist

```
[ ] systemd-analyze security xproxy.service in the OK band
[ ] getenforce = Enforcing, no AVC denials for xproxy_t after a traffic run
[ ] sysctl profile applied
[ ] nftables policy drop with per-source new connection limit
[ ] file ownership and modes as in section 5
[ ] xproxy group membership reviewed
[ ] xproxy -validate clean; trusted_proxies reviewed
[ ] security and audit logs shipped off host
[ ] certificate renewal procedure tested with xproxyctl reload-certs
```
