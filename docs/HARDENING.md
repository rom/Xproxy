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

The unit is `Type=notify-reload` (systemd 253, Fedora 38 and newer):
`systemctl reload` sends `SIGHUP` and waits for the daemon's
`RELOADING`/`READY` notifications, so no helper program runs inside the
sandbox and `NoExecPaths=/` with `ExecPaths=` for the binary alone can
be enforced. `KeyringMode=private`, `PrivateMounts=yes` and
`RestrictFileSystems=` (ignored on kernels without the BPF LSM) complete
the set. To have systemd refuse every bind except a fixed port list,
install `deploy/systemd/xproxy.service.d/10-socket-bind.conf` and list
the ports the daemon binds itself.

## 1a. The in-process sandbox

After the listeners, log files, state files and the management socket
are open, and before it reports ready, the daemon confines itself
(`sandbox` section of [CONFIG.md](CONFIG.md), on by default):

- Landlock file system rules derived from the configuration: the
  directory of every configured file is readable, the log, state,
  history, capture and certificate directories are writable, the
  resolver files,
  trust stores and time zone data are readable, and nothing else exists.
  On kernels with Landlock ABI 4 (6.7 and newer) new TCP binds are
  refused as well. The rules are the file system view the process keeps
  for its lifetime; a reload naming a file outside them is refused with
  "restart to apply", never silently widened.
- A seccomp deny list installed on every thread: process tracing and
  memory access to other processes, module loading, kexec and reboot,
  mounts, namespaces, chroot, keyrings, BPF, `perf_event_open`,
  io_uring, memory policy, identity changes, `execve` and `clone3`
  return `EPERM`; a system call from a foreign architecture (including
  the x32 ABI on x86_64) kills the process.
- Capability clearing: ambient, bounding, effective, permitted and
  inheritable sets are emptied. Under the unit they already are and the
  step verifies it.
- `PR_SET_NO_NEW_PRIVS` (idempotent with the unit's directive) and non
  dumpable with a core size limit of zero, so no process of the same
  user can read the daemon's memory and no crash writes keys to disk.

The unit and the in-process layer overlap on purpose: a container image
or a hand written unit that lacks a directive still gets the in-process
control, and a kernel without Landlock still gets the unit's mount
namespace. With `strict: true` the daemon refuses to start when a
mechanism is unavailable, which is the right setting on a host where
the kernel is known.

Verify:

```sh
xproxyctl sandbox
# platform linux  enabled true  strict false  applied 2026-09-18T10:00:00+02:00
# MECHANISM     STATE    DETAIL
# debuggable    applied  non dumpable, core size 0
# capabilities  applied  already empty
# no_new_privs  applied  -
# landlock      applied  ABI 5, 14 read and 4 write rules present, TCP bind refused
# seccomp       applied  filter installed on every thread, 97 system calls refused
grep -E 'Seccomp|NoNewPrivs|CapBnd' /proc/$(systemctl show -p MainPID --value xproxy.service)/status
```

`Seccomp: 2`, `NoNewPrivs: 1` and `CapBnd: 0000000000000000` are the
expected values. A `landlock: unavailable` line means the kernel lacks
the LSM (`cat /sys/kernel/security/lsm` should list `landlock`; add
`lsm=landlock,...` to the kernel command line on a custom kernel).

## 2. SELinux enforcing with the xproxy module

Install `xproxy-selinux` (or load the module from `deploy/selinux`), label
the ports the configuration uses (`xproxy_upstream_port_t`,
`xproxy_cluster_port_t`, `xproxy_metrics_port_t`, `xproxy_admin_port_t`),
and leave `xproxy_connect_any` off. Run the domain permissive during the
first day and inspect AVCs, then switch to enforcing. The GUI runs in its
own domain `xproxy_admin_t`; turn `xproxy_admin_manage_service` off if the
restart button is not wanted.

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
| `/etc/xproxy` | `root:xproxy-config` | `0750` |
| `/etc/xproxy/*.yaml` | `root:xproxy-config` | `0640` |
| `/etc/xproxy/certs/*` | `root:xproxy-config` | `0640` |
| `/var/log/xproxy` | `xproxy:xproxy` | `0750` |
| `/var/lib/xproxy` | `xproxy:xproxy` | `0700` |
| `/run/xproxy/mgmt.sock` | `xproxy:xproxy` | `0660` |

`xproxy-config` is the group the three daemons share for this directory
and nothing else: each reads its own file there and they share the
includes beside it, so no one of them can own it. It is created by
`tmpfiles.d`, deliberately not by `ConfigurationDirectory=`, which
systemd chowns to the unit's own user on every start -- three units
declaring it is three daemons taking the directory from each other, and
at `0750` the two that did not start last cannot read their
configuration at all.

xproxy refuses a world writable configuration file. Nothing under
`/etc/xproxy` should be writable by the service user; the unit mounts it
read only.

## 5a. Private keys: get them off the file system

The table above is the best a private key in a file can do, and a file is
still a file: readable by whatever else can read that directory, present
in the machine's backups, and replaced by whatever can write there. Three
arrangements, weakest to strongest:

1. **`key_file`** -- a PEM file on this machine. An attacker who reads
   `/etc/xproxy/certs` gets the key, and nothing in this document
   changes that.

2. **`key: vault:secret/tls/site#key`** -- the key comes from HashiCorp
   Vault. What is on the machine is a token, in a file with mode `0400`
   owned by `root` and group-readable by `xproxy-config`. A token can be
   scoped to one path, revoked the moment a machine is suspected, and its
   every use is in the vault's own audit log -- none of which a file can
   do. Rotation reaches a running proxy on `refresh_interval` with no
   reload.

   Name `secrets.vault.ca_file`. Do **not** reach for `insecure` on an
   `https://` address: validation refuses it, and the reason is that
   anything on the path between this proxy and the vault could otherwise
   hand it the private keys it will then serve with.

3. **`signer: {socket: ..., key: ...}`** -- the key never enters this
   process. A helper holds it, in a PKCS#11 token, an HSM or a TPM, and
   answers signature requests over a Unix socket; the proxy sends a digest
   and gets a signature back. Anything that reads this proxy's memory --
   a Heartbleed-shaped bug, a core dump, a debugger -- gets nothing.

   `xsigner`(8) is the shipped helper, with its own user, its own unit and
   `PrivateNetwork=yes` -- a bug in a process that cannot send anywhere
   cannot exfiltrate a key. Its socket lives in `/run/xsigner` at mode
   2750 `xsigner:xsigner-clients`, with the socket itself at 0660
   inheriting that group from the setgid directory: connecting to a Unix
   socket needs **write** permission on it, so the group is the access
   list and the directory is the wall. The derived Landlock ruleset gives
   the proxy a write rule on that directory for the same reason; the
   helper needs no rule from the proxy at all.

   The helper's configuration and keys are under `/etc/xsigner`, **not**
   `/etc/xproxy`: that directory is readable by the `xproxy-config` group,
   which is the three proxy daemons, and the whole point of this
   arrangement is that they cannot read what the helper reads.

   For a key in an HSM, a TPM, a smartcard or a cloud KMS, write a helper
   of your own -- [SIGNER.md](SIGNER.md) specifies the protocol and what a
   helper must and must not do.

Put the most valuable certificate in the strongest arrangement rather
than moving everything at once: the three are per certificate, and
`examples/security/key-custody.yaml` is a listener with all three so a
migration can be read off it. `xproxyctl status` and
`xproxy_private_keys{custody="file"}` are how you watch the first number
go down.

**FIPS 140-3.** Where a deployment must be FIPS, set `fips.required:
true` and build with `GOFIPS140=v1.0.0`, running with
`GODEBUG=fips140=on`. The setting is a refusal to start rather than a
warning, which is its whole value: a rebuild with the wrong toolchain
cannot quietly leave the estate out of compliance. Note that the module
refuses `X25519` and the ChaCha20-Poly1305 suites, so a listener's
`key_exchange` needs `X25519MLKEM768` or a P-curve left in it; the probe
at start says which of your configured algorithms it will actually do,
and `xproxy_fips_refused_algorithms` is the number to keep at zero.

## 5b. Cluster

Use a dedicated private CA for cluster certificates, never the public web
CA. Set `allowed_names` to the exact node names. Bind `listen` to the
internal interface and restrict the port with nftables to the peers.
Rotate node certificates by installing the new files and restarting one
node at a time; the others keep serving with local limits meanwhile.
The session ticket master (`server.session_tickets.secret_file`) is a
key to every resumable session across the cluster: keep it `0600`,
owned by `xproxy`, under `/var/lib/xproxy`, out of unencrypted backups,
and rotate it with `xproxyctl rotate-secret` on every node within one
epoch (a node with another file falls back to full handshakes and shows
under `mismatched_peers`).

## 5c. Origins accept traffic only from the proxy

A WAF in front of an application that is also reachable directly
protects nothing. Close the direct path with three layers; each holds
where the others cannot.

**Network.** On every origin host allow the application port from the
proxies' addresses only:

```
table inet origin {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport 8080 ip saddr { 10.0.0.1, 10.0.0.2 } accept   # the xproxy nodes
    tcp dport 22 ip saddr 10.0.0.0/8 accept
  }
}
```

In a cloud, put the same rule in the security group of the origin and
give the proxies static addresses or a NAT gateway. A load balancer or
CDN in front of the proxy must not also have a path to the origin.

**Mutual TLS.** Give the proxy a client certificate
(`upstreams[].tls.client_cert_file`, `client_key_file`) from a private
CA and make the origin require it (`ssl_verify_client on` in nginx,
`SSLVerifyClient require` in Apache, `ClientAuth: tls.RequireAndVerifyClientCert`
in Go). This binds the connection, not the request, so a compromised
host on the proxy network still cannot speak to the origin.

**Request signature.** Where network rules do not reach (a shared
platform, an origin the internet must reach for other reasons), sign
every request (`upstreams[].origin_signature`) and verify at the origin.
The rule is one function in any language: rebuild the signed string,
compute HMAC-SHA256 with the key named by `kid`, compare in constant
time, refuse when `t` is older than the TTL. In Go:

```go
keys := ring.All() // the keyring file the proxy uses, shared out of band
if err := originsig.Verify(r, "X-Xproxy-Signature", nil, keys, 5*time.Minute, time.Now()); err != nil {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

In nginx with njs, the same steps: split the header on `;`, build
`"v1\n" + method + "\n" + host + "\n" + path + "\n" + query + "\n" + t + "\n" + x_real_ip + "\n" + x_request_id`,
`crypto.createHmac('sha256', key).update(msg).digest('base64url')`,
compare, check the age. When the signature ends in `;bd=1`
(`body_digest: true`), append one more line: the body digest, which is
also in `Content-Digest`, as `sha-256=:` + base64(sha256(body)) + `:`.
Rotate with `xproxyctl rotate-secret FILE` on the proxy, copy the new
file to the origins within the grace period, then rotate again with
`-keep 1` to drop the old key.

A signature stays valid for its TTL, so anything that captured one can
replay it. `body_digest` bounds what a replay may change; to stop the
replay itself, have the origin remember the `X-Request-Id` values it
has answered for the TTL and refuse a repeat. The proxy sets a fresh
id per request and the id is signed, so a replay arrives with the id it
was captured with.

Whatever the layer, the check is `xproxyctl upstreams` on the proxy and
a request straight to the origin port from another host: it must fail.

## 6. Management access

Only members of the `xproxy` group and root can reach the socket. Keep
that group small; every action is in the audit log with the caller's uid.
Do not expose the socket through a TCP forwarder. For remote administration
use SSH with `xproxyctl`, or the GUI through an SSH tunnel to its loopback
listener. If the GUI must be reachable on an internal network, bind it
with a server certificate and a client CA (the process refuses anything
else), give operators client certificates, and keep viewers to the
`viewer` role.

## 6a. Descriptor and memory budget

Plan one descriptor per client connection and one per idle upstream
connection (at most `max_idle_conns_per_host` per endpoint), plus about
15 KiB of memory per idle upstream connection and 1.5 KiB per endpoint
for its health loop. The unit sets `LimitNOFILE=1048576`; a source
install without the unit must raise the limit (`ulimit -n`) or the
proxy will refuse connections under load. Above a few thousand endpoints
set `metrics.endpoint_series: false`. PERFORMANCE.md has the measured
figures.

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
[ ] xproxyctl sandbox: every mechanism applied (strict: true on known kernels)
[ ] getenforce = Enforcing, no AVC denials for xproxy_t after a traffic run
[ ] sysctl profile applied
[ ] nftables policy drop with per-source new connection limit
[ ] file ownership and modes as in section 5
[ ] xproxy group membership reviewed
[ ] xproxy -validate clean; trusted_proxies reviewed
[ ] security and audit logs shipped off host
[ ] certificate renewal procedure tested with xproxyctl reload-certs
```
