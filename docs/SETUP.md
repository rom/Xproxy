# Setup

Installing xproxy on Fedora with the hardened systemd units, socket
activation and SELinux. Other systemd based distributions work the same way
apart from package names. See [HARDENING.md](HARDENING.md) for the host
level checklist and [USAGE.md](USAGE.md) for operation.

## Requirements

- Fedora 40 or newer (any current release), systemd, SELinux enforcing
- Go 1.25 or newer to build from source (no runtime dependency)
- `checkmodule` and `semodule_package` from `checkpolicy` and
  `policycoreutils` for the SELinux module

## Build

```sh
git clone https://github.com/rom/xproxy.git
cd xproxy
make build          # bin/xproxy, bin/xproxyctl (static, stripped)
make check          # fmt, vet, race tests, lint
```

`CGO_ENABLED=0` is set by the Makefile. The binaries have no shared library
dependencies.

## Install

As root:

```sh
useradd --system --home-dir /var/lib/xproxy --shell /usr/sbin/nologin --user-group xproxy
make install        # binaries, units, sysctl, logrotate, example config
sysctl --system
```

`make install` puts:

| Path | Content |
|------|---------|
| `/usr/local/bin/xproxy`, `/usr/local/bin/xproxyctl` | binaries |
| `/etc/systemd/system/xproxy.service` | hardened service |
| `/etc/systemd/system/xproxy.socket`, `xproxy-https.socket` | listening sockets on 80 and 443 |
| `/etc/sysctl.d/90-xproxy.conf` | kernel profile |
| `/etc/logrotate.d/xproxy` | rotation calling `xproxyctl reopen-logs` |
| `/etc/xproxy/xproxy.yaml` | example configuration (existing file backed up) |

systemd creates `/etc/xproxy`, `/var/log/xproxy`, `/run/xproxy` and
`/var/lib/xproxy` with the right owner on first start.

## Certificates

```sh
install -d -m 0750 -o root -g xproxy /etc/xproxy/certs
install -m 0640 -o root -g xproxy fullchain.pem /etc/xproxy/certs/example.com.pem
install -m 0640 -o root -g xproxy privkey.pem   /etc/xproxy/certs/example.com-key.pem
```

The service user needs read access; nothing else does. ACME automation
arrives in 1.0; until then, run `xproxyctl reload-certs` after renewal.

## Configure

Edit `/etc/xproxy/xproxy.yaml`. Listener names must match the
`FileDescriptorName` in the socket units (`public-http` and `public` in the
shipped files) or xproxy falls back to matching by address. Validate:

```sh
xproxy -config /etc/xproxy/xproxy.yaml -validate
```

Every problem is listed at once. Fix them all, then:

```sh
systemctl daemon-reload
systemctl enable --now xproxy.socket xproxy-https.socket
systemctl start xproxy.service
systemctl status xproxy.service
xproxyctl status
```

The service is `Type=notify`; `systemctl start` returns when the proxy is
serving.

## SELinux

Build and load the policy module:

```sh
dnf install checkpolicy policycoreutils-python-utils
make selinux
semodule -i deploy/selinux/xproxy.pp
semanage port -a -t xproxy_upstream_port_t -p tcp 8080     # each upstream port not already http_port_t
restorecon -Rv /usr/local/bin/xproxy /etc/xproxy /var/log/xproxy /run/xproxy /var/lib/xproxy
systemctl restart xproxy.service
ausearch -m AVC -ts recent
```

The module confines the daemon to `xproxy_t`: read `xproxy_conf_t`, append
`xproxy_log_t`, manage `xproxy_var_run_t` and `xproxy_var_lib_t`, bind
`http_port_t`, connect to `http_port_t` and `xproxy_upstream_port_t`. Any
other access is denied and shows up in the audit log. The policy is a
skeleton in this release and is finalised in 1.0 (AMR-017); run in
permissive mode for the domain first if you deploy it now:

```sh
semanage permissive -a xproxy_t
```

## Cluster

For several proxies, create a private CA and one certificate per node,
install them under `/etc/xproxy/cluster` (`root:xproxy`, `0640`), add the
`cluster` section (see CONFIG.md) with `listen` on the internal interface
and every other node in `peers`, and open the port to the peers only. To
socket activate the cluster port add a `ListenStream=10.0.0.1:7946` with
`FileDescriptorName=cluster` to the socket unit. Check with
`xproxyctl cluster` that every peer shows `connected: true`.

## WAF roll-out

Each compiled WAF profile costs tens of megabytes of memory per mode. Plan
for roughly 100 MB per profile that routes use in both `block` and
`detect`. Start with `default_mode: detect`, review
`xproxyctl tail security` for a few days of real traffic, put exclusions in
`/etc/xproxy/waf/exclusions.conf` (labelled `xproxy_conf_t`), then switch
to `block`. Ban persistence lives in `/var/lib/xproxy/bans.db`, which
systemd creates as `StateDirectory` with mode `0700`.

## Log handling

By default logs are files in `/var/log/xproxy` rotated by size when
`max_size_mb` is set, or by logrotate daily with the shipped configuration.
To use journald instead, set `logging.stdout: true` and disable the file
streams; `journalctl -u xproxy -o json` then shows the JSON lines. Native
journald and syslog sinks arrive in 1.0.

## Verifying the hardening

```sh
systemd-analyze security xproxy.service     # expect a score in the OK band
systemctl show xproxy.service -p CapabilityBoundingSet -p NoNewPrivileges
ss -ltnp | grep xproxy                       # sockets owned by systemd (pid 1)
ls -la /run/xproxy/mgmt.sock                 # srw-rw---- xproxy xproxy
```

## Upgrading

```sh
make build && make install
systemctl restart xproxy.service             # socket stays open; clients see a short drain
```

Configuration schema changes are versioned (`version: 1`); a new major
schema version ships with a migration note in the change log.

## Uninstall

```sh
systemctl disable --now xproxy.service xproxy.socket xproxy-https.socket
semodule -r xproxy
rm -f /usr/local/bin/xproxy /usr/local/bin/xproxyctl /etc/systemd/system/xproxy*.{service,socket} /etc/sysctl.d/90-xproxy.conf /etc/logrotate.d/xproxy
```

Configuration, certificates and logs are left in place.

## Development setup

```sh
make test-race
go test -run TestProxyBasics -v ./internal/proxy/
./bin/xproxy -config deploy/config/xproxy.yaml -validate    # fails on missing certs, by design
```

For a local run without certificates use the smoke procedure in
[TESTS.md](TESTS.md).
