# Setup

Installing xproxy on Fedora with the hardened systemd units, socket
activation and SELinux. Other systemd based distributions work the same way
apart from package names. See [HARDENING.md](HARDENING.md) for the host
level checklist and [USAGE.md](USAGE.md) for operation.

## Requirements

- Fedora 40 or newer (any current release), systemd 253 or newer
  (`Type=notify-reload`), SELinux enforcing; a kernel with Landlock
  (Fedora's has it) for the in-process file system rules
- macOS 13 or newer is supported as well: see [SETUP_MACOS.md](SETUP_MACOS.md)
- Go 1.25 or newer to build from source (no runtime dependency)
- `selinux-policy-devel` to build the SELinux module, `rpm-build`,
  `rpmlint` and `systemd-rpm-macros` to build the packages

## Build

```sh
git clone https://github.com/rom/xproxy.git
cd xproxy
make build          # bin/xproxy, bin/xproxyctl, bin/xproxy-admin (static, stripped)
make check          # fmt, vet, race tests, lint
```

`CGO_ENABLED=0` is set by the Makefile. The binaries have no shared library
dependencies.

## Install from RPM (recommended on Fedora)

Build the packages once, on any Fedora host with the build tools, from a
checkout:

```sh
dnf install golang rpm-build rpmlint selinux-policy-devel systemd-rpm-macros bzip2
make rpm            # rpmbuild/RPMS/{x86_64,noarch}/xproxy-*.rpm, offline from a vendored tarball
make rpmlint
```

Four packages come out:

| Package | Content |
|---------|---------|
| `xproxy` | `xproxy`, `xproxyctl`, the four units, sysctl profile, logrotate, sysusers, example configuration, documentation, Grafana dashboards and alert rules |
| `xproxy-admin` | `xproxy-admin`, its unit and the polkit rule |
| `xproxy-fleet` | `xproxy-fleet`, its unit and state directory (for the management host of a fleet) |
| `xproxy-selinux` | the policy module (loaded on install, relabels the paths) and the interface file for other policies |

Install and start:

```sh
dnf install ./rpmbuild/RPMS/x86_64/xproxy-*.rpm ./rpmbuild/RPMS/noarch/xproxy-selinux-*.rpm
vi /etc/xproxy/xproxy.yaml               # or drop in your own; %config(noreplace)
xproxyctl validate
systemctl enable --now xproxy.socket xproxy-https.socket
systemctl status xproxy.service
```

The packages create the `xproxy` and `xproxy-admin` users through
`sysusers.d`, own `/etc/xproxy`, `/var/log/xproxy` and `/var/lib/xproxy`
with the right modes, apply the sysctl profile, and load the SELinux
module with `semodule` and relabel on install. Upgrades restart the
service (`%systemd_postun_with_restart`); the socket stays open so no
connection is refused. The version is `VERSION` plus a git suffix unless
the checkout is on a tag.

## Install from source

As root:

```sh
useradd --system --home-dir /var/lib/xproxy --shell /usr/sbin/nologin --user-group xproxy
make install        # binaries, units, sysctl, logrotate, example config
sysctl --system
```

`make install` puts:

| Path | Content |
|------|---------|
| `/usr/local/bin/xproxy`, `/usr/local/bin/xproxyctl`, `/usr/local/bin/xproxy-admin`, `/usr/local/bin/xproxy-fleet` | binaries |
| `/etc/systemd/system/xproxy-fleet.service` | fleet controller service (disabled until you enable it on a management host) |
| `/etc/systemd/system/xproxy.service` | hardened service |
| `/etc/systemd/system/xproxy-admin.service`, `/etc/polkit-1/rules.d/50-xproxy-admin.rules` | web GUI service (disabled until you enable it) and the polkit rule that lets it restart the data plane |
| `/etc/systemd/system/xproxy.socket`, `xproxy-https.socket`, `xproxy-h3.socket` | listening sockets on TCP 80, TCP 443 and UDP 443 |
| `/etc/sysctl.d/90-xproxy.conf` | kernel profile |
| `/etc/logrotate.d/xproxy` | rotation calling `xproxyctl reopen-logs` |
| `/etc/xproxy/xproxy.yaml` | example configuration (existing file backed up) |
| `/usr/local/share/man/man8/xproxy.8`, `xproxyctl.8`, `/usr/local/share/man/man5/xproxy.yaml.5` | manual pages |
| `/usr/local/share/xproxy/xproxy.schema.json` | JSON schema of the configuration for editors |
| `/usr/local/share/bash-completion/completions/xproxyctl`, `zsh/site-functions/_xproxyctl`, `fish/vendor_completions.d/xproxyctl.fish` | shell completion |

systemd creates `/etc/xproxy`, `/var/log/xproxy`, `/run/xproxy` and
`/var/lib/xproxy` with the right owner on first start.

## Certificates

```sh
install -d -m 0750 -o root -g xproxy /etc/xproxy/certs
install -m 0640 -o root -g xproxy fullchain.pem /etc/xproxy/certs/example.com.pem
install -m 0640 -o root -g xproxy privkey.pem   /etc/xproxy/certs/example.com-key.pem
```

The service user needs read access; nothing else does. Run
`xproxyctl reload-certs` after replacing the files.

Alternatively let the proxy obtain certificates itself: put an `acme`
section in the configuration and `tls.acme` groups on the listener (see
[USAGE.md](USAGE.md)). The state lives in `/var/lib/xproxy/acme`, which
the unit's `StateDirectory=xproxy` creates with mode `0700`; nothing else
needs to be installed. The CA must reach port 80 (`http-01`) or 443
(`tls-alpn-01`) of this host from the Internet, so with a firewall or a
socket activated setup make sure the plaintext listener is bound even when
it only redirects.

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
systemctl enable --now xproxy.socket xproxy-https.socket xproxy-h3.socket   # omit h3 without HTTP/3
systemctl start xproxy.service
systemctl status xproxy.service
xproxyctl status
```

The service is `Type=notify`; `systemctl start` returns when the proxy is
serving.

## Web GUI

The GUI is optional and off until enabled. It runs as its own user so that
a compromise of the data plane cannot write its configuration, and it owns
the configuration file so that operators can edit it from the browser:

```sh
useradd --system --gid xproxy --home-dir /var/lib/xproxy --shell /usr/sbin/nologin xproxy-admin   # already exists with the RPM (sysusers)
chown xproxy-admin:xproxy /etc/xproxy/xproxy.yaml && chmod 0640 /etc/xproxy/xproxy.yaml
sudo -u xproxy-admin xproxy-admin user add admin -role operator
systemctl enable --now xproxy-admin
ssh -L 8443:127.0.0.1:8443 edge          # from the workstation
xdg-open http://127.0.0.1:8443/
```

The shipped unit listens on `127.0.0.1:8443` only. To reach it directly
from an internal network, issue a server certificate and a client CA,
then change `ExecStart` to add `-listen 10.0.0.5:8443 -tls-cert ...
-tls-key ... -client-ca ...`; without all three the process refuses to
bind a non-loopback address. The restart button runs
`systemctl restart xproxy.service`; the polkit rule allows exactly that
verb on that unit for the `xproxy-admin` user and nothing else. Remove
`-restart-cmd` from the unit to disable the button.

The users file `/etc/xproxy/admin-users` holds PBKDF2 hashes and is
written `0600` by the `user` and `passwd` subcommands, run as
`xproxy-admin`. `xproxy-admin passwd NAME` changes a password; restart
the service afterwards to end that user's sessions.

## SELinux

The `xproxy-selinux` package loads the module and relabels on install. From
a source install, build and load it by hand:

```sh
dnf install selinux-policy-devel policycoreutils-python-utils
make selinux                                  # deploy/selinux/xproxy.pp
semodule -i deploy/selinux/xproxy.pp
restorecon -Rv /usr/local/bin/xproxy* /etc/xproxy /var/log/xproxy /run/xproxy /var/lib/xproxy
systemctl restart xproxy.service
ausearch -m AVC -ts recent
```

Ports are labelled by the operator because they depend on the
configuration (modules cannot carry `portcon` rules):

```sh
semanage port -a -t xproxy_upstream_port_t -p tcp 8080    # each upstream port that is not http_port_t (80, 443, 8008, 8009, 8443, 9000)
semanage port -a -t xproxy_cluster_port_t  -p tcp 7946    # cluster listener
semanage port -a -t xproxy_metrics_port_t  -p tcp 9100    # TCP metrics listener
semanage port -a -t xproxy_admin_port_t    -p tcp 8443    # web GUI listener (8443 may already be http_port_t; then nothing to do)
```

What the module allows:

| Domain | Files | Network | Other |
|--------|-------|---------|-------|
| `xproxy_t` (data plane) | read `xproxy_conf_t` and system certificates; create, append, rename `xproxy_log_t`; manage `xproxy_var_run_t` (socket) and `xproxy_var_lib_t` (bans, ACME, challenge key) | bind `http_port_t` and `xproxy_cluster_port_t`, `xproxy_metrics_port_t`; connect to `http_port_t`, `xproxy_upstream_port_t`, `xproxy_cluster_port_t`, `syslogd_port_t`; DNS | journald and syslog sockets, systemd notify and socket activation, read its own process state, urandom. No capabilities, no exec |
| `xproxy_admin_t` (GUI) | read and write `xproxy_conf_t`; read `xproxy_log_t`; connect to the socket in `xproxy_var_run_t` | bind `xproxy_admin_port_t` | `systemctl` over D-Bus for `xproxy_unit_file_t` (start, stop, status, reload) when the boolean below is on |

Booleans:

| Boolean | Default | Effect |
|---------|---------|--------|
| `xproxy_connect_any` | off | Let the data plane connect to any TCP port instead of labelling upstream ports |
| `xproxy_admin_manage_service` | on | Let the GUI restart the data plane through systemd |

```sh
setsebool -P xproxy_connect_any on
```

Other policies (log shippers, configuration management) can use the
interfaces in `xproxy.if`: `xproxy_stream_connect`, `xproxy_read_config`,
`xproxy_manage_config`, `xproxy_read_log`, `xproxy_admin`.

Any access outside these rules is denied and shows up in the audit log.
For the first deployment of a new configuration feature, run the domain
permissive for a day and review the denials before enforcing:

```sh
semanage permissive -a xproxy_t
ausearch -m AVC -c xproxy -ts today
semanage permissive -d xproxy_t
```

## HTTP/3

List `h3` in the protocols of the TLS listener. The UDP socket comes from
`xproxy-h3.socket` (`FileDescriptorName=public-udp`) or is bound by the
process. Allow UDP 443 in the firewall and apply the sysctl profile, which
raises the UDP buffer limits QUIC needs (`net.core.rmem_max` at least
7 MiB). Verify with a browser or `curl --http3-only` from a curl build with
HTTP/3 support; the access log shows `HTTP/3.0`.

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
Each stream can also list `journald` (native protocol, indexed `XPROXY_*`
fields) and `syslog` (UDP, TCP, TLS or `/dev/log`) in its `sinks`; see
CONFIG.md and USAGE.md. The SELinux module allows the journal socket
(`init_dgram_send`) and `/dev/log`; a remote syslog collector needs the
collector port allowed for `xproxy_t`, for example
`semanage port -a -t xproxy_upstream_port_t -p tcp 6514`. Enable
`logging.redaction` before the first production traffic if the logs are
subject to data protection requirements; the key file for `hash` mode
lives in the state directory.

## Verifying the hardening

```sh
systemd-analyze security xproxy.service     # expect a score in the OK band
systemctl show xproxy.service -p CapabilityBoundingSet -p NoNewPrivileges
ss -ltnp | grep xproxy                       # sockets owned by systemd (pid 1)
ls -la /run/xproxy/mgmt.sock                 # srw-rw---- xproxy xproxy
xproxyctl sandbox                            # landlock, seccomp, capabilities: applied
```

`xproxyctl sandbox` lists the in-process layer the daemon applies after
start; `unavailable` next to `landlock` means the kernel lacks the LSM
and the unit's mount namespace is the only file system confinement.
[HARDENING.md](HARDENING.md) section 1a explains each line.

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
systemctl disable --now xproxy-admin.service
rm -f /usr/local/bin/xproxy /usr/local/bin/xproxyctl /usr/local/bin/xproxy-admin /etc/systemd/system/xproxy*.{service,socket} /etc/sysctl.d/90-xproxy.conf /etc/logrotate.d/xproxy /etc/polkit-1/rules.d/50-xproxy-admin.rules
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
