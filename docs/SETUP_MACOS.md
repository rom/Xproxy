# Setup on macOS

Installing xproxy on macOS as a launchd system daemon under a dedicated
user, confined by a Seatbelt profile, with pf in front of it. macOS is a
supported platform for edge, lab and developer deployments; the Fedora
installation in [SETUP.md](SETUP.md) remains the reference for
production, and [HARDENING_MACOS.md](HARDENING_MACOS.md) lists what macOS
offers instead of systemd, SELinux, Landlock and seccomp.

## Requirements

- macOS 13 (Ventura) or newer on Apple silicon or Intel. Ports below
  1024 need no privilege since macOS 10.14, so nothing runs as root.
- Go 1.25 or newer to build; the binaries are static and have no
  dependency on Homebrew or Xcode at run time.
- Administrator access for the installation (users, launchd, pf).

## Build

On any machine with Go, including Linux:

```sh
make build-darwin                 # bin/darwin-arm64/, bin/darwin-amd64/
make dist-darwin                  # dist/xproxy-<version>-darwin-<arch>.tar.gz
```

`make check` type checks the macOS targets on every run (`vet-all`), so
a change that breaks the port fails the Linux build too.

## Install

From a checkout on the Mac:

```sh
make install-macos                # builds for this Mac and runs deploy/macos/install.sh
```

or from an unpacked release tarball:

```sh
sudo sh macos/install.sh .
```

The installer is idempotent and does, in order:

1. Creates the hidden system users `_xproxy` and `_xproxy-admin` and
   the group `_xproxy` with ids below 500, no shell and no home.
2. Installs `xproxy`, `xproxyctl` and `xproxy-admin` into
   `/usr/local/bin`.
3. Creates the directories with the layout every platform default
   follows on macOS:

   | Path | Owner | Mode | Content |
   |------|-------|------|---------|
   | `/usr/local/etc/xproxy` | root:_xproxy | 0750 | `xproxy.yaml`, certificates, `xproxy.sb`, `pf-xproxy.conf`, `admin-users` |
   | `/usr/local/var/log/xproxy` | _xproxy | 0750 | the four log streams, `launchd.log` |
   | `/usr/local/var/run/xproxy` | _xproxy | 0750 | `mgmt.sock` |
   | `/usr/local/var/lib/xproxy` | _xproxy | 0700 | bans, ACME state, history |

   `xproxy -config`, `xproxyctl -socket` and `xproxy-admin` default to
   these paths when built for macOS, so the commands in
   [USAGE.md](USAGE.md) work unchanged.
4. Writes the example configuration with the paths rewritten, unless one
   exists, plus the Seatbelt profile, the pf anchor and the newsyslog
   rotation file.
5. Installs a sudoers fragment that lets `_xproxy-admin` run exactly
   `launchctl kickstart -k system/com.sysctl.xproxy` (the GUI's restart
   action) and nothing else.
6. Installs the launchd jobs and starts the data plane once the
   configuration validates.

Then:

```sh
sudo xproxyctl status                      # version, listeners, counters, sandbox
sudo xproxyctl sandbox                     # debugger denial, seatbelt profile
sudo launchctl kill HUP system/com.sysctl.xproxy      # reload
sudo launchctl kickstart -k system/com.sysctl.xproxy  # restart
```

`xproxyctl` needs to reach `/usr/local/var/run/xproxy/mgmt.sock`, which
the `_xproxy` group owns; add an operator account to the group
(`sudo dseditgroup -o edit -a alice -t user _xproxy`) instead of using
sudo. The daemon identifies callers through `LOCAL_PEERCRED`, so the
audit log names the user and process id as on Linux.

## Certificates

Place the certificate and key under `/usr/local/etc/xproxy` (readable by
the group, key `0640`), or let ACME issue them into
`/usr/local/var/lib/xproxy/acme`; both directories are admitted by the
Seatbelt profile. A certificate elsewhere needs a `file-read*` line in
`xproxy.sb`, see [HARDENING_MACOS.md](HARDENING_MACOS.md).

## Web GUI

```sh
sudo -u _xproxy-admin xproxy-admin -users /usr/local/etc/xproxy/admin-users user add admin -role operator
sudo launchctl bootstrap system /Library/LaunchDaemons/com.sysctl.xproxy-admin.plist
ssh -L 8443:127.0.0.1:8443 host        # then https://127.0.0.1:8443
```

The GUI binds the loopback address only; for an internal address use
`-tls-cert`, `-tls-key` and `-client-ca` in the job's arguments as on
Linux. It runs without the Seatbelt profile because its restart action
executes `launchctl`; it has its own user, no shell, and the sudoers
fragment above is the only privilege it holds.

## Log handling

`newsyslog` rotates the streams daily (`/etc/newsyslog.d/xproxy.conf`,
30 days for access and error, 90 for security, 365 for audit) and sends
`SIGUSR1` so the files are reopened. To ship logs off the host, point a
forwarder at the directory or set `sinks: [syslog]` on a stream: macOS
`syslogd` accepts the local socket. `journald` is not available; the
configuration refuses it on macOS with a message naming the alternatives.

## Firewall

pf is installed but idle by default. Load the anchor and enable pf:

```sh
sudo sh -c 'printf "\nanchor \"xproxy\"\nload anchor \"xproxy\" from \"/usr/local/etc/xproxy/pf-xproxy.conf\"\n" >> /etc/pf.conf'
sudo pfctl -f /etc/pf.conf && sudo pfctl -e
sudo pfctl -a xproxy -sr                  # show the loaded rules
```

Edit `mgmt_net` and `proxy_ports` in the anchor first. pf is not enabled
across reboots by default; [HARDENING_MACOS.md](HARDENING_MACOS.md)
shows the launchd job that makes it persistent.

## Upgrading

```sh
make build-darwin && sudo sh deploy/macos/install.sh bin/darwin-arm64
```

The installer keeps the configuration and users file, replaces binaries,
profile and jobs, and restarts the data plane (there is no socket
activation on macOS, so a restart drops connections for the restart
time; `launchctl kill HUP` reloads without a restart when only the
configuration changed).

## Uninstall

```sh
sudo launchctl bootout system/com.sysctl.xproxy-admin
sudo launchctl bootout system/com.sysctl.xproxy
sudo rm /Library/LaunchDaemons/com.sysctl.xproxy*.plist /etc/sudoers.d/xproxy-admin /etc/newsyslog.d/xproxy.conf
sudo rm -r /usr/local/etc/xproxy /usr/local/var/log/xproxy /usr/local/var/run/xproxy /usr/local/var/lib/xproxy
sudo rm /usr/local/bin/xproxy /usr/local/bin/xproxyctl /usr/local/bin/xproxy-admin
sudo dscl . -delete /Users/_xproxy; sudo dscl . -delete /Users/_xproxy-admin; sudo dscl . -delete /Groups/_xproxy
```

Remove the `anchor "xproxy"` lines from `/etc/pf.conf` and reload pf.

## Differences from the Fedora installation

| Fedora | macOS |
|--------|-------|
| systemd unit with socket activation | launchd job; the daemon binds its own ports (allowed unprivileged) |
| `systemctl reload` (`Type=notify-reload`) | `launchctl kill HUP system/com.sysctl.xproxy` |
| SELinux module | Seatbelt profile (`sandbox-exec`) |
| In-process Landlock, seccomp, capability clearing | In-process debugger denial and core limit; file system and system call confinement from the profile |
| nftables per-source rate | pf anchor with `max-src-conn-rate` |
| logrotate | newsyslog |
| journald sink | file or syslog sinks |
| RPM | tarball plus `install.sh` |
| `/etc/xproxy`, `/run/xproxy`, `/var/log/xproxy`, `/var/lib/xproxy` | the same names under `/usr/local` |
