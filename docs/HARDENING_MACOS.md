# Hardening guide (macOS)

Host level measures for an xproxy host running macOS, in the order of
their impact, each with a verification step. The controls built into the
binary are the same as on Linux (see [SECURITY.md](SECURITY.md)); what
differs is the platform layer around the process. Where Fedora offers
systemd sandboxing, SELinux, Landlock and seccomp, macOS offers launchd,
the Seatbelt sandbox, System Integrity Protection, the hardened runtime
and pf. [SETUP_MACOS.md](SETUP_MACOS.md) covers the installation this
guide assumes.

## 1. Dedicated user, launchd job, no root

The job runs as `_xproxy` (hidden system user, no shell, home
`/var/empty`) with `Umask 027`, a file descriptor limit of 65536 and a
core size limit of zero. Ports below 1024 are bindable without
privilege on macOS 10.14 and newer, so the job never needs root and
never drops privileges: there is nothing to drop.

Verify:

```sh
sudo launchctl print system/com.sysctl.xproxy | grep -E 'state|pid|user|program'
ps -o user,pid,command -p "$(sudo launchctl print system/com.sysctl.xproxy | awk '/pid =/ {print $3}')"
```

## 2. Seatbelt profile

`deploy/macos/xproxy.sb` denies everything and admits what the daemon
needs: its own binary for exec, the configuration directory for reading,
the log, run and state directories for writing, the system resolver,
trust store and time zone files, the network, and the Mach services
every process uses (logging, notifications, trustd). The job passes the
profile to `sandbox-exec` and sets `XPROXY_SEATBELT` so the daemon can
report it in `xproxyctl sandbox`.

The profile is the macOS counterpart of the Linux Landlock rules the
process derives from its configuration; on macOS those rules cannot be
applied from inside a static binary, so they are explicit. When the
configuration names a file outside the admitted directories (a
certificate under `/opt`, a static root under `/Users/Shared/www`), add
a `file-read*` or `file-write*` line and restart. Narrow the network
lines to the ports in use once the configuration has settled.

Verify:

```sh
sudo xproxyctl sandbox                 # seatbelt: applied, profile /usr/local/etc/xproxy/xproxy.sb
sandbox-exec -f /usr/local/etc/xproxy/xproxy.sb /usr/local/bin/xproxy -config /usr/local/etc/xproxy/xproxy.yaml -validate
log stream --predicate 'sender == "Sandbox" and process == "xproxy"'   # denials while traffic runs
```

`sandbox-exec` is marked deprecated in Apple's headers but is present
and enforced on every current release; Apple's own daemons use the same
profile language. Watch the release notes of a new macOS version before
upgrading a proxy host.

## 3. In-process controls

On start the daemon denies debugger attachment (`PT_DENY_ATTACH`) and
sets its core size limit to zero, so no process of the same user can
read its memory with `lldb` or `vmmap` and a crash leaves no file with
keys or request data. `xproxyctl sandbox` shows `debuggable: applied`.
`sandbox.debuggable: true` in the configuration turns this off for a
debugging session and must not stay in production.

The WebAssembly compiler needs writable-then-executable memory. Under
the hardened runtime (a signed binary with `--options runtime`) that is
refused unless the `com.apple.security.cs.allow-jit` entitlement is
granted; the default `engine: auto` of the `wasm` filter detects the
refusal and uses the interpreter. Do not grant the entitlement to keep
the compiler: the interpreter is the safer choice on a proxy.

## 4. Code signing and the hardened runtime

Sign the binaries with a Developer ID or an internal certificate and
enable the hardened runtime so that the kernel refuses to load modified
code, injected libraries and debuggers, in addition to what the process
does itself:

```sh
codesign --force --options runtime --timestamp --sign "Developer ID Application: Example AB" /usr/local/bin/xproxy /usr/local/bin/xproxyctl /usr/local/bin/xproxy-admin
codesign --verify --verbose=2 /usr/local/bin/xproxy
spctl --assess --type execute /usr/local/bin/xproxy
```

No entitlements are needed. Re-sign after every upgrade; the installer
leaves signing to the operator because the identity is site specific.

## 5. System Integrity Protection and FileVault

Keep SIP enabled (`csrutil status`): it protects `/usr/bin/sandbox-exec`,
`launchd` and the system trust store from a root compromise. Enable
FileVault on a host that holds private keys or logs with personal data;
a proxy host normally runs headless, so store the recovery key in the
secrets system and prefer an institutional recovery key over a personal
one.

## 6. Firewall: pf

`deploy/macos/pf-xproxy.conf` drops all inbound traffic except SSH from
the management range and the proxy ports, with a per-source new
connection rate (`max-src-conn-rate 100/5`) that moves offenders to a
table for the state lifetime, plus the ICMP types needed for path MTU
discovery. The application firewall in System Settings is per
application and unsuited to a server; leave it off and use pf.

Make pf persistent across reboots:

```sh
sudo tee /Library/LaunchDaemons/com.sysctl.pf.plist >/dev/null <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.sysctl.pf</string>
  <key>ProgramArguments</key><array><string>/sbin/pfctl</string><string>-e</string><string>-f</string><string>/etc/pf.conf</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.sysctl.pf.plist
```

Verify: `sudo pfctl -si | head -3` shows `Status: Enabled`;
`sudo pfctl -a xproxy -sr` lists the anchor;
`sudo pfctl -t xproxy_abusers -T show` after a connection flood test.

## 7. Kernel network settings

macOS has no `sysctl.d`; settings are applied at boot by a launchd job.
The ones that matter for a public proxy:

```sh
sudo sysctl -w kern.ipc.somaxconn=4096 net.inet.tcp.msl=7500 net.inet.tcp.blackhole=2 net.inet.udp.blackhole=1 net.inet.icmp.icmplim=250
```

`somaxconn` is the accept queue for every listener; `blackhole` drops
segments and datagrams to closed ports without a reply; `msl` shortens
TIME_WAIT. Persist them with a `RunAtLoad` job that runs `sysctl -w`,
as for pf above. `kern.maxfiles` and `kern.maxfilesperproc` bound the
descriptor budget together with the job's `NumberOfFiles`.

## 8. File permissions and ownership

Same rules as on Fedora with the `/usr/local` prefix:

| Path | Owner | Mode |
|------|-------|------|
| `/usr/local/bin/xproxy*` | root:wheel | 0755 |
| `/usr/local/etc/xproxy` | root:_xproxy | 0750 |
| `/usr/local/etc/xproxy/xproxy.yaml` | _xproxy-admin:_xproxy | 0640 |
| `/usr/local/etc/xproxy/*.key` | root:_xproxy | 0640 |
| `/usr/local/etc/xproxy/xproxy.sb` | root:_xproxy | 0644 |
| `/usr/local/var/log/xproxy` | _xproxy:_xproxy | 0750 |
| `/usr/local/var/run/xproxy` | _xproxy:_xproxy | 0750 |
| `/usr/local/var/lib/xproxy` | _xproxy:_xproxy | 0700 |
| `/Library/LaunchDaemons/com.sysctl.xproxy*.plist` | root:wheel | 0644 |
| `/etc/sudoers.d/xproxy-admin` | root:wheel | 0440 |

Homebrew, when installed, makes `/usr/local` writable by the
administrator account; the directories above are created by the
installer with explicit owners and must stay that way. Verify with
`ls -la /usr/local/etc/xproxy /usr/local/var/*/xproxy` and
`sudo -l -U _xproxy-admin`.

## 9. Management access

The management socket is reachable by the `_xproxy` group; the daemon
reads the caller's user and process id from the kernel
(`LOCAL_PEERCRED`, `LOCAL_PEERPID`) and writes both to the audit log.
Review group membership periodically:
`dscl . -read /Groups/_xproxy GroupMembership`. The web GUI listens on
the loopback address; expose it only through SSH or with client
certificates.

## 10. Logging and retention

`newsyslog` keeps 30 days of access and error logs, 90 of security and
365 of audit, compressed, and signals the daemon to reopen. Ship the
security and audit streams off the host (a forwarder on the directory or
`sinks: [syslog]`), because a compromised host can edit its own files.
Time Machine and other backups should exclude the log directory or the
retention policy in `logging.<stream>.max_files` becomes meaningless.

## 11. Updates

Track releases and rebuild with the current Go toolchain for standard
library fixes; the macOS binaries are cross compiled by the same
`make dist-darwin` that produces the Linux artefacts, so a release
covers both. Keep macOS itself on a supported version: the Seatbelt
profile language and `pf` change only between major versions, and the
release notes name such changes.

## Verification checklist

```
[ ] launchctl print shows the job running as _xproxy under sandbox-exec
[ ] xproxyctl sandbox: debuggable applied, seatbelt applied
[ ] no Sandbox denials for xproxy in `log stream` after a traffic run
[ ] codesign --verify passes; hardened runtime flag set
[ ] csrutil status: enabled; FileVault on hosts with keys or personal data
[ ] pfctl -si: Enabled; anchor xproxy loaded; persistent job installed
[ ] kernel settings applied at boot
[ ] file ownership and modes as in section 8; sudoers fragment unchanged
[ ] _xproxy group membership reviewed
[ ] xproxy -validate clean; trusted_proxies reviewed
[ ] security and audit logs shipped off host
```
