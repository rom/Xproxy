# xrelay

## NAME

xrelay - relay daemon: SMTP, MQTT, FTP and syslog proxies

## SYNOPSIS

`xrelay` [`-config` *FILE*] [`-validate`] [`-version`]

## DESCRIPTION

`xrelay` is the relay: the daemon machines talk to. It reads one YAML
configuration file (see `xproxy.yaml`(5)), binds the listeners it
describes or takes them from systemd socket activation, and serves until
stopped.

It serves the listener kinds of the relay role: `smtp` (mail and
submission, with STARTTLS), `mqtt` (3.1.1 and 5.0), `ftp` and `syslog`.
There are no interactive sessions here and no recordings; the traffic
comes from devices and services, and the policy is written in each
protocol's own terms — which commands, topics, facilities and paths are
allowed, and what the relay does with a message it will not pass.

The internet-facing HTTP machinery its sibling `xproxy`(8) runs, and the
interactive access its sibling `xgate`(8) mediates, are separate programs
and separate processes with separate users. A listener of another role in
the same file is validated in full and left to its owner, which is what
lets the three share a set of includes; a listener kind this binary did
not link is never bound.

The process runs as the `xrelay` user under the shipped systemd unit and
confines itself with Landlock, seccomp and a dropped capability set (see
`docs/HARDENING.md`). It is controlled at run time through its own
management socket by `xproxyctl`(8).

## OPTIONS

| Option | Description |
|--------|-------------|
| `-config` *FILE* | Configuration file. Default `/etc/xproxy/xrelay.yaml` (`/usr/local/etc/xproxy/xrelay.yaml` on macOS). |
| `-validate` | Load and validate the configuration, report every problem, and exit with status 0 when it is valid and 1 otherwise. Nothing is bound. The whole file is checked, siblings' listeners included, and the summary says how many of them this daemon would serve. |
| `-version` | Print the version, commit and build date, and exit. |

## SIGNALS

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Reload the configuration. A new generation is built and validated first; on error the running one stays active. |
| `SIGUSR1` | Reopen the log files (used by logrotate). |
| `SIGTERM`, `SIGINT` | Stop: listeners close, in-flight sessions get `server.shutdown_timeout` to finish, then the process exits. |

## FILES

| Path | Purpose |
|------|---------|
| `/etc/xproxy/xrelay.yaml` | Configuration, mode `0640`, owner `root:xrelay`. |
| `/run/xrelay/mgmt.sock` | Management socket, mode `0660`; `xproxyctl -socket` connects here. |
| `/var/log/xrelay/` | The access, error, security and audit logs when file sinks are configured. |
| `/var/lib/xrelay/` | State: ban list and configuration history. |

## EXIT STATUS

0 after a clean stop or a successful `-validate`; 1 when the
configuration does not load, a listener cannot be bound or validation
fails; 2 on a usage error.

## ENVIRONMENT

`LISTEN_FDS`, `LISTEN_PID` and `LISTEN_FDNAMES` are read for systemd
socket activation. `NOTIFY_SOCKET` receives readiness and reload
notifications.

## SEE ALSO

`xproxy`(8), `xgate`(8), `xproxyctl`(8), `xproxy.yaml`(5), the
documentation under `/usr/share/doc/xproxy/` (USAGE.md, CONFIG.md,
HARDENING.md, ARCHITECTURE.md).
