# xgate

## NAME

xgate - gate daemon: SSH bastion with session recording and SFTP mediation

## SYNOPSIS

`xgate` [`-config` *FILE*] [`-validate`] [`-version`]

## DESCRIPTION

`xgate` is the gate: the daemon people log into. It reads one YAML
configuration file (see `xproxy.yaml`(5)), binds the listeners it
describes or takes them from systemd socket activation, and serves until
stopped.

It serves the listener kinds of the gate role, which today is `ssh`: the
bastion, its per-principal policy, its SFTP mediation and its session
recording. A session belongs to a named principal, is recorded to an
asciicast file, can be made to carry a second factor, and is bounded by a
policy written in SSH's own terms — which channels, requests,
subsystems, commands, environment variables and forwards are allowed —
rather than by a destination list.

The internet-facing HTTP machinery its sibling `xproxy`(8) runs is a
separate program and a separate process with a separate user. A listener
of another role in the same file is validated in full and left to its
owner, which is what lets the three share a set of includes; a listener
kind this binary did not link is never bound.

The process runs as the `xgate` user under the shipped systemd unit and
confines itself with Landlock, seccomp and a dropped capability set (see
`docs/HARDENING.md`). It is controlled at run time through its own
management socket by `xproxyctl`(8).

## OPTIONS

| Option | Description |
|--------|-------------|
| `-config` *FILE* | Configuration file. Default `/etc/xproxy/xgate.yaml` (`/usr/local/etc/xproxy/xgate.yaml` on macOS). |
| `-validate` | Load and validate the configuration, report every problem, and exit with status 0 when it is valid and 1 otherwise. Nothing is bound. The whole file is checked, siblings' listeners included, and the summary says how many of them this daemon would serve. |
| `-version` | Print the version, commit and build date, and exit. |

## SIGNALS

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Reload the configuration. A new generation is built and validated first; on error the running one stays active. |
| `SIGUSR1` | Reopen the log files (used by logrotate). |
| `SIGTERM`, `SIGINT` | Stop: listeners close, live sessions get `server.shutdown_timeout` to finish, then the process exits. |

## FILES

| Path | Purpose |
|------|---------|
| `/etc/xproxy/xgate.yaml` | Configuration, mode `0640`, owner `root:xgate`. |
| `/run/xgate/mgmt.sock` | Management socket, mode `0660`; `xproxyctl -socket` connects here. |
| `/var/log/xgate/` | The access, error, security and audit logs when file sinks are configured. |
| `/var/lib/xgate/` | State: ban list, configuration history, session recordings. |

## EXIT STATUS

0 after a clean stop or a successful `-validate`; 1 when the
configuration does not load, a listener cannot be bound or validation
fails; 2 on a usage error.

## ENVIRONMENT

`LISTEN_FDS`, `LISTEN_PID` and `LISTEN_FDNAMES` are read for systemd
socket activation. `NOTIFY_SOCKET` receives readiness and reload
notifications.

## SEE ALSO

`xproxy`(8), `xrelay`(8), `xproxyctl`(8), `xproxy.yaml`(5), the
documentation under `/usr/share/doc/xproxy/` (USAGE.md, CONFIG.md,
HARDENING.md, ARCHITECTURE.md).
