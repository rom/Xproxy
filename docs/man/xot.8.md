# xot

## NAME

xot - OT daemon: the control protocols and the plant's own infrastructure

## SYNOPSIS

`xot` [`-config` *FILE*] [`-validate`] [`-version`]

## DESCRIPTION

`xot` is the OT daemon: the one the plant talks to, and the one that
belongs at level 3.5 between a process network and everything else. It
reads one YAML configuration file (see `xproxy.yaml`(5)), binds the
listeners it describes or takes them from systemd socket activation, and
serves until stopped.

It serves the control protocols — `modbus`, `iec104`, `s7`, `mms`,
`bacnet`, `opcua` and `coap` — and the protocols the field equipment
itself speaks: `snmp`, `tftp`, `dhcp`, `dhcp6`, `syslog`, the `ntp` and
`ntske` time gateway, and `mqtt` for Sparkplug B telemetry. Those last
eight are served by `xrelay`(8) as well, because a data centre runs them
too; a listener of one of those kinds belongs to `xrelay` unless it says
`daemon: xot`. MQTT is in the set for a narrower reason: the device
inventory collects what one daemon saw, so an estate whose device births
arrive over Sparkplug needs them on the daemon that serves its Modbus.

What it does not serve is the point of it being a program of its own.
There is no mail parser in this binary, no FTP, no LDAP, no database
wire protocol and no AMQP: that code is in `xrelay`(8), and an attack on
the proxy in front of a process network has none of it to work with. It
is the same argument the first split was made for, applied to the daemon
whose failure mode is a plant.

A listener of another role in the same file is validated in full and
left to its owner, which is what lets the daemons share a set of
includes; a listener kind this binary did not link is never bound.

The process runs as the `xot` user under the shipped systemd unit and
confines itself with Landlock, seccomp and a dropped capability set (see
`docs/HARDENING.md`). It is controlled at run time through its own
management socket by `xproxyctl`(8).

## OPTIONS

| Option | Description |
|--------|-------------|
| `-config` *FILE* | Configuration file. Default `/etc/xproxy/xot.yaml` (`/usr/local/etc/xproxy/xot.yaml` on macOS). |
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
| `/etc/xproxy/xot.yaml` | Configuration, mode `0640`, owner `root:xot`. |
| `/run/xot/mgmt.sock` | Management socket, mode `0660`; `xproxyctl -socket` connects here. |
| `/var/log/xot/` | The access, error, security and audit logs when file sinks are configured. |
| `/var/lib/xot/` | State: the device inventory, learning reports, ban list and configuration history. |

## EXIT STATUS

0 after a clean stop or a successful `-validate`; 1 when the
configuration does not load, a listener cannot be bound or validation
fails; 2 on a usage error.

## ENVIRONMENT

`LISTEN_FDS`, `LISTEN_PID` and `LISTEN_FDNAMES` are read for systemd
socket activation. `NOTIFY_SOCKET` receives readiness and reload
notifications.

## SEE ALSO

`xproxy`(8), `xgate`(8), `xrelay`(8), `xproxyctl`(8), `xproxy.yaml`(5),
the documentation under `/usr/share/doc/xproxy/` (USAGE.md, CONFIG.md,
HARDENING.md, ARCHITECTURE.md).
