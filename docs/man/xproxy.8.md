# xproxy

## NAME

xproxy - edge data plane: reverse proxy, web application firewall and load balancer

## SYNOPSIS

`xproxy` [`-config` *FILE*] [`-validate`] [`-version`]

## DESCRIPTION

`xproxy` is the edge data plane: the daemon that faces the internet. It
reads one YAML configuration file (see `xproxy.yaml`(5)), binds the
listeners it describes or takes them from systemd socket activation, and
serves until stopped. Requests pass the listener limits, the ban list,
rate limits, the web application firewall, the configured filters and the
route action, then reach an upstream pool with health checks, retries and
circuit breaking.

It serves the listener kinds of the edge role: `http` (the default),
`forward`, `tcp` and `dns`. Its siblings `xgate`(8) and `xrelay`(8) serve
the kinds people log into and the kinds machines talk to. A listener of
another role in the same file is validated in full and left to its owner,
which is what lets the three share a set of includes; a listener kind
this binary did not link is never bound and never falls through to the
HTTP data plane.

The process runs as the `xproxy` user under the shipped systemd unit and
confines itself with Landlock, seccomp and a dropped capability set (see
`docs/HARDENING.md`). It is controlled at run time through the management
socket by `xproxyctl`(8) and, when installed, the web GUI process
`xproxy-admin`.

## OPTIONS

| Option | Description |
|--------|-------------|
| `-config` *FILE* | Configuration file. Default `/etc/xproxy/xproxy.yaml` (`/usr/local/etc/xproxy/xproxy.yaml` on macOS). |
| `-validate` | Load and validate the configuration, report every problem, and exit with status 0 when it is valid and 1 otherwise. Nothing is bound. |
| `-version` | Print the version, commit and build date, and exit. |

## SIGNALS

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Reload the configuration. A new generation is built and validated first; on error the running one stays active and the failure is counted. Listeners are added, removed and rebuilt as the file changed; see the reload semantics in `xproxy.yaml`(5). |
| `SIGUSR1` | Reopen the log files (used by logrotate). |
| `SIGTERM`, `SIGINT` | Stop: listeners close, in-flight requests get `server.shutdown_timeout` to finish, then the process exits. |

Under systemd use `systemctl reload xproxy` and `systemctl restart
xproxy`; the unit maps them to these signals and socket activation keeps
the listening sockets across a restart.

## FILES

| Path | Purpose |
|------|---------|
| `/etc/xproxy/xproxy.yaml` | Configuration, mode `0640`, owner `root:xproxy`. |
| `/etc/xproxy/*.yaml` | Fragments named by `includes`. |
| `/run/xproxy/mgmt.sock` | Management socket, mode `0660`; `xproxyctl` and the GUI connect here. |
| `/var/log/xproxy/` | The access, error, security and audit logs when file sinks are configured. |
| `/var/lib/xproxy/` | State: ban list, configuration history, ACME account and certificates, secret keyrings. |
| `/usr/share/xproxy/xproxy.schema.json` | JSON schema of the configuration for editors. |

## EXIT STATUS

0 after a clean stop or a successful `-validate`; 1 when the
configuration does not load, a listener cannot be bound or validation
fails; 2 on a usage error.

## ENVIRONMENT

`LISTEN_FDS`, `LISTEN_PID` and `LISTEN_FDNAMES` are read for systemd
socket activation. `NOTIFY_SOCKET` receives readiness and reload
notifications. `NO_COLOR` is honoured by `xproxyctl tui`.

## SEE ALSO

`xgate`(8), `xrelay`(8), `xproxyctl`(8), `xproxy.yaml`(5), the documentation under
`/usr/share/doc/xproxy/` (USAGE.md, CONFIG.md, HARDENING.md,
ARCHITECTURE.md).
