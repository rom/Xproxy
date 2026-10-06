# xproxy-admin

## NAME

xproxy-admin - web interface for xproxy, in a process of its own

## SYNOPSIS

`xproxy-admin serve` [`-listen` *ADDR*] [`-socket` *PATH*] [`-config` *PATH*] [`-users` *PATH*] [`-tls-cert` *PATH* `-tls-key` *PATH* [`-client-ca` *PATH*]] [`-restart-cmd` *COMMAND*] [`-validate`]

`xproxy-admin user add` *NAME* [`-role` viewer|operator] [`-cert-only`]

`xproxy-admin user del` *NAME*

`xproxy-admin user list`

`xproxy-admin passwd` *NAME*

`xproxy-admin version`

## DESCRIPTION

`xproxy-admin` serves the browser interface for `xproxy`(8) and its siblings. It
is a separate program and a separate process, and that is the point: the data
plane terminates TLS for an estate and has no business also parsing session
cookies, rendering HTML and writing configuration files. Everything this process
decides it decides for itself; everything it *does* it asks the management socket
to do, which is the same socket `xproxyctl`(8) uses and the same authorisation.

It holds no copy of the proxy's state. Each page is a question put to the
management socket and the answer rendered, so a GUI that is out of date is a GUI
that cannot reach the socket, which it says rather than showing a stale number.

**What it can change** is what the socket exposes: the ban list, the WAF's mode
and rule statistics, rate-limit and quota state, listener drain and
maintenance, live sessions (list and kill), MFA enrolments, API keys, work
orders against OT devices, the behaviour packs, and — with `-config` — the
configuration file itself, through the same dry-run, diff and rollback path
`xproxyctl policy` uses. A change is written, validated by the data plane, and
either applied or refused with the reason.

### Where it may listen

A plaintext listener is permitted on the loopback address and a Unix socket, and
nowhere else: any other address requires `-tls-cert`, `-tls-key` **and**
`-client-ca`, and the process refuses to start otherwise. This is not advice in
the documentation, it is a check in the code, because the alternative is an
interface that can restart the estate's proxy reachable over the office network
behind a password. The shipped unit binds `127.0.0.1:8443` and expects an SSH
tunnel:

```
ssh -L 8443:127.0.0.1:8443 proxyhost
```

### Who may log in

Two roles. A **viewer** reads every page and changes nothing. An **operator** may
act: everything in *What it can change* above. The roles live in the users file,
one `name:role:hash` line each, re-read whenever it changes on disk — so
removing a user or downgrading a role takes effect without a restart, because
revocation that needs a restart is revocation that silently does not happen.

Three ways to authenticate, which compose:

- A **password** from the users file (PBKDF2-HMAC-SHA256). Failed logins are
  rate limited per account.
- A **client certificate**, when `-client-ca` is set: the common name is the user
  name. `user add -cert-only` creates a user with no password at all, which is
  the arrangement worth having — there is then no password to guess.
- **Single sign-on**, when `-oidc-issuer` is set: the role comes from a claim
  (`-oidc-role-claim`, default `groups`) matched against `-oidc-operators` and
  `-oidc-viewers`.

Sessions are bounded twice, by idle time (`-session-idle`) and absolutely
(`-session-max`), because a browser tab left open overnight is not a reason to
stay logged in.

## OPTIONS

### serve

| Option | Description |
|--------|-------------|
| `-listen` *ADDR* | `host:port` or `unix:/path`. Default `127.0.0.1:8443`. A non-loopback address requires `-tls-cert`, `-tls-key` and `-client-ca`. |
| `-socket` *PATH* | Management socket of the data plane. Default `/run/xproxy/mgmt.sock`. |
| `-config` *PATH* | The data plane's configuration file, which operators may then edit through the GUI, and which the log view reads paths from. Empty disables editing and the log view. |
| `-users` *PATH* | Users file. Default `/etc/xproxy/admin-users`. |
| `-tls-cert`, `-tls-key` *PATH* | Server certificate and key, PEM. They go together. |
| `-client-ca` *PATH* | Require a client certificate from this CA; its common name is the user. Needs `-tls-cert`. |
| `-restart-cmd` *COMMAND* | Command behind the restart action, split on spaces and run **without a shell**. Empty disables the action. |
| `-session-idle` *DURATION* | Session idle timeout. Default 30m. |
| `-session-max` *DURATION* | Session absolute lifetime. Default 12h. |
| `-oidc-issuer` *URL* | OpenID Connect issuer; setting it enables single sign-on. |
| `-oidc-client-id`, `-oidc-client-secret-file` | The client registration. |
| `-oidc-external-url` *URL* | Address users reach the GUI at, for the redirect URI. Default: taken from the request. |
| `-oidc-ca` *PATH* | CA that signs the provider's certificate. Default: the system pool. |
| `-oidc-scopes` *LIST* | Scopes requested, comma separated. Default `openid,profile,email`. |
| `-oidc-user-claim`, `-oidc-role-claim` | Which claims name the user and carry the role. Defaults `email` and `groups`. |
| `-oidc-operators`, `-oidc-viewers` *LIST* | Role claim values granting each role, comma separated. `*` in `-oidc-viewers` accepts every authenticated user. |
| `-validate` | Check the options, the users file, the certificates, the configuration file and the restart command, print what was found, and exit without binding anything. |

### user, passwd

| Option | Description |
|--------|-------------|
| `-users` *PATH* | Users file. |
| `-role` viewer\|operator | The role for `user add`. Default `viewer`. |
| `-cert-only` | Create the user with no password; they log in with a client certificate whose common name is the user name. |

A password is read from the terminal without echo, or from standard input when
that is not a terminal, one line — so `passwd` works from a provisioning script
without a password ever appearing in a command line.

## VALIDATION

`-validate` is the check worth running from a unit file's `ExecStartPre` or by
hand after an edit. `serve` already refuses a configuration that contradicts
itself — a non-loopback address without mutual TLS, a certificate without a key,
a users file that will not parse — but those are decisions about the options.
`-validate` additionally *touches the files*: the certificate and key must pair,
the client CA must hold a certificate, the configuration file must be readable
by this process, and the restart command must exist on the system. Each of those
otherwise fails at its first use, and the first use of the restart command is an
operator pressing the button during an incident.

## EXIT STATUS

0 on success, 1 on a configuration, file or runtime error, 2 on a usage mistake.

## EXAMPLES

Create the first operator and check what would start:

```
xproxy-admin user add admin -role operator
xproxy-admin serve -validate -users /etc/xproxy/admin-users -config /etc/xproxy/xproxy.yaml
```

Serve on an internal address, with client certificates as the only credential:

```
xproxy-admin user add alice -role operator -cert-only
xproxy-admin serve -listen 10.0.0.5:8443 \
  -tls-cert /etc/xproxy/tls/gui.pem -tls-key /etc/xproxy/tls/gui-key.pem \
  -client-ca /etc/xproxy/tls/operators-ca.pem
```

## FILES

| Path | What |
|------|------|
| `/etc/xproxy/admin-users` | The users file, mode 0600, written atomically. |
| `/run/xproxy/mgmt.sock` | The management socket this process asks. |
| `/usr/share/polkit-1/rules.d/50-xproxy-admin.rules` | Authorises the restart action for the `xproxy-admin` user, so the process needs no general privilege. |

## SEE ALSO

`xproxy`(8), `xgate`(8), `xrelay`(8), `xot`(8), `xproxyctl`(8),
`xproxy.yaml`(5), `docs/HARDENING.md`
