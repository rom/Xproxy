# xproxyctl

## NAME

xproxyctl - control and inspect a running xproxy

## SYNOPSIS

`xproxyctl` [`-socket` *PATH*] [`-config` *PATH*] [`-json`] *COMMAND* [*ARGS*]

## DESCRIPTION

`xproxyctl` talks to the management socket of `xproxy`(8) and prints
status, applies operations and follows logs. The user running it must be
in the `xproxy` group (the socket is mode `0660`) or be root. Commands
that need the configuration file (`validate`, `reload`, `tail`) read it
locally; everything else goes through the socket.

## OPTIONS

| Option | Description |
|--------|-------------|
| `-socket` *PATH* | Management socket. Default `/run/xproxy/mgmt.sock`. |
| `-config` *PATH* | Configuration file for `validate`, `reload` and `tail`. Default `/etc/xproxy/xproxy.yaml`. |
| `-json` | Machine readable output for the status views (`status`, `stats`, `upstreams`, `quotas`, `waf`, `sandbox`, `tls`, `series` and the others). |

## COMMANDS

| Command | Description |
|---------|-------------|
| `status` | Version, pid, generation, listeners, counters, sandbox state |
| `stats` | Counters only |
| `upstreams` | Endpoints with health, ejection, active requests, request and error counts |
| `quotas` [`-top` *N*] | Usage per tenant, per route and per rate limit policy with the top consumers, plus request share per upstream |
| `config` | Active configuration as YAML, defaults filled in |
| `validate` | Validate the configuration file locally |
| `reload` [`-dry-run`] | Validate locally, then ask the daemon to reload; `-dry-run` shows what the file would change (per item, restart list, connection drains, text diff) without applying |
| `diff` [*FROM*] [*TO*] | Compare `active`, `file` or a history id (default `active file`); exit status 1 when they differ |
| `history` | Recorded configurations with generation, time, note and size (needs `management.history_dir`) |
| `rollback` *ID* | Apply a recorded configuration (audited; becomes a new history entry) |
| `tls` | Served certificates per listener: names, issuer, expiry, source, OCSP staple state and Certificate Transparency verdict |
| `tls tickets` | Session ticket keys: epoch, next rotation, key count, fingerprint and which cluster peers derive the same set |
| `sandbox` | In-process hardening: each mechanism with its state and the file rules in force |
| `waf` [`rules`\|`proposals`\|`anomalies`\|`exclusions`\|`reset`] | WAF profiles (with their CRS plugins and JSON schemas), counters and the most matched rules (`-top` *N*); `proposals` lists learned exclusion candidates, `anomalies` the behavioural baseline and flagged clients, `exclusions` prints the proposals as SecLang, `reset` clears the statistics |
| `rotate-secret` [`-keep` *N*] *FILE* | Add a fresh primary key to a secret file, keeping *N* (default 2) previous keys for verification; then `reload` |
| `reload-certs` | Re-read certificate files |
| `reopen-logs` | Reopen log files |
| `tail` *STREAM* | Follow `access`, `error`, `security` or `audit` |
| `bans` | List active bans with expiry, source and count |
| `ban` [`-duration` *D*] [`-reason` *TEXT*] *TARGET* | Ban an address, a CIDR or a TLS fingerprint as `ja4:`*FP* (default one hour) |
| `unban` *TARGET* | Remove a ban |
| `cluster` | Peers, inbound connections and gossip counters |
| `api` [`all`\|`shadow`\|`zombie`\|`versions`\|`documented`\|`undocumented`] | API inventory discovered from traffic: host, method, path template, route, version, state (documented, shadow, zombie, superseded), counts, credentials seen and last seen (`-top` *N*); with `-openapi` [`-title` *T*] the view as an OpenAPI 3.0 skeleton in YAML |
| `patches` | Virtual patches with state (active, disabled, expired), action, hits, last hit and expiry |
| `policy` [`report`\|`reset`] [`-top` *N*] | What the listeners in shadow mode would have refused and did not: the count, the kind, the listener, the reason, the rule that decided, when it was first and last seen, and one example of what was asked for, most frequent first. `reset` empties the ledger, which is what an operator does after fixing a policy so the next report is about the new one. Shadow mode is `policy: {mode: shadow}` for the estate or for one listener; it covers policy only -- authentication, bans, rate limits, bounds and malformed input are refused in shadow mode too |
| `sessions` [`-kill` *ID*] [`-kill-matching` `-kind` *K* `-listener` *L* `-user` *U*] | The sessions the daemon is serving now — SSH, SFTP, telnet, VNC, RDP, FTP and the Modbus device queues — oldest first: the identifier, the kind, the listener, where the client came from, the login, the target it reached, one detail the kind chose (the desktop's name, the unit identifier, the subsystem) and how long it has been up. `-kill` *ID* closes one; `-kill-matching` closes every session matching the `-kind`, `-listener` and `-user` given, and refuses to run with none of them, so a filter is never accidentally everything. A session is registered before its handshake finishes, so one stuck in a handshake is listed and can be closed. Every closure is written to the audit log with who asked. The names, logins and details came off the network and are clipped and filtered before they are printed. This is the live table; `session` (singular) reads recordings back from disk |
| `session` `list` *DIR* \| `show` [`-safe`] [`-input`] *FILE* \| `play` [`-speed` *N*] [`-plain`] *FILE* | Read a recorded gate session back. `list` names the recordings in a directory with their size, start, dimensions and title; `show` prints what the session showed, and `play` replays it with its timing. The escape sequences that reach outside the window a replay is drawn in are never forwarded: a recording is the bytes a session sent, and a terminal is an interpreter of exactly those bytes, so writing one out unfiltered lets a recorded session set the reviewer's clipboard (OSC 52), retitle their window, or ask for a device report — which the terminal answers on its own input, and a shell reads as a command line. `show` keeps the text and drops every sequence; `-safe` keeps the colours and cursor movement and writes the rest out inert; `play` is `-safe` by default and `-plain` is the reading view. The file itself is never rewritten |
| `capture` [`status`\|`start` [`-duration` *D*]\|`stop`] | Packet capture of the exchanges the proxy handled, written as pcapng: whether it is recording, when the window ends, the current file and the per rule counters; `start` opens a window (*D*, bounded by `capture.max_duration`), `stop` closes it. The files hold decrypted request and response bytes |
| `fleet` | Fleet agent state: controller, node id, applied bundle digest and result, pending bundle, poll and report counters |
| `accounts` [`-top` *N*] | Account guard state: endpoints with tracked addresses, accounts and pairs, active blocks (*N* per endpoint), window totals, campaign state and the action counters |
| `maintenance` [`on`\|`off`] | Show or set maintenance mode (holds every request but the allowlist behind a 503) |
| `origin-check` [*upstream*] [`-host` *H*] [`-path` *P*] | Probe origins directly to verify origin-lock is enforced: an unsigned and a signed request per endpoint of every upstream with an `origin_signature` (or the named one), reporting the verdict and exiting non-zero if any origin is not `enforced` |
| `botscore` [`-top` *N*] | Learning-mode `bot_score` baselines: per-route score percentiles and suggested `challenge_at`/`deny_at` from observed traffic (needs `learn: true`) |
| `acme` [`renew`] | Managed certificates with expiry, issuer and last error; `renew` forces renewal and waits |
| `icap` | ICAP services with reachability, preview size, ISTag and counters |
| `filters` | Middleware API version, registered kinds, configured filters with routes and deny counts |
| `geoip` | Country database kind, path, build date, lookup and unknown counters |
| `cache` [`purge` [*HOST* [*PATH-PREFIX*]]] | Cache entries, bytes and counters; `purge` removes entries |
| `honeypot` [`forget` *IP*] | Clients marked by honeypot routes; `forget` removes a mark |
| `dns` [`purge`] | DNS listener counters; `purge` empties the caches |
| `ingress` | Kubernetes ingress controller status |
| `otlp` | OpenTelemetry metrics exporter status |
| `telemetry` | Every OpenTelemetry exporter with sent, dropped, pushes, failures, queue depth and last error |
| `htpasswd` *FILE* *NAME* | Add or replace a `basic_auth` user; the password is read from standard input |
| `apikey` `add`\|`rotate`\|`revoke`\|`remove`\|`list` [*ID*] [`-file` *PATH*] [`-scopes` *A,B*] [`-expires` *90d*] [`-note` *TEXT*] [`-grace` *24h*] | Manage the keys file of `api_key` filters: `add` prints the plaintext once, `rotate` issues a new secret and keeps the old one for the grace period, `revoke` and `remove` retire a key, `list` shows the file |
| `mfa` `enrol`\|`verify`\|`list` [`-user` *NAME*] [`-file` *PATH*] [`-issuer` *NAME*] [`-digits` *N*] [`-period` *N*] [`-algo` *A*] [`-recovery` *N*] [`-code` *CODE*] [`-skew` *N*] | Second factors in the enrolment file: `enrol` prints the line, the `otpauth://` URI and the recovery codes once, `verify` checks a code, `list` shows who is enrolled. Listeners re-read the file, so a change applies without a reload |
| `spki` *CERT.pem* | Print the `spki_pins` value of a certificate |
| `metrics` | Print the Prometheus exposition |
| `series` [`-since` *D*] [`-last` *N*] | Print sampled series |
| `tui` [`-refresh` *D*] [`-no-color`] | Full-screen live view (`NO_COLOR` also disables colours). Ten screens, selected with `1`-`9` and `0` or with tab; on the bans screen `j`/`k` select, `u` unbans and `b` bans, on the MFA screen `j`/`k` select, `u` unlocks a person who guessed wrong too often and `x` removes their second factor |
| `schema` | Print the JSON schema of the configuration (also installed at `/usr/share/xproxy/xproxy.schema.json`) |
| `completion` `bash`\|`zsh`\|`fish` | Print a completion script for `xproxyctl` and `xproxy` |
| `help` | List the commands with a summary |
| `version` | Print version |

## EXIT STATUS

0 on success; 1 when the daemon reports an error or cannot be reached;
2 on a usage error. `diff` exits 1 when the two configurations differ.

## FILES

`/run/xproxy/mgmt.sock`, `/etc/xproxy/xproxy.yaml`.

## EXAMPLES

```
xproxyctl status
xproxyctl -json stats | jq .denied_rate_limit
xproxyctl tail security | jq -c '{t:.time, ip:.client_ip, r:.reason}'
xproxyctl reload -dry-run
xproxyctl ban -duration 24h -reason "credential stuffing" 203.0.113.0/24
xproxyctl rotate-secret /var/lib/xproxy/challenge.key && xproxyctl reload
xproxyctl completion bash > /etc/bash_completion.d/xproxyctl
```

## SEE ALSO

`xproxy`(8), `xproxy.yaml`(5), `docs/USAGE.md`.
