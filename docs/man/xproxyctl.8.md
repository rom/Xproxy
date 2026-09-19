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
| `waf` [`rules`\|`proposals`\|`exclusions`\|`reset`] | WAF profiles, counters and the most matched rules (`-top` *N*); `proposals` lists learned exclusion candidates, `exclusions` prints them as SecLang, `reset` clears the statistics |
| `rotate-secret` [`-keep` *N*] *FILE* | Add a fresh primary key to a secret file, keeping *N* (default 2) previous keys for verification; then `reload` |
| `reload-certs` | Re-read certificate files |
| `reopen-logs` | Reopen log files |
| `tail` *STREAM* | Follow `access`, `error`, `security` or `audit` |
| `bans` | List active bans with expiry, source and count |
| `ban` [`-duration` *D*] [`-reason` *TEXT*] *TARGET* | Ban an address or CIDR (default one hour) |
| `unban` *TARGET* | Remove a ban |
| `cluster` | Peers, inbound connections and gossip counters |
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
| `spki` *CERT.pem* | Print the `spki_pins` value of a certificate |
| `metrics` | Print the Prometheus exposition |
| `series` [`-since` *D*] [`-last` *N*] | Print sampled series |
| `tui` [`-refresh` *D*] [`-no-color`] | Full-screen live view (`NO_COLOR` also disables colours) |
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
