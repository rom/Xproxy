# Usage

Day to day operation of xproxy: running the daemons, the control tool,
configuration patterns and reading the logs. Installation is covered in
[SETUP.md](SETUP.md), the full configuration reference in
[CONFIG.md](CONFIG.md) and diagnosing a misbehaving proxy in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Binaries

| Binary | Purpose |
|--------|---------|
| `xproxy` | The edge data plane: `http`, `forward`, `tcp` and `dns` listeners |
| `xgate` | The gate: `ssh` listeners — the bastion, its SFTP mediation and its session recording |
| `xrelay` | The relay: `smtp`, `mqtt`, `ftp` and `syslog` listeners |
| `xproxyctl` | Control tool talking to a daemon's Unix socket |
| `xproxy-admin` | Web GUI: a separate process serving a browser interface over the same socket |

### The three daemons

`xproxy`, `xgate` and `xrelay` are the same program with different
protocol code linked into them, split by who is on the other end of the
socket: the open internet, a person, or a machine. Run only the ones you
need — a site with no bastion never installs `xgate`, and the SSH and
SFTP implementation is then not present on the machine at all, rather
than present and unconfigured.

They take the same flags, read the same configuration format, and are
controlled by the same `xproxyctl` over a socket each:

```
xproxy -config /etc/xproxy/xproxy.yaml     # run
xgate  -config /etc/xproxy/xgate.yaml
xrelay -config /etc/xproxy/xrelay.yaml

xproxy -config file.yaml -validate         # validate and exit 0/1
xproxy -version
```

A daemon validates every listener in the file it is given, including
kinds its siblings serve, and binds only its own; the rest are named in
the error log at start under `listeners left to a sibling daemon`. A
listener kind the binary did not link is never bound and never falls
through to the HTTP data plane — it is an error naming the daemon that
does serve it. That refusal is what makes the split worth having: a port
answering the wrong protocol is worse than a port that does not answer.

Keep what is common to the estate in `includes` and give each daemon a
file of its own for `management`, `metrics` and `logging`. Those three
name a socket, an address and a directory, and two processes cannot
share any of them.

The daemons refuse to start as uid 0. Privileged ports come from
systemd socket activation (or a capability), and the shipped unit
already runs as `User=xproxy`, so root buys nothing and costs every
mitigation that a separate user provides. `-allow-root` starts anyway
and says so in the security log on every start, for the rare
environment that has no other way to bind.

Validation has two channels. An error stops the start; *advice* is a
configuration that loads but is a bad idea — an empty
`cluster.tls.allowed_names`, `bind_node_id` off, a `kind: dns` listener
on a public address with neither `allow_clients` nor `rate_limit`. It
is printed by `-validate` and logged as `configuration advice` at every
start and reload.

Signals:

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Re-read and apply the configuration; on error the old one stays |
| `SIGUSR1` | Reopen log files (after external rotation) |
| `SIGTERM`, `SIGINT` | Drain within `server.shutdown_timeout`, then exit |

Under systemd use `systemctl reload xproxy` and `systemctl restart xproxy`
(likewise `xgate` and `xrelay`);
on macOS `launchctl kill HUP system/com.sysctl.xproxy` and `launchctl
kickstart -k system/com.sysctl.xproxy`. A reload that names a file
outside the directories the sandbox admitted at start is refused with
"restart to apply"; `xproxyctl sandbox` lists those directories.
With socket activation a restart does not lose the listening socket, so
listener changes (which reload refuses) cost only the drain time.

### xproxyctl

```
xproxyctl [-socket /run/xproxy/mgmt.sock] [-config /etc/xproxy/xproxy.yaml] [-json] COMMAND
```

One `xproxyctl` talks to all three daemons; `-socket` picks which.
`/run/xgate/mgmt.sock` and `/run/xrelay/mgmt.sock` are where the shipped
units put the other two.

| Command | Description |
|---------|-------------|
| `status` | Version, pid, generation, listeners, counters |
| `stats` | Counters only |
| `upstreams` | Table of endpoints with health, ejection, active requests, request and error counts |
| `quotas` | Usage per tenant, per route (requests by class, denied, rate limited, bytes) and per rate limit policy (decisions, top consumers with tokens left, `-top 10`), plus request share per upstream |
| `config` | Active configuration as YAML, defaults filled in |
| `validate` | Validate the configuration file locally |
| `reload` | Validate locally, then ask the daemon to reload; `-dry-run` shows what the file would change (per item, restart list, text diff) without applying |
| `diff [FROM] [TO]` | Compare `active`, `file` or a history id (default `active file`); exit status 1 when they differ |
| `history` | Recorded configurations with generation, time, note and size (needs `management.history_dir`) |
| `rollback ID` | Apply a recorded configuration (audited; becomes a new history entry) |
| `tls` | Served certificates per listener: names, issuer, expiry, source (file or ACME), OCSP staple state and Certificate Transparency verdict |
| `tls tickets` | Session ticket keys: epoch, next rotation, key count, fingerprint and which cluster peers derive the same set |
| `sandbox` | In-process hardening: platform, each mechanism (Landlock, seccomp, capabilities, no_new_privs, debuggable; Seatbelt on macOS) with applied, unavailable, failed or disabled and a detail, the Landlock ABI and the read and write rules in force |
| `waf [rules\|proposals\|exclusions\|reset]` | WAF profiles with rule set source and version, route assignments, counters and the most matched rules (`-top 20`); `proposals` lists learned exclusion candidates, `exclusions` prints them as SecLang for review, `reset` clears the statistics (audited) |
| `rotate-secret FILE` | Add a fresh primary key to a secret file (affinity, challenge, OIDC cookie, redaction hash), keeping `-keep 2` previous keys for verification; then `reload` |
| `reload-certs` | Re-read certificate files |
| `reopen-logs` | Reopen log files |
| `tail STREAM` | Follow `access`, `error`, `security` or `audit` |
| `bans` | List active bans with expiry, source and count |
| `ban TARGET` | Ban an address, CIDR or `ja4:<fingerprint>`; `-duration 1h`, `-reason text` |
| `unban TARGET` | Remove a ban |
| `cluster` | Peers, inbound connections and gossip counters |
| `accounts` | Account guard state: endpoints with tracked keys, active blocks (`-top N` per endpoint), campaign state and the action counters |
| `maintenance` [`on`\|`off`] | Show or set maintenance mode; on holds every request but the allowlist behind a 503 |
| `origin-check` [`upstream`] [`-host H`] [`-path P`] | Probe origins directly to verify origin-lock is enforced: sends an unsigned and a signed request to each endpoint of every upstream with an `origin_signature` (or the named one) and reports the verdict; exits non-zero if any origin is not `enforced` |
| `botscore` [`-top N`] | Learning-mode `bot_score` baselines: per-route score percentiles and suggested `challenge_at`/`deny_at` from observed traffic (needs `learn: true` on the filter) |
| `spki CERT.pem` | Print the `spki_pins` value of a certificate |
| `acme` | Managed certificates with expiry, issuer, last error; `acme renew` forces renewal and waits |
| `icap` | ICAP services with reachability, preview size, ISTag and counters |
| `filters` | Middleware API version, registered kinds, configured filters with routes and deny counts |
| `geoip` | Country database kind, path, build date, lookup and unknown counters |
| `cache` | Cache entries, bytes and counters; `cache purge [HOST [PATH-PREFIX]]` removes entries |
| `honeypot` | Clients marked by honeypot routes and the decoy names; `honeypot forget IP` removes a mark |
| `capture` [`status`\|`start`\|`stop`] | Packet capture of the exchanges the proxy handled as pcapng: whether it is recording, when the window ends, the current file and the per-rule counters; `start [-duration 10m]` opens a window (bounded by `capture.max_duration`), `stop` closes it (both audited) |
| `dns` | DNS listener counters (queries, cache, blocked, refused, dropped, upstream failures); `dns purge` empties the caches |
| `ingress` | Kubernetes ingress controller status: syncs, watches, counts, warnings |
| `otlp` | OpenTelemetry metrics exporter status: pushes, failures, last error |
| `telemetry` | Every OpenTelemetry exporter (metrics, traces, logs) with sent, dropped, pushes, failures, queue depth and last error |
| `htpasswd FILE NAME` | Add or replace a `basic_auth` user; the password is read from stdin |
| `apikey add\|rotate\|revoke\|remove\|list` | Manage the keys file of `api_key` filters: `add ID [-scopes a,b] [-expires 90d] [-note TEXT]` prints the plaintext once, `rotate ID [-grace 24h]` issues a new secret and keeps the old one for the grace, `revoke ID`, `remove ID`, `list`; `-file` names the file (default `/etc/xproxy/api-keys`) |
| `tui` | Full-screen live view; `-refresh 2s`, `-no-color` (or `NO_COLOR`) |
| `metrics` | Print the Prometheus exposition |
| `series` | Print sampled series; `-since 10m`, `-last 30`, `-json` |
| `schema` | Print the JSON schema of the configuration (see below) |
| `completion bash\|zsh\|fish` | Print a shell completion script for `xproxyctl` and `xproxy` |
| `help` | List the commands with a summary |
| `version` | Print version |

`-json` switches `status`, `stats` and `upstreams` to machine readable
output. The user running `xproxyctl` must be in the `xproxy` group (socket
mode `0660`) or be root.

Examples:

```sh
xproxyctl status
xproxyctl -json stats | jq .denied_rate_limit
xproxyctl upstreams
xproxyctl tail security | jq -c '{t:.time, ip:.client_ip, r:.reason, p:.path}'
xproxyctl reload
xproxyctl bans
xproxyctl ban -duration 24h -reason "credential stuffing" 203.0.113.0/24
xproxyctl unban 203.0.113.0/24
```

### Shell completion, manual pages and the configuration schema

`make install` and the RPM install completion for bash, zsh and fish
(`xproxyctl` commands, their words and flags, and the flags of
`xproxy`), the manual pages `xproxy(8)`, `xproxyctl(8)` and
`xproxy.yaml(5)`, and the JSON schema of the configuration at
`/usr/share/xproxy/xproxy.schema.json`. For a source build without the
install step:

```sh
xproxyctl completion bash > ~/.local/share/bash-completion/completions/xproxyctl
xproxyctl completion zsh > ~/.zfunc/_xproxyctl      # with fpath+=~/.zfunc before compinit
xproxyctl completion fish > ~/.config/fish/completions/xproxyctl.fish
man -l docs/man/xproxyctl.8
```

The schema (JSON Schema draft 2020-12) is generated from the
configuration types with every key, its type, the value sets of
enumerated keys, required keys and the documentation comment of each
key, and forbids unknown keys as the loader does. Editors with a YAML
language server pick it up from a modeline at the top of the file:

```yaml
# yaml-language-server: $schema=/usr/share/xproxy/xproxy.schema.json
version: 1
server:
  listeners: [{name: main, address: ":8080"}]
upstreams:
  - {name: app, endpoints: [{address: "127.0.0.1:3000"}]}
routes:
  - {name: all, upstream: app}
```

Visual Studio Code (with the Red Hat YAML extension), Neovim with
`yamlls` and JetBrains IDEs then complete keys, show the documentation
on hover and mark unknown keys and wrong types while you type; the
authoritative check remains `xproxy -validate`, which also verifies
references, files and cross-field rules the schema cannot express.
`xproxyctl schema` prints the same document for tooling.

## Configuration patterns

### Minimal

```yaml
version: 1
server:
  listeners:
    - {name: http, address: ":8080"}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:3000}]
routes:
  - name: all
    upstream: app
```

### Pushing metrics to an OpenTelemetry collector

```yaml
metrics:
  otlp:
    endpoint: https://otel.example.internal:4318/v1/metrics
    interval: 15s
    headers: {Authorization: "Bearer replace-me"}
    ca_file: /etc/xproxy/otel-ca.pem
    service_name: edge
    attributes: {deployment.environment: production}
```

Every family in `/metrics` reaches the collector as OTLP with the same
names, so dashboards built on the Prometheus exposition carry over;
`xproxyctl otlp` shows whether pushes succeed.

### Distributed tracing and logs to an OpenTelemetry collector

```yaml
tracing:
  sample_percent: 10
  otlp: {endpoint: https://otel.example.internal:4318/v1/traces, headers: {Authorization: "Bearer replace-me"}}
logging:
  otlp: {endpoint: https://otel.example.internal:4318/v1/logs, headers: {Authorization: "Bearer replace-me"}}
  access: {sinks: [file, otlp]}
  security: {sinks: [file, otlp]}
```

Every request carries a `traceparent` to the upstream, so an
application that already traces sees the proxy's server and upstream
spans above its own; one request in ten is exported. The access and
security streams reach the collector as log records with the trace id
of their request, and the files keep receiving everything. Applications
behind the proxy only need to read `traceparent` from the request (most
frameworks do so out of the box). `xproxyctl telemetry` shows whether
spans and records arrive:

```
SIGNAL   ENDPOINT                                       SENT   DROPPED  PUSHES  FAILED  QUEUED  LAST ERROR
metrics  https://otel.example.internal:4318/v1/metrics  120    -        120     0       -       -
traces   https://otel.example.internal:4318/v1/traces   9310   0        41      0       12      -
logs     https://otel.example.internal:4318/v1/logs     93102  0        190     0       0       -
```

### Splitting the configuration into fragments

```yaml
# /etc/xproxy/xproxy.yaml
version: 1
includes: ["/etc/xproxy/conf.d/*.yaml"]
server:
  listeners:
    - {name: https, address: ":443", tls: {certificates: [{cert_file: /etc/xproxy/certs/site.pem, key_file: /etc/xproxy/certs/site.key}]}}
```

```yaml
# /etc/xproxy/conf.d/10-shop.yaml
upstreams:
  - name: shop
    endpoints: [{address: 10.0.1.10:8080}]
routes:
  - name: shop
    hosts: [shop.example.com]
    upstream: shop
```

Fragments hold only `upstreams`, `routes`, `rate_limits` and `filters`;
everything that controls the process (listeners, limits, logging,
management) stays in the main file, so a fragment can add a site but
never weaken a defence. Files are appended in lexical order, names must
be unique across all of them, and `xproxyctl validate` checks the whole
set. A reload re-reads every fragment. `xproxyctl config` prints the
expanded result as one self-contained document (with `includes` cleared
and the fragment paths in a leading comment), so its output can be
saved and loaded as a main file without expanding the fragments twice.
The Kubernetes ingress merge works on the expanded document the same
way.


### OCSP stapling and Certificate Transparency checks

```yaml
server:
  listeners:
    - name: public
      address: ":443"
      tls:
        certificates: [{cert_file: /etc/xproxy/tls/www.pem, key_file: /etc/xproxy/tls/www-key.pem}]
        ocsp_stapling: {refresh: 1h}
        ct: {require: 2, log_list_file: /etc/xproxy/ct/log_list.json, enforce: true}
```

The chain file must hold the issuer after the leaf: the OCSP request
and the SCT verification both need it. `xproxyctl tls` shows every
certificate with its staple (`good until 09-18 14:00`, or the fetch
error) and its SCTs (`2/2 verified`). With `enforce`, a reload that
brings in a certificate with fewer than two verifiable SCTs is refused
and the previous certificate keeps serving, which is the outcome you
want when a CA misissues without logging. Download `log_list.json`
from the Chrome CT policy site into the path above and refresh it with
your certificate tooling; a log that is not in the list leaves its SCT
unverified.

### TLS edge with HTTP redirect

```yaml
server:
  listeners:
    - {name: public-http, address: ":80", redirect_to_https: true}
    - name: public
      address: ":443"
      tls:
        certificates:
          - {cert_file: /etc/xproxy/certs/site.pem, key_file: /etc/xproxy/certs/site-key.pem}
```

Add more certificates to the list; SNI selects the matching one.

### Encrypted Client Hello

The SNI is the last plaintext identifier in a modern connection. TLS
1.3 encrypts the certificate, ALPN and everything after it, but the
name being visited still travels in the clear at the front of the
ClientHello, which is what network-level monitoring and blocking
actually key on. ECH encrypts the real hello to a key published in DNS
and wraps it in an outer hello naming a *public name* shared by
everything behind that key.

```sh
# One key, its files, and the record to publish.
xproxyctl ech keygen -public-name ech.example.com -id 1 -dir /etc/xproxy/ech
```

```yaml
server:
  listeners:
    - name: public
      address: ":443"
      tls:
        certificates:
          # This certificate must cover ech.example.com as well as the
          # sites served here.
          - {cert_file: /etc/xproxy/certs/site.pem, key_file: /etc/xproxy/certs/site-key.pem}
        ech:
          keys:
            - {config_file: /etc/xproxy/ech/1.echconfig, key_file: /etc/xproxy/ech/1.key}
```

Publish the record `keygen` printed for every name served behind the
key:

```
www.example.com. 300 IN HTTPS 1 . ech="AEr+DQBG..."
```

**The public name is a real site, not a label.** A client whose key is
stale — a cached DNS answer, a record that has not propagated, a
resolver that strips the parameter — falls back to an ordinary
handshake with the public name, and gets a certificate error unless
this listener can serve it. Give it a certificate and something
ordinary to answer with. That fallback is not a failure to design
around: it is what makes key rotation safe.

**Rotating a key.** Generate the second key, add it to `keys`, publish
a record containing both configs, wait out the old record's TTL
everywhere, then remove the old key and republish. Clients holding a
stale config are handed the current one *during the handshake they
fail*, so a rotation heals itself:

```sh
xproxyctl ech keygen -public-name ech.example.com -id 2 -dir /etc/xproxy/ech
xproxyctl ech record -name www.example.com /etc/xproxy/ech/1.echconfig /etc/xproxy/ech/2.echconfig
xproxyctl reload-certs      # re-reads ECH keys with the certificates
```

**Check what is actually served, not what you meant to publish.**

```
$ xproxyctl tls
ech public: 2 key(s), require=false, accepted 41203, without ech 6112, refused 0 (87.1% of handshakes)
  config id 1  public name ech.example.com  retry=true  /etc/xproxy/ech/1.echconfig
  config id 2  public name ech.example.com  retry=true  /etc/xproxy/ech/2.echconfig
  publish: ech="AEr+DQBG..."
```

The `publish:` line is generated from the keys the listener holds, so a
record that has drifted from the deployment shows up as a difference
between that string and the one in DNS.

**What it changes elsewhere.** `sni` in the access log is the public
name for every ECH client, so `ech: true` is the field that separates
them from clients that genuinely asked for that name. JA3 and JA4 are
computed from the outer hello and keep working. A `kind: tcp` listener
routes on the outer name, so it cannot split ECH clients apart —
terminate TLS where ECH is accepted.

**`require`** refuses every handshake that did not use ECH. That
includes clients whose DNS answer was filtered and platforms with no
ECH support at all, so it belongs on a listener that exists for ECH
clients and nothing else. Validation says so when you set it.

### Post-quantum key exchange

```yaml
server:
  listeners:
    - name: public
      address: ":443"
      tls:
        certificates: [{cert_file: /etc/xproxy/certs/site.pem, key_file: /etc/xproxy/certs/site-key.pem}]
        # The default. Written out here because it is worth knowing it
        # is on, and because naming any group replaces the whole list.
        key_exchange: [X25519MLKEM768, X25519, P-256, P-384]
upstreams:
  - name: app
    scheme: https
    endpoints: [{address: "10.0.1.10:443"}]
    tls: {key_exchange: [X25519MLKEM768, X25519]}
```

The threat is not a quantum computer today; it is a recorder today and
a quantum computer later. Traffic captured now — a session, a token, a
year of an API — is decrypted whenever the key exchange falls, and
nothing about the recording has to be noticed at the time. A hybrid
group closes that: X25519MLKEM768 agrees a secret that needs *both*
X25519 and ML-KEM broken, costs about a kilobyte in the ClientHello,
and is what Chrome, Firefox and the large CDNs already negotiate.

The reason it is a setting rather than a default buried in the runtime
is a trap worth naming: Go picks a good set on its own, but only while
the list is unset, and naming a single group replaces the lot. A
listener written years ago to "prefer X25519" therefore stops offering
the hybrid the day the toolchain adds it, silently, with a handshake
that looks perfectly healthy. Making the list explicit turns that into
something validated, documented and visible.

Measure it on traffic, not on configuration:

```
$ xproxyctl tls
key exchange public: X25519MLKEM768, X25519, P-256, P-384
negotiated: X25519MLKEM768 184203  X25519 26611  P-256 44  (post-quantum 87.4%)
```

`tls_group` in the access log says which group each request's
connection agreed, and `xproxy_tls_key_exchange_total{group}` charts
the share over time. That share moves as client fleets upgrade; it is
the only honest measure of a rollout, and it is the one to watch before
deciding whether the classical groups can ever be removed.

A list that names groups but leaves the hybrid out still loads — some
fleets genuinely cannot negotiate it — but it loads with an advice line
saying what has been traded away. Restricting the list to one group
forces it at the cost of a HelloRetryRequest for clients that guessed
differently, which is a round trip, not a failure.

### Session tickets shared across a cluster

```yaml
server:
  session_tickets: {secret_file: /var/lib/xproxy/tickets.key, rotate: 12h}
```

Without the section every process picks its own ticket keys, so a
client that lands on another node behind the balancer, or on the same
node after a restart, does a full handshake. With it the keys are
derived from the shared file and the wall clock (epoch `now / rotate`),
so all nodes holding the file encrypt with the same key at the same
time and any of them resumes a ticket from any other; the previous
epoch's key is kept so a rotation never cuts a fresh ticket off. Copy
the file (`0600`, owner `xproxy`) to every node, or rotate it on all of
them within one epoch with `xproxyctl rotate-secret`. `xproxyctl tls
tickets` shows the epoch, the next rotation and, in a cluster, which
peers derive the same set:

```
$ xproxyctl tls tickets
session tickets: epoch 20732 (since 2026-09-19T00:00:00Z, next rotation 2026-09-19T12:00:00Z, every 12h0m0s)
keys 2 from 1 master key(s)  fingerprint 4c1f0e9a7b2d5e31  rotations 0
peer edge-2 agrees (4c1f0e9a7b2d5e31)
peer edge-3 MISMATCH (9a02b7c4d1e8f356)
```

A mismatch means that peer holds another secret file or its clock is an
epoch off; its tickets do not resume here and vice versa, which costs a
handshake per client, not correctness. Changing the section needs a
restart.

### Automatic certificates (ACME)

```yaml
server:
  listeners:
    - {name: public-http, address: ":80", redirect_to_https: true}
    - name: public
      address: ":443"
      tls:
        acme:
          - hosts: [shop.example.com, www.shop.example.com]
          - hosts: [api.example.com]

acme:
  directory: https://acme-v02.api.letsencrypt.org/directory
  email: hostmaster@example.com
  accept_terms: true
```

Each `hosts` group becomes one certificate. With the default `http-01`
challenge the plaintext listener answers the validation requests before
the HTTPS redirect; with `challenge: tls-alpn-01` only port 443 is needed.
File certificates and ACME groups can be mixed on the same listener. The
first order runs at start; watch it with:

```sh
xproxyctl acme
xproxyctl tail error | jq -c 'select(.component=="acme")'
xproxyctl acme renew      # force, for example after changing hosts
```

Certificates and the account live under `/var/lib/xproxy/acme`; back that
directory up with the configuration. Adding or removing a group rebuilds
the listener on the next reload (its connections drain, the socket is
kept).

### HTTP/3

```yaml
    - name: public
      address: ":443"
      protocols: [h1, h2, h3]
      h3: {max_streams: 100, validate_addresses: always}
      tls: {certificates: [...]}
```

xproxy binds UDP 443 next to TCP 443 (or takes the datagram socket from
`xproxy-h3.socket`), advertises `Alt-Svc` on TLS responses, and serves the
same routes over QUIC. Open UDP 443 in the firewall. `xproxyctl status`
lists the endpoint as `public/udp`; access log lines show
`proto: HTTP/3.0`.

### HTTP/3 to upstreams

```yaml
upstreams:
  - name: edge-api
    scheme: https
    h3: true
    endpoints: [{address: "10.0.5.10:443"}]
    tls: {server_name: api.internal, ca_file: /etc/xproxy/ca/internal.pem}
```

The pool opens QUIC connections to its endpoints and multiplexes
requests on them; health probes go over the same transport. When UDP
is blocked or a handshake times out, the request is retried over TCP on
the same endpoint and `xproxyctl upstreams` counts an `h3_fallbacks`
per such request, so a QUIC-hostile network degrades to HTTP/2, not to
errors; `h3_fallback: false` makes the failures visible instead.

### WebTransport

```yaml
server:
  listeners:
    - name: public
      address: ":443"
      protocols: [h1, h2, h3]
      h3: {webtransport: true}
      tls: {certificates: [{cert_file: /etc/xproxy/tls/www.pem, key_file: /etc/xproxy/tls/www-key.pem}]}
upstreams:
  - name: realtime
    scheme: https
    h3: true
    endpoints: [{address: "10.0.6.10:4433"}]
    tls: {server_name: realtime.internal, ca_file: /etc/xproxy/ca/internal.pem}
routes:
  - name: wt
    hosts: [rt.example.com]
    paths: [/session]
    upstream: realtime
    webtransport: true
```

A browser's `new WebTransport("https://rt.example.com/session")` is an
extended CONNECT over HTTP/3; the listener accepts it, the route opens
a session to the upstream over HTTP/3 (with the request header
operations and the usual forwarding headers on the CONNECT) and relays
every bidirectional and unidirectional stream and every datagram in
both directions until either side ends the session. The route's
limits, bans, expressions and ACLs apply to the CONNECT like to any
request; the access log line carries `webtransport`, the streams and
datagrams relayed. The `Origin` header is forwarded unchanged so the
upstream applies its own origin policy.

### Virtual hosts and path routing

```yaml
routes:
  - {name: api,  hosts: [api.example.com],        upstream: api}
  - {name: docs, hosts: [example.com], paths: [/docs], upstream: docs}
  - {name: web,  hosts: [example.com, "*.example.com"], upstream: web}
  - {name: default, priority: -100, respond: {status: 404, body: "not found\n"}}
```

Precedence: exact host over wildcard over no host; then longest path
prefix; then `priority`; then configuration order. A route with `methods`
only matches those methods; other methods fall through to the next route.

### Protecting a login endpoint

```yaml
rate_limits:
  - {name: login, key: client_ip, rate: 0.2, burst: 5, action: tarpit, tarpit_delay: 10s}
routes:
  - name: login
    hosts: [example.com]
    paths: [/login]
    methods: [POST]
    rate_limits: [login]
    max_body_bytes: 16384
    upstream: web
```

Beyond five attempts, each further attempt is held for ten seconds and then
answered 429. The hold is released early if the client disconnects.

### Rate limiting by API key with a fallback

```yaml
rate_limits:
  - {name: per-key, key: "header:X-Api-Key", rate: 100, burst: 200}
```

Requests without the header are limited by client address instead, so the
limit cannot be avoided by omitting the header.

### Limits per session, account, token, network and endpoint

The key decides what a bucket belongs to, and several policies can sit on
one route, so a login endpoint is bounded per session, per account and
per network at once:

```yaml
rate_limits:
  - {name: per-session, key: "cookie:sid", algorithm: sliding_window, limit: 30, window: 1m}
  - {name: per-account, key: "jwt:sub", algorithm: sliding_window, limit: 600, window: 1h}
  - {name: per-network, key: client_net, net_v4: 24, net_v6: 48, rate: 50, burst: 100}
  - {name: per-endpoint, key: endpoint, algorithm: sliding_window, limit: 5000, window: 1m}
  - {name: per-fingerprint, key: ja4, rate: 20, burst: 40}
routes:
  - {name: api, hosts: [api.example.com], upstream: api, rate_limits: [per-session, per-account, per-network, per-endpoint]}
```

`client_net` counts a whole allocation as one client, which is what a
scraper rotating through a /24 looks like; `endpoint` folds identifiers
in the path (`/users/42`, `/users/43`) into one template per method and
route, so a single expensive endpoint is protected without a route per
path; `ja4` groups clients by TLS stack, which catches a bot fleet
behind many addresses; `jwt:<claim>` reads the claim without verifying
the token, so it costs nothing and only names a bucket. Every
identifier key falls back to the client address when the identifier is
missing.

### Sliding windows and exact cluster limits

```yaml
rate_limits:
  - {name: login, key: client_ip, algorithm: sliding_window, limit: 20, window: 1m}
  - {name: partner, key: "header:X-Api-Key", algorithm: sliding_window, limit: 10000, window: 1h, distributed: exact}
cluster:
  exact_timeout: 30ms
```

A token bucket lets a client spend its whole `burst` at once and then
trickle at `rate`; a sliding window says "at most 20 per minute" and
holds it across the minute boundary, which is the shape of most
contractual and abuse limits. `distributed: exact` makes the count one
per key across the cluster: the key's owner (chosen by hashing over the
connected members, so all nodes agree) decides and the others ask it,
adding one round trip on the cluster link. Use it for per customer
quotas where over-admission costs money; keep the default approximate
mode for abuse limits, where a node that cannot reach the owner within
`exact_timeout` deciding on its own is the right trade. `xproxyctl
quotas` shows the algorithm, limit and mode per policy, `xproxyctl
cluster` the members and how many decisions were asked, answered and
decided locally.

### Restricting an admin path

```yaml
routes:
  - name: admin
    hosts: [example.com]
    paths: [/admin]
    allow_cidrs: [10.0.0.0/8]
    upstream: web
```

Deny lists are evaluated before allow lists. Client addresses come from the
peer unless it is in `trusted_proxies`.

### Access log in Common Log Format

```yaml
logging:
  access: {format: combined}
```

Tools built for Apache and nginx logs (GoAccess, AWStats, fail2ban
filters) read the access stream directly:

```
203.0.113.9 - - [18/Sep/2026:10:12:01 +0000] "GET /index.html HTTP/2.0" 200 2326 "https://www.example.com/" "Mozilla/5.0 ..."
```

`format: common` drops the two quoted fields; `format: custom` with a
`template` picks any access log attribute, so a line can carry the
route, the upstream endpoint, the duration or the bot score:

```yaml
logging:
  access:
    format: custom
    template: '{time_iso} {client_ip} {country} "{request}" {status} {duration_ms}ms route={route} endpoint={endpoint} denied={denied}'
```

Redaction (`logging.redaction`) still applies before the line is
rendered, and the other streams stay JSON, since their records vary by
event. The query string is never logged in any format.

### Behind a load balancer that sets X-Forwarded-For

```yaml
trusted_proxies: [10.0.0.0/24]
```

Only hops from this range are believed. Never list `0.0.0.0/0`.

### Behind a layer 4 balancer that speaks the PROXY protocol

```yaml
trusted_proxies: [10.0.0.0/24]
server:
  listeners:
    - {name: public, address: ":443", proxy_protocol: true, tls: {certificates: [...]}}
```

A TCP balancer that cannot add HTTP headers (HAProxy in `mode tcp`,
cloud network load balancers) prepends a PROXY protocol v1 or v2 header
to every connection instead. With `proxy_protocol: true` the listener
reads it from peers in `trusted_proxies` before TLS starts, and from
then on the client address in the header is the client: bans, connection
and rate limits, ACLs, country lookups, the access log and the
forwarding headers all see it. A trusted balancer that sends no header
is dropped, so turn the option on together with the balancer, and a
connection from any other peer is served as before, so nobody outside
the balancer range can choose an address. Layer 4 listeners (`kind:
tcp`) do the opposite: their `proxy_protocol` sends the header to the
upstream.

### Rotating secrets

```
$ xproxyctl rotate-secret /var/lib/xproxy/challenge.key
/var/lib/xproxy/challenge.key: new primary key, 3 key(s) in the ring; run xproxyctl reload to apply
$ xproxyctl reload
```

Secret files (`affinity.secret_file`, `challenge.secret_file`, the
OIDC `cookie_secret_file`, `logging.redaction.hash_secret_file`,
`server.session_tickets.secret_file`) hold a
single raw key when created and become a keyring on the first rotation:
a text file whose first key signs and seals and whose other keys only
verify and open. Cookies and sessions issued under a kept key stay
valid until a later rotation drops it (`-keep 0` drops everything at
once). A rotation takes effect on the next reload for the challenge,
affinity and OIDC keys and at the next restart for the redaction key,
whose pseudonyms then start a new series. In a cluster rotate the same
file on every node within the retention window, or copy the ring; the
ring is the whole secret, so keep it `0600` and out of backups that are
not encrypted. Copy a ring rather than a raw key when moving a node.

### Previewing, comparing and rolling back configuration

```
$ xproxyctl reload -dry-run
active -> file
  routes: 1 added, 1 changed
  upstreams: 1 changed
  added    routes checkout
  changed  routes web
  changed  upstreams app

--- active
+++ file
@@ -41,6 +41,7 @@
 ...
$ xproxyctl reload
reloaded
$ xproxyctl history
ID                                   GENERATION  APPLIED                    NOTE     SIZE
20260918T101522.184201000-gen4       4           2026-09-18T12:15:22+02:00  reload   6120
20260918T093001.002144000-gen3       3           2026-09-18T11:30:01+02:00  reload   5988
20260918T090000.000000000-gen1       1           2026-09-18T11:00:00+02:00  start    5988
$ xproxyctl diff 20260918T093001.002144000-gen3 active
$ xproxyctl rollback 20260918T093001.002144000-gen3
rolled back to 20260918T093001.002144000-gen3
```

Set `management: {history_dir: /var/lib/xproxy/history}` to keep the
last twenty applied configurations (the RPM creates the directory).
A dry run validates the file exactly as a reload would, including file
existence checks, and names the changes that need a restart, so a
change to a listener address is caught before the reload silently
leaves it in place. Rollback goes through the same validation and
audit trail as a reload and never touches the file on disk: after
rolling back, fix the file, or the next `reload` re-applies it.

### Adding, removing and changing listeners without a restart

```yaml
server:
  listeners:
    - {name: public, address: ":443", tls: {certificates: [{cert_file: /etc/xproxy/tls/www.pem, key_file: /etc/xproxy/tls/www-key.pem}]}}
    - {name: public-http, address: ":80", redirect_to_https: true}   # new
```

```
$ xproxyctl reload -dry-run
  added    server.listeners public-http
$ xproxyctl reload
```

A reload binds the listeners it does not have yet and serves them at
once; a listener taken out of the file stops accepting and its open
connections get `shutdown_timeout` to finish. A listener whose settings
changed (protocols, TLS mode, client authentication, `redirect_to_https`,
`h2c`, ACME groups, kind) is rebuilt: on the same address the accept
socket is handed to the new listener, so a socket passed by systemd or
bound on a privileged port is kept and no client sees a refused
connection; the old generation drains as for a removal. Certificate
files, forward and dns policies still apply in place without a drain.
The dry run lists the drains and the one case that still needs a
restart, a listener with a UDP socket (`h3`, `tcp.quic`, plain `dns`)
changed on the same address, because that socket stays bound until the
drain ends. A port that cannot be bound fails the reload with the
running set untouched.

### Usage per tenant and route

```yaml
routes:
  - {name: shop-web, hosts: [shop.example.com], tenant: shop, upstream: shop}
  - {name: shop-api, hosts: [api.shop.example.com], tenant: shop, rate_limits: [api], upstream: shop-api}
  - {name: blog, hosts: [blog.example.com], tenant: blog, upstream: blog}
```

`xproxyctl quotas` then prints one line per tenant (requests, denied,
rate limited, bytes in and out over the routes that carry the label),
one per route with the status classes, and one per rate limit policy
with its decisions and the keys that consumed the most tokens together
with the tokens they have left, so the client hitting a limit is
visible without reading logs. `GET /v1/quotas?top=N` returns the same
as JSON for billing or capacity scripts, and the per route metrics
carry a `tenant` label with `xproxy_route_bytes_total` and
`xproxy_rate_limit_decisions_total` next to the request counters.
Counters restart with each configuration generation; the metrics
exporter keeps the long history.

### Rewriting paths with captures and templating headers

```yaml
routes:
  - name: api
    hosts: [api.example.com]
    paths: [/api/]
    rewrite_regex: {pattern: "^/api/v([0-9]+)/(?P<rest>.*)$", replace: "/internal/v${1}/${rest}"}
    request_headers:
      set: {X-Client-Ip: "${client_ip}", X-Api-Version: "${1}", X-Tenant: "${header:X-Tenant}"}
    response_headers:
      set: {X-Served-By: "${route}", X-Request-Id: "${request_id}"}
    upstream: api
  - name: old-blog
    hosts: [blog.example.com]
    redirect: {to: "https://www.example.com/blog${path}?${raw_query}", status: 308}
```

`rewrite_regex` runs on the cleaned path after `strip_prefix`; a path
that does not match is forwarded as is. The groups of the pattern are
available as `${1}` to `${9}` and by name in the replacement, in header
values and in the redirect target, together with the request variables
listed in [CONFIG.md](CONFIG.md#variables). A header whose variable has
no value (a missing header, a route without a tenant) is set to the
empty string, so a downstream service can rely on the header existing.

### Custom error pages

```yaml
server:
  error_pages:
    dir: /etc/xproxy/errors
    pages: {"404": "404.html", "429": "429.html", "5xx": "5xx.html", "default": "error.html"}
    intercept_upstream: [502, 503, 504]
routes:
  - name: api
    hosts: [api.example.com]
    error_pages: {dir: /etc/xproxy/errors, pages: {"default": "api.json"}, content_type: application/json, json: false}
    upstream: api
```

Every status the proxy writes itself (denials, unknown hosts, upstream
failures, static misses) is served from the matching document, chosen
by exact status, class or `default`, with `${status}`, `${status_text}`,
`${request_id}`, `${host}`, `${path}` and `${reason}` filled in; a client
whose `Accept` prefers JSON gets a small JSON document unless `json` is
off. Upstream responses are left alone unless their status is listed
in `intercept_upstream`, which is the usual choice for 502, 503 and 504
so that a failing backend never shows its own stack trace or a bare
gateway error. A route section replaces the server section for that
route. Documents are read at load and at reload, so an edit needs
`xproxyctl reload`; a missing file fails the reload.

### Endpoints from DNS and slow start

Instead of listing addresses, a pool can resolve them:

```yaml
upstreams:
  - name: api
    discovery: {type: dns, name: api.internal.example., port: 8080, interval: 15s}
    slow_start: 30s
  - name: workers
    discovery: {type: srv, name: _http._tcp.workers.internal.example., resolver: 10.0.0.53:53}
    health_check: {path: /healthz, interval: 5s}
```

`dns` turns every A and AAAA record into an endpoint on `port`; `srv`
takes target, port and weight from the records and uses the lowest
priority group. The name is resolved once at start (synchronously,
bounded by `timeout`, so the pool serves from its first request) and
then every `interval`: addresses that disappear are removed, new ones
added, and an endpoint that stays keeps its counters and health state.
A failed resolution keeps the previous set and shows up as `errors` and
`last_error` under `discovery` in `xproxyctl upstreams` and the pool
views. Static `endpoints` may be listed next to a discovery block; they
are never removed.

`slow_start` gives an endpoint that joins (discovered) or returns to
service (healthy again, or its ejection over) a share ramping from
10 % to its full weight over the duration, so a cold instance warms
its caches before it carries a full share. Weighted and least
connection balancers scale the weight; round robin and hash admit a
ramping endpoint with the ramp's probability and pick another
otherwise. Endpoints present at start do not ramp. The current share
is the `ramp` column of `xproxyctl upstreams`.

### Retrying failed responses on another endpoint

```yaml
upstreams:
  - name: api
    retries: 2
    retry_on: ["502", "503", "504"]
    endpoints: [{address: 10.0.1.10:8080}, {address: 10.0.1.11:8080}, {address: 10.0.1.12:8080}]
    outlier_ejection: {consecutive_failures: 3, base_ejection_time: 30s}
```

Connection failures are retried on another endpoint by default; with
`retry_on`, a gateway status from an endpoint counts the same way, so
one endpoint that answers 503 while restarting costs the client nothing
and gets ejected after a few such answers. Only replayable requests
(safe methods without a body) are retried, at most `retries` times, and
when every endpoint fails the last answer is passed through unchanged.
`upstream_retries` and `upstream_status_retries` count the attempts.

### Taking a backend out of service without dropping anything

A machine has to be patched, restarted or removed. The thing you do not
want is to take it out by stopping it and letting the proxy discover
that: the requests in flight on it are lost, and the ones that arrive in
the second before the health check notices are lost too.

Drain it first:

```console
$ xproxyctl drain app 10.0.1.12:8080     # no new work here
$ xproxyctl upstreams | grep 10.0.1.12   # watch ACTIVE fall to 0
$ # ... patch, restart, whatever ...
$ xproxyctl drain -restore app 10.0.1.12:8080
```

Draining stops new work and ends nothing: what is already on the endpoint
runs to its own end, which is why `ACTIVE` falling to zero is the signal
that the machine is yours. The endpoint stays `healthy` in the listing
and shows `draining`, so nobody reading the status confuses "somebody
took this out" with "the proxy found this broken".

For a whole service, name only the pool:

```console
$ xproxyctl drain reports                # the pool offers nothing
$ xproxyctl drain                        # what is currently out
POOL     ENDPOINT       STATE
reports  (whole pool)   maintenance
app      10.0.1.12:8080 draining
```

The decision survives a reload, on purpose: a reload builds new pools,
and somebody who drained a machine to patch it did not mean "until the
next configuration change". The declarative forms —
`endpoints[].drain: true` and a pool's `maintenance: true` — are for an
outage long enough to write down; an API decision overrides the file
until the daemon restarts.

**A rolling restart, then, is:** drain one endpoint, wait for its
`ACTIVE` to reach zero, do the work, restore it, move to the next. No
request is refused at any point as long as the rest of the pool can
carry the load — which is what `max_connections` on an endpoint is for if
one of them cannot.

### Protecting a slow upstream: concurrency, queue and circuit breaker

```yaml
upstreams:
  - name: reports
    max_concurrent: 20
    queue: {size: 50, timeout: 2s}
    circuit_breaker: {consecutive_failures: 5, open_for: 15s, half_open_requests: 2}
    endpoints: [{address: 10.0.3.10:8080}, {address: 10.0.3.11:8080}]
```

At most twenty requests are in flight to the report service; the next
fifty wait up to two seconds for a slot and get 503 with `Retry-After`
when none frees up, and anything beyond that is refused at once, so a
burst never piles hundreds of connections onto a service that is
already slow. If the service fails five attempts in a row the circuit
opens: for fifteen seconds every request is answered 503 locally, then
two trial requests probe it, and one success closes the circuit again
(each reopen doubles the wait, up to ten times). `xproxyctl upstreams`
shows the circuit state and queue depth per pool.

### Weighted and sticky pools

```yaml
upstreams:
  - name: web
    balancer: weighted
    endpoints:
      - {address: 10.0.1.10:8080, weight: 3}
      - {address: 10.0.1.11:8080, weight: 1}
    affinity: {cookie_name: XPSESS, ttl: 1h, secret_file: /var/lib/xproxy/web.key}
```

The cookie contains a signed endpoint index. If the endpoint is unhealthy
the request is rebalanced and a new cookie issued.

### Consistent hashing by tenant

```yaml
upstreams:
  - name: api
    balancer: hash
    hash_on: "header:X-Tenant"
    endpoints: [{address: 10.0.2.10:8443}, {address: 10.0.2.11:8443}]
```

Missing hash input falls back to the client address.

### WebSockets

```yaml
routes:
  - {name: ws, hosts: [example.com], paths: [/socket], websocket: true, upstream: web}
```

Without `websocket: true` an upgrade request is refused with 403 and logged.

### Health checks and ejection

```yaml
upstreams:
  - name: web
    endpoints: [...]
    health_check: {path: /healthz, interval: 5s, timeout: 2s, healthy_threshold: 2, unhealthy_threshold: 3}
    outlier_ejection: {consecutive_failures: 5, base_ejection_time: 30s, max_ejection_percent: 50}
```

Active checks mark endpoints unhealthy; passive ejection reacts to real
traffic failures with growing back-off. At most half the pool is ejected.

```yaml
upstreams:
  - name: api
    endpoints: [...]
    health_check:
      path: /healthz
      body_contains: '"status":"ok"'
      body_regex: '"database":"(up|degraded)"'
    outlier_ejection:
      consecutive_failures: 5
      base_ejection_time: 30s
      latency_threshold: 800ms
      latency_factor: 3
      latency_min_samples: 20
```

An application that answers 200 while its database is down passes a
status-only probe; `body_contains` and `body_regex` make the probe read
the first 64 KiB and require the text and the pattern. The latency rules
eject an endpoint that still answers but slowly: `latency_threshold` is
absolute, `latency_factor` relative to the pool (an endpoint three times
slower than the others), both on a smoothed time to first byte after
`latency_min_samples` responses, with the same ejection time, back-off
and 50 % bound as failures. `xproxyctl upstreams` shows `latency_ms` and
`latency_ejections` per endpoint; `xproxyctl quotas` shows p50, p95 and
p99 per route from the route histograms
(`xproxy_route_request_duration_seconds` in the exposition).

### Web application firewall

Enable the bundled OWASP Core Rule Set and roll it out in detect mode
first:

```yaml
waf:
  default_mode: detect
  profiles:
    - name: default
      crs: {paranoia_level: 1}
```

Watch the security log for `waf_detected` entries and the access log for
`waf_matched`. Add exclusions for legitimate traffic in a SecLang file,
then move to block in steps rather than at once: first the testers, then
a share of the clients, then everyone. The split is by client address,
so a customer who reports a problem always sees the same behaviour and
`waf_enforced` in the access log says which one:

```yaml
routes:
  - name: shop
    upstream: web
    waf: {mode: block, block_percent: 0, block_cidrs: [10.0.0.0/8]}   # test mode: staff only
  # later: block_percent: 10, 50, 100
```

Once the roll-out is through, the whole site runs in block:

```yaml
waf:
  default_mode: block
  inspect_responses: true
  profiles:
    - name: default
      crs: {paranoia_level: 1}
      directive_files: [/etc/xproxy/waf/exclusions.conf]
    - name: strict
      crs: {paranoia_level: 2}
routes:
  - {name: api,    hosts: [api.example.com], upstream: api, waf: {profile: strict}}
  - {name: upload, hosts: [example.com], paths: [/upload], upstream: web, waf: {mode: off}}
  - {name: web,    hosts: [example.com], upstream: web}
```

Example exclusion file:

```
# Rich text editor posts HTML in the "body" field of /posts.
SecRule REQUEST_URI "@beginsWith /posts" \
  "id:10001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:body,ctl:ruleRemoveTargetById=941160;ARGS:body"
```

Custom rules without the CRS work the same way through `directives`.

#### Rule statistics and learned exclusions

`xproxyctl waf` shows the compiled profiles (rule set source and CRS
version), which route runs which profile in which mode, and the rules
that matched most with their block and detect counts, severity and
last seen time; `xproxyctl waf rules -top 50` lists more. The counters
belong to the process, not to a configuration generation, so they keep
accumulating while a rule set is tuned across reloads; `xproxyctl waf
reset` starts them over (audited).

Turning on learning makes the same tuning data driven:

```yaml
waf:
  default_mode: detect
  learning: {enabled: true, min_hits: 10}
  profiles:
    - name: default
      crs: {paranoia_level: 2}
```

Every detection rule match is aggregated by rule, matched variable and
route. Once a combination reaches `min_hits`, `xproxyctl waf proposals`
lists it with the number of distinct clients and a sample value, and
`xproxyctl waf exclusions > /etc/xproxy/waf/learned.conf` writes the
proposals as SecLang, scoped to the route's path prefix:

```
# rule 941100: XSS Attack Detected via libinjection
# route posts, 37 hits from 12 clients, last 2026-09-18T10:22:41Z
SecRule REQUEST_URI "@beginsWith /posts" "id:10000,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=941100;ARGS:body"
```

Review every line: a proposal means the rule fired on that variable
repeatedly, which is what both a false positive and a persistent
attacker look like. Many distinct clients and a sample that is plainly
application data point to the former; a handful of addresses and
payload-like samples point to the latter and belong in a ban trigger
instead. Keep the reviewed lines in a `directive_files` entry, reload,
and the matching entries stop appearing. Learning runs in block mode
too, so exclusions for rules that already deny traffic surface the
same way.

#### Updating the Core Rule Set without a new binary

The embedded rule set is the version the binary was built with. To run
a newer release, or a patched one, unpack it into a directory and point
the profile at it:

```yaml
waf:
  profiles:
    - name: default
      crs: {dir: /etc/xproxy/crs, paranoia_level: 1}
```

The directory holds `crs-setup.conf.example` (or a tuned
`crs-setup.conf`, which is preferred) and `rules/` with the `.conf`
and `.data` files, exactly as the upstream archive lays them out. It is
read once per load: `xproxyctl reload -dry-run` validates a new
version before it is applied, a syntax error in any file fails the
reload and keeps the running rules, and `xproxyctl waf` reports the
directory and its `crs_setup_version` so the version in service is
never a guess. The engine settings that the embedded set carries
(`coraza.conf-recommended`) are applied to a directory rule set as
well, so the directory needs nothing besides the CRS files.

#### Core Rule Set plugins

CRS plugins (the official ones such as the WordPress, Nextcloud or
fake bot exclusion plugins, or your own) load from a directory:

```yaml
waf:
  profiles:
    - name: default
      crs:
        paranoia_level: 1
        plugins_dir: /etc/xproxy/crs-plugins
        plugins: [wordpress-rule-exclusions, fake-bots]   # default: every plugin found
```

The directory holds the plugin files themselves
(`<plugin>-config.conf`, `<plugin>-before.conf`, `<plugin>-after.conf`)
or one subdirectory per plugin, which is what `git clone` of a plugin
repository produces (the files sit in its `plugins/` folder). Config
and before files load after the CRS setup and before the CRS rules,
after files after the rules, the order the CRS documents; data files a
plugin references with `@pmFromFile` resolve next to the plugin file
and under `plugins/`. Plugins compile with the profile, so a broken
plugin fails the reload and `xproxyctl reload -dry-run` catches it;
`xproxyctl waf` lists the plugins each profile carries.

#### JSON body schemas

A profile can enforce a JSON Schema on request bodies before the
rules see them, so an API accepts only the shapes it documents and
fields that the rules would otherwise have to guess at (a free text
comment, an encoded blob) are bounded by the schema:

```yaml
waf:
  profiles:
    - name: api
      crs: {paranoia_level: 2}
      json_schemas:
        - name: order
          paths: [/api/orders]
          methods: [POST, PUT]
          schema_file: /etc/xproxy/waf/order-schema.json
          required: true
```

In block mode a violating body is refused with 400 and a JSON problem
body naming the fields; in detect mode it is logged with `waf_schema`
and `waf_schema_issue` and the request continues, so a schema rolls
out the same way a rule set does. `xproxyctl waf` counts the
violations (`schema violations`). For an API with a full OpenAPI
description the `openapi` filter validates paths, parameters and
bodies together; the WAF schemas suit an application that has a
schema for a few sensitive endpoints and the CRS for the rest.

#### Behavioural anomaly detection

The CRS scores requests. Some abuse never scores: a credential
stuffing run of well formed logins, a scraper walking every product
page, a scanner probing for files that do not exist. Anomaly detection
looks at clients over a window instead:

```yaml
waf:
  anomaly: {enabled: true, window: 5m, min_requests: 30, threshold: 4, action: challenge}
```

Every WAF protected request is attributed to its client. At the end of
each window every client with at least `min_requests` becomes a vector
of four features: request rate, share of requests that matched a rule,
share that ended in a deny or an error status, and spread over
distinct paths. The population's mean and spread per feature form the
baseline, carried across windows as a weighted average, so it follows
the site's daily rhythm without being pulled by one burst. A client
whose largest positive z-score reaches `threshold` is flagged; its
requests are then logged with `waf_anomaly` and `waf_anomaly_score`,
challenged, or denied with 403 and reason `waf_anomaly` (which a ban
trigger can count) until a later window scores it normal or it stays
away for three windows. A window with fewer than eight scored clients
changes nothing, so a quiet site never flags its only user.

```
$ xproxyctl waf anomalies
FEATURE      MEAN   STDDEV
rate         4.428  0.225
match_ratio  0.000  0.000
error_ratio  0.023  0.146
path_spread  0.162  0.075
CLIENT        SCORE  FEATURE      VALUE  MEAN   SINCE                 EXPIRES
203.0.113.99  11.2   path_spread  1.000  0.162  2026-09-19T07:15:00Z  2026-09-19T07:30:00Z
```

Start with `action: log`, watch which clients appear and with which
feature, and move to `challenge` (browsers pass, scripts do not) or
`block` once the flags match what the access log shows. `rate` is on a
log scale, so a client is flagged for volume only when it sends
several times what its peers do.

### Locking origins to the proxy

A control at the proxy holds only if the application accepts no other
path. Besides firewalling the origin to the proxy addresses (HARDENING.md
5c) and mutual TLS (`upstreams[].tls.client_cert_file`), the proxy can
sign every request it forwards:

```yaml
upstreams:
  - name: app
    endpoints: [{address: "10.0.0.20:8080"}]
    origin_signature:
      secret_file: /var/lib/xproxy/origin-app.key
      ttl: 5m
      include: [X-Tenant]
```

The origin verifies `X-Xproxy-Signature` with the same key file (an
HMAC over method, host, path, query, time, client address, request id
and the listed headers; the exact recipe and verifier snippets are in
CONFIG.md and HARDENING.md) and answers 403 to anything else, so a
request that did not pass the proxy, or was altered after it, is
refused whatever network it came from. `xproxyctl rotate-secret
/var/lib/xproxy/origin-app.key` adds a new key while the old one keeps
verifying until the origins have the new file.

Verify the lock is actually in force with `xproxyctl origin-check`: it
sends an unsigned and a signed request straight to each origin endpoint
(bypassing the proxy) and reports `enforced` only when the origin refuses
the unsigned one and accepts the signed one. It exits non-zero if any
origin is `not_enforced`, so it can gate a deploy. Point it at one
upstream with `xproxyctl origin-check <upstream>`, and override the probe
target with `-host` and `-path` when the origin's health path is
protected differently.

### Positive security model

Where an API is documented, refusing everything else is cheaper and
safer than recognising attacks in it. `routes[].policy` states what a
request may look like and the proxy answers 405, 415, 400, 414 or 431
to the rest, before rate limits, filters and the WAF run:

```yaml
routes:
  - name: api
    hosts: [api.example.com]
    paths: [/v1/]
    upstream: api
    policy:
      methods: [GET, POST, PUT, DELETE]
      content_types: [application/json]
      require_content_type: true
      max_query_params: 16
      max_headers: 40
      deny_unknown_query: true
      query:
        - {name: page, type: int}
        - {name: sort, type: enum, values: [created, updated]}
        - {name: q, type: string, max_length: 128}
        - {name: id, type: uuid, max_repeat: 50}
```

The security event names the failed check (`detail: query:page:not_int`)
so a broken client is diagnosed from the log, `denied_policy` counts the
refusals and a ban trigger on `policy` catches clients that keep probing.
For bodies use `waf.profiles[].json_schemas` or the `openapi` filter,
which derives the whole positive model, parameters included, from an
OpenAPI description.

### Request normalisation

An attacker who knows the proxy and the application decode differently
writes the path the application will accept and the proxy will not
recognise. `server.normalization` refuses those forms before routing:

```yaml
server:
  normalization:
    reject_double_encoding: true     # %252e%252e
    reject_encoded_slashes: true     # %2F, %5C
    reject_backslashes: true
    unicode: nfkc                    # ｕsers routes like users
```

Control characters and invalid UTF-8 are refused without any setting,
as is ambiguous HTTP/1 framing (the parser refuses most of it; the
check counts what remains). Each refusal carries the check in the
security event (`detail: path_double_encoding`), so a legitimate client
that double encodes is found in the log before the strict setting goes
to production.

### Virtual patching

When a vulnerability is published and the fix is days away, a virtual
patch blocks the exploit's request shape at the proxy:

```yaml
virtual_patches:
  - id: cve-2024-1234
    description: legacy export command injection
    hosts: [www.example.com]
    paths: [/plugins/legacy-export/]
    query: [{name: cmd}]
    status: 404
    expires: "2026-12-31"
  - id: prototype-pollution
    routes: [api]
    body: {pattern: '"__proto__"\s*:', content_types: [application/json]}
```

Conditions combine with AND, so a patch is as narrow as the exploit:
path plus parameter, header pattern on a host, body pattern on a route.
`action: log` runs a patch in shadow first; `expires` retires a
temporary measure on a date so it cannot silently outlive the fix, and
`xproxyctl patches` shows every patch with its hits, last hit and
state:

```
$ xproxyctl patches
PATCH                STATE    ACTION  STATUS  HITS  LAST HIT     EXPIRES     DESCRIPTION
cve-2024-1234        active   block   404     37    2m14s ago    2026-12-31  legacy export command injection
prototype-pollution  active   block   403     0     -            -
log4shell-probe      active   log     403     1203  4s ago       -           JNDI lookups in any header
```

A patch needs no WAF section and runs before it; patches that need the
rule engine's transformations (decoding, normalisation, scoring) are
still written as SecLang in `directive_files`, as
`examples/waf/custom-rules.conf` and `examples/waf/hardening-rules.conf`
show. The second file is the set most estates end up writing by hand:
backup and source-control leftovers answered 404, JNDI and template
expressions, Spring's class loader reached through a bound parameter,
`..;/` path parameters, the diagnostic methods, executable upload names,
bounds on parameters, cookies and byte ranges, GraphQL introspection,
and private keys, cloud access keys and database error messages refused
on the way out.

`examples/waf/attack-surface-rules.conf` is a third file, and a
different kind of rule: it refuses *shapes* rather than payloads —
cloud metadata addresses and non-web schemes in a parameter, the files
a traversal asks for and the PHP stream wrappers that turn one into
code, serialised Java, PHP and YAML objects, external entity
declarations, query operators where a field name belongs, a shell
command after a separator, Spring's SpEL routing header and
Shellshock, the two Transfer-Encoding spellings that let two servers
disagree, the routing headers that poison a cache and the static
extension bolted onto a private path, prototype pollution parameter
names, header injection and off-site redirects, debugger parameters,
uploads that execute in a browser, the scanners that still announce
themselves, and interpreter error pages and directory listings on the
way out. Shape rules are blunter than payload rules: an application
that legitimately fetches `file://` URLs, speaks a Mongo-style query
language or accepts SVG uploads will be refused by one of them. Load
the file into a `mode: detect` profile, read `xproxyctl waf rules` for
a week, and promote what is quiet — which is what the example
`waf.yaml` does.

### Ban list

```yaml
bans:
  state_file: /var/lib/xproxy/bans.db
  action: drop
  exempt_cidrs: [10.0.0.0/8]
  triggers:
    - {name: waf-repeat, reasons: [waf], threshold: 5, window: 1m, duration: 15m}
    - {name: brute,      reasons: [rate_limit, acl], threshold: 20, window: 5m, duration: 1h, escalation: 2, max_duration: 24h}
```

A client that trips the WAF five times in a minute is banned for fifteen
minutes; a second ban within the escalation memory doubles it. With
`action: drop` the connection is closed at accept, which costs the proxy
nothing per attempt. Use `reject` when the proxy sits behind a load
balancer that sets `X-Forwarded-For`, because at accept only the balancer's
address is visible.

#### Distributed attacks: banning networks and tools

An attacker with a thousand addresses stays under every per address
threshold. Two aggregates catch what the addresses have in common:

```yaml
bans:
  triggers:
    - {name: waf-repeat, reasons: [waf], threshold: 5, window: 1m, duration: 15m}
    - {name: net-sweep,  reasons: [waf, rate_limit, account_abuse], aggregate: net, net_v4: 24, net_v6: 48,
       threshold: 50, min_sources: 5, window: 5m, duration: 1h}
    - {name: tool,       reasons: [waf, account_abuse, challenge], aggregate: ja4,
       threshold: 100, min_sources: 10, window: 5m, duration: 6h}
```

`net-sweep` counts denies per client network instead of per address
and bans the whole `/24` (or `/48`) once fifty denies have come from at
least five different addresses in it, so a rented range or a cloud
allocation used for a sweep is closed while a single misbehaving host
in an office network is not enough to ban its neighbours. `tool`
counts per TLS client fingerprint (JA4) across every network and bans
the fingerprint, so a stuffing tool rotating through residential
proxies is refused wherever it connects, while `min_sources` keeps a
fingerprint shared by a popular browser from being banned by one bad
client. The entries show up in `xproxyctl bans` as `203.0.113.0/24` and
`ja4:t13d0403h1_...`, propagate to cluster peers like address bans, and
can be placed or lifted by hand (`xproxyctl ban ja4:<fp>`). Exempt
ranges are never covered by a network ban and never refused by a
fingerprint ban.

### Cluster of proxies

A cluster is either **local** — the three daemons of one machine, over
Unix sockets — or **networked**, over mutual TLS between hosts. The form
of `listen` decides which, and `listen` and every `peers` entry must
agree.

#### The three daemons of one machine

`xproxy`, `xgate` and `xrelay` share a ban list, so an address the
bastion refuses at the SSH port is refused at the edge too. There is no
certificate: the peers are processes this kernel can name.

```yaml
# In each of the three files, with its own node_id and listen path.
cluster:
  node_id: xgate
  listen: unix:/run/xproxy-cluster/xgate.sock
  peers:
    - unix:/run/xproxy-cluster/xproxy.sock
    - unix:/run/xproxy-cluster/xrelay.sock
  local:
    socket_mode: "0660"
    allow_uids: [990, 991, 992]   # id -u xproxy xgate xrelay
  share_rate_limits: false        # different protocols, different ports
  share_bans: true
  share_events: true
```

Two things admit a peer, and both have to be wrong before something
else gets in. The sockets live in `/run/xproxy-cluster`, which the
shipped `tmpfiles.d` entry creates as `0770 root:xproxy-cluster`; the
three daemons are in that group and nothing else is. And `allow_uids`
lists the user ids they run as, read from the connected socket rather
than announced, so a peer cannot talk its way past it. Leaving
`allow_uids` out leaves the whole decision to the file permissions and
validation says so.

A cluster peer is trusted completely — it places bans, decides rate
limits and is named in the audit trail — so a local peer is recorded
under the user id the kernel reported (`uid:991`), never under the node
id it announced. `xproxyctl -socket /run/xgate/mgmt.sock cluster` shows
it.

`examples/estate/` is the whole thing: three files, one shared include,
one local cluster.

#### Across hosts

Issue one certificate per node from a private cluster CA, then on every
node:

```yaml
cluster:
  node_id: edge-1
  listen: 10.0.0.1:7946          # internal interface
  peers: [10.0.0.2:7946, 10.0.0.3:7946]
  tls:
    cert_file: /etc/xproxy/cluster/edge-1.pem
    key_file: /etc/xproxy/cluster/edge-1-key.pem
    ca_file: /etc/xproxy/cluster/ca.pem
    allowed_names: [edge-1, edge-2, edge-3]
```

With this in place every `rate_limits` policy is approximately cluster
wide per key and every ban (manual or triggered) reaches all nodes within
a gossip interval. So do security events: a client that touches a
honeypot on one node is marked on all of them (`xproxyctl honeypot`
shows `peer:<node>/<route>` as the route), and an OIDC logout on one
node revokes the provider session on all of them. `share_rate_limits`,
`share_bans` and `share_events` switch each channel off separately; set
`share_events: false` while nodes older than 1.3 are still in the
cluster, since they close a connection that carries events. `xproxyctl
cluster` shows connection state and the counters per channel; a peer
with `connected: false` and a `last_error` is being redialled with
back-off. Firewall the cluster port to the peers' addresses
(HARDENING.md).

### Fleet management

Many nodes are operated from one controller: `xproxy-fleet` serves each
node the configuration bundle assigned to it and collects the nodes'
status; every node runs the agent. On the management host:

```sh
mkdir -p /var/lib/xproxy-fleet/{common,nodes/edge-1,nodes/edge-2}
cp shared-rules.conf /var/lib/xproxy-fleet/common/waf/custom.conf
cp edge-1.yaml /var/lib/xproxy-fleet/nodes/edge-1/xproxy.yaml
xproxy-fleet validate -dir /var/lib/xproxy-fleet
systemctl enable --now xproxy-fleet        # serve -listen :8447 -cert ... -key ... -ca ...
```

Every node gets the files under `common/` plus its own directory (its
files win), and `nodes/<id>/xproxy.yaml` is the node's configuration,
which carries the `fleet` section that points back at the controller:

```yaml
fleet:
  controller: https://fleet.example.internal:8447
  node_id: edge-1
  tls:
    cert_file: /etc/xproxy/fleet/edge-1.pem
    key_file: /etc/xproxy/fleet/edge-1-key.pem
    ca_file: /etc/xproxy/fleet/ca.pem
```

Issue one certificate per node from a private fleet CA with the node id
as its common name; the controller binds a node id to that name, so a
node cannot fetch another node's bundle or report as it. Editing files
under the directory is the push: the controller rescans every two
seconds, computes a digest per node, and the agents, which long poll,
receive the new bundle within seconds, write it next to their
configuration file, reload and report. A bundle that does not parse is
never served (the previous one stays, `xproxy-fleet nodes` shows the
error); a bundle the node's own validation or sandbox refuses is rolled
back on the node and the error appears in both `xproxyctl fleet` and the
controller's view. `apply: false` on a node turns the agent into a
reviewer: it reports the pending digest without touching anything.

```
$ xproxy-fleet nodes
directory /var/lib/xproxy-fleet  scans 1842
NODE    STATE     ASSIGNED      APPLIED       VERSION  LAST SEEN  REQUESTS  5XX  DENIED  UPSTREAMS  ERROR
edge-1  in sync   7c1a9f0e2b44  7c1a9f0e2b44  1.3.0    12s ago    1848213   31   2201    2/2        -
edge-2  failed    7c1a9f0e2b44  3e0d55a1c9f7  1.3.0    9s ago     1790022   28   2140    2/2        reload: sandbox: /srv/rules.conf (read) outside...
$ xproxy-fleet node edge-2
$ xproxy-fleet bundle edge-1
```

`nodes` states: `in sync` (applied digest equals the assigned one),
`behind` (a newer bundle is assigned), `pending` (received, apply off),
`failed` (the last apply was refused), `stale` (no report for five
minutes), `unassigned` (reporting, no directory), `never seen`. The
controller keeps the last report per node in `status/`, so the list
survives its restart. The configuration history on each node records
fleet applies like any reload, so `xproxyctl history` and `rollback`
work as usual; a rollback is reported as a different applied digest
and the controller shows the node `behind` until the directory is
changed or the node reloads its bundle.

### Priority classes and load shedding

```yaml
shedding:
  target_latency: 250ms
  window: 10s
routes:
  - {name: health,  hosts: [example.com], paths: [/healthz], priority_class: critical, upstream: web}
  - {name: login,   hosts: [example.com], paths: [/login],   priority_class: high,     upstream: web}
  - {name: search,  hosts: [example.com], paths: [/search],  priority_class: low,      upstream: web}
  - {name: web,     hosts: [example.com],                     upstream: web}   # normal
```

When the upstream slows past the target or the proxy nears its concurrency
ceiling, search is shed first, then normal pages, then login; health checks
are never shed. `xproxyctl status` shows `load_level`,
`upstream_latency_ms` and `shedding_classes`. Tune `target_latency` to the
site's healthy time to first byte, not to the slowest page.

### Mutual TLS to upstreams

```yaml
upstreams:
  - name: api
    scheme: https
    tls:
      server_name: api.internal
      ca_file: /etc/xproxy/certs/internal-ca.pem
      min_version: "1.3"
      client_cert_file: /etc/xproxy/certs/edge.pem
      client_key_file: /etc/xproxy/certs/edge-key.pem
      spki_pins: ["<base64 sha256>"]     # xproxyctl spki api.internal.pem
```

The upstream can now require the edge's certificate, and the edge refuses
any upstream whose public key is not pinned. Rotate the client certificate
by replacing the files and running `xproxyctl reload-certs`; a broken pair
is rejected and the old one stays in use. Keep two pins during an upstream
key rotation.

### Forwarding the client certificate identity

```yaml
server:
  listeners:
    - name: partners
      address: ":8443"
      tls:
        certificates: [{cert_file: /etc/xproxy/tls/api.pem, key_file: /etc/xproxy/tls/api-key.pem}]
        client_auth: require
        client_ca_file: /etc/xproxy/tls/partner-ca.pem
routes:
  - name: batch
    hosts: [api.example.com]
    when: 'cert("cn") == "billing-batch"'
    upstream: batch
  - name: partners
    hosts: [api.example.com]
    upstream: api
    request_headers:
      set:
        X-Client-CN: "${cert:cn}"
        X-Client-Fingerprint: "${cert:fingerprint}"
        X-Forwarded-Client-Cert: "${cert:xfcc}"
```

The listener verifies the certificate against the partner CA; the
route forwards the identity the application needs as headers (`set`
discards whatever the client sent under those names, so the values are
trustworthy downstream) and `cert("cn")` in `when` routes a machine
identity to its own pool. `${cert:xfcc}` produces the
`X-Forwarded-Client-Cert` format that applications behind Envoy or
Istio already parse; `${cert:pem}` carries the whole certificate when
the application validates it itself.

### Browser login with OpenID Connect

```yaml
filters:
  - name: sso
    kind: oidc
    options:
      issuer: https://login.example.com
      client_id: intranet
      client_secret_file: /etc/xproxy/sso.secret
      cookie_secret_file: /etc/xproxy/sso.cookie
      external_url: https://intranet.example.com
      scopes: [openid, email, profile]
      forward_headers: {X-Remote-User: sub, X-Remote-Email: email, X-Remote-Name: name}
      require_claims: {hd: example.com}
      log_claims: [email]
      session_ttl: 12h
routes:
  - name: intranet
    hosts: [intranet.example.com]
    upstream: intranet
    filters: [sso]
```

Register `https://intranet.example.com/oauth2/callback` as the redirect
URI at the provider, and
`https://intranet.example.com/oauth2/frontchannel-logout` as the front
channel logout URI so that a logout at the provider (or at another
application) ends the session here too. The first visit bounces through the provider and
comes back to the page that was asked for; after that the browser
carries an encrypted cookie and the application receives the user in
`X-Remote-User`, never a cookie it could misuse. `/oauth2/logout` ends
the session at the proxy and at the provider. Put `basic_auth` or JWT
in front of API paths instead; the OIDC filter is for people with
browsers.

### Browser login with SAML 2.0

For the identity providers that speak SAML and not OpenID Connect, which
in an enterprise is most of the older ones:

```yaml
filters:
  - name: sso
    kind: saml_sp
    options:
      entity_id: https://intranet.example.com/saml/metadata
      idp_metadata_file: /etc/xproxy/saml/idp-metadata.xml
      cookie_secret_file: /etc/xproxy/saml.cookie
      external_url: https://intranet.example.com
      forward_headers: {X-Remote-User: nameid, X-Remote-Email: mail}
      groups_attribute: groups
      session_ttl: 8h
routes:
  - name: intranet
    hosts: [intranet.example.com]
    upstream: intranet
    filters: [sso]
```

Import `https://intranet.example.com/saml/metadata` at the provider — the
proxy serves it from the running configuration — and point
`idp_metadata_file` at the metadata the provider publishes, which is where
its entity ID, its sign-on endpoint and its signing certificate come
from. The flow is the same shape as OpenID Connect's: the first visit
bounces through the provider, the signed response arrives at
`/saml/acs`, and the browser then carries an encrypted cookie while the
application receives the user in a header.

What is different is how much of SAML this accepts. The profile is
deliberately narrow — one unencrypted assertion per response, exclusive
canonicalization, SHA-256 and above, the signing key from the
configuration and never from the document, no provider-initiated sign-on
and no single logout — because SAML's failure mode is a document that
means one thing to the code checking the signature and another to the
code reading the assertion. [CONFIG.md](CONFIG.md) lists every refusal
with its reason, and it is worth reading before configuring the provider:
a provider set to encrypt assertions, or to sign with SHA-1, is refused
rather than accommodated.

### JWT validation

```yaml
jwt:
  providers:
    - name: idp
      issuer: https://idp.example.com/
      audiences: [api]
      algorithms: [RS256, ES256]
      jwks_url: https://idp.example.com/.well-known/jwks.json
      jwks_ca_file: /etc/xproxy/certs/idp-ca.pem
      forward_claims: {X-User: sub, X-Scopes: scope}
      log_claims: [sub]
routes:
  - {name: api,    hosts: [api.example.com], jwt: {provider: idp}, upstream: api}
  - {name: public, hosts: [api.example.com], paths: [/public], jwt: {provider: idp, required: false}, upstream: api}
```

Requests without a valid token get 401 with `WWW-Authenticate`; valid ones
reach the upstream with `X-User` and `X-Scopes` set from the token and the
`Authorization` header removed. A client cannot inject `X-User` itself. For
a first-party service with a shared secret use `algorithms: [HS256]` and
`hmac_secret_file`. Combine with `rate_limits` keyed by `header:X-User`
on a downstream route if you need per-user limits today; token-keyed rate
limits are planned.

### OAuth 2.0 token introspection

```yaml
jwt:
  providers:
    - name: as
      issuer: https://as.example.com
      audiences: [api]
      introspection:
        url: https://as.example.com/oauth2/introspect
        client_id: xproxy
        client_secret_file: /etc/xproxy/as-client-secret
        cache_ttl: 30s
      forward_claims: {X-User: sub, X-Scope: scope}
routes:
  - name: api
    paths: [/api]
    upstream: api
    jwt: {provider: as}
```

Opaque access tokens (reference tokens) cannot be verified locally: the
proxy asks the authorization server's introspection endpoint with its
own credentials and treats the answer as the token's claims, so
`forward_claims`, `required_claims` and `log_claims` work as for a
signed token. Answers are cached for `cache_ttl` (never past the
token's `exp`), positive and negative alike, so a revoked token costs
one call per `cache_ttl`, not one per request. A provider that also has
keys introspects only tokens that are not JWS; `always: true` sends
signed tokens too, which turns a JWT deployment into one with
revocation at the price of a call per `cache_ttl` per token.

### Virus and content scanning (ICAP)

```yaml
icap:
  services:
    - name: av
      url: icaps://scanner.internal:11344/avscan
      tls: {ca_file: /etc/xproxy/certs/internal-ca.pem}
      max_body: 52428800        # 50 MiB uploads
      body_limit_action: reject
      fail: closed
routes:
  - {name: upload,   hosts: [example.com], paths: [/upload],   icap: {service: av}, upstream: web}
  - {name: download, hosts: [example.com], paths: [/files],    icap: {service: av, request: false, response: true}, upstream: web}
```

Uploads are scanned before they reach the application; downloads are
scanned before they reach the client. A detection returns the scanner's
own block page, is logged with reason `icap`, and counts towards ban
triggers. `xproxyctl icap` shows whether each service answered its last
exchange, the preview size it advertised, and how many exchanges were
unmodified, modified, replaced, failed or bypassed.

### TLS passthrough by server name (layer 4)

```yaml
server:
  listeners:
    - name: passthrough
      address: ":8443"
      kind: tcp
      tcp:
        routes:
          - {sni: [mail.example.com, "*.mail.example.com"], upstream: mail}
          - {sni: [legacy.example.com], upstream: legacy}
        default: legacy           # non-TLS and unknown names
        quic: true                # also relay HTTP/3 (UDP 8443) by server name
upstreams:
  - name: mail
    health_check: {path: /healthz}     # for https upstreams checks still use HTTP
    endpoints: [{address: 10.0.3.10:443}, {address: 10.0.3.11:443}]
  - name: legacy
    endpoints: [{address: 10.0.3.20:443}]
```

The upstream keeps its own certificates and the WAF does not see the
traffic (it is encrypted end to end); use an `http` listener with TLS
termination where inspection is wanted. With `quic: true` the same
routes relay QUIC (HTTP/3) datagrams: the server name is read from the
client's Initial packet and every later datagram of that client goes
to the chosen endpoint. `proxy_protocol` applies to TCP connections
only and cannot be combined with `quic`.

### Kubernetes ingress controller

```sh
podman build -f deploy/kubernetes/Containerfile -t registry.example.com/xproxy:1.2 .
kubectl create namespace xproxy
kubectl -n xproxy create secret tls xproxy-default-tls --cert=default.pem --key=default.key
kubectl apply -f deploy/kubernetes/xproxy.yaml
```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop
  namespace: shop
  annotations:
    xproxy.sysctl.se/rate-limits: "api"
    xproxy.sysctl.se/websocket: "true"
spec:
  ingressClassName: xproxy
  tls:
    - hosts: [shop.example.com]
      secretName: shop-tls
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: web, port: {number: 80}}}
          - path: /api
            pathType: Prefix
            backend: {service: {name: api, port: {name: http}}}
```

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: infra}
spec:
  gatewayClassName: xproxy
  listeners:
    - name: https
      hostname: "*.example.com"
      port: 443
      protocol: HTTPS
      tls: {certificateRefs: [{name: wildcard-tls}]}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: shop, namespace: shop}
spec:
  parentRefs: [{name: edge, namespace: infra}]
  hostnames: [shop.example.com]
  rules:
    - matches: [{path: {type: PathPrefix, value: /api}}]
      filters:
        - type: RequestHeaderModifier
          requestHeaderModifier: {set: [{name: X-Tenant, value: shop}]}
      backendRefs:
        - {name: api-v1, port: 80, weight: 90}
        - {name: api-v2, port: 80, weight: 10}
```

The proxy pods read Ingress resources of class `xproxy`, and Gateway
API resources of the same class where the cluster has them, with their
service account, turn them into routes and upstreams (pod addresses
from EndpointSlices, so traffic goes to pods directly; weighted
backends become a weighted pool), install TLS secrets on the `https`
listener and reload within a second of a change through watch
streams, with a full poll every `resync` as the fallback. Everything else in the ConfigMap's `xproxy.yaml` (bans, rate
limits, filters, WAF) applies to the generated routes through the
annotations. `xproxyctl ingress` in a pod shows the controller state.

### DNS proxy with a block list

```yaml
server:
  listeners:
    - name: resolver
      address: "10.0.0.5:53"
      kind: dns
      dns:
        upstreams: ["9.9.9.9:53", "149.112.112.112:53"]
        allow_clients: [10.0.0.0/8]
        block: [tracker.example, "*.ads.example"]
        block_file: /etc/xproxy/blocklist.txt      # hosts file format accepted
        block_action: sinkhole
        sinkhole_ipv4: 10.0.0.5                     # a local page explaining the block
        cache: {max_entries: 100000, max_ttl: 6h}
        rate_limit: {qps: 20, burst: 200}
bans:
  triggers:
    - {name: dns-abuse, reasons: [dns_blocked], threshold: 500, window: 10m, duration: 1h}
```

```yaml
# Encrypted upstreams and DNS over HTTPS for clients
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:53"
      kind: dns
      dns:
        upstreams: ["tls://dns.quad9.net:853", "https://dns.quad9.net/dns-query"]
        upstream_ca_file: /etc/pki/tls/certs/ca-bundle.crt
    - name: https
      address: ":443"
      tls: {certificates: [{cert_file: /etc/xproxy/dns.pem, key_file: /etc/xproxy/dns.key}]}
routes:
  - name: doh
    hosts: [dns.example.com]
    paths: [/dns-query]
    doh: {listener: resolver}
    rate_limits: [doh-clients]
```

Clients on the internal network resolve through the proxy, which
answers repeated questions from its cache, replaces blocked names with
the sinkhole address, refuses everyone else, drops floods per client
and forwards the rest to the upstream resolvers with a fresh
transaction id and source port per query, or over TLS or HTTPS with
reused connections when the upstream string says so. Browsers and
phones can use the `doh` route as their DNS over HTTPS resolver, with
the same block list and cache. `xproxyctl dns` shows the
counters; `log_queries: true` writes every question to the access log
when an investigation needs it.

### Encrypted DNS: DoT, DoH, DoQ and discovery

```yaml
server:
  listeners:
    - name: dns-plain
      address: "10.0.0.53:53"
      kind: dns
      dns:
        upstreams: ["quic://9.9.9.9:853", "tls://149.112.112.112:853"]
        discovery:
          - {transport: doq, name: dns.example.com, port: 853, ipv4: [10.0.0.53]}
          - {transport: dot, name: dns.example.com, port: 853, ipv4: [10.0.0.53]}
          - {transport: doh, name: dns.example.com, port: 443}
    - name: dns-encrypted
      address: "10.0.0.53:853"
      kind: dns
      tls:
        certificates: [{cert_file: /etc/xproxy/certs/dns.pem, key_file: /etc/xproxy/certs/dns-key.pem}]
      dns:
        upstreams: ["quic://9.9.9.9:853"]
        doq: true
```

One certificate and one policy serve all three encrypted transports.
DoT and DoH share the TCP port; **DoQ** takes the UDP one, separated
from HTTP/3 by its ALPN. The reason to add DoQ rather than stop at DoT
is head-of-line blocking: DoT and DoH both ride TCP, so one slow answer
holds up every query queued behind it on that connection — which is
exactly what a resolver's traffic looks like. QUIC gives each query its
own stream.

**Discovery** is the part that changes anything in practice. A client
handed `10.0.0.53` by DHCP has no way to know the same service speaks
DoQ. With `discovery`, it asks `_dns.resolver.arpa` for SVCB records,
gets the endpoints above, verifies the certificate against
`dns.example.com`, and upgrades itself — no client configuration, and
no trust placed in the record, since a certificate it cannot verify
means it stays on plaintext. Order is preference.

```sh
kdig @10.0.0.53 -t SVCB _dns.resolver.arpa            # what a client sees
kdig +quic @10.0.0.53 example.com                     # DoQ
xproxyctl dns                                         # queries_doq, queries_local
```

Watch `xproxy_dns_queries_by_transport_total`: the plaintext share is
the number a rollout has to move, and it moves as clients discover the
encrypted endpoints rather than as this file changes.

### Publishing HTTPS records (and making ECH work)

```yaml
    dns:
      records:
        - name: www.example.com
          type: https
          priority: 1
          target: "."
          params:
            alpn: "h3,h2"
            ipv4hint: "10.0.1.10"
            ech: "AEr+DQBGAwAgACD..."      # from xproxyctl ech keygen
        - {name: example.com, type: https, priority: 0, target: www.example.com}
```

A client cannot use Encrypted Client Hello until it has read the `ech`
parameter from an HTTPS record, so for an estate running its own
resolver this is the other half of that feature: the value
`xproxyctl ech keygen` printed goes here, and `xproxyctl tls` prints
the list the listener is actually serving so the two can be compared.

A name listed in `records` is **owned**: answered locally, never
forwarded, and a type it does not have gets NOERROR with no answers
rather than an upstream lookup — a forwarded answer would contradict
the local one. Answers carry the AA bit and `queries_local` counts
them. `examples/blocklists/dns-encrypted.yaml` is the whole
arrangement: plaintext with discovery, encrypted with all three
transports, and the records.

### Validating DNSSEC for clients

```yaml
server:
  listeners:
    - name: dns
      address: "10.0.0.53:53"
      kind: dns
      dns:
        upstreams: ["9.9.9.9:53", "149.112.112.112:53"]
        dnssec: {}
```

Answers now come with the AD bit for clients that ask for it, forged or
broken answers are refused with SERVFAIL and logged as `dns_bogus`, and
unsigned zones keep working. The root keys are built in; an internal
zone with its own trust anchor adds a DS line to `trust_anchors`.
Clients that set CD (debugging with `dig +cd`) get the raw answer.
`xproxyctl dns` counts secure, insecure and bogus answers per listener.

### Catching a DNS tunnel

```yaml
server:
  listeners:
    - name: resolver
      address: "10.0.0.5:53"
      kind: dns
      dns:
        upstreams: ["9.9.9.9:53"]
        allow_clients: ["10.0.0.0/8"]
        tunnel_detection:
          action: log
          allow_domains:
            - "*.avts.mcafee.com"      # reputation lookups really do look like this
            - "*.spamhaus.org"
            - "*.sophosxl.net"
bans:
  triggers:
    - {name: dns-exfil, reasons: [dns_tunnel], threshold: 1, window: 1h, duration: 24h}
```

A network can block every outbound port and still leak, because the
resolver is the one thing every host may talk to. Tools like iodine,
dnscat2 and DNSExfiltrator put the payload in the query name and take
the answer back in a TXT record; the domain is delegated to the other
end, so the query reaches them whatever `upstreams` says. Blocking the
upstream does nothing about it, and a block list only helps if somebody
already knew the name.

The detector watches the shape of one client's traffic under one
registered domain and needs several signals to agree — encoded-looking
names, a new subdomain nearly every query, mostly TXT, mostly NXDOMAIN,
and the bytes those names carry. Each signal on its own has honest
traffic behind it, which is why `min_signals` defaults to 2 and why
setting it to 1 warns.

Start with `action: log` and read the detections:

```sh
xproxyctl status | grep tunnel
#   dns resolver tunnel log detections 3 blocked 0 tracked 412 evicted 0
```

Each one is a `dns_tunnel` security event naming the domain, the signals
that fired, the queries and the bytes, so it can be argued with rather
than just believed. Put whatever turns out to be a reputation service or
telemetry in `allow_domains`, and only then consider `action: block` —
which answers NXDOMAIN for the whole registered domain, for that client,
for the cooldown, so a false positive is an outage for them.

The ban trigger above is often the better enforcement: a detection is a
strong enough signal to act on the client rather than the name, and the
ban list already knows how to escalate and expire.

### Encrypted DNS for clients (DoT and DoH)

```yaml
server:
  listeners:
    - name: dns
      address: "10.0.0.53:53"
      kind: dns
      dns: {upstreams: ["tls://9.9.9.9:853"], block_file: /etc/xproxy/dns/blocklist.txt}
    - name: dns-tls
      address: "10.0.0.53:853"
      kind: dns
      tls: {certificates: [{cert_file: /etc/xproxy/tls/dns.pem, key_file: /etc/xproxy/tls/dns-key.pem}]}
      dns: {upstreams: ["tls://9.9.9.9:853"], block_file: /etc/xproxy/dns/blocklist.txt, doh_path: /dns-query}
```

Phones and browsers with private DNS settings reach the second
listener over TLS (`dns.example.com` on 853) or HTTPS
(`https://dns.example.com:853/dns-query`); the first keeps serving the
network's plain resolvers. Both apply the same block list and share
the counters, and `xproxyctl dns` shows `queries_dot` and
`queries_doh` next to the UDP and TCP ones. For DoH on 443 next to web
sites, a `doh` route on the https listener (see above) does the same
through the http pipeline.

### Forward proxy for outbound clients (CONNECT)

```yaml
server:
  listeners:
    - name: egress
      address: "10.0.0.5:3128"
      kind: forward
      forward:
        ports: [80, 443]
        allow: ["*.example.com", "api.partner.test", "203.0.113.0/24"]
        deny: ["admin.example.com"]
        auth: {users_file: /etc/xproxy/egress.htpasswd, realm: egress}
        max_tunnels: 2000
bans:
  triggers:
    - {name: egress-abuse, reasons: [forward_denied, forward_auth], threshold: 20, window: 1m, duration: 10m}
```

```sh
xproxyctl htpasswd /etc/xproxy/egress.htpasswd build-agent   # prompts for the passphrase
HTTPS_PROXY=http://build-agent:passphrase@10.0.0.5:3128 curl https://api.example.com/
```

Clients send `CONNECT api.example.com:443` and the proxy tunnels the
bytes after the destination passed the policy: the port is listed, the
resolved address is public (private ranges are refused unless
`allow_private: true`), it is not denied and it matches the allow list.
Plain `http://` URLs are relayed as requests with hop-by-hop headers
removed. Every request is one `forward` line in the access log with the
user and destination; refusals are security events and, with the
trigger above, ban a client that keeps probing. Keep the listener on an
internal address or in front of `tls` with client certificates; a
forward proxy reachable from the Internet without `auth` is an open
relay.

### Seeing inside HTTPS (TLS interception)

```yaml
server:
  listeners:
    - name: egress
      address: "10.0.0.5:3128"
      kind: forward
      forward:
        ports: [80, 443]
        auth: {users_file: /etc/xproxy/egress.htpasswd}
        intercept:
          ca_cert_file: /etc/xproxy/mitm-ca.pem
          ca_key_file: /etc/xproxy/mitm-ca-key.pem
          hosts: ["*.example.com", "*.partner.test"]
          bypass_hosts: ["*.bank.test", "*.nhs.test", "*.tax.test"]
          yara: {rules_dir: /etc/xproxy/yara}
```

A `CONNECT` tunnel is opaque: the proxy knows a name, a port and a byte
count, so the destination policy is the only policy it can apply. The
rules an estate actually cares about — this file must not leave, that
binary must not arrive — are written against bytes, and the bytes are
inside TLS. `intercept` is how they get read: the proxy answers the
client's handshake with a certificate it signs itself, opens its own
TLS connection to the destination, and relays the plaintext between the
two while the scanners see it.

Make the CA and put the certificate — not the key — in the trust store
of every machine whose traffic this covers:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out /etc/xproxy/mitm-ca-key.pem
openssl req -x509 -new -key /etc/xproxy/mitm-ca-key.pem -sha256 -days 825 \
  -subj "/CN=Example Ltd proxy CA" -out /etc/xproxy/mitm-ca.pem
chmod 600 /etc/xproxy/mitm-ca-key.pem   # refused otherwise, at check and at start
```

The order the proxy works in is the security property. It dials the
destination and **verifies the destination's own certificate first**,
and only then forges one for it. A client therefore never sees a
trusted certificate for a server that did not verify — it sees the
handshake fail, which is what it would have seen with no proxy in the
way. `verify_upstream: false` turns that off and warns at validation,
because a proxy that presents a trusted certificate for a server it did
not check has taken the padlock away from every client behind it and
left the picture of one.

`bypass_hosts` is consulted before anything is decrypted and beats
`hosts`. It is where the traffic an estate must not read goes —
banking, health, tax, anything carrying somebody's own credentials —
and the reason it is a separate list rather than an exception inside
`hosts` is that a rule another rule can overtake is not the rule you
wanted.

Two things are refused rather than guessed at. A tunnel whose first
bytes are not a TLS ClientHello is passed through untouched, because
`CONNECT` carries SSH and database protocols too and answering a
handshake to one of those breaks it for nothing. And a handshake whose
server name disagrees with the host in the `CONNECT` is closed: a
tunnel opened to one name and a handshake for another is somebody
reaching a destination the policy checked against a different one.

What the client ends up verifying carries the real certificate's names,
so name pinning still works and key pinning still fails, as it should.
The cache is keyed on the destination's real certificate, so a rotation
upstream produces a fresh forgery rather than a stale one.

```sh
xproxyctl status | grep intercept
# forward_intercepted 184  forward_intercept_refused 2  forward_intercept_passed 11
```

**Tell people.** Interception is lawful and sensible inside an estate
that owns the machines and says so in writing; it is not something to
switch on quietly. `hosts` empty means every destination the listener
allows, and validation warns about exactly that.

### SOCKS5 on the same port

```yaml
server:
  listeners:
    - name: egress
      address: "10.0.0.5:1080"
      kind: forward
      forward:
        socks5: true
        socks_udp: true                  # only if something needs datagrams
        ports: [80, 443, 22, 53]
        allow: ["*.github.com", "proxy.golang.org", "*.example.com"]
        auth: {users_file: /etc/xproxy/egress.htpasswd, realm: egress}
```

```sh
curl --socks5-hostname 10.0.0.5:1080 https://api.example.com/
git config --global http.proxy socks5h://build-agent:pass@10.0.0.5:1080
ssh -o ProxyCommand='nc -X 5 -x 10.0.0.5:1080 %h %p' gateway.example.com
```

An HTTP proxy only helps clients that speak HTTP proxying. Everything
else — `ssh`, `git`, package managers, database clients, anything using
`curl --socks5-hostname` — speaks SOCKS5, and without it that traffic
leaves the estate outside the policy entirely. Turning it on puts it
back under the same destination rules, the same credentials, the same
access log and the same bans.

The two protocols share the port: a SOCKS greeting begins with `0x05`
and an HTTP request with a method, so the first byte separates them.
Nothing is configured twice, and `xproxyctl status` counts both.

With `auth`, SOCKS clients authenticate with RFC 1929
username/password against the same users file, and a client that offers
only "no authentication" is refused outright. Without `auth`, the
listener is an open proxy for both protocols — validation says so at
load, and the answer is an internal address, an allow list, or
credentials.

Refusals come back as the closest SOCKS reply code rather than a
blanket failure, so a client reports something true: "connection not
allowed" for a destination the policy refused, "host unreachable" for a
name that does not resolve. SOCKS4 is refused (no authentication, no
names) and `BIND` is not implemented, because it asks the proxy to open
a listening socket on a client's say-so.

`socks_udp: true` adds `UDP ASSOCIATE`, which is how DNS and QUIC
travel through a SOCKS proxy. Each association gets its own socket,
belongs to the client address that opened it, relays answers only from
destinations that client actually sent to, and dies with its control
connection — the three properties that keep a UDP relay from being an
open reflector. Leave it off unless something needs it;
`forward_udp_dropped` counts every datagram refused, which is what to
watch if it is on.

`examples/forward/socks.yaml` is a complete egress proxy with both
protocols, an allow list, credentials and the ban triggers.

### UDP and IP proxying (MASQUE)

```yaml
server:
  listeners:
    - name: egress
      address: "10.0.0.5:443"
      kind: forward
      protocols: [h1, h2]          # extended CONNECT needs HTTP/2
      tls: {certificates: [{cert_file: /etc/xproxy/certs/proxy.pem, key_file: /etc/xproxy/certs/proxy-key.pem}]}
      forward:
        ports: [53, 443, 853]
        allow: ["9.9.9.9", "*.example.com"]
        auth: {users_file: /etc/xproxy/egress.htpasswd, realm: egress}
        masque:
          udp: true
```

`CONNECT` tunnels TCP and nothing else. Everything datagram-shaped an
estate sends — DNS, QUIC, NTP, telemetry — either goes around the proxy
or does not go at all, and going around it is the usual answer, which
is the problem this solves rather than the protocol being interesting.
A client asks for

```
CONNECT https://proxy/.well-known/masque/udp/9.9.9.9/853/
:protocol = connect-udp
```

and gets a session carrying datagrams as capsules, under the same
destination rules, credentials, access log and bans as a CONNECT
tunnel. `xproxyctl status` counts the sessions and `GET /v1/masque`
reports them per listener.

**CONNECT-IP is a VPN endpoint, and is treated like one.** It needs a
`tun` device that the *operator* creates, addresses, routes and
firewalls — the proxy only opens it:

```sh
ip tuntap add mode tun xproxy0
ip addr add 10.8.0.1/24 dev xproxy0
ip link set xproxy0 up
# then the firewall rules that decide what this tunnel may reach
```

```yaml
        masque:
          ip: true
          ip_device: xproxy0
          ip_assign: ["10.8.0.2/32"]     # the source a client may use
          ip_routes: ["10.0.0.0/8"]      # where it may send
```

The division is deliberate. A userspace process cannot put an arbitrary
IP packet on the wire: a raw socket would need `CAP_NET_RAW`, would not
receive the replies a session needs, and would let a bug here forge any
packet on the network. A tun device confines the traffic to what the
host's routing and firewall allow, and the network policy of a VPN
belongs in the host's configuration rather than in this file. Where no
device is available the request is refused with 501 and the reason goes
to the error log.

`ip_assign` and `ip_routes` are both required because they are the
anti-spoofing rule: a packet whose source is not the assigned address,
or whose destination is outside the advertised routes, is dropped and
counted in `xproxy_masque_dropped_total`. A client is told both in
ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT capsules before it can send
anything.

`examples/forward/masque.yaml` has both, with `ip` off by default.

### Mail submission (SMTP and STARTTLS)

```yaml
server:
  listeners:
    - name: submission
      address: "0.0.0.0:587"
      kind: smtp
      tls: {certificates: [{cert_file: /etc/xproxy/certs/mail.pem, key_file: /etc/xproxy/certs/mail-key.pem}]}
      smtp:
        upstream: mta
        banner: "mail.example.com ESMTP"
        require_tls: true            # no AUTH or MAIL in clear
        require_auth: true           # relay for users, not for whoever connects
        max_recipients: 50
        max_message_size: 26214400   # advertised as SIZE
        upstream_tls_mode: starttls
        upstream_tls: {server_name: mta.internal, ca_file: /etc/xproxy/certs/internal-ca.pem}
```

A `kind: tcp` listener would carry the same bytes to the same mail
server. The reason this is a protocol-aware listener instead is that
SMTP's framing is decided by the reader, and a splice leaves two readers
to decide it separately. The proxy reads each command and each message
itself and writes them out again, so there is one decision:

- **Lines end with CRLF.** A line ended by LF alone is the 2023 SMTP
  smuggling class: a permissive parser sees `\n.\n` as the end of a
  message and a strict one sees a line of text, and the attacker gets a
  second message the first server never knew about. Here it is `500`
  and the session ends (`bare_newlines: convert` repairs the line
  instead, which is only safe because the proxy re-emits it).
- **`STARTTLS` accepts nothing pipelined behind it.** Octets already
  buffered when the command arrives were written before the client
  could see the `220`; treating them as part of the encrypted session
  is CVE-2011-0411. The session ends with `554`, and the event is a
  `smtp_denied` deny that `bans.triggers` can act on.
- **`CHUNKING` is never advertised.** BDAT frames a message with a
  length instead of a terminator, so relaying it would put the framing
  decision back in two places.
- **A reply the proxy cannot parse is not passed on.** The client gets
  `421`. A reply the proxy did not understand is exactly the one the
  client would read differently.

On 465, `tls_mode: implicit` gives RFC 8314 implicit TLS with no
plaintext phase to downgrade; drop `STARTTLS` from `commands` there, so
nothing offers an upgrade that is already done.

The capability list the client sees is the proxy's promise rather than
the upstream's: hidden keywords are stripped, `SIZE` is replaced by
`max_message_size` when one is set, and `STARTTLS` is advertised only
while the proxy can still answer it. `banner` replaces the mail
server's greeting, which otherwise tells every prober its brand and
version.

Refusals are bounded on purpose. `max_errors` ends a session that walks
the command space, `max_recipients` and `max_messages` keep one
connection from becoming a fan-out, and `VRFY` and `EXPN` are not in
the default command set because they answer whether an address exists.

`examples/mail/submission.yaml` has both listeners, the ban trigger and
the upstream TLS.

### MQTT for a device fleet

```yaml
server:
  listeners:
    - name: iot
      address: "0.0.0.0:8883"
      kind: mqtt
      tls: {certificates: [{cert_file: /etc/xproxy/certs/iot.pem, key_file: /etc/xproxy/certs/iot-key.pem}]}
      mqtt:
        upstream: broker
        require_auth: true
        client_id_pattern: "^device-[0-9a-f]{12}$"
        publish_allow: ["devices/+/telemetry", "devices/+/status"]
        publish_deny:  ["$SYS/#", "devices/+/commands"]
        subscribe_allow: ["devices/+/commands", "estate/announcements"]
        subscribe_deny:  ["$SYS/#"]
        allow_retain: false
        upstream_tls_mode: implicit
        upstream_tls: {server_name: broker.internal, ca_file: /etc/xproxy/certs/internal-ca.pem}
```

An MQTT broker's authorisation is per topic, and a topic is a string
inside a packet. A `kind: tcp` listener carries those packets without
looking, so there is nowhere to say that a device may publish its own
telemetry and nothing else — and a device that holds a broker
credential holds the whole tree, including what every other device
publishes. That is what this listener is for.

The subtlety worth knowing is that **a subscription is a filter, not a
topic**. A device asking for `#` is not asking for one topic; it is
asking for all of them. So `subscribe_allow` is checked by subsumption:
an entry must cover everything the requested filter could deliver.
`devices/+/commands` allows `devices/1/commands` and allows
`devices/+/commands`, and refuses `devices/#` and `#`. `subscribe_deny`
is checked the other way, by overlap: a filter is refused when it could
reach anything denied, not only when it names it.

`publish_allow` and `publish_deny` are simpler, because a publication
names one concrete topic. They also cover the will — the message the
broker publishes on the device's behalf once it is gone — which is
checked at CONNECT, the only moment there is.

Refusals end the session by default. `action: drop` refuses the one
packet instead and answers it properly (PUBACK or PUBREC with
not-authorized, a SUBACK of failures), which is what a fleet wants: one
misconfigured device should not fall off the network, and a QoS 1
publisher that is never acknowledged retries for ever.

MQTT has no STARTTLS. `tls_mode: implicit` on 8883 is the only
encrypted shape, and a plaintext listener stays plaintext for the life
of the session — validation says so rather than leaving it implied.

`examples/iot/mqtt.yaml` has the whole thing, with a ban trigger on
`mqtt_denied`: a device does not probe topics, so something walking the
tree is either broken or not a device.

### A syslog relay that reads what it forwards

```yaml
server:
  listeners:
    - name: relay
      address: "0.0.0.0:514"
      kind: syslog
      syslog:
        upstream: collectors
        udp: true
        allow_senders: ["10.0.0.0/8"]
        hostname: annotate
        min_severity: info
        rate_limit: 500
        redact:
          - {name: card, pattern: "[0-9]{13,16}", with: "[card]"}
```

A relay that forwards syslog without reading it is a pipe. The reason
to read it is that almost every field is written by the sender and
believed by the collector: the host name, the facility, the severity,
the time. A message claiming to be `auth.emerg` from another machine
costs nothing to send.

**And a message whose text carries a newline becomes two records** in
any collector that frames on newlines — the second one saying whatever
the sender wanted a record to say, with a priority of its own. That is
the injection this format invites, and it is the reason every message
here is parsed and re-emitted as RFC 5424 in one framing, whatever
arrived. One dialect out means the record a collector stores is the
record the relay decided about.

`hostname` is the other half of the same idea. `keep` takes the sender's
word, which nothing checks; `observed` replaces the field with the
address the message came from; `annotate`, the default, keeps both and
says which is which, because the sender's name is often the useful one
and is never the true one.

The rest is what a relay in front of a SIEM needs: facility and
severity filters, sender CIDRs (on UDP the only authentication there
is), a per-sender rate limit — a log flood is a denial of service on
the collector and a way to push older records out of its window —
patterns that drop a record and patterns that redact part of one, and a
bounded queue that drops and counts rather than holding every sender
behind one slow collector.

Both transports on one address: TCP with either RFC 6587 framing, UDP
one datagram per message, TLS as RFC 5425 defines it. A message over
the bound on a delimited stream is dropped and the connection carries
on; on a counted stream it ends the connection, because refusing to
read the octets a frame declared leaves the reader at an offset nobody
knows.

**The secure upgrade.** A switch, a printer, an appliance or a
twenty-year-old application sends syslog the only way it knows: in
clear, usually over UDP. It cannot be taught TLS and the vendor is not
going to teach it. Put this relay next to it:

```yaml
    - name: legacy
      address: "10.20.0.1:514"
      kind: syslog
      syslog:
        upstream: collectors
        udp: true
        tls_mode: none              # the senders could not use one
        upstream_tls_mode: implicit # this is the upgrade
        upstream_tls: {server_name: siem.internal, ca_file: /etc/xproxy/certs/internal-ca.pem}
        allow_senders: ["10.20.0.0/24"]
        hostname: observed
```

Clear UDP or plain TCP in, RFC 5425 TLS out, and the records arrive at
the collector as RFC 5424 whatever dialect the device speaks. The
sender never changes; the part of the path that crosses anything does.

What it does not do is make the sender trustworthy. Between the device
and this port the records are still in clear and still forgeable, so
put the port where only those devices can reach it, keep
`allow_senders` tight, and let `hostname: observed` record where each
record actually came from rather than what it claimed to be.

`examples/logs/syslog.yaml` has a general relay, a legacy upgrade
listener and a separate audit path with client certificates.

### FTP with the data connection mediated

```yaml
server:
  listeners:
    - name: intake
      address: "0.0.0.0:21"
      kind: ftp
      tls:
        certificates: [{cert_file: /etc/xproxy/certs/ftp.pem, key_file: /etc/xproxy/certs/ftp-key.pem}]
      ftp:
        upstream: files
        tls_mode: starttls
        require_tls: true
        data_ports: "50000-50100"
        allow_paths: ["/srv/intake/{user}/**"]
        deny_extensions: [exe, dll, so, sh, php]
        max_file_bytes: 2147483648
        yara: {rules_dir: /etc/xproxy/yara, action: close}
```

FTP is two connections, and the second one is why this cannot be a
`tcp` listener. Every transfer happens on a data connection whose
address one side announces to the other inside a reply; a proxy that
forwards that reply has told the client to go round it, and the
commands it read are instructions for a transfer it never saw. So the
proxy replaces the address with its own, listens on one side and dials
the other, and the file passes through it. Only the port the target
announced is used — the proxy dials the host its control connection is
already talking to, so a target cannot redirect it somewhere else. And
only the side that arranged the connection may use it: a passive
connection has to come from the client's own address.

**`PORT` and `EPRT` are off by default**, and that is not a
compatibility oversight. They ask the server to connect back to an
address the client names, which makes it a port scanner and a relay for
anyone who can log in: the bounce attack, CERT CA-1997-27. With
`allow_active: true` the announced address has to be the client's own
and the port unprivileged; that check is the whole of the defence.

The rest is the same vocabulary as the SFTP policy, because the
questions are the same: `read_only`, path lists that may name `{user}`,
extension lists that read every suffix in a name, a bound on one
transfer, and rules over what is uploaded. `max_file_bytes` and a rule
match both act by cutting the data connection and answering 426 rather
than 226 — a transfer cannot be un-sent, so there is nothing else
honest to do.

A control line that is not exactly CRLF-terminated is refused, and so is
one carrying a telnet `IAC`. Each is a way for the proxy and the target
to disagree about where a command ends: the proxy reads `NOOP` and the
target reads `NOOP` and the `DELE` hidden behind a bare newline.

`require_tls` defaults on wherever TLS is reachable, because a control
connection in clear carries the password. `PROT P` data is terminated on
both sides rather than tunnelled, so a protected transfer is still one
this proxy can bound and read. `CCC` is refused: clearing the control
channel after `AUTH TLS` puts every path that follows back in clear.

`examples/files/ftp.yaml` has a supplier drop box and a read-only
mirror.

### SSH bastion with SFTP inspection

```yaml
server:
  listeners:
    - name: bastion
      address: "0.0.0.0:22"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [/etc/xproxy/ssh/host_ed25519]
        authorized_keys: /etc/xproxy/ssh/authorized_keys
        allow_channels: [session, direct-tcpip]
        allow_requests: [pty-req, env, shell, exec, subsystem, window-change, signal]
        allow_subsystems: [sftp]
        forward: ["10.20.0.0/16:5432"]
        upstream_user: operator
        upstream_key_file: /etc/xproxy/ssh/bastion_id_ed25519
        upstream_known_hosts: /etc/xproxy/ssh/known_hosts
```

A jump host forwards the stream, so it cannot tell a shell from a port
forward and the only policy it can hold is "may connect". This listener
terminates the client's SSH session and opens its own to the target, so
the channels and the requests inside them are decisions: `direct-tcpip`
only to the destinations in `forward`, `exec` only for commands matching
`allow_commands`, `subsystem` only for the ones listed, and `x11-req`
and agent forwarding refused unless something asks for them — each of
those hands whatever runs on the target a channel back into the client.

The other half is the credential. The client authenticates to the
bastion with its own key; the bastion authenticates to the target with
`upstream_key_file`, which no client holds. A developer key that leaves
on a laptop is then not a key that opens a server, and
`upstream_known_hosts` makes the bastion the one place that would notice
a machine in the middle.

**One policy for everyone is one policy too few.** `authorized_keys`
says who may connect; `principals` says what each of them may do, and
the listener's own settings are what an entry leaves unset:

```yaml
        trusted_user_ca_keys: /etc/xproxy/ssh/user_ca.pub
        principals:
          - name: deploy-bot
            fingerprints: ["SHA256:2nFf3v0mP7nMZcRe0KQ1ZFQ5t3aJH2c7pXoLdW8yqQk"]
            policy:
              upstream_user: ci
              allow_requests: [exec]
              allow_commands: ["^/usr/local/bin/deploy( |$)"]
          - name: on-call
            cert_principals: [oncall]      # signed by the CA above
            policy: {upstream_user: operator}
          - name: on-leave
            fingerprints: ["SHA256:8kJq0pZ1rT4yWn6XsB2cVfL9dE3hGm5uA7iOxQ1zRyM"]
            policy: {deny: true}
          - name: staff                    # names no key, so it is the default
            policy: {allow_commands: ["^(uptime|df -h)$"]}
```

Once there is one entry the list is the policy: a key no entry covers is
refused at authentication rather than served under the listener's
default, because falling back would be the opposite of what the list
says. An entry naming neither a fingerprint nor a certificate principal
matches everything and must therefore be last. `deny: true` is how a key
stays in `authorized_keys` while the person it belongs to is on leave,
without the list losing the record that they exist.

With `trusted_user_ca_keys` a certificate is accepted when its signature
verifies, its validity window covers now, and its principal list names
the login being used — which is how the rota changes without this file
changing.

**Two ways to run code the command policy never sees.** The first is the
environment. `allow_env` defaults to `TERM`, `LANG` and `LC_*`, and the
loader and interpreter variables (`LD_PRELOAD`, `BASH_ENV`, `PERL5OPT`,
`PYTHONSTARTUP`, `PATH`, …) are refused whatever it says — naming one
fails the load. A target that reads `LD_PRELOAD` runs the attacker's
code before it runs the command `allow_commands` approved.

The second is `scp` and `rsync`. Neither ever opens the `sftp`
subsystem, so a read-only `sftp` policy with `exec` allowed is a
read-only policy with `scp -t` wide open beside it. So
`allow_file_transfer_commands` defaults to `false` exactly where there
is an `sftp` section to bypass, and setting it to `true` there warns.
Every word of the command is read, not only the first, each the way a
shell would take it (directory part removed, `VAR=value` prefixes
skipped): a wrapper is otherwise all it takes to walk past the check —
`env scp -t`, `sudo rsync`, `sh -c 'scp -t /etc'`. That refuses more
than it must, which is the direction to be wrong in.

**SFTP is where "may use sftp" stops being the whole answer.** The
entire difference between reading a file and deleting a tree happens
inside the subsystem channel:

```yaml
        sftp:
          read_only: true
          allow_paths: ["/srv/exports/**"]
          deny_paths:  ["/srv/exports/private/**"]
          deny_operations: [symlink, readlink]
```

Each request is decided and refused with a permission-denied status, so
the session survives and the client is told which operation was refused.
A path that climbs above its own root (`../../etc/shadow`) is refused
rather than matched: what it means depends on a working directory the
proxy cannot see, and a check on a path whose meaning is unknown is not
a check. Absolute paths always work.

**One rule instead of one per person.** A path pattern may name the
session's own identity:

```yaml
        sftp:
          allow_paths: ["/srv/intake/{user}/**"]
          deny_paths:  ["/srv/intake/{user}/.ssh/**"]
          allow_extensions: [csv, xml, pdf, gz]
          deny_extensions: [exe, dll, so, sh, php]
          max_file_bytes: 1073741824
          yara: {rules_dir: /etc/xproxy/yara, action: close}
```

`{user}` is the login the client authenticated as and `{principal}` the
`principals` entry covering its key; both are substituted once, when the
subsystem starts. A name that could change what the pattern means —
anything outside letters, digits, `-`, `_` and `.` — refuses the session
instead of being escaped into it, because a login of `../..` expanded
into an allow list is an allow list for somebody else's directory.

`allow_extensions` and `deny_extensions` decide what a file may be
called, on `open` and on both names of a `rename` or `symlink`. Every
extension in a name is read, not only the last, so `invoice.pdf.exe` is
an exe whatever the allow list says.

**A write is the one request whose content the proxy can see**, so two
checks live there. `max_file_bytes` bounds the file the writes make,
counted from the highest offset any write reaches rather than from the
bytes that arrived — otherwise a client writes one byte at a gigabyte
and stays under every total. And `yara` runs the rule set per file: each
open handle gets its own scanner, because two uploads interleaved on one
channel are two files and a rule about a file's first bytes is a rule
about one of them. A match refuses that write and logs `yara_match` with
the path; `action: close` ends the transfer rather than only that
packet. Both of these need to know which handle is which file, so a
write on a handle whose `open` the proxy never saw is refused: a write
that cannot be held to a bound is not a write to pass on.

**What was actually done in the session.** The access log says one
happened; `recording` writes what it showed, one file per channel, in
the asciicast v2 format:

```yaml
        recording:
          directory: /var/log/xproxy/sessions
          max_file_bytes: 33554432
          max_files: 2000
```

`xproxyctl session` reads one back; the format is line oriented, so one
cut short by a crash or by the bound still plays up to where it stops.
The header carries the terminal size, the login and the target, and for
an `exec` the command; a `window-change` becomes a resize event; stderr
is recorded with stdout, because a terminal does not keep them apart and
a recording without stderr is missing exactly the errors. An `sftp`
channel is not recorded — it is not a terminal, and its own log line
already says what each request did.

### Reading a recording without running it

**A recording is a program for a terminal, and the person recorded
wrote it.** That is not a flaw in the format; it is what a faithful
record of a terminal session *is*. A terminal is an interpreter of
exactly those bytes, and some of what it will do on request reaches
outside the window a replay is drawn in:

- `OSC 52` writes the reviewer's clipboard, and waits to be pasted.
- `OSC 0`, `OSC 2` and `OSC 7` retitle the window and change what it
  says the working directory is; `OSC 8` makes a hyperlink whose text
  and target need not agree.
- The device reports — `CSI c`, `CSI n`, `DECRQSS`, the window
  manipulation sequences — make the terminal **write back on its own
  input**. What a terminal writes on its input, a shell reads as a
  command line. This is the one that turns reading a log into running
  one.
- The mouse and focus reporting modes make the terminal send on every
  movement; `CSI t` resizes and moves the window.
- A bidirectional override reorders a line, so what is on the screen and
  what is in the file disagree.

So read one with the tool rather than with `cat` or a player:

```sh
xproxyctl session list /var/log/xproxy/sessions
xproxyctl session show /var/log/xproxy/sessions/ssh-alice-20260924T101500.cast
xproxyctl session show -safe FILE      # keep the colours, name the rest
xproxyctl session play -speed 2 FILE   # with the timing it had
```

`show` keeps the text and drops every sequence, which is what reading a
session wants. `-safe` keeps the ones that draw inside the window —
colour, cursor movement, erasing — and writes the rest out in a form no
terminal acts on, so a sequence the session sent appears as
`\e]52;c;cHduZWQ=\x07` rather than silently doing something or silently
going missing. `play` is `-safe` by default. The file is never
rewritten: what is on disk is what happened, because a record an
operator cannot trust is not a record.

The same filtering is on everything `xproxyctl` prints, since most of
what its tables carry came off the network as well.

`input: false` is the default and stays that way unless you mean it: a
terminal's input stream carries what the screen never showed, which
includes every password typed into a `sudo` prompt. Recording output is
watching over a shoulder; recording input is a keylogger, and the
difference matters to the people recorded and to whoever holds the
files. Those files hold everything an administrative session printed —
keys, configuration, tokens — so the directory deserves the care its
contents will deserve. A principal's `recording` replaces the
listener's, so one entry can be recorded and another spared with
`recording: {enabled: false}`.

Every session writes an `ssh` access line, every allowed `exec` is a
security event with the command line, every closed recording writes an
`ssh_recording` line with the file and its size, and every inspected
SFTP request writes an `sftp` line with the operation and the path. That record is
the other reason to terminate rather than forward: a stream you cannot
read is a stream you cannot log.

`examples/bastion/ssh.yaml` has an operator listener with principals for
a deployment robot, an on-call rota by certificate and everyone else,
and a delivery account that can do nothing but read one directory over
sftp.

### A second factor, on SSH and on HTTPS

```sh
xproxyctl mfa enrol -user alice -issuer example.com -recovery 5
```

That prints one line for the enrolment file (0600), an `otpauth://` URI
for the user's authenticator, and five single-use recovery codes shown
only then. The same file serves both listeners below, which is the
point: a second factor that means different things on different ports
is not a second factor, because the weakest door decides.

```yaml
server:
  listeners:
    - name: bastion
      address: "0.0.0.0:22"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [/etc/xproxy/ssh/host_ed25519]
        authorized_keys: /etc/xproxy/ssh/authorized_keys
        upstream_key_file: /etc/xproxy/ssh/bastion_id_ed25519
        upstream_known_hosts: /etc/xproxy/ssh/known_hosts
        mfa:
          file: /etc/xproxy/mfa

filters:
  - name: staff
    kind: basic_auth
    options: {users_file: /etc/xproxy/staff.htpasswd}
  - name: staff-mfa
    kind: mfa
    options:
      file: /etc/xproxy/mfa
      cookie_secret_file: /etc/xproxy/mfa.cookie

routes:
  - name: app
    paths: [/]
    upstream: app
    filters: [staff, staff-mfa]      # order matters
```

On SSH the key is the first factor: the client is told authentication
partially succeeded (RFC 4252) and is then asked for a code over
keyboard-interactive. A key alone opens no channel. On HTTPS the filter
challenges whatever identity the filter before it established, with an
HTML form and a signed cookie afterwards; `mfa` before `basic_auth`
would have nothing to challenge, and refuses the request rather than
prompting.

Three properties are worth knowing because they are what makes it a
second factor rather than a second password:

- **A code is spent when used.** A later attempt at the same step, or at
  an earlier one, is refused even though it verifies. The memory is per
  process, so in a cluster a code can be replayed once per node; put the
  listener behind one node where that matters, or set `skew: 0`.
- **Failures are indistinguishable.** A wrong code, a replayed one, a
  locked account and a name that never enrolled get one answer. On SSH
  the prompt is shown even to a user with no enrolment: refusing before
  asking would say the name is not enrolled.
- **Guessing is bounded.** Six digits is a million values and a step
  lasts thirty seconds, so `max_failures` within `window` locks the user
  out for `lockout` — without it a fast client gets a real chance at
  every step.

`require_enrolment: false` exists and warns, because the account that
never enrolled is the one an attacker will use.

`examples/mfa/bastion.yaml` and `examples/mfa/web.yaml` are the two
halves: the SSH listener xgate serves and the filter chain xproxy
serves, against one enrolment file on disk.

### Administering enrolments

The enrolment file is the authority and every listener re-reads it when
it changes on disk, at most once a second. So a change takes effect on
the next connection: no reload, and — the half that matters — removing
somebody actually removes them, instead of leaving them enrolled until
whoever remembers runs a reload.

Three ways to make one, all writing the same file:

```sh
xproxyctl mfa enrol -user alice -issuer example.com -recovery 5
xproxyctl mfa list -file /etc/xproxy/mfa
```

In the GUI, the **MFA** page lists every listener that asks for a second
factor with who is enrolled, how many recovery codes are left and who is
locked out, and an operator can enrol, replace somebody's recovery
codes, remove them or unlock them. A viewer sees the list and can change
nothing. In `xproxyctl tui`, the MFA screen shows the same list; `u`
unlocks the selected person and `x` removes their second factor, each
after a confirmation.

The GUI's enrolment shows a QR code of the `otpauth://` URI beside it:
point the authenticator at the screen rather than typing twenty-six
characters into a telephone, which is where enrolments go wrong. The
symbol is drawn by the daemon and arrives as an image in the answer, so
nothing is fetched from anywhere and the URI is there to read either
way.

Enrolling is only in the GUI and in `xproxyctl mfa enrol`, because the
secret, the `otpauth://` URI and the recovery codes exist in exactly one
answer and are never stored: the file keeps what checks a code and
hashes of the recovery codes, nothing that can produce one. Hand them
over then, or enrol the person again.

Two things about scope are worth reading twice, and both are on the
screen:

- **An enrolment belongs to the file, not to the listener.** Enrolling
  through one listener enrols the person on every listener that reads
  the same file, which is usually what one file is for.
- **A lockout belongs to the listener, not to the file.** It lives in
  the process that counted the wrong codes, so unlocking is per
  listener, and in a cluster per node.

Every change is audited twice over: by the daemon with the calling
process's kernel-reported credentials, and, when it came through the
GUI, by the GUI with the operator's account. Neither line ever carries
what was handed out — only who changed whose factor on which listener.

### YARA rules over streams and bodies

```yaml
server:
  listeners:
    - name: transfer
      address: "0.0.0.0:2121"
      kind: tcp
      tcp:
        default: files
        yara:
          rules_file: /etc/xproxy/rules/stream.yar
          action: close
          directions: [client, upstream]
          max_bytes: 33554432

filters:
  - name: upload-scan
    kind: yara
    options:
      rules_file: /etc/xproxy/rules/stream.yar
      scan: [request]
      action: block
      content_types: ["application/octet-stream", "application/zip"]
```

The engine is a subset of the YARA language written in Go. That is a
deliberate trade: linking libyara would mean `CGO_ENABLED=1` and a C
parser in the data plane, and the proxy's build property is worth more
than the last few features of the grammar. `docs/CONFIG.md` lists
exactly what is supported — strings with `nocase`, `wide`, `fullword`,
hex with `??` wildcards and bounded jumps, RE2 regular expressions, and
conditions up to `N of ($a*)`, `#a` and `filesize`. Everything else is
**refused at load with the line number**, because a rule that silently
matched nothing would be worse than one that will not start.

Two things differ from scanning a file, and rules should be written
knowing them:

- **A rule fires the first time its condition becomes true**, not at the
  end. A decision that arrives after the last byte is a decision about a
  transfer that already happened. Conditions that can be satisfied by a
  prefix are the useful ones here.
- **`filesize` is the bytes seen so far.** `filesize > 1MB` becomes true
  partway through a large transfer; `filesize < 100` is only reliable
  near the start.

On a layer 4 listener nothing is held back waiting for a verdict: the
bytes scanned are the bytes forwarded, because a stream cannot be paused
without the peer noticing. What a match decides is whether the
connection continues. In the filter a body is buffered to `max_bytes`
first, so there a match can refuse the request; past the bound the body
is forwarded and the access log marks it `yara_partial`, because holding
an arbitrary upload in memory is a worse failure than an unscanned tail.

Start with `action: log` (or `action: log` on the filter). A rule set
decides nothing until it has been watched against real traffic for a
while; `xproxy_yara_matches_total` and the `yara_match` security events
are what that watching looks at.

`examples/yara/rules.yar` has a starting set — executable headers,
archives of executables, dropped shell scripts, leaked credentials, a
planted internal marker, webshells — and `examples/yara/scanning.yaml`
wires it into both places.

### Virtual security.txt

A `security.txt` (RFC 9116) tells a finder where to report a
vulnerability. It belongs to the organisation rather than to any one
application, so putting a file on every origin means every team that
owns an origin has to remember it — and the host that forgot is the one
a finder tries. Here it is configuration, served by the proxy **before
routing**, so a host with no route at all still answers.

```yaml
security_txt:
  # Internal clients get the contact that reaches somebody today.
  - name: internal
    client_cidrs: ["10.0.0.0/8", "fd00::/8"]
    contact: ["mailto:appsec@corp.internal"]
    valid_for: 720h
  # One brand.
  - name: shop
    hosts: ["shop.example.com", "*.shop.example.com"]
    contact: ["https://example.com/vdp", "mailto:security@example.com"]
    policy: ["https://example.com/vdp"]
  # A naming scheme a wildcard cannot express.
  - name: numbered-api
    host_regex: '^api[0-9]{1,3}\.example\.com$'
    contact: ["mailto:api-security@example.com"]
  # The addresses themselves: a machine found in a range scan has no
  # name for a finder to go on.
  - name: parked-addresses
    host_cidrs: ["198.51.100.0/24", "2001:db8:1::/48"]
    contact: ["mailto:security@example.com"]
  # Everything else, parked names included. No selectors, so it goes
  # last and answers what the entries above did not.
  - name: default
    contact: ["mailto:security@example.com"]
```

Entries are tried in order and the first whose selectors *all* match
answers. Selectors come in two kinds, and both must hold:

- **Which host was asked for** — `hosts` (exact names and `*.`
  wildcards), `host_regex`, and `host_cidrs` for a `Host` that is an
  address literal rather than a name. These are a union: any one of
  them naming the host is enough. An entry with none of them answers
  for every host.
- **Who is asking, and where** — `client_cidrs` and `listeners`. These
  narrow: an entry naming them answers only inside them.

So one host is `hosts: ["shop.example.com"]`, a group is a wildcard, a
regular expression or a CIDR, and all of them is an entry with no host
selector at all. `host_cidrs: ["0.0.0.0/0", "::/0"]` is every address
literal there is, for an estate whose addresses are not known in
advance; a `Host` that is a name never matches it, because the proxy
does not resolve the `Host` header and a document that turned on what a
name resolves to would be answering on the client's word.

The document is rendered from the fields, with `Expires` required by
the RFC: set it explicitly, or set `valid_for` and let every reload
push it forward so it cannot quietly go stale. For a clear-signed
document, `body_file` is served verbatim and re-read on reload — give
that one an explicit `Expires` inside the signature, since `valid_for`
cannot refresh what is signed.

```sh
curl -s http://localhost:8080/.well-known/security.txt
curl -s -H 'Host: 198.51.100.7' http://localhost:8080/security.txt
```

A request that matches no entry is routed as usual, so an origin
already serving its own file keeps doing so. Only `GET` and `HEAD` are
answered; the `security_txt` counter records how many were served, and
the access log names the entry that answered.
`examples/security/security-txt.yaml` is the whole pattern.

### Honeypot routes and decoys

The sections that follow — honeypot routes, honeytokens, form
honeypots, the slow lane, deceptive answers and refusal at the
handshake — are one family, and [DECEPTION.md](DECEPTION.md) is the
chapter that reads them together: what each costs an attacker, how a
mark propagates from one to the next, and the order to build them in.
Each section here is the worked example of one.

```yaml
routes:
  - name: wp-probe
    paths: [/wp-login.php, /xmlrpc.php]
    honeypot: {decoy: wp-login, delay: 2s}
    response_headers: {set: {Server: "Apache/2.4.41 (Ubuntu)"}}
  - name: env-probe
    paths: [/.env, /.git/config]
    honeypot: {decoy: env}
  - name: admin-probe
    paths: [/admin]
    honeypot: {body_file: /etc/xproxy/decoys/admin.html, status: 200}
bans:
  triggers:
    - {name: probes, reasons: [honeypot], threshold: 1, window: 10m, duration: 24h}
```

A scanner that asks for `/.env` receives a plausible file and is banned
on the spot; the security log records the request with reason
`honeypot`. Clients that touched a honeypot stay marked for an hour by
default: their later requests on every route carry
`honeypot_marked: true` in the access log, and a `bot_score` filter can
weigh the mark. `xproxyctl honeypot` lists the marks and the decoy names
this build carries.

Seventy-seven decoys ship built in, grouped in docs/CONFIG.md by what a
scanner is after: PHP and WordPress, leaked files, the secrets a laptop
or a build agent leaves behind (`.npmrc`, `.pypirc`, `.gitlab-ci.yml`,
`terraform.tfstate`, `.vscode/sftp.json`, `appsettings.json`,
`config/database.yml`, `web.config`), the cloud and orchestration APIs a
server side request forgery probe asks for (`imds`, `gcp-metadata`,
`azure-imds`, `consul`, `vault`, `docker-api`, `kubelet`), data stores,
dashboards and the newer scan targets (`couchdb`, `solr`, `rabbitmq`,
`kibana`, `prometheus-config`, `traefik`, `clickhouse`, `minio`,
`jupyter`, `ollama`), the application servers with their own exploit
history (`weblogic`, `jboss`, `coldfusion`, `aspnet-trace`,
`registry-catalog`, `argocd`, `keycloak`), and the enterprise front
doors a mass scanner fingerprints before it picks an exploit
(`confluence`, `gitlab-login`, `citrix`, `fortinet`, `esxi`,
`exchange-autodiscover`, `ivanti`, `nextcloud`, `cpanel`, `cgi-bin`,
`printer`, `camera`). Every credential, key and host name in them is
visibly fake, and a test refuses a decoy that hands one out without a
marker saying so.

`examples/security/honeypots.yaml` wires up all of them — one route per
decoy and the ban ladder that turns a sweep into a ban — with the mark
scaled to what the request means: an hour for a path a confused crawler
might reach, six hours for a file that only a credential hunt asks for,
a day for a metadata or orchestration probe.

```yaml
# The probes that are never a mistake: the client is asking this proxy
# to fetch its own credentials.
routes:
  - name: hp-imds
    paths:
      - /latest/meta-data
      - /latest/meta-data/iam/security-credentials
      - /computeMetadata/v1
      - /metadata/instance
    honeypot: {decoy: imds, mark: 24h, delay: 5s}
  - name: hp-kubelet
    paths: [/pods, /runningpods, /metrics/cadvisor]
    honeypot: {decoy: kubelet, mark: 24h, delay: 5s}
```

Two rules keep a honeypot from becoming an outage of its own. Never put
one in front of a namespace a real application serves — if the origin
answers `/admin`, do not shadow it here — and keep the catch-all route
last, so every decoy path is the more specific match. The shipped
example is checked for both.

### Answering a scanner with something plausible

Refusing tells the scanner which request was the interesting one. It
will vary that request until something is not refused, and the refusal
is the signal that says when it has found the way through.

```yaml
routes:
  - name: api
    paths: [/api]
    upstream: app
    deceive:
      marked: true
      status: 200
      body: '{"items":[],"total":0}'
      content_type: application/json
      mark: 1h
```

A client a honeypot or a honeytoken marked now gets an empty, valid,
uninteresting answer from `/api` — and its writes never reach the
origin. The crawl finishes, the data is wrong, and nothing in the
response says so.

This is the sharpest tool in the configuration, so treat it that way. A
route must name a condition (validation refuses one that would admit
everybody, and warns on every route that has a `deceive` block), the
conditions should be ones you have already watched in the access log,
and a false positive means a real client silently losing data. Start
with `client_cidrs` on a range you are certain of, or `marked: true`
with honeypots you trust, before reaching for a score.

It is loud on the inside: `deceived: <route>` in the access log, a
`deceive` security event, `xproxy_deceived_total{route}`, and
`GET /v1/deceive`. Nothing is added to the response, because anything
added is the tell.

### Serving a suspect client slowly

Refusing a scanner tells it which request to change. It will try
variations until one is not refused, and the refusal is the signal that
tells it when it has found one. Serving it in full, meanwhile, funds
the next request.

```yaml
degradation:
  levels:
    - name: marked
      marked: true
      bytes_per_second: 8192
      delay: 500ms
      close: true
    - name: likely-bot
      bot_score_at: 60
      routes: [catalogue, search]
      bytes_per_second: 65536
```

A client a honeypot or a honeytoken marked now gets the real page, at
eight kilobytes a second, half a second late, on a connection it cannot
reuse. There is nothing to report as broken and nothing to tune
against; the only thing that changed is what the crawl costs. The
delay is spent in a tarpit slot rather than a request slot, so held
responses never eat the concurrency sold to everyone else.

Levels are tried in order and the first match decides, so put the
narrow ones first. `degraded: <level>` appears in the access log line
and `xproxy_degraded_total{level}` counts them; `xproxyctl status` and
`GET /v1/degradation` show how often each level applied.

### Refusing before the handshake

A banned client still gets a TLS handshake: keys agreed, certificate
sent, request parsed, and then a 403. That is a key exchange spent on a
refusal, and an answer a scanner can read — the certificate, the cipher
list, the error page, the headers.

```yaml
handshake:
  refuse_banned: true
  deny_fingerprints: ["ja4:t13d31*", "579ccef312d18482fc42e2b822ca2430"]
bans:
  action: reject
  triggers:
    - {name: probes, reasons: [honeypot, honeytoken], threshold: 1, window: 10m, duration: 24h}
```

Now the ban is enforced one layer down: the ClientHello is answered
with a failed negotiation and nothing else. It applies to every TLS
listener including HTTP/3, and `deny_fingerprints` refuses a TLS stack
outright whether or not its address is banned.

What you give up is the record. A refused connection never becomes a
request, so there is no access log line, no request id and no route —
only the security log (reason `handshake`) and
`xproxy_tls_handshakes_refused_total`. `xproxyctl tls` prints the
policy and the count above the certificates.

Fingerprints group clients, they do not identify them. A full JA4 is
safe to deny once you have seen it in your own security log; a prefix
covers a whole family, browsers included, so check what else it matches
before adding one.

### Honeytokens: the hook on the bait

A decoy hands out an AWS key, a database password, a connection string.
Until something watches for their use, none of that is a detection: the
scanner reads the file, and the proxy knows only that the file was
read. Registering the planted values turns each one into a tripwire.

```yaml
honeytokens:
  - name: env-aws-key
    description: planted in the env and aws-credentials decoys
    values: ["AKIADECOY000000EXAMPLE", "decoy/secret/not/real/0000000000000000"]
  - name: backup-session
    description: seeded in the 2026-01 customer database export
    values: ["s%3Adecoy.0000000000000000000000000000"]
    in: [cookies]
  - name: unlinked-export-url
    description: printed in the internal runbook only
    values: ["export-7f3a9c2b1d8e4056"]
    in: [path]
bans:
  triggers:
    - {name: honeytoken-use, reasons: [honeytoken], threshold: 1, window: 1m, duration: 24h}
```

Nothing legitimate ever sends one, which is what makes this different
from every other control here: there is no score to tune and no
false-positive rate to trade against a detection rate. A threshold of
one is the right threshold. The request is refused before routing, the
security log names the token and where it was planted (never the
value), the client is marked for a day, and
`xproxy_honeytoken_hits_total{token}` is the metric to alert on — a
single hit is worth waking someone.

Plant them beyond the decoys, and the token tells you which copy
leaked: a key committed to a public repository, a session seeded into a
database export, an identifier embedded in a document, a URL that
appears only in the runbook. `examples/security/honeytokens.yaml` shows
each of those with the decoy routes they pair with; `xproxyctl
honeypot` lists the plants with their hits and last hit.

Two rules. Start a new plant with `action: log` until it is proven
quiet — a token that fires on real traffic was planted somewhere real
traffic reaches — and never register a real credential: the value is
compared as an ordinary string and the whole design assumes it is fake.

### Form honeypots: the hidden field and the clock

A form bot does two things a person does not. It fills in every field
it finds, including the one nobody can see, and it submits faster than
anyone could have read the page. The `form_guard` filter watches for
both.

```yaml
filters:
  - name: signup-guard
    kind: form_guard
    stage: before_auth
    options:
      fields: [contact_reason, website]   # must arrive empty or absent
      min_seconds: 2                      # after the form page was fetched
      max_seconds: 3600                   # and not from a page fetched yesterday
      form_paths: [/signup]
      reason: honeypot
routes:
  - name: signup
    paths: [/signup]
    filters: [signup-guard]
    upstream: app
```

The hidden field costs the application one element and no JavaScript:

```html
<div style="position:absolute;left:-9999px" aria-hidden="true">
  <label>Leave this empty<input type="text" name="contact_reason"
         tabindex="-1" autocomplete="off"></label>
</div>
```

Keep it off screen rather than `display:none` (some crawlers skip what
is not rendered), give it a name worth filling in, and keep password
managers out with `tabindex="-1"` and `autocomplete="off"`. A person
never sees the field, so a value in it is a signal with no
false-positive rate to trade away — which is why `fields` is the option
to reach for first and the one to start with alone.

Timing is the weaker half and needs the care. The filter remembers when
the client address last fetched a page under `form_paths`; a
submission that arrives within `min_seconds` of it is `too_fast`, and
one from a page fetched longer ago than `max_seconds` is `too_old`. A
client with no fetch on record is allowed, because a form page can be
cached, prerendered, or served by another node — set `require_fetch`
only where the deployment makes all three impossible. Set
`min_seconds` to what the shortest honest fill takes, not to what an
average one does: a password manager filling a login form is quick, and
a one-field newsletter box is quicker.

Only `application/x-www-form-urlencoded` bodies are parsed, up to
`max_body_bytes`, and the body is replayed byte for byte, so the
application receives exactly what the client sent; a JSON API sharing
the route passes untouched. The query string of a submission is
searched too, so a field cannot be smuggled past the body check.

Denies carry a detail — `field:<name>`, `too_fast`, `too_old`,
`no_form_fetch` — that says which half fired, and `form_seconds` in the
access log says by how much. Watch the details for a week before
tightening anything: `field:` hits are the ones to ban on,
`too_fast` is the one to tune. `examples/filters/form-guard.yaml`
pairs a sign-up, a contact form and a password reset, each with the
amount of checking its page can carry.

### WebSocket message inspection

```yaml
routes:
  - name: chat
    paths: [/ws/chat]
    websocket: true
    websocket_guard:
      max_frame_bytes: 65536
      max_message_bytes: 262144
      messages_per_second: 30
      allow_subprotocols: [chat.v2]
      allow_opcodes: [text, close, ping, pong]
      deny_patterns: ["(?i)<script[^>]*>"]
      action: close
    upstream: chat
```

`websocket: true` allows the upgrade. `websocket_guard` is what happens
after it. Without the guard, everything before the 101 is inspected —
routing, the WAF, the filters, the logs — and everything after it is a
byte stream nobody looks at. Applications put their real API in there.

Three kinds of check, with three different false-positive profiles:

**Structure** has none, because it is the protocol's own rules. A
reserved bit set without a negotiated extension, a reserved opcode, an
unmasked client frame, a masked server frame, a fragmented or oversize
control frame, a continuation with nothing to continue, a close frame
with one byte of status, a close code that must never appear on the
wire, text that is not UTF-8. A browser does none of these.

**Bounds** are a capacity decision. `max_frame_bytes` and
`max_message_bytes` stop one connection deciding how much memory the
proxy uses; `messages_per_second` stops it deciding how much CPU the
origin uses. Set them from what the application actually sends —
`xproxy_websocket_messages_total{route}` tells you.

**Patterns** are the part with a real rate, so start there in log mode:

```yaml
    websocket_guard: {deny_patterns: ["(?i)\\bDROP\\s+TABLE\\b"], action: log}
```

```
$ xproxyctl metrics | grep websocket
xproxy_websocket_connections_total{route="chat"} 4120
xproxy_websocket_messages_total{route="chat"} 1840223
xproxy_websocket_violations_total{route="chat"} 3
xproxy_websocket_closed_total{route="chat"} 0
```

Both directions are inspected. That is deliberate: the origin is the
side that holds the data, and a compromised or simply buggy
application pushing something it should not is the case worth catching.
It is also why a violation count can be double what you expect — a
denied message and its echo are two.

A few things worth knowing. The subprotocol is checked on the 101,
before any frame exists, so an application that answers with an
unlisted one never gets a connection. Messages over
`max_inspect_bytes` are checked up to that bound and forwarded, because
the alternative is buffering whatever a client sends. And
`permessage-deflate` is refused rather than ignored: a compressed frame
cannot be inspected, so a negotiated compression extension would turn
every check above off silently.

`examples/routes/websocket.yaml` pairs a chat route with tight bounds
and a market-data feed with wide ones and no inspection.

### gRPC services

```yaml
server:
  listeners:
    - name: rpc
      address: "10.0.0.5:8443"
      tls: {certificates: [{cert_file: /etc/xproxy/rpc.pem, key_file: /etc/xproxy/rpc.key}]}
    - name: rpc-internal
      address: "10.0.0.5:8080"
      h2c: true                     # plaintext HTTP/2 for in-cluster clients
upstreams:
  - name: orders
    h2c: true                       # the gRPC servers listen without TLS
    endpoints: [{address: 10.0.5.10:9000}, {address: 10.0.5.11:9000}]
    health_check: {type: grpc, grpc_service: orders.v1.Orders, interval: 5s}
  - name: catalog
    scheme: https
    endpoints: [{address: catalog.svc.internal:443}]
    health_check: {type: grpc}
routes:
  - name: orders
    grpc: {services: [orders.v1.Orders]}
    upstream: orders
    rate_limits: [api]
  - name: catalog-read
    grpc: {methods: [catalog.v1.Catalog/Get, catalog.v1.Catalog/List]}
    upstream: catalog
  - name: rpc-other
    grpc: {}
    respond: {status: 404}          # invalid: gRPC routes need an upstream
```

(Drop the last route: a request for an unlisted service gets
`grpc-status: 12 UNIMPLEMENTED` from the proxy on its own.) Health
checks use the standard health service, so an endpoint that reports
`NOT_SERVING` is taken out of rotation before clients see errors, and
a rate limited call is refused with `RESOURCE_EXHAUSTED` rather than a
text page a gRPC client cannot read.

**Routing gRPC by its path reads the envelope.** The messages are
length-prefixed frames of protobuf inside the body, and a proxy that
does not read them cannot say how large *one message* is — only how
large the whole body is — cannot notice a stream that stops in the
middle of a frame, and cannot see a message nested a thousand deep.
That last one costs the backend's parser far more than it costs the
sender to write. The `grpc_guard` filter reads them:

```yaml
filters:
  - name: rpc
    kind: grpc_guard
    options:
      max_message_bytes: 4194304   # one message, not the stream
      max_messages: 100            # a streaming call is still bounded
      max_depth: 12
      max_fields: 2000
      allow_compressed: false
      deny_patterns: ["(?i)-----BEGIN (RSA )?PRIVATE KEY-----"]
routes:
  - name: orders
    grpc: {services: [orders.v1.Orders]}
    upstream: orders
    filters: [rpc]
```

No schema is used, and that is the design rather than a shortcut: a
schema has to be kept in step with the service, and a check that is
only as current as its schema is a check that quietly stops applying
the week somebody adds a field. The protobuf wire format carries the
field number and the wire type, which is enough for every bound above.

`allow_compressed: false` is required with `deny_patterns`, and the
load fails otherwise: a compressed message is bytes this filter does
not decompress, so the patterns would simply not run over it. Saying so
beats finding out.

Refusals are gRPC statuses, so a client sees `RESOURCE_EXHAUSTED` or
`INVALID_ARGUMENT` rather than a page it cannot parse, and a content
refusal names the field path it matched at. The access line carries
`grpc_messages`, `grpc_depth` and `grpc_fields` — run it with
`action: log` first and those three numbers tell you what to set the
bounds to, rather than guessing and finding out in production.

What it does not do is understand the fields: `deny_patterns` run
against every string in a message, not against a named field.

### gRPC-web for browsers

```yaml
upstreams:
  - {name: rpc, h2c: true, endpoints: [{address: "10.0.4.10:9090"}]}
routes:
  - name: rpc-web
    hosts: [api.example.com]
    grpc: {web: true, web_origins: ["https://app.example.com"]}
    upstream: rpc
```

Browsers cannot speak gRPC (no trailers, no HTTP/2 control), so
gRPC-web clients send the same frames with a different content type
over HTTP/1.1 or HTTP/2 and expect the trailers as a last frame in the
body. The route translates: the upstream receives plain gRPC over the
pool's transport (h2c or HTTPS), the response goes back as
`application/grpc-web+proto` with the trailer frame, and the `-text`
variants are decoded and encoded as base64. `web_origins` answers the
CORS preflight and exposes `grpc-status` and `grpc-message` to the
page; proxy errors (a rate limit, a denied ACL) are answered in
gRPC-web form so the client library reports a status rather than a
transport failure. A gRPC-web request on a gRPC route without `web`
gets status 2 (UNKNOWN) with the proxy's reason.

### Routing by pattern, header and cookie

```yaml
routes:
  - name: canary
    hosts: [app.example.com]
    headers: [{name: X-Canary, exact: "1"}]
    upstream: app-v2
  - name: beta-testers
    hosts: [app.example.com]
    cookies: [{name: beta, present: true}]
    upstream: app-v2
  - name: item-api
    hosts: [app.example.com]
    path_regex: ['/api/v[0-9]+/items/[0-9]+']
    upstream: items
  - name: app
    hosts: [app.example.com]
    upstream: app-v1
```

A request with `X-Canary: 1` or a `beta` cookie reaches the new
version whatever its path; `/api/v3/items/42` reaches the item service
while `/api/v3/items/list` does not (patterns match the whole path);
everything else goes to the current version. Conditioned routes are
tried before the plain route on the same path, so the order above does
not matter.

### Routing and headers by expression

```yaml
routes:
  - name: internal-beta
    hosts: [app.example.com]
    when: 'client_ip in cidr("10.0.0.0/8", "192.168.0.0/16") && (header("X-Env") == "beta" || has_cookie("beta"))'
    upstream: app-v2
  - name: night-readonly
    hosts: [app.example.com]
    methods: [POST, PUT, PATCH, DELETE]
    when: 'hour >= 1 && hour < 3 && weekday in ["Sun"]'
    respond: {status: 503, body: "maintenance window"}
  - name: app
    hosts: [app.example.com]
    upstream: app-v1
    request_headers:
      set: {X-Debug: "1"}
      when: 'query("debug") == "1" && client_ip in cidr("10.0.0.0/8")'
    response_headers:
      set: {Cache-Control: "no-store"}
      when: 'has_cookie("session") || starts_with(path, "/account")'
```

`when` adds a condition the static matches cannot express: address
ranges, combinations with `or`, comparisons, patterns on any variable,
the time of day. A route with `when` ranks like a route with one header
condition (more conditions win at equal path length), so the order of
the routes above does not matter. The same language gates header
operations, which keeps a debugging header off production clients
without a second route. Expressions are checked at load: a misspelt
variable, function or pattern fails `xproxy -validate` with the route
and position. The grammar and every function are in `docs/CONFIG.md`,
"Expressions".

### Canary endpoints inside one pool

```yaml
upstreams:
  - name: app
    canary: {header: X-Canary, cookie: canary, percent: 5}
    endpoints:
      - {address: 10.0.1.10:8080}
      - {address: 10.0.1.11:8080}
      - {address: 10.0.1.12:8080, canary: true}
```

The third endpoint runs the new build. Testers reach it with an
`X-Canary` header or a `canary` cookie, five percent of everyone else
lands on it too, and the remaining traffic never does. If the canary
fails its health checks its traffic falls back to the other two. Raise
`percent` as confidence grows; to promote, mark the old endpoints
`canary: true` and the new one not, or drop the policy. The access log
shows `canary: true` on responses the canary served.

### Response compression

```yaml
compression: {level: 5, min_bytes: 1024, encodings: [br, zstd, gzip]}
routes:
  - name: api
    hosts: [api.example.com]
    upstream: api                      # JSON compressed on the way out
  - name: account
    hosts: [www.example.com]
    paths: [/account]
    compress: false                    # pages with tokens: leave as they are
    upstream: web
```

One section turns gzip on for every route; a route opts out with
`compress: false`. Bodies the upstream already compressed, images,
ranges and `no-transform` responses pass through, small bodies are left
alone, and `Vary: Accept-Encoding` is set on everything that could be
compressed so shared caches stay correct. The access log shows
`encoding: gzip` on compressed answers and `xproxyctl status` counts
them.

Three encodings are offered: Brotli (`br`), zstd and gzip. The client's
`Accept-Encoding` decides: the acceptable encoding with the highest
quality wins and ties go to the order of `encodings`, so the default
prefers Brotli for browsers, zstd for clients that ask for it and gzip
otherwise. Restrict `encodings` to `[gzip]` for a fleet of old clients
or to save CPU; `brotli_level` and `zstd_level` trade ratio for time.
The access log's `encoding` field and `xproxy_compressed_total` show
what was sent.

### Static files and single page applications

```yaml
routes:
  - name: assets
    hosts: [app.example.com]
    paths: [/static]
    strip_prefix: /static
    static: {root: /srv/app/static, cache_control: "public, max-age=86400, immutable"}
  - name: spa
    hosts: [app.example.com]
    paths: [/]
    static: {root: /srv/app/dist, fallback: /index.html}
  - name: api
    hosts: [app.example.com]
    paths: [/api]
    upstream: api
```

Requests for `/static/app.js` serve `/srv/app/static/app.js` with an
`ETag`, ranges and conditional requests; anything under `/` that is not
a file in `/srv/app/dist` serves `index.html`, so client side routes
deep link; the API is proxied. Files are opened inside the root only,
dot files are never served, and a root that disappears fails the reload
rather than the site. Give the `xproxy` user read access to the tree
and, under SELinux, label it `httpd_sys_content_t` or the policy's
equivalent (SETUP.md). `static_served` and `static_not_found` count the
answers.

### Request mirroring

```yaml
upstreams:
  - name: api-v2
    endpoints: [{address: 10.0.4.10:8080}]
  - name: api-v3-candidate
    endpoints: [{address: 10.0.4.50:8080}]
routes:
  - name: api
    hosts: [api.example.com]
    upstream: api-v2
    mirror: {upstream: api-v3-candidate, percent: 10, methods: [GET], max_in_flight: 32}
```

One request in ten is copied to the candidate with `X-Xproxy-Mirror: 1`
and the same `X-Request-Id` as the live request, so the two backends'
logs can be joined. The client only ever sees the live response;
copies are bounded in body size, time and number in flight, and
dropped rather than queued when the candidate falls behind.

### Packet capture (pcapng)

A tcpdump in front of the proxy captures ciphertext, and one behind it
has lost the client. `capture` writes what the proxy itself saw — the
request as it arrived, the response as the client got it — as a pcapng
file Wireshark, tshark and every other pcap tool open directly. Each
exchange becomes one synthesised TCP conversation between the client
address and the listener, so `Follow TCP stream` shows the request and
the answer, and each frame carries the `X-Request-Id` as a pcapng
comment, so a frame and an access log line name each other.

```yaml
capture:
  enabled: true
  directory: /var/lib/xproxy/capture
  max_duration: 30m
  bodies: true
  max_body_bytes: 65536
  redact: [authorization, cookie, set-cookie, x-api-key]
  rules:
    - {name: reported-client, routes: [api], client_cidrs: ["198.51.100.7/32"]}
    - {name: denials, denied: true, max_flows: 500}
    - {name: waf-only, reasons: [waf], max_flows: 200}
    - {name: sample-uploads, methods: [POST], paths: [/upload], percent: 1}
```

Two switches, and both have to be on. The configuration decides what
*may* be captured and reloads; the runtime switch decides whether
anything is being captured *now*, and is off unless `start_active` is
set:

```console
# xproxyctl capture start -duration 10m
capture: on
until: 2026-09-21T12:10:00Z
# xproxyctl capture status
capture: on
until: 2026-09-21T12:10:00Z
file: /var/lib/xproxy/capture/xproxy-20260921-120000.123.pcapng (1 open)
captured: 42  skipped: 1180  truncated: 3  dropped: 0  failed: 0  bytes: 2216440
rule denials: 42/500
# xproxyctl capture stop
capture: off
```

The window closes on its own after `max_duration`, so a capture started
during an incident cannot be left running for a month, and a reload
keeps the switch exactly as it was, deadline included.

Rules are how "only this flow" is said. Every selector a rule names has
to hold, the first matching rule decides, and a rule that names no
selector matches everything — which is also what leaving `rules` out
means. The selectors on the answer (`statuses`, `reasons`, `denied`)
cannot be decided when the request arrives, so those exchanges are held
and written once the proxy has answered: `denied: true` gives a file of
exactly what the proxy is refusing, which is the question a capture
answers best. That includes the refusals decided before a route is
known — a ban, the maintenance gate, a malformed `Host` — which no
request-side selector can describe and which are written without
bodies, because nothing read them.

Then open the file:

```console
$ tshark -r xproxy-20260921-120000.123.pcapng -Y http -T fields \
    -e frame.comment -e http.request.method -e http.request.uri -e http.response.code
```

Read what the file is, and is not. It is the proxy's view, so segment
boundaries, sequence numbers and frame timestamps are synthesised, and
TLS, HTTP/2 framing and HTTP/3 are gone by the time it is written (an
HTTP/2 or HTTP/3 exchange is rendered with an `HTTP/1.1` start line,
because a dissector needs one). It is not the packets that were on the
wire, and it is not evidence of what a client sent byte for byte.

**The files hold decrypted traffic.** Session cookies, bearer tokens
and whatever personal data the application carries are in them in the
clear. They are created `0600` in the directory the operator names, the
proxy chooses the names and writes nothing else there, and `redact`
replaces the listed header values with `REDACTED` — a fixed string, so
neither the value nor its length is in the file. Bodies are off by
default. Treat the directory like an access log with redaction turned
off: not on a shared volume, not in a backup that travels, and removed
when the investigation is over. `xproxy_capture_flows_total{result}`
and `xproxy_capture_bytes_total` say how much has been written, and
`xproxy_capture_active` is 1 while a capture is running, which is worth
an alert if one is ever left on.

### Response caching

```yaml
cache: {max_bytes: 268435456, max_object_bytes: 2097152}
routes:
  - name: assets
    hosts: [www.example.com]
    paths: [/static/]
    cache: {ttl: 1h, headers: [Accept-Encoding]}
    upstream: web
  - name: api-public
    hosts: [api.example.com]
    paths: [/v1/public/]
    cache: {ttl: 10s, query: listed, query_params: [page, lang]}
    upstream: api
```

The upstream stays in control through `Cache-Control`; `xproxyctl cache
purge www.example.com /static/` drops entries after a deploy.

### Country policy (GeoIP)

```yaml
geoip: {database: /var/lib/xproxy/GeoLite2-Country.mmdb}   # or csv: /etc/xproxy/geo.csv
rate_limits:
  - {name: per-country, key: country, rate: 500, burst: 1000}
routes:
  - name: shop
    hosts: [shop.example.com]
    geo: {allow: [SE, NO, DK, FI], unknown: deny}
    rate_limits: [per-country]
    upstream: shop
  - name: api
    hosts: [api.example.com]
    geo: {deny: [KP]}
    upstream: api
```

`xproxyctl geoip` shows the database, its build date and lookup
counters. The database file is owned by root, group `xproxy`, mode
`0640`, and replaced atomically before `xproxyctl reload`.

### Bot classification

```yaml
challenge: {secret_file: /var/lib/xproxy/challenge.key}
filters:
  - name: bots
    kind: bot_score
    options:
      challenge_at: 50          # scripted clients solve the proof of work first
      deny_at: 85               # scanners and denied fingerprints are refused
      header: X-Bot-Score       # let the application decide on the rest
      ja4_allow: [t13d1516h2_8daaf6152771_b0da82dd1658]   # the monitoring probe
routes:
  - name: web
    hosts: [www.example.com]
    filters: [bots]
    upstream: web
```

Start with `deny_at` and `challenge_at` at 0 and `log_at: 1` for a day:
the access log then carries `bot_score`, `bot_signals` and `ja4` for
every request, which gives the fingerprints of your own tools for
`ja4_allow` and the score distribution for the thresholds.

### Account protection: credential stuffing, brute force and abuse

Login, registration, password reset, cart and catalogue endpoints are
attacked by volume: leaked credential lists replayed against the login
form, one account hammered, one password sprayed across many accounts,
thousands of throwaway registrations, reset floods, bots emptying stock
into carts, scrapers walking the catalogue. The `account_guard` filter
watches these endpoints with a ladder of progressive actions:

```yaml
challenge: {secret_file: /var/lib/xproxy/challenge.key}
filters:
  - name: accounts
    kind: account_guard
    options:
      endpoints:
        - name: login
          class: login
          paths: [/api/login]
          identity: {json: username, form: username}
          failure: {statuses: [401], body_regex: '"error":"invalid_credentials"'}
        - name: signup
          class: register
          paths: [/api/register]
          identity: {json: email}
          disposable: challenge
        - name: reset
          class: reset
          paths: [/api/password/reset]
          identity: {json: email}
        - name: cart
          class: cart
          paths: [/api/cart/items]
          identity: {header: X-Session-Id}
        - name: catalogue
          class: scrape
          paths: [/products/*]
routes:
  - {name: app, hosts: [shop.example.com], upstream: app, filters: [accounts]}
bans:
  triggers:
    - {name: account-abuse, reasons: [account_abuse], threshold: 5, window: 10m, duration: 1h}
```

For `login` the filter reads the account identifier from the request,
learns from the response whether the attempt failed, and counts per
address, per account, per address and account pair, distinct accounts
per address and distinct addresses per account. Three failures on one
pair earn a two second delay, five the browser challenge (a `captcha`
step is available where a CAPTCHA provider is configured), ten a
fifteen minute block of that pair; ten different accounts tried from
one address is credential stuffing and gets the challenge, thirty a
block; one account tried from five addresses is a distributed attack
on that account. A successful login clears the account's failures, so
a user who mistypes twice is never blocked. When the whole endpoint
sees two hundred failures from fifty addresses inside the window, each
under its own thresholds, a campaign is declared and every unverified
client is challenged for the next window; peers in a cluster learn
blocks and campaigns through the event bus. Registration with an
address on a disposable domain is challenged, and repeat registrations
of one identity or many from one address escalate; resets are counted
per account and address; cart and catalogue endpoints count requests
and distinct paths. Identities are hashed (`account_hash`) before they
are counted or logged; the access log shows the endpoint, the action,
the threshold that fired and the counts on every matched request, so a
week in the default ladder shows what the thresholds should be for
your traffic before `steps` tightens them. Blocks are `account_abuse`
denials, which the ban trigger above turns into an address ban after
five. `examples/filters/accounts.yaml` is a complete configuration.

### WebAssembly filters

```yaml
filters:
  - name: tenant-policy
    kind: wasm
    options:
      module: /etc/xproxy/filters/tenant-policy.wasm
      config: "allowed=acme,globex"
      timeout: 20ms
routes:
  - name: api
    hosts: [api.example.com]
    upstream: api
    filters: [tenant-policy]
```

The module decides per request from what it reads through the host
functions (method, path, headers, client address, country, JA4, its
own `config`), may add or remove headers in both directions, deny with
a status and reason of its own, and annotate the access log. It runs
with a memory bound and a deadline; a module that traps or overruns
fails closed unless `on_error: allow`. Build it with any toolchain that
targets WebAssembly; EXTENDING.md has the ABI and a minimal guest.

### Rewriting bodies without WebAssembly

```yaml
filters:
  - name: links
    kind: body_rewrite
    options:
      response:
        types: [text/html, application/json]
        rules:
          - {find: "http://app.internal:8080/", replace: "https://www.example.com/"}
          - {regex: '"card":\s*"\d{12}(\d{4})"', replace: '"card": "************$1"'}
      request:
        types: [application/json]
        rules: [{regex: '"userName"', replace: '"user_name"'}]
routes:
  - name: app
    hosts: [www.example.com]
    filters: [links]
    upstream: app
```

Links the application renders with its internal name come out with the
public one, card numbers in JSON answers are masked to their last four
digits, and a client still sending the old key name reaches the new
API. Bodies above `max_bytes`, encoded bodies and other media types
pass through unchanged; the access log shows `body_rewrite` on lines
where something changed.

### Header policy and basic authentication (filters)

Filters are middleware instances attached to routes; the built-in kinds
are `header_guard`, `basic_auth`, `api_key`, `openapi`, `graphql`,
`upload_guard`, `sensitive_data`, `account_guard`, `body_rewrite`,
`bot_score`, `oidc`, `saml_sp`, `xml_guard` and `wasm` (`xproxyctl filters` lists what the binary has;
[EXTENDING.md](EXTENDING.md) shows how to add one).

```yaml
filters:
  - name: scanners
    kind: header_guard
    options:
      deny: [{header: User-Agent, pattern: "(?i)sqlmap|nikto|masscan|zgrab"}]
  - name: partner-key
    kind: header_guard
    options:
      require: [{header: X-API-Key, pattern: "^pk_[A-Za-z0-9]{32}$"}]
      status: 401
  - name: staff
    kind: basic_auth
    stage: before_auth
    options: {users_file: /etc/xproxy/staff.htpasswd, realm: staff, forward_user_header: X-Remote-User}

routes:
  - name: partner-api
    hosts: [api.example.com]
    paths: [/partner/]
    filters: [scanners, partner-key]
    upstream: api
  - name: intranet
    hosts: [intranet.example.com]
    filters: [staff]
    upstream: intranet
```

```sh
echo 'correct horse battery staple' | xproxyctl htpasswd /etc/xproxy/staff.htpasswd alice
chown root:xproxy /etc/xproxy/staff.htpasswd && chmod 0640 /etc/xproxy/staff.htpasswd
xproxyctl reload
xproxyctl filters
```

Denies are logged on the security stream with the filter name as reason
and can drive ban triggers (`categories: [scanners]`).

### API security: keys, OpenAPI validation and GraphQL bounds (filters)

```
$ xproxyctl apikey add acme -scopes orders:read,orders:write -expires 365d -note "Acme Corp, ticket 4711"
xpk_acme_Qm9vay1vZi1zaGFkb3dz...        # shown once; hand it to the customer
$ xproxyctl apikey rotate acme -grace 48h   # new secret, the old one works two more days
$ xproxyctl apikey revoke acme
```

```yaml
filters:
  - name: keys
    kind: api_key
    options: {keys_file: /etc/xproxy/api-keys, required_scopes: [orders:read]}
  - name: orders-spec
    kind: openapi
    options: {spec_file: /etc/xproxy/openapi/orders.yaml, strict_query: true}
  - name: gql
    kind: graphql
    options: {max_depth: 8, max_complexity: 500, max_aliases: 10, introspection: false}
routes:
  - {name: orders, paths: [/v1/orders], upstream: orders, filters: [keys, orders-spec]}
  - {name: graphql, paths: [/graphql], upstream: gateway, filters: [keys, gql]}
```

The key filter authenticates the caller and forwards `X-Api-Key-Id` and
`X-Api-Key-Scopes` to the application, which never sees the secret; the
file is re-read when `xproxyctl apikey` changes it, so issuing,
rotating and revoking need no reload. Rate limit a partner by key with
`rate_limits: [{name: partner, key: "header:X-Api-Key", ...}]` on the
same route. The OpenAPI filter turns the API description into an
allow list: undocumented paths, methods, parameters, media types and
malformed bodies never reach the application, and the caller gets a
JSON answer naming what was wrong. The GraphQL filter refuses the
queries that take an API down (deep nesting, wide lists, alias floods,
batches, introspection in production) without knowing the schema. The
security log carries the filter name as the reason and the access log
the key id (`api_key`).

### Authorisation: from an identity to a policy (filter)

Every authenticating filter here answers "who": `basic_auth`,
`ldap_auth`, `api_key`, `oidc`, `saml_sp`, the JWT filter, client
certificates.
None of them answers "what may they do", so each grew its own small
allow list — required scopes on the key, a required group on the
directory bind, required claims on the session. An allow list per
filter is a policy nobody can read in one place, and the one nobody
reads is the one with the hole in it.

`authz` reads the identity those filters verified and decides once:

```yaml
filters:
  - name: keys
    kind: api_key
    options: {keys_file: /etc/xproxy/api-keys}
  - name: policy
    kind: authz
    options:
      default: deny
      forward_groups_header: X-Auth-Groups
      rules:
        - {name: no-deletes-from-outside, allow: false, methods: [DELETE], not_networks: ["10.0.0.0/8"]}
        - {name: read, allow: true, methods: [GET, HEAD], paths: [/v1/orders/**], scopes: [orders:read]}
        - {name: write, allow: true, paths: [/v1/orders/**], scopes: [orders:read, orders:write]}
routes:
  - {name: orders, paths: [/v1/orders], upstream: orders, filters: [keys, policy]}
```

Three things worth knowing before writing rules.

**It runs last.** The subject, groups, scopes and claims all come from a
filter that verified them, so a header a client sent cannot reach a
rule — which also means that before those filters have run there is
nothing to decide about. Put `authz` at the end of the route's filter
list. `require_authenticated` is on by default and refuses a request
nothing verified, rather than deciding on values a client supplied.

**Scopes are all-of, groups are any-of.** A rule naming two scopes is
satisfied only by a credential carrying both; a rule naming two groups
is satisfied by membership of either. That is what each of them means
in practice, and getting it the other way round is how a policy ends up
wider than it reads.

**The first matching rule decides**, so a deny above an allow carves an
exception out of it. A rule that names no selectors matches everything:
as a deny that is a legitimate backstop, and as an allow it fails the
load — `default: allow` is where that belongs, out loud.

A refusal tells the client nothing about why. Which rule, which group it
would have needed and whether the path even exists are all things a
prober would like to know; the reason is in the proxy's log, and the
access line carries `authz_rule`, which is the only way to tell a policy
that allowed from one that never matched.

What feeds it: `oidc` records groups from `groups_claim` (default
`groups`), scopes from the token's `scope` and whatever `attr_claims`
names; `saml_sp` records the assertion's groups from `groups_attribute`
and whatever `policy_attributes` names; `ldap_auth` records the
directory's own groups from `group_attr`; `api_key` records the key's
scopes. Every filter records the subject, so
`subjects` and `kinds` work whatever authenticated.

### Upload protection (filter)

Uploads are where a web shell arrives. The `upload_guard` filter
inspects every file part of a multipart request before the application
sees it:

```yaml
filters:
  - name: uploads
    kind: upload_guard
    options:
      max_files: 10
      max_file_bytes: 10485760
      allowed_extensions: [jpg, jpeg, png, gif, webp, pdf, docx, xlsx]
      fields: [file, attachment]
routes:
  - {name: attachments, paths: [/api/attachments], methods: [POST], upstream: app, filters: [uploads], max_body_bytes: 52428800}
```

`invoice.pdf.exe` is refused for the `exe` in its chain, `photo.html.jpg`
for the unexpected `html` under an allow list, `cute.png` that starts
with `MZ` for being a Windows program, `cute.jpg` with `<?php` inside
for being server side code, a PNG named `.jpg` for not matching its
name, and a file declared `application/pdf` whose bytes are an image
for not matching its declaration. Each refusal names the check and the
file in the security event (`detail: executable:pe:cute.png`), the
request never reaches the application, and the body of an accepted
upload is replayed unchanged. `strict_magic: true` also refuses content
nobody recognises, right for an avatar endpoint; `raw_uploads: true`
covers `PUT /files/name.png` style uploads without multipart. Virus
scanning is the ICAP filter's job (`routes[].icap`), and the two
combine on one route. `examples/filters/uploads.yaml` is a complete
configuration.

### Sensitive data in requests and responses (filter)

An API that returns card numbers, personal identity numbers or tokens
it should not, or a client that sends them where they do not belong,
is a data protection incident waiting for a log line. The
`sensitive_data` filter watches both directions:

```yaml
filters:
  - name: dlp
    kind: sensitive_data
    options:
      detectors: [card, personnummer, iban, email, jwt, private_key, api_keys, password_query]
      custom: [{name: order_secret, regex: "OS-[0-9]{12}"}]
      request: {action: log, scan: [query, headers, body]}
      response: {action: mask, scan: [headers, body], types: [application/json, text/plain]}
  - name: no-cards-out
    kind: sensitive_data
    options: {detectors: [card], response: {action: block}, block_status: 502}
routes:
  - {name: export, hosts: [api.example.com], paths: [/v1/export], upstream: api, filters: [no-cards-out]}
  - {name: api, hosts: [api.example.com], upstream: api, filters: [dlp]}
```

Every detector validates its match (Luhn for cards, date and checksum
for personnummer, mod 97 for IBANs, a JSON header for JWTs), so a
sixteen digit order number does not count. `log` leaves the message
alone and records `sensitive_types=card,email sensitive_count=2
sensitive_where=response_body` in the access log; `mask` rewrites the
values (`************1111`, `a***@example.com`) before the client or
the upstream sees them; `block` refuses with a JSON problem that names
the kinds and never the values. Start in `log`, review the log for a
week, then mask the responses of the routes that leak and block the
exports that must never carry cards. Credential headers are not
scanned by default because they always carry secrets; `password_query`
catches the mistake of a password in a query string, where it lands in
every log on the path. `examples/filters/sensitive-data.yaml` is a
complete configuration.

### API inventory: discovery, shadow and zombie APIs

An API programme starts with knowing what is exposed. With
`api_inventory` present the proxy learns it from the traffic it
proxies and, where a route has an `openapi` filter, compares it with
the description:

```yaml
api_inventory:
  state_file: /var/lib/xproxy/api-inventory.json
  zombie_after: 720h
filters:
  - {name: orders-spec, kind: openapi, options: {spec_file: /etc/xproxy/openapi/orders.yaml, unknown_paths: allow}}
routes:
  - {name: orders, hosts: [api.example.com], upstream: api, filters: [orders-spec]}
```

The description can also come from a registry (`spec_url`, refreshed
in the background with a `cache_file` for outages), and a `spec_file`
is re-read when it changes, so publishing a new version of the
description needs no proxy reload. `unknown_paths: allow` keeps the
description advisory while the inventory fills; `deny` turns the same description into the positive
model once the shadow list is empty. The shortest way from a shadow
list to a description is the export:

```
$ xproxyctl api undocumented -openapi -title "Orders (discovered)" > orders-discovered.yaml
```

The skeleton carries every observed path with named parameters, the
methods, media types, status classes, credential kinds and an
`x-xproxy` block with request counts and last seen times; complete the
schemas and it becomes the `spec_file` (or the `spec_url` document) of
an `openapi` filter on the route.

```
$ xproxyctl api shadow
since 2026-09-01T00:00:00Z  endpoints 214/10000  dropped 0  shadow 3  zombie 5 (after 720h0m0s)  superseded 2
HOST             METHOD  PATH               ROUTE   VERSION  STATE   REQUESTS  2XX   4XX  5XX  AUTH    LAST SEEN
api.example.com  GET     /v1/admin/export   orders  v1       shadow  1842      1840  2    0    cookie  12s ago
api.example.com  POST    /v1/orders/*/note  orders  v1       shadow  77        77    0    0    bearer  3h12m0s ago
api.example.com  GET     /internal/health   orders  -        shadow  9         9     0    0    none    1h0m3s ago
$ xproxyctl api zombie
$ xproxyctl api versions
```

The shadow view is the list of endpoints to document, protect or
remove; the zombie view the list to retire; the versions view shows a
`v1` marked `superseded` while a `v2` serves the same path, with the
credentials and last use that tell whether anyone would notice its
removal. Everything the inventory records is a template and a count:
no path parameter values, no query strings, no bodies.

### Browser challenge

```yaml
challenge:
  secret_file: /var/lib/xproxy/challenge.key
  difficulty: 16
  ttl: 1h
routes:
  - {name: signup, hosts: [example.com], paths: [/signup], challenge: {mode: always}, upstream: web}
  - {name: web,    hosts: [example.com], challenge: {mode: load, level: 0.5}, upstream: web}
```

The signup page always requires a solved challenge. The rest of the site
requires one only while the load level is at or above 0.5, so a flood of
plain HTTP clients is turned away with a static page while browsers carry
on after a short delay. Do not gate API routes: clients without JavaScript
cannot pass. Give monitoring systems `exempt_cidrs`.

#### CAPTCHA tier and device identifiers

The proof of work stops floods and plain scripts; it does not stop a
headless browser working through a credential list. For the endpoints
where that matters, add a hosted CAPTCHA as a second tier and let the
account guard escalate to it:

```yaml
challenge:
  secret_file: /var/lib/xproxy/challenge.key
  captcha:
    provider: turnstile            # or hcaptcha, recaptcha
    site_key: 0x4AAAAAAAExampleSiteKey
    secret_file: /etc/xproxy/turnstile.secret
rate_limits:
  - {name: per-device, key: device, rate: 5, burst: 20}
filters:
  - name: accounts
    kind: account_guard
    options:
      endpoints:
        - name: login
          class: login
          paths: [/api/login]
          identity: {json: username}
          steps:
            - {action: challenge, pair: 3, ip: 10}
            - {action: captcha, pair: 6, ip: 30, ip_accounts: 15}
            - {action: block, duration: 15m, pair: 12, ip: 60}
          distributed: {ips: 50, events: 200, action: captcha}
routes:
  - {name: login, hosts: [shop.example.com], paths: [/api/login], methods: [POST], upstream: app, filters: [accounts], rate_limits: [per-device]}
```

A `challenge` step earns a proof of work cookie; a `captcha` step shows
the provider's widget, and a client holding only the proof cookie sees
it too. The token is verified with the provider from the proxy, the
cookie records the higher tier, and a campaign spread over many
addresses sends every new client through the widget. `mode: always`
under `captcha` replaces the proof of work on every challenge page,
including route gates, for sites that prefer a familiar widget. The
challenge script also derives a device identifier from stable browser
properties; it travels in the cookie, shows up as `device` in the
access log and keys the `device` rate limit above, so a client that
passed a challenge and then rotates addresses still shares one bucket
(it falls back to the address until a cookie exists). The account guard
counts events and distinct accounts per device (`device`,
`device_accounts` thresholds) and blocks a device wherever it connects
from; `bot_score` adds `device_shared` when one device arrives from
many addresses. The script also reports automation markers (WebDriver
and friends); they reach the log as `automation`, weigh 45 in
`bot_score` and an `account_guard` endpoint can send such clients
through the CAPTCHA (`automation: captcha`). The identifier and the
markers are computed by the client and are advisory: treat them as
correlation, not identity. `examples/security/captcha.yaml` is a complete configuration.

## Web GUI

`xproxy-admin` serves the browser interface. It is a separate process from
the data plane, holds no secrets of its own beyond its users file, and
forwards every action to the management socket, so everything it does is
in the audit log like a `xproxyctl` call.

```
xproxy-admin serve [-listen 127.0.0.1:8443] [-socket /run/xproxy/mgmt.sock]
                   [-config /etc/xproxy/xproxy.yaml] [-users /etc/xproxy/admin-users]
                   [-tls-cert PATH -tls-key PATH [-client-ca PATH]]
                   [-restart-cmd "systemctl restart xproxy.service"]
                   [-session-idle 30m] [-session-max 12h]
                   [-oidc-issuer URL -oidc-client-id ID -oidc-client-secret-file PATH
                    -oidc-operators GROUP,... [-oidc-viewers GROUP,...|"*"]
                    [-oidc-role-claim groups] [-oidc-user-claim email]
                    [-oidc-external-url https://admin.example.com] [-oidc-ca PATH]]
xproxy-admin user add NAME -role viewer|operator [-cert-only]
xproxy-admin user del NAME
xproxy-admin user list
xproxy-admin passwd NAME
```

Roles:

| Role | May |
|------|-----|
| `viewer` | See every screen: overview, upstreams, routes, WAF, bans, graphs, cluster, certificates, subsystems, history, the configuration file and the logs |
| `operator` | Everything a viewer may, plus ban and unban, reload, reload certificates, reopen logs, renew certificates, reset the WAF statistics, roll back to a recorded configuration, edit and save the configuration file, restart the data plane |

`viewer` is a trusted operator without write access, not a
low-privilege or public role. It reads the whole configuration file —
including the paths of every key and secret, the upstream addresses,
the access lists and the WAF profile — the logs, and the bans and
fingerprints of real clients. Give it to the people you would give
read access to the host, an on-call engineer or a second pair of eyes
during a change; do not give it to anyone who may not see the
configuration. What it cannot do is change anything, which is the
whole of the distinction.

Revocation takes effect while the GUI runs. The users file is the
authority, not a copy read at start-up: it is re-read whenever it changes
on disk, whoever changed it, and the account behind a session cookie is
resolved again on every request. Deleting a user with `xproxy-admin user
del` (or removing the line by hand, or from configuration management)
ends their live sessions at their next request, and lowering a role takes
their write access away at once. A users file that cannot be parsed keeps
the previous set in force and is reported in the log, so a half-written
file does not lock everyone out. Each line is `name:role:hash`; the hash
is either a `pbkdf2-sha256` string or the literal `x509` for a user who
only logs in with a client certificate. An empty hash is a parse error
rather than an account nobody can use, because it can only come from a
truncated line or a botched edit. Accounts from the identity provider are
not in the users file, and the provider's claims decide their role.

Screens:

- **Overview**: version, uptime, generation, request and response counters,
  denials by reason, load level, listeners; the action buttons for
  operators.
- **Upstreams**: every endpoint with health, ejection, active requests and
  error counts, refreshed every five seconds; per pool the balancer,
  availability, circuit breaker state, concurrency gate and queue
  counters, and the canary share with its fallbacks.
- **Routes**: usage per tenant, per route (requests by status class,
  denied, rate limited, bytes) and per rate limit policy with the top
  consumers, plus the request share per upstream (the quota report).
- **WAF**: counters, learning state, profiles with rule set source and
  CRS version, route assignments, the most matched rules with block and
  detect counts, the exclusion proposals with their directives and a
  SecLang download; operators reset the statistics.
- **Bans**: the active list with expiry, source and count; add a ban with a
  duration and reason (recorded as `admin:<user>: <reason>`), unban.
- **Graphs**: requests, denials, bytes, connections, load level, upstream
  latency, bans and cluster peers from the sampled series buffer, with a
  selectable window.
- **Cluster**; **Certificates**: every served certificate per listener
  with issuer, days left, source, OCSP status and Certificate
  Transparency verdict, then the ACME status with a renew button.
- **Subsystems**: one page for the status documents of the sandbox
  (mechanisms and Landlock rules), telemetry exporters, dns listeners,
  ICAP, cache, GeoIP, honeypots, filters, ingress and the OpenTelemetry
  metrics exporter; unconfigured ones say so.
- **History**: the pending changes between the file and the active
  configuration (a dry run), and the recorded generations with a roll
  back button for operators.
- **Config**: the active configuration as the data plane loaded it, and an
  editor for the file. *Validate* runs the full validation without
  touching the file and lists every problem; *Validate and save* writes
  the file atomically, keeps the previous version in `xproxy.yaml.bak`,
  and refuses to overwrite a file that changed since it was loaded;
  *Reload data plane* applies it.
- **Logs**: the last lines of a stream and a live follow with a substring
  filter and pause.

Access: the default listener is `127.0.0.1:8443` in plain HTTP, reached
through an SSH tunnel (`ssh -L 8443:127.0.0.1:8443 edge`). Binding to any
other address requires `-tls-cert`, `-tls-key` and `-client-ca`: the
browser must present a client certificate from that CA, and a certificate
whose common name matches a user logs that user in without a password
(`-cert-only` users have no password at all). Five failed logins lock
that address and account pair out for five minutes; a hundred failures
from anywhere in the same window close the login page for everyone,
which is the right answer when that many logins fail at once. The pair
is the key because everyone arriving over the Unix socket or an SSH
tunnel shares one address, so keying on the address alone let one
client lock every operator out with five bad guesses. Sessions end
after thirty minutes idle or twelve hours in total.

Single sign-on: with `-oidc-issuer`, `-oidc-client-id` and
`-oidc-client-secret-file` the login page offers "Sign in with
<provider>". The GUI runs the authorization code flow with PKCE and a
nonce, verifies the ID token against the provider's keys, names the
user from `-oidc-user-claim` (default `email`) and takes the role from
`-oidc-role-claim` (default `groups`): a value listed in
`-oidc-operators` makes an operator, one in `-oidc-viewers` a viewer
(`*` accepts every authenticated user as a viewer), anything else is
refused. Register `https://<gui>/api/oidc/callback` as the redirect
URI at the provider (`-oidc-external-url` when the GUI sits behind a
proxy). Password and certificate logins keep working alongside; a
single sign-on session is subject to the same idle and absolute limits
and appears in the audit log with `via=oidc`.

The first user:

```sh
xproxy-admin user add admin -role operator     # prompts for the password twice
xproxy-admin user add oncall -role viewer
```

## Live terminal view

`xproxyctl tui` opens a full-screen view that refreshes from the
management socket:

| Screen | Content |
|--------|---------|
| 1 Overview | Version, listeners, counters, shedding state, the sandbox summary, telemetry exporter counters, dns listener counters with DNSSEC results, request and denied sparklines |
| 2 Upstreams | Endpoint health, ejection, in-flight, requests and errors; per pool the circuit breaker state, concurrency gate and queue, and canary counters |
| 3 Bans | Active bans; `j`/`k` select, `u` unban (confirm with `y`), `b` ban with `address [duration] [reason]` |
| 4 Cluster | Peers, inbound connections, message counters |
| 5 Graphs | Sparklines of the sampled series over the retention window |
| 6 Log | Last events from the security log file (needs `-config` to locate it) |
| 7 Routes | Usage per route (requests by class, denied, rate limited, bytes), per tenant, and per rate limit policy with the top consumers |
| 8 WAF | Counters, learning state, profiles with rule set source and version, route assignments, the most matched rules and the exclusion proposals |
| 9 TLS | Served certificates per listener: names, issuer, days left, source, OCSP status and CT verdict |

Keys: `1` to `9` or `tab` and `shift-tab` switch screens, `r` refreshes,
`p` pauses, `+` and `-` change the interval, `q` quits. Bans and unbans
from the TUI go through the same audited API as the CLI.

## Metrics and graphs

Scrape through the socket with a local exporter, or enable the TCP
endpoint for Prometheus:

```yaml
metrics:
  listen: 10.0.0.1:9100
  allow_cidrs: [10.0.5.0/24]          # the Prometheus servers
  tls:
    cert_file: /etc/xproxy/certs/metrics.pem
    key_file: /etc/xproxy/certs/metrics-key.pem
    client_ca_file: /etc/xproxy/certs/monitoring-ca.pem
```

```sh
xproxyctl metrics | grep -E '^xproxy_(requests_total|load_level|denied_total)'
xproxyctl series -since 30m -last 12
```

Useful expressions: `rate(xproxy_denied_total[5m])` by `reason` for attack
activity, `rate(xproxy_refusals_total[5m])` by `kind` and `reason` for
the same thing on the protocols that are not HTTP (an SSH bastion, an
FTP relay, a datagram listener), `histogram_quantile(0.99, rate(xproxy_upstream_ttfb_seconds_bucket[5m]))`
for backend health, `xproxy_shedding` to alert on load shedding,
`xproxy_upstream_endpoint_healthy == 0` for dead endpoints,
`xproxy_log_dropped_total` for a collector problem. The `series` command
shows the same numbers the TUI and GUI graph, sampled in process for the
configured retention, so a graph is available on a host with no
monitoring stack at all.

### Grafana dashboards and alert rules

Two Grafana dashboards and a Prometheus rule file ship with the product
(`deploy/grafana`, `deploy/prometheus`; installed under
`/usr/share/xproxy/grafana` and `/usr/share/xproxy/prometheus`):

- `xproxy-overview.json`: requests, status classes, request and
  upstream latency percentiles, upstream failures and healthy endpoints,
  per route rates and p99, bytes, load and shedding, in flight and
  queued requests, cache, certificate expiry, reloads and a node table.
- `xproxy-security.json`: denied requests by reason, WAF blocks and
  detect mode hits, bans, challenges, rate limit decisions per policy,
  filter denials, connections rejected at accept, honeypot and ICAP
  results, forward proxy policy, DNS filtering, log delivery per sink,
  cluster peers, and protocol refusals by kind and by reason for the
  listeners that are not HTTP.
- `xproxy-alerts.yaml`: availability rules (node down, no healthy
  endpoint, unhealthy endpoint, circuit open, 5xx ratio, p99 latency,
  shedding, queue refusals), operations rules (failed reload,
  certificate expiring at 14 and 3 days, log drops and write errors,
  cluster peer down, ICAP unreachable) and security rules (denies at
  ten times the hourly baseline, a protocol listener's refusals at ten
  times theirs, WAF block spike, ban wave, honeypot activity, saturated
  rate limit policy, refusals exported without a reason), each with a
  severity label and a description that names the command to look at.

Import the dashboards (Dashboards > New > Import) and pick the
Prometheus data source; both have an `instance` variable and link to
each other. Add the rule file to `rule_files` in `prometheus.yml`. A
test in the repository checks that every metric the assets name is one
the proxy exports, so they stay current with the binary.

## Logs

All streams are JSON lines with `time`, `level`, `msg` and `stream`.

### Sinks

Each stream lists where it goes. A typical production setup keeps access
logs in files, sends security and audit events to journald and to a remote
collector, and lets journald handle operational messages:

```yaml
logging:
  directory: /var/log/xproxy
  access:   {file: access.log, max_size_mb: 512, max_files: 10, sinks: [file]}
  error:    {sinks: [journald]}
  security: {file: security.log, sinks: [file, journald, syslog]}
  audit:    {file: audit.log, sinks: [file, syslog]}
  journald: {identifier: xproxy}
  syslog:
    network: tcp+tls
    address: logs.example.internal:6514
    ca_file: /etc/xproxy/certs/logs-ca.pem
    server_name: logs.example.internal
    facility: local3
```

`journalctl -t xproxy XPROXY_STREAM=security` and
`journalctl XPROXY_CLIENT_IP=203.0.113.9` filter on the indexed fields.
`xproxyctl status` shows `log_syslog_sent`, `log_syslog_dropped` and
`log_journald_dropped`; drops mean the collector is slow or unreachable,
never that the proxy waited.

### SIEM export

Security teams rarely want raw syslog. The `siem` sink posts batches
over HTTPS in the shape the receiving system expects, and the syslog
sink can speak CEF or LEEF for collectors that parse those from syslog:

```yaml
logging:
  security: {sinks: [file, siem]}
  audit:    {sinks: [file, siem]}
  access:   {sinks: [file]}
  siem:
    endpoint: https://splunk.example.com:8088/services/collector/event
    format: hec                     # or json, cef, leef
    auth_file: /etc/xproxy/siem-token   # "Splunk 1a2b3c..."
    ca_file: /etc/xproxy/certs/splunk-ca.pem
    batch: 256
    interval: 2s
```

With `format: hec` every record arrives as a Splunk event with
`sourcetype xproxy:security`, `xproxy:audit` and so on; with `json` the
body is newline delimited JSON for Elastic, OpenSearch, Logstash, Vector
or Fluent Bit inputs; `cef` and `leef` produce ArcSight and QRadar
lines whose standard fields (`src`, `suser`, `requestMethod`, `act`,
`reason`, `cn1` status...) map without a custom parser, and every other
attribute keeps its name. Sending is asynchronous behind a bounded
queue: an unreachable SIEM never slows a request, drops are counted and
`xproxyctl telemetry` shows the last error. For a syslog based
collector, `logging.syslog.format: cef` sends the same CEF line behind
an RFC 5424 header instead. Redaction applies before either sink, so
the SIEM receives the same pseudonymised addresses the files do unless
the security stream is excluded from the rules.

### Redaction

```yaml
logging:
  redaction:
    client_ip: hash
    hash_secret_file: /var/lib/xproxy/redaction.key
    user_agent: drop
    referer: origin
    claims: hash
    drop_fields: [sni]
```

With this in place the access, security and error streams carry a stable
pseudonym instead of the client address (the same client keeps the same
`h:` value across restarts and across nodes sharing the key file), no user
agent, referers cut to their origin and hashed token subjects, while the
audit stream keeps full detail. Set `enabled: false` to switch the rules
off temporarily during an incident without deleting them, and remember
that `xproxyctl bans` and the ban list itself still hold real addresses.

### access

One line per request:

```json
{"time":"...","level":"INFO","msg":"request","stream":"access","request_id":"6e74c0...","client_ip":"203.0.113.9","method":"GET","host":"example.com","path":"/","query_len":0,"proto":"HTTP/2.0","status":200,"bytes_in":0,"bytes_out":1234,"duration_ms":3.2,"route":"web","upstream":"web","endpoint":"10.0.1.10:8080","attempts":1,"user_agent":"...","referer":"","tls":"1.3","sni":"example.com"}
```

`denied` appears when the proxy rejected the request; `upstream_error` when
the upstream failed. Status 499 means the client left before a response.

### security

One line per deny, tarpit or dropped connection:

```json
{"time":"...","level":"WARN","msg":"security","stream":"security","action":"deny","reason":"rate_limit","request_id":"...","client_ip":"203.0.113.9","method":"POST","host":"example.com","path":"/login","route":"login","status":429,"user_agent":"..."}
```

Reasons: `concurrency`, `uri_length`, `bad_host`, `no_route`, `acl_deny`,
`acl_allow`, `rate_limit`, `rate_limit:<name>` (tarpit), `body_size`,
`websocket`, `waf`, `banned`, `max_connections`, `max_connections_per_ip`.

WAF entries add `waf_profile`, `waf_mode`, `waf_matched` (rule ids),
`waf_message`, `waf_score`, `waf_rule` (the interrupting rule), `waf_phase`.
Detections in `detect` mode appear on the access line with
`waf_detected: true`. Bans and unbans are logged with `msg: "client banned"`
and `"client unbanned"`, including trigger name, duration and count.

### error

Operational events: start, stop, listeners, reloads, upstream errors,
endpoint health transitions and ejections.

### audit

Management actions with the caller's uid, gid and pid, and every reload.

## Counters

`xproxyctl status` shows the counters used for graphs (1.0 adds a
Prometheus endpoint). Names match the JSON fields: `requests`,
`responses_2xx` to `responses_5xx`, `bytes_in`, `bytes_out`, `denied_*`,
`tarpitted`, `upstream_errors`, `upstream_timeouts`, `upstream_no_healthy`,
`client_aborts`, `denied_ban`, `denied_waf`, `waf_detected`, `bans_active`,
`bans_total`, `cluster_peers`, `cluster_connected`, `shed`, `load_level`,
`upstream_latency_ms`, `shedding_classes`, `challenges_issued`,
`challenges_passed`, `challenges_failed`, `captchas_passed`,
`honeytoken_hits`, `handshakes_refused`, `degraded`, `deceived`,
`denied_sensitive_data`, `denied_account_abuse`, `sensitive_findings`,
`account_blocks`, `account_campaigns`, `account_blocks_active`, `reloads`,
`reload_failures`,
`open_connections`, `rejected_connections`, `in_flight`.

## Troubleshooting

Every symptom, the log line that proves it and the fix live in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md), in five parts:

- **Orientation** — a sixty-second triage, a field guide to the access
  log line, a symptom index, what each `xproxyctl` command is for, the
  ordered list of every stage a request can die at, the timeout ladder,
  how to prove the problem is not the proxy, and how to reproduce one
  without affecting clients.
- **The proxy itself** — start-up, reload, routing, TLS, upstreams, the
  three HTTP versions, WebSockets and streaming, gRPC, static files,
  cache and compression.
- **Protection** — rate limits, bans, shedding and tarpits, the WAF,
  virtual patches and the positive policy, authentication, the challenge
  and CAPTCHA, filters, bot scoring, origin lock and security.txt.
- **Beyond one proxy** — cluster, DNS listener, forward proxy and layer
  4, mirroring and shadowing, the API inventory, Kubernetes ingress
  mode, fleet.
- **Operations and reference** — the management socket and GUI, logs and
  telemetry, the sandbox, performance, capacity, clocks, misbehaving
  clients, emergency procedures, upgrades, the bounded tables, every
  deny reason with the component that raises it and whether a ban
  trigger may name it, when to escalate, a glossary, and what to collect
  for a bug report.
