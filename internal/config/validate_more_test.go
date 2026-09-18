package config

import (
	"strings"
	"testing"
)

// rich is a configuration touching most optional sections; file checks are
// off so referenced files need not exist.
const rich = `
version: 1
server:
  listeners:
    - name: http
      address: ":8080"
    - name: https
      address: ":8443"
      protocols: [h1, h2]
      tls:
        min_version: "1.3"
        certificates: [{cert_file: /c.pem, key_file: /k.pem}]
        client_auth: request
        client_ca_file: /ca.pem
logging:
  directory: /var/log/xproxy
  level: debug
  access: {sinks: [file, syslog, journald]}
  journald: {identifier: xproxy}
  syslog: {network: udp, address: 127.0.0.1:514, format: rfc3164, facility: local3}
  redaction: {streams: [access], client_ip: hash, hash_secret_file: /s, user_agent: drop, referer: origin, claims: hash, drop_fields: [cookie]}
rate_limits:
  - {name: per-ip, key: client_ip, rate: 10, burst: 20, action: tarpit}
  - {name: key, key: "header:X-Key", rate: 1, burst: 1}
upstreams:
  - name: app
    scheme: https
    balancer: hash
    hash_on: "cookie:sid"
    retries: 2
    tls: {ca_file: /ca.pem, min_version: "1.3", spki_pins: ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="], client_cert_file: /cc.pem, client_key_file: /ck.pem}
    health_check: {path: /h, interval: 1s, timeout: 500ms, expected_status: [200, 204]}
    affinity: {cookie_name: sid, ttl: 1h, secret_file: /af}
    outlier_ejection: {consecutive_failures: 2, base_ejection_time: 30s, max_ejection_percent: 50}
    endpoints:
      - {address: 127.0.0.1:9000, weight: 2}
      - {address: 127.0.0.1:9001}
bans:
  state_file: /var/lib/xproxy/bans.db
  action: reject
  exempt_cidrs: [10.0.0.0/8]
  triggers:
    - {name: t, reasons: [waf, rate_limit], threshold: 3, window: 1m, duration: 10m, escalation: 2, max_duration: 1h}
cluster:
  node_id: n1
  listen: 10.0.0.1:7946
  peers: [10.0.0.2:7946]
  tls: {cert_file: /c.pem, key_file: /k.pem, ca_file: /ca.pem}
shedding: {target_latency: 200ms, window: 10s}
challenge: {secret_file: /ch, difficulty: 16, ttl: 10m, cookie_name: xc, exempt_cidrs: [10.0.0.0/8], title: Checking}
jwt:
  providers:
    - {name: hs, issuer: https://issuer.example, algorithms: [HS256], hmac_secret_file: /hs, source: "header:X-Token", forward_claims: {X-User: sub}}
    - {name: rs, issuer: https://issuer.example, algorithms: [RS256], jwks_url: https://issuer.example/jwks, jwks_refresh: 5m, clock_skew: 30s}
icap:
  services:
    - {name: av, url: "icaps://scan.example:11344/avscan", tls: {ca_file: /ca.pem}, preview: 4096}
waf:
  default_mode: detect
  default_profile: p
  profiles:
    - {name: p, crs: {paranoia_level: 2}}
    - {name: custom, directives: "SecRuleEngine On"}
filters:
  - {name: g, kind: header_guard, options: {deny: [{header: A, pattern: b}]}}
metrics:
  listen: 10.0.0.1:9100
  allow_cidrs: [10.0.0.0/8]
  tls: {cert_file: /c.pem, key_file: /k.pem, client_ca_file: /ca.pem}
  sample_interval: 5s
  retention: 30m
acme:
  directory: https://acme.example/directory
  email: a@example.com
  accept_terms: true
routes:
  - name: r
    hosts: ["*.example.com"]
    paths: [/api/]
    methods: [GET, POST]
    rate_limits: [per-ip, key]
    allow_cidrs: [0.0.0.0/0]
    deny_cidrs: [192.0.2.0/24]
    priority_class: high
    waf: {mode: block, profile: custom}
    jwt: {provider: hs}
    icap: {service: av, response: true}
    challenge: {mode: load}
    filters: [g]
    request_headers: {set: {X-A: b}, remove: [X-Old]}
    upstream: app
`

func parseRich(t *testing.T, mutate func(string) string) error {
	t.Helper()
	_, err := ParseWith([]byte(mutate(rich)), false)
	return err
}

func TestRichConfigValid(t *testing.T) {
	if err := parseRich(t, func(s string) string { return s }); err != nil {
		t.Fatal(err)
	}
}

func TestValidationBranches(t *testing.T) {
	rep := func(old, new string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				t.Fatalf("snippet %q not in rich config", old)
			}
			return strings.Replace(s, old, new, 1)
		}
	}
	cases := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{"log dir", rep("directory: /var/log/xproxy", "directory: relative"), "logging.directory"},
		{"log level", rep("level: debug", "level: loud"), "logging.level"},
		{"log file name", rep("access: {sinks", "access: {file: a/b, sinks"), "bare file name"},
		{"log rotation", rep("access: {sinks", "access: {max_files: -1, sinks"), "rotation values"},
		{"sink journald without section", rep("  journald: {identifier: xproxy}\n", ""), "journald requires"},
		{"sink syslog without section", rep("  syslog: {network: udp, address: 127.0.0.1:514, format: rfc3164, facility: local3}\n", ""), "syslog requires"},
		{"sink unknown", rep("sinks: [file, syslog, journald]", "sinks: [file, pigeon]"), "must be file, journald or syslog"},
		{"journald socket", rep("journald: {identifier: xproxy}", "journald: {identifier: xproxy, socket: rel}"), "journald.socket"},
		{"journald identifier", rep("identifier: xproxy", "identifier: 'x y'"), "journald.identifier"},
		{"syslog unix path", rep("network: udp, address: 127.0.0.1:514", "network: unix, address: rel"), "absolute socket path"},
		{"syslog address", rep("address: 127.0.0.1:514", "address: nohost"), "must be host:port"},
		{"syslog network", rep("network: udp", "network: carrier-pigeon"), "syslog.network"},
		{"syslog format", rep("format: rfc3164", "format: rfc9999"), "syslog.format"},
		{"syslog facility", rep("facility: local3", "facility: local9"), "unknown facility"},
		{"syslog app name", rep("facility: local3", "facility: local3, app_name: 'a b'"), "app_name"},
		{"syslog tls cert pair", rep("network: udp", "network: tcp+tls, cert_file: /c.pem"), "cert_file and key_file"},
		{"syslog queue", rep("facility: local3", "facility: local3, queue_size: 1"), "queue_size"},
		{"redaction stream", rep("streams: [access]", "streams: [debug]"), "unknown stream"},
		{"redaction ip", rep("client_ip: hash", "client_ip: blur"), "redaction.client_ip"},
		{"redaction secret", rep("hash_secret_file: /s", "hash_secret_file: s"), "hash_secret_file"},
		{"redaction ua", rep("user_agent: drop", "user_agent: shorten"), "redaction.user_agent"},
		{"redaction referer", rep("referer: origin", "referer: host"), "redaction.referer"},
		{"redaction claims", rep("claims: hash", "claims: mask"), "redaction.claims"},
		{"redaction drop msg", rep("drop_fields: [cookie]", "drop_fields: [msg]"), "cannot be dropped"},
		{"rate limit key", rep("key: client_ip", "key: user"), "rate_limits[0].key"},
		{"rate limit rate", rep("rate: 10, burst: 20", "rate: 0, burst: 20"), "rate: must be positive"},
		{"rate limit burst", rep("rate: 10, burst: 20", "rate: 10, burst: -1"), "burst"},
		{"rate limit action", rep("action: tarpit", "action: ban"), "action: must be reject or tarpit"},
		{"balancer", rep("balancer: hash", "balancer: random"), "balancer"},
		{"hash_on", rep(`hash_on: "cookie:sid"`, `hash_on: "path"`), "hash_on"},
		{"scheme", rep("scheme: https", "scheme: ftp"), "scheme"},
		{"tls on http", rep("scheme: https", "scheme: http"), "set only when scheme is https"},
		{"weight", rep("weight: 2", "weight: 1001"), "weight"},
		{"duplicate endpoint", rep("127.0.0.1:9001", "127.0.0.1:9000"), "duplicate"},
		{"endpoint port", rep("127.0.0.1:9001", "127.0.0.1:99999"), "bad port"},
		{"retries", rep("retries: 2", "retries: 9"), "retries"},
		{"idle conns", rep("retries: 2", "retries: 2\n    max_idle_conns_per_host: -1"), "max_idle_conns_per_host"},
		{"timeouts", rep("retries: 2", "retries: 2\n    timeouts: {connect: -1s}"), "timeouts"},
		{"health path", rep("path: /h", "path: h"), "health_check.path"},
		{"health interval", rep("interval: 1s, timeout: 500ms", "interval: 100ms, timeout: 50ms"), "health_check.interval"},
		{"health timeout", rep("timeout: 500ms", "timeout: 2s"), "health_check.timeout"},
		{"health max concurrent", rep("expected_status: [200, 204]", "expected_status: [200], max_concurrent: 5000"), "max_concurrent"},
		{"health thresholds", rep("expected_status: [200, 204]", "expected_status: [200], healthy_threshold: -1"), "thresholds"},
		{"health status", rep("expected_status: [200, 204]", "expected_status: [999]"), "not an HTTP status"},
		{"affinity cookie", rep("cookie_name: sid", "cookie_name: 'bad cookie'"), "cookie_name"},
		{"affinity ttl", rep("ttl: 1h, secret_file: /af", "ttl: -1s, secret_file: /af"), "affinity.ttl"},
		{"affinity secret", rep("secret_file: /af", "secret_file: af"), "affinity.secret_file"},
		{"outlier failures", rep("consecutive_failures: 2", "consecutive_failures: -1"), "consecutive_failures"},
		{"outlier base", rep("base_ejection_time: 30s", "base_ejection_time: -1s"), "base_ejection_time"},
		{"outlier percent", rep("max_ejection_percent: 50", "max_ejection_percent: 101"), "max_ejection_percent"},
		{"upstream tls version", rep(`min_version: "1.3", spki_pins`, `min_version: "1.1", spki_pins`), "min_version"},
		{"spki pin", rep(`spki_pins: ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]`, `spki_pins: ["nope"]`), "spki_pins"},
		{"pins with insecure", rep("client_cert_file: /cc.pem, client_key_file: /ck.pem", "client_cert_file: /cc.pem, client_key_file: /ck.pem, insecure_skip_verify: true, allow_insecure: true"), "cannot be combined"},
		{"client cert pair", rep(", client_key_file: /ck.pem", ""), "client_cert_file and client_key_file"},
		{"listener tls version", rep(`min_version: "1.3"
        certificates`, `min_version: "1.0"
        certificates`), "min_version"},
		{"client auth", rep("client_auth: request", "client_auth: maybe"), "client_auth"},
		{"client ca missing", rep("\n        client_ca_file: /ca.pem", ""), "client_ca_file"},
		{"ban state", rep("state_file: /var/lib/xproxy/bans.db", "state_file: bans.db"), "bans.state_file"},
		{"ban entries", rep("action: reject", "action: reject\n  max_entries: -1"), "max_entries"},
		{"ban exempt", rep("exempt_cidrs: [10.0.0.0/8]\n  triggers", "exempt_cidrs: [10.0.0.0]\n  triggers"), "exempt_cidrs"},
		{"ban action", rep("action: reject", "action: nuke"), "bans.action"},
		{"trigger reason", rep("reasons: [waf, rate_limit]", "reasons: [weather]"), "unknown reason"},
		{"trigger threshold", rep("threshold: 3", "threshold: 0"), "threshold"},
		{"trigger window", rep("window: 1m, duration: 10m", "window: 25h, duration: 10m"), "window"},
		{"trigger duration", rep("duration: 10m, escalation", "duration: 0s, escalation"), "duration: must be positive"},
		{"trigger escalation", rep("escalation: 2", "escalation: 101"), "escalation"},
		{"trigger max", rep("max_duration: 1h", "max_duration: 1m"), "max_duration"},
		{"cluster node", rep("node_id: n1", "node_id: 'n 1'"), "cluster.node_id"},
		{"cluster listen", rep("listen: 10.0.0.1:7946", "listen: 0.0.0.0:7946"), "internal interface"},
		{"cluster listen missing", rep("listen: 10.0.0.1:7946\n  peers", "peers"), "cluster.listen: required"},
		{"cluster peer", rep("peers: [10.0.0.2:7946]", "peers: [nohost]"), "peers[0]"},
		{"cluster peer dup", rep("peers: [10.0.0.2:7946]", "peers: [10.0.0.2:7946, 10.0.0.2:7946]"), "duplicate"},
		{"cluster tls", rep("tls: {cert_file: /c.pem, key_file: /k.pem, ca_file: /ca.pem}\nshedding", "tls: {cert_file: /c.pem}\nshedding"), "mutual TLS is mandatory"},
		{"cluster gossip", rep("  peers: [10.0.0.2:7946]\n", "  peers: [10.0.0.2:7946]\n  gossip_interval: 10ms\n"), "gossip_interval"},
		{"cluster stale", rep("  peers: [10.0.0.2:7946]\n", "  peers: [10.0.0.2:7946]\n  peer_stale: 1ms\n"), "peer_stale"},
		{"cluster keys", rep("  peers: [10.0.0.2:7946]\n", "  peers: [10.0.0.2:7946]\n  max_keys_per_report: 70000\n"), "max_keys_per_report"},
		{"shedding latency", rep("target_latency: 200ms", "target_latency: -1s"), "target_latency"},
		{"shedding window", rep("window: 10s}", "window: 11m}"), "shedding.window"},
		{"challenge secret", rep("secret_file: /ch", "secret_file: ch"), "challenge.secret_file"},
		{"challenge difficulty", rep("difficulty: 16", "difficulty: 40"), "difficulty"},
		{"challenge ttl", rep("ttl: 10m, cookie_name", "ttl: 1s, cookie_name"), "challenge.ttl"},
		{"challenge cookie", rep("cookie_name: xc", "cookie_name: 'x c'"), "challenge.cookie_name"},
		{"challenge exempt", rep("exempt_cidrs: [10.0.0.0/8], title", "exempt_cidrs: [nope], title"), "challenge.exempt_cidrs"},
		{"challenge title", rep("title: Checking", "title: '<b>'"), "challenge.title"},
		{"jwt issuer", rep("{name: hs, issuer: https://issuer.example,", "{name: hs,"), "issuer: required"},
		{"jwt algorithm", rep("algorithms: [HS256]", "algorithms: [none]"), "not allowed"},
		{"jwt jwks url", rep("jwks_url: https://issuer.example/jwks", "jwks_url: http://issuer.example/jwks"), "jwks_url"},
		{"jwt refresh", rep("jwks_refresh: 5m", "jwks_refresh: 1s"), "jwks_refresh"},
		{"jwt hmac without hs", rep("algorithms: [RS256], jwks_url: https://issuer.example/jwks", "algorithms: [RS256], jwks_url: https://issuer.example/jwks, hmac_secret_file: /x"), "no HS algorithm"},
		{"jwt hs without secret", rep(", hmac_secret_file: /hs", ""), "require hmac_secret_file"},
		{"jwt no key source", rep("jwks_url: https://issuer.example/jwks, jwks_refresh: 5m, clock_skew: 30s", "clock_skew: 30s"), "is required"},
		{"jwt skew", rep("clock_skew: 30s", "clock_skew: 1h"), "clock_skew"},
		{"jwt source", rep(`source: "header:X-Token"`, `source: "query:t"`), "source"},
		{"jwt forward header", rep("forward_claims: {X-User: sub}", "forward_claims: {'bad header': sub}"), "not a valid header name"},
		{"jwt forward host", rep("forward_claims: {X-User: sub}", "forward_claims: {Host: sub}"), "cannot be overwritten"},
		{"icap url", rep(`url: "icaps://scan.example:11344/avscan"`, `url: "http://scan.example/avscan"`), "icap://"},
		{"icap tls on plain", rep(`url: "icaps://scan.example:11344/avscan"`, `url: "icap://scan.example:1344/avscan"`), "set only with an icaps"},
		{"icap timeout", rep("preview: 4096}", "preview: 4096, timeout: 5m}"), "timeout"},
		{"icap max conns", rep("preview: 4096}", "preview: 4096, max_conns: 2000}"), "max_conns"},
		{"icap max body", rep("preview: 4096}", "preview: 4096, max_body: 10}"), "max_body"},
		{"icap limit action", rep("preview: 4096}", "preview: 4096, body_limit_action: explode}"), "body_limit_action"},
		{"icap fail", rep("preview: 4096}", "preview: 4096, fail: sometimes}"), "fail: must be open or closed"},
		{"icap preview", rep("preview: 4096}", "preview: huge}"), "preview"},
		{"waf mode", rep("default_mode: detect", "default_mode: maybe"), "waf.default_mode"},
		{"waf body limit", rep("default_mode: detect", "default_mode: detect\n  request_body_limit: 10"), "request_body_limit"},
		{"waf body action", rep("default_mode: detect", "default_mode: detect\n  request_body_limit_action: drop"), "request_body_limit_action"},
		{"waf response limit", rep("default_mode: detect", "default_mode: detect\n  response_body_limit: 10"), "response_body_limit"},
		{"waf profile empty", rep("{name: custom, directives: \"SecRuleEngine On\"}", "{name: custom}"), "needs crs"},
		{"waf paranoia", rep("paranoia_level: 2", "paranoia_level: 9"), "paranoia_level"},
		{"waf default profile", rep("default_profile: p", "default_profile: nope"), "unknown profile"},
		{"route waf mode", rep("waf: {mode: block, profile: custom}", "waf: {mode: loud, profile: custom}"), "mode: must be off, detect or block"},
		{"route waf profile", rep("waf: {mode: block, profile: custom}", "waf: {mode: block, profile: nope}"), "unknown profile"},
		{"route header name", rep("request_headers: {set: {X-A: b}, remove: [X-Old]}", "request_headers: {set: {'bad name': b}}"), "not a valid header name"},
		{"route header value", rep("request_headers: {set: {X-A: b}, remove: [X-Old]}", "request_headers: {set: {X-A: \"a\\u0000b\"}}"), "control characters"},
		{"metrics listen", rep("listen: 10.0.0.1:9100\n  allow_cidrs: [10.0.0.0/8]\n  tls: {cert_file: /c.pem, key_file: /k.pem, client_ca_file: /ca.pem}", "listen: 0.0.0.0:9100\n  tls: {cert_file: /c.pem, key_file: /k.pem}"), "binding all interfaces"},
		{"metrics cidr", rep("allow_cidrs: [10.0.0.0/8]\n  tls", "allow_cidrs: [nope]\n  tls"), "metrics.allow_cidrs"},
		{"metrics tls pair", rep("tls: {cert_file: /c.pem, key_file: /k.pem, client_ca_file: /ca.pem}\n  sample_interval", "tls: {cert_file: /c.pem}\n  sample_interval"), "cert_file and key_file are required"},
		{"metrics interval", rep("sample_interval: 5s", "sample_interval: 10ms"), "sample_interval"},
		{"metrics retention", rep("retention: 30m", "retention: 1s"), "retention"},
		{"metrics points", rep("sample_interval: 5s\n  retention: 30m", "sample_interval: 1s\n  retention: 168h"), "100000 points"},
		{"acme directory", rep("directory: https://acme.example/directory", "directory: http://acme.example/directory"), "acme.directory"},
		{"acme terms", rep("accept_terms: true", "accept_terms: false"), "accept_terms"},
		{"acme email", rep("email: a@example.com", "email: nobody"), "acme.email"},
		{"acme state", rep("accept_terms: true", "accept_terms: true\n  state_dir: rel"), "state_dir"},
		{"acme challenge", rep("accept_terms: true", "accept_terms: true\n  challenge: dns-01"), "acme.challenge"},
		{"acme renew", rep("accept_terms: true", "accept_terms: true\n  renew_before: 1h"), "renew_before"},
		{"acme check", rep("accept_terms: true", "accept_terms: true\n  check_interval: 1s"), "check_interval"},
		{"route rate limit", rep("rate_limits: [per-ip, key]", "rate_limits: [nope]"), "unknown rate limit"},
		{"route allow", rep("allow_cidrs: [0.0.0.0/0]", "allow_cidrs: [nope]"), "allow_cidrs"},
		{"route class", rep("priority_class: high", "priority_class: urgent"), "priority_class"},
		{"route jwt provider", rep("jwt: {provider: hs}", "jwt: {provider: nope}"), "jwt"},
		{"route icap service", rep("icap: {service: av, response: true}", "icap: {service: nope}"), "icap"},
		{"route challenge mode", rep("challenge: {mode: load}", "challenge: {mode: sometimes}"), "challenge"},
	}
	for _, c := range cases {
		err := parseRich(t, c.mutate)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err.Error(), c.want)
		}
	}
}
