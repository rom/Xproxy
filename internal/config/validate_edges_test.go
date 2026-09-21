package config

import (
	"strings"
	"testing"
)

// The validator is what stands between an operator's typing mistake and
// a proxy that comes up serving something nobody meant. The sections
// below are the ones the rich configuration does not reach: the log
// shipper, the fleet agent, maintenance, the CAPTCHA, the sandbox, the
// virtual patches and the positive policy.

const wider = `
version: 1
server:
  listeners:
    - name: main
      address: ":8080"
    - name: l4
      kind: tcp
      address: ":9000"
      tcp: {default: app, idle_timeout: 10m, max_connections: 1000}
  limits: {max_connections: 1024, max_connections_per_ip: 64}
  error_pages:
    dir: /var/lib/xproxy/pages
    pages: {"404": 404.html, "5xx": 5xx.html, default: default.html}
    content_type: "text/html; charset=utf-8"
    intercept_upstream: [502, 503]
logging:
  directory: /var/log/xproxy
  access: {sinks: [siem]}
  siem:
    endpoint: https://collector.example/services/collector
    format: hec
    headers: {X-Index: main}
    auth_file: /siem-token
    timeout: 10s
    batch: 512
    interval: 5s
    queue: 8192
    vendor: Sysctl
    product: Xproxy
sandbox:
  landlock: {read_paths: [/etc/xproxy], write_paths: [/var/lib/xproxy]}
maintenance:
  enabled: false
  status: 503
  retry_after: 300s
  message: back soon
  allow_cidrs: [10.0.0.0/8]
  allow_header: "X-Bypass: let-me-in"
challenge:
  secret_file: /ch
  difficulty: 16
  ttl: 10m
  cookie_name: xc
  cookie_scope: host
  captcha:
    provider: turnstile
    site_key: sk
    secret_file: /captcha
    verify_url: https://challenges.example/verify
    timeout: 5s
    min_score: 0.5
    mode: escalation
    hostnames: [shop.test]
fleet:
  controller: https://fleet.example
  node_id: node-a
  interval: 30s
  timeout: 10s
  dir: /var/lib/xproxy/fleet
  tags: [edge, se]
  tls: {cert_file: /c.pem, key_file: /k.pem, ca_file: /ca.pem}
virtual_patches:
  - id: cve-2026-1
    description: a patch
    hosts: ["*.shop.test"]
    methods: [POST]
    paths: [/admin]
    path_regex: ["/admin/[a-z]+"]
    query: [{name: id, pattern: "^[0-9]+$"}]
    headers: [{name: X-Trigger}]
    cookies: [{name: sid, pattern: "^s-"}]
    action: block
    status: 403
    expires: "2999-01-01"
security_txt:
  - name: public
    contact: ["mailto:security@shop.test"]
    expires: "2999-01-01T00:00:00Z"
upstreams:
  - name: app
    endpoints: [{address: "127.0.0.1:9000"}]
routes:
  - name: api
    hosts: [shop.test]
    upstream: app
    policy:
      methods: [GET, POST]
      max_query_params: 32
      max_header_bytes: 8192
      query: [{name: id, pattern: "^[0-9]+$"}]
`

func parseWider(t *testing.T, mutate func(string) string) error {
	t.Helper()
	_, err := ParseWith([]byte(mutate(wider)), false)
	return err
}

func TestWiderConfigValid(t *testing.T) {
	if err := parseWider(t, func(s string) string { return s }); err != nil {
		t.Fatal(err)
	}
}

func TestWiderValidationBranches(t *testing.T) {
	rep := func(old, new string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				t.Fatalf("snippet %q not in the wider config", old)
			}
			return strings.Replace(s, old, new, 1)
		}
	}
	cases := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		// The log shipper carries security events off the box; a
		// collector reached in plain text, or a batch nobody bounded,
		// is refused rather than shipped.
		{"siem scheme", rep("endpoint: https://collector.example/services/collector", "endpoint: http://collector.example/x"), "must be an https URL"},
		{"siem not a url", rep("endpoint: https://collector.example/services/collector", "endpoint: \"::\""), "must be a URL"},
		{"siem empty endpoint", rep("endpoint: https://collector.example/services/collector", "endpoint: \"\""), "must be a URL"},
		{"siem format", rep("format: hec", "format: xml"), "must be json, hec, cef or leef"},
		{"siem timeout", rep("timeout: 10s", "timeout: 5m"), "siem.timeout"},
		{"siem header name", rep("headers: {X-Index: main}", "headers: {\"Bad Header\": main}"), "is not a header"},
		{"siem batch", rep("batch: 512", "batch: 20000"), "siem.batch"},
		{"siem interval", rep("interval: 5s", "interval: 10ms"), "siem.interval"},
		{"siem queue", rep("queue: 8192", "queue: 2000000"), "siem.queue"},
		{"siem vendor", rep("vendor: Sysctl", "vendor: \"a|b\""), "siem.vendor"},
		{"siem product", rep("product: Xproxy", "product: \"a\\\\b\""), "siem.product"},
		{"siem half a client certificate", rep("auth_file: /siem-token", "auth_file: /siem-token\n    cert_file: /c.pem"), "cert_file and key_file"},

		// The sandbox's extra paths become kernel rules; a relative one
		// would silently widen what the process may touch.
		{"sandbox read path", rep("read_paths: [/etc/xproxy]", "read_paths: [etc/xproxy]"), "must be an absolute path"},
		{"sandbox write path", rep("write_paths: [/var/lib/xproxy]", "write_paths: [\"var/lib\"]"), "must be an absolute path"},

		// Maintenance holds every client, so its exemptions have to be
		// exactly what they claim to be.
		{"maintenance status", rep("status: 503\n  retry_after", "status: 200\n  retry_after"), "4xx or 5xx"},
		{"maintenance retry", rep("retry_after: 300s", "retry_after: -1s"), "retry_after"},
		{"maintenance cidr", rep("allow_cidrs: [10.0.0.0/8]\n  allow_header", "allow_cidrs: [10.0.0.0]\n  allow_header"), "is not a CIDR"},
		{"maintenance header", rep(`allow_header: "X-Bypass: let-me-in"`, `allow_header: "X-Bypass"`), "allow_header"},
		{"maintenance header without value", rep(`allow_header: "X-Bypass: let-me-in"`, `allow_header: "X-Bypass: "`), "allow_header"},

		// The challenge cookie is the pass a client carries; its scope,
		// its name and the CAPTCHA behind it all gate admission.
		{"challenge scope", rep("cookie_scope: host", "cookie_scope: everywhere"), "cookie_scope"},
		{"challenge difficulty", rep("difficulty: 16", "difficulty: 40"), "difficulty"},
		{"challenge ttl", rep("ttl: 10m", "ttl: 1s"), "challenge.ttl"},
		{"challenge cookie name", rep("cookie_name: xc", "cookie_name: \"x c\""), "cookie_name"},
		{"challenge secret path", rep("secret_file: /ch", "secret_file: ch"), "absolute path"},
		{"captcha provider", rep("provider: turnstile", "provider: mycaptcha"), "captcha.provider"},
		{"captcha site key", rep("site_key: sk", "site_key: \"<script>\""), "site_key"},
		{"captcha secret path", rep("secret_file: /captcha", "secret_file: captcha"), "captcha.secret_file"},
		{"captcha verify url", rep("verify_url: https://challenges.example/verify", "verify_url: http://challenges.example/verify"), "verify_url"},
		{"captcha timeout", rep("timeout: 5s\n    min_score", "timeout: 5m\n    min_score"), "captcha.timeout"},
		{"captcha score", rep("min_score: 0.5", "min_score: 2"), "min_score"},
		{"captcha mode", rep("mode: escalation", "mode: never"), "captcha.mode"},
		{"captcha hostname", rep("hostnames: [shop.test]", "hostnames: [\"Shop.Test\"]"), "lower case host name"},

		// The fleet agent takes configuration from a controller, so the
		// controller has to be named exactly and reached with mutual TLS.
		{"fleet scheme", rep("controller: https://fleet.example", "controller: http://fleet.example"), "https URL"},
		{"fleet path", rep("controller: https://fleet.example", "controller: https://fleet.example/agent"), "must not carry a path"},
		{"fleet not a url", rep("controller: https://fleet.example", "controller: \"::\""), "must be a URL"},
		{"fleet node id", rep("node_id: node-a", "node_id: \"node a\""), "node_id"},
		{"fleet interval", rep("interval: 30s\n  timeout", "interval: 1s\n  timeout"), "fleet.interval"},
		{"fleet timeout", rep("timeout: 10s\n  dir", "timeout: 5m\n  dir"), "fleet.timeout"},
		{"fleet dir", rep("dir: /var/lib/xproxy/fleet", "dir: relative"), "absolute path"},
		{"fleet tag", rep("tags: [edge, se]", "tags: [\"edge zone\"]"), "fleet.tags"},
		{"fleet tls", rep("tls: {cert_file: /c.pem, key_file: /k.pem, ca_file: /ca.pem}", "tls: {cert_file: /c.pem}"), "mutual TLS is mandatory"},

		// A virtual patch is a rule written under time pressure; every
		// pattern in it is compiled here rather than at the first request.
		{"patch path regex", rep(`path_regex: ["/admin/[a-z]+"]`, `path_regex: ["/admin/["]`), "path_regex"},
		{"patch query pattern", rep(`query: [{name: id, pattern: "^[0-9]+$"}]`, `query: [{name: id, pattern: "("}]`), "pattern"},
		{"patch expiry", rep(`expires: "2999-01-01"`, `expires: "soon"`), "expires"},
		{"patch status", rep("status: 403", "status: 99"), "status"},
		{"patch action", rep("action: block\n    status", "action: melt\n    status"), "action"},
		{"patch host", rep(`hosts: ["*.shop.test"]`, `hosts: ["*"]`), "hosts"},
		{"patch header without a name", rep("headers: [{name: X-Trigger}]", "headers: [{name: \"\"}]"), "headers"},
		{"patch cookie pattern", rep(`cookies: [{name: sid, pattern: "^s-"}]`, `cookies: [{name: sid, pattern: "("}]`), "cookies"},

		// The error pages and security.txt are served to everyone.
		{"error page name", rep("pages: {\"404\": 404.html", "pages: {\"nope\": 404.html"), "error_pages"},
		{"error page intercept", rep("intercept_upstream: [502, 503]", "intercept_upstream: [99]"), "intercept_upstream"},
		{"security.txt contact", rep(`contact: ["mailto:security@shop.test"]`, `contact: []`), "contact"},
		{"security.txt expiry", rep(`expires: "2999-01-01T00:00:00Z"`, `expires: "next year"`), "expires"},

		// The positive policy says what a route accepts; a pattern that
		// does not compile would otherwise fail open at the first request.
		{"policy method", rep("methods: [GET, POST]", "methods: [\"GET POST\"]"), "policy"},
		{"policy query type", rep(`      query: [{name: id, pattern: "^[0-9]+$"}]`, `      query: [{name: id, type: colour}]`), "must be string, int"},
		{"policy query pattern", rep(`      query: [{name: id, pattern: "^[0-9]+$"}]`, `      query: [{name: id, pattern: "["}]`), "pattern"},
		{"policy deny_unknown without a list", rep(`      query: [{name: id, pattern: "^[0-9]+$"}]`, `      deny_unknown_query: true`), "requires a query list"},
	}
	for _, c := range cases {
		err := parseWider(t, c.mutate)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err.Error(), c.want)
		}
	}
}

func TestValidateEntryPointsAndAdvice(t *testing.T) {
	c, err := ParseWith([]byte(wider), false)
	if err != nil {
		t.Fatal(err)
	}
	// ValidateNoFiles is what a dry run and the fleet controller use:
	// the document is judged without the files it names being present.
	if err := ValidateNoFiles(c); err != nil {
		t.Errorf("ValidateNoFiles on a valid document: %v", err)
	}
	// Validate is the same with the file checks on, so a configuration
	// naming files that are not there is refused.
	if err := Validate(c); err == nil {
		t.Error("Validate accepted a document naming files that do not exist")
	}
	// Advice is the warnings the last validation produced; it never
	// stops a start, and it is always safe to read.
	_ = c.Advice()

	// A configuration that weakens the deployment loads with advice
	// rather than an error, which is the whole point of the channel.
	weak, err := ParseWith([]byte(`
version: 1
server:
  listeners: [{name: main, address: ":8080"}]
cluster:
  node_id: n1
  listen: 10.0.0.1:7946
  peers: [10.0.0.2:7946]
  tls: {cert_file: /c.pem, key_file: /k.pem, ca_file: /ca.pem}
upstreams: [{name: app, endpoints: [{address: "127.0.0.1:9000"}]}]
routes: [{name: r, upstream: app}]
`), false)
	if err != nil {
		t.Fatalf("a weak but valid configuration was refused: %v", err)
	}
	if len(weak.Advice()) == 0 {
		t.Error("a cluster that admits any certificate its CA issued produced no advice")
	}
}

func TestSandboxOn(t *testing.T) {
	// The section defaults to on when present: an operator who writes a
	// sandbox block gets one without also having to enable it.
	if !(&Sandbox{}).On() {
		t.Error("a sandbox section without enabled is off")
	}
	yes, no := true, false
	if !(&Sandbox{Enabled: &yes}).On() {
		t.Error("enabled: true is off")
	}
	if (&Sandbox{Enabled: &no}).On() {
		t.Error("enabled: false is on")
	}
}

// A reload decides per listener whether it can be changed in place,
// rebuilt behind the same socket, or only by restarting the process.
// Getting that wrong either drops connections needlessly or leaves a
// listener serving the old settings.
func TestListenerChangeClassification(t *testing.T) {
	parse := func(t *testing.T, y string) *Config {
		t.Helper()
		c, err := ParseWith([]byte(y), false)
		if err != nil {
			t.Fatalf("parse: %v\n%s", err, y)
		}
		return c
	}
	const base = `
version: 1
server:
  listeners:
    - name: main
      address: ":8443"
      protocols: [h1, h2]
      tls: {certificates: [{cert_file: /c.pem, key_file: /k.pem}]}
    - name: fw
      kind: forward
      address: ":3128"
      forward: {allow: ["*.example.com"]}
    - name: d
      kind: dns
      address: ":5353"
      dns: {upstreams: ["1.1.1.1:53"], doh_path: /dns-query}
upstreams: [{name: app, endpoints: [{address: "127.0.0.1:9000"}]}]
routes: [{name: r, upstream: app}]
`
	from := parse(t, base)

	// Nothing changed at all.
	if got := listenerChange(from, parse(t, base), "main"); got != listenerInPlace {
		t.Errorf("an unchanged listener = %v", got)
	}
	// A listener one side does not have is not this function's business:
	// adding and removing are handled by the reload itself.
	if got := listenerChange(from, parse(t, base), "nosuchlistener"); got != listenerInPlace {
		t.Errorf("an unknown listener = %v", got)
	}

	// Certificates, the forward policy and the DNS policy are all read
	// again in place, so a certificate renewal does not drop a
	// connection.
	inPlace := map[string]string{
		"main": strings.Replace(base, "cert_file: /c.pem", "cert_file: /new.pem", 1),
		"fw":   strings.Replace(base, `allow: ["*.example.com"]`, `allow: ["*.other.com"]`, 1),
		"d":    strings.Replace(base, `upstreams: ["1.1.1.1:53"]`, `upstreams: ["9.9.9.9:53"]`, 1),
	}
	for name, y := range inPlace {
		if got := listenerChange(from, parse(t, y), name); got != listenerInPlace {
			t.Errorf("%s: a policy change = %v, want in place", name, got)
		}
	}
	// The DoH path is part of the listener's routing, not its policy, so
	// it rebuilds.
	if got := listenerChange(from, parse(t, strings.Replace(base, "doh_path: /dns-query", "doh_path: /resolve", 1)), "d"); got == listenerInPlace {
		t.Error("the DoH path changed in place")
	}

	// An address change rebuilds: the old socket goes, the new one binds.
	if got := listenerChange(from, parse(t, strings.Replace(base, `address: ":8443"`, `address: ":9443"`, 1)), "main"); got != listenerRebuild {
		t.Errorf("an address change = %v, want a rebuild", got)
	}
	// A listener that also binds UDP cannot be rebuilt on the same
	// address while the old one still holds the socket, so it needs a
	// restart.
	withH3 := strings.Replace(base, "protocols: [h1, h2]", "protocols: [h1, h2, h3]", 1)
	h3 := parse(t, withH3)
	if got := listenerChange(h3, parse(t, withH3), "main"); got != listenerInPlace {
		t.Errorf("an unchanged h3 listener = %v", got)
	}
	changed := strings.Replace(withH3, "tls: {certificates:", `tls: {min_version: "1.3", certificates:`, 1)
	if got := listenerChange(h3, parse(t, changed), "main"); got != listenerRestart {
		t.Errorf("a changed h3 listener = %v, want a restart", got)
	}
}

func TestListenerHasUDP(t *testing.T) {
	cases := []struct {
		name string
		l    Listener
		want bool
	}{
		{"a plain http listener", Listener{}, false},
		{"h1 and h2", Listener{Protocols: []Protocol{ProtocolH1, ProtocolH2}}, false},
		{"h3", Listener{Protocols: []Protocol{ProtocolH1, ProtocolH3}}, true},
		{"a tcp listener", Listener{Kind: "tcp", TCP: &TCPListener{}}, false},
		{"a tcp listener relaying QUIC", Listener{Kind: "tcp", TCP: &TCPListener{QUIC: true}}, true},
		{"a tcp listener with no section", Listener{Kind: "tcp"}, false},
		{"a plain dns listener", Listener{Kind: "dns"}, true},
		{"an encrypted dns listener", Listener{Kind: "dns", TLS: &TLS{}}, false},
	}
	for _, c := range cases {
		if got := ListenerHasUDP(c.l); got != c.want {
			t.Errorf("%s = %v want %v", c.name, got, c.want)
		}
	}
}

func TestClusterNeedsRestart(t *testing.T) {
	with := func(node, listen, cert string) *Config {
		return &Config{Cluster: &Cluster{NodeID: node, Listen: listen, TLS: ClusterTLS{CertFile: cert, KeyFile: "/k.pem", CAFile: "/ca.pem"}}}
	}
	base := with("n1", "10.0.0.1:7946", "/c.pem")

	if clusterNeedsRestart(base, with("n1", "10.0.0.1:7946", "/c.pem")) {
		t.Error("an unchanged cluster section needs a restart")
	}
	// The peer list and the intervals are picked up by a reload; the
	// identity, the address and the certificates are not.
	for name, to := range map[string]*Config{
		"a new node id":  with("n2", "10.0.0.1:7946", "/c.pem"),
		"a new address":  with("n1", "10.0.0.2:7946", "/c.pem"),
		"a new key pair": with("n1", "10.0.0.1:7946", "/new.pem"),
	} {
		if !clusterNeedsRestart(base, to) {
			t.Errorf("%s does not need a restart", name)
		}
	}
	// Turning clustering on or off is a restart in either direction: the
	// node has no listener to add or remove at runtime.
	none := &Config{}
	if !clusterNeedsRestart(base, none) || !clusterNeedsRestart(none, base) || !clusterNeedsRestart(none, none) {
		t.Error("adding or removing the cluster section does not need a restart")
	}
	// The peer list alone is reloadable.
	peers := with("n1", "10.0.0.1:7946", "/c.pem")
	peers.Cluster.Peers = []string{"10.0.0.9:7946"}
	if clusterNeedsRestart(base, peers) {
		t.Error("a new peer needs a restart")
	}
}
