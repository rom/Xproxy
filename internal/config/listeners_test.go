package config

import (
	"strings"
	"testing"
	"time"
)

// TestListenerKinds covers the tcp and forward listener kinds: defaults,
// the fields each kind refuses and every validation rule of their
// sections.
func TestListenerKinds(t *testing.T) {
	base := `
version: 1
server:
  listeners:
    - name: main
      address: ":8080"
%s
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: r
    hosts: [example.test]
    upstream: app
`
	valid := `
    - name: l4
      address: ":8443"
      kind: tcp
      tcp:
        routes: [{sni: [a.test, "*.b.test"], upstream: app}]
        default: app
    - name: fwd
      address: ":3128"
      kind: forward
      forward:
        allow: ["*.example.test", "203.0.113.0/24", "2001:db8::1"]
        deny: [internal.example.test]
        auth: {users_file: /etc/xproxy/proxy.htpasswd}
`
	cfg, err := Parse([]byte(strings.Replace(base, "%s", valid, 1)))
	if err != nil {
		t.Fatal(err)
	}
	l4, fwd := cfg.Server.Listeners[1], cfg.Server.Listeners[2]
	if l4.TCP.IdleTimeout.D().Minutes() != 10 || l4.TCP.MaxConnections != 10000 || len(l4.Protocols) != 0 {
		t.Fatalf("tcp defaults: %+v protocols %v", l4.TCP, l4.Protocols)
	}
	f := fwd.Forward
	if len(f.Ports) != 2 || f.Ports[0] != 80 || f.Ports[1] != 443 || f.ConnectTimeout.D().Seconds() != 10 || f.IdleTimeout.D().Minutes() != 10 ||
		f.MaxTunnels != 10000 || f.MaxResponseBytes != 64<<20 || f.Auth.Realm != "proxy" || f.AllowPrivate {
		t.Fatalf("forward defaults: %+v", f)
	}
	if len(fwd.Protocols) != 1 || fwd.Protocols[0] != ProtocolH1 {
		t.Fatalf("forward protocols: %v", fwd.Protocols)
	}
	cases := []struct {
		name, snippet, want string
	}{
		{"unknown kind", "    - {name: x, address: \":1\", kind: udp}\n", "must be http, tcp or forward"},
		{"tcp block on http", "    - {name: x, address: \":1\", tcp: {default: app}}\n", "set on an http listener"},
		{"forward block on http", "    - {name: x, address: \":1\", forward: {}}\n", "set on an http listener"},
		{"tcp without section", "    - {name: x, address: \":1\", kind: tcp}\n", "required for kind tcp"},
		{"tcp with tls", "    - {name: x, address: \":1\", kind: tcp, tcp: {default: app}, redirect_to_https: true}\n", "takes no tls"},
		{"tcp nothing to route", "    - {name: x, address: \":1\", kind: tcp, tcp: {}}\n", "routes or default is required"},
		{"tcp route without sni", "    - {name: x, address: \":1\", kind: tcp, tcp: {routes: [{upstream: app}]}}\n", "at least one server name"},
		{"tcp bad sni", "    - {name: x, address: \":1\", kind: tcp, tcp: {routes: [{sni: [\"a*b\"], upstream: app}]}}\n", "not a valid name"},
		{"tcp duplicate sni", "    - {name: x, address: \":1\", kind: tcp, tcp: {routes: [{sni: [a.test, a.test], upstream: app}]}}\n", "listed twice"},
		{"tcp route without upstream", "    - {name: x, address: \":1\", kind: tcp, tcp: {routes: [{sni: [a.test]}]}}\n", "upstream: required"},
		{"tcp unknown upstream", "    - {name: x, address: \":1\", kind: tcp, tcp: {default: nope}}\n", "nope"},
		{"tcp idle", "    - {name: x, address: \":1\", kind: tcp, tcp: {default: app, idle_timeout: 48h}}\n", "idle_timeout"},
		{"tcp max", "    - {name: x, address: \":1\", kind: tcp, tcp: {default: app, max_connections: -1}}\n", "max_connections"},
		{"forward without section", "    - {name: x, address: \":1\", kind: forward}\n", "required for kind forward"},
		{"forward with tcp", "    - {name: x, address: \":1\", kind: forward, forward: {}, tcp: {default: app}}\n", "speaks h1 only"},
		{"forward h2", "    - {name: x, address: \":1\", kind: forward, forward: {}, protocols: [h1, h2]}\n", "speaks h1 only"},
		{"forward port", "    - {name: x, address: \":1\", kind: forward, forward: {ports: [0]}}\n", "not a port"},
		{"forward port twice", "    - {name: x, address: \":1\", kind: forward, forward: {ports: [443, 443]}}\n", "listed twice"},
		{"forward allow", "    - {name: x, address: \":1\", kind: forward, forward: {allow: [\"a*b\"]}}\n", "allow"},
		{"forward deny", "    - {name: x, address: \":1\", kind: forward, forward: {deny: [\"10.0.0.0/33\"]}}\n", "deny"},
		{"forward auth file", "    - {name: x, address: \":1\", kind: forward, forward: {auth: {}}}\n", "users_file: required"},
		{"forward realm", "    - {name: x, address: \":1\", kind: forward, forward: {auth: {users_file: /u, realm: \"a\\\"b\"}}}\n", "realm"},
		{"forward connect timeout", "    - {name: x, address: \":1\", kind: forward, forward: {connect_timeout: 10m}}\n", "connect_timeout"},
		{"forward idle", "    - {name: x, address: \":1\", kind: forward, forward: {idle_timeout: 48h}}\n", "idle_timeout"},
		{"forward tunnels", "    - {name: x, address: \":1\", kind: forward, forward: {max_tunnels: -1}}\n", "max_tunnels"},
		{"forward response bytes", "    - {name: x, address: \":1\", kind: forward, forward: {max_response_bytes: -1}}\n", "max_response_bytes"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(strings.Replace(base, "%s", tc.snippet, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestRouteActions covers the honeypot action's validation.
func TestRouteActions(t *testing.T) {
	base := `
version: 1
server:
  listeners:
    - {name: main, address: ":8080"}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
  - name: shadow
    endpoints: [{address: 127.0.0.1:9001}]
routes:
  - name: r
    paths: [/x]
    %s
`
	cfg, err := Parse([]byte(strings.Replace(base, "%s", "honeypot: {}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	mcfg, err := Parse([]byte(strings.Replace(base, "%s", "upstream: app\n    mirror: {upstream: shadow}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if m := mcfg.Routes[0].Mirror; m.Percent != 100 || m.MaxBodyBytes != 1<<20 || m.Timeout.D() != 5*time.Second || m.MaxInFlight != 64 {
		t.Fatalf("mirror defaults: %+v", m)
	}
	hp := cfg.Routes[0].Honeypot
	if hp.Decoy != "admin-login" || hp.Status != 200 || hp.Mark.D() != time.Hour || hp.ContentType == "" {
		t.Fatalf("honeypot defaults: %+v", hp)
	}
	cases := []struct{ name, snippet, want string }{
		{"two actions", "upstream: app\n    honeypot: {decoy: env}", "exactly one of upstream, redirect, respond or honeypot"},
		{"two sources", "honeypot: {decoy: env, body: x}", "exactly one of decoy, body or body_file"},
		{"unknown decoy", "honeypot: {decoy: nope}", "unknown decoy"},
		{"status", "honeypot: {decoy: env, status: 99}", "honeypot.status"},
		{"relative file", "honeypot: {body_file: rel.html}", "absolute path"},
		{"delay", "honeypot: {decoy: env, delay: 2m}", "honeypot.delay"},
		{"mark", "honeypot: {decoy: env, mark: 800h}", "honeypot.mark"},
		{"content type", "honeypot: {body: x, content_type: \"a\\nb\"}", "content_type"},
		{"mirror without upstream", "honeypot: {decoy: env}\n    mirror: {upstream: app}", "only a route with an upstream"},
		{"mirror same upstream", "upstream: app\n    mirror: {upstream: app}", "must differ"},
		{"mirror unknown upstream", "upstream: app\n    mirror: {upstream: nope}", "unknown upstream"},
		{"mirror percent", "upstream: app\n    mirror: {upstream: shadow, percent: 101}", "mirror.percent"},
		{"mirror method", "upstream: app\n    mirror: {upstream: shadow, methods: [get]}", "mirror.methods"},
		{"mirror body", "upstream: app\n    mirror: {upstream: shadow, max_body_bytes: 100000000}", "mirror.max_body_bytes"},
		{"mirror timeout", "upstream: app\n    mirror: {upstream: shadow, timeout: 10m}", "mirror.timeout"},
		{"mirror in flight", "upstream: app\n    mirror: {upstream: shadow, max_in_flight: -1}", "mirror.max_in_flight"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(strings.Replace(base, "%s", tc.snippet, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}
