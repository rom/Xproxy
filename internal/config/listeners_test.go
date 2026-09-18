package config

import (
	"fmt"
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
    - name: resolver
      address: ":5353"
      kind: dns
      dns:
        upstreams: ["9.9.9.9:53", "[2620:fe::fe]:53", "tls://dns.quad9.net:853", "https://dns.quad9.net/dns-query"]
        block: [ads.test, "*.tracker.test", =exact.test]
        rate_limit: {}
`
	cfg, err := Parse([]byte(strings.Replace(base, "%s", valid, 1)))
	if err != nil {
		t.Fatal(err)
	}
	l4, fwd := cfg.Server.Listeners[1], cfg.Server.Listeners[2]
	if l4.TCP.IdleTimeout.D().Minutes() != 10 || l4.TCP.MaxConnections != 10000 || len(l4.Protocols) != 0 || l4.TCP.QUICIdleTimeout.D() != 30*time.Second {
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
	d := cfg.Server.Listeners[3].DNS
	if d.Timeout.D().Seconds() != 2 || d.BlockAction != "nxdomain" || d.SinkholeIPv4 != "0.0.0.0" || d.SinkholeIPv6 != "::" ||
		d.Cache.MaxEntries != 10000 || d.Cache.MinTTL.D().Seconds() != 5 || d.Cache.MaxTTL.D().Hours() != 1 || d.Cache.NegativeTTL.D().Seconds() != 60 ||
		d.MaxInFlight != 1024 || d.RateLimit.QPS != 50 || d.RateLimit.Burst != 100 || len(cfg.Server.Listeners[3].Protocols) != 0 {
		t.Fatalf("dns defaults: %+v cache %+v rl %+v", d, d.Cache, d.RateLimit)
	}
	cases := []struct {
		name, snippet, want string
	}{
		{"unknown kind", "    - {name: x, address: \":1\", kind: udp}\n", "must be http, tcp, forward or dns"},
		{"tcp block on http", "    - {name: x, address: \":1\", tcp: {default: app}}\n", "set on an http listener"},
		{"forward block on http", "    - {name: x, address: \":1\", forward: {}}\n", "set on an http listener"},
		{"proxy protocol needs trusted proxies", "    - {name: x, address: \":1\", proxy_protocol: true}\n", "needs trusted_proxies"},
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
		{"tcp quic idle", "    - {name: x, address: \":1\", kind: tcp, tcp: {default: app, quic: true, quic_idle_timeout: 2h}}\n", "quic_idle_timeout"},
		{"tcp quic proxy protocol", "    - {name: x, address: \":1\", kind: tcp, tcp: {default: app, quic: true, proxy_protocol: true}}\n", "disable proxy_protocol or quic"},
		{"forward without section", "    - {name: x, address: \":1\", kind: forward}\n", "required for kind forward"},
		{"forward with tcp", "    - {name: x, address: \":1\", kind: forward, forward: {}, tcp: {default: app}}\n", "takes no tcp"},
		{"forward h2 without tls", "    - {name: x, address: \":1\", kind: forward, forward: {}, protocols: [h1, h2]}\n", "requires tls"},
		{"forward h3", "    - {name: x, address: \":1\", kind: forward, forward: {}, protocols: [h1, h3], tls: {certificates: [{cert_file: /c, key_file: /k}]}}\n", "takes no tcp, redirect_to_https, h3"},
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
		{"dns without section", "    - {name: x, address: \":1\", kind: dns}\n", "required for kind dns"},
		{"dns block on http", "    - {name: x, address: \":1\", dns: {upstreams: [\"9.9.9.9:53\"]}}\n", "set on an http listener"},
		{"dns with tls", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"]}, h2c: true}\n", "takes only address and dns"},
		{"dns no upstreams", "    - {name: x, address: \":1\", kind: dns, dns: {}}\n", "at least one resolver"},
		{"dns bad upstream", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9\"]}}\n", "must be host:port"},
		{"dns tls upstream", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"tls://9.9.9.9\"]}}\n", "tls://host:port"},
		{"dns https upstream", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"https://dns.test\"]}}\n", "https://host"},
		{"dns transport", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"quic://dns.test:853\"]}}\n", "unknown transport"},
		{"dns ca", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"tls://9.9.9.9:853\"], upstream_ca_file: rel.pem}}\n", "upstream_ca_file"},
		{"dns timeout", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], timeout: 1m}}\n", "dns.timeout"},
		{"dns client cidr", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], allow_clients: [x]}}\n", "allow_clients"},
		{"dns block entry", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], block: [\"a b\"]}}\n", "dns.block"},
		{"dns block file", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], block_file: rel}}\n", "block_file"},
		{"dns action", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], block_action: drop}}\n", "block_action"},
		{"dns sinkhole4", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], sinkhole_ipv4: \"::1\"}}\n", "sinkhole_ipv4"},
		{"dns sinkhole6", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], sinkhole_ipv6: 1.2.3.4}}\n", "sinkhole_ipv6"},
		{"dns cache ttl", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], cache: {min_ttl: 2h}}}\n", "min_ttl must not exceed"},
		{"dns cache entries", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], cache: {max_entries: -1}}}\n", "max_entries"},
		{"dns negative ttl", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], cache: {negative_ttl: 48h}}}\n", "negative_ttl"},
		{"dns rate", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], rate_limit: {qps: -1}}}\n", "dns.rate_limit"},
		{"dns in flight", "    - {name: x, address: \":1\", kind: dns, dns: {upstreams: [\"9.9.9.9:53\"], max_in_flight: -1}}\n", "max_in_flight"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(strings.Replace(base, "%s", tc.snippet, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestGRPCConfig covers h2c and gRPC health check validation.
func TestGRPCConfig(t *testing.T) {
	base := `
version: 1
server:
  listeners:
    - {name: main, address: ":8080"%s}
upstreams:
  - name: app
    %s
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: r
    upstream: app
`
	if _, err := Parse([]byte(fmt.Sprintf(base, ", h2c: true", "h2c: true\n    health_check: {type: grpc, grpc_service: a.B}"))); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, listener, upstream, want string }{
		{"h2c with tls", ", h2c: true, tls: {certificates: [{cert_file: /c, key_file: /k}]}", "", "only for plaintext"},
		{"h2c on https upstream", "", "scheme: https\n    h2c: true", "only for scheme http"},
		{"grpc check needs h2", "", "health_check: {type: grpc}", "needs h2c or scheme https"},
		{"grpc check path", "", "h2c: true\n    health_check: {type: grpc, path: /x}", "not used by type grpc"},
		{"grpc service on http check", "", "health_check: {grpc_service: a}", "only for type grpc"},
		{"bad grpc service", "", "h2c: true\n    health_check: {type: grpc, grpc_service: \"a b\"}", "not a service name"},
		{"check type", "", "health_check: {type: tcp}", "must be http or grpc"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(fmt.Sprintf(base, tc.listener, tc.upstream)))
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
		{"two actions", "upstream: app\n    honeypot: {decoy: env}", "exactly one of upstream, redirect, respond, honeypot, doh or static"},
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
		{"grpc service", "upstream: app\n    grpc: {services: [\"a/b\"]}", "grpc.services"},
		{"grpc method", "upstream: app\n    grpc: {methods: [nomethod]}", "grpc.methods"},
		{"grpc without upstream", "respond: {status: 200}\n    grpc: {}", "only a route with an upstream"},
		{"doh without listener", "doh: {}", "doh.listener: required"},
		{"doh unknown listener", "doh: {listener: main}", "not a kind: dns listener"},
		{"doh and upstream", "upstream: app\n    doh: {listener: main}", "exactly one of"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(strings.Replace(base, "%s", tc.snippet, 1)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestIngressConfig covers the ingress section's defaults and rules.
func TestIngressConfig(t *testing.T) {
	base := `
version: 1
server:
  listeners:
    - {name: main, address: ":8080"}
    - name: https
      address: ":8443"
      tls: {certificates: [{cert_file: /c.pem, key_file: /k.pem}]}
ingress:
  enabled: true
%s
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: r
    upstream: app
`
	cfg, err := ParseWith([]byte(strings.Replace(base, "%s", "  listener: https", 1)), false)
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Ingress
	if in.APIServer != "https://kubernetes.default.svc" || in.Class != "xproxy" || in.CertDir != "/var/lib/xproxy/ingress" || in.Resync.D() != 30*time.Second ||
		in.Timeout.D() != 10*time.Second || !strings.HasSuffix(in.TokenFile, "/token") || !strings.HasSuffix(in.CAFile, "/ca.crt") || !in.Watches() || in.Debounce.D() != 500*time.Millisecond {
		t.Fatalf("ingress defaults: %+v", in)
	}
	cases := []struct{ name, snippet, want string }{
		{"http api", "  api_server: http://localhost:8001", "api_server"},
		{"relative token", "  token_file: token", "token_file"},
		{"relative ca", "  ca_file: ca.crt", "ca_file"},
		{"class", "  class: \"a b\"", "ingress.class"},
		{"namespace", "  namespaces: [\"a.b\"]", "namespaces[0]"},
		{"unknown listener", "  listener: nope", "unknown listener"},
		{"plain listener", "  listener: main", "must be an http listener with tls"},
		{"cert dir", "  cert_dir: certs", "cert_dir"},
		{"resync", "  resync: 2h", "ingress.resync"},
		{"timeout", "  timeout: 10m", "ingress.timeout"},
		{"debounce", "  debounce: 5m", "ingress.debounce"},
	}
	for _, tc := range cases {
		_, err := ParseWith([]byte(strings.Replace(base, "%s", tc.snippet, 1)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
	// Disabled sections are not checked.
	if _, err := ParseWith([]byte(strings.Replace(strings.Replace(base, "enabled: true", "enabled: false", 1), "%s", "  resync: 2h", 1)), false); err != nil {
		t.Fatalf("disabled ingress validated: %v", err)
	}
}

// TestOTLPConfig covers the exporter section's defaults and rules.
func TestOTLPConfig(t *testing.T) {
	base := `
version: 1
server:
  listeners:
    - {name: main, address: ":8080"}
metrics:
  otlp:
    endpoint: %s
%s
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: r
    upstream: app
`
	cfg, err := ParseWith([]byte(fmt.Sprintf(base, "https://otel.test:4318/v1/metrics", "")), false)
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.Metrics.OTLP
	if o.Interval.D() != 30*time.Second || o.Timeout.D() != 10*time.Second || o.ServiceName != "xproxy" || o.Compress == nil || !*o.Compress {
		t.Fatalf("otlp defaults: %+v", o)
	}
	cases := []struct{ name, endpoint, extra, want string }{
		{"http", "http://otel.test/v1/metrics", "", "otlp.endpoint"},
		{"http allowed", "http://otel.test/v1/metrics", "    allow_http: true\n    interval: 0s", ""},
		{"interval", "https://otel.test/v1/metrics", "    interval: 2h", "otlp.interval"},
		{"timeout", "https://otel.test/v1/metrics", "    timeout: 1m", "otlp.timeout"},
		{"header", "https://otel.test/v1/metrics", "    headers: {\"a b\": x}", "otlp.headers"},
		{"ca", "https://otel.test/v1/metrics", "    ca_file: rel.pem", "otlp.ca_file"},
		{"service", "https://otel.test/v1/metrics", "    service_name: " + strings.Repeat("s", 256), "otlp.service_name"},
	}
	for _, tc := range cases {
		_, err := ParseWith([]byte(fmt.Sprintf(base, tc.endpoint, tc.extra)), false)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}
