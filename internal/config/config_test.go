package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const minimal = `
version: 1
server:
  listeners:
    - name: http
      address: ":8080"
upstreams:
  - name: app
    endpoints:
      - address: 127.0.0.1:9000
routes:
  - name: all
    upstream: app
`

func TestMinimalDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	l := c.Server.Limits
	if l.MaxHeaderBytes != DefaultMaxHeaderBytes || l.MaxBodyBytes != DefaultMaxBodyBytes || l.ReadHeaderTimeout.D() != DefaultReadHeaderTimeout {
		t.Fatalf("limits defaults: %+v", l)
	}
	if c.Server.Listeners[0].Protocols[0] != ProtocolH1 || len(c.Server.Listeners[0].Protocols) != 1 {
		t.Fatalf("protocol default: %v", c.Server.Listeners[0].Protocols)
	}
	u := c.Upstreams[0]
	if u.Balancer != "round_robin" || u.Scheme != "http" || *u.Retries != 1 || u.Endpoints[0].Weight != 1 || u.Timeouts.Connect.D() != DefaultUpstreamConnect {
		t.Fatalf("upstream defaults: %+v", u)
	}
	if c.Routes[0].Paths[0] != "/" {
		t.Fatal("route path default")
	}
	if c.Logging.Directory != DefaultLogDirectory || c.Logging.Access.File != "access.log" || c.Logging.Level != "info" {
		t.Fatalf("logging defaults: %+v", c.Logging)
	}
	if c.Management.SocketMode != "0660" {
		t.Fatal("socket mode default")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":      strings.Replace(minimal, "version: 1", "version: 1\nbogus: true", 1),
		"bad version":        strings.Replace(minimal, "version: 1", "version: 7", 1),
		"no listeners":       strings.Replace(minimal, "    - name: http\n      address: \":8080\"\n", "    []\n", 1),
		"unknown upstream":   strings.Replace(minimal, "upstream: app", "upstream: nope", 1),
		"no action":          strings.Replace(minimal, "    upstream: app", "    paths: [/]", 1),
		"two actions":        strings.Replace(minimal, "    upstream: app", "    upstream: app\n    respond: {status: 200}", 1),
		"bad endpoint":       strings.Replace(minimal, "127.0.0.1:9000", "127.0.0.1", 1),
		"h2 without tls":     strings.Replace(minimal, "address: \":8080\"", "address: \":8080\"\n      protocols: [h1, h2]", 1),
		"tls 1.0":            minimal + "\n",
		"negative timeout":   strings.Replace(minimal, "server:\n", "server:\n  limits: {read_header_timeout: -1s}\n", 1),
		"tiny header limit":  strings.Replace(minimal, "server:\n", "server:\n  limits: {max_header_bytes: 10}\n", 1),
		"insecure upstream":  strings.Replace(minimal, "    endpoints:", "    scheme: https\n    tls: {insecure_skip_verify: true}\n    endpoints:", 1),
		"bad cidr":           strings.Replace(minimal, "    upstream: app", "    upstream: app\n    deny_cidrs: [nope]", 1),
		"header injection":   strings.Replace(minimal, "    upstream: app", "    upstream: app\n    request_headers: {set: {X-A: \"a\\r\\nInjected: b\"}}", 1),
		"path traversal":     strings.Replace(minimal, "    upstream: app", "    upstream: app\n    paths: [/a/../b]", 1),
		"unknown rate limit": strings.Replace(minimal, "    upstream: app", "    upstream: app\n    rate_limits: [x]", 1),
		"duplicate route":    minimal + "  - name: all\n    upstream: app\n",
		"socket other-rw":    minimal + "management: {socket: /run/x.sock, socket_mode: \"0666\"}\n",
		"relative log dir":   minimal + "logging: {directory: logs}\n",
		"empty":              "",
		"two documents":      minimal + "---\nversion: 1\n",
		"hash without key":   strings.Replace(minimal, "    endpoints:", "    balancer: hash\n    hash_on: nope\n    endpoints:", 1),
		"bad retries":        strings.Replace(minimal, "    endpoints:", "    retries: 9\n    endpoints:", 1),
	}
	// "tls 1.0" needs a real TLS block.
	cases["tls 1.0"] = strings.Replace(minimal, "address: \":8080\"", "address: \":8443\"\n      tls: {min_version: \"1.0\", certificates: [{cert_file: /c, key_file: /k}]}", 1)
	for name, y := range cases {
		c, err := parseNoFiles([]byte(y))
		if err == nil {
			t.Errorf("%s: accepted: %+v", name, c)
		}
	}
}

func TestMultipleErrorsReported(t *testing.T) {
	y := strings.Replace(minimal, "upstream: app", "upstream: nope\n    deny_cidrs: [bad]", 1)
	_, err := Parse([]byte(y))
	var ve *ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 2 {
		t.Fatalf("want 2 problems, got %v", err)
	}
	if !strings.Contains(err.Error(), "2 problems") {
		t.Fatal(err.Error())
	}
}

func TestZeroTimeoutMeansDefault(t *testing.T) {
	// A zero timeout can never disable a slowloris defence: it is treated as
	// "unset" and replaced by the default.
	c, err := Parse([]byte(strings.Replace(minimal, "server:\n", "server:\n  limits: {read_header_timeout: 0s}\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Limits.ReadHeaderTimeout.D() != DefaultReadHeaderTimeout {
		t.Fatal(c.Server.Limits.ReadHeaderTimeout)
	}
}

func TestDuration(t *testing.T) {
	c, err := Parse([]byte(strings.Replace(minimal, "server:\n", "server:\n  limits: {read_header_timeout: 1500ms}\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Limits.ReadHeaderTimeout.D() != 1500*time.Millisecond {
		t.Fatal(c.Server.Limits.ReadHeaderTimeout)
	}
	if _, err := Parse([]byte(strings.Replace(minimal, "server:\n", "server:\n  limits: {read_header_timeout: soon}\n", 1))); err == nil {
		t.Fatal("bad duration accepted")
	}
}

func TestRateLimitDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal + "rate_limits:\n  - name: r\n    rate: 0.5\n"))
	if err != nil {
		t.Fatal(err)
	}
	rl := c.RateLimits[0]
	if rl.Key != "client_ip" || rl.Action != "reject" || rl.Burst != 1 || rl.TarpitDelay.D() != DefaultTarpitDelay {
		t.Fatalf("%+v", rl)
	}
}

func TestHostPattern(t *testing.T) {
	good := []string{"example.com", "*.example.com", "localhost", "a-b.c_d.e", "xn--80ak6aa92e.com"}
	bad := []string{"", "*", "*.", "a.*.b", "*example.com", "exa mple.com", "a..b", strings.Repeat("a", 64) + ".com"}
	for _, h := range good {
		if !hostPatternOK(h) {
			t.Errorf("%q rejected", h)
		}
	}
	for _, h := range bad {
		if hostPatternOK(h) {
			t.Errorf("%q accepted", h)
		}
	}
}

// parseNoFiles parses and validates without checking file existence.
func parseNoFiles(data []byte) (*Config, error) {
	return ParseWith(data, false)
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(minimal))
	f.Add([]byte("version: 1\n"))
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err == nil && c == nil {
			t.Fatal("nil config without error")
		}
	})
}
