package config

import (
	"strings"
	"testing"
	"time"
)

func TestDiscoveryConfig(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    %s
routes:
  - {name: r, upstream: u}
`
	ok, err := parseNoFiles([]byte(strings.Replace(base, "%s", `discovery: {type: dns, name: api.example., port: 8080}
    slow_start: 30s`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	d := ok.Upstreams[0].Discovery
	if d.Type != "dns" || d.Interval.D() != 30*time.Second || d.Timeout.D() != 5*time.Second || d.Weight != 1 || ok.Upstreams[0].SlowStart.D() != 30*time.Second {
		t.Fatalf("defaults %+v", d)
	}
	if _, err := parseNoFiles([]byte(strings.Replace(base, "%s", `discovery: {type: srv, name: _http._tcp.example.}`, 1))); err != nil {
		t.Fatalf("srv without port: %v", err)
	}
	// HTTP registry discovery: the URL is the name, format defaults to list.
	hc, err := parseNoFiles([]byte(strings.Replace(base, "%s", `discovery: {type: http, name: "https://consul.local/v1/health/service/api?passing", format: consul, port: 8080}`, 1)))
	if err != nil {
		t.Fatalf("http discovery: %v", err)
	}
	if d := hc.Upstreams[0].Discovery; d.Format != "consul" {
		t.Fatalf("http discovery format %q", d.Format)
	}
	hl, err := parseNoFiles([]byte(strings.Replace(base, "%s", `discovery: {type: http, name: "http://registry.local/services"}`, 1)))
	if err != nil {
		t.Fatalf("http list discovery: %v", err)
	}
	if d := hl.Upstreams[0].Discovery; d.Format != "list" {
		t.Fatalf("http discovery default format %q", d.Format)
	}
	cases := map[string]string{
		"http bad url":    `discovery: {type: http, name: "not a url"}`,
		"http scheme":     `discovery: {type: http, name: "ftp://registry.local/x"}`,
		"http format":     `discovery: {type: http, name: "http://registry.local/x", format: xml}`,
		"http resolver":   `discovery: {type: http, name: "http://registry.local/x", resolver: 10.0.0.53:53}`,
		"type":            `discovery: {type: mdns, name: a.example., port: 80}`,
		"dns needs port":  `discovery: {type: dns, name: a.example.}`,
		"port range":      `discovery: {type: dns, name: a.example., port: 70000}`,
		"name":            `discovery: {type: dns, name: "not a name", port: 80}`,
		"wildcard":        `discovery: {type: dns, name: "*.example.", port: 80}`,
		"interval":        `discovery: {type: dns, name: a.example., port: 80, interval: 2h}`,
		"timeout":         `discovery: {type: dns, name: a.example., port: 80, timeout: 5m}`,
		"resolver":        `discovery: {type: dns, name: a.example., port: 80, resolver: 10.0.0.53}`,
		"weight":          `discovery: {type: dns, name: a.example., port: 80, weight: -1}`,
		"canary no block": `discovery: {type: dns, name: a.example., port: 80, canary: true}`,
		"slow start":      "endpoints: [{address: \"10.0.0.1:80\"}]\n    slow_start: 2h",
		"nothing":         "balancer: round_robin",
	}
	for name, snippet := range cases {
		if _, err := parseNoFiles([]byte(strings.Replace(base, "%s", snippet, 1))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
