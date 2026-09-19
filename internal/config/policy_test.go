package config

import (
	"strings"
	"testing"
)

const policyBase = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: web
    endpoints: [{address: "10.0.0.1:8080"}]
routes:
  - name: api
    upstream: web
    policy:
      methods: [GET, POST]
      content_types: [application/json, text/*]
      max_uri_length: 2048
      max_query_params: 20
      deny_unknown_query: true
      query:
        - {name: id, type: int, required: true}
        - {name: kind, type: enum, values: [a, b]}
        - {name: tag, pattern: "[a-z]+", max_length: 8, max_repeat: 3}
virtual_patches:
  - id: cve-2024-1234
    paths: [/plugins/legacy-export]
    query: [{name: cmd}]
    expires: "2030-01-01"
  - id: body.probe
    routes: [api]
    body: {pattern: "__proto__", content_types: [application/json]}
    action: log
`

func TestPolicyAndPatchValidation(t *testing.T) {
	cfg, err := ParseWith([]byte(policyBase), false)
	if err != nil {
		t.Fatal(err)
	}
	pol := cfg.Routes[0].Policy
	if pol.Query[0].Type != "int" || pol.Query[2].Type != "string" || pol.Query[0].MaxRepeat != 1 || pol.Query[2].MaxRepeat != 3 {
		t.Fatalf("query defaults %+v", pol.Query)
	}
	if p := cfg.VirtualPatches; p[0].Action != "block" || p[0].Status != 403 || p[1].Body.MaxBytes != 64<<10 || !p[0].IsEnabled() {
		t.Fatalf("patch defaults %+v", p)
	}
	if exp, err := ParsePatchExpiry("2030-01-01"); err != nil || exp.Year() != 2030 || exp.Hour() != 23 {
		t.Fatalf("expiry %v %v", exp, err)
	}
	if _, err := ParsePatchExpiry("soon"); err == nil {
		t.Fatal("bad expiry accepted")
	}
	cases := []struct{ old, new, want string }{
		{"methods: [GET, POST]", "methods: [get]", "upper-case token"},
		{"methods: [GET, POST]", "methods: [GET, GET]", "duplicate"},
		{"content_types: [application/json, text/*]", "content_types: [json]", "type/subtype"},
		{"content_types: [application/json, text/*]", "content_types: ['*/json']", "type/subtype"},
		{"max_uri_length: 2048", "max_uri_length: -1", "max_uri_length"},
		{"max_query_params: 20", "max_query_params: 100000", "max_query_params"},
		{"        - {name: kind, type: enum, values: [a, b]}\n", "        - {name: kind, type: enum}\n", "type enum needs"},
		{"type: int, required: true", "type: int, required: true, values: [1]", "only for type enum"},
		{"type: int", "type: date", "must be string, int"},
		{"pattern: \"[a-z]+\"", "pattern: \"[a-z\"", "pattern"},
		{"max_repeat: 3", "max_repeat: 5000", "max_repeat"},
		{"- {name: id, type: int, required: true}", "- {name: kind, type: int}", "duplicate"},
		{"deny_unknown_query: true\n      query:\n        - {name: id, type: int, required: true}\n        - {name: kind, type: enum, values: [a, b]}\n        - {name: tag, pattern: \"[a-z]+\", max_length: 8, max_repeat: 3}\n", "deny_unknown_query: true\n", "requires a query list"},
		{"id: cve-2024-1234", "id: 'CVE 2024'", "not a valid identifier"},
		{"id: body.probe", "id: cve-2024-1234", "duplicate"},
		{"routes: [api]", "routes: [nope]", "unknown route"},
		{"paths: [/plugins/legacy-export]", "paths: [plugins]", "absolute, normalised prefix"},
		{"query: [{name: cmd}]", "query: [{name: cmd, pattern: \"(\"}]", "pattern"},
		{"body: {pattern: \"__proto__\", content_types: [application/json]}", "body: {pattern: \"\"}", "body.pattern"},
		{"body: {pattern: \"__proto__\", content_types: [application/json]}", "body: {pattern: x, max_bytes: 999999999}", "body.max_bytes"},
		{"    paths: [/plugins/legacy-export]\n    query: [{name: cmd}]\n", "    methods: [GET]\n", "needs at least one of"},
		{"action: log", "action: drop", "must be block or log"},
		{"expires: \"2030-01-01\"", "expires: soon", "expires"},
		{"expires: \"2030-01-01\"", "status: 200", "4xx or 5xx"},
	}
	for _, c := range cases {
		if !strings.Contains(policyBase, c.old) {
			t.Fatalf("snippet %q not in base", c.old)
		}
		mutated := strings.Replace(policyBase, c.old, c.new, 1)
		_, err := ParseWith([]byte(mutated), false)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q -> %q: error %v does not mention %q", c.old, c.new, err, c.want)
		}
	}
}
