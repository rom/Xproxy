package config

import (
	"strings"
	"testing"
)

func TestAccessLogFormatValidation(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging:
  %s
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
routes:
  - name: r
    upstream: app
`
	ok := []string{
		"access: {format: common}",
		"access: {format: combined}",
		"access: {format: custom, template: '{client_ip} {status}'}",
		"access: {format: json}",
	}
	for _, snippet := range ok {
		if _, err := Parse([]byte(strings.Replace(base, "%s", snippet, 1))); err != nil {
			t.Errorf("%s: %v", snippet, err)
		}
	}
	bad := []struct{ snippet, want string }{
		{"access: {format: apache}", "must be json, common, combined or custom"},
		{"error: {format: common}", "only the access stream"},
		{"access: {format: custom}", "required for format custom"},
		{"access: {format: custom, template: '{client_ip'}", "unclosed"},
		{"access: {format: custom, template: '{a b}'}", "bad field name"},
		{"access: {format: common, template: x}", "only for format custom"},
		{"audit: {template: x}", "only for format custom"},
	}
	for _, c := range bad {
		_, err := Parse([]byte(strings.Replace(base, "%s", c.snippet, 1)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.snippet, err, c.want)
		}
	}
}
