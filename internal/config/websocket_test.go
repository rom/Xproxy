package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wsRouteConfig wraps a websocket_guard in the smallest configuration that
// carries an upgraded route.
func wsRouteConfig(guard string) string {
	return `
version: 1
server:
  listeners:
    - {name: main, address: ":8080"}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: ws
    paths: [/ws]
    upstream: app
    websocket: true
    websocket_guard:
` + guard
}

// TestTheWebSocketMessagePolicyIsChecked: the message policy has three ways to
// be written down and mean nothing, and each of them is a refusal rather than a
// surprise in production.
func TestTheWebSocketMessagePolicyIsChecked(t *testing.T) {
	schema := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(schema, []byte(`{"type":"object"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// checkFiles is off, as it is for every other parse test here, so the
	// one path check these cases can make is the one that does not need a
	// filesystem; a missing schema file is caught by the same v.file as
	// every other path in the configuration.
	for _, c := range []struct {
		name, guard, want string
	}{
		{"an unknown compression policy", "      compression: maybe\n", "must be strip, refuse or inspect"},
		{"inflating what nothing reads", "      compression: inspect\n      inspect: none\n",
			"inflates every message and reads none of them"},
		{"a ratio that is not one", "      compression: inspect\n      max_inflate_ratio: 1\n",
			"max_inflate_ratio"},
		{"types on a route that keeps no bytes", "      inspect: none\n      types: [{name: a}]\n",
			"decides nothing, because no message is read"},
		{"a type twice", "      types: [{name: a}, {name: a}]\n", "is already a type on this route"},
		{"a type with no name", "      types: [{max_bytes: 10}]\n", "name: required"},
		{"a bound larger than the connection's", "      max_message_bytes: 4096\n      max_frame_bytes: 4096\n" +
			"      types: [{name: a, max_bytes: 8192}]\n", "between 0 and max_message_bytes"},
		{"a direction that is not one", "      types: [{name: a, direction: sideways}]\n",
			"must be client, server or both"},
		{"a schema that is not a path", "      types: [{name: a, schema_file: s.json}]\n",
			"must be an absolute path"},
		{"refusing every message", "      unknown_types: deny\n",
			"deny with no types refuses every message"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseWith([]byte(wsRouteConfig(c.guard)), false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one mentioning %q", err, c.want)
			}
		})
	}

	// The defaults: a route that names types refuses the ones it does not
	// name, because a list of what is carried that also carries everything
	// else is not a list. A route that names none allows them, because
	// that is every configuration written before this existed.
	cfg, err := ParseWith([]byte(wsRouteConfig("      types: [{name: a}]\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.Routes[0].WebSocketGuard
	if g.UnknownTypes != "deny" || g.TypeField != "type" || g.Compression != "strip" || g.MaxInflateRatio != 100 {
		t.Errorf("defaults: unknown_types %q, type_field %q, compression %q, ratio %d",
			g.UnknownTypes, g.TypeField, g.Compression, g.MaxInflateRatio)
	}
	cfg, err = ParseWith([]byte(wsRouteConfig("      max_frame_bytes: 4096\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Routes[0].WebSocketGuard.UnknownTypes; got != "allow" {
		t.Errorf("unknown_types on a route with no types = %q, want allow", got)
	}

	// A schema that could not be checked against the largest message the
	// type allows is advice rather than an error: it is the operator's
	// choice, and it is not silent.
	cfg, err = ParseWith([]byte(wsRouteConfig("      max_inspect_bytes: 1024\n"+
		"      types: [{name: a, max_bytes: 4096, schema_file: "+schema+"}]\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "cannot be validated against the schema") {
		t.Errorf("no advice about a schema that cannot always apply: %v", cfg.Advice())
	}
}
