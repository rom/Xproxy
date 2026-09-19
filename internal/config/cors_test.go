package config

import (
	"strings"
	"testing"
)

func corsCfg(cors string) string {
	return `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - {name: web, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: api, upstream: web, cors: ` + cors + `}
`
}

func TestCORSValidation(t *testing.T) {
	// A valid policy parses and gets its defaults.
	cfg, err := ParseWith([]byte(corsCfg(`{allow_origins: ["https://a.example"]}`)), false)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Routes[0].CORS
	if len(c.AllowMethods) != 6 || c.MaxAge.D().Minutes() != 10 {
		t.Fatalf("defaults: %+v", c)
	}
	bad := map[string]string{
		"no origins":        `{allow_methods: [GET]}`,
		"bad origin":        `{allow_origins: ["app.example"]}`,
		"star with creds":   `{allow_origins: ["*"], allow_credentials: true}`,
		"star with others":  `{allow_origins: ["*", "https://a.example"]}`,
		"lowercase method":  `{allow_origins: ["https://a.example"], allow_methods: [get]}`,
		"bad header":        `{allow_origins: ["https://a.example"], allow_headers: ["a b"]}`,
		"bad expose header": `{allow_origins: ["https://a.example"], expose_headers: ["a b"]}`,
		"max age too long":  `{allow_origins: ["https://a.example"], max_age: 48h}`,
	}
	for name, cors := range bad {
		if _, err := ParseWith([]byte(corsCfg(cors)), false); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "cors") {
			t.Errorf("%s: error not about cors: %v", name, err)
		}
	}
}

func TestRouteTimeoutsValidation(t *testing.T) {
	base := func(rt string) string {
		return `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - {name: web, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: api, upstream: web, ` + rt + `}
`
	}
	if _, err := ParseWith([]byte(base(`timeouts: {total: 5s, idle: 1s}`)), false); err != nil {
		t.Fatal(err)
	}
	for name, rt := range map[string]string{
		"both timeout and timeouts": `timeout: 5s, timeouts: {total: 5s}`,
		"idle over total":           `timeouts: {total: 1s, idle: 2s}`,
	} {
		if _, err := ParseWith([]byte(base(rt)), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
