package router

import (
	"net/http"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

type testEnv map[string]string

func (e testEnv) Resolve(name, arg string) (string, bool) {
	key := name
	if arg != "" {
		key += ":" + arg
	}
	v, ok := e[key]
	return v, ok
}

func TestWhen(t *testing.T) {
	r := New([]config.Route{
		{Name: "plain", Paths: []string{"/"}, Upstream: "a"},
		{Name: "beta", Paths: []string{"/"}, When: `header("X-Env") == "beta" && client_ip in cidr("10.0.0.0/8")`, Upstream: "b"},
		{Name: "both", Paths: []string{"/"}, Headers: []config.HeaderMatch{{Name: "X-Env", Exact: "beta"}}, When: `method == "POST"`, Upstream: "c"},
		{Name: "api", Paths: []string{"/api"}, When: `scheme == "http"`, Upstream: "d"},
	})
	hdr := http.Header{"X-Env": {"beta"}}
	cases := []struct {
		path, method string
		env          testEnv
		want         string
	}{
		{"/", "GET", testEnv{"client_ip": "10.1.1.1", "header:X-Env": "beta"}, "beta"},
		{"/", "POST", testEnv{"client_ip": "10.1.1.1", "header:X-Env": "beta", "method": "POST"}, "both"}, // two conditions beat one
		{"/", "GET", testEnv{"client_ip": "192.168.1.1", "header:X-Env": "beta"}, "plain"},
		{"/", "GET", nil, "plain"},                             // nil env fails every expression
		{"/api/x", "GET", testEnv{"scheme": "https"}, "plain"}, // longer path but false condition falls through
		{"/api/x", "GET", testEnv{"scheme": "http"}, "api"},
	}
	for _, c := range cases {
		var env any = c.env
		got := ""
		if c.env == nil {
			if m := r.MatchRequest("h", c.path, c.method, false, hdr, nil); m != nil {
				got = m.Cfg.Name
			}
		} else if m := r.MatchRequest("h", c.path, c.method, false, hdr, c.env); m != nil {
			got = m.Cfg.Name
		}
		_ = env
		if got != c.want {
			t.Errorf("%s %s %v: got %q want %q", c.method, c.path, c.env, got, c.want)
		}
	}
}
