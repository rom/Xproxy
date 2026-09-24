package http

import (
	"fmt"
	"net/http"
	"testing"
)

// docs/CONFIG.md says an API version needs no key of its own, because
// every way a version is actually spelled is already a matcher, and it
// shows four of them. This drives that configuration: a documented
// pattern nobody ran is a pattern that works until somebody tries it.
func TestAVersionIsRoutedByTheMatchersThatExist(t *testing.T) {
	v1 := newBackend(t, "v1")
	v2 := newBackend(t, "v2")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: orders-v1, endpoints: [{address: %s}]}
  - {name: orders-v2, endpoints: [{address: %s}]}
routes:
  - {name: api-v1, hosts: [api.test], paths: ["/v1/"], upstream: orders-v1}
  - {name: api-v2, hosts: [api.test], paths: ["/v2/"], upstream: orders-v2}
  - name: api-accept-v2
    hosts: [api.test]
    paths: ["/orders/"]
    headers: [{name: Accept, regex: ".*vnd\\.example\\.v2(\\+json)?"}]
    upstream: orders-v2
  - name: api-header-v2
    hosts: [api.test]
    paths: ["/orders/"]
    headers: [{name: X-API-Version, exact: "2"}]
    upstream: orders-v2
  - name: api-pinned
    hosts: [api.test]
    paths: ["/orders/"]
    when: 'query("api-version") == "2024-11-01" || client_ip in cidr("10.9.0.0/16")'
    upstream: orders-v2
  - {name: api-default, hosts: [api.test], paths: ["/orders/"], upstream: orders-v1}
`, v1.addr(), v2.addr())
	_, url := startServer(t, yaml)
	which := func(path string, hdr ...string) string {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, url+path, nil)
		r.Host = "api.test"
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s answered %d", path, resp.StatusCode)
		}
		return resp.Header.Get("X-Backend")
	}
	for _, tc := range []struct {
		name, path, want string
		hdr              []string
	}{
		{"in the path", "/v1/orders", "v1", nil},
		{"in the path, v2", "/v2/orders", "v2", nil},
		{"in the media type", "/orders/1", "v2", []string{"Accept", "application/vnd.example.v2+json"}},
		{"another media type falls to the default", "/orders/1", "v1", []string{"Accept", "application/json"}},
		{"in a header", "/orders/1", "v2", []string{"X-API-Version", "2"}},
		{"the header's other value falls to the default", "/orders/1", "v1", []string{"X-API-Version", "1"}},
		{"in a query parameter, by expression", "/orders/1?api-version=2024-11-01", "v2", nil},
		{"no version at all", "/orders/1", "v1", nil},
	} {
		if got := which(tc.path, tc.hdr...); got != tc.want {
			t.Errorf("%s: reached %s, want %s", tc.name, got, tc.want)
		}
	}
}
