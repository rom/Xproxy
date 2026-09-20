package config

import "testing"

// TestRedirectTargetFixed: request data may fill the path or query of a
// redirect, never choose its host.
func TestRedirectTargetFixed(t *testing.T) {
	ok := []string{
		"/",
		"/new",
		"/new${path}",
		"/x?next=${query:next}",
		"https://example.com/",
		"https://example.com${path}",
		"https://example.com:8443/a${raw_query}",
		"https://www.example.com/blog${path}?${raw_query}",
		"https://${host}/new",
		"https://${host}${path}",
		"${scheme}://example.com/x",
		"http://[2001:db8::1]:8080/",
	}
	for _, to := range ok {
		if !redirectTargetFixed(to) {
			t.Errorf("%q refused", to)
		}
	}
	bad := []string{
		"${query:next}",
		"/${query:next}",
		"//${header:X-Host}/",
		"/\\${path}",
		"https://${header:Host}/",
		"https://example.com${query:x}",
		"https://example.com@${host}/",
		"https://${path}",
	}
	for _, to := range bad {
		if redirectTargetFixed(to) {
			t.Errorf("%q accepted", to)
		}
	}
}
