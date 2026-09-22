package http

import (
	"net/http/httptest"
	"testing"
)

// A honeypot marks and bans the client that went looking. A browser that
// fetched the decoy because another origin told it to did not go looking:
// an <img src="https://victim.example/.env"> in a forum post, a prefetch
// or a planted link would otherwise mark and ban every reader across the
// cluster. A scanner sends no fetch metadata at all and must still count.
func TestThirdPartyInducedRequests(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		induced bool
	}{
		{"scanner sends no metadata", nil, false},
		{"typed url", map[string]string{"Sec-Fetch-Site": "none"}, false},
		{"same origin fetch", map[string]string{"Sec-Fetch-Site": "same-origin"}, false},
		{"sub-resource of another site", map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
		{"another host of the same site", map[string]string{"Sec-Fetch-Site": "Same-Site"}, true},
		{"prefetch", map[string]string{"Sec-Purpose": "prefetch;anonymous-client-ip"}, true},
		{"legacy prefetch", map[string]string{"Purpose": "Prefetch"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://victim.test/.env", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := thirdPartyInduced(r); got != tc.induced {
				t.Fatalf("induced = %v, want %v", got, tc.induced)
			}
		})
	}
}
