package jwt

import "testing"

// TestCheckAuthorizedParty pins OpenID Connect Core 3.1.3.7 steps 4 and 5:
// a multi-audience ID token must carry azp, and azp must be this client.
func TestCheckAuthorizedParty(t *testing.T) {
	cases := []struct {
		claims Claims
		ok     bool
	}{
		{Claims{"aud": "app"}, true},
		{Claims{"aud": []any{"app"}}, true},
		{Claims{"aud": "app", "azp": "app"}, true},
		{Claims{"aud": []any{"app", "other"}, "azp": "app"}, true},
		{Claims{"aud": []any{"app", "other"}}, false},
		{Claims{"aud": "app", "azp": "other"}, false},
		{Claims{"aud": []any{"app", "other"}, "azp": "other"}, false},
	}
	for i, c := range cases {
		if err := CheckAuthorizedParty(c.claims, "app"); (err == nil) != c.ok {
			t.Errorf("case %d: err=%v want ok=%v", i, err, c.ok)
		}
	}
}
