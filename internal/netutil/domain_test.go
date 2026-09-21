package netutil

import "testing"

// TestRegistrable pins the grouping key. DNS tunnel detection counts a
// client's queries under the name somebody registered, so an answer
// that is one label too high lumps unrelated services together and one
// label too low splits a tunnel's traffic into names that never add up.
func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		// The ordinary case, at every depth.
		"example.com":                 "example.com",
		"www.example.com":             "example.com",
		"a.b.c.d.example.com":         "example.com",
		"mfzwizlt.tunnel.example.com": "example.com",
		// A registry suffix takes one more label, or every name under
		// it would be grouped as one.
		"bbc.co.uk":          "bbc.co.uk",
		"www.bbc.co.uk":      "bbc.co.uk",
		"a.b.c.bbc.co.uk":    "bbc.co.uk",
		"co.uk":              "co.uk",
		"shop.example.com":   "example.com",
		"site.github.io":     "site.github.io",
		"x.y.site.github.io": "site.github.io",
		// Case and the trailing dot are noise in a key.
		"WWW.Example.COM.": "example.com",
		// Nothing to group.
		"localhost": "localhost",
		"":          "",
	}
	for in, want := range cases {
		if got := Registrable(in); got != want {
			t.Errorf("Registrable(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRegistrableGroupsATunnel: the point of the whole function.
func TestRegistrableGroupsATunnel(t *testing.T) {
	names := []string{
		"mfzwizltoq2gk3tf.evil.test",
		"or4hi7dbnzsw4y3p.evil.test",
		"nu2gk3tfmfzwizlt.sub.evil.test",
	}
	for _, n := range names {
		if got := Registrable(n); got != "evil.test" {
			t.Fatalf("Registrable(%q) = %q, so a tunnel's queries would not be counted together", n, got)
		}
	}
	// And an unrelated name is not swept in with them.
	if Registrable("www.good.test") == "evil.test" {
		t.Fatal("unrelated names group together")
	}
}
