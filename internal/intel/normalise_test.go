package intel

import (
	"strings"
	"testing"
)

// Normalisation, which is where a list either covers what an operator thought
// they listed or quietly does not.
//
// A feed writes a name in every shape there is and a request arrives in
// another, so every refusal and every rewrite below is the difference between
// an indicator that matches and one that sits in the file doing nothing. The
// refusals matter as much: a key this package cannot make sense of has to be
// refused at load, where somebody reads the error, rather than stored as a
// string nothing will ever equal.

func TestANameIsNormalisedTheWayEveryFeedWritesIt(t *testing.T) {
	for _, tc := range []struct {
		in, want, wantErr string
	}{
		{in: "example.com", want: "example.com"},
		{in: "  EXAMPLE.COM.  ", want: "example.com"},
		// A leading dot is how a feed says "and subdomains"; the name is the
		// same name, and the walk below is what covers the subdomains.
		{in: ".example.com", want: "example.com"},
		// Written as a URL, with userinfo and a port, which is how half of
		// the public lists write a host.
		{in: "http://bob@example.com:8080/wp-login.php", want: "example.com"},
		{in: "", wantErr: "empty"},
		{in: strings.Repeat("a", maxName+1), wantErr: "longer than"},
		{in: "example..com", wantErr: "an empty label"},
	} {
		got, err := domainKey(tc.in)
		if tc.wantErr != "" {
			if err == nil {
				t.Errorf("%q became %q, want a refusal saying %q", tc.in, got, tc.wantErr)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q was refused with %v, want it to say %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q became %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAURLIsNormalisedToWhatItNames(t *testing.T) {
	for _, tc := range []struct {
		in, want, wantErr string
	}{
		// The scheme goes: the same payload is served over https the next
		// day, and the fragment never reaches a server at all.
		{in: "https://example.com/dl/x.bin#top", want: "example.com/dl/x.bin"},
		{in: "example.com/dl/x.bin", want: "example.com/dl/x.bin"},
		// Userinfo and a port are not part of what is named.
		{in: "http://bob@example.com:8080/a", want: "example.com/a"},
		// A bare query, as some feeds write it: the path is implied.
		{in: "example.com?id=1", want: "example.com/?id=1"},
		{in: "", wantErr: "empty"},
		{in: "https://" + strings.Repeat("a", maxURL), wantErr: "longer than"},
		{in: "https://:8080/a", wantErr: "no host"},
	} {
		got, err := urlKey(tc.in)
		if tc.wantErr != "" {
			if err == nil {
				t.Errorf("%q became %q, want a refusal saying %q", tc.in, got, tc.wantErr)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q was refused with %v, want it to say %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q became %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A port is not part of an indicator, and an IPv6 literal is not a port: the
// colons in one are what makes this its own function rather than a Split.
func TestAPortIsTakenOffAHostAndAnAddressIsNot(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		wantOK   bool
	}{
		{in: "example.com:8080", want: "example.com", wantOK: true},
		{in: "example.com", want: "example.com"},
		// A trailing colon with nothing after it names no port.
		{in: "example.com:", want: "example.com:"},
		// Not digits: a scheme-like suffix is not a port either.
		{in: "example.com:http", want: "example.com:http"},
		{in: "[2001:db8::1]:443", want: "[2001:db8::1]", wantOK: true},
		{in: "[2001:db8::1]", want: "[2001:db8::1]"},
		// Unbracketed, so there is nothing to tell a port from the address:
		// the whole thing is taken, and the caller refuses it for having no
		// dot rather than listing "2001:db8:".
		{in: "2001:db8::1", want: "2001:db8::1"},
	} {
		got, ok := trimPort(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("%q became %q %v, want %q %v", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

// The walk a lookup makes: a name is offered to the list from the registrable
// name outwards, and a URL at its path boundaries. What is bounded here is
// how much work one request can be made to do.
func TestTheWalkOffersWhatAListCouldPlausiblyName(t *testing.T) {
	seen := func(name string, depth int) []string {
		var out []string
		domainCandidates(name, depth, func(c string) bool {
			out = append(out, c)
			return false
		})
		return out
	}
	if got := seen("a.b.example.com", 3); strings.Join(got, " ") != "example.com b.example.com" {
		t.Errorf("the walk offered %v", got)
	}
	// Asked for more depth than anything may be listed at, the walk stops at
	// the bound rather than at the name: a request is not made to do work an
	// operator cannot have asked for.
	if got := seen("a.b.example.com", maxLabels+1000); len(got) != 3 {
		t.Errorf("an unbounded depth offered %v", got)
	}
	// Nothing can be listed for one label, for an empty name, or at a depth
	// below the two labels a name needs.
	for _, tc := range []struct {
		name  string
		depth int
	}{{"localhost", 4}, {"", 4}, {"a.b.example.com", 1}, {strings.Repeat("a", maxName+1), 4}} {
		if got := seen(tc.name, tc.depth); len(got) != 0 {
			t.Errorf("%q at depth %d offered %v", tc.name, tc.depth, got)
		}
	}

	urls := func(raw string, segs int) []string {
		var out []string
		urlCandidates(raw, segs, func(c string) bool {
			out = append(out, c)
			return false
		})
		return out
	}
	// The exact key first, then the site, then the path a segment at a time:
	// an entry for /dl must not match /download, so the walk stops at
	// boundaries.
	got := urls("https://example.com/dl/pkg/x.bin", 8)
	want := "example.com/dl/pkg/x.bin example.com/ example.com/dl example.com/dl/pkg example.com/dl/pkg/x.bin"
	if strings.Join(got, " ") != want {
		t.Errorf("the walk offered %v", got)
	}
	// A query is part of an exact entry a feed may have listed, and no part
	// of the boundary walk: /dl?x=1 must not escape an entry for /dl.
	got = urls("example.com/dl?x=1", 8)
	if strings.Join(got, " ") != "example.com/dl?x=1 example.com/ example.com/dl" {
		t.Errorf("a query walked as %v", got)
	}
	// A host with no path at all has nowhere to walk to: the exact key is
	// already the site, and each candidate is offered once.
	if got := urls("example.com", 8); strings.Join(got, " ") != "example.com/" {
		t.Errorf("a bare host walked as %v", got)
	}
	// And the segment count is bounded the same way the depth is.
	if got := urls("example.com/a/b/c", maxSegments+1000); len(got) != 5 {
		t.Errorf("an unbounded segment count offered %v", got)
	}
	// Something that is not a URL at all offers nothing.
	if got := urls("", 8); len(got) != 0 {
		t.Errorf("an empty URL offered %v", got)
	}
}
