package intel

import (
	"path/filepath"
	"strings"
	"testing"
)

// set builds a one-list set of a kind from a body, without a file check.
func oneList(t *testing.T, kind, body string) *Set {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	write(t, filepath.Dir(path), filepath.Base(path), body)
	s, err := New([]Spec{{Name: "feed", Kind: kind, Action: ActionBlock, File: path}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A domain entry covers the name and every name under it, because a feed that
// lists a campaign's domain means the campaign: the payload is on
// cdn.<domain> the next day.
func TestADomainEntryCoversTheNamesUnderIt(t *testing.T) {
	s := oneList(t, KindDomain, `# a feed writes a name in every shape there is
evil.example
.dots.example
TRAILING.example.
http://as-a-url.example/some/path
with-port.example:8443
`)
	for _, name := range []string{
		"evil.example", "EVIL.example", "evil.example.",
		"cdn.evil.example", "a.b.c.evil.example",
		"dots.example", "x.dots.example",
		"trailing.example", "x.trailing.example",
		"as-a-url.example", "with-port.example",
	} {
		if _, ok := s.Match(Subject{Domain: name}); !ok {
			t.Errorf("%q did not match", name)
		}
	}
	for _, name := range []string{
		// Not a subdomain: a name that merely ends in the same letters.
		"notevil.example", "xevil.example",
		// The parent is not listed, only the child.
		"example", "example.com",
		// A sibling.
		"good.example",
		// Nothing offered at all.
		"",
	} {
		if _, ok := s.Match(Subject{Domain: name}); ok {
			t.Errorf("%q matched and should not have", name)
		}
	}
}

// A single-label entry would match every name under it, which for "com" is
// every name there is. It is refused at load, where an operator sees it, rather
// than at three in the morning.
func TestASingleLabelEntryIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	write(t, filepath.Dir(path), filepath.Base(path), "com\n")
	_, err := New([]Spec{{Name: "feed", Kind: KindDomain, File: path}})
	if err == nil {
		t.Fatal("a single-label domain entry was accepted")
	}
	if !strings.Contains(err.Error(), "every name under it") {
		t.Errorf("error %q does not say why", err)
	}
	// And the same rule applies through a url entry, so a url feed cannot
	// smuggle in the match a domain feed refuses.
	path2 := filepath.Join(t.TempDir(), "urls.txt")
	write(t, filepath.Dir(path2), filepath.Base(path2), "http://com/whatever\n")
	if _, err := New([]Spec{{Name: "u", Kind: KindURL, File: path2}}); err == nil {
		t.Error("a single-label host in a url entry was accepted")
	}
}

// A URL entry matches at a path boundary, which is the difference between
// naming a resource and naming every resource whose name starts the same way.
func TestAURLEntryMatchesAtAPathBoundary(t *testing.T) {
	s := oneList(t, KindURL, `http://evil.example/dl
https://other.example/a/b/c
bare.example
trailing.example/p/
with-query.example/x?id=1
`)
	for _, u := range []string{
		// The entry itself, and under it.
		"evil.example/dl", "evil.example/dl/", "evil.example/dl/payload.bin",
		"evil.example/dl/deep/er",
		// The scheme is not part of the key: the same payload over https the
		// next day is the same indicator.
		"https://evil.example/dl/x", "http://evil.example/dl",
		// Case in the host but not in the path.
		"EVIL.example/dl",
		// A deeper entry matches its own resource.
		"other.example/a/b/c", "other.example/a/b/c/d",
		// A host with no path listed covers the site.
		"bare.example/", "bare.example/anything/at/all",
		// A trailing slash in the entry carries no information.
		"trailing.example/p", "trailing.example/p/q",
		"with-query.example/x?id=1",
		// A query cannot be used to escape an entry: the boundary walk is
		// over the path, so /dl?x=1 is still /dl.
		"evil.example/dl?x=1", "evil.example/dl/payload.bin?a=b",
	} {
		if _, ok := s.Match(Subject{URL: u}); !ok {
			t.Errorf("%q did not match", u)
		}
	}
	for _, u := range []string{
		// The boundary: a different resource whose name starts the same way.
		// On a shared host this is somebody else's.
		"evil.example/download", "evil.example/dlx", "evil.example/dl-old",
		"evil.example/download?x=1",
		// An entry that names a query names that query: another one is
		// another request, and the path alone is not the entry either.
		"with-query.example/x?id=2", "with-query.example/x",
		// A parent of the entry is not the entry.
		"evil.example/", "other.example/a", "other.example/a/b",
		// A different host.
		"good.example/dl",
		// A subdomain is NOT covered by a url entry: the entry names a
		// resource, and a resource on another host is another resource. The
		// domain kind is what covers names.
		"cdn.evil.example/dl",
		"",
	} {
		if _, ok := s.Match(Subject{URL: u}); ok {
			t.Errorf("%q matched and should not have", u)
		}
	}
}

// A digest is recognised by its length, and normalised the same way on the way
// in and on the way out, so a caller handing over an upper-case digest still
// matches an entry a feed wrote in lower case.
func TestAHashEntryMatchesAnyOfTheThreeDigests(t *testing.T) {
	const (
		md5sum  = "d41d8cd98f00b204e9800998ecf8427e"
		sha1sum = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
		sha256s = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)
	s := oneList(t, KindHash, "# a feed writes a digest with and without its name\n"+
		md5sum+"\n"+
		"sha1:"+sha1sum+"\n"+
		"SHA256 "+strings.ToUpper(sha256s)+"\n")

	for _, h := range []string{md5sum, strings.ToUpper(md5sum), sha1sum, sha256s} {
		if _, ok := s.Match(Subject{Hashes: []string{h}}); !ok {
			t.Errorf("%q did not match", h)
		}
	}
	// A subject offering several digests of one payload matches on any of
	// them, which is the point: a feed lists whichever it had.
	if _, ok := s.Match(Subject{Hashes: []string{"0" + sha256s[1:], md5sum}}); !ok {
		t.Error("a payload whose md5 is listed did not match when its sha256 is not")
	}
	for _, h := range []string{"", "notahash", "0" + sha256s[1:], sha1sum[:39]} {
		if _, ok := s.Match(Subject{Hashes: []string{h}}); ok {
			t.Errorf("%q matched and should not have", h)
		}
	}
}

// A digest of a length nothing produces can never match, so it is refused at
// load rather than stored: an entry that cannot match is an entry an operator
// believes is protecting them.
func TestAHashOfTheWrongLengthIsRefused(t *testing.T) {
	for _, body := range []string{
		"abc\n",
		"d41d8cd98f00b204e9800998ecf8427\n",  // 31
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n", // right length, not hex
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855a\n", // 65
	} {
		path := filepath.Join(t.TempDir(), "h.txt")
		write(t, filepath.Dir(path), filepath.Base(path), body)
		if _, err := New([]Spec{{Name: "h", Kind: KindHash, File: path}}); err == nil {
			t.Errorf("%q was accepted", strings.TrimSpace(body))
		}
	}
}

// A list of one kind is never matched against a subject of another. The lists
// are ordered and the first match decides, so a cidr list that answered a
// domain question would decide a request it knows nothing about.
func TestAListOnlyAnswersItsOwnKind(t *testing.T) {
	dir := t.TempDir()
	nets := write(t, dir, "nets.txt", "10.0.0.0/8\n")
	names := write(t, dir, "names.txt", "evil.example\n")
	hashes := write(t, dir, "h.txt", "d41d8cd98f00b204e9800998ecf8427e\n")
	s, err := New([]Spec{
		{Name: "nets", Kind: KindCIDR, Action: ActionBlock, File: nets},
		{Name: "names", Kind: KindDomain, Action: ActionChallenge, File: names},
		{Name: "hashes", Kind: KindHash, Action: ActionLog, File: hashes},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A name matches the name list and not the address one, and the hit says
	// which list decided -- which is what an operator acts on.
	hit, ok := s.Match(Subject{Domain: "cdn.evil.example"})
	if !ok || hit.List != "names" || hit.Kind != KindDomain || hit.Action != ActionChallenge {
		t.Errorf("a name matched %+v", hit)
	}
	hit, ok = s.Match(Subject{Hashes: []string{"D41D8CD98F00B204E9800998ECF8427E"}})
	if !ok || hit.List != "hashes" {
		t.Errorf("a digest matched %+v", hit)
	}
	// And a subject with nothing the lists can answer matches nothing, rather
	// than the first list in the file.
	if hit, ok := s.Match(Subject{}); ok {
		t.Errorf("an empty subject matched %+v", hit)
	}
}

// The walks cannot be evaded by the client, and cost what the *feed* is deep
// rather than what the request is.
//
// This is the bypass the direction of the walk decides. Walking from the
// request's own name or path downwards has to stop somewhere, and the client
// chooses how many labels or segments it sends: pad past the bound and the walk
// never reaches the entry. Every case below is a client trying exactly that.
func TestTheWalksCannotBeEvadedByPadding(t *testing.T) {
	d := oneList(t, KindDomain, "evil.example\n")
	for _, name := range []string{
		"cdn.evil.example",
		// A hundred labels in front of the listed name, which fits inside the
		// 255-byte name bound and is therefore a name a Host header can carry.
		strings.Repeat("a.", 100) + "evil.example",
		strings.Repeat("pad.", 40) + "evil.example",
	} {
		if _, ok := d.Match(Subject{Domain: name}); !ok {
			t.Errorf("a name padded to %d labels escaped the list", strings.Count(name, ".")+1)
		}
	}
	// Past the *name* bound nothing matches, which is a refusal to look rather
	// than a failure to find: a name longer than any name can be is not a name.
	if _, ok := d.Match(Subject{Domain: strings.Repeat("a.", 200) + "evil.example"}); ok {
		t.Error("a name longer than the DNS limit was walked at all")
	}

	u := oneList(t, KindURL, "evil.example/dl\n")
	for _, raw := range []string{
		"evil.example/dl",
		"evil.example/dl/x",
		// Segments appended past any fixed bound.
		"evil.example/dl" + strings.Repeat("/x", 100),
		"evil.example/dl/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z",
	} {
		if _, ok := u.Match(Subject{URL: raw}); !ok {
			t.Errorf("a path padded with %d segments escaped the list", strings.Count(raw, "/"))
		}
	}
	// And the boundary still holds under padding: a different resource whose
	// name merely starts the same way is still not the listed one.
	for _, raw := range []string{
		"evil.example/download" + strings.Repeat("/x", 100),
		"evil.example/dlx/a/b",
	} {
		if _, ok := u.Match(Subject{URL: raw}); ok {
			t.Errorf("%q matched; the boundary was lost under padding", raw)
		}
	}
}

// The cost of a match is bounded by the feed, so an entry deep enough to make
// every request expensive is refused at load rather than paid for per request.
func TestAnEntryTooDeepToWalkIsRefused(t *testing.T) {
	deep := strings.Repeat("a.", 100) + "example"
	path := filepath.Join(t.TempDir(), "d.txt")
	write(t, filepath.Dir(path), filepath.Base(path), deep+"\n")
	_, err := New([]Spec{{Name: "d", Kind: KindDomain, File: path}})
	if err == nil {
		t.Fatal("a 101-label entry was accepted")
	}
	if !strings.Contains(err.Error(), "walk that many candidates") {
		t.Errorf("error %q does not say why", err)
	}

	deepURL := "evil.example" + strings.Repeat("/x", 100)
	upath := filepath.Join(t.TempDir(), "u.txt")
	write(t, filepath.Dir(upath), filepath.Base(upath), deepURL+"\n")
	if _, err := New([]Spec{{Name: "u", Kind: KindURL, File: upath}}); err == nil {
		t.Error("a 100-segment url entry was accepted")
	}
}

// A shallow feed costs a shallow walk. Asserted through the bound rather than
// by timing: a list of two-label names has depth 2, so a request with a hundred
// labels performs two lookups and not a hundred.
func TestTheWalkIsAsDeepAsTheFeed(t *testing.T) {
	s := oneList(t, KindDomain, "evil.example\nalso.bad.example\n")
	s.mu.RLock()
	depth := s.lists[0].depth
	s.mu.RUnlock()
	if depth != 3 {
		t.Errorf("depth %d, want the deepest entry's 3 labels", depth)
	}
	// A name deeper than the feed is still matched at the depth the feed has.
	if _, ok := s.Match(Subject{Domain: strings.Repeat("x.", 50) + "also.bad.example"}); !ok {
		t.Error("a deep name did not match the three-label entry")
	}
	// And a name that would only match at a depth the feed does not reach is
	// not matched, because there is nothing there to match.
	if _, ok := s.Match(Subject{Domain: "bad.example"}); ok {
		t.Error("a two-label suffix of a three-label entry matched")
	}
}
