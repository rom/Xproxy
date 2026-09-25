package ldap

import "testing"

// Distinguished names, and the comparison a subtree policy is.
//
// The case that matters most is the last one: a value with an escaped comma in
// it produces a *string* that ends with the suffix and a *name* that is not
// under it. A policy compared as text admits it, which is why this comparison
// is per relative name.

func TestANameIsSplitIntoItsRelativeNames(t *testing.T) {
	dn, err := ParseDN("CN=Alice Smith, OU=People ,DC=Example,DC=com")
	if err != nil {
		t.Fatal(err)
	}
	if dn.Depth() != 4 {
		t.Fatalf("depth %d: %v", dn.Depth(), dn)
	}
	// The type is folded, the value is folded, and the insignificant space
	// around each is gone -- so two spellings of one name are one name.
	if got := dn.String(); got != "cn=alice smith,ou=people,dc=example,dc=com" {
		t.Errorf("normalised to %q", got)
	}
	other, err := ParseDN("cn=ALICE SMITH,ou=PEOPLE,dc=EXAMPLE,dc=COM")
	if err != nil {
		t.Fatal(err)
	}
	if !dn.Equal(other) {
		t.Error("two spellings of one name are not equal")
	}
	// The empty name is the root DSE, which is a real name and is above
	// everything.
	root, err := ParseDN("")
	if err != nil {
		t.Fatal(err)
	}
	if root.Depth() != 0 || !dn.Under(root) {
		t.Errorf("the root DSE: depth %d, covers %v", root.Depth(), dn.Under(root))
	}
}

func TestAMultiValuedRelativeNameIsOrderIndependent(t *testing.T) {
	a, err := ParseDN("cn=alice+ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseDN("ou=people+cn=alice,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Error("one relative name written in two orders is not equal to itself")
	}
	if a.Depth() != 3 {
		t.Errorf("depth %d", a.Depth())
	}
}

func TestTheEscapingIsResolvedBeforeAnythingIsCompared(t *testing.T) {
	for what, pair := range map[string][2]string{
		"a backslash escape": {`cn=a\,b,dc=x`, `cn=a\,b,dc=x`},
		"a hex escape":       {`cn=a\2cb,dc=x`, `cn=a\,b,dc=x`},
		"the quoted form":    {`cn="a,b",dc=x`, `cn=a\,b,dc=x`},
	} {
		a, err := ParseDN(pair[0])
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		b, err := ParseDN(pair[1])
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if !a.Equal(b) {
			t.Errorf("%s: %q and %q are not the same name", what, a, b)
		}
		if a.Depth() != 2 {
			t.Errorf("%s: depth %d, so the comma inside the value split the name", what, a.Depth())
		}
	}
}

// The comparison a subtree policy is. Each of these is a name a string test
// gets wrong.
func TestASuffixIsComparedPerRelativeName(t *testing.T) {
	suffix, err := ParseDN("dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"dc=example,dc=com":                true,
		"ou=people,dc=example,dc=com":      true,
		"cn=a,ou=people,dc=example,dc=com": true,
		"dc=com":                           false,
		"dc=other,dc=com":                  false,
		// The trap a string *suffix* test falls into.
		"dc=notexample,dc=com": false,
		// And the one it does not, but a string *prefix* test does: this is
		// under a different subtree whose text starts the same way.
		"ou=peoplex,dc=other,dc=com": false,
		// The trap that matters most: an escaped comma in a value makes a
		// name whose *text* ends with the suffix and which is not under it.
		// A policy compared as text admits this; compared per relative name
		// it does not.
		`cn=a\,dc=example,dc=com`: false,
	} {
		dn, err := ParseDN(name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if got := dn.Under(suffix); got != want {
			t.Errorf("%q under %q: %v, wanted %v (normalised %q)", name, suffix, got, want, dn)
		}
	}
}

func TestTheNamesThatAreNotNames(t *testing.T) {
	for what, name := range map[string]string{
		"no equals sign":        "people",
		"an empty type":         "=value,dc=x",
		"a trailing escape":     `cn=a\`,
		"half a hex escape":     `cn=a\2`,
		"a bad hex escape":      `cn=a\zz`,
		"an unterminated quote": `cn="a,dc=x`,
		"a name past the bound": "cn=" + string(make([]byte, MaxDNLength)),
	} {
		if _, err := ParseDN(name); err == nil {
			t.Errorf("%s parsed as a name", what)
		}
	}
}

// An escaped space at the end of a value is significant, and an unescaped one
// is not. That is the whole reason the trimming here is escape-aware rather
// than a call to TrimSpace: `cn=a\ ` is a value that ends in a space on
// purpose, and a reader that trimmed before resolving the escaping would turn
// it into the value "a" -- silently, and into a *different* entry.
func TestAnEscapedTrailingSpaceIsSignificant(t *testing.T) {
	withSpace, err := ParseDN(`cn=a\ ,dc=example,dc=com`)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := ParseDN("cn=a,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	if withSpace.Equal(plain) {
		t.Error(`cn=a\  and cn=a are the same name, so the escaped space was dropped`)
	}
	if got := withSpace.Values()[0]; got != "a " {
		t.Errorf("the value is %q, wanted %q", got, "a ")
	}
	// An *unescaped* trailing space is insignificant, and the two names with
	// one are the same name.
	padded, err := ParseDN("cn=a   ,dc=example,dc=com")
	if err != nil {
		t.Fatal(err)
	}
	if !padded.Equal(plain) {
		t.Errorf("%q is not the same name as %q", padded, plain)
	}
	// And a leading one, which the grammar treats the same way.
	leading, err := ParseDN(`cn=\ a,dc=example,dc=com`)
	if err != nil {
		t.Fatal(err)
	}
	if leading.Equal(plain) {
		t.Error("an escaped leading space was dropped")
	}
}

// The string form is written back escaped, so a name that came in with a
// comma in a value goes out with one and is read the same way twice.
func TestANameSurvivesARoundTrip(t *testing.T) {
	for _, name := range []string{
		`cn=a\,b,dc=example,dc=com`,
		`cn=a\+b,dc=example,dc=com`,
		`cn=\#hash,dc=example,dc=com`,
		`cn=a\ ,dc=example,dc=com`,
		"cn=alice,ou=people,dc=example,dc=com",
	} {
		first, err := ParseDN(name)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		second, err := ParseDN(first.String())
		if err != nil {
			t.Fatalf("%q written back as %q: %v", name, first, err)
		}
		if !first.Equal(second) {
			t.Errorf("%q became %q and read back as %q", name, first, second)
		}
	}
}
