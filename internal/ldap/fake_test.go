package ldap_test

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/ldap/ldaptest"
)

// TestFilterShapesAgainstTheFakeDirectory drives every filter form the
// parser produces through a real connection, so the client, the
// encoder, the decoder and a server's evaluation of the same packet are
// checked against each other rather than one side alone.
func TestFilterShapesAgainstTheFakeDirectory(t *testing.T) {
	long := strings.Repeat("d", 300) // a value that needs a long-form length
	users := []ldaptest.User{
		{DN: "uid=alice,dc=example,dc=com", Password: "s3cret",
			Attrs: map[string][]string{"uid": {"alice"}, "mail": {"alice@example.com"}, "memberOf": {"cn=staff"}, "note": {long}}},
		{DN: "uid=bob,dc=example,dc=com", Password: "hunter2",
			Attrs: map[string][]string{"uid": {"bob"}, "mail": {"bob@example.com"}}},
		{DN: "uid=carol,dc=example,dc=com", Password: "pw",
			Attrs: map[string][]string{"uid": {"carol"}}},
	}
	s := ldaptest.Start(t, users)
	conn, err := ldap.Dial(ldap.Options{URL: s.URL()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	cases := []struct {
		filter string
		want   []string
	}{
		{"(uid=alice)", []string{"alice"}},
		{"(uid=ALICE)", []string{"alice"}}, // the directory matches case insensitively
		{"(|(uid=alice)(uid=bob))", []string{"alice", "bob"}},
		{"(&(uid=alice)(mail=alice@example.com))", []string{"alice"}},
		{"(&(uid=alice)(mail=bob@example.com))", nil},
		{"(!(uid=alice))", []string{"bob", "carol"}},
		{"(&(!(uid=alice))(mail=bob@example.com))", []string{"bob"}},
		{"(mail=*)", []string{"alice", "bob"}},
		{"(memberOf=*)", []string{"alice"}},
		{"(note=" + long + ")", []string{"alice"}},
		{"(uid=nobody)", nil},
		{"(uid=" + ldap.EscapeFilter("*") + ")", nil}, // an escaped star matches nothing, not everything
		{"(|(uid=alice)(|(uid=bob)(uid=carol)))", []string{"alice", "bob", "carol"}},
	}
	for _, tc := range cases {
		f, err := ldap.ParseFilter(tc.filter)
		if err != nil {
			t.Errorf("%s: %v", tc.filter, err)
			continue
		}
		entries, err := conn.Search("dc=example,dc=com", ldap.ScopeSub, f, nil, 0)
		if err != nil {
			t.Errorf("%s: %v", tc.filter, err)
			continue
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Attrs["uid"]...)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s matched %v, want %v", tc.filter, got, tc.want)
		}
	}
	// A long attribute value survives the round trip byte for byte.
	f, err := ldap.ParseFilter("(uid=alice)")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := conn.Search("dc=example,dc=com", ldap.ScopeSub, f, []string{"note"}, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("search: %v %d", err, len(entries))
	}
	if got := entries[0].Attrs["note"]; len(got) != 1 || got[0] != long {
		t.Fatalf("a %d byte value came back as %d bytes", len(long), len(got))
	}
	// The connection is reusable across all of that.
	if err := conn.Bind("uid=alice,dc=example,dc=com", "s3cret"); err != nil {
		t.Fatalf("bind after the searches: %v", err)
	}
}
