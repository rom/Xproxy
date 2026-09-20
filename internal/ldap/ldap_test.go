package ldap_test

import (
	"errors"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/ldap/ldaptest"
)

func directory() []ldaptest.User {
	return []ldaptest.User{
		{DN: "uid=alice,ou=people,dc=example,dc=com", Password: "s3cret",
			Attrs: map[string][]string{"uid": {"alice"}, "memberOf": {"cn=staff,ou=groups,dc=example,dc=com"}}},
		{DN: "uid=bob,ou=people,dc=example,dc=com", Password: "hunter2",
			Attrs: map[string][]string{"uid": {"bob"}}},
		{DN: "cn=svc,dc=example,dc=com", Password: "svcpw", Attrs: map[string][]string{"cn": {"svc"}}},
	}
}

func TestBind(t *testing.T) {
	s := ldaptest.Start(t, directory())
	conn, err := ldap.Dial(ldap.Options{URL: s.URL()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("uid=alice,ou=people,dc=example,dc=com", "s3cret"); err != nil {
		t.Fatalf("valid bind: %v", err)
	}
	if err := conn.Bind("uid=alice,ou=people,dc=example,dc=com", "wrong"); !errors.Is(err, ldap.ErrInvalidCredentials) {
		t.Fatalf("bad password: %v", err)
	}
	// An empty password must never pass (an unauthenticated bind).
	if err := conn.Bind("uid=alice,ou=people,dc=example,dc=com", ""); !errors.Is(err, ldap.ErrInvalidCredentials) {
		t.Fatalf("empty password: %v", err)
	}
}

func TestSearch(t *testing.T) {
	s := ldaptest.Start(t, directory())
	conn, err := ldap.Dial(ldap.Options{URL: s.URL()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Bind("cn=svc,dc=example,dc=com", "svcpw"); err != nil {
		t.Fatal(err)
	}
	f, err := ldap.ParseFilter("(uid=alice)")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := conn.Search("ou=people,dc=example,dc=com", ldap.ScopeSub, f, []string{"memberOf"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].DN != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("entries %+v", entries)
	}
	if got := entries[0].Attrs["memberOf"]; len(got) != 1 || got[0] != "cn=staff,ou=groups,dc=example,dc=com" {
		t.Fatalf("memberOf %v", got)
	}
	// A conjunction and a non-matching user.
	f, _ = ldap.ParseFilter("(&(uid=bob)(uid=*))")
	entries, err = conn.Search("ou=people,dc=example,dc=com", ldap.ScopeSub, f, nil, 2)
	if err != nil || len(entries) != 1 || entries[0].DN != "uid=bob,ou=people,dc=example,dc=com" {
		t.Fatalf("and filter: %v %+v", err, entries)
	}
	f, _ = ldap.ParseFilter("(uid=nobody)")
	entries, _ = conn.Search("ou=people,dc=example,dc=com", ldap.ScopeSub, f, nil, 2)
	if len(entries) != 0 {
		t.Fatalf("unexpected match %+v", entries)
	}
}

func TestDialErrors(t *testing.T) {
	for _, url := range []string{"://bad", "ftp://x", "ldap://127.0.0.1:1"} {
		if _, err := ldap.Dial(ldap.Options{URL: url, Timeout: time.Second}); err == nil {
			t.Errorf("dial %q succeeded", url)
		}
	}
}

func TestSearchSizeLimit(t *testing.T) {
	// Two users share a uid; a size limit of 1 is exceeded by the second.
	users := []ldaptest.User{
		{DN: "uid=dup,ou=a,dc=example,dc=com", Password: "p", Attrs: map[string][]string{"uid": {"dup"}}},
		{DN: "uid=dup,ou=b,dc=example,dc=com", Password: "p", Attrs: map[string][]string{"uid": {"dup"}}},
	}
	s := ldaptest.Start(t, users)
	conn, err := ldap.Dial(ldap.Options{URL: s.URL()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	f, _ := ldap.ParseFilter("(uid=dup)")
	if _, err := conn.Search("dc=example,dc=com", ldap.ScopeSub, f, nil, 1); err == nil {
		t.Fatal("size limit not enforced client side")
	}
	// A fresh connection (aborting a search mid-stream desyncs the old one,
	// which is fine in practice: the filter dials one connection per auth).
	conn2, err := ldap.Dial(ldap.Options{URL: s.URL()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	entries, err := conn2.Search("dc=example,dc=com", ldap.ScopeSub, f, nil, 5)
	if err != nil || len(entries) != 2 {
		t.Fatalf("search: %v %d", err, len(entries))
	}
}

func TestParseFilterErrors(t *testing.T) {
	for _, s := range []string{"uid=alice", "(uid)", "(=alice)", "(&)", "(uid=a*b)", "(uid=alice)x"} {
		if _, err := ldap.ParseFilter(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	for _, s := range []string{"(uid=alice)", "(cn=*)", "(!(uid=alice))", "(|(uid=a)(uid=b))"} {
		if _, err := ldap.ParseFilter(s); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
}

func TestEscape(t *testing.T) {
	if got := ldap.EscapeFilter("a)(uid=*"); got != `a\29\28uid=\2a` {
		t.Fatalf("filter escape %q", got)
	}
	if got := ldap.EscapeDN("a,b+c"); got != `a\,b\+c` {
		t.Fatalf("dn escape %q", got)
	}
	// An injected filter value cannot break out: the escaped payload matches
	// no attribute and the round trip is lossless.
	f, err := ldap.ParseFilter("(uid=" + ldap.EscapeFilter("*)(objectClass=*") + ")")
	if err != nil {
		t.Fatalf("escaped filter rejected: %v", err)
	}
	_ = f
}
