package ldapauth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
	"github.com/rom/xproxy/internal/ldap/ldaptest"
)

func directory() []ldaptest.User {
	return []ldaptest.User{
		{DN: "uid=alice,ou=people,dc=example,dc=com", Password: "s3cret",
			Attrs: map[string][]string{"uid": {"alice"}, "memberOf": {"cn=staff,ou=groups,dc=example,dc=com"}}},
		{DN: "uid=bob,ou=people,dc=example,dc=com", Password: "hunter2",
			Attrs: map[string][]string{"uid": {"bob"}, "memberOf": {"cn=other,ou=groups,dc=example,dc=com"}}},
		{DN: "cn=svc,dc=example,dc=com", Password: "svcpw", Attrs: map[string][]string{"cn": {"svc"}}},
	}
}

func req(user, pass string) *http.Request {
	r := httptest.NewRequest("GET", "http://shop.test/", nil)
	if user != "" {
		r.SetBasicAuth(user, pass)
	}
	return r
}

func TestDirectBind(t *testing.T) {
	s := ldaptest.Start(t, directory())
	f, err := filtertest.Build("ldap_auth", "dir", filter.Options{
		"url":              s.URL(),
		"bind_dn_template": "uid=%s,ou=people,dc=example,dc=com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := filtertest.Run(f, req("alice", "s3cret"), nil).Request; v.Deny {
		t.Fatalf("valid login denied: %+v", v)
	}
	if v := filtertest.Run(f, req("alice", "wrong"), nil).Request; !v.Deny || v.Status != http.StatusUnauthorized {
		t.Fatalf("bad password: %+v", v)
	}
	if v := filtertest.Run(f, req("", ""), nil).Request; !v.Deny {
		t.Fatal("no credentials accepted")
	}
	// An injection attempt in the username cannot alter the bind DN: the
	// escaped value simply names no entry.
	if v := filtertest.Run(f, req("alice,ou=x", "s3cret"), nil).Request; !v.Deny {
		t.Fatal("dn injection accepted")
	}
}

func TestSearchBindWithGroup(t *testing.T) {
	s := ldaptest.Start(t, directory())
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "svc.secret")
	if err := os.WriteFile(pwFile, []byte("svcpw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := filtertest.Build("ldap_auth", "grp", filter.Options{
		"url":                 s.URL(),
		"bind_dn":             "cn=svc,dc=example,dc=com",
		"bind_password_file":  pwFile,
		"base_dn":             "ou=people,dc=example,dc=com",
		"user_filter":         "(uid=%s)",
		"require_group":       "cn=staff,ou=groups,dc=example,dc=com",
		"forward_user_header": "X-Remote-User",
	})
	if err != nil {
		t.Fatal(err)
	}
	// alice is in staff.
	r := req("alice", "s3cret")
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("staff member denied: %+v", v)
	}
	if got := r.Header.Get("X-Remote-User"); got != "alice" {
		t.Fatalf("forwarded user %q", got)
	}
	if r.Header.Get("Authorization") != "" {
		t.Fatal("Authorization not stripped")
	}
	// bob authenticates but is not in staff.
	if v := filtertest.Run(f, req("bob", "hunter2"), nil).Request; !v.Deny {
		t.Fatal("non-member accepted")
	}
	// Wrong password for a staff member.
	if v := filtertest.Run(f, req("alice", "nope"), nil).Request; !v.Deny {
		t.Fatal("bad password accepted")
	}
}

func TestValidate(t *testing.T) {
	bad := []filter.Options{
		{},                  // no url
		{"url": "http://x"}, // wrong scheme
		{"url": "ldap://x"}, // neither template nor search
		{"url": "ldap://x", "bind_dn_template": "uid=x,dc=y"},                                  // template without %s
		{"url": "ldap://x", "base_dn": "dc=y", "user_filter": "uid=%s"},                        // filter without parens
		{"url": "ldap://x", "base_dn": "dc=y"},                                                 // filter missing
		{"url": "ldap://x", "bind_dn_template": "uid=%s", "base_dn": "dc=y"},                   // exclusive
		{"url": "ldap://x", "base_dn": "dc=y", "user_filter": "(uid=%s)", "bind_dn": "cn=svc"}, // bind_dn without password
	}
	for i, opts := range bad {
		if _, err := filtertest.Build("ldap_auth", "t", opts); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	ok := filter.Options{"url": "ldaps://x", "base_dn": "dc=y", "user_filter": "(sAMAccountName=%s)"}
	if _, err := filtertest.Build("ldap_auth", "t", ok); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}
