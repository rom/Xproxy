package ldapauth

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
	"github.com/rom/xproxy/internal/ldap/ldaptest"
)

// This filter turns a login form into a bind against a directory.
// Everything in the request is the client's, and the cache in front of
// the directory is what stops a password spray from becoming load on
// somebody else's infrastructure.

func build(t *testing.T, s *ldaptest.Server, extra filter.Options) filter.Filter {
	t.Helper()
	opts := filter.Options{"url": s.URL(), "allow_plaintext": true,
		"bind_dn_template": "uid=%s,ou=people,dc=example,dc=com"}
	for k, v := range extra {
		opts[k] = v
	}
	f, err := filtertest.Build("ldap_auth", "ldap", opts)
	if err != nil {
		t.Fatalf("building the filter: %v", err)
	}
	return f
}

// TestCredentialsThatAreNotCredentials covers what a client can put in
// the Authorization header.
func TestCredentialsThatAreNotCredentials(t *testing.T) {
	s := ldaptest.Start(t, directory())
	f := build(t, s, nil)

	// A header that is not basic authentication at all.
	for _, h := range []string{
		"", "Basic", "Basic ", "Basic !!!!", "Bearer abc", "Negotiate abc",
		"Basic " + strings.Repeat("A", 10000),
	} {
		r := req("", "")
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		v := filtertest.Run(f, r, nil).Request
		if !v.Deny || v.Status != http.StatusUnauthorized {
			t.Errorf("the header %.20q gave %+v", h, v)
		}
		// The challenge names the realm and is one header line.
		if ch := v.Headers["WWW-Authenticate"]; !strings.Contains(ch, "realm=") || strings.ContainsAny(ch, "\r\n") {
			t.Errorf("the header %.20q produced the challenge %q", h, ch)
		}
	}
	// A user name with the characters a DN or a filter is made of: the
	// escaping means they name no entry, and none of them can reach the
	// directory as syntax.
	for _, user := range []string{
		"alice,ou=x", "alice)(uid=*", "*", "alice\\", "alice\x00", "alice ", " alice",
		"alice=1", "a+b", "a<b>c", "a;b", "a\"b", strings.Repeat("a", 300),
		"alice\r\nuid=bob",
	} {
		if v := filtertest.Run(f, req(user, "s3cret"), nil).Request; !v.Deny {
			t.Errorf("the user %q was accepted", user)
		}
	}
	// A name differing only in case is the same entry: LDAP compares
	// distinguished names case insensitively, and so does the directory.
	if v := filtertest.Run(f, req("ALICE", "s3cret"), nil).Request; v.Deny {
		t.Error("a name in another case was refused")
	}
	// An empty password never becomes an anonymous bind.
	if v := filtertest.Run(f, req("alice", ""), nil).Request; !v.Deny {
		t.Error("an empty password was accepted")
	}
	// The real login still works after all of that.
	if v := filtertest.Run(f, req("alice", "s3cret"), nil).Request; v.Deny {
		t.Errorf("a valid login was denied: %+v", v)
	}
}

// TestHeadersAroundTheIdentity covers what the filter does to the
// request once it has authenticated it.
func TestHeadersAroundTheIdentity(t *testing.T) {
	s := ldaptest.Start(t, directory())
	f := build(t, s, filter.Options{"forward_user_header": "X-Auth-User"})
	r := req("alice", "s3cret")
	// A client-supplied identity header must not survive the filter.
	r.Header.Set("X-Auth-User", "admin")
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("denied: %+v", res.Request)
	}
	if got := r.Header.Get("X-Auth-User"); got != "alice" {
		t.Errorf("the forwarded identity is %q", got)
	}
	// The credentials are not forwarded to the upstream by default.
	if r.Header.Get("Authorization") != "" {
		t.Error("the Authorization header reached the upstream")
	}
	// The identity is attached for the log.
	if len(res.Attrs) != 2 || res.Attrs[0] != "auth_user" || res.Attrs[1] != "alice" {
		t.Errorf("attributes %v", res.Attrs)
	}
	// A failed login attaches nothing.
	if res := filtertest.Run(f, req("alice", "wrong"), nil); len(res.Attrs) != 0 {
		t.Errorf("a failed login attached %v", res.Attrs)
	}
	// With strip off, the header travels on.
	keep := build(t, s, filter.Options{"strip": false})
	r = req("alice", "s3cret")
	if v := filtertest.Run(keep, r, nil).Request; v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	if r.Header.Get("Authorization") == "" {
		t.Error("strip: false still removed the header")
	}
	// The filter has a name and does nothing to a response.
	if keep.Name() != "ldap" {
		t.Errorf("name %q", keep.Name())
	}
	in := keep.Begin(context.Background(), &filter.Info{})
	if v := in.Response(&http.Response{StatusCode: 200, Header: http.Header{}}); v.Deny {
		t.Errorf("the response phase denied: %+v", v)
	}
}

// TestCacheAndConcurrency covers the cache in front of the directory: a
// spray of wrong passwords must not become one bind each, and a right
// password must not be remembered past its time.
func TestCacheAndConcurrency(t *testing.T) {
	s := ldaptest.Start(t, directory())
	f := build(t, s, filter.Options{"cache_ttl": "1h"})
	// The same credentials twice: the second is a cache hit, which the
	// test sees by stopping the directory.
	if v := filtertest.Run(f, req("alice", "s3cret"), nil).Request; v.Deny {
		t.Fatal("the first login was denied")
	}
	if v := filtertest.Run(f, req("alice", "wrong"), nil).Request; !v.Deny {
		t.Fatal("a wrong password was accepted")
	}
	s.Close()
	if v := filtertest.Run(f, req("alice", "s3cret"), nil).Request; v.Deny {
		t.Error("the cached login was not used once the directory went away")
	}
	if v := filtertest.Run(f, req("alice", "wrong"), nil).Request; !v.Deny {
		t.Error("a cached failure turned into a success")
	}
	// A user nobody cached, with the directory gone, is denied rather
	// than admitted.
	if v := filtertest.Run(f, req("carol", "whatever"), nil).Request; !v.Deny {
		t.Error("an unknown user was admitted while the directory was down")
	}

	// With the cache off, every attempt reaches the directory. A burst
	// larger than the queue bound is shed rather than queued — the
	// filter holds a request slot of the process while it waits — so
	// the property is that no wrong password is ever accepted, and that
	// a burst within the bound is served in full.
	s2 := ldaptest.Start(t, directory())
	nocache := build(t, s2, filter.Options{"cache_ttl": "0"})
	run := func(n int) (ok, denied int) {
		var wg sync.WaitGroup
		results := make([]bool, n)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				pass := "s3cret"
				if i%2 == 1 {
					pass = "wrong"
				}
				deny := filtertest.Run(nocache, req("alice", pass), nil).Request.Deny
				if i%2 == 1 && !deny {
					t.Errorf("request %d: a wrong password was accepted", i)
				}
				results[i] = deny
			}(i)
		}
		wg.Wait()
		for i, deny := range results {
			if i%2 == 1 {
				continue
			}
			if deny {
				denied++
			} else {
				ok++
			}
		}
		return ok, denied
	}
	// Eight concurrent logins is within the bound: all of them succeed.
	if ok, denied := run(8); denied != 0 {
		t.Errorf("%d of %d valid logins were shed at a concurrency of eight", denied, ok+denied)
	}
	// A much larger burst may shed, but never accepts a wrong password
	// (checked inside run) and never fails every valid one.
	if ok, _ := run(128); ok == 0 {
		t.Error("every valid login was shed")
	}
}

// TestClientThatLeaves covers the request context: a client that goes
// away must not leave a bind running, and must never be authenticated.
func TestClientThatLeaves(t *testing.T) {
	s := ldaptest.Start(t, directory())
	f := build(t, s, nil)
	r := req("alice", "s3cret")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = r.WithContext(ctx)
	if v := filtertest.Run(f, r, nil).Request; !v.Deny {
		t.Error("a request whose client had left was authenticated")
	}
}

// TestOptionRefusals covers the configuration, where the dangerous
// defaults have to be opted into explicitly.
func TestOptionRefusals(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "bind.pw")
	if err := os.WriteFile(pw, []byte("svcpw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	world := filepath.Join(dir, "world.pw")
	if err := os.WriteFile(world, []byte("svcpw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := func(extra filter.Options) filter.Options {
		o := filter.Options{"url": "ldaps://dir.example", "bind_dn_template": "uid=%s,dc=example,dc=com"}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	bad := map[string]filter.Options{
		"no url":                       {"bind_dn_template": "uid=%s,dc=x"},
		"an http url":                  base(filter.Options{"url": "https://dir.example"}),
		"a bare host":                  base(filter.Options{"url": "dir.example:389"}),
		"plain ldap without start_tls": base(filter.Options{"url": "ldap://dir.example"}),
		"a template with no %s":        base(filter.Options{"bind_dn_template": "uid=fixed,dc=x"}),
		"a template and a base dn":     base(filter.Options{"base_dn": "dc=x"}),
		"a template and a filter":      base(filter.Options{"user_filter": "(uid=%s)"}),
		"no base dn":                   {"url": "ldaps://dir.example", "user_filter": "(uid=%s)"},
		"no user filter":               {"url": "ldaps://dir.example", "base_dn": "dc=x"},
		"a filter with no %s":          {"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=fixed)"},
		"a filter that does not parse": {"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=%s"},
		"a filter nested too deep": {"url": "ldaps://dir.example", "base_dn": "dc=x",
			"user_filter": strings.Repeat("(&", 40) + "(uid=%s)" + strings.Repeat(")", 40)},
		"a bind dn with no password file": {"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=%s)", "bind_dn": "cn=svc"},
		"a password file that is not there": {"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=%s)",
			"bind_dn": "cn=svc", "bind_password_file": filepath.Join(dir, "missing")},
		"a world readable password file": {"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=%s)",
			"bind_dn": "cn=svc", "bind_password_file": world},
		"require_group with a template":  base(filter.Options{"require_group": "cn=staff"}),
		"a realm with a quote":           base(filter.Options{"realm": `a"b`}),
		"a realm with a newline":         base(filter.Options{"realm": "a\nb"}),
		"a cache ttl that is not one":    base(filter.Options{"cache_ttl": "soon"}),
		"a negative cache ttl":           base(filter.Options{"cache_ttl": "-1m"}),
		"a cache ttl past a day":         base(filter.Options{"cache_ttl": "25h"}),
		"a timeout below a second":       base(filter.Options{"timeout": "10ms"}),
		"a timeout past a minute":        base(filter.Options{"timeout": "2m"}),
		"a ca file that is not there":    base(filter.Options{"ca_file": filepath.Join(dir, "missing.pem")}),
		"a ca file with no certificates": base(filter.Options{"ca_file": notPEM}),
		"an unknown option":              base(filter.Options{"bogus": 1}),
	}
	for name, opts := range bad {
		if _, err := filtertest.Build("ldap_auth", "x", opts); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	good := map[string]filter.Options{
		"ldaps with a template": base(nil),
		"start_tls over ldap":   base(filter.Options{"url": "ldap://dir.example", "start_tls": true}),
		"plaintext opted into":  base(filter.Options{"url": "ldap://dir.example", "allow_plaintext": true}),
		"a search bind":         {"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=%s)"},
		"a service account":     {"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=%s)", "bind_dn": "cn=svc", "bind_password_file": pw},
		"a group requirement":   {"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=%s)", "require_group": "cn=staff"},
		"a cache turned off":    base(filter.Options{"cache_ttl": "0"}),
		"a day of cache":        base(filter.Options{"cache_ttl": "24h"}),
		"a one second timeout":  base(filter.Options{"timeout": "1s"}),
		"a minute of timeout":   base(filter.Options{"timeout": "1m"}),
		"insecure_skip_verify":  base(filter.Options{"insecure_skip_verify": true}),
	}
	for name, opts := range good {
		if _, err := filtertest.Build("ldap_auth", "x", opts); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	// The group attribute defaults for a search bind that needs one.
	c, err := parse(filter.Options{"url": "ldaps://dir.example", "base_dn": "dc=x", "user_filter": "(uid=%s)", "require_group": "cn=staff"})
	if err != nil {
		t.Fatal(err)
	}
	if c.GroupAttr != "memberOf" {
		t.Errorf("group_attr defaulted to %q", c.GroupAttr)
	}
	if c.Realm != "restricted" {
		t.Errorf("realm defaulted to %q", c.Realm)
	}
	if c.ttl != 5*time.Minute || c.timeout != 5*time.Second {
		t.Errorf("defaults: ttl %v timeout %v", c.ttl, c.timeout)
	}
	// buildTLS carries the pinned authority and the opt-in.
	tc, err := buildTLS(&Config{})
	if err != nil || tc.RootCAs != nil || tc.InsecureSkipVerify {
		t.Errorf("a default TLS configuration: %+v %v", tc, err)
	}
	if _, err := buildTLS(&Config{CAFile: notPEM}); err == nil {
		t.Error("a CA file with no certificates was accepted")
	}
	if _, err := buildTLS(&Config{CAFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Error("a missing CA file was accepted")
	}
}
