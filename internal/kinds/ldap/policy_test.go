package ldap

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/ldap"
)

func policyFor(t *testing.T, l *config.LDAPListener) *Policy {
	t.Helper()
	p, err := compile(l, func() time.Time {
		// A Wednesday at 14:00 UTC, so a schedule in a test is about the
		// window and not about when the test happens to run.
		return time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// decide applies the policy to a message from an unbound, unprotected
// connection unless the options say otherwise.
type as struct {
	from   string
	bound  string
	method wire.Method
	secure bool
}

func decide(t *testing.T, p *Policy, who as, raw []byte) Decision {
	t.Helper()
	if who.from == "" {
		who.from = "10.0.0.1"
	}
	dn, err := wire.ParseDN(who.bound)
	if err != nil {
		t.Fatalf("bound dn %q: %v", who.bound, err)
	}
	return p.Decide(request{client: netip.MustParseAddr(who.from), msg: parseMsg(raw),
		bound: dn, boundName: who.bound, method: who.method, secure: who.secure})
}

// The refusal this relay exists for on this protocol. A simple bind with a
// name and an empty password is an anonymous bind by RFC 4513; the directory
// answers success; the application reads that success as authentication.
func TestABindWithAnEmptyPasswordIsRefusedByDefault(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{DefaultAction: "allow"})
	d := decide(t, p, as{secure: true}, bind(1, "cn=alice,dc=example,dc=com", ""))
	if d.Allow {
		t.Fatal("an unauthenticated bind was allowed")
	}
	if d.Reason != "ldap_unauthenticated_bind" {
		t.Errorf("reason %q", d.Reason)
	}
	if d.Detail != "cn=alice,dc=example,dc=com" {
		t.Errorf("the refusal did not name the identity being claimed: %q", d.Detail)
	}
	// The anonymous bind proper -- no name and no password -- is refused too
	// and named separately, because they are different statements.
	d = decide(t, p, as{secure: true}, bind(2, "", ""))
	if d.Allow || d.Reason != "ldap_anonymous_bind" {
		t.Errorf("anonymous bind: %+v", d)
	}
	// And a real bind passes.
	d = decide(t, p, as{secure: true}, bind(3, "cn=alice,dc=example,dc=com", "s3cret"))
	if !d.Allow {
		t.Errorf("a simple bind with a password was refused: %+v", d)
	}
	// Named explicitly, an unauthenticated bind is allowed: an operator who
	// says so gets it.
	p = policyFor(t, &config.LDAPListener{
		Methods: []string{"simple", "unauthenticated"}, DefaultAction: "allow"})
	if d := decide(t, p, as{secure: true}, bind(4, "cn=alice", "")); !d.Allow {
		t.Errorf("an explicitly allowed unauthenticated bind was refused: %+v", d)
	}
}

// The password in the clear, which is the other thing this protocol does by
// default that nobody intends.
func TestAPasswordIsNotCarriedInTheClear(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{DefaultAction: "allow"})
	d := decide(t, p, as{}, bind(1, "cn=alice,dc=example,dc=com", "s3cret"))
	if d.Allow {
		t.Fatal("a simple bind with a password was carried on an unprotected connection")
	}
	if d.Reason != "ldap_bind_in_clear" {
		t.Errorf("reason %q", d.Reason)
	}
	// Protected, it passes.
	if d := decide(t, p, as{secure: true}, bind(2, "cn=alice", "s3cret")); !d.Allow {
		t.Errorf("a protected bind was refused: %+v", d)
	}
	// A bind that carries no password is not a password in the clear: an
	// anonymous bind on port 389 is how a client reads the root DSE.
	p = policyFor(t, &config.LDAPListener{Methods: []string{"anonymous"}, DefaultAction: "allow"})
	if d := decide(t, p, as{}, bind(3, "", "")); !d.Allow {
		t.Errorf("an anonymous bind was refused as a password in the clear: %+v", d)
	}
	// And SASL PLAIN is a simple bind with extra steps, which is why it is
	// named here and not only in the mechanism list.
	p = policyFor(t, &config.LDAPListener{DefaultAction: "allow"})
	if d := decide(t, p, as{}, saslBind(4, "PLAIN", "\x00alice\x00s3cret")); d.Allow {
		t.Error("SASL PLAIN carried a password in the clear")
	}
	if d := decide(t, p, as{}, saslBind(5, "GSSAPI", "token")); !d.Allow {
		t.Error("GSSAPI was refused as a password in the clear")
	}
	// require_tls: false is the operator saying so.
	no := false
	p = policyFor(t, &config.LDAPListener{RequireTLS: &no, DefaultAction: "allow"})
	if d := decide(t, p, as{}, bind(6, "cn=alice", "s3cret")); !d.Allow {
		t.Errorf("require_tls false still refused: %+v", d)
	}
	if !p.BindsInClear() {
		t.Error("the policy does not report that it carries binds in the clear")
	}
}

// LDAPv2 is a different protocol wearing the same tags.
func TestTheVersionIsAFloor(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{DefaultAction: "allow"})
	d := decide(t, p, as{secure: true}, bindVersion(1, 2, "cn=alice", "s3cret"))
	if d.Allow || d.Reason != "ldap_version" {
		t.Errorf("a v2 bind: %+v", d)
	}
	p = policyFor(t, &config.LDAPListener{MinVersion: 2, DefaultAction: "allow"})
	if d := decide(t, p, as{secure: true}, bindVersion(2, 2, "cn=alice", "s3cret")); !d.Allow {
		t.Errorf("a v2 bind on a listener that allows it: %+v", d)
	}
}

// The SASL mechanism list, because PLAIN and GSSAPI are not the same
// statement.
func TestTheSASLMechanismListDecides(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{
		SASLMechanisms: []string{"GSSAPI"}, DefaultAction: "allow"})
	if d := decide(t, p, as{secure: true}, saslBind(1, "GSSAPI", "t")); !d.Allow {
		t.Errorf("the listed mechanism was refused: %+v", d)
	}
	d := decide(t, p, as{secure: true}, saslBind(2, "DIGEST-MD5", "t"))
	if d.Allow || d.Reason != "ldap_sasl_mechanism" || d.Detail != "DIGEST-MD5" {
		t.Errorf("an unlisted mechanism: %+v", d)
	}
	// The comparison is case-insensitive, because a client writes the
	// mechanism as it likes and the registry is upper case.
	if d := decide(t, p, as{secure: true}, saslBind(3, "gssapi", "t")); !d.Allow {
		t.Errorf("a lower-case mechanism name was refused: %+v", d)
	}
}

// read_only is one line covering every operation that changes the directory,
// and a rule cannot open a hole in it.
func TestReadOnlyCannotBeOverriddenByARule(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{ReadOnly: true, DefaultAction: "allow",
		Rules: []config.LDAPRule{{Name: "let-them-write", Action: "allow", Access: []string{"write"}}}})
	for _, raw := range [][]byte{
		modify(1, "cn=alice,dc=example,dc=com", change(2, "userPassword", "new")),
		add(2, "cn=bob,dc=example,dc=com"),
		del(3, "cn=carol,dc=example,dc=com"),
		msg(4, appC(12, octets("cn=dan,dc=example,dc=com"), octets("cn=dave"), boolean(true))),
	} {
		d := decide(t, p, as{secure: true, bound: "cn=admin"}, raw)
		if d.Allow {
			t.Errorf("a write was allowed through a read-only listener: %s", parseMsg(raw).Op)
		} else if d.Reason != "ldap_read_only" {
			t.Errorf("reason %q", d.Reason)
		}
	}
	// A search is untouched by it.
	if d := decide(t, p, as{secure: true}, search(5, "dc=example,dc=com", wire.ScopeSub, present("objectClass"))); !d.Allow {
		t.Errorf("a search was refused by read_only: %+v", d)
	}
}

// The naming contexts a listener fronts, checked before the rules and before
// default_action: allow.
func TestTheBaseSuffixesAreABoundary(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{
		BaseDNs: []string{"dc=example,dc=com"}, DefaultAction: "allow"})
	if d := decide(t, p, as{secure: true},
		search(1, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"))); !d.Allow {
		t.Errorf("a search inside the naming context was refused: %+v", d)
	}
	// The trap a string suffix test falls into.
	d := decide(t, p, as{secure: true},
		search(2, "dc=notexample,dc=com", wire.ScopeSub, present("objectClass")))
	if d.Allow {
		t.Error("dc=notexample,dc=com passed a base of dc=example,dc=com")
	}
	if d.Reason != "ldap_base_dn" {
		t.Errorf("reason %q", d.Reason)
	}
	// And the one a prefix test falls into.
	if d := decide(t, p, as{secure: true},
		search(3, "ou=peoplex,dc=other,dc=com", wire.ScopeSub, present("objectClass"))); d.Allow {
		t.Error("a name outside the context was allowed")
	}
	// A bind names an object too, so a bind DN outside the contexts is
	// refused: an application binding as a name in another tree is
	// authenticating somewhere this listener is not for.
	if d := decide(t, p, as{secure: true}, bind(4, "cn=admin,dc=other,dc=com", "s3cret")); d.Allow {
		t.Error("a bind outside the naming contexts was allowed")
	}
}

// The attribute policy, in both halves and in its three shapes.
func TestTheAttributePolicyAppliesToTheQuestionAndTheAnswer(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{
		BaseDNs: []string{"dc=example,dc=com"}, DefaultAction: "allow"})

	// Asked for by name: refused, because stripping would answer a plain
	// question with a silence the client cannot tell from an empty
	// directory.
	d := decide(t, p, as{secure: true},
		search(1, "dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn", "userPassword"))
	if d.Allow || d.Reason != "ldap_attribute" || d.Detail != "userPassword" {
		t.Errorf("a named password attribute: %+v", d)
	}
	// Asked for in a filter: refused, because a filter that tests a password
	// is a password oracle -- one character at a time, with substrings.
	d = decide(t, p, as{secure: true},
		search(2, "dc=example,dc=com", wire.ScopeSub, substr("userPassword", initialPart("a"))))
	if d.Allow || d.Reason != "ldap_filter_attribute" {
		t.Errorf("a filter testing a password: %+v", d)
	}
	// Asked for with "*": allowed, and the answer is stripped. This is the
	// half a request-side access list cannot do.
	d = decide(t, p, as{secure: true},
		search(3, "dc=example,dc=com", wire.ScopeSub, present("objectClass"), "*"))
	if !d.Allow {
		t.Fatalf("a search for * was refused: %+v", d)
	}
	if !d.Strip.Has("userPassword") || !d.Strip.Has("unicodePwd") {
		t.Error("the answer filter does not carry the built-in list")
	}
	if d.Strip.Has("cn") {
		t.Error("the answer filter would remove an ordinary attribute")
	}
	// The transfer option is not part of the name.
	if !d.Strip.Has("userPassword;binary") {
		t.Error("an attribute with a transfer option escaped the answer filter")
	}
	// A listener's own list replaces the built-in one.
	p = policyFor(t, &config.LDAPListener{DenyAttributes: []string{"employeeNumber"},
		DefaultAction: "allow"})
	d = decide(t, p, as{secure: true}, search(4, "", wire.ScopeSub, present("objectClass"), "*"))
	if !d.Strip.Has("employeeNumber") || d.Strip.Has("userPassword") {
		t.Error("a named deny list did not replace the built-in one")
	}
	// on_denied_attribute: deny carries nothing and strips nothing: the
	// request named none of them.
	p = policyFor(t, &config.LDAPListener{OnDeniedAttribute: "deny", DefaultAction: "allow"})
	d = decide(t, p, as{secure: true}, search(5, "", wire.ScopeSub, present("objectClass"), "*"))
	if !d.Allow || !d.Strip.Empty() {
		t.Errorf("on_denied_attribute deny: %+v", d)
	}
	// A rule with an attribute list turns the answer policy inside out:
	// anything not named is removed.
	p = policyFor(t, &config.LDAPListener{Rules: []config.LDAPRule{
		{Name: "phonebook", Action: "allow", Attributes: []string{"cn", "mail", "telephoneNumber"}},
	}})
	d = decide(t, p, as{secure: true}, search(6, "", wire.ScopeSub, present("objectClass"), "*"))
	if !d.Allow || d.Rule != "phonebook" {
		t.Fatalf("the rule did not decide: %+v", d)
	}
	if !d.allowOnly.Has("cn") || d.allowOnly.Has("employeeNumber") {
		t.Error("the rule's attribute list is not the answer filter")
	}
	// And naming an attribute the rule does not allow is refused.
	d = decide(t, p, as{secure: true}, search(7, "", wire.ScopeSub, present("objectClass"), "employeeNumber"))
	if d.Allow || d.Reason != "ldap_attribute_not_allowed" {
		t.Errorf("an attribute outside the rule's list: %+v", d)
	}
}

// The filter bounds: a filter is the one part of a request whose size the
// client chooses and whose cost the directory pays.
func TestTheFilterBoundsHold(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{MaxFilterTerms: 3, MaxFilterDepth: 2,
		DefaultAction: "allow"})
	ok := or(present("cn"), present("mail"))
	if d := decide(t, p, as{secure: true}, search(1, "", wire.ScopeSub, ok)); !d.Allow {
		t.Errorf("a filter inside the bounds: %+v", d)
	}
	wide := or(present("a"), present("b"), present("c"), present("d"))
	d := decide(t, p, as{secure: true}, search(2, "", wire.ScopeSub, wide))
	if d.Allow || d.Reason != "ldap_filter_terms" {
		t.Errorf("a filter past the term bound: %+v", d)
	}
	deep := and(or(not(present("cn"))))
	d = decide(t, p, as{secure: true}, search(3, "", wire.ScopeSub, deep))
	if d.Allow || d.Reason != "ldap_filter_depth" {
		t.Errorf("a filter past the depth bound: %+v", d)
	}
	// The leading wildcard, which no index can serve.
	no := false
	p = policyFor(t, &config.LDAPListener{AllowLeadingWildcard: &no, DefaultAction: "allow"})
	d = decide(t, p, as{secure: true}, search(4, "", wire.ScopeSub, substr("cn", finalPart("smith"))))
	if d.Allow || d.Reason != "ldap_leading_wildcard" {
		t.Errorf("a leading wildcard: %+v", d)
	}
	// With an initial part it is an index lookup and passes.
	if d := decide(t, p, as{secure: true},
		search(5, "", wire.ScopeSub, substr("cn", initialPart("smi")))); !d.Allow {
		t.Errorf("an anchored substring was refused: %+v", d)
	}
	// A rule may raise the bound for its own traffic, and does not cover
	// traffic past it.
	p = policyFor(t, &config.LDAPListener{MaxFilterTerms: 3, DefaultAction: "deny",
		Rules: []config.LDAPRule{{Name: "reports", Action: "allow", MaxFilterTerms: 8}}})
	if d := decide(t, p, as{secure: true}, search(6, "", wire.ScopeSub, wide)); !d.Allow {
		t.Errorf("the rule's own bound was not used: %+v", d)
	}
}

// The identity a rule names, and the fact that an unbound connection is
// nobody.
func TestARuleCanNameTheIdentity(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{Rules: []config.LDAPRule{
		{Name: "services", Action: "allow", BindDNs: []string{"ou=services,dc=example,dc=com"},
			Access: []string{"read"}},
		{Name: "pre-auth", Action: "allow", BindDNs: []string{""}, Operations: []string{"bind"}},
	}})
	// A service account may read.
	if d := decide(t, p, as{secure: true, bound: "cn=app1,ou=services,dc=example,dc=com"},
		search(1, "dc=example,dc=com", wire.ScopeSub, present("objectClass"))); !d.Allow {
		t.Errorf("a service account was refused: %+v", d)
	}
	// A person's account, in another container, is not covered.
	if d := decide(t, p, as{secure: true, bound: "cn=alice,ou=people,dc=example,dc=com"},
		search(2, "dc=example,dc=com", wire.ScopeSub, present("objectClass"))); d.Allow {
		t.Error("a name outside the rule's container matched it")
	}
	// An unbound connection may bind and nothing else, which is how "before
	// you authenticate, you may do this and no more" is written.
	if d := decide(t, p, as{secure: true}, bind(3, "cn=app1,ou=services,dc=example,dc=com", "s3cret")); !d.Allow {
		t.Errorf("an unbound connection could not bind: %+v", d)
	}
	if d := decide(t, p, as{secure: true},
		search(4, "dc=example,dc=com", wire.ScopeSub, present("objectClass"))); d.Allow {
		t.Error("an unbound connection could search")
	}
}

// The scope, the deny_dns exception and the schedule.
func TestARuleNarrowsByScopeSubtreeAndWindow(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{Rules: []config.LDAPRule{
		{Name: "people", Action: "allow", BaseDNs: []string{"ou=people,dc=example,dc=com"},
			DenyDNs: []string{"ou=admins,ou=people,dc=example,dc=com"},
			Scopes:  []string{"one", "base"}},
	}})
	who := as{secure: true, bound: "cn=app"}
	if d := decide(t, p, who,
		search(1, "ou=people,dc=example,dc=com", wire.ScopeOne, present("objectClass"))); !d.Allow {
		t.Errorf("a one-level search was refused: %+v", d)
	}
	if d := decide(t, p, who,
		search(2, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"))); d.Allow {
		t.Error("a subtree search matched a rule naming base and one")
	}
	if d := decide(t, p, who,
		search(3, "ou=admins,ou=people,dc=example,dc=com", wire.ScopeBase, present("objectClass"))); d.Allow {
		t.Error("the excluded container was allowed")
	}
	// A window.
	day := policyFor(t, &config.LDAPListener{Rules: []config.LDAPRule{
		{Name: "office", Action: "allow",
			Schedule: &config.ModbusSchedule{Days: []string{"wed"}, From: "09:00", To: "17:00"}},
	}})
	if d := decide(t, day, who, search(4, "", wire.ScopeBase, present("objectClass"))); !d.Allow {
		t.Errorf("a Wednesday afternoon was outside a Wednesday window: %+v", d)
	}
	night := policyFor(t, &config.LDAPListener{Rules: []config.LDAPRule{
		{Name: "night", Action: "allow",
			Schedule: &config.ModbusSchedule{From: "22:00", To: "06:00"}},
	}})
	if d := decide(t, night, who, search(5, "", wire.ScopeBase, present("objectClass"))); d.Allow {
		t.Error("14:00 fell inside a 22:00-to-06:00 window")
	}
}

// The extended operations, named by OID because that is all a relay can read
// of one.
func TestAnExtendedOperationIsNamedByItsOID(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{DefaultAction: "allow"})
	// StartTLS is always in the set, because the relay implements it.
	if d := decide(t, p, as{}, extended(1, wire.OIDStartTLS)); !d.Allow {
		t.Errorf("StartTLS was refused: %+v", d)
	}
	d := decide(t, p, as{secure: true}, extended(2, wire.OIDPasswordModify))
	if d.Allow || d.Reason != "ldap_extended" || d.Detail != wire.OIDPasswordModify {
		t.Errorf("password modify: %+v", d)
	}
	p = policyFor(t, &config.LDAPListener{
		ExtendedOperations: []string{wire.OIDWhoAmI}, DefaultAction: "allow"})
	if d := decide(t, p, as{secure: true}, extended(3, wire.OIDWhoAmI)); !d.Allow {
		t.Errorf("a named operation was refused: %+v", d)
	}
}

// A control this listener refuses to carry, and the operations that carry no
// decision at all.
func TestControlsAndTheOperationsWithNoDecision(t *testing.T) {
	const paged = "1.2.840.113556.1.4.319"
	p := policyFor(t, &config.LDAPListener{DenyControls: []string{paged},
		DefaultAction: "allow"})
	raw := msg(1, appC(3, octets(""), enumerated(0), enumerated(0), integer(0), integer(0),
		boolean(false), present("objectClass"), seq()), seq(octets(paged), boolean(true)))
	d := decide(t, p, as{secure: true}, raw)
	if d.Allow || d.Reason != "ldap_control" || d.Detail != paged {
		t.Errorf("a refused control: %+v", d)
	}
	// Unbind and abandon carry no decision: refusing either would leave a
	// connection in a state neither end agrees about.
	p = policyFor(t, &config.LDAPListener{})
	if d := decide(t, p, as{}, unbind(2)); !d.Allow {
		t.Errorf("an unbind was refused: %+v", d)
	}
	if d := decide(t, p, as{}, msg(3, ber(0x40|16, 2))); !d.Allow {
		t.Errorf("an abandon was refused: %+v", d)
	}
}

// observe logs and keeps looking; the default decides what no rule covered.
func TestObserveAndTheDefault(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{Rules: []config.LDAPRule{
		{Name: "watch-writes", Action: "observe", Access: []string{"write"}},
		{Name: "allow-all", Action: "allow"},
	}})
	d := decide(t, p, as{secure: true, bound: "cn=admin"},
		modify(1, "cn=alice,dc=example,dc=com", change(2, "cn", "x")))
	if !d.Allow || d.Rule != "allow-all" {
		t.Errorf("the observe rule decided: %+v", d)
	}
	p = policyFor(t, &config.LDAPListener{})
	d = decide(t, p, as{secure: true, bound: "cn=admin"},
		search(2, "dc=example,dc=com", wire.ScopeSub, present("objectClass")))
	if d.Allow || d.Reason != "ldap_default_deny" {
		t.Errorf("the default: %+v", d)
	}
	if d.Detail != "search dc=example,dc=com" {
		t.Errorf("the default's detail is %q", d.Detail)
	}
	// And a deny rule names itself.
	p = policyFor(t, &config.LDAPListener{DefaultAction: "allow", Rules: []config.LDAPRule{
		{Name: "no-admins", Action: "deny", BaseDNs: []string{"ou=admins,dc=example,dc=com"}},
	}})
	d = decide(t, p, as{secure: true, bound: "cn=app"},
		search(3, "ou=admins,dc=example,dc=com", wire.ScopeSub, present("objectClass")))
	if d.Allow || d.Rule != "no-admins" || d.Reason != "ldap_rule" {
		t.Errorf("a deny rule: %+v", d)
	}
}

// The entry bound a search carries, and whether a rule raised it.
func TestTheEntryBoundIsCarriedWithTheDecision(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{MaxEntries: 50, DefaultAction: "allow"})
	d := decide(t, p, as{secure: true}, search(1, "", wire.ScopeSub, present("objectClass")))
	if d.Entries != 50 {
		t.Errorf("entries %d", d.Entries)
	}
	p = policyFor(t, &config.LDAPListener{MaxEntries: 50, DefaultAction: "deny",
		Rules: []config.LDAPRule{{Name: "reports", Action: "allow", MaxEntries: 5000}}})
	d = decide(t, p, as{secure: true}, search(2, "", wire.ScopeSub, present("objectClass")))
	if d.Entries != 5000 {
		t.Errorf("the rule's own bound was not used: %d", d.Entries)
	}
	// And the default, for a listener that named none.
	p = policyFor(t, &config.LDAPListener{DefaultAction: "allow"})
	d = decide(t, p, as{secure: true}, search(3, "", wire.ScopeSub, present("objectClass")))
	if d.Entries != 500 {
		t.Errorf("the default bound is %d", d.Entries)
	}
}

// The client list, which happens before anything is read.
func TestTheClientListHappensBeforeAnythingIsRead(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{
		AllowClients: []string{"10.0.0.0/24"}, DenyClients: []string{"10.0.0.9/32"}})
	for from, want := range map[string]bool{"10.0.0.7": true, "10.0.0.9": false, "10.1.0.7": false} {
		if got := p.Client(netip.MustParseAddr(from)); got != want {
			t.Errorf("client %s: %v", from, got)
		}
	}
}

// Everything that can be wrong about a rule is wrong at load.
func TestEveryBadRuleIsRefusedAtLoad(t *testing.T) {
	for what, l := range map[string]*config.LDAPListener{
		"a client that is not a net": {AllowClients: []string{"10.0.0.1"}},
		"a deny that is not a net":   {DenyClients: []string{"nonsense"}},
		"a method that is not one":   {Methods: []string{"kerberos"}},
		"a base that is not a name":  {BaseDNs: []string{"not a dn"}},
		"a rule client":              {Rules: []config.LDAPRule{{Name: "r", Clients: []string{"x"}}}},
		"a rule method":              {Rules: []config.LDAPRule{{Name: "r", Methods: []string{"x"}}}},
		"a rule bind dn":             {Rules: []config.LDAPRule{{Name: "r", BindDNs: []string{"="}}}},
		"an operation":               {Rules: []config.LDAPRule{{Name: "r", Operations: []string{"dump"}}}},
		"an access class":            {Rules: []config.LDAPRule{{Name: "r", Access: []string{"execute"}}}},
		"a rule base":                {Rules: []config.LDAPRule{{Name: "r", BaseDNs: []string{"x=,"}}}},
		"a rule deny base":           {Rules: []config.LDAPRule{{Name: "r", DenyDNs: []string{"="}}}},
		"a scope":                    {Rules: []config.LDAPRule{{Name: "r", Scopes: []string{"everything"}}}},
		"a schedule day": {Rules: []config.LDAPRule{{Name: "r",
			Schedule: &config.ModbusSchedule{Days: []string{"caturday"}}}}},
		"a schedule time": {Rules: []config.LDAPRule{{Name: "r",
			Schedule: &config.ModbusSchedule{From: "25:00"}}}},
	} {
		if _, err := compile(l, time.Now); err == nil {
			t.Errorf("%s compiled", what)
		}
	}
}

// A compare reads one attribute of one object, which is a read -- and it is
// also how a password is tested one value at a time where a search cannot see
// it, so an attribute policy has to cover it.
func TestACompareIsAReadAndIsCoveredByTheAttributePolicy(t *testing.T) {
	p := policyFor(t, &config.LDAPListener{DefaultAction: "allow"})
	if d := decide(t, p, as{secure: true, bound: "cn=app"},
		compare(1, "cn=alice,dc=example,dc=com", "employeeNumber", "42")); !d.Allow {
		t.Errorf("an ordinary compare was refused: %+v", d)
	}
	// The rule that makes a compare a read.
	p = policyFor(t, &config.LDAPListener{Rules: []config.LDAPRule{
		{Name: "reads", Action: "allow", Access: []string{"read"}},
	}})
	if d := decide(t, p, as{secure: true, bound: "cn=app"},
		compare(2, "cn=alice,dc=example,dc=com", "cn", "alice")); !d.Allow {
		t.Errorf("a compare did not match a read rule: %+v", d)
	}
	// An equality filter naming a password is the same oracle a compare is,
	// and is refused by the same list.
	d := decide(t, p, as{secure: true, bound: "cn=app"},
		search(3, "dc=example,dc=com", wire.ScopeSub, equality("userPassword", "guess")))
	if d.Allow || d.Reason != "ldap_filter_attribute" {
		t.Errorf("an equality filter on a password: %+v", d)
	}
}

// accessOf names what an operation does, so a policy about writing does not
// have to list the operations that write.
func TestAnOperationIsNamedByWhatItDoes(t *testing.T) {
	for _, c := range []struct {
		op   wire.Op
		want string
	}{
		{wire.OpBindRequest, "bind"},
		{wire.OpSearchRequest, "read"},
		{wire.OpCompareRequest, "read"},
		{wire.OpModifyRequest, "write"},
		{wire.OpAddRequest, "write"},
		{wire.OpDelRequest, "write"},
		{wire.OpModifyDNRequest, "write"},
		{wire.OpUnbindRequest, ""},
		{wire.OpExtendedRequest, ""},
	} {
		if got := accessOf(c.op); got != c.want {
			t.Errorf("%s does %q, wanted %q", c.op, got, c.want)
		}
	}
}
