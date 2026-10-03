package kkdcp

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/kerberos"
)

// The policy on its own.
//
// The end-to-end tests next door build real DER and drive it through the
// relay, which is what proves the parser and the policy agree. This file is
// about the policy's own shape: the validation that refuses a configuration
// at load, and the one-line cases for each refusal in order -- which on this
// kind matters more than usual, because which *leg* a check is on is a
// security property rather than a matter of taste.

func compiled(t *testing.T, c *config.KKDCPListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func yes() *bool  { b := true; return &b }
func offs() *bool { b := false; return &b }

func peer(s string) netip.Addr { return netip.MustParseAddr(s) }

var when = time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

// realms is the minimum a listener needs: a KDC proxy with no realm list is
// an open relay.
func realms(extra ...string) *config.KKDCPListener {
	return &config.KKDCPListener{Upstream: "kdc", Realms: append([]string{"CORP.EXAMPLE"}, extra...)}
}

// as is an AS-REQ as the relay's own request() builds one.
func as() Request {
	return Request{Client: peer("10.0.0.5"), TargetDomain: "CORP.EXAMPLE",
		Realm: "CORP.EXAMPLE", Type: wire.MsgASReq, Principal: "bob",
		ETypes: []wire.EType{wire.ETypeAES256SHA1}, Preauth: true, At: when}
}

// tgs is a TGS-REQ for a service, which is the message Kerberoasting is
// made of.
func tgs(service, class string) Request {
	r := as()
	r.Type, r.Service, r.ServiceClass = wire.MsgTGSReq, service, class
	return r
}

// A listener with no realms is refused at load, and the kind refuses it
// again rather than trusting that a validator ran.
func TestAListenerWithNoRealmListIsRefused(t *testing.T) {
	if _, err := compile(&config.KKDCPListener{Upstream: "kdc"}); err == nil ||
		!strings.Contains(err.Error(), "realms: required") {
		t.Fatalf("compile error is %v", err)
	}
}

// The defaults: what an operator gets by naming an upstream and a realm.
func TestTheDefaultsRefuseTheThreeWaysAKDCIsAbused(t *testing.T) {
	p := compiled(t, realms())

	if !p.refuseWeak {
		t.Error("an RC4-only request is carried by default")
	}
	if !p.refuseExempt {
		t.Error("a pre-authentication-exempt account's reply is carried by default, which is the cracking target")
	}
	for _, c := range []struct {
		name string
		on   bool
	}{
		{"allow_s4u2self", p.allowS4U2Self},
		{"allow_s4u2proxy", p.allowS4U2Proxy},
		{"allow_anonymous", p.allowAnonymous},
		{"allow_password_change", p.allowPassword},
		{"refuse_weak_ticket_etypes", p.refuseWeakTicket},
		{"require_target_domain", p.needTarget},
	} {
		if c.on {
			t.Errorf("%s is on by default", c.name)
		}
	}
	if !p.allowForwarded {
		t.Error("forwarded tickets are refused by default, which refuses ordinary delegation")
	}
	// The message types default to the two a KDC answers, and a
	// password-change AP-REQ is not one of them.
	if !p.types[wire.MsgASReq] || !p.types[wire.MsgTGSReq] || p.types[wire.MsgAPReq] {
		t.Errorf("the default message types are %v", p.types)
	}
	// And allow_password_change adds the third rather than needing the list
	// written out.
	pw := realms()
	pw.AllowPasswordChange = yes()
	if !compiled(t, pw).types[wire.MsgAPReq] {
		t.Error("allow_password_change did not add the AP-REQ to the default list")
	}
}

// A configuration that is wrong is wrong at load.
func TestCompileRefusesEveryNameItCannotRead(t *testing.T) {
	cases := []struct {
		name string
		edit func(*config.KKDCPListener)
		want string
	}{
		{"message_types", func(c *config.KKDCPListener) { c.MessageTypes = []string{"as-reqest"} },
			"message_types: \"as-reqest\" is not a request type"},
		{"etypes", func(c *config.KKDCPListener) { c.ETypes = []string{"aes512"} },
			"etypes: \"aes512\" is not an encryption type"},
		{"deny_etypes", func(c *config.KKDCPListener) { c.DenyETypes = []string{"rc5"} },
			"deny_etypes: \"rc5\" is not an encryption type"},
		{"deny_options", func(c *config.KKDCPListener) { c.DenyOptions = []string{"forwardabel"} },
			"deny_options: \"forwardabel\" is not a KDC option"},
		{"rules.clients", func(c *config.KKDCPListener) {
			c.Rules = []config.KKDCPRule{{Name: "r", Clients: []string{"dc1"}}}
		}, "rules[0].clients:"},
		{"rules.message_types", func(c *config.KKDCPListener) {
			c.Rules = []config.KKDCPRule{{Name: "r", MessageTypes: []string{"tgs-reqest"}}}
		}, "rules[0].message_types:"},
		{"rules.etypes", func(c *config.KKDCPListener) {
			c.Rules = []config.KKDCPRule{{Name: "r", ETypes: []string{"des4"}}}
		}, "rules[0].etypes:"},
		{"rules.schedule", func(c *config.KKDCPListener) {
			c.Rules = []config.KKDCPRule{{Name: "r",
				Schedule: &config.ModbusSchedule{Timezone: "Mars/Olympus"}}}
		}, "rules[0].schedule:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := realms()
			c.edit(cfg)
			if _, err := compile(cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
}

// The realm is decided first and is never shadowed, because a proxy that
// forwarded a message for a realm it does not serve is an open relay.
func TestTheRealmIsDecidedFirstAndEveryRefusalIsHard(t *testing.T) {
	p := compiled(t, realms())

	for _, c := range []struct {
		name           string
		target, realm  string
		reason, detail string
	}{
		{"a realm this proxy does not serve", "OTHER.EXAMPLE", "OTHER.EXAMPLE",
			"realm_not_allowed", "OTHER.EXAMPLE"},
		{"two realms that disagree", "CORP.EXAMPLE", "OTHER.EXAMPLE",
			"realm_mismatch", "CORP.EXAMPLE != OTHER.EXAMPLE"},
		{"an inner realm off the list", "", "OTHER.EXAMPLE",
			"realm_not_allowed", "OTHER.EXAMPLE"},
	} {
		d := p.Realm(Request{Client: peer("10.0.0.5"), TargetDomain: c.target, Realm: c.realm})
		if d.Allow || d.Reason != c.reason || d.Detail != c.detail || !d.Hard {
			t.Errorf("%s decided %+v, want %s/%s and hard", c.name, d, c.reason, c.detail)
		}
	}
	// Folded, because a realm is case-insensitive in every directory that
	// serves one.
	if d := p.Realm(Request{TargetDomain: "corp.example", Realm: "Corp.Example"}); !d.Allow {
		t.Errorf("the realm list is case-sensitive: %+v", d)
	}
	// A message with neither realm is not refused here: the envelope is
	// optional and the message's own realm is what the parser reads.
	if d := p.Realm(Request{Client: peer("10.0.0.5")}); !d.Allow {
		t.Errorf("a message naming no realm was refused by the realm policy: %+v", d)
	}
	// Unless the listener requires the envelope to say.
	strict := realms()
	strict.RequireTargetDomain = yes()
	d := compiled(t, strict).Realm(Request{Client: peer("10.0.0.5"), Realm: "CORP.EXAMPLE"})
	if d.Allow || d.Reason != "target_domain_required" || !d.Hard {
		t.Errorf("require_target_domain decided %+v", d)
	}
}

// The delegation and anonymity settings, each of which is one refusal and
// all of which are off by default.
func TestTheDelegationAndAnonymitySettingsEachRefuseOnce(t *testing.T) {
	p := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.DefaultAction = "allow"
		return c
	}())

	anon := as()
	anon.Anonymous = true
	if d := p.Decide(anon); d.Allow || d.Reason != "anonymous_not_allowed" {
		t.Fatalf("an anonymous request decided %+v", d)
	}
	self := tgs("host/dc1.corp.example", "host")
	self.S4U2Self = true
	if d := p.Decide(self); d.Allow || d.Reason != "s4u2self_not_allowed" || d.Detail != "bob" {
		t.Fatalf("an S4U2Self request decided %+v", d)
	}
	proxy := tgs("mssqlsvc/db1.corp.example", "mssqlsvc")
	proxy.S4U2Proxy = true
	if d := p.Decide(proxy); d.Allow || d.Reason != "s4u2proxy_not_allowed" ||
		d.Detail != "mssqlsvc/db1.corp.example" {
		t.Fatalf("an S4U2Proxy request decided %+v", d)
	}
	// A password-change AP-REQ reaches the type list first, and with the
	// type allowed and the setting off it is refused by name.
	pw := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.DefaultAction = "allow"
		c.MessageTypes = []string{"as-req", "tgs-req", "ap-req"}
		return c
	}())
	ap := as()
	ap.Type, ap.Service = wire.MsgAPReq, "kadmin/changepw"
	if d := pw.Decide(ap); d.Allow || d.Reason != "password_change_not_allowed" {
		t.Fatalf("a password change against allow_password_change: false decided %+v", d)
	}
	// And a type off the list is refused before any of it.
	if d := p.Decide(ap); d.Allow || d.Reason != "message_type_not_allowed" ||
		d.Detail != "ap-req" {
		t.Fatalf("a message type off the list decided %+v", d)
	}
}

// The KDC options, in the two forms: the forwarded-ticket pair and the
// explicit deny list.
func TestTheOptionsAreRefusedByPairAndByName(t *testing.T) {
	strict := realms()
	strict.DefaultAction = "allow"
	strict.AllowForwardedTickets = offs()
	p := compiled(t, strict)

	for _, o := range []wire.Options{wire.OptForwarded, wire.OptProxy} {
		req := as()
		req.Options = o
		if d := p.Decide(req); d.Allow || d.Reason != "forwarded_ticket_not_allowed" {
			t.Errorf("a request with %s decided %+v", o, d)
		}
	}
	// Forwardable is the right to be forwarded later, not a forwarded
	// ticket, so it is not this refusal.
	fw := as()
	fw.Options = wire.OptForwardable
	if d := p.Decide(fw); !d.Allow {
		t.Fatalf("a forwardable request was refused as a forwarded one: %+v", d)
	}
	named := realms()
	named.DefaultAction = "allow"
	named.DenyOptions = []string{"renewable", "enc-tkt-in-skey"}
	byName := compiled(t, named)
	u2u := as()
	u2u.Options = wire.OptEncTktInSkey
	if d := byName.Decide(u2u); d.Allow || d.Reason != "option_not_allowed" ||
		d.Detail != "enc-tkt-in-skey" {
		t.Fatalf("an option on the deny list decided %+v", d)
	}
}

// A service is matched on the whole name and on its class alone, which is
// the shape a real policy has: an estate knows which kinds of service it
// wants reachable long before it knows every instance's name.
func TestAServiceIsNamedWholeOrByItsClass(t *testing.T) {
	p := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.DefaultAction = "allow"
		c.Services = []string{"host", "cifs/files.corp.example"}
		c.DenyServices = []string{"mssqlsvc"}
		c.Principals = []string{"bob", "carol"}
		c.DenyPrincipals = []string{"krbtgt"}
		return c
	}())

	for _, c := range []struct {
		name, service, class string
		allow                bool
	}{
		{"by class", "host/dc1.corp.example", "host", true},
		{"by whole name", "cifs/files.corp.example", "cifs", true},
		{"a class off the list", "ldap/dc1.corp.example", "ldap", false},
		{"another instance of a named service", "cifs/other.corp.example", "cifs", false},
		{"a denied class", "mssqlsvc/db1.corp.example", "mssqlsvc", false},
	} {
		d := p.Decide(tgs(c.service, c.class))
		if d.Allow != c.allow {
			t.Errorf("%s (%s) decided %+v, want allow=%v", c.name, c.service, d, c.allow)
		}
		if !c.allow && (d.Reason != "service_not_allowed" || d.Detail != c.service) {
			t.Errorf("%s was refused as %q/%q", c.name, d.Reason, d.Detail)
		}
	}
	// The principal lists, which are read before the service lists because
	// a principal is who is asking.
	for _, c := range []struct {
		name, princ string
	}{{"a denied principal", "krbtgt"}, {"a principal off the list", "dave"}} {
		req := as()
		req.Principal = c.princ
		d := p.Decide(req)
		if d.Allow || d.Reason != "principal_not_allowed" || d.Detail != c.princ {
			t.Errorf("%s decided %+v", c.name, d)
		}
	}
	// A message carrying no principal is not measured against the list: a
	// TGS-REQ names its service and the principal is inside the ticket.
	bare := tgs("host/dc1.corp.example", "host")
	bare.Principal = ""
	if d := p.Decide(bare); !d.Allow {
		t.Fatalf("a request with no principal was refused by the principal list: %+v", d)
	}
}

// The encryption types are decided on the request, because that is the only
// point at which refusing costs nothing: by the time the reply exists the
// KDC has minted a ticket.
func TestTheEncryptionTypesAreDecidedOnTheRequest(t *testing.T) {
	p := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.DefaultAction = "allow"
		c.DenyETypes = []string{"des-cbc-crc"}
		return c
	}())

	des := as()
	des.ETypes = []wire.EType{wire.ETypeAES256SHA1, wire.ETypeDESCBCCRC}
	if d := p.Decide(des); d.Allow || d.Reason != "etype_not_allowed" ||
		d.Detail != "des-cbc-crc" {
		t.Fatalf("a request offering a denied type decided %+v", d)
	}
	// Only-weak rather than any-weak, and the distinction is the whole
	// setting: a Windows client lists aes256, aes128 and rc4 and the KDC
	// takes the first it can.
	rc4 := as()
	rc4.ETypes, rc4.OnlyWeak = []wire.EType{wire.ETypeRC4HMAC}, true
	d := p.Decide(rc4)
	if d.Allow || d.Reason != "weak_etype_only" || d.Detail != "rc4-hmac" {
		t.Fatalf("an RC4-only request decided %+v", d)
	}
	mixed := as()
	mixed.ETypes = []wire.EType{wire.ETypeAES256SHA1, wire.ETypeRC4HMAC}
	if d := p.Decide(mixed); !d.Allow {
		t.Fatalf("a mixed request was refused, which would refuse the estate: %+v", d)
	}
	// An allow list, listener-wide and then narrowed by the rule that
	// covers this traffic.
	only := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.DefaultAction = "allow"
		c.ETypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
		c.Rules = []config.KKDCPRule{{Name: "strict", Action: "allow",
			Clients: []string{"10.0.9.0/24"}, ETypes: []string{"aes256-cts-hmac-sha1-96"}}}
		return c
	}())
	aes128 := as()
	aes128.ETypes = []wire.EType{wire.ETypeAES128SHA1}
	if d := only.Decide(aes128); !d.Allow {
		t.Fatalf("a type on the listener's list was refused: %+v", d)
	}
	aes128.Client = peer("10.0.9.4")
	d = only.Decide(aes128)
	if d.Allow || d.Reason != "etype_not_allowed" || d.Rule != "strict" {
		t.Fatalf("the rule's own list did not narrow the policy: %+v", d)
	}
}

// The ticket lifetime bound, listener-wide and per rule.
func TestTheTicketLifetimeIsBoundedByTheRuleThatDecides(t *testing.T) {
	p := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.DefaultAction = "allow"
		c.MaxTicketLifetime = config.Duration(10 * time.Hour)
		c.Rules = []config.KKDCPRule{{Name: "long", Action: "allow",
			Principals: []string{"batch"}, MaxTicketLifetime: config.Duration(48 * time.Hour)}}
		return c
	}())

	long := as()
	long.Lifetime, long.HasLifetime = 24*time.Hour, true
	d := p.Decide(long)
	if d.Allow || d.Reason != "lifetime_too_long" || !strings.Contains(d.Detail, "above 10h0m0s") {
		t.Fatalf("a lifetime above the bound decided %+v", d)
	}
	// The rule that decides the request raises the bound for its own
	// traffic, which is how one batch account keeps its long ticket.
	long.Principal = "batch"
	if d := p.Decide(long); !d.Allow || d.Rule != "long" {
		t.Fatalf("the rule's own bound did not apply: %+v", d)
	}
	// A request that asks for nothing in particular is not measured, and
	// neither is anything on a listener with no bound.
	short := as()
	short.Lifetime, short.HasLifetime = time.Hour, true
	if d := p.Decide(short); !d.Allow {
		t.Fatalf("a lifetime under the bound was refused: %+v", d)
	}
	noBound := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.DefaultAction = "allow"
		return c
	}())
	if d := noBound.Decide(long); !d.Allow {
		t.Fatalf("a listener with no lifetime bound refused one: %+v", d)
	}
}

// The rules decide in order, and a rule's own deny list of services is read
// after it matched.
func TestTheRulesDecideInOrderAndCarryTheirOwnServiceDenyList(t *testing.T) {
	p := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.Rules = []config.KKDCPRule{
			{Name: "no-krbtgt", Action: "deny", Principals: []string{"krbtgt"}},
			{Name: "workstations", Action: "allow", Clients: []string{"10.0.0.0/24"},
				DenyServices: []string{"mssqlsvc"}},
			{Name: "night", Action: "allow", Clients: []string{"10.0.9.0/24"},
				Schedule: &config.ModbusSchedule{From: "22:00", To: "06:00"}},
		}
		return c
	}())

	krbtgt := as()
	krbtgt.Principal = "krbtgt"
	if d := p.Decide(krbtgt); d.Allow || d.Reason != "rule_denied" || d.Rule != "no-krbtgt" {
		t.Fatalf("the deny rule did not win: %+v", d)
	}
	if d := p.Decide(as()); !d.Allow || d.Rule != "workstations" {
		t.Fatalf("the allow rule did not decide its traffic: %+v", d)
	}
	sql := tgs("mssqlsvc/db1.corp.example", "mssqlsvc")
	d := p.Decide(sql)
	if d.Allow || d.Reason != "service_not_allowed" || d.Rule != "workstations" {
		t.Fatalf("the rule's own service deny list decided %+v", d)
	}
	night := as()
	night.Client = peer("10.0.9.4")
	if d := p.Decide(night); d.Allow || d.Reason != "outside_schedule" || d.Rule != "night" {
		t.Fatalf("a request outside the window decided %+v", d)
	}
	night.At = time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC)
	if d := p.Decide(night); !d.Allow {
		t.Fatalf("a request inside the window was refused: %+v", d)
	}
	off := as()
	off.Client = peer("192.0.2.1")
	if d := p.Decide(off); d.Allow || d.Reason != "no_rule_matched" {
		t.Fatalf("a request matching no rule decided %+v", d)
	}
}

// Every selector narrows, and a rule covers a request only when all of them
// match. The realm selector is the one with two readings: either realm on
// the message satisfies it, because the two have already been made to agree.
func TestARuleCoversOnlyWhatEverySelectorMatches(t *testing.T) {
	p := compiled(t, func() *config.KKDCPListener {
		c := realms("OTHER.EXAMPLE")
		c.DefaultAction = "allow"
		c.Rules = []config.KKDCPRule{{Name: "narrow", Action: "deny",
			Clients: []string{"10.0.0.0/24"}, Realms: []string{"CORP.EXAMPLE"},
			MessageTypes: []string{"tgs-req"}, Principals: []string{"bob"},
			Services: []string{"host"}}}
		return c
	}())
	covered := tgs("host/dc1.corp.example", "host")
	if d := p.Decide(covered); d.Allow {
		t.Fatalf("the rule did not cover what every selector names: %+v", d)
	}
	for _, c := range []struct {
		name string
		edit func(*Request)
	}{
		{"client", func(r *Request) { r.Client = peer("10.0.1.5") }},
		{"realm", func(r *Request) { r.Realm, r.TargetDomain = "OTHER.EXAMPLE", "OTHER.EXAMPLE" }},
		{"type", func(r *Request) { r.Type = wire.MsgASReq }},
		{"principal", func(r *Request) { r.Principal = "carol" }},
		{"service", func(r *Request) { r.Service, r.ServiceClass = "ldap/dc1", "ldap" }},
	} {
		req := covered
		c.edit(&req)
		if d := p.Decide(req); !d.Allow {
			t.Errorf("the rule still covered a request whose %s does not match: %+v", c.name, d)
		}
	}
	// A request carrying no service at all is not excluded by the service
	// selector: an AS-REQ has none, and a rule about a realm should still
	// cover it.
	bare := tgs("", "")
	if d := p.Decide(bare); d.Allow {
		t.Fatalf("the service selector excluded a request with no service: %+v", d)
	}
}

// An observe rule records and the search carries on.
func TestObserveRulesAreRecordedAndDecideNothingHere(t *testing.T) {
	p := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.DefaultAction = "allow"
		c.Rules = []config.KKDCPRule{
			{Name: "watch-realm", Action: "observe", Realms: []string{"CORP.EXAMPLE"}},
			{Name: "watch-net", Action: "observe", Clients: []string{"10.0.0.0/8"}},
			{Name: "no-sql", Action: "deny", Services: []string{"mssqlsvc"}},
		}
		return c
	}())
	d := p.Decide(tgs("mssqlsvc/db1.corp.example", "mssqlsvc"))
	if d.Allow || d.Reason != "rule_denied" || d.Rule != "no-sql" {
		t.Fatalf("the observe rules shadowed the deny rule below them: %+v", d)
	}
	if strings.Join(d.Observed, ",") != "watch-realm,watch-net" {
		t.Errorf("the observe rules recorded are %v, want both in order", d.Observed)
	}
	// And they are recorded on a request that was allowed, too -- a ticket
	// for a service the deny rule does not name.
	if ok := p.Decide(tgs("host/dc1.corp.example", "host")); !ok.Allow ||
		strings.Join(ok.Observed, ",") != "watch-realm,watch-net" {
		t.Fatalf("an allowed request recorded %v: %+v", ok.Observed, ok)
	}
}

// The reply leg: the exempt account, which is the one check that can only be
// made here, and the ticket's own encryption type.
func TestTheReplyLegRefusesTheCrackableAnswers(t *testing.T) {
	p := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.RefuseWeakTicketETypes = yes()
		return c
	}())

	exempt := Answer{Client: peer("10.0.0.5"), Type: wire.MsgASRep,
		PreauthExempt: true, Rule: "workstations", At: when}
	d := p.Answer(exempt)
	if d.Allow || d.Reason != "preauth_not_required" || !d.Hard || d.Rule != "workstations" {
		t.Fatalf("an exempt account's reply decided %+v, and the refusal must stand in shadow mode", d)
	}
	// The ticket's own type, which on a service ticket is the service
	// account's key and is what Kerberoasting is about.
	weak := Answer{Client: peer("10.0.0.5"), Type: wire.MsgTGSRep,
		TicketEType: wire.ETypeRC4HMAC, HasTicketEType: true, At: when}
	if d := p.Answer(weak); d.Allow || d.Reason != "weak_ticket_etype" ||
		d.Detail != "rc4-hmac" {
		t.Fatalf("an RC4 service ticket decided %+v", d)
	}
	strong := weak
	strong.TicketEType = wire.ETypeAES256SHA1
	if d := p.Answer(strong); !d.Allow {
		t.Fatalf("an AES service ticket was refused: %+v", d)
	}
	// Both checks are settings, and off they carry what they would have
	// refused.
	lax := compiled(t, func() *config.KKDCPListener {
		c := realms()
		c.RefusePreauthExempt = offs()
		return c
	}())
	if d := lax.Answer(exempt); !d.Allow {
		t.Fatalf("refuse_preauth_exempt: false still refused one: %+v", d)
	}
	if d := lax.Answer(weak); !d.Allow {
		t.Fatalf("refuse_weak_ticket_etypes defaults on: %+v", d)
	}
	// A KRB-ERROR grants nothing, so there is nothing on it to refuse.
	if d := p.Answer(Answer{Client: peer("10.0.0.5"), Type: wire.MsgError,
		IsError: true, ErrorCode: 25, At: when}); !d.Allow {
		t.Fatalf("a KRB-ERROR was refused: %+v", d)
	}
}

// The log line's rendering of what a request offered.
func TestTheOfferedTypesAreRenderedByName(t *testing.T) {
	got := etypeList([]wire.EType{wire.ETypeAES256SHA1, wire.ETypeRC4HMAC, 99})
	if got != "aes256-cts-hmac-sha1-96,rc4-hmac,etype(99)" {
		t.Errorf("etypeList rendered %q", got)
	}
	if got := etypeList(nil); got != "" {
		t.Errorf("an empty list rendered %q", got)
	}
}
