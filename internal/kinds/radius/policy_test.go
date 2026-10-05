package radius

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/radius"
)

// The policy on its own, without a socket.
//
// The end-to-end tests next door prove the relay carries what the policy
// allows and refuses what it does not, which is the part worth proving
// against real packets. What they cannot reach is the shape of the policy
// itself: the validation that turns a mistyped code name into a refusal at
// load rather than at the first login, and the branches of a decision that
// need a particular combination of listener settings and rules to reach.
// Those are here, where a case is three lines rather than a server, a
// client and a secret file.

func compiled(t *testing.T, c *config.RADIUSListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func yes() *bool     { b := true; return &b }
func off() *bool     { b := false; return &b }
func lvl(n int) *int { return &n }

var noon = time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

func from(s string) netip.Addr { return netip.MustParseAddr(s) }

// access builds an Access-Request the way the relay's request() does, with
// the fields a policy reads and nothing else.
func access(user string) Request {
	return Request{Client: from("10.0.0.5"), Code: wire.CodeAccessRequest, ID: 7,
		User: user, AuthType: wire.AuthPAP, At: noon}
}

// The defaults are what an operator gets by writing `radius: {upstream: r}`,
// and on this protocol the ones that matter are the two integrity checks and
// the three codes that are *not* in the list.
func TestTheDefaultsAreTheOnesThatMatter(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r"})

	if !p.needMAC || !p.NeedMAC(from("10.0.0.5")) {
		t.Error("Message-Authenticator is not required by default, which is the Blast-RADIUS mitigation")
	}
	if !p.verifyResp {
		t.Error("the response authenticator is not verified by default")
	}
	if !p.refuseWeak {
		t.Error("the weak EAP methods are allowed by default")
	}
	if p.dynamic {
		t.Error("the dynamic authorization codes are carried by default")
	}
	if p.maxPriv != 15 {
		t.Errorf("the default privilege bound is %d, not 15, which would bound a reply nobody asked to bound", p.maxPriv)
	}
	// The four a client sends are on the list and nothing else is: a
	// listener with no `codes` line is not one that carries
	// Disconnect-Request.
	for _, c := range []wire.Code{wire.CodeAccessRequest, wire.CodeAccountingRequest,
		wire.CodeStatusServer, wire.CodeStatusClient} {
		if !p.codes[c] {
			t.Errorf("%s is not allowed by default", c)
		}
	}
	if len(p.codes) != 4 {
		t.Errorf("the default code list has %d codes", len(p.codes))
	}
	// A request matching no rule takes the default action, which is deny:
	// a listener written with an upstream and nothing else carries nothing.
	if d := p.Decide(access("bob")); d.Allow || d.Reason != "no_rule_matched" {
		t.Errorf("the default action is not deny: %+v", d)
	}
	for _, c := range []wire.Code{wire.CodeDisconnectRequest, wire.CodeCoARequest} {
		d := p.Decide(Request{Client: from("10.0.0.5"), Code: c, At: noon})
		if d.Allow {
			t.Errorf("%s is carried by default", c)
		}
		if d.Reason != "dynamic_authorization_not_allowed" || !d.Hard {
			t.Errorf("%s is refused as %q hard=%v, which should stand in shadow mode", c, d.Reason, d.Hard)
		}
	}
	// An Access-Accept is not something a client sends, and the code list
	// is read in the one direction: on a listener that allows by default
	// it is still refused by the list rather than carried.
	open := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow"})
	d := open.Decide(Request{Client: from("10.0.0.5"), Code: wire.CodeAccessAccept, At: noon})
	if d.Allow || d.Reason != "code_not_allowed" {
		t.Errorf("an Access-Accept is accepted as a request: %+v", d)
	}
}

// A configuration that is wrong is wrong at load. Every one of these is a
// name somebody could plausibly mistype, and each has to name the field it
// was written in: an error that said only `"peep" is not an EAP method`
// leaves an operator grepping a thousand-line file for it.
func TestCompileRefusesEveryNameItCannotRead(t *testing.T) {
	bad := config.RADIUSRule{Name: "bad"}
	cases := []struct {
		name string
		cfg  config.RADIUSListener
		want string
	}{
		{"allow_clients", config.RADIUSListener{AllowClients: []string{"not-an-address"}}, "allow_clients:"},
		{"deny_clients", config.RADIUSListener{DenyClients: []string{"10.0.0.0/33"}}, "deny_clients:"},
		{"codes", config.RADIUSListener{Codes: []string{"access-reqeust"}}, "codes: \"access-reqeust\" is not a code"},
		{"deny_codes", config.RADIUSListener{DenyCodes: []string{"coa-reqeust"}}, "deny_codes: \"coa-reqeust\" is not a code"},
		{"auth_types", config.RADIUSListener{AuthTypes: []string{"mschapv3"}}, "auth_types: \"mschapv3\" is not an authentication method"},
		{"eap_types", config.RADIUSListener{EAPTypes: []string{"peep"}}, "eap_types: \"peep\" is not an EAP method"},
		{"deny_eap_types", config.RADIUSListener{DenyEAPTypes: []string{"md6"}}, "deny_eap_types: \"md6\" is not an EAP method"},
		{"deny_attributes", config.RADIUSListener{DenyAttributes: []string{"proxy-stat"}}, "deny_attributes: \"proxy-stat\" is not an attribute"},
		{"deny_reply_attributes", config.RADIUSListener{DenyReplyAttributes: []string{"vlan"}}, "deny_reply_attributes: \"vlan\" is not an attribute"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.cfg
			cfg.Upstream = "r"
			if _, err := compile(&cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// The same names inside a rule, which have to name the rule's index as
	// well as the field.
	rules := []struct {
		name string
		rule config.RADIUSRule
		want string
	}{
		{"clients", config.RADIUSRule{Name: "r", Clients: []string{"ten.oh.oh.oh"}}, "rules[0].clients:"},
		{"codes", config.RADIUSRule{Name: "r", Codes: []string{"statuss"}}, "rules[0].codes:"},
		{"auth_types", config.RADIUSRule{Name: "r", AuthTypes: []string{"ntlm"}}, "rules[0].auth_types:"},
		{"eap_types", config.RADIUSRule{Name: "r", EAPTypes: []string{"tlsv2"}}, "rules[0].eap_types:"},
		{"schedule", config.RADIUSRule{Name: "r", Schedule: &config.ModbusSchedule{Days: []string{"funday"}}}, "rules[0].schedule:"},
	}
	for _, c := range rules {
		t.Run("rule_"+c.name, func(t *testing.T) {
			cfg := config.RADIUSListener{Upstream: "r", Rules: []config.RADIUSRule{bad, c.rule}}
			cfg.Rules[0] = c.rule
			cfg.Rules = cfg.Rules[:1]
			if _, err := compile(&cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
}

// A code and an attribute may be written as a number, because the installed
// base carries vendor codes the name table does not have.
func TestANameListAlsoReadsNumbers(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", Codes: []string{"1", "4"},
		DenyAttributes: []string{"33"}, EAPTypes: []string{"25"}})
	if !p.codes[wire.CodeAccessRequest] || !p.codes[wire.CodeAccountingRequest] {
		t.Error("a numeric code list did not compile to the codes it names")
	}
	if !p.denyAttrs[wire.AttrProxyState] {
		t.Error("a numeric attribute list did not compile to the attribute it names")
	}
	if !p.eap[wire.EAPTypePEAP] {
		t.Error("a numeric EAP list did not compile to the method it names")
	}
	// And the short forms an operator is likely to write.
	short := compiled(t, &config.RADIUSListener{Upstream: "r",
		Codes: []string{"auth", "acct", "status"}, DenyCodes: []string{"coa", "disconnect"}})
	if !short.codes[wire.CodeAccessRequest] || !short.codes[wire.CodeAccountingRequest] ||
		!short.codes[wire.CodeStatusServer] {
		t.Error("the short code names did not compile to the codes they name")
	}
	if !short.denyCodes[wire.CodeCoARequest] || !short.denyCodes[wire.CodeDisconnectRequest] {
		t.Error("the short dynamic-authorization names did not compile")
	}
}

// The address lists are answered before a packet is parsed, so they are the
// only policy a malformed datagram meets.
func TestTheClientListsAreAnsweredFirstAndDenyWins(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r",
		AllowClients: []string{"10.0.0.0/24", "192.168.1.7"},
		DenyClients:  []string{"10.0.0.9"}})
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},
		{"192.168.1.7", true}, // a bare address is a host route
		{"10.0.0.9", false},   // on the allow list and on the deny list
		{"10.0.1.5", false},
	} {
		if got := p.Client(from(c.ip)); got != c.want {
			t.Errorf("Client(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	// With no allow list every address that is not denied is admitted,
	// because a listener on a management network is already bound by where
	// it listens.
	open := compiled(t, &config.RADIUSListener{Upstream: "r", DenyClients: []string{"10.0.0.9"}})
	if !open.Client(from("203.0.113.1")) || open.Client(from("10.0.0.9")) {
		t.Error("with no allow list the deny list alone did not decide")
	}
}

// deny_codes is read before the allow list and before the dynamic
// authorization check, so naming a code in both lists refuses it.
func TestADeniedCodeCannotBeAllowedByACodeList(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		Codes: []string{"access-request", "status-server"}, DenyCodes: []string{"status-server"}})
	d := p.Decide(Request{Client: from("10.0.0.5"), Code: wire.CodeStatusServer, At: noon})
	if d.Allow || d.Reason != "code_not_allowed" || d.Detail != "status-server" {
		t.Fatalf("a code on both lists decided %+v", d)
	}
	if d := p.Decide(access("bob")); !d.Allow {
		t.Fatalf("the code that is only on the allow list was refused: %+v", d)
	}
}

// Proxy-State and the attribute deny list are read off the request's type
// list, which is all the relay keeps: the values are a session's own data.
func TestTheAttributeListsReadTheTypesARequestCarried(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		RefuseProxyState: yes(), DenyAttributes: []string{"tunnel-private-group-id"}})

	req := access("bob")
	req.Attrs = []wire.AttrType{wire.AttrUserName, wire.AttrProxyState}
	if d := p.Decide(req); d.Allow || d.Reason != "proxy_state_not_allowed" {
		t.Fatalf("a request carrying Proxy-State decided %+v", d)
	}
	req.Attrs = []wire.AttrType{wire.AttrUserName, wire.AttrTunnelPrivateGroupID}
	if d := p.Decide(req); d.Allow || d.Reason != "attribute_not_allowed" ||
		d.Detail != "tunnel-private-group-id" {
		t.Fatalf("a request carrying a denied attribute decided %+v", d)
	}
	req.Attrs = []wire.AttrType{wire.AttrUserName, wire.AttrNASIdentifier}
	if d := p.Decide(req); !d.Allow {
		t.Fatalf("a request carrying neither was refused: %+v", d)
	}
}

// refuse_plaintext_passwords is about the credential shape rather than the
// attribute, because that is what an estate decides: no more PAP.
func TestPlaintextPasswordsAreRefusedByShape(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		RefusePlaintextPasswords: yes()})
	if d := p.Decide(access("bob")); d.Allow || d.Reason != "plaintext_password" {
		t.Fatalf("a PAP request decided %+v", d)
	}
	chap := access("bob")
	chap.AuthType = wire.AuthCHAP
	if d := p.Decide(chap); !d.Allow {
		t.Fatalf("a CHAP request was refused by the plaintext setting: %+v", d)
	}
}

// The credential allow list is listener-wide, and a rule that names its own
// replaces it for the traffic that rule covers -- which is how one old
// concentrator keeps CHAP while the estate is on EAP.
func TestTheCredentialListIsListenerWideUnlessARuleNarrowsIt(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		AuthTypes: []string{"eap"},
		Rules: []config.RADIUSRule{{Name: "old-wlc", Action: "allow",
			Clients: []string{"10.0.9.9"}, AuthTypes: []string{"chap"}}}})

	pap := access("bob")
	if d := p.Decide(pap); d.Allow || d.Reason != "auth_type_not_allowed" || d.Detail != "pap" {
		t.Fatalf("a PAP request against an eap-only listener decided %+v", d)
	}
	old := access("bob")
	old.Client, old.AuthType = from("10.0.9.9"), wire.AuthCHAP
	if d := p.Decide(old); !d.Allow || d.Rule != "old-wlc" {
		t.Fatalf("the rule's own credential list did not admit its traffic: %+v", d)
	}
	// A rule's credential list is a selector as well as a policy, so the
	// rule does not cover EAP from that address at all and the listener's
	// own list decides it -- which allows it. That is the reading worth
	// writing down: naming chap on a rule exempts chap, it does not confine
	// that address to chap.
	eap := access("bob")
	eap.Client, eap.AuthType = from("10.0.9.9"), wire.AuthEAP
	if d := p.Decide(eap); !d.Allow {
		t.Fatalf("EAP from the exempted address was refused: %+v", d)
	}
	// And a credential on neither list is refused there as everywhere else.
	ms := access("bob")
	ms.Client, ms.AuthType = from("10.0.9.9"), wire.AuthMSCHAP
	if d := p.Decide(ms); d.Allow || d.Reason != "auth_type_not_allowed" {
		t.Fatalf("a credential on neither list was carried: %+v", d)
	}
}

// The offers matter as much as the method: a Nak naming EAP-MD5 is a client
// asking the server to downgrade, and the type in the packet is Nak.
func TestTheEAPPolicyReadsTheOffersAsWellAsTheMethod(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow"})

	nak := access("bob")
	nak.AuthType, nak.HasEAP, nak.EAPType = wire.AuthEAP, true, wire.EAPTypeNak
	nak.EAPOffers = []wire.EAPType{wire.EAPTypeMD5Challenge}
	d := p.Decide(nak)
	if d.Allow || d.Reason != "weak_eap_type" || d.Detail != "offered md5-challenge" {
		t.Fatalf("a Nak offering EAP-MD5 decided %+v", d)
	}
	// RFC 3748 §5.3.1's zero is a client giving up rather than asking for
	// something, and refusing it would refuse the end of a legitimate
	// exchange.
	nak.EAPOffers = []wire.EAPType{0}
	if d := p.Decide(nak); !d.Allow {
		t.Fatalf("a Nak with no acceptable method was refused: %+v", d)
	}
	// Identity, Notification and Nak carry no credential, so they are not
	// measured against the method list at all.
	only := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		EAPTypes: []string{"peap"}})
	for _, e := range []wire.EAPType{wire.EAPTypeIdentity, wire.EAPTypeNotification, wire.EAPTypeNak} {
		req := access("bob")
		req.AuthType, req.HasEAP, req.EAPType = wire.AuthEAP, true, e
		if d := only.Decide(req); !d.Allow {
			t.Errorf("the negotiation's own type %s was measured against the method list: %+v", e, d)
		}
	}
	// And the method itself is.
	tls := access("bob")
	tls.AuthType, tls.HasEAP, tls.EAPType = wire.AuthEAP, true, wire.EAPTypeTLS
	if d := only.Decide(tls); d.Allow || d.Reason != "eap_type_not_allowed" || d.Detail != "tls" {
		t.Fatalf("a method outside the list decided %+v", d)
	}
	peap := access("bob")
	peap.AuthType, peap.HasEAP, peap.EAPType = wire.AuthEAP, true, wire.EAPTypePEAP
	if d := only.Decide(peap); !d.Allow {
		t.Fatalf("the one method on the list was refused: %+v", d)
	}
	// deny_eap_types is read before the weak check and before the allow
	// list, so a method can be refused while weak ones are tolerated.
	deny := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		RefuseWeakEAP: off(), DenyEAPTypes: []string{"leap"}})
	leap := access("bob")
	leap.AuthType, leap.HasEAP, leap.EAPType = wire.AuthEAP, true, wire.EAPTypeLEAP
	if d := deny.Decide(leap); d.Allow || d.Reason != "eap_type_not_allowed" {
		t.Fatalf("a denied method decided %+v", d)
	}
	md5 := access("bob")
	md5.AuthType, md5.HasEAP, md5.EAPType = wire.AuthEAP, true, wire.EAPTypeMD5Challenge
	if d := deny.Decide(md5); !d.Allow {
		t.Fatalf("refuse_weak_eap: false did not carry EAP-MD5: %+v", d)
	}
	// A request with no EAP at all is not measured against any of it.
	if d := deny.Decide(access("bob")); !d.Allow {
		t.Fatalf("a request with no EAP met the EAP policy: %+v", d)
	}
}

// A rule's EAP list is a selector as well as a policy, and the two readings
// meet on a Nak: the rule is selected by the method in the packet and then
// bounds what that exchange may be talked down to.
func TestARuleNarrowsWhatItsOwnTrafficMayBeTalkedDownTo(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		RefuseWeakEAP: off(),
		Rules: []config.RADIUSRule{{Name: "wifi", Action: "allow",
			Clients: []string{"10.0.9.0/24"}, EAPTypes: []string{"peap", "tls"}}}})
	req := access("bob")
	req.Client, req.AuthType, req.HasEAP, req.EAPType = from("10.0.9.4"), wire.AuthEAP, true, wire.EAPTypePEAP
	req.EAPOffers = []wire.EAPType{wire.EAPTypeGTC}
	if d := p.Decide(req); d.Allow || d.Reason != "eap_type_not_allowed" ||
		d.Detail != "offered gtc" {
		t.Fatalf("the rule's method list did not bound the offers: %+v", d)
	}
	req.EAPOffers = []wire.EAPType{wire.EAPTypeTLS}
	if d := p.Decide(req); !d.Allow || d.Rule != "wifi" {
		t.Fatalf("an offer on the rule's list was refused: %+v", d)
	}
	// Outside the rule's networks the listener's own policy decides, which
	// here has no list at all.
	other := access("bob")
	other.AuthType, other.HasEAP, other.EAPType = wire.AuthEAP, true, wire.EAPTypeGTC
	if d := p.Decide(other); !d.Allow {
		t.Fatalf("the rule's method list reached traffic it does not cover: %+v", d)
	}
}

// The name lists only apply to the codes that carry a name. A status query
// has none, and refusing one for not being on a user list would refuse
// every health check the estate's monitoring sends.
func TestTheNameListsOnlyApplyToTheCodesThatCarryAName(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		Users: []string{"Bob", "carol"}, DenyUsers: []string{"root"},
		Realms: []string{"CORP"}, DenyRealms: []string{"guest"},
		NASIdentifiers: []string{"wlc-1"}})

	named := func(user, realm, nas string) Request {
		req := access(user)
		req.Realm, req.NASID = realm, nas
		return req
	}
	// Folded on both sides, because every server that fronts a directory
	// is case-insensitive and a policy that was not would admit Bob and
	// refuse bob.
	if d := p.Decide(named("BOB", "corp", "WLC-1")); !d.Allow {
		t.Fatalf("the name lists are case-sensitive: %+v", d)
	}
	for _, c := range []struct {
		name           string
		req            Request
		reason, detail string
	}{
		{"denied user", named("root", "corp", "wlc-1"), "user_not_allowed", "root"},
		{"user off the list", named("dave", "corp", "wlc-1"), "user_not_allowed", "dave"},
		{"denied realm", named("bob", "guest", "wlc-1"), "realm_not_allowed", "guest"},
		{"realm off the list", named("bob", "partner", "wlc-1"), "realm_not_allowed", "partner"},
		{"nas off the list", named("bob", "corp", "wlc-9"), "nas_not_allowed", "wlc-9"},
	} {
		d := p.Decide(c.req)
		if d.Allow || d.Reason != c.reason || d.Detail != c.detail {
			t.Errorf("%s decided %+v, want %s/%s", c.name, d, c.reason, c.detail)
		}
	}
	// The same lists, and a status query that carries none of it.
	status := Request{Client: from("10.0.0.5"), Code: wire.CodeStatusServer, At: noon}
	if d := p.Decide(status); !d.Allow {
		t.Fatalf("a status query was measured against the name lists: %+v", d)
	}
	// An accounting record is named traffic and is measured.
	acct := named("dave", "corp", "wlc-1")
	acct.Code = wire.CodeAccountingRequest
	if d := p.Decide(acct); d.Allow {
		t.Fatalf("an accounting request escaped the name lists: %+v", d)
	}
}

// require_realm refuses the bare names, which is where a misconfigured
// supplicant and a hand-typed login both land.
func TestRequireRealmRefusesABareName(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		RequireRealm: yes()})
	if d := p.Decide(access("bob")); d.Allow || d.Reason != "realm_required" || d.Detail != "bob" {
		t.Fatalf("a bare name against require_realm decided %+v", d)
	}
	req := access("bob@corp")
	req.Realm = "corp"
	if d := p.Decide(req); !d.Allow {
		t.Fatalf("a name with a realm was refused: %+v", d)
	}
	// Without it a bare name is carried, and the realm lists are simply
	// not consulted.
	open := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		Realms: []string{"corp"}})
	if d := open.Decide(access("bob")); !d.Allow {
		t.Fatalf("a bare name was measured against the realm allow list: %+v", d)
	}
}

// Message-Authenticator is answered before the rules decide anything,
// because it is an integrity question -- and it is answered by the rules,
// because the one piece of equipment too old to send one is written down as
// a rule rather than by turning the check off for the estate.
func TestNeedMACIsAnsweredByAddressAlone(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r",
		Rules: []config.RADIUSRule{
			// An observe rule decides nothing, here as everywhere else.
			{Name: "watch", Action: "observe", Clients: []string{"10.0.0.0/8"},
				RequireMessageAuthenticator: off()},
			// A rule with no network cannot be matched on the address
			// alone, so it is not read for this question at all.
			{Name: "by-user", Action: "allow", Users: []string{"bob"},
				RequireMessageAuthenticator: off()},
			{Name: "old-switch", Action: "allow", Clients: []string{"10.0.9.9"},
				RequireMessageAuthenticator: off()},
			// A rule that names a network and says nothing about the check
			// leaves the listener's answer alone.
			{Name: "rest", Action: "allow", Clients: []string{"10.0.0.0/8"}},
		}})
	if !p.NeedMAC(from("10.0.0.5")) {
		t.Error("an observe rule, or a rule that says nothing, turned the integrity check off")
	}
	if p.NeedMAC(from("10.0.9.9")) {
		t.Error("the one rule written for the old switch did not exempt it")
	}
	if !p.NeedMAC(from("192.0.2.1")) {
		t.Error("an address no rule covers lost the listener's own setting")
	}
	// And a rule may require it where the listener does not.
	strict := compiled(t, &config.RADIUSListener{Upstream: "r",
		RequireMessageAuthenticator: off(),
		Rules: []config.RADIUSRule{{Name: "new", Action: "allow",
			Clients: []string{"10.0.0.0/24"}, RequireMessageAuthenticator: yes()}}})
	if !strict.NeedMAC(from("10.0.0.5")) || strict.NeedMAC(from("10.0.1.5")) {
		t.Error("a rule did not raise the check above the listener's setting")
	}
}

// The rules decide in order, first match wins, and a request that matches
// none takes the default action.
func TestTheRulesDecideInOrderAndTheDefaultDecidesTheRest(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r",
		Rules: []config.RADIUSRule{
			{Name: "no-root", Action: "deny", Users: []string{"root"}},
			{Name: "corp", Action: "allow", Realms: []string{"corp"}},
		}})
	req := access("root")
	req.Realm = "corp"
	if d := p.Decide(req); d.Allow || d.Reason != "rule_denied" || d.Rule != "no-root" {
		t.Fatalf("the first rule did not win: %+v", d)
	}
	ok := access("bob")
	ok.Realm = "corp"
	if d := p.Decide(ok); !d.Allow || d.Rule != "corp" {
		t.Fatalf("the second rule did not allow its traffic: %+v", d)
	}
	none := access("bob")
	none.Realm = "partner"
	if d := p.Decide(none); d.Allow || d.Reason != "no_rule_matched" {
		t.Fatalf("a request matching no rule decided %+v under the default deny", d)
	}
	open := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow"})
	if d := open.Decide(access("bob")); !d.Allow || d.Reason != "" {
		t.Fatalf("default_action: allow refused a request no rule covered: %+v", d)
	}
}

// A schedule is read after the rule matched, so a request outside the
// window is refused by name rather than falling through to the next rule:
// the rule for it is the one that says when.
func TestAScheduledRuleRefusesOutsideItsWindow(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r",
		Rules: []config.RADIUSRule{{Name: "office-hours", Action: "allow",
			Schedule: &config.ModbusSchedule{Days: []string{"wed"}, From: "09:00", To: "17:00"}}}})
	if d := p.Decide(access("bob")); !d.Allow || d.Rule != "office-hours" {
		t.Fatalf("a request inside the window was refused: %+v", d)
	}
	night := access("bob")
	night.At = time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC)
	if d := p.Decide(night); d.Allow || d.Reason != "outside_schedule" || d.Rule != "office-hours" {
		t.Fatalf("a request outside the window decided %+v", d)
	}
}

// An observe rule records and the search carries on. A rule that stopped
// the search would allow everything it covered, so trying a rule out would
// have been a way to turn off every deny rule below it.
func TestAnObserveRuleIsRecordedAndDecidesNothing(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		Rules: []config.RADIUSRule{
			{Name: "watch-pap", Action: "observe", AuthTypes: []string{"pap"}},
			{Name: "watch-all", Action: "observe", Clients: []string{"10.0.0.0/8"}},
			{Name: "no-root", Action: "deny", Users: []string{"root"}},
		}})
	d := p.Decide(access("root"))
	if d.Allow || d.Reason != "rule_denied" || d.Rule != "no-root" {
		t.Fatalf("the observe rules above the deny rule shadowed it: %+v", d)
	}
	if strings.Join(d.Observed, ",") != "watch-pap,watch-all" {
		t.Errorf("the observe rules recorded are %v, want both in order", d.Observed)
	}
	// And they are recorded on a request that was allowed, too, which is
	// the line an operator reads to find out what the rule would cover.
	ok := p.Decide(access("bob"))
	if !ok.Allow || strings.Join(ok.Observed, ",") != "watch-pap,watch-all" {
		t.Fatalf("an allowed request recorded %v: %+v", ok.Observed, ok)
	}
}

// Every selector narrows, and a rule covers a request only when all of them
// match.
func TestARuleCoversOnlyWhatEverySelectorMatches(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", DefaultAction: "allow",
		Rules: []config.RADIUSRule{{Name: "narrow", Action: "deny",
			Clients: []string{"10.0.0.0/24"}, Codes: []string{"access-request"},
			AuthTypes: []string{"pap"}, Users: []string{"bob"}, Realms: []string{"corp"},
			NASIdentifiers: []string{"wlc-1"}}}})
	covered := access("bob")
	covered.Realm, covered.NASID = "corp", "wlc-1"
	if d := p.Decide(covered); d.Allow {
		t.Fatalf("the rule did not cover the request every selector names: %+v", d)
	}
	for _, c := range []struct {
		name string
		edit func(*Request)
	}{
		{"client", func(r *Request) { r.Client = from("10.0.1.5") }},
		{"code", func(r *Request) { r.Code = wire.CodeAccountingRequest }},
		{"auth type", func(r *Request) { r.AuthType = wire.AuthCHAP }},
		{"user", func(r *Request) { r.User = "carol" }},
		{"realm", func(r *Request) { r.Realm = "partner" }},
		{"nas", func(r *Request) { r.NASID = "wlc-2" }},
	} {
		req := covered
		c.edit(&req)
		if d := p.Decide(req); !d.Allow {
			t.Errorf("the rule still covered a request whose %s does not match: %+v", c.name, d)
		}
	}
}

// The reply leg is a different policy from the request leg, because a reply
// is a grant and what a policy can do with a grant is bound it.
func TestTheReplyLegBoundsWhatIsGranted(t *testing.T) {
	p := compiled(t, &config.RADIUSListener{Upstream: "r", MaxPrivilegeLevel: lvl(1),
		DenyAdministrativeReplies: yes(),
		DenyReplyAttributes:       []string{"tunnel-private-group-id"},
		Rules: []config.RADIUSRule{{Name: "jump-host", Action: "allow",
			Clients: []string{"10.0.9.9"}, MaxPrivilegeLevel: lvl(15)}}})

	accept := func() Reply {
		return Reply{Client: from("10.0.0.5"), Code: wire.CodeAccessAccept, At: noon}
	}
	vlan := accept()
	vlan.Attrs = []wire.AttrType{wire.AttrTunnelPrivateGroupID}
	if d := p.Reply(vlan); d.Allow || d.Reason != "reply_attribute_not_allowed" ||
		d.Detail != "tunnel-private-group-id" {
		t.Fatalf("a reply carrying a denied attribute decided %+v", d)
	}
	admin := accept()
	admin.Administrative = true
	if d := p.Reply(admin); d.Allow || d.Reason != "administrative_reply_not_allowed" {
		t.Fatalf("an administrative reply decided %+v", d)
	}
	high := accept()
	high.HasPrivilege, high.Privilege = true, 15
	d := p.Reply(high)
	if d.Allow || d.Reason != "privilege_too_high" || d.Detail != "priv-lvl=15 above 1" {
		t.Fatalf("a reply granting enable decided %+v", d)
	}
	// The rule that allowed the question bounds the answer, which is how
	// the one jump host that really does get enable is written down.
	jump := accept()
	jump.HasPrivilege, jump.Privilege, jump.Rule = true, 15, "jump-host"
	if d := p.Reply(jump); !d.Allow {
		t.Fatalf("the rule's own bound did not apply to its reply: %+v", d)
	}
	// A name that is not a rule's falls back to the listener's bound
	// rather than to no bound at all.
	stray := accept()
	stray.HasPrivilege, stray.Privilege, stray.Rule = true, 15, "deleted-rule"
	if d := p.Reply(stray); d.Allow {
		t.Fatalf("an unknown rule name lifted the listener's bound: %+v", d)
	}
	low := accept()
	low.HasPrivilege, low.Privilege = true, 1
	if d := p.Reply(low); !d.Allow {
		t.Fatalf("a reply at the bound was refused: %+v", d)
	}
	// A reply with no privilege in it is not a grant to bound.
	if d := p.Reply(accept()); !d.Allow {
		t.Fatalf("a plain Access-Accept was refused: %+v", d)
	}
}

// The anomaly models are shared with every other kind; what is this kind's
// own is the translation into them.
func TestTheAnomalyEventNamesTheMethodAndTheRealm(t *testing.T) {
	req := access("bob")
	req.Realm, req.NASID = "corp", "wlc-1"
	e := anomalyEvent(req, noon)
	if e.Symbol != "access-request/pap" {
		t.Errorf("the symbol is %q, so a NAS that switches from PEAP to PAP is not a change", e.Symbol)
	}
	if e.Device != "wlc-1" || e.Point != "corp" {
		t.Errorf("the event names device %q point %q", e.Device, e.Point)
	}
	if e.Actor != req.Client || !e.At.Equal(noon) {
		t.Errorf("the event names actor %v at %v", e.Actor, e.At)
	}
	// A status query has no credential, and a symbol with a trailing
	// slash would make every one of them its own symbol.
	bare := Request{Client: from("10.0.0.5"), Code: wire.CodeStatusServer}
	if s := anomalyEvent(bare, noon).Symbol; s != "status-server" {
		t.Errorf("a request with no credential has symbol %q", s)
	}
}

// The log line's rendering of a Nak's offers, which is what an operator
// reads to see which way a downgrade was asked for.
func TestTheOfferListIsRenderedByName(t *testing.T) {
	got := offers([]wire.EAPType{wire.EAPTypeMD5Challenge, wire.EAPTypePEAP, 99})
	if got != "md5-challenge,peap,eap-type(99)" {
		t.Errorf("offers rendered %q", got)
	}
	if got := offers(nil); got != "" {
		t.Errorf("an empty offer list rendered %q", got)
	}
}
