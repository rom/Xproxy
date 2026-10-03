package tacacs

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/engineering"
	wire "github.com/rom/xproxy/internal/tacacs"
)

// The policy on its own.
//
// The end-to-end tests next door drive a device against a server through the
// relay, which is what proves the command lists reach real traffic. What
// they cannot reach cheaply is the validation that refuses a configuration
// at load, the pattern grammar's own edges, and the combinations of
// listener settings that each lead to one refusal. A case here is three
// lines rather than a session.

func compiled(t *testing.T, c *config.TACACSListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func yes() *bool               { b := true; return &b }
func offs() *bool              { b := false; return &b }
func lvl(n int) *int           { return &n }
func host(s string) netip.Addr { return netip.MustParseAddr(s) }

var midday = time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

// login is an authentication start as the relay's own request() builds one.
func login() Request {
	return Request{Client: host("10.0.0.5"), Exchange: wire.TypeAuthen, Seq: 1,
		Session: 1, Action: wire.ActionLogin, AuthenType: wire.AuthenASCII,
		Service: wire.ServiceLogin, User: "bob", Port: "tty0", At: midday}
}

// author is an authorization request carrying a command, which is the
// request this protocol exists to decide about.
func author(cmd string) Request {
	return Request{Client: host("10.0.0.5"), Exchange: wire.TypeAuthor, Seq: 1,
		Session: 1, Method: wire.MethodTACACSPlus, AuthenType: wire.AuthenASCII,
		Service: wire.ServiceLogin, User: "bob", Port: "tty0", PrivLvl: 1,
		Command: cmd, ServiceArg: "shell", At: midday}
}

// The defaults: a listener written with an upstream and nothing else refuses
// the four things nobody in a modern estate should be sending.
func TestTheDefaultsRefuseTheFourThingsNobodyShouldSend(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t"})

	if !p.refuseClear {
		t.Error("a body in the clear is carried by default, which puts a password on the wire")
	}
	for _, c := range []struct {
		name string
		on   bool
	}{
		{"allow_follow", p.allowFollow},
		{"allow_change_password", p.allowChpass},
		{"allow_sendauth", p.allowSend},
		{"allow_unauthenticated_authorization", p.allowUnauth},
	} {
		if c.on {
			t.Errorf("%s is on by default", c.name)
		}
	}
	if p.maxPriv != 15 || p.maxArgs != 64 {
		t.Errorf("the defaults bound privilege at %d and arguments at %d", p.maxPriv, p.maxArgs)
	}
	// And the default action is deny, so a listener with no rules carries
	// nothing.
	if d := p.Decide(login()); d.Allow || d.Reason != "no_rule_matched" {
		t.Errorf("the default action is not deny: %+v", d)
	}
}

// A configuration that is wrong is wrong at load, and the error names the
// field it was written in.
func TestCompileRefusesEveryNameItCannotRead(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.TACACSListener
		want string
	}{
		{"allow_clients", config.TACACSListener{AllowClients: []string{"switch-1"}}, "allow_clients:"},
		{"deny_clients", config.TACACSListener{DenyClients: []string{"10.0.0.0/33"}}, "deny_clients:"},
		{"exchanges", config.TACACSListener{Exchanges: []string{"authz"}}, "exchanges: \"authz\" is not an exchange"},
		{"authen_types", config.TACACSListener{AuthenTypes: []string{"mschapv3"}}, "authen_types: \"mschapv3\" is not an authentication type"},
		{"authen_services", config.TACACSListener{AuthenServices: []string{"shell"}}, "authen_services: \"shell\" is not a service"},
		{"commands", config.TACACSListener{Commands: []string{"show ... version"}}, "commands:"},
		{"deny_commands", config.TACACSListener{DenyCommands: []string{"   "}}, "deny_commands:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.cfg
			cfg.Upstream = "t"
			if _, err := compile(&cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	rules := []struct {
		name string
		rule config.TACACSRule
		want string
	}{
		{"clients", config.TACACSRule{Name: "r", Clients: []string{"switch-1"}}, "rules[0].clients:"},
		{"exchanges", config.TACACSRule{Name: "r", Exchanges: []string{"acct-ing"}}, "rules[0].exchanges:"},
		{"authen_types", config.TACACSRule{Name: "r", AuthenTypes: []string{"ntlm"}}, "rules[0].authen_types:"},
		{"authen_services", config.TACACSRule{Name: "r", AuthenServices: []string{"junos"}}, "rules[0].authen_services:"},
		{"commands", config.TACACSRule{Name: "r", Commands: []string{"sho... version"}}, "rules[0].commands:"},
		{"deny_commands", config.TACACSRule{Name: "r", DenyCommands: []string{"reload ... now"}}, "rules[0].deny_commands:"},
		{"schedule", config.TACACSRule{Name: "r", Schedule: &config.ModbusSchedule{From: "nine"}}, "rules[0].schedule:"},
	}
	for _, c := range rules {
		t.Run("rule_"+c.name, func(t *testing.T) {
			cfg := config.TACACSListener{Upstream: "t", Rules: []config.TACACSRule{c.rule}}
			if _, err := compile(&cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
}

// The pattern grammar is words and an optional trailing `...`, and the
// smallness is the point: every other spelling is refused at load rather
// than given a reading its author did not intend.
func TestThePatternGrammarRefusesEverythingItDoesNotMean(t *testing.T) {
	for _, c := range []struct{ pat, want string }{
		{"", "is empty"},
		{"   ", "is empty"},
		{"...", "covers every command"},
		{"show ... version", "must be the last word"},
		{"sho...", "must stand alone as the last word"},
		{"show run...", "must stand alone as the last word"},
	} {
		if _, err := compilePattern(c.pat); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("compilePattern(%q) returned %v, want an error containing %q", c.pat, err, c.want)
		}
	}
	// And the two forms that are the grammar.
	exact, err := compilePattern("Show Running-Config")
	if err != nil {
		t.Fatal(err)
	}
	if exact.prefix || strings.Join(exact.words, " ") != "show running-config" {
		t.Errorf("an exact pattern compiled to %+v, and should be folded", exact)
	}
	if exact.raw != "Show Running-Config" {
		t.Errorf("the pattern does not keep what was written: %q", exact.raw)
	}
	wild, err := compilePattern("show ...")
	if err != nil {
		t.Fatal(err)
	}
	if !wild.prefix || strings.Join(wild.words, " ") != "show" {
		t.Errorf("a prefix pattern compiled to %+v", wild)
	}
}

// An allow list is read exactly and a deny list is read as a prefix, and the
// asymmetry is the whole of what makes a deny mean what it says: `show
// running-config | include password` begins with the command somebody
// denied.
func TestAnAllowListReadsExactlyAndADenyListReadsWhatFollows(t *testing.T) {
	exact, _ := compilePattern("show running-config")
	wild, _ := compilePattern("show ...")

	for _, c := range []struct {
		cmd          string
		match, reach bool
	}{
		{"show running-config", true, true},
		{"SHOW RUNNING-CONFIG", true, true},
		{"show running-config | include password", false, true},
		{"show", false, false},
		{"show version", false, false},
	} {
		if got := exact.match(c.cmd); got != c.match {
			t.Errorf("exact.match(%q) = %v, want %v", c.cmd, got, c.match)
		}
		if got := exact.reaches(c.cmd); got != c.reach {
			t.Errorf("exact.reaches(%q) = %v, want %v", c.cmd, got, c.reach)
		}
	}
	// A prefix pattern reads the same both ways, which is why it is the one
	// an operator should reach for first.
	for _, cmd := range []string{"show", "show version", "show running-config | include password"} {
		if !wild.match(cmd) || !wild.reaches(cmd) {
			t.Errorf("show ... did not cover %q", cmd)
		}
	}
	if wild.match("reload") || wild.reaches("reload") {
		t.Error("show ... covered reload")
	}
	// And the two list helpers over an empty list, which is how a listener
	// with no command policy reaches them.
	if matchAny(nil, "show version") || reachesAny(nil, "show version") {
		t.Error("an empty pattern list matched a command")
	}
}

// Both deny lists are a union and both allow lists an intersection: a rule
// narrows, it never widens. An estate that added a deny of its own to the
// network team's rule must not thereby have handed that team `reload`.
func TestARuleNarrowsTheCommandListsInBothDirections(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t",
		Commands:     []string{"show ...", "configure terminal", "reload"},
		DenyCommands: []string{"show running-config"},
		Rules: []config.TACACSRule{{Name: "netops", Action: "allow",
			Commands:     []string{"show ...", "configure terminal"},
			DenyCommands: []string{"configure terminal"}}}})

	for _, c := range []struct {
		cmd   string
		allow bool
		why   string
	}{
		{"show version", true, "on both allow lists and neither deny list"},
		{"show running-config", false, "the listener's deny list"},
		{"configure terminal", false, "the rule's own deny list"},
	} {
		d := p.Decide(author(c.cmd))
		if d.Allow != c.allow {
			t.Errorf("%q decided %+v, want allow=%v (%s)", c.cmd, d, c.allow, c.why)
		}
		if !c.allow && d.Reason != "command_not_allowed" {
			t.Errorf("%q was refused as %q", c.cmd, d.Reason)
		}
	}
	// `reload` is on the listener's allow list and outside the rule's, so
	// the rule does not cover it -- which means no rule decides it and the
	// default action does. That is the narrowing from the other side: a
	// rule written about `show ...` is not also the rule that lets
	// `reload` through.
	d := p.Decide(author("reload"))
	if d.Allow || d.Reason != "no_rule_matched" || d.Rule != "" {
		t.Errorf("a command outside the rule's list decided %+v", d)
	}
}

// A request that carries no command meets none of the command policy, which
// is what lets a listener police commands without refusing every login.
func TestARequestWithNoCommandMeetsNoCommandPolicy(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t", DefaultAction: "allow",
		Commands: []string{"show ..."}})
	if d := p.Decide(login()); !d.Allow {
		t.Fatalf("an authentication start met the command list: %+v", d)
	}
}

// The header is what a listener with no key will ever know, so what can be
// decided from twelve octets is decided there.
func TestTheHeaderDecidesWhatTwelveOctetsAllow(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t",
		Exchanges: []string{"authentication", "authorization"}})
	ip := host("10.0.0.5")

	if d := p.Header(ip, wire.Header{Type: 9}); d.Allow || d.Reason != "unknown_exchange" {
		t.Fatalf("an unknown exchange decided %+v", d)
	}
	if d := p.Header(ip, wire.Header{Type: wire.TypeAcct}); d.Allow ||
		d.Reason != "exchange_not_allowed" || d.Detail != "accounting" {
		t.Fatalf("an exchange off the list decided %+v", d)
	}
	if d := p.Header(ip, wire.Header{Type: wire.TypeAuthen}); !d.Allow {
		t.Fatalf("an exchange on the list was refused: %+v", d)
	}
	// A body in the clear is a hard refusal: carrying it to find out what
	// the policy would have said is what puts the password on the wire.
	clear := wire.Header{Type: wire.TypeAuthen, Flags: wire.FlagUnencrypted}
	d := p.Header(ip, clear)
	if d.Allow || d.Reason != "unencrypted_body" || !d.Hard {
		t.Fatalf("a body in the clear decided %+v", d)
	}
	lax := compiled(t, &config.TACACSListener{Upstream: "t", RefuseUnencrypted: offs()})
	if d := lax.Header(ip, clear); !d.Allow {
		t.Fatalf("refuse_unencrypted: false still refused a clear body: %+v", d)
	}
}

// What kind of authentication a session is, which is the one place the
// action field is read.
func TestTheAuthenticationSettingsAreReadOnlyOnAnAuthenticationStart(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t", DefaultAction: "allow",
		RefusePlaintextPasswords: yes()})

	chpass := login()
	chpass.Action = wire.ActionChangePass
	if d := p.Decide(chpass); d.Allow || d.Reason != "change_password_not_allowed" {
		t.Fatalf("a change-password session decided %+v", d)
	}
	send := login()
	send.Action = wire.ActionSendAuth
	if d := p.Decide(send); d.Allow || d.Reason != "sendauth_not_allowed" || !d.Hard {
		t.Fatalf("a SENDAUTH session decided %+v, and the refusal should stand in shadow mode", d)
	}
	bad := login()
	bad.Action = 0x09
	if d := p.Decide(bad); d.Allow || d.Reason != "unknown_action" {
		t.Fatalf("an unknown action decided %+v", d)
	}
	unknown := login()
	unknown.AuthenType = 0x7f
	if d := p.Decide(unknown); d.Allow || d.Reason != "unknown_authen_type" {
		t.Fatalf("an unknown authentication type decided %+v", d)
	}
	// ascii and pap put the password in the body, and that is a shape
	// rather than a value.
	if d := p.Decide(login()); d.Allow || d.Reason != "plaintext_password" || d.Detail != "ascii" {
		t.Fatalf("an ascii login against refuse_plaintext_passwords decided %+v", d)
	}
	chap := login()
	chap.AuthenType = wire.AuthenCHAP
	if d := p.Decide(chap); !d.Allow {
		t.Fatalf("a CHAP login was refused by the plaintext setting: %+v", d)
	}
	// The allow lists, listener-wide.
	only := compiled(t, &config.TACACSListener{Upstream: "t", DefaultAction: "allow",
		AuthenTypes: []string{"chap"}, AuthenServices: []string{"login"}})
	if d := only.Decide(login()); d.Allow || d.Reason != "authen_type_not_allowed" {
		t.Fatalf("a type off the list decided %+v", d)
	}
	svc := login()
	svc.AuthenType, svc.Service = wire.AuthenCHAP, wire.ServiceEnable
	if d := only.Decide(svc); d.Allow || d.Reason != "authen_service_not_allowed" ||
		d.Detail != "enable" {
		t.Fatalf("a service off the list decided %+v", d)
	}
	// On an authorization request the type says how the user was
	// authenticated earlier, and the list still applies -- but the action
	// and the service do not, because the session already decided them.
	cmd := author("show version")
	if d := only.Decide(cmd); d.Allow || d.Reason != "authen_type_not_allowed" {
		t.Fatalf("an authorization request escaped the type list: %+v", d)
	}
	cmd.AuthenType = 0
	if d := only.Decide(cmd); !d.Allow {
		t.Fatalf("an authorization request carrying no type was measured against the list: %+v", d)
	}
}

// An authorization request whose method says the device authenticated
// nobody is the shape of a device asking what an unauthenticated user may
// run.
func TestAnUnauthenticatedAuthorizationIsRefusedUnlessItIsAllowed(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t", DefaultAction: "allow"})
	req := author("show version")
	req.Method = wire.MethodNone
	if d := p.Decide(req); d.Allow || d.Reason != "unauthenticated_authorization" ||
		d.Detail != "none" {
		t.Fatalf("an unauthenticated authorization decided %+v", d)
	}
	open := compiled(t, &config.TACACSListener{Upstream: "t", DefaultAction: "allow",
		AllowUnauthenticatedAuthorization: yes()})
	if d := open.Decide(req); !d.Allow {
		t.Fatalf("allow_unauthenticated_authorization did not carry it: %+v", d)
	}
	// And the same method on an accounting record is not the same question:
	// the check is about what a device is asking to be authorised.
	acct := req
	acct.Exchange, acct.Command = wire.TypeAcct, "show version"
	if d := p.Decide(acct); !d.Allow {
		t.Fatalf("an accounting record was refused for its method: %+v", d)
	}
}

// The bounds and the identity lists, each of which is one refusal.
func TestTheBoundsAndTheIdentityListsEachRefuseOnce(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t", DefaultAction: "allow",
		MaxPrivilegeLevel: lvl(7), MaxArgs: 2,
		Users: []string{"Bob", "carol"}, DenyUsers: []string{"root"},
		Services: []string{"shell"}})

	many := author("show version")
	many.Args = wire.Args{{Name: "service"}, {Name: "cmd"}, {Name: "cmd-arg"}}
	if d := p.Decide(many); d.Allow || d.Reason != "too_many_arguments" || d.Detail != "3" {
		t.Fatalf("an argument list over the bound decided %+v", d)
	}
	high := author("show version")
	high.PrivLvl = 15
	if d := p.Decide(high); d.Allow || d.Reason != "privilege_too_high" ||
		d.Detail != "priv-lvl=15 above 7" {
		t.Fatalf("a request above the privilege bound decided %+v", d)
	}
	for _, c := range []struct {
		name, user, service, reason, detail string
	}{
		{"denied user", "root", "shell", "user_not_allowed", "root"},
		{"user off the list", "dave", "shell", "user_not_allowed", "dave"},
		{"service off the list", "bob", "junos-exec", "service_not_allowed", "junos-exec"},
	} {
		req := author("show version")
		req.User, req.ServiceArg = c.user, c.service
		d := p.Decide(req)
		if d.Allow || d.Reason != c.reason || d.Detail != c.detail {
			t.Errorf("%s decided %+v, want %s/%s", c.name, d, c.reason, c.detail)
		}
	}
	// Folded on both sides, and a request with no user name at all is not
	// measured against the user lists: an authentication start that has not
	// reached the prompt yet has none.
	ok := author("show version")
	ok.User = "BOB"
	if d := p.Decide(ok); !d.Allow {
		t.Fatalf("the user list is case-sensitive: %+v", d)
	}
	anon := login()
	anon.User = ""
	if d := p.Decide(anon); !d.Allow {
		t.Fatalf("a session with no user name yet was refused: %+v", d)
	}
}

// The rules decide in order, and a rule's own privilege bound is read after
// it matched -- which is how one team's rule is allowed more than the
// listener's own bound.
func TestTheRulesDecideInOrderAndCarryTheirOwnBound(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t", MaxPrivilegeLevel: lvl(15),
		Rules: []config.TACACSRule{
			{Name: "no-root", Action: "deny", Users: []string{"root"}},
			{Name: "readonly", Action: "allow", Users: []string{"bob"},
				MaxPrivilegeLevel: lvl(1)},
			{Name: "night", Action: "allow", Users: []string{"carol"},
				Schedule: &config.ModbusSchedule{From: "22:00", To: "06:00"}},
		}})
	root := author("show version")
	root.User = "root"
	if d := p.Decide(root); d.Allow || d.Reason != "rule_denied" || d.Rule != "no-root" {
		t.Fatalf("the deny rule did not win: %+v", d)
	}
	if d := p.Decide(author("show version")); !d.Allow || d.Rule != "readonly" {
		t.Fatalf("the allow rule did not decide its traffic: %+v", d)
	}
	high := author("show version")
	high.PrivLvl = 15
	d := p.Decide(high)
	if d.Allow || d.Reason != "privilege_too_high" || d.Rule != "readonly" ||
		d.Detail != "priv-lvl=15 above 1" {
		t.Fatalf("the rule's own bound decided %+v", d)
	}
	// The schedule, which is read after the rule matched: a request outside
	// the window is refused by name rather than falling through.
	carol := author("show version")
	carol.User = "carol"
	if d := p.Decide(carol); d.Allow || d.Reason != "outside_schedule" || d.Rule != "night" {
		t.Fatalf("a request outside the window decided %+v", d)
	}
	carol.At = time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC)
	if d := p.Decide(carol); !d.Allow {
		t.Fatalf("a request inside the window was refused: %+v", d)
	}
	// And a request no rule covers takes the default action.
	dave := author("show version")
	dave.User = "dave"
	if d := p.Decide(dave); d.Allow || d.Reason != "no_rule_matched" {
		t.Fatalf("a request matching no rule decided %+v", d)
	}
}

// Every selector narrows, and a rule covers a request only when all of them
// match.
func TestARuleCoversOnlyWhatEverySelectorMatches(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t", DefaultAction: "allow",
		Rules: []config.TACACSRule{{Name: "narrow", Action: "deny",
			Clients: []string{"10.0.0.0/24"}, Exchanges: []string{"authorization"},
			Users: []string{"bob"}, Services: []string{"shell"},
			AuthenServices: []string{"login"}, AuthenTypes: []string{"ascii"},
			Commands: []string{"show ..."}}}})
	if d := p.Decide(author("show version")); d.Allow {
		t.Fatalf("the rule did not cover the request every selector names: %+v", d)
	}
	for _, c := range []struct {
		name string
		edit func(*Request)
	}{
		{"client", func(r *Request) { r.Client = host("10.0.1.5") }},
		{"exchange", func(r *Request) { r.Exchange = wire.TypeAcct }},
		{"user", func(r *Request) { r.User = "carol" }},
		{"service argument", func(r *Request) { r.ServiceArg = "ppp" }},
		{"authentication service", func(r *Request) { r.Service = wire.ServiceEnable }},
		{"authentication type", func(r *Request) { r.AuthenType = wire.AuthenCHAP }},
		{"command", func(r *Request) { r.Command = "reload" }},
	} {
		req := author("show version")
		c.edit(&req)
		if d := p.Decide(req); !d.Allow {
			t.Errorf("the rule still covered a request whose %s does not match: %+v", c.name, d)
		}
	}
}

// An observe rule records and the search carries on, so a rule can be tried
// on live traffic without turning off the deny rules below it.
func TestObserveRulesAreRecordedAndDecideNothingHere(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t", DefaultAction: "allow",
		Rules: []config.TACACSRule{
			{Name: "watch-shell", Action: "observe", Services: []string{"shell"}},
			{Name: "watch-net", Action: "observe", Clients: []string{"10.0.0.0/8"}},
			{Name: "no-reload", Action: "deny", Commands: []string{"reload"}},
		}})
	d := p.Decide(author("reload"))
	if d.Allow || d.Reason != "rule_denied" || d.Rule != "no-reload" {
		t.Fatalf("the observe rules shadowed the deny rule below them: %+v", d)
	}
	if strings.Join(d.Observed, ",") != "watch-shell,watch-net" {
		t.Errorf("the observe rules recorded are %v, want both in order", d.Observed)
	}
	if ok := p.Decide(author("show version")); !ok.Allow ||
		strings.Join(ok.Observed, ",") != "watch-shell,watch-net" {
		t.Fatalf("an allowed request recorded %v: %+v", ok.Observed, ok)
	}
}

// The answer leg: a redirect the client would follow, and the privilege a
// server granted.
func TestTheAnswerLegRefusesAFollowAndBoundsAGrant(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t", MaxPrivilegeLevel: lvl(1),
		Rules: []config.TACACSRule{{Name: "jump", Action: "allow",
			Users: []string{"bob"}, MaxPrivilegeLevel: lvl(15)}}})

	follow := Answer{Client: host("10.0.0.5"), Exchange: wire.TypeAuthen,
		Status: "follow", Follow: true, At: midday}
	d := p.Answer(follow)
	if d.Allow || d.Reason != "follow_not_allowed" || !d.Hard || d.Detail != "follow" {
		t.Fatalf("a FOLLOW decided %+v, and the refusal should stand in shadow mode", d)
	}
	open := compiled(t, &config.TACACSListener{Upstream: "t", AllowFollow: yes()})
	if d := open.Answer(follow); !d.Allow {
		t.Fatalf("allow_follow did not carry one: %+v", d)
	}
	grant := Answer{Client: host("10.0.0.5"), Exchange: wire.TypeAuthor,
		Status: "pass-add", Pass: true, HasPrivilege: true, Privilege: 15, At: midday}
	if d := p.Answer(grant); d.Allow || d.Reason != "privilege_grant_too_high" ||
		d.Detail != "priv-lvl=15 above 1" {
		t.Fatalf("a grant above the bound decided %+v", d)
	}
	grant.Rule = "jump"
	if d := p.Answer(grant); !d.Allow {
		t.Fatalf("the rule's own bound did not apply to its answer: %+v", d)
	}
	// A name that is not a rule's falls back to the listener's bound rather
	// than to no bound at all.
	grant.Rule = "deleted-rule"
	if d := p.Answer(grant); d.Allow {
		t.Fatalf("an unknown rule name lifted the listener's bound: %+v", d)
	}
	// An answer that grants nothing is not a grant to bound.
	if d := p.Answer(Answer{Client: host("10.0.0.5"), Exchange: wire.TypeAuthor,
		Status: "pass-repl", Pass: true, At: midday}); !d.Allow {
		t.Fatalf("an answer with no privilege in it was refused: %+v", d)
	}
}

// The address lists, asked before anything is read.
func TestTheClientListsAreAnsweredBeforeAnythingIsRead(t *testing.T) {
	p := compiled(t, &config.TACACSListener{Upstream: "t",
		AllowClients: []string{"10.0.0.0/24", "192.168.1.7"},
		DenyClients:  []string{"10.0.0.9"}})
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},
		{"192.168.1.7", true},
		{"10.0.0.9", false},
		{"10.0.1.5", false},
	} {
		if got := p.Client(host(c.ip)); got != c.want {
			t.Errorf("Client(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	open := compiled(t, &config.TACACSListener{Upstream: "t", DenyClients: []string{"10.0.0.9"}})
	if !open.Client(host("203.0.113.1")) || open.Client(host("10.0.0.9")) {
		t.Error("with no allow list the deny list alone did not decide")
	}
}

// Which commands are engineering activity, which is the judgement this kind
// makes that no other listener can: a `configure terminal` is a change to
// infrastructure, and a `show` is not.
func TestTheEngineeringClassificationNamesTheCommandsThatChangeADevice(t *testing.T) {
	for _, c := range []struct {
		cmd   string
		class engineering.Class
	}{
		{"reload", engineering.ClassRestart},
		{"reboot now", engineering.ClassRestart},
		{"restart", engineering.ClassRestart},
		{"configure terminal", engineering.ClassConfiguration},
		{"conf t", engineering.ClassConfiguration},
		{"write memory", engineering.ClassConfiguration},
		{"write erase", engineering.ClassConfiguration},
		{"save", engineering.ClassConfiguration},
		{"set system host-name r1", engineering.ClassConfiguration},
		{"delete interfaces ge-0/0/0", engineering.ClassConfiguration},
		{"commit", engineering.ClassConfiguration},
		{"rollback 1", engineering.ClassConfiguration},
		// A file moving to or from the device, and the arguments decide
		// which of the two it is.
		{"copy running-config tftp://10.0.0.1/r1.cfg", engineering.ClassFileTransfer},
		{"copy tftp: flash:", engineering.ClassFirmware},
		{"archive config", engineering.ClassFileTransfer},
		{"upgrade hardware-module", engineering.ClassFirmware},
		{"install add file ios.bin", engineering.ClassFirmware},
		{"boot system flash:", engineering.ClassFirmware},
		{"request system reboot", engineering.ClassRestart},
		{"request system software add", engineering.ClassFirmware},
		{"request chassis fpc slot 0 offline", engineering.ClassConfiguration},
	} {
		op, ok := engineeringOf(author(c.cmd))
		if !ok {
			t.Errorf("%q is not engineering activity", c.cmd)
			continue
		}
		if op.Class != c.class {
			t.Errorf("%q is classified %s, want %s", c.cmd, op.Class, c.class)
		}
		if op.Detail != c.cmd || op.Subject != "bob" || op.Point != "tty0" {
			t.Errorf("%q reported %+v", c.cmd, op)
		}
	}
	// What is not engineering is everything an estate's monitoring does all
	// day, because a class that included those is a class nobody reads.
	for _, cmd := range []string{"show version", "show running-config", "ping 10.0.0.1",
		"traceroute 10.0.0.1", "terminal length 0", ""} {
		if _, ok := engineeringOf(author(cmd)); ok {
			t.Errorf("%q is reported as engineering activity", cmd)
		}
	}
	// With no port the device's address stands in as the point, because a
	// report has to say where.
	req := author("configure terminal")
	req.Port = ""
	op, ok := engineeringOf(req)
	if !ok || op.Point != "10.0.0.5" {
		t.Errorf("a command with no port reported point %q", op.Point)
	}
}

// The timeout test the accept loop and both relay loops share.
func TestATimeoutIsToldApartFromEveryOtherError(t *testing.T) {
	var ne net.Error
	if !errorsAsTimeout(os.ErrDeadlineExceeded, &ne) {
		t.Error("a deadline is not read as a timeout")
	}
	if errorsAsTimeout(net.ErrClosed, &ne) {
		t.Error("a closed connection is read as a timeout")
	}
	if errorsAsTimeout(errors.New("upstream refused"), &ne) {
		t.Error("an error that is not a net.Error is read as a timeout")
	}
}
