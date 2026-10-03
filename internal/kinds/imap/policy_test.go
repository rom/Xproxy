package imap

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/imap"
)

// The policy on its own.
//
// The end-to-end tests next door drive a client and a server through the
// relay, which is what proves the literal handling and the state machine.
// This file is the policy's five questions in order, one case each, plus the
// mailbox pattern grammar -- which is where the subtle reading lives, because
// IMAP has two wildcards that mean different things and one name the standard
// makes case-insensitive.

func compiled(t *testing.T, c *config.IMAPListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func peer(s string) netip.Addr { return netip.MustParseAddr(s) }

func on() *bool { b := true; return &b }
func no() *bool { b := false; return &b }

// cmd parses a command line the way the relay does, so a case is written as
// the client would send it.
func cmd(t *testing.T, line string) *wire.Command {
	t.Helper()
	c, err := wire.ParseCommand([]byte(line))
	if err != nil {
		t.Fatalf("parsing %q: %v", line, err)
	}
	return c
}

// ask builds a request in the selected state, which is where most of the
// interesting commands are legal.
func ask(t *testing.T, line string, mailboxes ...string) Request {
	return Request{Client: peer("10.0.0.5"), User: "bob", State: wire.StateSelected,
		Encrypted: true, Command: cmd(t, line), Mailboxes: mailboxes}
}

// The defaults, which on this kind are four refusals and one bound.
func TestTheDefaultsAreTheOnesThatMatter(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail"})

	if !p.requireTLS {
		t.Error("a password may travel in the clear by default")
	}
	if !p.noCompress {
		t.Error("COMPRESS is carried by default, which hides every later command from inspection")
	}
	if p.openSets {
		t.Error("a sequence set running to the end of the mailbox is allowed by default")
	}
	if !p.allowIdle {
		t.Error("IDLE is refused by default, which breaks every mail client")
	}
	if p.maxLiteral != 64<<10 || p.maxAppend != 32<<20 {
		t.Errorf("the default bounds are literal=%d append=%d", p.maxLiteral, p.maxAppend)
	}
	// The default action is allow: this listener is a mail relay, and a
	// listener with no command list is not one that refuses mail.
	if !p.defaultAllow {
		t.Error("the default action is deny, which would refuse every command on a listener with no lists")
	}
	if d := p.Decide(ask(t, "a1 FETCH 1 BODY[]")); !d.Allow {
		t.Errorf("a plain FETCH was refused by the defaults: %+v", d)
	}
}

// A configuration that is wrong is wrong at load, and a command name this
// relay has no meaning for is the one worth catching: a rule naming it is a
// rule that never matches and an operator who thinks something is allowed.
func TestCompileRefusesWhatCannotBeAPolicy(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.IMAPListener
		want string
	}{
		{"allow_clients", config.IMAPListener{AllowClients: []string{"mail-1"}}, "allow_clients:"},
		{"deny_clients", config.IMAPListener{DenyClients: []string{"10.0.0.0/33"}}, "deny_clients:"},
		{"commands", config.IMAPListener{Commands: []string{"FETCH", "DOWNLOAD"}},
			"\"DOWNLOAD\" is not an IMAP command this relay knows"},
		{"deny_commands", config.IMAPListener{DenyCommands: []string{"XPIG-LATIN"}}, "deny_commands:"},
		{"mailboxes", config.IMAPListener{Mailboxes: []string{"Sent*box"}},
			"a wildcard is only ever the last character"},
		{"deny_mailboxes", config.IMAPListener{DenyMailboxes: []string{"Sh%red/HR"}}, "deny_mailboxes:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.cfg
			cfg.Upstream = "mail"
			if _, err := compile(&cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// The same inside a rule, where the error has to name the rule's index
	// as well as the field.
	rules := []struct {
		name string
		rule config.IMAPRule
		want string
	}{
		{"clients", config.IMAPRule{Name: "r", Clients: []string{"mail-1"}}, "rules[0]: clients:"},
		{"mailboxes", config.IMAPRule{Name: "r", Mailboxes: []string{"A*B"}}, "rules[0]: mailboxes:"},
		{"commands", config.IMAPRule{Name: "r", Commands: []string{"NOTIFYME"}}, "rules[0]: commands:"},
		{"deny_commands", config.IMAPRule{Name: "r", DenyCommands: []string{"NOTIFYME"}}, "rules[0]: deny_commands:"},
		{"schedule", config.IMAPRule{Name: "r", Schedule: &config.ModbusSchedule{Days: []string{"caturday"}}}, "rules[0]: schedule:"},
	}
	for _, c := range rules {
		t.Run("rule_"+c.name, func(t *testing.T) {
			cfg := config.IMAPListener{Upstream: "mail", Rules: []config.IMAPRule{c.rule}}
			if _, err := compile(&cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// An empty entry in a list is not a mistake worth refusing: it is what
	// a YAML list with a trailing blank looks like.
	p := compiled(t, &config.IMAPListener{Upstream: "mail", Commands: []string{"FETCH", "  "},
		Mailboxes: []string{"INBOX", ""}})
	if len(p.allow) != 1 || len(p.mailboxes) != 1 {
		t.Errorf("an empty list entry became a policy: commands=%v mailboxes=%d", p.allow, len(p.mailboxes))
	}
}

// The first three questions, which are about the command rather than about
// any list: is it a command, is it legal here, and does it hide what follows.
func TestACommandIsRefusedBeforeAnyListIsConsulted(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail"})

	for _, c := range []struct {
		name, line     string
		state          wire.State
		reason, detail string
	}{
		{"an unknown command", "a1 XPIGLATIN", wire.StateSelected, "unknown_command", "XPIGLATIN"},
		{"a UID with nothing after it", "a1 UID", wire.StateSelected, "malformed_command", "UID with no command"},
		{"a FETCH before a SELECT", "a1 FETCH 1 BODY[]", wire.StateAuth, "wrong_state",
			"FETCH in authenticated"},
		{"a LOGIN after one", "a1 LOGIN bob pw", wire.StateSelected, "wrong_state",
			"LOGIN in selected"},
		{"a command after LOGOUT", "a1 NOOP", wire.StateLogout, "wrong_state", "NOOP in logout"},
		// COMPRESS has no entry in the command table at all, because the
		// capability is stripped from the greeting and no client should be
		// asking: one that asks anyway is refused as a command this relay
		// has no name for, which is the same answer by a shorter road.
		{"COMPRESS", "a1 COMPRESS DEFLATE", wire.StateSelected, "unknown_command", "COMPRESS"},
	} {
		req := ask(t, c.line)
		req.State = c.state
		d := p.Decide(req)
		if d.Allow || d.Reason != c.reason || d.Detail != c.detail {
			t.Errorf("%s decided %+v, want %s/%s", c.name, d, c.reason, c.detail)
		}
		if !d.Hard {
			t.Errorf("%s was refused softly, and no configuration admits it", c.name)
		}
	}
	// IDLE is a setting rather than a refusal, because every mail client
	// uses it.
	noIdle := compiled(t, &config.IMAPListener{Upstream: "mail", AllowIdle: no()})
	if d := noIdle.Decide(ask(t, "a1 IDLE")); d.Allow || d.Reason != "idle_not_allowed" {
		t.Errorf("IDLE against allow_idle: false decided %+v", d)
	}
	if d := p.Decide(ask(t, "a1 IDLE")); !d.Allow {
		t.Errorf("IDLE was refused by default: %+v", d)
	}
}

// The credential's transport, which is the one refusal that cannot wait for
// shadow mode: the password has travelled by the time any list is consulted.
func TestTheCredentialsTransportIsDecidedBeforeItTravels(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail",
		Mechanisms: []string{"plain", "xoauth2"}})

	for _, mech := range []string{"LOGIN", "PLAIN", "login"} {
		d := p.Mechanism(mech, false)
		if d.Allow || d.Reason != "tls_required" || !d.Hard {
			t.Errorf("%s in the clear decided %+v", mech, d)
		}
	}
	// A mechanism that does not carry the password itself is not this
	// refusal, and is then measured against the list.
	if d := p.Mechanism("GSSAPI", false); d.Allow || d.Reason != "mechanism_not_allowed" {
		t.Errorf("a mechanism off the list in the clear decided %+v", d)
	}
	if d := p.Mechanism("PLAIN", true); !d.Allow {
		t.Errorf("PLAIN over TLS was refused: %+v", d)
	}
	if d := p.Mechanism("XOAUTH2", true); !d.Allow {
		t.Errorf("a mechanism on the list was refused: %+v", d)
	}
	// With require_tls off, the transport question is not asked -- which is
	// what an operator terminating TLS in front of this relay needs.
	lax := compiled(t, &config.IMAPListener{Upstream: "mail", RequireTLS: no()})
	if d := lax.Mechanism("LOGIN", false); !d.Allow {
		t.Errorf("require_tls: false still refused a LOGIN in the clear: %+v", d)
	}
	// A listener with no mechanism list admits any mechanism over TLS,
	// because the list is an allow list and not a requirement to have one.
	if d := lax.Mechanism("SCRAM-SHA-256", true); !d.Allow {
		t.Errorf("a listener with no mechanism list refused one: %+v", d)
	}
}

// The claimed identity, which is a list of its own because the name arrives
// before any mailbox does.
func TestTheClaimedIdentityIsMeasuredAgainstTheUserList(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail", Users: []string{"Bob", "carol"}})
	if d := p.User("BOB"); !d.Allow {
		t.Errorf("the user list is case-sensitive: %+v", d)
	}
	d := p.User("dave")
	if d.Allow || d.Reason != "user_not_allowed" || d.Detail != "dave" {
		t.Errorf("a user off the list decided %+v", d)
	}
	// A long name is clipped on its way into the log line.
	long := strings.Repeat("a", 100)
	if d := p.User(long); len(d.Detail) != 67 || !strings.HasSuffix(d.Detail, "...") {
		t.Errorf("a long name reached the log line as %d characters", len(d.Detail))
	}
	// And a listener with no list admits whatever the server will.
	open := compiled(t, &config.IMAPListener{Upstream: "mail"})
	if d := open.User("dave"); !d.Allow {
		t.Errorf("a listener with no user list refused a name: %+v", d)
	}
}

// The mailbox pattern grammar: two wildcards that mean different things, and
// the one name the standard makes case-insensitive.
func TestTheMailboxPatternsReadTheTwoWildcardsApart(t *testing.T) {
	compile := func(t *testing.T, pat string) pattern {
		t.Helper()
		ps, err := patterns([]string{pat})
		if err != nil {
			t.Fatal(err)
		}
		return ps[0]
	}
	// `*` takes the rest of the name, separator and all.
	star := compile(t, "Shared/*")
	for _, name := range []string{"Shared/", "Shared/HR", "Shared/HR/Payroll"} {
		if !star.match(name) {
			t.Errorf("Shared/* did not match %q", name)
		}
	}
	// `%` stays inside one level, which is the distinction a policy that
	// treated them the same would lose.
	level := compile(t, "Shared/%")
	if !level.match("Shared/HR") {
		t.Error("Shared/% did not match one level down")
	}
	if level.match("Shared/HR/Payroll") {
		t.Error("Shared/% matched two levels down, which is the rule nobody wrote")
	}
	// Without a wildcard it is the name and nothing else.
	exact := compile(t, "Archive")
	if !exact.match("Archive") || exact.match("Archive/2026") || exact.match("archive") {
		t.Error("an exact pattern did not compare exactly, and mailbox names other than INBOX are the server's own")
	}
	// INBOX is folded, and so is the hierarchy below it in either
	// separator -- which is what Dovecot's INBOX. namespace needs.
	inbox := compile(t, "INBOX")
	for _, name := range []string{"INBOX", "inbox", "Inbox"} {
		if !inbox.match(name) {
			t.Errorf("INBOX did not match %q", name)
		}
	}
	below := compile(t, "INBOX/Finance*")
	for _, name := range []string{"INBOX/Finance", "inbox/Finance", "INBOX/Finance/2026"} {
		if !below.match(name) {
			t.Errorf("INBOX/Finance* did not match %q", name)
		}
	}
	if below.match("inbox/finance") {
		t.Error("the fold reached past the INBOX component, and Finance is not finance")
	}
	// And a mailbox whose name merely begins with those five letters is not
	// INBOX.
	if inbox.match("Inboxes") {
		t.Error("Inboxes was folded into INBOX")
	}
	if foldInbox("Inboxes") != "Inboxes" || foldInbox("inbox.Finance") != "INBOX.Finance" ||
		foldInbox("in") != "in" || foldInbox("inbox") != "INBOX" {
		t.Error("foldInbox rewrote the wrong component")
	}
}

// The mailbox lists, which are read on the decoded name and apply to every
// mailbox a command refers to.
func TestTheMailboxListsApplyToEveryNameACommandRefersTo(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail",
		Mailboxes:     []string{"INBOX", "INBOX/*", "Archive/%"},
		DenyMailboxes: []string{"INBOX/Finance*"}})

	for _, c := range []struct {
		name           string
		boxes          []string
		reason, detail string
	}{
		{"a denied mailbox", []string{"INBOX/Finance"}, "mailbox_denied", "INBOX/Finance"},
		{"the hierarchy below a denied one", []string{"inbox/Finance/2026"}, "mailbox_denied", "inbox/Finance/2026"},
		{"a mailbox off the list", []string{"Shared/HR"}, "mailbox_not_allowed", "Shared/HR"},
		{"two levels under a % pattern", []string{"Archive/2026/Q1"}, "mailbox_not_allowed", "Archive/2026/Q1"},
		// A COPY names two, and the second one is decided about as well as
		// the first.
		{"the second of two names", []string{"INBOX", "Shared/HR"}, "mailbox_not_allowed", "Shared/HR"},
	} {
		d := p.Decide(ask(t, "a1 SELECT x", c.boxes...))
		if d.Allow || d.Reason != c.reason || d.Detail != c.detail {
			t.Errorf("%s decided %+v, want %s/%s", c.name, d, c.reason, c.detail)
		}
	}
	for _, boxes := range [][]string{{"INBOX"}, {"inbox"}, {"INBOX/Projects"}, {"Archive/2026"}} {
		if d := p.Decide(ask(t, "a1 SELECT x", boxes...)); !d.Allow {
			t.Errorf("%v was refused: %+v", boxes, d)
		}
	}
	// A command that names no mailbox is not a mailbox decision.
	if d := p.Decide(ask(t, "a1 NOOP")); !d.Allow {
		t.Errorf("a command naming no mailbox met the mailbox lists: %+v", d)
	}
}

// The command lists and the read-only switch, which are what "this account
// may read its own mail and nothing else" is written with.
func TestTheCommandListsAndTheReadOnlySwitch(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail",
		Commands:     []string{"CAPABILITY", "LOGIN", "SELECT", "FETCH", "UID", "NOOP", "LOGOUT", "APPEND"},
		DenyCommands: []string{"APPEND"}})

	// The deny list wins over the allow list, which is how an exception
	// inside an allowed set is written.
	if d := p.Decide(ask(t, "a1 APPEND INBOX {10}")); d.Allow || d.Reason != "command_denied" ||
		d.Detail != "APPEND" {
		t.Errorf("a command on both lists decided %+v", p.Decide(ask(t, "a1 APPEND INBOX {10}")))
	}
	if d := p.Decide(ask(t, "a1 STORE 1 +FLAGS (\\Seen)")); d.Allow ||
		d.Reason != "command_not_allowed" || d.Detail != "STORE" {
		t.Errorf("a command off the allow list decided %+v", d)
	}
	// The UID forms are decided as the command they qualify, which is the
	// whole reason Effective exists: a listener that allowed FETCH and not
	// UID FETCH would be refusing every real client.
	if d := p.Decide(ask(t, "a1 UID FETCH 1 BODY[]")); !d.Allow {
		t.Errorf("UID FETCH was refused where FETCH is allowed: %+v", d)
	}
	// read_only is about the operation rather than the name, so it covers
	// the UID forms without naming them.
	ro := compiled(t, &config.IMAPListener{Upstream: "mail", ReadOnly: true})
	for _, line := range []string{"a1 APPEND INBOX {10}", "a1 STORE 1 +FLAGS (\\Seen)",
		"a1 UID STORE 1 +FLAGS (\\Seen)", "a1 EXPUNGE", "a1 CREATE Archive/2026",
		"a1 UID MOVE 1 Archive"} {
		d := ro.Decide(ask(t, line))
		if d.Allow || d.Reason != "read_only" {
			t.Errorf("%q against a read-only listener decided %+v", line, d)
		}
	}
	if d := ro.Decide(ask(t, "a1 UID FETCH 1 BODY[]")); !d.Allow {
		t.Errorf("a read on a read-only listener was refused: %+v", d)
	}
}

// The two bounds that are about volume rather than access.
func TestTheVolumeBoundsAreDecidedBeforeTheOctetsArrive(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail", MaxFetchMessages: 100,
		MaxLiteralBytes: 1024, MaxAppendBytes: 4096})

	open := ask(t, "a1 FETCH 1:* BODY[]")
	open.Open, open.Messages = true, 1
	d := p.Decide(open)
	if d.Allow || d.Reason != "open_sequence_set" ||
		d.Detail != "FETCH to the end of the mailbox" {
		t.Fatalf("a set running to the end of the mailbox decided %+v", d)
	}
	big := ask(t, "a1 FETCH 1:500 BODY[]")
	big.Messages = 500
	d = p.Decide(big)
	if d.Allow || d.Reason != "fetch_too_large" ||
		d.Detail != "FETCH names 500 messages, the bound is 100" {
		t.Fatalf("a fetch over the bound decided %+v", d)
	}
	small := ask(t, "a1 FETCH 1:50 BODY[]")
	small.Messages = 50
	if d := p.Decide(small); !d.Allow {
		t.Fatalf("a fetch under the bound was refused: %+v", d)
	}
	// allow_open_sets is the setting for the clients that really do want
	// the whole mailbox.
	anySet := compiled(t, &config.IMAPListener{Upstream: "mail", AllowOpenSets: on()})
	if d := anySet.Decide(open); !d.Allow {
		t.Fatalf("allow_open_sets still refused one: %+v", d)
	}
	// The literal bound, and APPEND's own bound, which is the larger of the
	// two because a message is not a command argument.
	lit := ask(t, "a1 SEARCH SUBJECT {2000}")
	lit.Literal = 2000
	d = p.Decide(lit)
	if d.Allow || d.Reason != "literal_too_large" ||
		d.Detail != "2000 octets, the bound is 1024" {
		t.Fatalf("a literal over the bound decided %+v", d)
	}
	app := ask(t, "a1 APPEND INBOX {5000}")
	app.Literal = 5000
	d = p.Decide(app)
	if d.Allow || d.Reason != "append_too_large" ||
		d.Detail != "5000 octets, the bound is 4096" {
		t.Fatalf("an APPEND over its own bound decided %+v", d)
	}
	app.Literal = 2000
	if d := p.Decide(app); !d.Allow {
		t.Fatalf("an APPEND between the two bounds was refused: %+v", d)
	}
}

// A rule narrows all of it for a named set of users, clients and mailboxes.
func TestARuleNarrowsThePolicyForTheTrafficItNames(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail", MaxFetchMessages: 100,
		MaxAppendBytes: 1 << 20,
		Rules: []config.IMAPRule{
			{Name: "no-bots", Action: "deny", Users: []string{"scanner"}},
			{Name: "archive-only", Users: []string{"bob"}, Mailboxes: []string{"Archive/*"},
				ReadOnly: true},
			{Name: "carol", Users: []string{"carol"}, MaxFetchMessages: 10,
				MaxAppendBytes: 2048, DenyCommands: []string{"SEARCH"},
				Commands: []string{"FETCH", "UID", "SELECT", "NOOP", "SEARCH", "APPEND"}},
		}})

	bot := ask(t, "a1 NOOP")
	bot.User = "scanner"
	if d := p.Decide(bot); d.Allow || d.Reason != "rule_denied" || d.Rule != "no-bots" {
		t.Fatalf("a denying rule decided %+v", d)
	}
	// The rule's mailboxes are a selector: bob writing in Archive meets the
	// rule's read_only, and bob in INBOX does not meet the rule at all.
	arch := ask(t, "a1 STORE 1 +FLAGS (\\Seen)", "Archive/2026")
	d := p.Decide(arch)
	if d.Allow || d.Reason != "read_only" || d.Rule != "archive-only" {
		t.Fatalf("a write inside the rule's mailboxes decided %+v", d)
	}
	inbox := ask(t, "a1 STORE 1 +FLAGS (\\Seen)", "INBOX")
	if d := p.Decide(inbox); !d.Allow || d.Rule != "" {
		t.Fatalf("a write outside the rule's mailboxes decided %+v", d)
	}
	// The rule's own bounds and lists.
	carol := ask(t, "a1 FETCH 1:50 BODY[]")
	carol.User, carol.Messages = "carol", 50
	d = p.Decide(carol)
	if d.Allow || d.Reason != "fetch_too_large" || d.Rule != "carol" ||
		!strings.Contains(d.Detail, "the bound is 10") {
		t.Fatalf("the rule's own fetch bound decided %+v", d)
	}
	search := ask(t, "a1 SEARCH SUBJECT x")
	search.User = "carol"
	if d := p.Decide(search); d.Allow || d.Reason != "command_denied" || d.Rule != "carol" {
		t.Fatalf("the rule's own deny list decided %+v", d)
	}
	appendBig := ask(t, "a1 APPEND INBOX {4000}")
	appendBig.User, appendBig.Literal = "carol", 4000
	d = p.Decide(appendBig)
	if d.Allow || d.Reason != "append_too_large" || !strings.Contains(d.Detail, "the bound is 2048") {
		t.Fatalf("the rule's own append bound decided %+v", d)
	}
	// A command the rule's allow list does not name.
	logout := ask(t, "a1 LOGOUT")
	logout.User = "carol"
	if d := p.Decide(logout); d.Allow || d.Reason != "command_not_allowed" || d.Rule != "carol" {
		t.Fatalf("a command off the rule's allow list decided %+v", d)
	}
	// And a request the rule allows carries the rule's name, which is what
	// the access line records.
	ok := ask(t, "a1 FETCH 1:5 BODY[]")
	ok.User, ok.Messages = "carol", 5
	if d := p.Decide(ok); !d.Allow || d.Rule != "carol" {
		t.Fatalf("the rule that allowed the command did not name itself: %+v", d)
	}
}

// A rule's client list and its schedule are selectors like the rest, and the
// schedule is read against the policy's own clock so a test can move it.
func TestARulesClientListAndScheduleSelectIt(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail",
		Rules: []config.IMAPRule{
			{Name: "office", Action: "deny", Clients: []string{"10.0.9.0/24"},
				Schedule: &config.ModbusSchedule{Days: []string{"wed"}, From: "09:00", To: "17:00"}},
		}})
	p.now = func() time.Time { return time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC) }

	inside := ask(t, "a1 NOOP")
	inside.Client = peer("10.0.9.4")
	if d := p.Decide(inside); d.Allow {
		t.Fatalf("the rule did not cover a client inside its network and window: %+v", d)
	}
	outside := ask(t, "a1 NOOP")
	if d := p.Decide(outside); !d.Allow || d.Rule != "" {
		t.Fatalf("the rule reached a client outside its network: %+v", d)
	}
	// Move the clock out of the window and the rule stops selecting.
	p.now = func() time.Time { return time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC) }
	if d := p.Decide(inside); !d.Allow {
		t.Fatalf("the rule still decided outside its window: %+v", d)
	}
	// A rule whose mailbox selector is set never matches a command that
	// names no mailbox, because matching on none would decide about every
	// command the rule was not written for.
	byBox := compiled(t, &config.IMAPListener{Upstream: "mail",
		Rules: []config.IMAPRule{{Name: "shared", Action: "deny",
			Mailboxes: []string{"Shared/*"}}}})
	if d := byBox.Decide(ask(t, "a1 NOOP")); !d.Allow {
		t.Fatalf("a mailbox rule decided a command that names no mailbox: %+v", d)
	}
	if matchAll([]pattern{{raw: "x", lit: "x"}}, nil) {
		t.Error("matchAll matched an empty name list")
	}
}

// default_action: deny is the other way to write the policy: nothing crosses
// but what a rule names.
func TestDefaultDenyRefusesWhatNoRuleAllows(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail", DefaultAction: "deny",
		Rules: []config.IMAPRule{{Name: "bob", Users: []string{"bob"}}}})
	if d := p.Decide(ask(t, "a1 NOOP")); !d.Allow || d.Rule != "bob" {
		t.Fatalf("the rule that names this user did not allow the command: %+v", d)
	}
	other := ask(t, "a1 NOOP")
	other.User = "dave"
	if d := p.Decide(other); d.Allow || d.Reason != "default_deny" {
		t.Fatalf("a user no rule names decided %+v", d)
	}
}

// The address lists, answered before a connection is anything else.
func TestTheClientListsDecideBeforeTheGreeting(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail",
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
		if got := p.Client(peer(c.ip)); got != c.want {
			t.Errorf("Client(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	open := compiled(t, &config.IMAPListener{Upstream: "mail", DenyClients: []string{"10.0.0.9"}})
	if !open.Client(peer("203.0.113.1")) || open.Client(peer("10.0.0.9")) {
		t.Error("with no allow list the deny list alone did not decide")
	}
}

// A PREAUTH greeting says the connection is authenticated before anybody
// claimed an identity, so carrying it would make every later decision about
// a name this relay never saw.
func TestAPreauthGreetingIsADecisionOfItsOwn(t *testing.T) {
	p := compiled(t, &config.IMAPListener{Upstream: "mail"})
	pre, err := wire.ParseResponse([]byte("* PREAUTH IMAP4rev2 ready"))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Answer(pre, true)
	if d.Allow || d.Reason != "preauth_greeting" || !d.Hard {
		t.Fatalf("a PREAUTH greeting decided %+v", d)
	}
	if d := p.Answer(pre, false); !d.Allow {
		t.Fatalf("refuse_preauth: false still refused one: %+v", d)
	}
	ok, err := wire.ParseResponse([]byte("* OK IMAP4rev2 ready"))
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Answer(ok, true); !d.Allow {
		t.Fatalf("an ordinary greeting was refused: %+v", d)
	}
}
