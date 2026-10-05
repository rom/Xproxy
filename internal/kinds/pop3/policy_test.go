package pop3

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/pop3"
)

// The policy on its own.
//
// POP3's policy is the imap kind's with two differences that come from the
// protocol rather than from a choice: there is no mailbox, so the retrieval
// bound takes its place as the only thing distinguishing a client collecting
// its own mail from a client collecting somebody's; and the credential
// question is harsher, because the password is on the line after USER and
// there is no mechanism negotiation to inspect.

func compiled(t *testing.T, c *config.POP3Listener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func peer(s string) netip.Addr { return netip.MustParseAddr(s) }

func off() *bool { b := false; return &b }

func cmd(t *testing.T, line string) *wire.Command {
	t.Helper()
	c, err := wire.ParseCommand([]byte(line))
	if err != nil {
		t.Fatalf("parsing %q: %v", line, err)
	}
	return c
}

// ask builds a request in the transaction state, which is where the mail is.
func ask(t *testing.T, line string) Request {
	return Request{Client: peer("10.0.0.5"), User: "bob", State: wire.StateTransaction,
		Encrypted: true, Command: cmd(t, line)}
}

// The defaults: the transport check is the one that matters, and the bounds
// are off until somebody writes one.
func TestTheDefaultsRequireTheTransportAndBoundNothingElse(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail"})

	if !p.requireTLS {
		t.Error("a password may travel in the clear by default")
	}
	if p.maxMsgs != 0 || p.maxBytes != 0 {
		t.Errorf("the default bounds are messages=%d bytes=%d, and a bound nobody wrote would cut off a mail run",
			p.maxMsgs, p.maxBytes)
	}
	if !p.defaultAllow {
		t.Error("the default action is deny, which on a mail relay refuses the mail")
	}
	if d := p.Decide(ask(t, "RETR 1")); !d.Allow {
		t.Errorf("a plain RETR was refused by the defaults: %+v", d)
	}
}

// A configuration that is wrong is wrong at load.
func TestCompileRefusesWhatCannotBeAPolicy(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.POP3Listener
		want string
	}{
		{"allow_clients", config.POP3Listener{AllowClients: []string{"mail-1"}}, "allow_clients:"},
		{"deny_clients", config.POP3Listener{DenyClients: []string{"10.0.0.0/33"}}, "deny_clients:"},
		{"commands", config.POP3Listener{Commands: []string{"RETR", "FETCH"}},
			"\"FETCH\" is not a POP3 command this relay knows"},
		{"deny_commands", config.POP3Listener{DenyCommands: []string{"XSENDER"}}, "deny_commands:"},
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
	rules := []struct {
		name string
		rule config.POP3Rule
		want string
	}{
		{"clients", config.POP3Rule{Name: "r", Clients: []string{"mail-1"}}, "rules[0]: clients:"},
		{"commands", config.POP3Rule{Name: "r", Commands: []string{"FETCH"}}, "rules[0]: commands:"},
		{"deny_commands", config.POP3Rule{Name: "r", DenyCommands: []string{"FETCH"}}, "rules[0]: deny_commands:"},
		{"schedule", config.POP3Rule{Name: "r", Schedule: &config.ModbusSchedule{To: "half nine"}}, "rules[0]: schedule:"},
	}
	for _, c := range rules {
		t.Run("rule_"+c.name, func(t *testing.T) {
			cfg := config.POP3Listener{Upstream: "mail", Rules: []config.POP3Rule{c.rule}}
			if _, err := compile(&cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("compile error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// A blank entry is what a YAML list with a trailing dash looks like, and
	// is not worth refusing.
	p := compiled(t, &config.POP3Listener{Upstream: "mail", Commands: []string{"RETR", " "}})
	if len(p.allow) != 1 {
		t.Errorf("a blank list entry became a policy: %v", p.allow)
	}
}

// The command's own three questions, each of them hard: no configuration
// admits a command this relay cannot name, one sent in the wrong state, or a
// message number that is not one.
func TestACommandIsRefusedBeforeAnyListIsConsulted(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail"})

	for _, c := range []struct {
		name, line string
		state      wire.State
		reason     string
	}{
		{"an unknown command", "XSENDER 1", wire.StateTransaction, "unknown_command"},
		{"a RETR before a login", "RETR 1", wire.StateAuthorization, "wrong_state"},
		{"a USER after one", "USER bob", wire.StateTransaction, "wrong_state"},
		{"a message number that is not one", "RETR nine", wire.StateTransaction,
			"malformed_message_number"},
		{"a line count that is not one", "TOP 1 many", wire.StateTransaction,
			"malformed_line_count"},
	} {
		req := ask(t, c.line)
		req.State = c.state
		d := p.Decide(req)
		if d.Allow || d.Reason != c.reason {
			t.Errorf("%s decided %+v, want %s", c.name, d, c.reason)
		}
		if !d.Hard {
			t.Errorf("%s was refused softly, and no configuration admits it", c.name)
		}
	}
	// CAPA and QUIT are legal in both states, which is what lets a client
	// find out what it may do before it logs in.
	for _, state := range []wire.State{wire.StateAuthorization, wire.StateTransaction} {
		for _, line := range []string{"CAPA", "QUIT"} {
			req := ask(t, line)
			req.State = state
			if d := p.Decide(req); !d.Allow {
				t.Errorf("%s in %s was refused: %+v", line, state, d)
			}
		}
	}
}

// The credential's transport. There is no mechanism negotiation on the USER
// and PASS pair, so either the transport protects the password or it is
// published -- and APOP is a digest, which is the one exception.
func TestTheCredentialsTransportIsDecidedBeforeItTravels(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail"})

	for _, mech := range []string{"user", "USER", "plain", "login"} {
		d := p.Mechanism(mech, false)
		if d.Allow || d.Reason != "tls_required" || !d.Hard {
			t.Errorf("%s in the clear decided %+v", mech, d)
		}
	}
	// APOP hashes the password against the server's timestamp, so the
	// transport question is not about it.
	if d := p.Mechanism("apop", false); !d.Allow {
		t.Errorf("APOP in the clear was refused as a plaintext credential: %+v", d)
	}
	if d := p.Mechanism("user", true); !d.Allow {
		t.Errorf("USER over TLS was refused: %+v", d)
	}
	// The mechanism list, which is read after the transport question.
	only := compiled(t, &config.POP3Listener{Upstream: "mail",
		Mechanisms: []string{"plain", "xoauth2"}})
	if d := only.Mechanism("CRAM-MD5", true); d.Allow || d.Reason != "mechanism_not_allowed" ||
		d.Detail != "cram-md5" {
		t.Errorf("a mechanism off the list decided %+v", d)
	}
	if d := only.Mechanism("PLAIN", true); !d.Allow {
		t.Errorf("a mechanism on the list was refused: %+v", d)
	}
	// With require_tls off nothing about the transport is asked, which is
	// what an operator terminating TLS in front of this relay needs.
	lax := compiled(t, &config.POP3Listener{Upstream: "mail", RequireTLS: off()})
	if d := lax.Mechanism("user", false); !d.Allow {
		t.Errorf("require_tls: false still refused a password in the clear: %+v", d)
	}
}

// The claimed identity.
func TestTheClaimedIdentityIsMeasuredAgainstTheUserList(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail", Users: []string{"Bob", "carol"}})
	if d := p.User("BOB"); !d.Allow {
		t.Errorf("the user list is case-sensitive: %+v", d)
	}
	d := p.User("dave")
	if d.Allow || d.Reason != "user_not_allowed" || d.Detail != "dave" {
		t.Errorf("a user off the list decided %+v", d)
	}
	if d := p.User(strings.Repeat("a", 100)); len(d.Detail) != 67 ||
		!strings.HasSuffix(d.Detail, "...") {
		t.Errorf("a long name reached the log line as %d characters", len(d.Detail))
	}
	open := compiled(t, &config.POP3Listener{Upstream: "mail"})
	if d := open.User("dave"); !d.Allow {
		t.Errorf("a listener with no user list refused a name: %+v", d)
	}
}

// The command lists and the read-only switch, which on this protocol is
// about the two commands that change the mailbox.
func TestTheCommandListsAndTheReadOnlySwitch(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail",
		Commands:     []string{"USER", "PASS", "CAPA", "STAT", "LIST", "UIDL", "RETR", "QUIT", "DELE"},
		DenyCommands: []string{"DELE"}})

	if d := p.Decide(ask(t, "DELE 1")); d.Allow || d.Reason != "command_denied" ||
		d.Detail != "DELE" {
		t.Errorf("a command on both lists decided %+v", d)
	}
	if d := p.Decide(ask(t, "TOP 1 10")); d.Allow || d.Reason != "command_not_allowed" ||
		d.Detail != "TOP" {
		t.Errorf("a command off the allow list decided %+v", d)
	}
	if d := p.Decide(ask(t, "RETR 1")); !d.Allow {
		t.Errorf("a command on the allow list was refused: %+v", d)
	}
	// read_only covers the two commands that change the mailbox without
	// naming them, and leaves the reads alone.
	ro := compiled(t, &config.POP3Listener{Upstream: "mail", ReadOnly: true})
	for _, line := range []string{"DELE 1", "RSET"} {
		d := ro.Decide(ask(t, line))
		if d.Allow || d.Reason != "read_only" {
			t.Errorf("%q against a read-only listener decided %+v", line, d)
		}
	}
	for _, line := range []string{"RETR 1", "TOP 1 10", "LIST", "UIDL", "STAT"} {
		if d := ro.Decide(ask(t, line)); !d.Allow {
			t.Errorf("%q was refused by read_only: %+v", line, d)
		}
	}
}

// The copying bound, which is measured against what this connection has
// already taken and is answered before the command rather than during it.
func TestTheCopyingBoundIsAnsweredBeforeTheNextCommand(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail", MaxMessages: 10,
		MaxRetrBytes: 1 << 20})

	at := func(msgs int, bytes int64, line string) Request {
		r := ask(t, line)
		r.Messages, r.Retrieved = msgs, bytes
		return r
	}
	d := p.Decide(at(10, 0, "RETR 1"))
	if d.Allow || d.Reason != "too_many_messages" ||
		d.Detail != "10 retrieved, the bound is 10" {
		t.Fatalf("a connection at the message bound decided %+v", d)
	}
	d = p.Decide(at(1, 1<<20, "TOP 1 10"))
	if d.Allow || d.Reason != "retrieval_too_large" ||
		d.Detail != "1048576 octets retrieved, the bound is 1048576" {
		t.Fatalf("a connection at the byte bound decided %+v", d)
	}
	if d := p.Decide(at(9, 1<<19, "RETR 1")); !d.Allow {
		t.Fatalf("a connection under both bounds was refused: %+v", d)
	}
	// The bound is about collecting mail, so the commands that do not
	// collect any are not measured: a client that has reached it can still
	// ask what is there and say goodbye.
	for _, line := range []string{"LIST", "UIDL", "STAT", "NOOP", "QUIT"} {
		if d := p.Decide(at(100, 1<<30, line)); !d.Allow {
			t.Errorf("%q was refused by the retrieval bound: %+v", line, d)
		}
	}
	// And Bounds reports the limits in force, which is what the relay needs
	// while a transfer is in flight rather than before it.
	msgs, bytes := p.Bounds(ask(t, "RETR 1"))
	if msgs != 10 || bytes != 1<<20 {
		t.Errorf("Bounds reports messages=%d bytes=%d", msgs, bytes)
	}
}

// A rule narrows the policy for the users and clients it names.
func TestARuleNarrowsThePolicyForTheTrafficItNames(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail", MaxMessages: 100,
		Rules: []config.POP3Rule{
			{Name: "no-bots", Action: "deny", Users: []string{"scanner"}},
			{Name: "carol", Users: []string{"carol"}, MaxMessages: 2, MaxRetrBytes: 4096,
				ReadOnly: true, DenyCommands: []string{"UIDL"}},
			{Name: "branch", Clients: []string{"10.0.9.0/24"},
				Commands: []string{"USER", "PASS", "STAT", "LIST", "QUIT"}},
		}})

	bot := ask(t, "STAT")
	bot.User = "scanner"
	if d := p.Decide(bot); d.Allow || d.Reason != "rule_denied" || d.Rule != "no-bots" {
		t.Fatalf("a denying rule decided %+v", d)
	}
	carol := func(line string) Request {
		r := ask(t, line)
		r.User = "carol"
		return r
	}
	if d := p.Decide(carol("DELE 1")); d.Allow || d.Reason != "read_only" || d.Rule != "carol" {
		t.Fatalf("the rule's own read_only decided %+v", d)
	}
	if d := p.Decide(carol("UIDL")); d.Allow || d.Reason != "command_denied" || d.Rule != "carol" {
		t.Fatalf("the rule's own deny list decided %+v", d)
	}
	msgs := carol("RETR 1")
	msgs.Messages = 2
	d := p.Decide(msgs)
	if d.Allow || d.Reason != "too_many_messages" || d.Rule != "carol" ||
		!strings.Contains(d.Detail, "the bound is 2") {
		t.Fatalf("the rule's own message bound decided %+v", d)
	}
	bytes := carol("RETR 1")
	bytes.Retrieved = 5000
	d = p.Decide(bytes)
	if d.Allow || d.Reason != "retrieval_too_large" || !strings.Contains(d.Detail, "the bound is 4096") {
		t.Fatalf("the rule's own byte bound decided %+v", d)
	}
	if m, b := p.Bounds(carol("RETR 1")); m != 2 || b != 4096 {
		t.Errorf("Bounds under the rule reports messages=%d bytes=%d", m, b)
	}
	// The client selector, and a command the branch rule does not name.
	branch := ask(t, "RETR 1")
	branch.Client, branch.User = peer("10.0.9.4"), "dave"
	if d := p.Decide(branch); d.Allow || d.Reason != "command_not_allowed" || d.Rule != "branch" {
		t.Fatalf("a command off the rule's allow list decided %+v", d)
	}
	ok := ask(t, "STAT")
	ok.Client, ok.User = peer("10.0.9.4"), "dave"
	if d := p.Decide(ok); !d.Allow || d.Rule != "branch" {
		t.Fatalf("the rule that allowed the command did not name itself: %+v", d)
	}
	// And a user no rule names takes the listener's own policy.
	dave := ask(t, "RETR 1")
	dave.User = "dave"
	if d := p.Decide(dave); !d.Allow || d.Rule != "" {
		t.Fatalf("a user no rule names decided %+v", d)
	}
}

// A rule's schedule is a selector like the rest, read against the policy's
// own clock.
func TestARulesScheduleSelectsIt(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail",
		Rules: []config.POP3Rule{{Name: "office", Action: "deny",
			Schedule: &config.ModbusSchedule{Days: []string{"wed"}, From: "09:00", To: "17:00"}}}})
	p.now = func() time.Time { return time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC) }
	if d := p.Decide(ask(t, "STAT")); d.Allow {
		t.Fatalf("the rule did not decide inside its window: %+v", d)
	}
	p.now = func() time.Time { return time.Date(2026, 3, 4, 23, 0, 0, 0, time.UTC) }
	if d := p.Decide(ask(t, "STAT")); !d.Allow {
		t.Fatalf("the rule still decided outside its window: %+v", d)
	}
}

// default_action: deny is the other way to write the policy.
func TestDefaultDenyRefusesWhatNoRuleAllows(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail", DefaultAction: "deny",
		Rules: []config.POP3Rule{{Name: "bob", Users: []string{"bob"}}}})
	if d := p.Decide(ask(t, "STAT")); !d.Allow || d.Rule != "bob" {
		t.Fatalf("the rule that names this user did not allow the command: %+v", d)
	}
	other := ask(t, "STAT")
	other.User = "dave"
	if d := p.Decide(other); d.Allow || d.Reason != "default_deny" {
		t.Fatalf("a user no rule names decided %+v", d)
	}
}

// The address lists, answered before the greeting.
func TestTheClientListsDecideBeforeTheGreeting(t *testing.T) {
	p := compiled(t, &config.POP3Listener{Upstream: "mail",
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
	open := compiled(t, &config.POP3Listener{Upstream: "mail", DenyClients: []string{"10.0.0.9"}})
	if !open.Client(peer("203.0.113.1")) || open.Client(peer("10.0.0.9")) {
		t.Error("with no allow list the deny list alone did not decide")
	}
}

// The two small helpers the relay leans on: a parse error rendered for a log
// line, and the timeout test the loops share.
func TestTheRelaysSmallHelpers(t *testing.T) {
	if got := reasonOf(nil); got != "" {
		t.Errorf("reasonOf(nil) = %q", got)
	}
	if got := reasonOf(errors.New("not a reply")); got != "not a reply" {
		t.Errorf("reasonOf rendered %q", got)
	}
	var ne net.Error
	if !errorsAsTimeout(os.ErrDeadlineExceeded, &ne) {
		t.Error("a deadline is not read as a timeout")
	}
	if errorsAsTimeout(net.ErrClosed, &ne) || errorsAsTimeout(errors.New("x"), &ne) {
		t.Error("something that is not a timeout was read as one")
	}
}
