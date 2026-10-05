package config

import (
	"strings"
	"testing"
)

// The validation of the two mailbox listeners.
//
// Both sections are mostly lists, and the checks worth having are the ones
// about a list that cannot mean what it says: a mailbox pattern with a
// wildcard in the middle, a command this relay has no name for, a TLS mode
// that needs a certificate the listener has not got. Each of those is a
// refusal at load rather than a rule that quietly never matches.

// mailConfig wraps an imap or pop3 section in the smallest configuration that
// carries one, with or without a certificate.
func mailConfig(kind, section string, withTLS bool) string {
	tls := ""
	if withTLS {
		tls = `      tls:
        certificates:
          - {cert_file: /etc/x/cert.pem, key_file: /etc/x/key.pem}
`
	}
	return `
version: 1
upstreams:
  - name: mailboxes
    endpoints: [{address: 127.0.0.1:1143}]
server:
  listeners:
    - name: mail
      address: ":1143"
      kind: ` + kind + `
` + tls + `      ` + kind + `:
        upstream: mailboxes
` + section
}

func TestTheIMAPSectionRefusesAListThatCannotMeanWhatItSays(t *testing.T) {
	for _, c := range []struct {
		name, section, want string
		withTLS             bool
	}{
		{"a command this relay has no name for", "        commands: [FETCH, DOWNLOAD]\n",
			"is not an IMAP command", false},
		{"a denied command this relay has no name for", "        deny_commands: [XPIGLATIN]\n",
			"is not an IMAP command", false},
		{"a wildcard that is not the last character", "        mailboxes: [\"Sent*box\"]\n",
			"has a wildcard that is not the last character", false},
		{"the same in a deny list", "        deny_mailboxes: [\"Sh%red/HR\"]\n",
			"has a wildcard that is not the last character", false},
		{"a mailbox name longer than one may be",
			"        mailboxes: [\"" + strings.Repeat("a", 2000) + "\"]\n",
			"is longer than a mailbox name may be", false},
		{"an empty mechanism name", "        mechanisms: [plain, \"\"]\n",
			"an empty mechanism name", false},
		{"a TLS mode that is not one", "        tls_mode: both\n",
			"is not implicit, starttls or none", false},
		{"an upstream TLS mode that is not one", "        upstream_tls_mode: maybe\n",
			"is not disable, implicit or starttls", false},
		// The two modes this relay terminates itself, each of which needs a
		// certificate: without one the listener would answer the upgrade with
		// a handshake it cannot make.
		{"starttls with no certificate", "        tls_mode: starttls\n",
			"starttls needs a tls section", false},
		{"implicit with no certificate", "        tls_mode: implicit\n",
			"implicit needs a tls section", false},
		{"upstream TLS settings nothing reads",
			"        upstream_tls_mode: disable\n        upstream_tls: {server_name: mail}\n",
			"which never uses it", false},
		{"a negative fetch bound", "        max_fetch_messages: -1\n",
			"max_fetch_messages: negative", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseWith([]byte(mailConfig("imap", c.section, c.withTLS)), false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// With a certificate both modes are what an estate actually writes.
	for _, mode := range []string{"implicit", "starttls", "none"} {
		if _, err := ParseWith([]byte(mailConfig("imap",
			"        tls_mode: "+mode+"\n        max_fetch_messages: 200\n", true)), false); err != nil {
			t.Errorf("tls_mode: %s with a certificate: %v", mode, err)
		}
	}
	// A mailbox pattern whose wildcard is the last character is the grammar,
	// and so is a name with no wildcard at all.
	if _, err := ParseWith([]byte(mailConfig("imap",
		"        mailboxes: [INBOX, \"INBOX/*\", \"Archive/%\"]\n", false)), false); err != nil {
		t.Errorf("the pattern grammar was refused: %v", err)
	}
}

// The two warnings an IMAP listener gets about the things that are legal and
// read as a mistake: a password in the clear, and no bound on a fetch.
func TestTheIMAPWarningsNameWhatMakesAMailboxCopyable(t *testing.T) {
	cfg, err := ParseWith([]byte(mailConfig("imap",
		"        require_tls: false\n", true)), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"a mailbox password travels in the clear",
		"max_fetch_messages: unset",
	} {
		if !hasAdvice(cfg, want) {
			t.Errorf("no warning containing %q: %v", want, cfg.Advice())
		}
	}
	// And a listener that requires TLS without having a certificate or the
	// upgrade is told that every LOGIN will be refused, which is the
	// configuration an operator writes when something else terminates TLS.
	cfg, err = ParseWith([]byte(mailConfig("imap",
		"        max_fetch_messages: 200\n", false)), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "every LOGIN will be refused") {
		t.Errorf("no warning about a listener with no certificate: %v", cfg.Advice())
	}
	// A listener with a certificate, TLS required and a fetch bound gets
	// neither.
	cfg, err = ParseWith([]byte(mailConfig("imap",
		"        tls_mode: implicit\n        require_tls: true\n        max_fetch_messages: 200\n",
		true)), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"travels in the clear", "max_fetch_messages: unset",
		"every LOGIN will be refused"} {
		if hasAdvice(cfg, unwanted) {
			t.Errorf("a correct configuration was warned about %q: %v", unwanted, cfg.Advice())
		}
	}
}

func TestThePOP3SectionRefusesAListThatCannotMeanWhatItSays(t *testing.T) {
	for _, c := range []struct {
		name, section, want string
		withTLS             bool
	}{
		{"a command this relay has no name for", "        commands: [RETR, FETCH]\n",
			"is not a POP3 command", false},
		{"a denied command this relay has no name for", "        deny_commands: [XSENDER]\n",
			"is not a POP3 command", false},
		{"an empty mechanism name", "        mechanisms: [user, \"\"]\n",
			"an empty mechanism name", false},
		{"an upstream TLS mode that is not one", "        upstream_tls_mode: maybe\n",
			"is not disable, implicit or starttls", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseWith([]byte(mailConfig("pop3", c.section, c.withTLS)), false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// The mechanism names this protocol has of its own -- the USER and PASS
	// pair, and the digest -- are names, and a SASL name is matched as
	// written with advice rather than refused: this project cannot know every
	// mechanism a server offers.
	cfg, err := ParseWith([]byte(mailConfig("pop3",
		"        mechanisms: [user, apop, plain, \"scram-sha-512\"]\n", true)), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "is not a mechanism this project knows") {
		t.Errorf("no advice about an unknown mechanism: %v", cfg.Advice())
	}
	// And the ones it does know draw none.
	cfg, err = ParseWith([]byte(mailConfig("pop3",
		"        mechanisms: [user, apop, plain, oauthbearer]\n", true)), false)
	if err != nil {
		t.Fatal(err)
	}
	if hasAdvice(cfg, "is not a mechanism this project knows") {
		t.Errorf("a list of known mechanisms drew advice: %v", cfg.Advice())
	}
}
