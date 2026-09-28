package config

import (
	"strings"
	"testing"
)

// mmsConfig is one mms listener with the given section.
func mmsConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: substation
      address: "127.0.0.1:102"
      kind: mms
      mms:
` + section + `
upstreams:
  - name: ieds
    endpoints: [{address: "10.30.7.11:102"}]
`
}

// The things a configuration must not be able to say, because a rule that can never
// match sitting in an allow list is a listener that refuses everything.
func TestMMSRefusesNamesThatCouldNeverMatch(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a functional constraint IEC 61850 does not define",
			section: "        upstream: ieds\n        functional_constraints: [ZZ]\n",
			wants:   `"ZZ" is not an IEC 61850 functional constraint`,
		},
		{
			name:    "a service MMS does not have",
			section: "        upstream: ieds\n        services: [read_the_plant]\n",
			wants:   `"read_the_plant" is not an MMS service`,
		},
		{
			name:    "a service class that is not one of the nine",
			section: "        upstream: ieds\n        service_classes: [everything]\n",
			wants:   `"everything" is not a service class`,
		},
		{
			name:    "an AP-title that is not an object identifier",
			section: "        upstream: ieds\n        ap_titles: [\"substation-one\"]\n",
			wants:   "is not an object identifier",
		},
		{
			name:    "an AP-title with an empty arc",
			section: "        upstream: ieds\n        ap_titles: [\"1..999\"]\n",
			wants:   "has an empty arc",
		},
		{
			name:    "an AE-qualifier that is not a number",
			section: "        upstream: ieds\n        ae_qualifiers: [\"engineering\"]\n",
			wants:   "ae_qualifiers",
		},
		{
			name: "two rules with one name",
			section: "        upstream: ieds\n" +
				"        rules:\n" +
				"          - {name: same, action: allow}\n" +
				"          - {name: same, action: deny}\n",
			wants: "is used twice",
		},
		{
			name:    "a deny response this listener cannot give",
			section: "        upstream: ieds\n        deny_response: negative\n",
			wants:   "is not error, reject, drop or close",
		},
		{
			name:    "no upstream",
			section: "        allow_clients: [\"10.0.0.0/8\"]\n",
			wants:   "upstream: required",
		},
		{
			name:    "a burst with no limit",
			section: "        upstream: ieds\n        rate_burst: 10\n",
			wants:   "set without rate_limit",
		},
		{
			name:    "learning with no file",
			section: "        upstream: ieds\n        learn: {enabled: true}\n",
			wants:   "learn.file: required",
		},
		{
			name:    "learning to a relative path",
			section: "        upstream: ieds\n        learn: {enabled: true, file: learned.yaml}\n",
			wants:   "must be an absolute path",
		},
		{
			name: "an AP-title pattern, which is allowed",
			section: "        upstream: ieds\n        ap_titles: [\"1.1.999.*\"]\n" +
				"        allow_clients: [\"10.0.0.0/8\"]\n",
		},
		{
			name: "the constraints IEC 61850 does define",
			section: "        upstream: ieds\n" +
				"        functional_constraints: [ST, MX, CO, SP, CF, SG, SE, BR, RP, LG, GO, BL]\n" +
				"        allow_clients: [\"10.0.0.0/8\"]\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWith([]byte(mmsConfig(tc.section)), false)
			if tc.wants == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// An mms listener takes no TLS section, and saying so is worth an error rather than
// silence: MMS on TCP 102 has none, and a certificate here would promise something
// the transport cannot do.
func TestMMSTakesNoTLSSection(t *testing.T) {
	yaml := `
version: 1
server:
  listeners:
    - name: substation
      address: "127.0.0.1:102"
      kind: mms
      tls:
        certificates: [{cert_file: /tmp/c.pem, key_file: /tmp/k.pem}]
      mms:
        upstream: ieds
upstreams:
  - name: ieds
    endpoints: [{address: "10.30.7.11:102"}]
`
	_, err := ParseWith([]byte(yaml), false)
	if err == nil || !strings.Contains(err.Error(), "MMS on TCP 102 has no transport TLS") {
		t.Fatalf("error %v, want the one about transport TLS", err)
	}
}

// The warnings, which are the part of this validator most easily got wrong: one that
// fires on a configuration that is already correct teaches people to ignore them all.
func TestMMSWarningsDoNotFireOnACorrectConfiguration(t *testing.T) {
	// The two a bare listener gets. Not the interlock: with the default action of
	// deny and no rules, this listener carries nothing at all, so warning that it
	// might operate a breaker would be warning about something that cannot happen.
	cfg, err := ParseWith([]byte(mmsConfig("        upstream: ieds\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if hasAdvice(cfg, "require_select_before_operate is off") {
		t.Errorf("a deny-by-default listener with no rules was warned about the interlock: %v",
			cfg.Advice())
	}
	for _, want := range []string{
		"allow_clients is empty",
		"names neither domains nor objects",
	} {
		if !hasAdvice(cfg, want) {
			t.Errorf("no warning about %q: %v", want, cfg.Advice())
		}
	}

	// And the one about the password, which fires when the refusal is ON rather than
	// off: on most of the installed base that password is the only authentication
	// the IED has.
	cfg, err = ParseWith([]byte(mmsConfig(
		"        upstream: ieds\n        refuse_plaintext_passwords: true\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "turn this on once the clients have moved") {
		t.Errorf("no warning about refusing the password: %v", cfg.Advice())
	}

	// A listener that narrowed everything the warnings ask for gets none of them.
	cfg, err = ParseWith([]byte(mmsConfig(
		"        upstream: ieds\n"+
			"        allow_clients: [\"10.10.0.0/24\"]\n"+
			"        domains: [\"AA1J1Q01A1LD0\"]\n"+
			"        default_action: allow\n"+
			"        write_constraints: [CO]\n"+
			"        require_select_before_operate: true\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, never := range []string{
		"allow_clients is empty",
		"names neither domains nor objects",
		"require_select_before_operate is off",
	} {
		if hasAdvice(cfg, never) {
			t.Errorf("a correct configuration was warned about %q: %v", never, cfg.Advice())
		}
	}
}

// A listener whose default is deny and whose rules never carry a Write does not
// operate anything, so the interlock warning must not fire on it. This is the case
// the engineering listener in examples/ot/mms.yaml is.
func TestMMSTheInterlockWarningReadsTheRules(t *testing.T) {
	cfg, err := ParseWith([]byte(mmsConfig(
		"        upstream: ieds\n"+
			"        allow_clients: [\"10.11.0.0/24\"]\n"+
			"        domains: [\"AA1J1Q01A1LD0\"]\n"+
			"        default_action: deny\n"+
			"        rules:\n"+
			"          - {name: read, action: allow, service_classes: [session, browse, read]}\n"+
			"          - {name: records, action: allow, service_classes: [file]}\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if hasAdvice(cfg, "require_select_before_operate is off") {
		t.Errorf("a listener that carries no Write was warned about the interlock: %v",
			cfg.Advice())
	}

	// And it does fire where a rule carries one.
	cfg, err = ParseWith([]byte(mmsConfig(
		"        upstream: ieds\n"+
			"        allow_clients: [\"10.11.0.0/24\"]\n"+
			"        domains: [\"AA1J1Q01A1LD0\"]\n"+
			"        default_action: deny\n"+
			"        rules:\n"+
			"          - {name: operate, action: allow, services: [write], write_constraints: [CO]}\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "require_select_before_operate is off") {
		t.Errorf("a listener whose rule writes a control object was not warned: %v",
			cfg.Advice())
	}
}

// The domain-services warning asks for a rule with a window, so it must not fire on a
// listener that has one.
func TestMMSTheDomainWarningAcceptsAScheduledRule(t *testing.T) {
	scheduled := "        upstream: ieds\n" +
		"        allow_clients: [\"10.11.0.0/24\"]\n" +
		"        domains: [\"AA1J1Q01A1LD0\"]\n" +
		"        allow_domain_services: true\n" +
		"        default_action: deny\n" +
		"        rules:\n" +
		"          - name: download\n" +
		"            action: allow\n" +
		"            service_classes: [domain]\n" +
		"            schedule: {days: [sun], from: \"02:00\", to: \"04:00\", timezone: UTC}\n"
	cfg, err := ParseWith([]byte(mmsConfig(scheduled)), false)
	if err != nil {
		t.Fatal(err)
	}
	if hasAdvice(cfg, "allow_domain_services is on") {
		t.Errorf("a scheduled download rule was warned about: %v", cfg.Advice())
	}

	// Without the window it does fire.
	cfg, err = ParseWith([]byte(mmsConfig(
		"        upstream: ieds\n"+
			"        allow_clients: [\"10.11.0.0/24\"]\n"+
			"        domains: [\"AA1J1Q01A1LD0\"]\n"+
			"        allow_domain_services: true\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "allow_domain_services is on") {
		t.Errorf("an unscheduled download was not warned about: %v", cfg.Advice())
	}
}

// Writing a protection setting is worth saying at load, because a wrong trip
// characteristic is invisible until the day it matters.
func TestMMSWarnsAboutWritingAProtectionSetting(t *testing.T) {
	cfg, err := ParseWith([]byte(mmsConfig(
		"        upstream: ieds\n"+
			"        allow_clients: [\"10.11.0.0/24\"]\n"+
			"        domains: [\"AA1J1Q01A1LD0\"]\n"+
			"        write_constraints: [ST, SG, SE]\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "change what the device does in a fault") {
		t.Errorf("no warning about writing a setting group: %v", cfg.Advice())
	}
}

// A learning listener decides nothing, so the interlock warning is noise on one --
// the warning about learning without enforce is the one to read.
func TestMMSALearningListenerIsNotWarnedAboutTheInterlock(t *testing.T) {
	cfg, err := ParseWith([]byte(mmsConfig(
		"        upstream: ieds\n"+
			"        allow_clients: [\"10.10.0.0/24\"]\n"+
			"        domains: [\"AA1J1Q01A1LD0\"]\n"+
			"        learn: {enabled: true, file: /var/lib/xproxy/mms.yaml}\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if hasAdvice(cfg, "require_select_before_operate is off") {
		t.Errorf("a learning listener was warned about the interlock: %v", cfg.Advice())
	}
	if !hasAdvice(cfg, "records and decides nothing") {
		t.Errorf("no warning about learning without enforce: %v", cfg.Advice())
	}
}

// A bare `*` in a pattern list says the same thing as an empty list and reads as
// though it did not, so it is worth a word.
func TestMMSWarnsAboutABareWildcard(t *testing.T) {
	cfg, err := ParseWith([]byte(mmsConfig(
		"        upstream: ieds\n"+
			"        allow_clients: [\"10.10.0.0/24\"]\n"+
			"        objects: [\"*\"]\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "leave the list empty instead") {
		t.Errorf("no warning about a bare wildcard: %v", cfg.Advice())
	}
}
