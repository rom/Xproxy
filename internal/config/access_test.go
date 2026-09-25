package config

import (
	"strings"
	"testing"
	"time"
)

// The access section and the listeners that require a grant are checked
// together, because each half alone reads as if it did something: a listener
// with no ledger to ask would refuse every session, and a ledger nobody asks is
// a queue of approvals nobody's access depends on.
func TestAccessConfig(t *testing.T) {
	base := `
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [/etc/xgate/host_ed25519]
        authorized_keys: /etc/xgate/authorized_keys
        upstream_key_file: /etc/xgate/id_ed25519
        upstream_known_hosts: /etc/xgate/known_hosts
%s
upstreams:
  - name: hosts
    endpoints: [{address: "10.0.0.1:22"}]
%s
`
	cfg := func(listenerExtra, top string) string {
		return strings.Replace(strings.Replace(base, "%s", listenerExtra, 1), "%s", top, 1)
	}

	ok, err := parseNoFiles([]byte(cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
`)))
	if err != nil {
		t.Fatal(err)
	}
	a := ok.Access
	if a.Approvals == nil || *a.Approvals != DefaultAccessApprovals {
		t.Errorf("approvals default %v, want %d", a.Approvals, DefaultAccessApprovals)
	}
	if a.MaxDuration.D() != DefaultAccessMaxDuration || a.MaxLead.D() != DefaultAccessMaxLead || a.MaxOpen != DefaultAccessMaxOpen {
		t.Errorf("defaults %+v", a)
	}
	if !ok.Server.Listeners[0].SSH.RequireGrant {
		t.Error("require_grant did not survive the parse")
	}
	// max_open follows every other bound in this file: an omitted or zero
	// value is the default rather than "no bound", so a pool of grants
	// cannot be made unbounded by leaving a field out.
	zeroOpen, err := parseNoFiles([]byte(cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  max_open: 0
`)))
	if err != nil {
		t.Fatal(err)
	}
	if zeroOpen.Access.MaxOpen != DefaultAccessMaxOpen {
		t.Errorf("max_open 0 became %d, want the default %d", zeroOpen.Access.MaxOpen, DefaultAccessMaxOpen)
	}

	// A zero the operator wrote is not the zero the parser left behind: it
	// stays 0 and is warned about rather than being filled in with 1.
	zero, err := parseNoFiles([]byte(cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  approvals: 0
`)))
	if err != nil {
		t.Fatal(err)
	}
	if zero.Access.Approvals == nil || *zero.Access.Approvals != 0 {
		t.Errorf("an explicit 0 became %v", zero.Access.Approvals)
	}
	if !hasAdvice(zero, "approvals") {
		t.Errorf("no advice about approvals: 0: %v", zero.Advice())
	}

	// The refusals.
	for name, c := range map[string]string{
		"a listener requiring a grant with no section": cfg("        require_grant: true", ""),
		"a relative ledger path": cfg("        require_grant: true", `
access:
  ledger: access.log
`),
		"too many approvals": cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  approvals: 9
`),
		"negative approvals": cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  approvals: -1
`),
		"a window shorter than a minute": cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  max_duration: 30s
`),
		"a window longer than a day": cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  max_duration: 48h
`),
		"a lead longer than a month": cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  max_lead: 1000h
`),
		"uses past the bound": cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  max_uses: 1001
`),
		"a negative bound on open grants": cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  max_open: -1
`),
		"a negative bound on uses": cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  max_uses: -1
`),
	} {
		if _, err := parseNoFiles([]byte(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// The warnings: each one is a configuration that loads and that an
	// operator has to be told about.
	for name, want := range map[string]struct{ yaml, advice string }{
		"a ledger nobody asks": {cfg("", `
access:
  ledger: /var/lib/xgate/access.log
`), "require_grant"},
		"no ledger": {cfg("        require_grant: true", `
access: {}
`), "ledger"},
		"self approval": {cfg("        require_grant: true", `
access:
  ledger: /var/lib/xgate/access.log
  self_approval: true
`), "self_approval"},
	} {
		c, err := parseNoFiles([]byte(want.yaml))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !hasAdvice(c, want.advice) {
			t.Errorf("%s: no advice naming %q: %v", name, want.advice, c.Advice())
		}
	}
}

// The four other gate kinds carry the same field, in the same spelling, so an
// estate does not have to remember which protocol calls it what.
func TestEveryGateKindCanRequireAGrant(t *testing.T) {
	l := Listener{
		SSH:    &SSHListener{RequireGrant: true},
		Telnet: &TelnetListener{RequireGrant: true},
		VNC:    &VNCListener{RequireGrant: true},
		RDP:    &RDPListener{RequireGrant: true},
		FTP:    &FTPListener{RequireGrant: true},
	}
	if !l.SSH.RequireGrant || !l.Telnet.RequireGrant || !l.VNC.RequireGrant || !l.RDP.RequireGrant || !l.FTP.RequireGrant {
		t.Error("a gate kind lost the field")
	}
	if DefaultAccessMaxDuration != 4*time.Hour {
		t.Errorf("max_duration default %s", DefaultAccessMaxDuration)
	}
}

// A grant names a person, so a listener that requires one has to learn a name.
// Two kinds cannot always: telnet has no identity of its own, and VNC only
// carries one with certain security types. Both are refused at load rather than
// failing closed on the first evening -- an empty subject matches no grant, so
// the listener would refuse every session and say nothing about why.
func TestAListenerThatCannotLearnANameIsRefused(t *testing.T) {
	base := `
version: 1
server:
  listeners:
    - name: gate
      address: "127.0.0.1:0"
      kind: %s
      %s:
        upstream: hosts
        require_grant: true
%s
upstreams:
  - name: hosts
    endpoints: [{address: "10.0.0.1:23"}]
access:
  ledger: /var/lib/xgate/access.log
`
	cfg := func(kind, extra string) []byte {
		return []byte(strings.Replace(strings.Replace(strings.Replace(base, "%s", kind, 1), "%s", kind, 1), "%s", extra, 1))
	}

	if _, err := parseNoFiles(cfg("telnet", "")); err == nil {
		t.Error("telnet require_grant without a factor prompt was accepted")
	}
	if _, err := parseNoFiles(cfg("telnet", `        mfa: {file: /etc/xgate/mfa}`)); err != nil {
		t.Errorf("telnet require_grant with a factor prompt: %v", err)
	}
	// VNC: a DES challenge proves a shared password and names nobody, so
	// require_grant needs a security type that carries a user -- or a factor.
	if _, err := parseNoFiles(cfg("vnc", `        security_types: [vncauth]
        password_file: /etc/xgate/vnc.pass`)); err == nil {
		t.Error("vnc require_grant with a nameless security type was accepted")
	}
	if _, err := parseNoFiles(cfg("vnc", `        security_types: [mslogon2]
        password_file: /etc/xgate/vnc.pass`)); err != nil {
		t.Errorf("vnc require_grant with a security type that names a user: %v", err)
	}
}
