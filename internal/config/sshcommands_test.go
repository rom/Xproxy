package config

import (
	"strings"
	"testing"
)

// sshRuleConfig is a listener with host keys and an upstream, plus
// whatever the test is about.
func sshRuleConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: bastion
      address: ":2222"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [/etc/xproxy/ssh_host_ed25519_key]
        authorized_keys: /etc/xproxy/authorized_keys
        upstream_key_file: /etc/xproxy/id_ed25519
        upstream_known_hosts: /etc/xproxy/known_hosts
` + section + `
upstreams:
  - name: hosts
    endpoints: [{address: "10.0.0.9:22"}]
`
}

// A rule that says something this proxy cannot act on is a load error,
// not a rule that quietly allows.
func TestCommandRulesAreCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{`        command_rules:
          - {command: ftp, directions: [upload]}`, "not a family"},
		{`        command_rules:
          - {command: scp, directions: [sideways]}`, "not a direction"},
		{`        command_rules:
          - {command: scp, directions: [upload, upload]}`, "listed twice"},
		{`        command_rules:
          - {command: scp, directions: [upload]}
          - {command: scp, directions: [download]}`, "has a rule already"},
		// A rule with no direction allows nothing, so the family is
		// simply refused -- which is a section written for nothing.
		{`        command_rules:
          - {command: scp, paths: ["/srv/**"]}`, "required"},
		// Only scp has -r, and only rsync has the options that delete.
		{`        command_rules:
          - {command: rsync, directions: [upload], recursive: true}`, "only scp"},
		{`        command_rules:
          - {command: scp, directions: [upload], delete: true}`, "only rsync"},
		// The sftp server exec is the subsystem under another name.
		{`        command_rules:
          - {command: sftp_server}`, "needs it"},
		{`        command_rules:
          - {command: sftp_server, enforce_sftp_policy: true}`, "no sftp section"},
		{`        sftp: {read_only: true}
        command_rules:
          - {command: sftp_server, enforce_sftp_policy: true, directions: [upload]}`, "takes none"},
		{`        command_rules:
          - {command: scp, directions: [upload], enforce_sftp_policy: true}`, "only an sftp_server rule"},
		// A pattern that could never match the paths this gateway
		// resolves.
		{`        command_rules:
          - {command: scp, directions: [upload], paths: ["srv/incoming/**"]}`, "must be absolute"},
		{`        command_rules:
          - {command: scp, directions: [upload], paths: [""]}`, "must be a path"},
		// exec has to be reachable or no command ever meets a rule.
		{`        allow_requests: [pty-req, shell]
        command_rules:
          - {command: scp, directions: [upload], paths: ["/srv/**"]}`, "without exec"},
	} {
		_, err := ParseWith([]byte(sshRuleConfig(tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\nerror %v, want one about %q", tc.section, err, tc.want)
		}
	}
}

// And the rules an operator would actually write load.
func TestCommandRulesThatLoad(t *testing.T) {
	section := `        sftp: {read_only: false, allow_paths: ["/srv/data/**"]}
        command_rules:
          - command: scp
            directions: [upload]
            paths: ["/srv/incoming/**"]
            deny_paths: ["/srv/incoming/keys/**"]
          - command: rsync
            directions: [upload, download]
            paths: ["/srv/data/**"]
            delete: true
          - command: git
            directions: [download]
            paths: ["/srv/git/**"]
          - command: sftp_server
            enforce_sftp_policy: true`
	cfg, err := ParseWith([]byte(sshRuleConfig(section)), false)
	if err != nil {
		t.Fatalf("a policy that should load: %v", err)
	}
	rules := cfg.Server.Listeners[0].SSH.CommandRules
	if len(rules) != 4 || rules[0].Command != "scp" || !rules[1].Delete || !rules[3].EnforceSFTPPolicy {
		t.Errorf("the rules were read as %+v", rules)
	}
	// A rule with no paths reaches every path on the target, which is
	// advice rather than an error: a jump host to one directory is the
	// common case, a whole machine is a decision.
	warned, err := ParseWith([]byte(sshRuleConfig(`        command_rules:
          - {command: scp, directions: [upload]}`)), false)
	if err != nil {
		t.Fatalf("a rule with no paths should load: %v", err)
	}
	if !strings.Contains(strings.Join(warned.Advice(), "\n"), "every path on the target") {
		t.Errorf("no advice about an empty path list: %v", warned.Advice())
	}
}

// A principal's own rules are checked the same way, including the exec
// it inherits from the listener.
func TestAPrincipalsCommandRulesAreChecked(t *testing.T) {
	section := `        principals:
          - name: deploy
            cert_principals: [deploy]
            policy:
              command_rules:
                - {command: scp, directions: [sideways]}`
	_, err := ParseWith([]byte(sshRuleConfig(section)), false)
	if err == nil || !strings.Contains(err.Error(), "not a direction") {
		t.Fatalf("error %v, want one about the direction", err)
	}
	ok := `        trusted_user_ca_keys: /etc/xproxy/user_ca.pub
        sftp: {allow_paths: ["/srv/data/**"]}
        principals:
          - name: deploy
            cert_principals: [deploy]
            policy:
              command_rules:
                - {command: scp, directions: [upload], paths: ["/srv/incoming/**"]}`
	if _, err := ParseWith([]byte(sshRuleConfig(ok)), false); err != nil {
		t.Fatalf("a principal's rules should load: %v", err)
	}
}
