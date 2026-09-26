package config

import (
	"strings"
	"testing"
)

// A requirement for a key held in a token is only as good as the ways around
// it, so what the validator looks for is the ways around it.
func TestTheHardwareKeyRequirementIsCheckedAtLoad(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		// A password is a second way in that no token stands behind. With a
		// second factor it is a different strength rather than none, so that
		// one is advice; without, it is the requirement defeated.
		{`        require_hardware_key: true
        users_file: /etc/xproxy/ssh.htpasswd`, "a way in that no token protects"},
		// Nothing a key could be offered against.
		{`        require_hardware_key: true
        authorized_keys: ""`, "no key it could accept"},
	} {
		_, err := ParseWith([]byte(hardwareConfig(tc.section)), false)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\nerror %v, want one about %q", tc.section, err, tc.want)
		}
	}
}

// What loads, and what it says out loud while loading.
func TestTheHardwareKeyRequirementAdvises(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{`        require_hardware_key: true
        users_file: /etc/xproxy/ssh.htpasswd
        mfa: {file: /etc/xproxy/mfa}`, "covers public keys only"},
		{`        require_touch: false`, "no longer proves somebody was there"},
		{`        require_hardware_key: true
        principals:
          - {name: robot, fingerprints: ["SHA256:LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE"], require_hardware_key: false}
          - {name: people}`, "exempts this principal"},
	} {
		cfg, err := ParseWith([]byte(hardwareConfig(tc.section)), false)
		if err != nil {
			t.Errorf("%s: %v", tc.section, err)
			continue
		}
		if !hasAdvice(cfg, tc.want) {
			t.Errorf("%s: advice %v, want %q", tc.section, cfg.Advice(), tc.want)
		}
	}
	// And the plain arrangement draws none of it: a requirement with keys to
	// satisfy it and the touch left alone is the shape this feature is for.
	cfg, err := ParseWith([]byte(hardwareConfig("        require_hardware_key: true")), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"no longer proves", "covers public keys only", "exempts this principal"} {
		if hasAdvice(cfg, unwanted) {
			t.Errorf("advised about %q on a plain hardware-key listener: %v", unwanted, cfg.Advice())
		}
	}
}

// hardwareConfig is an ssh listener with the token settings under test.
func hardwareConfig(section string) string {
	base := `
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
	// The one case that needs the key file gone says so by setting it empty,
	// which YAML cannot do twice in one mapping.
	if strings.Contains(section, `authorized_keys: ""`) {
		base = strings.Replace(base, "        authorized_keys: /etc/xproxy/authorized_keys\n", "", 1)
	}
	return base
}
