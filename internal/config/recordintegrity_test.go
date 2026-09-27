package config

import (
	"strings"
	"testing"
)

// recordingConfig is an ssh bastion that records, with whatever the test
// puts under the recording section.
func recordingConfig(integrity string) string {
	return `
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [/etc/xproxy/ssh_host_ed25519_key]
        authorized_keys: /etc/xproxy/authorized_keys
        upstream_key_file: /etc/xproxy/id_ed25519
        upstream_known_hosts: /etc/xproxy/known_hosts
        recording:
          directory: /var/log/xproxy/sessions
` + integrity + `
upstreams:
  - name: hosts
    endpoints: [{address: "10.0.0.9:22"}]
`
}

// The manifest's key is a secret reference like every other, so it is
// held to the same rules: a scheme that exists, an absolute path, and a
// vault only where there is a vault to ask.
func TestTheManifestKeyIsASecretReference(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		wants string
	}{
		{name: "a path", key: "/etc/xproxy/recording.key"},
		{name: "the environment", key: "env:XPROXY_CHAIN_KEY"},
		{name: "a relative path", key: "file:recording.key", wants: "must be an absolute path"},
		{name: "a vault with no vault", key: "vault:secret/rec#key", wants: "there is no secrets.vault section"},
		{name: "a scheme that does not exist", key: "kms:arn/whatever", wants: "unknown reference scheme"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(recordingConfig(
				"          integrity:\n            key: " + tc.key + "\n")))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// How much one record covers decides how precisely an edit is located.
// It is bounded rather than left open: a record per byte is a manifest
// larger than the recording, and one per gigabyte localises nothing.
func TestTheSegmentSizeIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes string
		wants string
	}{
		{name: "the default", bytes: ""},
		{name: "four kilobytes", bytes: "            segment_bytes: 4096\n"},
		{name: "one byte", bytes: "            segment_bytes: 1\n", wants: "must be 4096..1073741824"},
		{name: "four gigabytes", bytes: "            segment_bytes: 4294967296\n", wants: "must be 4096..1073741824"},
		{name: "negative", bytes: "            segment_bytes: -1\n", wants: "must be 4096..1073741824"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseNoFiles([]byte(recordingConfig(
				"          integrity:\n            key: env:K\n" + tc.bytes)))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
				got := cfg.Server.Listeners[0].SSH.Recording.Integrity.SegmentBytes
				if tc.bytes == "" && got != 1<<20 {
					t.Errorf("segment_bytes defaulted to %d, want 1048576", got)
				}
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// A chain with no key is worth having and is not what an operator who
// asked for evidence thinks they configured, so it loads and says so.
func TestAManifestWithNoKeyWarns(t *testing.T) {
	cfg, err := ParseWith([]byte(recordingConfig("          integrity: {}\n")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAdvice(cfg, "recompute the chain") {
		t.Fatalf("no warning about an unkeyed manifest: %v", cfg.Advice())
	}
	// With a key it is quiet, and a section turned off says nothing at
	// all -- including nothing about the key it does not have.
	for _, quiet := range []string{
		"          integrity:\n            key: env:K\n",
		"          integrity:\n            enabled: false\n",
	} {
		cfg, err = ParseWith([]byte(recordingConfig(quiet)), false)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range cfg.Advice() {
			if strings.Contains(a, "integrity") {
				t.Errorf("%q warned: %q", quiet, a)
			}
		}
	}
}

// Turning the manifest off must not also turn off its bounds check on
// the way past, and a section that is off is not a section to complete.
func TestAnIntegritySectionThatIsOffIsNotValidated(t *testing.T) {
	_, err := parseNoFiles([]byte(recordingConfig(
		"          integrity:\n            enabled: false\n            segment_bytes: 1\n")))
	if err != nil {
		t.Fatalf("a section that is off did not load: %v", err)
	}
}
