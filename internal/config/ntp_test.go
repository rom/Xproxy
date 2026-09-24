package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ntpConfig wraps an ntp section in the smallest document that carries
// it: one time listener and a pool of three servers, because three is
// what makes a comparison able to name the wrong clock.
func ntpConfig(t *testing.T, section string) string {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "ntp.key")
	if err := os.WriteFile(key, []byte("2b7e151628aed2a6abf7158809cf4f3c"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := `
version: 1
server:
  listeners:
    - name: time
      address: "0.0.0.0:123"
      kind: ntp
      ntp:
` + section + `
upstreams:
  - name: clocks
    endpoints:
      - {address: "10.0.0.11:123"}
      - {address: "10.0.0.12:123"}
      - {address: "10.0.0.13:123"}
  - name: one_clock
    endpoints: [{address: "10.0.0.11:123"}]
`
	return strings.ReplaceAll(doc, "KEYFILE", key)
}

const ntpGood = `        upstream: clocks
        allow_clients: ["10.20.0.0/16"]
        rate_limit: 20
        rate_burst: 40
        versions: [4]
        modes: [client, server]
        quality:
          compare_sources: true
          probe_interval: 64s
          max_disagreement: 100ms
          max_root_dispersion: 1s
          max_stratum: 10
`

// The section a plant writes loads, and the defaults are the ones the
// documentation promises.
func TestNTPSectionLoads(t *testing.T) {
	cfg, err := ParseWith([]byte(ntpConfig(t, ntpGood)), false)
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.Server.Listeners[0].NTP
	if n == nil || n.Upstream != "clocks" {
		t.Fatalf("section: %+v", n)
	}
	if !n.Alerts() {
		t.Error("a refusal is alerted on unless the listener says otherwise")
	}
	if !n.InterleavedAllowed() {
		t.Error("interleaved mode is accepted by default")
	}
	off := false
	n.Interleaved = &off
	if n.InterleavedAllowed() {
		t.Error("turning interleaved off has to work")
	}
	var absent *NTPListener
	if !absent.Alerts() || absent.InterleavedAllowed() != true {
		t.Error("a listener with no ntp section has the safe answers")
	}
	var noKE *NTSKEListener
	if !noKE.Alerts() || !noKE.ALPNRequired() {
		t.Error("the key establishment defaults are the strict ones")
	}
}

// What does not load. Each of these is a time policy that would read as
// something it is not.
func TestNTPRefusals(t *testing.T) {
	for _, tc := range []struct{ name, section, want string }{
		{"no upstream", `        allow_clients: ["10.0.0.0/8"]
`, "upstream: required"},
		{"a mode that is not one", `        upstream: clocks
        mode: sideways
`, "mode: must be reverse or forward"},
		{"a version this parser does not read", `        upstream: clocks
        versions: [7]
`, "is not an NTP version"},
		{"version 5 in the version list", `        upstream: clocks
        versions: [5]
`, "allow_version5 forwards it as opaque bytes"},
		{"the control protocol named as a mode", `        upstream: clocks
        modes: [client, control]
`, "not a time service mode and is always refused"},
		{"the private protocol named as a mode", `        upstream: clocks
        modes: [client, private]
`, "not a time service mode and is always refused"},
		{"a mode nobody defined", `        upstream: clocks
        modes: [gossip]
`, "is not a mode"},
		{"a symmetric mode with no peers", `        upstream: clocks
        modes: [client, symmetric_active]
`, "peers: required when a symmetric or broadcast mode is accepted"},
		{"manycast with no responders", `        upstream: clocks
        allow_manycast: true
`, "manycast_responders: required"},
		{"a client list that is not networks", `        upstream: clocks
        allow_clients: ["10.0.0.1"]
`, "is not a network in CIDR form"},
		{"an egress list that is not networks", `        upstream: clocks
        allow_servers: ["notanaddress"]
`, "is not a network in CIDR form"},
		{"a key identifier outside the field", `        upstream: clocks
        auth: {keys: [{id: 70000, key_file: KEYFILE}]}
`, "id: must be between 1 and 65535"},
		{"two keys with one identifier", `        upstream: clocks
        auth: {keys: [{id: 7, key_file: KEYFILE}, {id: 7, key_file: KEYFILE}]}
`, "duplicate 7"},
		{"an algorithm nobody implements", `        upstream: clocks
        auth: {keys: [{id: 7, algorithm: sha3, key_file: KEYFILE}]}
`, "must be aes-cmac, md5 or sha1"},
		{"a legacy algorithm without the exception", `        upstream: clocks
        auth: {keys: [{id: 7, algorithm: md5, key_file: KEYFILE}]}
`, "needs auth.allow_legacy_algorithms"},
		{"a key with no file", `        upstream: clocks
        auth: {keys: [{id: 7}]}
`, "key_file: required"},
		{"a key file that is not absolute", `        upstream: clocks
        auth: {keys: [{id: 7, key_file: ntp.key}]}
`, "must be an absolute path"},
		{"authentication required with nothing to check it with", `        upstream: clocks
        auth: {require: true}
`, "needs keys, or nts.require"},
		{"a probe key nobody holds", `        upstream: clocks
        auth: {probe_key_id: 9, keys: [{id: 7, key_file: KEYFILE}]}
`, "probe_key_id: 9 is not one of the keys"},
		{"an NTS mode that is not one", `        upstream: clocks
        nts: {mode: terminate}
`, "nts.mode: must be passthrough or off"},
		{"NTS required and turned off at once", `        upstream: clocks
        nts: {mode: off, require: true}
`, "require with mode off refuses every packet"},
		{"more extension fields than a packet has", `        upstream: clocks
        extensions: {max: 64}
`, "extensions.max: must be between 1 and 32"},
		{"a probe interval nobody meant", `        upstream: clocks
        quality: {probe_interval: 10ms}
`, "probe_interval: must be between 1s and 1h"},
		{"a stratum that is not one", `        upstream: clocks
        quality: {max_stratum: 20}
`, "max_stratum: must be between 0 and 16"},
		{"hysteresis nobody meant", `        upstream: clocks
        quality: {healthy_after: 500}
`, "healthy_after: must be between 0 and 100"},
		{"an on_all_suspect that is not one", `        upstream: clocks
        quality: {on_all_suspect: shrug}
`, "on_all_suspect: must be pass or refuse"},
		{"a holdover nobody meant", `        upstream: clocks
        holdover: {max_duration: 48h}
`, "holdover.max_duration: must be between 0 and 24h"},
		{"a packet bound below the header", `        upstream: clocks
        max_packet_bytes: 32
`, "max_packet_bytes: must be between 48"},
		{"an association table nobody meant", `        upstream: clocks
        max_associations: 4
`, "max_associations: must be between 16 and 1000000"},
		{"an outstanding table nobody meant", `        upstream: clocks
        max_outstanding: 4
`, "max_outstanding: must be between 16 and 1000000"},
		{"a request timeout nobody meant", `        upstream: clocks
        request_timeout: 5m
`, "request_timeout: must be between 100ms and 1m"},
		{"an idle timeout nobody meant", `        upstream: clocks
        idle_timeout: 48h
`, "idle_timeout: must be between 1s and 24h"},
		{"a rate limit nobody meant", `        upstream: clocks
        rate_limit: -1
`, "rate_limit: must be between 0 and 1000000"},
		{"a prefix length nobody meant", `        upstream: clocks
        rate_prefix_length: 200
`, "rate_prefix_length: must be between 0 and 128"},
		{"learning with no file", `        upstream: clocks
        learn: {enabled: true}
`, "learn.file: required"},
		{"a learning interval nobody meant", `        upstream: clocks
        learn: {enabled: true, file: /var/lib/x.yaml, interval: 1s}
`, "learn.interval: must be between 10s and 24h"},
		{"a trace with no file", `        upstream: clocks
        trace: {}
`, "trace.file: required"},
		{"a trace bound nobody meant", `        upstream: clocks
        trace: {file: /var/log/t.jsonl, max_bytes: 4096}
`, "trace.max_bytes: must be between 1MiB and 64GiB"},
		{"an upstream that is not there", `        upstream: nowhere
`, "unknown upstream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWith([]byte(ntpConfig(t, tc.section)), false)
			if err == nil {
				t.Fatalf("the document loaded; wanted %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// The time service is UDP and its TLS belongs to the key establishment
// listener, so a tls section on a time listener is a mistake rather than
// a choice.
func TestNTPTakesNoTLSSection(t *testing.T) {
	_, err := ParseWith([]byte(`
version: 1
server:
  listeners:
    - name: time
      address: "0.0.0.0:123"
      kind: ntp
      tls: {certificates: [{cert_file: /c.pem, key_file: /k.pem}]}
      ntp: {upstream: clocks}
upstreams:
  - {name: clocks, endpoints: [{address: "10.0.0.11:123"}]}
`), false)
	if err == nil || !strings.Contains(err.Error(), "an ntp listener takes only address and ntp") {
		t.Fatalf("error %v", err)
	}
}

// The ntp section only belongs on an ntp listener, and the same for the
// key establishment one: a section read nowhere is a policy an operator
// believes is in force.
func TestNTPSectionsBelongToTheirKinds(t *testing.T) {
	for _, tc := range []struct{ name, section, want string }{
		{"ntp on a tcp listener", "ntp: {upstream: clocks}", "ntp: set on a tcp listener"},
		{"ntske on a tcp listener", "ntske: {upstream: clocks}", "ntske: set on a tcp listener"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWith([]byte(`
version: 1
server:
  listeners:
    - name: l
      address: ":9000"
      kind: tcp
      tcp: {default: clocks}
      `+tc.section+`
upstreams:
  - {name: clocks, endpoints: [{address: "10.0.0.11:123"}]}
`), false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// The advice: each of these loads, and each is a time gateway with one
// fewer control than it should have.
func TestNTPAdvice(t *testing.T) {
	for _, tc := range []struct{ name, section, want string }{
		{"no client list", `        upstream: clocks
        rate_limit: 20
`, "allow_clients is empty"},
		{"no rate limit", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
`, "has no rate limit"},
		{"comparison turned off", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        quality: {compare_sources: false}
`, "compare_sources is off"},
		{"fewer than three sources", `        upstream: one_clock
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
`, "the wrong clock cannot be identified"},
		{"a legacy version", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        versions: [2, 4]
`, "which has no mode field of its own"},
		{"unknown extension fields forwarded", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        extensions: {allow_unknown: true}
`, "allow_unknown forwards fields this relay cannot read"},
		{"the ambiguity resolved silently", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        extensions: {refuse_ambiguous_mac: false}
`, "refuse_ambiguous_mac is off"},
		{"an unsynchronised server's answer passed on", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        quality: {refuse_unsynchronised: false}
`, "refuse_unsynchronised is off"},
		{"failing closed when no source is trusted", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        quality: {on_all_suspect: refuse}
`, "deliberate outage"},
		{"version 5 forwarded unparsed", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        allow_version5: true
`, "allow_version5 forwards version 5 packets as opaque bytes"},
		{"learning left on", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        learn: {enabled: true, file: /var/lib/xproxy/ntp-learned.yaml}
`, "learn is enabled without enforce"},
		{"a legacy algorithm kept on purpose", `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 20
        auth: {allow_legacy_algorithms: true, keys: [{id: 7, algorithm: md5, key_file: KEYFILE}]}
`, "which RFC 8573 replaced with AES-CMAC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(ntpConfig(t, tc.section)), false)
			if err != nil {
				t.Fatalf("the document did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.want) {
				t.Fatalf("no advice about %q: %v", tc.want, cfg.Advice())
			}
		})
	}
	// And the configuration an estate should be running is quiet.
	cfg, err := ParseWith([]byte(ntpConfig(t, ntpGood)), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range cfg.Advice() {
		if strings.Contains(a, ".ntp") {
			t.Errorf("a sound configuration warned: %q", a)
		}
	}
}

// The key establishment listener.
func TestNTSKEValidation(t *testing.T) {
	doc := func(section, address string) string {
		return `
version: 1
server:
  listeners:
    - name: ke
      address: "` + address + `"
      kind: ntske
      ntske:
` + section + `
upstreams:
  - {name: ke_servers, endpoints: [{address: "10.0.0.11:4460"}]}
`
	}
	// The section an estate writes loads.
	cfg, err := ParseWith([]byte(doc(`        upstream: ke_servers
        allow_clients: ["10.20.0.0/16"]
        server_names: ["time.plant.example"]
        max_concurrent_handshakes: 16
`, "0.0.0.0:4460")), false)
	if err != nil {
		t.Fatal(err)
	}
	if k := cfg.Server.Listeners[0].NTSKE; k == nil || !k.ALPNRequired() {
		t.Fatalf("section: %+v", k)
	}
	for _, tc := range []struct{ name, section, address, want string }{
		{"no upstream", "        allow_clients: [\"10.0.0.0/8\"]\n", "0.0.0.0:4460", "upstream: required"},
		{"a name that is not a host pattern", "        upstream: ke_servers\n        server_names: [\"not a host\"]\n",
			"0.0.0.0:4460", "is not a valid host pattern"},
		{"a handshake bound nobody meant", "        upstream: ke_servers\n        max_concurrent_handshakes: 99999\n",
			"0.0.0.0:4460", "max_concurrent_handshakes: must be between 1 and 4096"},
		{"a handshake timeout nobody meant", "        upstream: ke_servers\n        handshake_timeout: 10m\n",
			"0.0.0.0:4460", "handshake_timeout: must be between 1s and 1m"},
		{"a byte bound nobody meant", "        upstream: ke_servers\n        max_bytes: 16\n",
			"0.0.0.0:4460", "max_bytes: must be between 1024 and 1GiB"},
		{"an upstream that is not there", "        upstream: nowhere\n", "0.0.0.0:4460", "unknown upstream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseWith([]byte(doc(tc.section, tc.address)), false)
			if err == nil {
				t.Fatalf("the document loaded; wanted %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
	// The advice.
	for _, tc := range []struct{ name, section, address, want string }{
		{"the application protocol not required", "        upstream: ke_servers\n        require_alpn: false\n",
			"0.0.0.0:4460", "require_alpn is off"},
		{"a port a client will not look for", "        upstream: ke_servers\n", "0.0.0.0:4461",
			"a client that found this service through a server's own key establishment record will look for 4460"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(doc(tc.section, tc.address)), false)
			if err != nil {
				t.Fatalf("the document did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.want) {
				t.Fatalf("no advice about %q: %v", tc.want, cfg.Advice())
			}
		})
	}
}
