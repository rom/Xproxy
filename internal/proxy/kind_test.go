package proxy

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/logging"
)

// sections are a minimal valid configuration section per kind, so the
// refusal below is reached through the engine rather than short of it:
// a listener that never passes validation proves nothing about what a
// daemon does with one that does.
var sections = map[string]string{
	"http":     "",
	"tcp":      "tcp: {default: u}",
	"forward":  "forward: {ports: [443]}",
	"dns":      `dns: {upstreams: ["127.0.0.1:53"]}`,
	"udp":      "udp: {upstream: u}",
	"ssh":      "ssh: {upstream: u, host_keys: [/dev/null], authorized_keys: /dev/null, upstream_key_file: /dev/null, upstream_known_hosts: /dev/null}",
	"telnet":   "telnet: {upstream: u}",
	"vnc":      "vnc: {upstream: u, security_types: [none]}",
	"rdp":      "rdp: {upstream: u}\n      tls: {certificates: [{cert_file: /dev/null, key_file: /dev/null}]}",
	"smtp":     "smtp: {upstream: u}",
	"mqtt":     "mqtt: {upstream: u}",
	"ftp":      "ftp: {upstream: u}",
	"syslog":   "syslog: {upstream: u}",
	"modbus":   "modbus: {upstream: u}",
	"iec104":   "iec104: {upstream: u}",
	"snmp":     "snmp: {upstream: u}",
	"ldap":     "ldap: {upstream: u}",
	"tftp":     "tftp: {upstream: u}",
	"postgres": "postgres: {upstream: u, require_tls: false}",
	"mysql":    "mysql: {upstream: u, require_tls: false}",
	"tds":      "tds: {upstream: u, require_tls: false}",
	"dhcp":     "dhcp: {upstream: u, relay_address: 10.0.0.1}",
	"ntp":      "ntp: {upstream: u}",
	"ntske":    "ntske: {upstream: u}",
}

// TestUnlinkedKindRefused is the guarantee the three-binary split rests
// on. internal/proxy links no kind of its own, so every kind in the
// roster is foreign to this test binary: each one must be refused by
// name, with the daemon that does serve it, rather than falling through
// to the HTTP data plane and answering the wrong protocol on the right
// port.
func TestUnlinkedKindRefused(t *testing.T) {
	reached := 0
	for _, kind := range listener.Kinds() {
		if _, linked := kindFor(kind); linked {
			t.Fatalf("kind %q is linked into internal/proxy; the engine must not depend on a kind package", kind)
		}
		section, ok := sections[kind]
		if !ok {
			t.Errorf("kind %q has no section here, so nothing tests the refusal for it", kind)
			continue
		}
		yaml := `
version: 1
server:
  listeners:
    - name: l
      address: "127.0.0.1:0"
      kind: ` + kind + `
      ` + section + `
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`
		cfg, err := config.Parse([]byte(yaml))
		if err != nil {
			t.Errorf("kind %q: the section here is not valid: %v", kind, err)
			continue
		}
		reached++
		s, err := New(cfg, logging.Discard())
		if err == nil {
			err = s.Start()
		}
		if err == nil {
			t.Errorf("kind %q started in a binary that did not link it", kind)
			s.Shutdown(t.Context())
			continue
		}
		want, _ := listener.RoleOf(kind)
		if !strings.Contains(err.Error(), want.Daemon()) {
			t.Errorf("kind %q: %v does not name %s", kind, err, want.Daemon())
		}
	}
	if reached == 0 {
		t.Fatal("no kind reached the engine, so nothing was tested")
	}
}

// TestRosterCoversEveryRegisteredName keeps the roster and the registry
// from drifting: a kind may be linked or not, but a name that no role
// owns cannot be configured, so registering one would build a daemon
// with a listener kind nothing can ask for.
func TestRosterCoversEveryRegisteredName(t *testing.T) {
	for _, n := range Registered() {
		if _, ok := listener.RoleOf(n); !ok {
			t.Errorf("kind %q is registered and not in the roster", n)
		}
	}
}
