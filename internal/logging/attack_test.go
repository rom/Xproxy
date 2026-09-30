package logging

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// A security event whose reason maps to an ATT&CK technique carries the
// technique and the matrix it is from, and one that does not carries no
// such field.
//
// It is tested here rather than in each kind because it happens here: one
// choke point, so a kind that gains a refusal reason tomorrow gets the
// tagging without remembering to ask for it.
func TestASecurityEventCarriesItsTechnique(t *testing.T) {
	read := func(t *testing.T, action, reason string) map[string]any {
		t.Helper()
		dir := t.TempDir()
		l, err := Open(config.Logging{Directory: dir, Level: "info",
			Access:   config.LogStream{File: "access.log"},
			Error:    config.LogStream{File: "error.log"},
			Security: config.LogStream{File: "security.log"},
			Audit:    config.LogStream{File: "audit.log"}})
		if err != nil {
			t.Fatal(err)
		}
		l.SecurityEvent(context.Background(), action, reason, "client_ip", "10.40.1.9")
		l.Close()
		b, err := os.ReadFile(filepath.Join(dir, "security.log"))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("not a single JSON line: %q", b)
		}
		return m
	}

	// A write refused on a read-only Modbus listener.
	m := read(t, "deny", "modbus_read_only")
	if m["technique"] != "T0855,T0835" {
		t.Errorf("technique %v", m["technique"])
	}
	if m["technique_name"] != "Unauthorized Command Message,Manipulate I/O Image" {
		t.Errorf("technique_name %v", m["technique_name"])
	}
	if m["tactic"] != "impair-process-control" {
		t.Errorf("tactic %v", m["tactic"])
	}
	if m["matrix"] != "ics" {
		t.Errorf("matrix %v", m["matrix"])
	}
	// The event's own fields are untouched, and the attributes a kind
	// passed still arrive.
	if m["reason"] != "modbus_read_only" || m["action"] != "deny" || m["client_ip"] != "10.40.1.9" {
		t.Errorf("the event lost its own fields: %v", m)
	}

	// Protocol hygiene carries nothing, because a technique label on the
	// noise floor would be a claim in a coverage report.
	for _, reason := range []string{"modbus_tls_handshake", "ldap_malformed", "acl_deny"} {
		m := read(t, "deny", reason)
		if _, ok := m["technique"]; ok {
			t.Errorf("%s was tagged %v", reason, m["technique"])
		}
	}

	// The estate's own refusals carry Enterprise ATT&CK, which is the
	// half of the taxonomy an operations centre outside a plant reads.
	// The HTTP side logs a bare reason, and a WAF refusal logs the rule
	// that fired after a colon: both resolve, because both are what is
	// actually in the log.
	for _, c := range []struct{ reason, id, matrix string }{
		{"waf:942100", "T1190", "enterprise"},
		{"rate_limit", "T1499", "enterprise"},
		{"ldap_leading_wildcard", "T1087", "enterprise"},
		{"postgres_copy_program", "T1059", "enterprise"},
		// A bastion session with no access grant is one refusal with two
		// readings: the way into a plant, and a step through an estate.
		{"ssh_no_grant", "T0886,T1133,T1078", "ics,enterprise"},
	} {
		m := read(t, "deny", c.reason)
		if m["technique"] != c.id {
			t.Errorf("%s: technique %v, want %s", c.reason, m["technique"], c.id)
		}
		if m["matrix"] != c.matrix {
			t.Errorf("%s: matrix %v, want %s", c.reason, m["matrix"], c.matrix)
		}
	}

	// A detection rather than a refusal is tagged the same way: the
	// action says what was done about it, the technique says what it was.
	if got := read(t, "alert", "modbus_anomaly_write_burst")["technique"]; got != "T0806,T0836" {
		t.Errorf("an anomaly finding was tagged %v", got)
	}
}
