package logging

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// A security event whose reason maps to an ATT&CK for ICS technique
// carries the technique, and one that does not carries no such field.
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
	// The event's own fields are untouched, and the attributes a kind
	// passed still arrive.
	if m["reason"] != "modbus_read_only" || m["action"] != "deny" || m["client_ip"] != "10.40.1.9" {
		t.Errorf("the event lost its own fields: %v", m)
	}

	// Protocol hygiene and the HTTP side carry nothing, because a
	// technique label on those would be a claim in a coverage report.
	for _, reason := range []string{"modbus_tls_handshake", "rate_limit", "waf"} {
		m := read(t, "deny", reason)
		if _, ok := m["technique"]; ok {
			t.Errorf("%s was tagged %v", reason, m["technique"])
		}
	}

	// A detection rather than a refusal is tagged the same way: the
	// action says what was done about it, the technique says what it was.
	if got := read(t, "alert", "modbus_anomaly_write_burst")["technique"]; got != "T0806,T0836" {
		t.Errorf("an anomaly finding was tagged %v", got)
	}
}
