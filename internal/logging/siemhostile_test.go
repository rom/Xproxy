package logging

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func hostileRecord(attrs ...any) slog.Record {
	r := slog.NewRecord(time.Unix(1_700_000_000, 0), slog.LevelWarn, "deny", 0)
	r.Add(attrs...)
	return r
}

// A SIEM record must survive a hostile value without letting the value
// become structure. The newline case was already handled; what was not
// is the rest of C0 and DEL, which carry an escape sequence into an
// operator's console and, in the case of NUL, truncate the record in
// collectors that treat it as a string terminator.
func TestSIEMNeutralisesControlBytes(t *testing.T) {
	m := siemMeta{vendor: "Sysctl", product: "Xproxy", version: "1.3", hostname: "edge1"}
	hostile := "ev\x00il\x1b[2J\x1b]0;pwned\x07tail\x7f"
	rec := hostileRecord("reason", "dns_blocked", "path", hostile)
	for name, line := range map[string]string{
		"cef":  string(cefLine(m, "security", slog.LevelWarn, rec)),
		"leef": string(leefLine(m, "security", slog.LevelWarn, rec)),
	} {
		for _, bad := range []string{"\x00", "\x1b", "\x07", "\x7f", "\n", "\r"} {
			if strings.Contains(line, bad) {
				t.Errorf("%s kept %q: %q", name, bad, line)
			}
		}
		if !strings.Contains(line, "\\x1b") {
			t.Errorf("%s did not render the escape byte: %q", name, line)
		}
	}
}

// An attribute must not overwrite a field the renderer writes itself. A
// DNS query name arrives in an attribute called "name", which is also
// the LEEF event name, so a client could file its own blocked query
// under a label of its choosing.
func TestLEEFAttributeCannotOverwriteAReservedField(t *testing.T) {
	m := siemMeta{vendor: "Sysctl", product: "Xproxy", version: "1.3", hostname: "edge1"}
	rec := hostileRecord("reason", "dns_blocked", "name", "informational heartbeat")
	line := string(leefLine(m, "security", slog.LevelWarn, rec))
	if strings.Count(line, "name=") != 2 { // the real one plus xproxy_name=
		t.Fatalf("expected the attribute to be renamed, got %q", line)
	}
	if !strings.Contains(line, "xproxy_name=informational heartbeat") {
		t.Fatalf("the attribute was not renamed: %q", line)
	}
	if !strings.Contains(line, "\tname=deny\t") {
		t.Fatalf("the renderer's own event name was lost: %q", line)
	}
}

// The standard user field must name the keys the authentication filters
// actually emit, or a SIEM's brute-force and privilege-use rules never
// fire for anything but the jwt filter.
func TestSIEMUserFieldNamesRealKeys(t *testing.T) {
	m := siemMeta{vendor: "Sysctl", product: "Xproxy", version: "1.3", hostname: "edge1"}
	for attr, value := range map[string]string{"auth_user": "alice", "api_key": "k-42", "oidc_user": "bob"} {
		rec := hostileRecord(attr, value)
		cef := string(cefLine(m, "access", slog.LevelInfo, rec))
		if !strings.Contains(cef, "suser="+value) {
			t.Errorf("CEF suser missing for %s: %q", attr, cef)
		}
		leef := string(leefLine(m, "access", slog.LevelInfo, rec))
		if !strings.Contains(leef, "usrName="+value) {
			t.Errorf("LEEF usrName missing for %s: %q", attr, leef)
		}
	}
}
