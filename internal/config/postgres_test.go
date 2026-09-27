package config

import (
	"strings"
	"testing"
)

// postgresDeceptionConfig is one postgres listener with a deception section.
func postgresDeceptionConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: postgres
      postgres:
` + section + `
upstreams:
  - name: pg
    endpoints: [{address: "10.0.0.9:5432"}]
`
}

// The client list, and the two contradictions worth refusing.
func TestPostgresDeceptionInsistsOnAClientList(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "answer mode with a client list",
			section: `        upstream: pg
        require_tls: false
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]
          version: "15.6"`,
		},
		{
			name: "answer mode with no client list",
			section: `        upstream: pg
        require_tls: false
        deception: {mode: answer, version: "15.6"}`,
			wants: "clients: required in mode answer",
		},
		{
			name: "a decoy listener needs no upstream and no clients",
			section: `        require_tls: false
        deception: {mode: decoy, version: "15.6"}`,
		},
		{
			name: "a decoy listener with an upstream is a contradiction",
			section: `        upstream: pg
        require_tls: false
        deception: {mode: decoy, version: "15.6"}`,
			wants: "decoy is the whole listener",
		},
		{
			// Unlike MySQL's, this fabrication can be behind TLS: the encryption
			// is negotiated before the startup packet and the relay answers the
			// SSLRequest itself, so a decoy with a certificate serves a client
			// that insists on TLS. Without one the existing check fires, and it
			// is the same check every other listener gets.
			name:    "a decoy listener that requires TLS it has no certificate for",
			section: `        deception: {mode: decoy, version: "15.6"}`,
			wants:   "require_tls",
		},
		{
			name: "a mode that is neither",
			section: `        require_tls: false
        deception: {mode: mirror}`,
			wants: "mode: must be answer or decoy",
		},
		{
			// A listener with no upstream and the section switched off is a
			// listener with nothing to relay to, so the ordinary requirement is
			// back.
			name: "a disabled decoy still needs an upstream",
			section: `        require_tls: false
        deception: {mode: decoy, enabled: false}`,
			wants: "upstream: required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(postgresDeceptionConfig(tc.section)))
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

// The fields of the section.
func TestPostgresDeceptionFieldsAreChecked(t *testing.T) {
	base := "        require_tls: false\n"
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a profile that does not exist",
			section: base + `        deception: {mode: decoy, version: "15.6", profile: oracle}`,
			wants:   "is not a profile",
		},
		{
			name:    "a version longer than a version",
			section: base + `        deception: {mode: decoy, version: "` + strings.Repeat("1", 130) + `"}`,
			wants:   "version: 130 characters",
		},
		{
			name:    "a database name PostgreSQL would not accept",
			section: base + `        deception: {mode: decoy, version: "15.6", databases: [""]}`,
			wants:   "databases[0]",
		},
		{
			// A catalogue query answers per schema, so a bare table name belongs
			// to none and would never be listed.
			name:    "a table with no schema in front of it",
			section: base + `        deception: {mode: decoy, version: "15.6", tables: ["users"]}`,
			wants:   "must be written schema.table",
		},
		{
			name:    "a tripwire with a space in it",
			section: base + `        deception: {mode: decoy, version: "15.6", tripwire: ["pg_read file"]}`,
			wants:   "tripwire[0]",
		},
		{
			name:    "a client record bound that is not a bound",
			section: base + `        deception: {mode: decoy, version: "15.6", max_clients: -1}`,
			wants:   "max_clients",
		},
		{
			name:    "a period outside the bounds",
			section: base + `        deception: {mode: decoy, version: "15.6", period: 2h}`,
			wants:   "period: must be between 1s and 1h",
		},
		{
			name:    "a client list that is not a prefix",
			section: base + `        deception: {mode: decoy, version: "15.6", clients: ["10.0.0.1"]}`,
			wants:   "clients",
		},
		{
			name: "and a whole section that is right",
			section: base + `        deception:
          mode: decoy
          profile: rails
          version: "13.14 (Debian 13.14-1.pgdg120+2)"
          databases: ["postgres", "app_production"]
          tables: ["public.users", "public.accounts"]
          tripwire: ["billing_secrets"]
          period: 30s
          max_clients: 512
          clients: ["10.9.0.0/24"]`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(postgresDeceptionConfig(tc.section)))
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

// What is worth saying at load rather than being discovered from a decoy nobody
// believed -- or from one that was believed and then said yes to the wrong
// question.
func TestPostgresDeceptionWarnings(t *testing.T) {
	base := "        require_tls: false\n"
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a decoy that answers every client",
			section: base + `        deception: {mode: decoy, version: "15.6"}`,
			wants:   "every client that connects is answered by the fabricated",
		},
		{
			name:    "no version, so the profile's is reported",
			section: base + `        deception: {mode: decoy}`,
			wants:   "A decoy should say what the",
		},
		{
			// The most consequential field of the section: a superuser can COPY
			// FROM PROGRAM, which is a shell command.
			name:    "a decoy that claims a superuser role",
			section: base + `        deception: {mode: decoy, version: "15.6", superuser: true}`,
			wants:   "COPY FROM PROGRAM is a shell command",
		},
		{
			// On this protocol the reconnaissance happens after the login, so a
			// decoy that refuses the login collects nothing past the startup.
			name:    "a decoy that refuses every login",
			section: base + `        deception: {mode: decoy, version: "15.6", require_auth: true}`,
			wants:   "nothing past the",
		},
		{
			// And in mode answer there is no login to refuse at all: the real
			// server decides that one. A setting that does nothing should say so
			// at load rather than be relied on.
			name: "require_auth on a listener that fronts a real server",
			section: `        upstream: pg
        require_tls: false
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]
          version: "15.6"
          require_auth: true`,
			wants: "does nothing in mode answer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(postgresDeceptionConfig(tc.section)), false)
			if err != nil {
				t.Fatalf("did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.wants) {
				t.Errorf("no warning %q: %v", tc.wants, cfg.Advice())
			}
		})
	}
}

// The profile list the validator checks against must be the one the listener has,
// or a configuration that loads names a profile the kind will refuse to build.
func TestThePostgresProfileListsAgree(t *testing.T) {
	for _, name := range PostgresDecoyProfiles {
		section := "        require_tls: false\n" +
			`        deception: {mode: decoy, version: "15.6", profile: ` + name + `}`
		if _, err := parseNoFiles([]byte(postgresDeceptionConfig(section))); err != nil {
			t.Errorf("profile %q does not load: %v", name, err)
		}
	}
}
