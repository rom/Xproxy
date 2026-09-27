package config

import (
	"strings"
	"testing"
)

// mysqlDeceptionConfig is one mysql listener with a deception section.
func mysqlDeceptionConfig(section string) string {
	return `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: mysql
      mysql:
` + section + `
upstreams:
  - name: my
    endpoints: [{address: "10.0.0.9:3306"}]
`
}

// The client list, and the two contradictions worth refusing.
func TestMySQLDeceptionInsistsOnAClientList(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name: "answer mode with a client list",
			section: `        upstream: my
        require_tls: false
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]
          version: "8.0.36"`,
		},
		{
			name: "answer mode with no client list",
			section: `        upstream: my
        require_tls: false
        deception: {mode: answer, version: "8.0.36"}`,
			wants: "clients: required in mode answer",
		},
		{
			name: "a decoy listener needs no upstream and no clients",
			section: `        require_tls: false
        deception: {mode: decoy, version: "8.0.36"}`,
		},
		{
			name: "a decoy listener with an upstream is a contradiction",
			section: `        upstream: my
        require_tls: false
        deception: {mode: decoy, version: "8.0.36"}`,
			wants: "decoy is the whole listener",
		},
		{
			// The fabricated greeting does not offer CLIENT_SSL, so a listener
			// requiring TLS would refuse every client before the fabrication
			// said a word.
			name:    "a decoy listener that requires TLS it cannot offer",
			section: `        deception: {mode: decoy, version: "8.0.36"}`,
			wants:   "decoy needs require_tls: false",
		},
		{
			name: "a mode that is neither",
			section: `        require_tls: false
        deception: {mode: mirror}`,
			wants: "mode: must be answer or decoy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(mysqlDeceptionConfig(tc.section)))
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
func TestMySQLDeceptionFieldsAreChecked(t *testing.T) {
	base := "        require_tls: false\n"
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a profile that does not exist",
			section: base + `        deception: {mode: decoy, version: "8.0", profile: oracle}`,
			wants:   "is not a profile",
		},
		{
			name:    "a version longer than a version",
			section: base + `        deception: {mode: decoy, version: "` + strings.Repeat("8", 70) + `"}`,
			wants:   "version: 70 characters",
		},
		{
			name:    "a database name MySQL would not accept",
			section: base + `        deception: {mode: decoy, version: "8.0", databases: [""]}`,
			wants:   "databases[0]",
		},
		{
			// SHOW TABLES answers per database, so a bare table name belongs to
			// none and would never be listed.
			name:    "a table with no database in front of it",
			section: base + `        deception: {mode: decoy, version: "8.0", tables: ["users"]}`,
			wants:   "must be written database.table",
		},
		{
			name:    "a tripwire with a space in it",
			section: base + `        deception: {mode: decoy, version: "8.0", tripwire: ["mysql user"]}`,
			wants:   "tripwire[0]",
		},
		{
			name:    "a client record bound that is not a bound",
			section: base + `        deception: {mode: decoy, version: "8.0", max_clients: -1}`,
			wants:   "max_clients",
		},
		{
			name:    "a period outside the bounds",
			section: base + `        deception: {mode: decoy, version: "8.0", period: 2h}`,
			wants:   "period: must be between 1s and 1h",
		},
		{
			name: "and a whole section that is right",
			section: base + `        deception:
          mode: decoy
          profile: wordpress
          version: "5.7.44-0ubuntu0.20.04.1"
          databases: ["information_schema", "mysql", "wordpress"]
          tables: ["wordpress.wp_users", "wordpress.wp_options"]
          tripwire: ["wp_users"]
          period: 30s
          max_clients: 512`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNoFiles([]byte(mysqlDeceptionConfig(tc.section)))
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
// believed.
func TestMySQLDeceptionWarnings(t *testing.T) {
	base := "        require_tls: false\n"
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a decoy that answers every client",
			section: base + `        deception: {mode: decoy, version: "8.0.36"}`,
			wants:   "every client that connects is answered by the fabricated",
		},
		{
			name:    "no version, so the profile's is reported",
			section: base + `        deception: {mode: decoy}`,
			wants:   "A decoy should say what the",
		},
		{
			name: "a table whose database is not in the list",
			section: base + `        deception:
          mode: decoy
          version: "8.0.36"
          databases: ["mysql"]
          tables: ["crm.contacts"]`,
			wants: "names a database that is not in databases",
		},
		{
			// On this protocol the reconnaissance happens after the login, so a
			// decoy that refuses the login collects nothing.
			name:    "a decoy that refuses every login",
			section: base + `        deception: {mode: decoy, version: "8.0.36", require_auth: true}`,
			wants:   "nothing past the greeting is ever collected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(mysqlDeceptionConfig(tc.section)), false)
			if err != nil {
				t.Fatalf("did not load: %v", err)
			}
			if !hasAdvice(cfg, tc.wants) {
				t.Errorf("no warning %q: %v", tc.wants, cfg.Advice())
			}
		})
	}
}
