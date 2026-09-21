package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func securityTxtConfig(entry string) string {
	return `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
security_txt:
  - ` + strings.ReplaceAll(entry, "\n", "\n    ") + `
upstreams:
  - name: app
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: app
`
}

func TestSecurityTxtValidation(t *testing.T) {
	cfg, err := Parse([]byte(securityTxtConfig(`name: public
hosts: ["example.com", "*.example.com"]
host_regex: '^api[0-9]+\.example\.com$'
host_cidrs: ["198.51.100.0/24", "2001:db8::/32"]
client_cidrs: ["10.0.0.0/8"]
listeners: [main]
contact: ["mailto:security@example.com"]
preferred_languages: [en, sv-SE]
extra: {X-Team: ["appsec"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	st := cfg.SecurityTxt[0]
	// Defaults: a name, an hour of caching and a year of validity, so a
	// document cannot quietly go stale.
	if st.Name != "public" || st.CacheFor != Duration(time.Hour) || st.ValidFor != Duration(365*24*time.Hour) {
		t.Fatalf("defaults: %+v", st)
	}
	// An unnamed entry is named after its position.
	cfg, err = Parse([]byte(securityTxtConfig(`contact: ["mailto:a@example.com"]`)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecurityTxt[0].Name != "security_txt[0]" {
		t.Fatalf("default name %q", cfg.SecurityTxt[0].Name)
	}

	bad := []struct{ entry, want string }{
		{`name: a`, "contact: required"},
		{`name: a
contact: ["mailto:a@example.com"]
body: "Contact: mailto:b@example.com"`, "body and body_file replace the whole document"},
		{`name: a
body: "x"
body_file: /etc/x`, "exclusive"},
		{`name: a
contact: ["mailto:a@example.com"]
expires: "2020-01-01T00:00:00Z"`, "is in the past"},
		{`name: a
contact: ["mailto:a@example.com"]
expires: "tomorrow"`, "not an RFC 3339 instant"},
		{`name: a
contact: ["mailto:a@example.com"]
expires: "2030-01-01T00:00:00Z"
valid_for: 24h`, "expires and valid_for are exclusive"},
		{`name: a
contact: ["mailto:a@example.com"]
valid_for: 1m`, "valid_for"},
		{`name: a
contact: ["mailto:a@example.com"]
cache_for: 1000h`, "cache_for"},
		{`name: a
contact: [""]`, "empty"},
		{`name: a
contact: ["mailto:a@example.com\nContact: mailto:attacker@example.net"]`, "line breaks are not allowed"},
		{`name: a
contact: ["mailto:a@example.com\u0007bell"]`, "control characters"},
		{`name: a
contact: ["mailto:a@example.com"]
hosts: ["not a host"]`, "not a valid host pattern"},
		{`name: a
contact: ["mailto:a@example.com"]
host_regex: "("`, "host_regex"},
		{`name: a
contact: ["mailto:a@example.com"]
client_cidrs: ["10.0.0.0/33"]`, "not a CIDR"},
		{`name: a
contact: ["mailto:a@example.com"]
host_cidrs: ["198.51.100.0"]`, "host_cidrs[0]"},
		{`name: a
contact: ["mailto:a@example.com"]
host_cidrs: ["not-a-network/24"]`, "host_cidrs[0]"},
		{`name: a
contact: ["mailto:a@example.com"]
listeners: [nope]`, "unknown listener"},
		{`name: a
contact: ["mailto:a@example.com"]
preferred_languages: ["en_US!"]`, "not a language tag"},
		{`name: a
contact: ["mailto:a@example.com"]
extra: {"Bad Name": ["x"]}`, "is not a field name"},
		{`name: a
contact: ["mailto:a@example.com"]
body_file: relative/path`, "absolute path"},
	}
	for _, c := range bad {
		_, err := Parse([]byte(securityTxtConfig(c.entry)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v, want %q", strings.SplitN(c.entry, "\n", 2)[0]+"…", err, c.want)
		}
	}
}

// Two entries may not share a name, because the name is what the status
// view and the logs identify the document by.
func TestSecurityTxtDuplicateNames(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
security_txt:
  - {name: same, contact: ["mailto:a@example.com"]}
  - {name: same, contact: ["mailto:b@example.com"]}
upstreams:
  - name: app
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: app
`))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("got %v", err)
	}
}

// A body_file is checked for existence when files are checked, which is
// what -validate does, so a typo is caught before a start rather than at
// the first request.
func TestSecurityTxtBodyFileMustExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.txt")
	yaml := []byte(securityTxtConfig(`name: signed
body_file: ` + path))
	if _, err := ParseWith(yaml, true); err == nil {
		t.Fatal("a missing body_file was accepted")
	}
	// Without the file check it parses, which is what a dry run on
	// another host does.
	if _, err := ParseWith(yaml, false); err != nil {
		t.Fatalf("without the file check: %v", err)
	}
	if err := os.WriteFile(path, []byte("Contact: mailto:a@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseWith(yaml, true); err != nil {
		t.Fatalf("an existing body_file was refused: %v", err)
	}
}
