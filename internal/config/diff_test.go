package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const diffBase = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
management: {socket: /tmp/x.sock}
rate_limits:
  - {name: api, rate: 10, burst: 20}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}]
  - name: old
    endpoints: [{address: 127.0.0.1:2}]
routes:
  - name: web
    hosts: [www.test]
    upstream: app
  - name: legacy
    hosts: [old.test]
    upstream: old
`

const diffNext = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}, {name: alt, address: "127.0.0.1:0"}]
management: {socket: /tmp/y.sock}
compression: {}
rate_limits:
  - {name: api, rate: 20, burst: 20}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:1}, {address: 127.0.0.1:3}]
routes:
  - name: web
    hosts: [www.test]
    upstream: app
  - name: api
    hosts: [api.test]
    rate_limits: [api]
    upstream: app
`

func TestDiff(t *testing.T) {
	a, err := Parse([]byte(diffBase))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(diffNext))
	if err != nil {
		t.Fatal(err)
	}
	same := Diff(a, a, "x", "y")
	if !same.Same || len(same.Changes) != 0 || same.Text != "" {
		t.Fatalf("identical configs differ: %+v", same)
	}
	ch := Diff(a, b, "active", "file")
	if ch.Same {
		t.Fatal("changes not seen")
	}
	want := map[string]string{
		"server.listeners/alt": "added", "management/": "changed", "compression/": "added", "rate_limits/api": "changed",
		"upstreams/app": "changed", "upstreams/old": "removed", "routes/api": "added", "routes/legacy": "removed",
	}
	got := map[string]string{}
	for _, c := range ch.Changes {
		got[c.Section+"/"+c.Name] = c.Kind
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all: %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected changes: %v", got)
	}
	joined := strings.Join(ch.Summary, "\n")
	for _, s := range []string{"routes: 1 added, 1 removed", "upstreams: 1 removed, 1 changed", "server.listeners: 1 added"} {
		if !strings.Contains(joined, s) {
			t.Errorf("summary %q missing in %q", s, joined)
		}
	}
	restart := strings.Join(ch.RestartNeeded, "\n")
	if strings.Contains(restart, "listener alt") || !strings.Contains(restart, "management.socket") {
		t.Errorf("restart needed: %v", ch.RestartNeeded)
	}
	if len(ch.Drains) != 0 {
		t.Errorf("an added listener drains nothing: %v", ch.Drains)
	}
	removedLegacy := regexp.MustCompile(`(?m)^-\s+- name: legacy$`)
	addedAPI := regexp.MustCompile(`(?m)^\+\s+- name: api$`)
	if !strings.HasPrefix(ch.Text, "--- active\n+++ file\n@@ ") || !removedLegacy.MatchString(ch.Text) || !addedAPI.MatchString(ch.Text) {
		t.Fatalf("text diff:\n%s", ch.Text)
	}
	// Dump clears includes and round trips.
	a.Includes = []string{"/etc/xproxy/conf.d/*.yaml"}
	out, err := Dump(a)
	if err != nil || strings.Contains(string(out), "conf.d") {
		t.Fatalf("dump: %v %s", err, out)
	}
	if _, err := Parse(out); err != nil {
		t.Fatalf("dump does not load: %v", err)
	}
}

func TestUnifiedDiff(t *testing.T) {
	text, trunc := unifiedDiff("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n", "a\nb\nc\nd\nE\nf\ng\nh\ni\nj\nk\n", "l", "r")
	if trunc {
		t.Fatal("truncated")
	}
	// The two changes are within twice the context of each other, so they
	// share one hunk, as diff -u would print.
	want := "--- l\n+++ r\n@@ -2,9 +2,10 @@\n b\n c\n d\n-e\n+E\n f\n g\n h\n i\n j\n+k\n"
	if text != want {
		t.Fatalf("got:\n%s\nwant:\n%s", text, want)
	}
	if _, trunc := unifiedDiff(strings.Repeat("x\n", 6000), strings.Repeat("y\n", 6000), "a", "b"); !trunc {
		t.Fatal("large inputs not truncated")
	}
}

func TestHistory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hist")
	h, err := NewHistory(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", st.Mode().Perm())
	}
	a, _ := Parse([]byte(diffBase))
	b, _ := Parse([]byte(diffNext))
	e1, err := h.Record(a, 1, "/etc/x.yaml", "start")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Record(b, 2, "/etc/x.yaml", "reload"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Record(a, 3, "/etc/x.yaml", "rollback "+e1.ID); err != nil {
		t.Fatal(err)
	}
	// Foreign files are ignored.
	_ = os.WriteFile(filepath.Join(dir, "notes.yaml"), []byte("x: 1\n"), 0o600)
	entries, err := h.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Generation != 3 || entries[1].Generation != 2 || entries[0].Note != "rollback "+e1.ID || entries[1].Source != "/etc/x.yaml" {
		t.Fatalf("entries %+v", entries)
	}
	if st, _ := os.Stat(filepath.Join(dir, entries[0].ID+".yaml")); st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o", st.Mode().Perm())
	}
	c, raw, err := h.Load(entries[1].ID)
	if err != nil || len(c.Routes) != 2 || c.Routes[1].Name != "api" || !strings.HasPrefix(string(raw), historyHeader) {
		t.Fatalf("load: %v %+v", err, c)
	}
	for _, bad := range []string{"", "../x", "a/b", e1.ID} { // e1 was pruned
		if _, _, err := h.Load(bad); err == nil {
			t.Errorf("load %q accepted", bad)
		}
	}
	var none *History
	if _, err := none.List(); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("nil history: %v", err)
	}
	if _, err := NewHistory("", 5); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("empty dir: %v", err)
	}
}

// A route's request_headers.set is where the credential the origin
// expects lives. A management response travels much further than the
// file on disk — xproxyctl over the socket, the GUI, a dry run pasted
// into a ticket — so the values go and the names stay. The history
// keeps the real document, because a rollback writes it back.
func TestHeaderValuesAreRedactedInDumpsAndDiffs(t *testing.T) {
	base := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - name: r
    upstream: u
    request_headers:
      set: {X-Origin-Key: %q}
    response_headers:
      add: {X-Trace: %q}
`
	from, err := Parse([]byte(fmt.Sprintf(base, "s3cret-one", "t-one")))
	if err != nil {
		t.Fatal(err)
	}
	to, err := Parse([]byte(fmt.Sprintf(base, "s3cret-two", "t-two")))
	if err != nil {
		t.Fatal(err)
	}
	red, err := DumpRedacted(from)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(red); strings.Contains(s, "s3cret-one") || strings.Contains(s, "t-one") {
		t.Fatalf("a header value survived the redaction:\n%s", s)
	}
	if !strings.Contains(string(red), "X-Origin-Key") || !strings.Contains(string(red), RedactedValue) {
		t.Fatalf("the header names or the placeholder are missing:\n%s", red)
	}
	// The history's document keeps them: a rollback writes it back.
	plain, err := Dump(from)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), "s3cret-one") {
		t.Fatal("Dump lost a value the history needs")
	}
	// The change is still reported, computed from the real documents,
	// and the text carries neither value.
	ch := Diff(from, to, "active", "file")
	if ch.Same || len(ch.Changes) == 0 {
		t.Fatalf("a changed header value was not reported: %+v", ch)
	}
	if strings.Contains(ch.Text, "s3cret-one") || strings.Contains(ch.Text, "s3cret-two") {
		t.Fatalf("the diff text leaked a header value:\n%s", ch.Text)
	}
}

func TestEveryCredentialFieldIsRedactedInDumpsAndDiffs(t *testing.T) {
	c := &Config{
		Metrics: Metrics{OTLP: &OTLP{Headers: map[string]string{"Authorization": "Bearer metrics-secret"}}},
		Logging: Logging{
			OTLP: &OTLPExport{Headers: map[string]string{"Authorization": "Bearer logs-secret"}},
			SIEM: &SIEM{Headers: map[string]string{"X-Token": "siem-secret"}},
		},
		Upstreams: []Upstream{{
			Name:      "api",
			Discovery: &Discovery{Headers: map[string]string{"X-Consul-Token": "consul-secret"}},
		}},
		ThreatIntel: &ThreatIntel{Lists: []ThreatList{{
			Name: "feed",
			HTTP: &FeedHTTP{Token: "feed-secret", HeaderValue: "hv-secret"},
		}}},
	}
	b, err := DumpRedacted(c)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, secret := range []string{
		"metrics-secret", "logs-secret", "siem-secret",
		"consul-secret", "feed-secret", "hv-secret",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s survived the redaction", secret)
		}
	}
	// The names stay: which header a collector wants is not the secret.
	for _, name := range []string{"Authorization", "X-Consul-Token", "X-Token"} {
		if !strings.Contains(out, name) {
			t.Errorf("the header name %s was lost", name)
		}
	}
	if !strings.Contains(out, RedactedValue) {
		t.Error("nothing was marked redacted")
	}
}
