package http

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// A decoy is served to whoever asked for the path, which means to an
// attacker, to a search engine and, sooner or later, to a screenshot in
// somebody's report. Every one of them has to be plausible enough to be
// worth answering and empty enough that being read costs nothing. These
// properties are checked for the whole table rather than per entry, so a
// decoy added later cannot skip them.

// decoyMarkers are what make a value visibly fake to a person while
// leaving it shaped like the real thing to a scanner: the word itself,
// the reserved documentation names of RFC 2606 and the reserved
// documentation addresses of RFC 5737 and RFC 1918.
var decoyMarkers = []string{
	"decoy", "example", "invalid", "localhost", "test.",
	"127.0.0.1", "10.0.", "192.168.", "198.51.100.", "203.0.113.",
}

func hasMarker(lower string) bool {
	for _, m := range decoyMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// credentialValue matches an assignment of a secret to a value, in the
// spellings the decoys use: JSON, YAML, an ini file and a shell export.
// A bare HTML input named "password" is not one: it carries no value.
var credentialValue = regexp.MustCompile(`(?i)(password|passwd|secret|token|credential|api[_-]?key|access[_-]?key|authtoken)["']?\s*[:=]\s*["']?[^\s"',;)]{6,}`)

// pemPayload returns the base64 body of the first PEM block decoded.
func pemPayload(s string) (string, bool) {
	_, rest, ok := strings.Cut(s, "-----\n")
	if !ok {
		return "", false
	}
	blob, _, ok := strings.Cut(rest, "\n-----")
	if !ok {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(blob, "\n", ""))
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func TestEveryDecoyIsPlausibleAndHarmless(t *testing.T) {
	if len(decoys) < 50 {
		t.Errorf("the decoy table holds %d entries; the documented set is larger", len(decoys))
	}
	// withCredential counts the bodies the marker rule actually judges,
	// so a change to the pattern that stops matching anything cannot
	// turn the rule into a no-op that still passes.
	withCredential, withKeyBlock := 0, 0
	for name, d := range decoys {
		if name != strings.ToLower(name) || strings.ContainsAny(name, " _/\\.") {
			t.Errorf("decoy %q: the name is a configuration value and a lower case identifier", name)
		}
		// A body a scanner would not believe is not a decoy, and one
		// that is too large costs the proxy more than the scanner.
		if len(d.body) < 40 {
			t.Errorf("decoy %q is %d bytes; nothing would believe it", name, len(d.body))
		}
		if len(d.body) > 64<<10 {
			t.Errorf("decoy %q is %d bytes, past what an inline body may be", name, len(d.body))
		}
		// The content type is sent verbatim on the wire.
		mt, _, err := mime.ParseMediaType(d.contentType)
		if err != nil {
			t.Errorf("decoy %q: content type %q does not parse: %v", name, d.contentType, err)
		}
		if strings.ContainsAny(d.contentType, "\r\n") {
			t.Errorf("decoy %q: the content type carries a line break", name)
		}
		// A decoy is never a redirect or a script the proxy's own
		// origin would execute, and never names a host that resolves.
		lower := strings.ToLower(d.body)
		for _, bad := range []string{"http://169.254.169.254", "\x00"} {
			if strings.Contains(lower, bad) {
				t.Errorf("decoy %q carries %q", name, bad)
			}
		}
		// A decoy that carries something shaped like a credential has to
		// mark it visibly fake. A login form with empty inputs carries
		// nothing and needs no marker; a file that hands out a password,
		// a token or a key does, because that value ends up in a scan
		// report and in somebody's screenshot.
		if loc := credentialValue.FindStringIndex(d.body); loc != nil {
			withCredential++
			if !hasMarker(lower) {
				t.Errorf("decoy %q hands out %q with nothing to show it is fake", name, strings.TrimSpace(d.body[loc[0]:loc[1]]))
			}
		}
		// A private key block is the strongest of those: what it holds
		// must decode to something a reader recognises as a message
		// rather than to key material.
		if strings.Contains(d.body, "PRIVATE KEY-----") {
			withKeyBlock++
			body, ok := pemPayload(d.body)
			if !ok {
				t.Errorf("decoy %q has a key block that is not base64", name)
			} else if !hasMarker(strings.ToLower(body)) {
				t.Errorf("decoy %q has a key block that does not say it is a decoy", name)
			}
		}
		// A decoy that claims a structured type has to parse as one, or
		// the scanner learns more from the parse error than from the
		// body.
		switch {
		case strings.Contains(mt, "json"):
			if !json.Valid([]byte(d.body)) {
				t.Errorf("decoy %q claims %s but is not JSON", name, mt)
			}
		case strings.Contains(mt, "xml"):
			if err := xml.Unmarshal([]byte(d.body), new(any)); err != nil {
				t.Errorf("decoy %q claims %s but is not XML: %v", name, mt, err)
			}
		case strings.Contains(mt, "html"):
			if !strings.Contains(lower, "<html") && !strings.Contains(lower, "<!doctype") {
				t.Errorf("decoy %q claims %s but has no document element", name, mt)
			}
		}
		// A decoy ends with a newline, so a terminal that cats it does
		// not run the shell prompt into the body.
		if !strings.HasSuffix(d.body, "\n") {
			t.Errorf("decoy %q does not end with a newline", name)
		}
	}
	if withCredential < 10 {
		t.Errorf("only %d decoys were judged by the credential rule; the pattern has stopped matching", withCredential)
	}
	if withKeyBlock < 1 {
		t.Error("no decoy carries a key block; the key rule was not exercised")
	}
}

// The names the proxy serves and the names the validator accepts are two
// lists in two packages, because the proxy imports the configuration and
// not the other way round. A decoy in one and not the other is either a
// body nobody can select or a name that validates and then fails to
// serve.
func TestDecoyListsAgree(t *testing.T) {
	names := DecoyNames()
	if len(names) != len(decoys) || len(names) != len(config.HoneypotDecoys) {
		t.Fatalf("%d bodies, %d names, %d accepted by the validator", len(decoys), len(names), len(config.HoneypotDecoys))
	}
	for _, n := range names {
		if !config.HoneypotDecoys[n] {
			t.Errorf("the proxy serves %q but the validator refuses it", n)
		}
	}
	for n := range config.HoneypotDecoys {
		if _, ok := decoys[n]; !ok {
			t.Errorf("the validator accepts %q but the proxy has no body for it", n)
		}
	}
	// The list is sorted, because it is printed in the management view
	// and in shell completion.
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("DecoyNames is not sorted: %q before %q", names[i-1], names[i])
		}
	}
}

// Every decoy is reachable through a route, answers with its own content
// type and body, and never reaches an upstream.
func TestEveryDecoyServesThroughARoute(t *testing.T) {
	b := newBackend(t, "origin")
	var sb strings.Builder
	sb.WriteString(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging:
  access: {enabled: false}
upstreams:
  - name: app
    endpoints: [{address: "` + b.addr() + `"}]
routes:
`)
	names := DecoyNames()
	for _, n := range names {
		sb.WriteString("  - {name: d-" + n + ", paths: [/d/" + n + "], honeypot: {decoy: " + n + ", mark: 1m}}\n")
	}
	sb.WriteString("  - {name: app, paths: [/], upstream: app}\n")

	s, base := startServer(t, sb.String())
	before := b.hits.Load()
	for _, n := range names {
		resp, body := get(t, base+"/d/"+n)
		if resp.StatusCode != 200 {
			t.Errorf("%s: status %d", n, resp.StatusCode)
			continue
		}
		if body != decoys[n].body {
			t.Errorf("%s: the served body is not the table's", n)
		}
		if got := resp.Header.Get("Content-Type"); got != decoys[n].contentType {
			t.Errorf("%s: content type %q want %q", n, got, decoys[n].contentType)
		}
	}
	if b.hits.Load() != before {
		t.Errorf("%d requests reached the upstream through a honeypot", b.hits.Load()-before)
	}
	// Every one of them marked the client, and the table holds one
	// address however many decoys it touched.
	marks := s.HoneypotMarks()
	if len(marks) != 1 {
		t.Fatalf("%d marks for one client", len(marks))
	}
	if marks[0].Hits != len(names) {
		t.Errorf("%d hits recorded for %d decoys", marks[0].Hits, len(names))
	}
	// A HEAD asks the same question without the body.
	req, err := http.NewRequest(http.MethodHead, base+"/d/"+names[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || n != 0 {
		t.Errorf("HEAD gave %d with %d bytes", resp.StatusCode, n)
	}
}

// The shipped example is the one an operator copies, so it has to name
// decoys that exist, keep the real application last, and never shadow a
// path a real application would serve.
func TestHoneypotExampleIsSound(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "security", "honeypots.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("the example does not validate: %v", err)
	}

	used := map[string]bool{}
	paths := map[string]string{}
	last := cfg.Routes[len(cfg.Routes)-1]
	for _, r := range cfg.Routes {
		if r.Honeypot == nil {
			if r.Name != last.Name {
				t.Errorf("route %q is not a honeypot and is not last", r.Name)
			}
			continue
		}
		if r.Honeypot.Decoy != "" {
			if !config.HoneypotDecoys[r.Honeypot.Decoy] {
				t.Errorf("route %q names the unknown decoy %q", r.Name, r.Honeypot.Decoy)
			}
			used[r.Honeypot.Decoy] = true
		}
		for _, p := range r.Paths {
			if other, seen := paths[p]; seen {
				t.Errorf("path %q is claimed by both %q and %q", p, other, r.Name)
			}
			paths[p] = r.Name
			if !strings.HasPrefix(p, "/") {
				t.Errorf("route %q: %q is not a path", r.Name, p)
			}
		}
	}
	// The catch-all is last, so every decoy path is more specific.
	if last.Upstream == "" || len(last.Paths) != 1 || last.Paths[0] != "/" {
		t.Errorf("the last route is %+v, want the application on /", last)
	}
	// Every decoy the proxy carries is demonstrated, or the table has an
	// entry nobody knows how to use.
	for _, n := range DecoyNames() {
		if !used[n] {
			t.Errorf("the example never uses the decoy %q", n)
		}
	}
}
