package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
)

// httptestRequest is a request as the handler sees one, for the table
// tests below.
func httptestRequest(method, target string) *http.Request {
	return httptest.NewRequest(method, "http://app.test"+target, nil)
}

// A honeytoken is the hook on the bait. These tests are about the two
// ways it can fail: not firing when the planted value comes back, and
// firing on traffic that never saw the plant.

func compileTokens(t *testing.T, tokens ...config.Honeytoken) *honeytokens {
	t.Helper()
	cfg := &config.Config{Honeytokens: tokens}
	applyTestDefaults(t, cfg)
	ht, err := newHoneytokens(cfg.Honeytokens, &honeytokenCounters{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if ht == nil {
		t.Fatal("no table for a configured token")
	}
	return ht
}

// applyTestDefaults runs the configuration through the parser so the
// tokens carry the same defaults the daemon gives them.
func applyTestDefaults(t *testing.T, cfg *config.Config) {
	t.Helper()
	var b strings.Builder
	b.WriteString(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams: [{name: u, endpoints: [{address: "127.0.0.1:1"}]}]
routes: [{name: r, upstream: u}]
honeytokens:
`)
	for _, h := range cfg.Honeytokens {
		fmt.Fprintf(&b, "  - name: %s\n", h.Name)
		if len(h.Values) > 0 {
			fmt.Fprintf(&b, "    values: [%q]\n", h.Values[0])
			for _, v := range h.Values[1:] {
				fmt.Fprintf(&b, "    # extra\n    values: [%q]\n", v)
			}
		}
		if h.ValuesFile != "" {
			fmt.Fprintf(&b, "    values_file: %s\n", h.ValuesFile)
		}
		if len(h.In) > 0 {
			fmt.Fprintf(&b, "    in: [%s]\n", strings.Join(h.In, ", "))
		}
		if len(h.Headers) > 0 {
			fmt.Fprintf(&b, "    headers: [%s]\n", strings.Join(h.Headers, ", "))
		}
		if h.Match != "" {
			fmt.Fprintf(&b, "    match: %s\n", h.Match)
		}
		if h.Action != "" {
			fmt.Fprintf(&b, "    action: %s\n", h.Action)
		}
	}
	parsed, err := config.ParseWith([]byte(b.String()), false)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Honeytokens = parsed.Honeytokens
}

const plantedKey = "AKIADECOY000000EXAMPLE"

func TestHoneytokenFindsThePlantWhereverItComesBack(t *testing.T) {
	ht := compileTokens(t, config.Honeytoken{Name: "env-key", Values: []string{plantedKey}})
	for _, tc := range []struct {
		name  string
		build func() *http.Request
		field string
	}{
		{"bare header", func() *http.Request {
			r := httptestRequest("GET", "/x")
			r.Header.Set("X-Api-Key", plantedKey)
			return r
		}, "headers"},
		{"bearer token", func() *http.Request {
			r := httptestRequest("GET", "/x")
			r.Header.Set("Authorization", "Bearer "+plantedKey)
			return r
		}, "headers"},
		{"lower case scheme", func() *http.Request {
			r := httptestRequest("GET", "/x")
			r.Header.Set("Authorization", "token "+plantedKey)
			return r
		}, "headers"},
		{"basic auth password", func() *http.Request {
			r := httptestRequest("GET", "/x")
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:"+plantedKey)))
			return r
		}, "headers"},
		{"basic auth user", func() *http.Request {
			r := httptestRequest("GET", "/x")
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(plantedKey+":x")))
			return r
		}, "headers"},
		{"cookie", func() *http.Request {
			r := httptestRequest("GET", "/x")
			r.Header.Set("Cookie", "session="+plantedKey)
			return r
		}, "cookies"},
		{"query parameter", func() *http.Request {
			return httptestRequest("GET", "/x?key="+plantedKey)
		}, "query"},
		{"encoded query parameter", func() *http.Request {
			return httptestRequest("GET", "/x?key=AKIADECOY000000EXAMPLE&other=1")
		}, "query"},
		{"path", func() *http.Request {
			return httptestRequest("GET", "/backup/"+plantedKey)
		}, "path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.build()
			path := r.URL.Path
			h, where := ht.check(r, path)
			if h == nil {
				t.Fatalf("the planted value came back in the %s and nothing fired", tc.field)
			}
			if where != tc.field {
				t.Errorf("found in %q, want %q", where, tc.field)
			}
		})
	}
}

// The other half: a token that fires on ordinary traffic is worse than
// no token, because it is believed.
func TestHoneytokenIgnoresOrdinaryTraffic(t *testing.T) {
	ht := compileTokens(t, config.Honeytoken{Name: "env-key", Values: []string{plantedKey}})
	for _, tc := range []struct{ name, method, target, header, value string }{
		{"a real looking key", "GET", "/x", "X-Api-Key", "AKIAREALKEY00000000000"},
		{"a prefix of the token", "GET", "/x", "X-Api-Key", plantedKey[:len(plantedKey)-1]},
		{"the token with a suffix", "GET", "/x", "X-Api-Key", plantedKey + "0"},
		{"the token inside a longer value", "GET", "/x", "X-Api-Key", "prefix-" + plantedKey + "-suffix"},
		{"an ordinary page", "GET", "/products?page=2", "", ""},
		{"a session cookie", "GET", "/x", "Cookie", "session=abcdefghijklmnop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptestRequest(tc.method, tc.target)
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			if h, where := ht.check(r, r.URL.Path); h != nil {
				t.Errorf("fired on ordinary traffic (%s in %s)", tc.value, where)
			}
		})
	}
}

// "contains" is for a token planted inside something a client echoes
// back whole; exact is for a credential presented as itself.
func TestHoneytokenContainsMatch(t *testing.T) {
	const long = "decoy-tracking-id-0123456789abcdef"
	ht := compileTokens(t, config.Honeytoken{Name: "doc-id", Values: []string{long}, Match: "contains"})
	r := httptestRequest("POST", "/report")
	r.Header.Set("X-Note", "copied from "+long+" as requested")
	if h, _ := ht.check(r, r.URL.Path); h == nil {
		t.Error("a contains token did not fire on a value holding it")
	}
	// And an exact token in the same position does not.
	exact := compileTokens(t, config.Honeytoken{Name: "doc-id", Values: []string{long}})
	if h, _ := exact.check(r, r.URL.Path); h != nil {
		t.Error("an exact token fired on a value that merely contains it")
	}
}

func TestHoneytokenFieldNarrowing(t *testing.T) {
	// Only the header, and only that one header.
	ht := compileTokens(t, config.Honeytoken{Name: "hdr", Values: []string{plantedKey},
		In: []string{"headers"}, Headers: []string{"X-Api-Key"}})
	r := httptestRequest("GET", "/x?key="+plantedKey)
	if h, where := ht.check(r, r.URL.Path); h != nil {
		t.Errorf("a headers-only token fired on the %s", where)
	}
	r = httptestRequest("GET", "/x")
	r.Header.Set("X-Other", plantedKey)
	if h, _ := ht.check(r, r.URL.Path); h != nil {
		t.Error("a token narrowed to X-Api-Key fired on another header")
	}
	r = httptestRequest("GET", "/x")
	r.Header.Set("X-Api-Key", plantedKey)
	if h, _ := ht.check(r, r.URL.Path); h == nil {
		t.Error("the narrowed header did not fire")
	}
}

// A client chooses how many headers it sends, so the work per request
// has to be bounded whatever it sends.
func TestHoneytokenWorkIsBounded(t *testing.T) {
	ht := compileTokens(t, config.Honeytoken{Name: "env-key", Values: []string{plantedKey}})
	r := httptestRequest("GET", "/x")
	for i := range maxCandidates * 2 {
		r.Header.Set(fmt.Sprintf("X-Pad-%d", i), "padding")
	}
	// The bound is a bound, not a filter: what matters is that the walk
	// ends. A token hidden past it is the cost of not doing unbounded
	// work on a client's say-so, and the header count limit is the
	// control that keeps the two close.
	if h, _ := ht.check(r, r.URL.Path); h != nil {
		t.Error("the padding matched a token")
	}
	long := strings.Repeat("A", maxContainsBytes+1)
	ct := compileTokens(t, config.Honeytoken{Name: "doc", Values: []string{"decoy-0123456789abcdef"}, Match: "contains"})
	r2 := httptestRequest("GET", "/x")
	r2.Header.Set("X-Long", long+"decoy-0123456789abcdef")
	if h, _ := ct.check(r2, r2.URL.Path); h != nil {
		t.Error("a value past the scan bound was scanned")
	}
}

func TestHoneytokenValuesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens")
	body := "# planted in the paste\n\nfirst-planted-value-01\nsecond-planted-value-02\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ht := compileTokens(t, config.Honeytoken{Name: "pasted", ValuesFile: path})
	for _, v := range []string{"first-planted-value-01", "second-planted-value-02"} {
		r := httptestRequest("GET", "/x")
		r.Header.Set("X-Api-Key", v)
		if h, _ := ht.check(r, r.URL.Path); h == nil {
			t.Errorf("value %q from the file did not fire", v)
		}
	}
	// A file with a value too short to be a token fails the build
	// rather than installing a plant that matches everything.
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newHoneytokens([]config.Honeytoken{{Name: "s", ValuesFile: short, Match: "exact", In: []string{"headers"}}}, &honeytokenCounters{}); err == nil {
		t.Error("a two-character planted value was accepted")
	}
}

func TestHoneytokenCountersSurviveAReload(t *testing.T) {
	counters := &honeytokenCounters{}
	cfg := []config.Honeytoken{{Name: "env-key", Values: []string{plantedKey}, Match: "exact", Action: "block", In: []string{"headers"}}}
	first, err := newHoneytokens(cfg, counters)
	if err != nil {
		t.Fatal(err)
	}
	r := httptestRequest("GET", "/x")
	r.Header.Set("X-Api-Key", plantedKey)
	h, _ := first.check(r, r.URL.Path)
	if h == nil {
		t.Fatal("no hit")
	}
	h.hits.Add(1)
	second, err := newHoneytokens(cfg, counters)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.status(); len(got) != 1 || got[0].Hits != 1 {
		t.Errorf("after the reload: %+v, want the hit kept", got)
	}
}

// Through a live proxy: the plant trips before routing, bans through
// the ordinary trigger, and marks the client the way a decoy does.
func TestHoneytokenEndToEnd(t *testing.T) {
	a := newBackend(t, "a")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
trusted_proxies: [127.0.0.0/8]
bans:
  action: reject
  triggers:
    - {name: token-use, reasons: [honeytoken], threshold: 1, window: 1m, duration: 1h}
honeytokens:
  - name: env-aws-key
    description: planted in the env decoy
    values: ["%s"]
    status: 404
  - name: quiet
    values: ["logged-only-token-000"]
    action: log
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: app, paths: [/], upstream: app}
`, plantedKey, a.addr())
	s, url := startServer(t, yaml)

	// Ordinary traffic is untouched.
	before := a.hits.Load()
	if resp, _ := get(t, url+"/", "X-Forwarded-For", "198.51.100.10"); resp.StatusCode != 200 {
		t.Fatalf("ordinary request: %d", resp.StatusCode)
	}
	if a.hits.Load() != before+1 {
		t.Fatal("the ordinary request did not reach the origin")
	}

	// The plant comes back: refused with the configured status, before
	// the origin, and never proxied.
	before = a.hits.Load()
	resp, _ := get(t, url+"/anything", "X-Forwarded-For", "198.51.100.11", "X-Api-Key", plantedKey)
	if resp.StatusCode != 404 {
		t.Errorf("status %d, want the configured 404", resp.StatusCode)
	}
	if a.hits.Load() != before {
		t.Error("a request presenting a planted credential reached the origin")
	}
	if n := s.Stats().HoneytokenHits; n != 1 {
		t.Errorf("honeytoken_hits = %d, want 1", n)
	}
	st := s.Honeytokens()
	if len(st) != 2 || st[0].Name != "env-aws-key" || st[0].Hits != 1 {
		t.Errorf("status %+v, want one hit on env-aws-key", st)
	}
	if st[0].LastHit.IsZero() {
		t.Error("the hit has no time")
	}
	// The client is marked, as a decoy hit marks it, and banned by the
	// trigger the reason feeds.
	marked := false
	for _, m := range s.HoneypotMarks() {
		if m.Address == "198.51.100.11" && strings.Contains(m.Route, "env-aws-key") {
			marked = true
		}
	}
	if !marked {
		t.Errorf("the client was not marked: %+v", s.HoneypotMarks())
	}
	if resp, _ := get(t, url+"/", "X-Forwarded-For", "198.51.100.11"); resp.StatusCode != 403 {
		t.Errorf("after the token use: %d, want a ban", resp.StatusCode)
	}

	// A token in log mode records the hit and serves the request.
	before = a.hits.Load()
	if resp, _ := get(t, url+"/", "X-Forwarded-For", "198.51.100.12", "X-Api-Key", "logged-only-token-000"); resp.StatusCode != 200 {
		t.Errorf("log mode: status %d, want the request served", resp.StatusCode)
	}
	if a.hits.Load() != before+1 {
		t.Error("log mode did not reach the origin")
	}
	if st := s.Honeytokens(); st[1].Hits != 1 {
		t.Errorf("the logged token has %d hits, want 1", st[1].Hits)
	}
}

// The values must never reach a log line: the whole point of naming the
// token is that the credential is not repeated somewhere new.
func TestHoneytokenValueIsNotLogged(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
logging:
  directory: %s
honeytokens:
  - {name: env-aws-key, description: planted in the env decoy, values: ["%s"]}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: app, paths: [/], upstream: app}
`, dir, plantedKey, a.addr())
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	url := "http://" + s.Addrs()["main"]
	if resp, _ := get(t, url+"/x?key="+plantedKey, "X-Forwarded-For", "198.51.100.20", "X-Api-Key", plantedKey); resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_ = s.Shutdown(t.Context())
	logs.Close()

	var all strings.Builder
	for _, name := range []string{"access.log", "security.log", "error.log"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		all.Write(b)
	}
	out := all.String()
	if !strings.Contains(out, "env-aws-key") {
		t.Errorf("the logs do not name the token:\n%s", out)
	}
	// The query carried the value too, which is the one place a log
	// legitimately records what the client sent — so the access log
	// keeps the path without it, and no line repeats the credential.
	if strings.Contains(out, plantedKey) {
		t.Errorf("the planted value was written to a log:\n%s", out)
	}
}
