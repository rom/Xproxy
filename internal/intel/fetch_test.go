package intel

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A plain feed URL, fetched and then re-fetched conditionally: an unchanged feed
// must cost a 304 rather than a download, because a feed polled every ten
// minutes by a fleet of proxies is a feed somebody pays for.
func TestAURLFeedIsFetchedThenValidated(t *testing.T) {
	var requests atomic.Int64
	const body = "evil.example\nalso-evil.example\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	s, err := New([]Spec{{Name: "feed", Kind: KindDomain, Action: ActionBlock, URL: srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Match(Subject{Domain: "cdn.evil.example"}); !ok {
		t.Error("the fetched feed did not match")
	}
	st := s.Status()[0]
	if st.Entries != 2 || st.Fetches != 1 {
		t.Errorf("status %+v", st)
	}
	if st.Source != srv.URL {
		t.Errorf("source %q", st.Source)
	}

	// The second poll sends the validator and gets a 304, which is not a
	// change and not a failure.
	changed, err := s.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Errorf("an unchanged feed reported %d changed", changed)
	}
	st = s.Status()[0]
	if st.NotModified != 1 {
		t.Errorf("not_modified %d, want the 304", st.NotModified)
	}
	if st.Failures != 0 {
		t.Errorf("a 304 was counted as a failure")
	}
	// And the entries are still there, because a 304 means they are current.
	if _, ok := s.Match(Subject{Domain: "evil.example"}); !ok {
		t.Error("a 304 emptied the list")
	}
	if n := requests.Load(); n != 2 {
		t.Errorf("%d requests, want one fetch and one validation", n)
	}
}

// A fetch that fails keeps the entries already loaded. A TAXII server having an
// afternoon must not empty the policy -- and the failure is counted, because a
// list that has quietly stopped updating looks exactly like one that is working.
func TestAFailedFetchKeepsTheEntries(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "evil.example\n")
	}))
	defer srv.Close()

	s, err := New([]Spec{{Name: "feed", Kind: KindDomain, URL: srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	changed, err := s.Reload()
	if err == nil {
		t.Fatal("a failing fetch was not reported")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not say what the server said", err)
	}
	if changed != 0 {
		t.Errorf("a failed fetch reported %d changed", changed)
	}
	if _, ok := s.Match(Subject{Domain: "evil.example"}); !ok {
		t.Error("a failed fetch emptied the list")
	}
	if st := s.Status()[0]; st.Failures != 1 {
		t.Errorf("failures %d", st.Failures)
	}
}

// The first fetch is different: at start there is nothing to keep, so a source
// that cannot be reached fails the load. A proxy that came up with an empty list
// it believes is populated is what this package exists to prevent.
func TestAFirstFetchThatFailsFailsTheLoad(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := New([]Spec{{Name: "feed", Kind: KindDomain, URL: srv.URL}}); err == nil {
		t.Fatal("a list whose first fetch failed was accepted")
	}
}

// A TAXII collection is paginated, and every page is followed -- because a
// collection is larger than a response and a half-read collection is a policy
// nobody wrote.
func TestATAXIICollectionIsReadToTheEnd(t *testing.T) {
	page := func(names []string, more bool, next string) string {
		objs := make([]map[string]any, 0, len(names))
		for _, n := range names {
			objs = append(objs, map[string]any{
				"type": "indicator", "id": "indicator--" + n,
				"pattern": "[domain-name:value = '" + n + "']",
			})
		}
		b, _ := json.Marshal(map[string]any{"objects": objs, "more": more, "next": next})
		return string(b)
	}
	var got struct {
		accept   atomic.Value
		auth     atomic.Value
		requests atomic.Int64
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.requests.Add(1)
		got.accept.Store(r.Header.Get("Accept"))
		got.auth.Store(r.Header.Get("Authorization"))
		if !strings.HasSuffix(r.URL.Path, "/collections/c1/objects/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		switch r.URL.Query().Get("next") {
		case "":
			_, _ = io.WriteString(w, page([]string{"one.example", "two.example"}, true, "cursor2"))
		case "cursor2":
			_, _ = io.WriteString(w, page([]string{"three.example"}, false, ""))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	s, err := New([]Spec{{
		Name: "taxii", Kind: KindDomain, Action: ActionBlock,
		TAXII: &TAXIISpec{APIRoot: srv.URL + "/api1/", Collection: "c1"},
		HTTP:  &HTTPSpec{Token: "s3cret"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one.example", "two.example", "three.example"} {
		if _, ok := s.Match(Subject{Domain: name}); !ok {
			t.Errorf("%q from page %d did not match", name, 1)
		}
	}
	if n := got.requests.Load(); n != 2 {
		t.Errorf("%d requests, want both pages", n)
	}
	// The media type is what makes this TAXII rather than a JSON file, and the
	// credential has to reach the server or the collection is empty.
	if a, _ := got.accept.Load().(string); !strings.Contains(a, "taxii") || !strings.Contains(a, "2.1") {
		t.Errorf("Accept %q", a)
	}
	if a, _ := got.auth.Load().(string); a != "Bearer s3cret" {
		t.Errorf("Authorization %q, want a bearer token", a)
	}
	if st := s.Status()[0]; !strings.Contains(st.Source, "collection c1") {
		t.Errorf("source %q does not name the collection", st.Source)
	}
}

// A server that keeps saying "more" is one this proxy would follow for ever, so
// the fetch fails with the page count. An operator can see a bound they have
// hit; they cannot see a loop.
//
// Removing the bound does not make this test fail cleanly -- it makes it hang,
// and the suite goes red on the package timeout rather than on an assertion.
// That is the honest description of the mutation: there is no assertion that
// catches an infinite loop, only a clock.
func TestATAXIIServerThatNeverEndsIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := r.URL.Query().Get("next")
		_, _ = io.WriteString(w, `{"objects":[{"type":"indicator","pattern":"[domain-name:value = 'a.example']"}],`+
			`"more":true,"next":"`+n+"x"+`"}`)
	}))
	defer srv.Close()
	_, err := New([]Spec{{
		Name: "taxii", Kind: KindDomain,
		TAXII: &TAXIISpec{APIRoot: srv.URL, Collection: "c1"},
	}})
	if err == nil {
		t.Fatal("an endless collection was accepted")
	}
	if !strings.Contains(err.Error(), "still paginating") {
		t.Errorf("error %q", err)
	}
}

// A MISP instance is searched with the attribute types this proxy can match on,
// because asking for all two hundred and discarding most of them makes the
// instance do work for nothing.
func TestAMISPSearchAsksForWhatCanBeMatched(t *testing.T) {
	var body atomic.Value
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/attributes/restSearch") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		body.Store(string(raw))
		auth.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"response":{"Attribute":[
		  {"type":"domain","value":"evil.example","to_ids":true},
		  {"type":"sha256","value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","to_ids":true}
		]}}`)
	}))
	defer srv.Close()

	s, err := New([]Spec{{
		Name: "misp", Kind: KindDomain, Action: ActionChallenge,
		MISP: &MISPSpec{BaseURL: srv.URL, Published: true, Tags: []string{"tlp:amber"}, Limit: 5000},
		HTTP: &HTTPSpec{Token: "apikey"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Match(Subject{Domain: "evil.example"}); !ok {
		t.Error("the searched attribute did not match")
	}
	sent, _ := body.Load().(string)
	for _, want := range []string{`"to_ids":true`, `"published":true`, `"tlp:amber"`, `"limit":5000`, `"domain"`, `"sha256"`} {
		if !strings.Contains(sent, want) {
			t.Errorf("the search body lacks %s: %s", want, sent)
		}
	}
	// MISP sends the API key bare rather than as a bearer token.
	if a, _ := auth.Load().(string); a != "apikey" {
		t.Errorf("Authorization %q, want the bare API key", a)
	}
}

// A feed that redirects off its host has changed owner, and following it would
// mean this proxy's block list comes from wherever the last hop said.
func TestAFeedThatRedirectsOffItsHostIsRefused(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "attacker-chosen.example\n")
	}))
	defer elsewhere.Close()
	var toElsewhere atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if toElsewhere.Load() {
			http.Redirect(w, r, elsewhere.URL, http.StatusFound)
			return
		}
		// A redirect within the host is followed, which is what a feed behind
		// a rewrite or a trailing slash needs.
		if r.URL.Path == "/feed" {
			http.Redirect(w, r, "/feed/current", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "evil.example\n")
	}))
	defer srv.Close()

	s, err := New([]Spec{{Name: "feed", Kind: KindDomain, URL: srv.URL + "/feed"}})
	if err != nil {
		t.Fatalf("a redirect within the host was refused: %v", err)
	}
	if _, ok := s.Match(Subject{Domain: "evil.example"}); !ok {
		t.Error("the feed behind an in-host redirect did not load")
	}
	toElsewhere.Store(true)
	if _, err := s.Reload(); err == nil {
		t.Fatal("a redirect to another host was followed")
	}
	if _, ok := s.Match(Subject{Domain: "attacker-chosen.example"}); ok {
		t.Error("the other host's entries were loaded")
	}
}

// Skipping verification is refused for anything but a loopback address, because
// a feed nobody authenticated becomes this proxy's block list. Refused rather
// than warned about: there is no estate where that is the intent.
func TestSkippingVerificationIsLoopbackOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		url   string
		spec  HTTPSpec
		wants string
	}{
		{"insecure without the second opt-in", "https://feeds.example/x",
			HTTPSpec{Insecure: true}, "two decisions"},
		{"insecure for a public host", "https://feeds.example/x",
			HTTPSpec{Insecure: true, AllowInsecure: true}, "loopback"},
		{"insecure for a loopback address", "https://127.0.0.1:8443/x",
			HTTPSpec{Insecure: true, AllowInsecure: true}, ""},
		{"insecure for localhost", "https://localhost:8443/x",
			HTTPSpec{Insecure: true, AllowInsecure: true}, ""},
		{"verification on, anywhere", "https://feeds.example/x", HTTPSpec{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkInsecure(tc.url, tc.spec)
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("accepted, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %q, want %q", err, tc.wants)
			}
		})
	}
}

// A feed that answers with more than the bound is refused rather than read into
// memory to find out how big it was.
func TestAFeedLargerThanTheBoundIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// One line, repeated past the document bound. Written rather than
		// declared so the bound is exercised on the reading side.
		line := strings.Repeat("a", 200) + ".example\n"
		for n := 0; n < MaxDocument/len(line)+16; n++ {
			if _, err := io.WriteString(w, line); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	_, err := New([]Spec{{Name: "feed", Kind: KindDomain, URL: srv.URL}})
	if err == nil {
		t.Fatal("a feed past the document bound was accepted")
	}
	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("error %q does not say it was the size", err)
	}
}

// The fetch is bounded in time, so a server that accepts and then says nothing
// cannot hold a refresh open.
func TestAFetchIsBoundedInTime(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	start := time.Now()
	_, err := New([]Spec{{
		Name: "feed", Kind: KindDomain, URL: srv.URL,
		HTTP: &HTTPSpec{Timeout: 200 * time.Millisecond},
	}})
	if err == nil {
		t.Fatal("a server that never answers was accepted")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the fetch took %v; the timeout did nothing", elapsed)
	}
}
