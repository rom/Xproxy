package intel

import (
	"strings"
	"testing"
)

// keys is the parsed keys of a kind, for comparing against what a document
// should have yielded.
func keys(t *testing.T, p *parsed, kind string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, k := range p.byKind[kind] {
		out[k] = true
	}
	return out
}

// A STIX bundle, read for the four things a proxy can compare against traffic.
// Everything else in it -- the campaign, the relationship, the marking -- is
// intelligence for a human, and skipping it is not an error.
func TestASTIXBundleYieldsWhatAProxyCanMatch(t *testing.T) {
	bundle := `{
  "type": "bundle",
  "id": "bundle--1",
  "objects": [
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--1",
     "pattern_type": "stix",
     "pattern": "[domain-name:value = 'evil.example']"},
    {"type": "indicator", "id": "indicator--2",
     "pattern": "[url:value = 'http://evil.example/dl/payload.bin']"},
    {"type": "indicator", "id": "indicator--3",
     "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"},
    {"type": "indicator", "id": "indicator--4",
     "pattern": "[ipv4-addr:value = '198.51.100.0/24']"},
    {"type": "indicator", "id": "indicator--5",
     "pattern": "[domain-name:value = 'a.example' OR domain-name:value = 'b.example']"},
    {"type": "campaign", "id": "campaign--1", "name": "a campaign"},
    {"type": "relationship", "id": "relationship--1", "relationship_type": "indicates"},
    {"type": "marking-definition", "id": "marking-definition--1"},
    {"type": "domain-name", "id": "domain-name--1", "value": "bare-observable.example"},
    {"type": "file", "id": "file--1",
     "hashes": {"MD5": "d41d8cd98f00b204e9800998ecf8427e", "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}}
  ]
}`
	p, err := parseSTIX([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	gotDomains := keys(t, p, KindDomain)
	for _, want := range []string{"evil.example", "a.example", "b.example", "bare-observable.example"} {
		if !gotDomains[want] {
			t.Errorf("domains lack %q: %v", want, gotDomains)
		}
	}
	if got := keys(t, p, KindURL); !got["evil.example/dl/payload.bin"] {
		t.Errorf("urls %v", got)
	}
	gotHashes := keys(t, p, KindHash)
	for _, want := range []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"d41d8cd98f00b204e9800998ecf8427e",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
	} {
		if !gotHashes[want] {
			t.Errorf("hashes lack %q: %v", want, gotHashes)
		}
	}
	if got := keys(t, p, KindCIDR); !got["198.51.100.0/24"] {
		t.Errorf("cidrs %v", got)
	}
	// The three objects a proxy cannot act on are counted, so a bundle of ten
	// thousand objects that yields four entries says so rather than looking
	// like a working list.
	if p.skipped != 3 {
		t.Errorf("skipped %d, want the campaign, the relationship and the marking", p.skipped)
	}
}

// A pattern this cannot read exactly is skipped rather than approximated. The
// second case is the one that matters: taking the readable half of a pattern
// would turn "this domain serving a small file" into "this domain", which is a
// broader rule than the publisher wrote -- and a broader rule is somebody
// else's outage.
func TestAPatternThatCannotBeReadExactlyIsSkipped(t *testing.T) {
	for _, pattern := range []string{
		// The case that matters most, and the one with no keyword to trip
		// over: a readable term joined to an unreadable one. Taking the
		// readable half turns "this domain serving a file of this size" into
		// "this domain", which is a broader rule than the publisher wrote --
		// and a broader rule is somebody else's outage.
		"[domain-name:value = 'a.example' AND file:size = '1024']",
		"[file:size = '1024' AND domain-name:value = 'a.example']",
		"[domain-name:value = 'a.example' AND network-traffic:dst_port = '8443']",
		"[url:value = 'http://a.example/p' AND file:name = 'x.exe']",
		"[domain-name:value = 'a.example' OR process:name = 'evil.exe']",
		// Negation, in either position.
		"[domain-name:value = 'a.example' AND NOT file:size = '1024']",
		"[NOT domain-name:value = 'a.example']",
		// Operators with no exact reading here.
		"[domain-name:value LIKE 'a%.example']",
		"[domain-name:value MATCHES '^a.*']",
		"[domain-name:value IN ('a.example', 'b.example')]",
		"[network-traffic:dst_ref.value ISSUBSET '198.51.100.0/24']",
		// Qualifiers: a count, a window, a period.
		"[domain-name:value = 'a.example'] REPEATS 5 TIMES",
		"[domain-name:value = 'a.example'] WITHIN 60 SECONDS",
		"[domain-name:value = 'a.example'] START '2026-01-01T00:00:00Z' STOP '2026-02-01T00:00:00Z'",
		// A sequence of observations, which one request cannot satisfy.
		"[domain-name:value = 'a.example'] FOLLOWEDBY [url:value = 'http://b.example/x']",
		// Inequality is not equality.
		"[file:size != '0']",
		"[domain-name:value != 'a.example']",
		// A path with nothing to compare against.
		"[process:command_line = 'cmd.exe /c whoami']",
		"[windows-registry-key:key = 'HKLM\\\\Software\\\\Evil']",
		// Malformed.
		"", "[]", "[domain-name:value = ]", "[= 'a.example']",
		"domain-name:value = 'a.example'",
	} {
		out := newParsed()
		if n := stixPattern(pattern, out); n != 0 || out.total() != 0 {
			t.Errorf("%q yielded %d indicators: %v", pattern, n, out.byKind)
		}
	}
	// And the readable shapes still read, so the refusals above are not simply
	// a parser that refuses everything.
	for _, tc := range []struct {
		pattern, kind, key string
	}{
		{"[domain-name:value = 'a.example']", KindDomain, "a.example"},
		{"  [ domain-name:value = 'a.example' ]  ", KindDomain, "a.example"},
		{"[url:value = 'https://a.example/p/q']", KindURL, "a.example/p/q"},
		{"[ipv4-addr:value = '198.51.100.7']", KindCIDR, "198.51.100.7"},
		{"[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']", KindHash, "d41d8cd98f00b204e9800998ecf8427e"},
		{"[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']", KindHash, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	} {
		out := newParsed()
		if n := stixPattern(tc.pattern, out); n != 1 {
			t.Errorf("%q yielded %d", tc.pattern, n)
			continue
		}
		if !keys(t, out, tc.kind)[tc.key] {
			t.Errorf("%q yielded %v, want %s %q", tc.pattern, out.byKind, tc.kind, tc.key)
		}
	}
}

// A revoked indicator is one the publisher withdrew. Loading it would be this
// proxy acting on intelligence its author has retracted.
func TestARevokedIndicatorIsNotLoaded(t *testing.T) {
	bundle := `{"objects":[
      {"type":"indicator","pattern":"[domain-name:value = 'live.example']"},
      {"type":"indicator","revoked":true,"pattern":"[domain-name:value = 'withdrawn.example']"}
    ]}`
	p, err := parseSTIX([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	got := keys(t, p, KindDomain)
	if !got["live.example"] {
		t.Error("the live indicator was not loaded")
	}
	if got["withdrawn.example"] {
		t.Error("a revoked indicator was loaded")
	}
}

// A pattern in another language must not be read as a STIX expression.
func TestANonSTIXPatternIsNotReadAsOne(t *testing.T) {
	bundle := `{"objects":[
      {"type":"indicator","pattern_type":"yara","pattern":"rule x { condition: true }"},
      {"type":"indicator","pattern_type":"snort","pattern":"alert tcp any any -> any 80"},
      {"type":"indicator","pattern_type":"stix","pattern":"[domain-name:value = 'a.example']"}
    ]}`
	p, err := parseSTIX([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if p.total() != 1 || !keys(t, p, KindDomain)["a.example"] {
		t.Errorf("yielded %v", p.byKind)
	}
	if p.skipped != 2 {
		t.Errorf("skipped %d, want the yara and the snort rule", p.skipped)
	}
}

// A document that is not the format, and a document of things this cannot act
// on, are both errors -- because a list that silently matches nothing is the
// failure this package exists to refuse.
func TestABundleThatYieldsNothingIsAnError(t *testing.T) {
	for _, body := range []string{
		`not json at all`,
		`{"type":"bundle"}`,
		`{"objects":[]}`,
		`{"objects":[{"type":"campaign"},{"type":"relationship"}]}`,
	} {
		if _, err := parseSTIX([]byte(body)); err == nil {
			t.Errorf("%q was accepted", body)
		}
	}
}

// MISP in each of the three shapes a deployment publishes.
func TestMISPIsReadInEveryShapeItIsPublished(t *testing.T) {
	const attrs = `[
      {"type":"domain","value":"evil.example","to_ids":true},
      {"type":"url","value":"http://evil.example/dl","to_ids":true},
      {"type":"sha256","value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"type":"ip-dst","value":"198.51.100.7"}
    ]`
	for _, tc := range []struct{ name, body string }{
		{"a bare attribute array", attrs},
		{"an attribute list", `{"Attribute":` + attrs + `}`},
		{"an event", `{"Event":{"info":"a report","Attribute":` + attrs + `}}`},
		{"a restSearch response", `{"response":{"Attribute":` + attrs + `}}`},
		{"an event with the attributes on an object", `{"Event":{"Object":[{"name":"file","Attribute":` + attrs + `}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseMISP([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if !keys(t, p, KindDomain)["evil.example"] {
				t.Errorf("domains %v", p.byKind[KindDomain])
			}
			if !keys(t, p, KindURL)["evil.example/dl"] {
				t.Errorf("urls %v", p.byKind[KindURL])
			}
			if len(p.byKind[KindHash]) != 1 {
				t.Errorf("hashes %v", p.byKind[KindHash])
			}
			if !keys(t, p, KindCIDR)["198.51.100.7"] {
				t.Errorf("cidrs %v", p.byKind[KindCIDR])
			}
		})
	}
}

// to_ids: false is MISP's way of saying "this is context, do not detect on it"
// -- the sandbox that ran the sample, the legitimate service the malware abused.
// Loading those is how a feed takes out a CDN.
func TestMISPContextAttributesAreNotLoaded(t *testing.T) {
	body := `{"Event":{"Attribute":[
      {"type":"domain","value":"evil.example","to_ids":true},
      {"type":"domain","value":"cdn.cloudflare.example","to_ids":false},
      {"type":"url","value":"http://sandbox.example/report","to_ids":false},
      {"type":"domain","value":"deleted.example","to_ids":true,"deleted":true},
      {"type":"domain","value":"default.example"}
    ]}}`
	p, err := parseMISP([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	got := keys(t, p, KindDomain)
	if !got["evil.example"] {
		t.Error("a detection attribute was not loaded")
	}
	// Absent to_ids is MISP's own default for a detection type, so it loads.
	if !got["default.example"] {
		t.Error("an attribute with no to_ids was not loaded")
	}
	for _, name := range []string{"cdn.cloudflare.example", "deleted.example"} {
		if got[name] {
			t.Errorf("%q was loaded", name)
		}
	}
	if keys(t, p, KindURL)["sandbox.example/report"] {
		t.Error("a context url was loaded")
	}
	if p.skipped != 2 {
		t.Errorf("skipped %d, want the two context attributes", p.skipped)
	}
}

// A composite attribute is halves of different kinds joined by a bar. Taking the
// whole string would store an entry that can never match.
func TestAMISPCompositeAttributeIsSplit(t *testing.T) {
	body := `{"Attribute":[
      {"type":"domain|ip","value":"evil.example|198.51.100.7"},
      {"type":"filename|sha256","value":"invoice.pdf.exe|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"type":"ip-dst|port","value":"203.0.113.9|8443"}
    ]}`
	p, err := parseMISP([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !keys(t, p, KindDomain)["evil.example"] {
		t.Errorf("the domain half was not taken: %v", p.byKind)
	}
	if !keys(t, p, KindCIDR)["198.51.100.7"] || !keys(t, p, KindCIDR)["203.0.113.9"] {
		t.Errorf("the address halves were not taken: %v", p.byKind[KindCIDR])
	}
	if !keys(t, p, KindHash)["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] {
		t.Errorf("the digest half was not taken: %v", p.byKind[KindHash])
	}
	// The file name half is not an indicator a proxy can match: it sees a
	// Content-Disposition it does not trust and a digest it computed.
	for kind, v := range p.byKind {
		for _, k := range v {
			if strings.Contains(k, "invoice") {
				t.Errorf("a file name was stored as a %s indicator: %q", kind, k)
			}
		}
	}
	// And the whole composite string is never an entry.
	for _, v := range p.byKind {
		for _, k := range v {
			if strings.Contains(k, "|") {
				t.Errorf("a composite value was stored whole: %q", k)
			}
		}
	}
}

// A MISP document of only the types this cannot match is an error, not an empty
// list. The types are real and interesting; a proxy has nothing to compare them
// against.
func TestAMISPDocumentOfUnmatchableTypesIsAnError(t *testing.T) {
	body := `{"Attribute":[
      {"type":"btc","value":"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},
      {"type":"mutex","value":"Global\\evil"},
      {"type":"email-src","value":"a@b.example"},
      {"type":"filename","value":"invoice.pdf.exe"}
    ]}`
	_, err := parseMISP([]byte(body))
	if err == nil {
		t.Fatal("a document with nothing to match on was accepted")
	}
	if !strings.Contains(err.Error(), "4 attributes") {
		t.Errorf("error %q does not say how many were looked at", err)
	}
}

// The format is decided from the bytes only when the configuration did not say.
// A MISP event and a STIX bundle are both JSON objects with a type field, so the
// decision is made on what is actually in them.
func TestTheFormatIsDetectedFromTheBytes(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"10.0.0.0/8\nevil.example\n", FormatLines},
		{"# a comment\n10.0.0.0/8\n", FormatLines},
		{`{"type":"bundle","objects":[]}`, FormatSTIX},
		{`  [{"type":"indicator"}]`, FormatSTIX},
		{`{"Event":{"Attribute":[]}}`, FormatMISP},
		{`{"response":{"Attribute":[]}}`, FormatMISP},
		{`{"Attribute":[]}`, FormatMISP},
		{"", FormatLines},
	} {
		if got := detectFormat([]byte(tc.body)); got != tc.want {
			t.Errorf("%q detected as %s, want %s", tc.body, got, tc.want)
		}
	}
}

// A list reads a structured document and keeps the indicators of its own kind,
// counting the rest as skipped -- so an estate that wants to block the domains
// and only log the digests configures two lists over one file, which says the
// two policies out loud.
func TestOneDocumentServesSeveralListsByKind(t *testing.T) {
	bundle := `{"objects":[
      {"type":"indicator","pattern":"[domain-name:value = 'evil.example']"},
      {"type":"indicator","pattern":"[url:value = 'http://evil.example/dl']"},
      {"type":"indicator","pattern":"[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"},
      {"type":"campaign","name":"c"}
    ]}`
	dir := t.TempDir()
	path := write(t, dir, "bundle.json", bundle)
	s, err := New([]Spec{
		{Name: "names", Kind: KindDomain, Action: ActionBlock, File: path},
		{Name: "digests", Kind: KindHash, Action: ActionLog, File: path},
	})
	if err != nil {
		t.Fatal(err)
	}
	hit, ok := s.Match(Subject{Domain: "cdn.evil.example"})
	if !ok || hit.List != "names" || hit.Action != ActionBlock {
		t.Errorf("the domain matched %+v", hit)
	}
	hit, ok = s.Match(Subject{Hashes: []string{"d41d8cd98f00b204e9800998ecf8427e"}})
	if !ok || hit.List != "digests" || hit.Action != ActionLog {
		t.Errorf("the digest matched %+v", hit)
	}
	// The status says what each list took and what it did not, because a
	// bundle of ten thousand objects behind four entries is either the wrong
	// feed or the wrong kind and the pair of numbers says which.
	for _, st := range s.Status() {
		if st.Entries != 1 {
			t.Errorf("%s took %d entries", st.Name, st.Entries)
		}
		if st.Skipped != 3 {
			t.Errorf("%s skipped %d, want the other two indicators and the campaign", st.Name, st.Skipped)
		}
	}
}

// A list whose kind is not in the document is an error, not an empty list. This
// is the whole reason the package refuses a list that matches nothing: the
// operator believes the kind they configured is being checked.
func TestAKindMissingFromTheDocumentIsAnError(t *testing.T) {
	bundle := `{"objects":[{"type":"indicator","pattern":"[domain-name:value = 'evil.example']"}]}`
	path := write(t, t.TempDir(), "bundle.json", bundle)
	_, err := New([]Spec{{Name: "digests", Kind: KindHash, File: path}})
	if err == nil {
		t.Fatal("a hash list over a document with no digests was accepted")
	}
	if !strings.Contains(err.Error(), "no hash indicators") {
		t.Errorf("error %q does not say which kind was missing", err)
	}
}

// A file's format may be named rather than sniffed, and naming it wrong is an
// error rather than a list that quietly reads nothing.
func TestANamedFormatIsHeldTo(t *testing.T) {
	dir := t.TempDir()
	lines := write(t, dir, "lines.txt", "evil.example\n")
	bundle := write(t, dir, "b.json", `{"objects":[{"type":"indicator","pattern":"[domain-name:value = 'a.example']"}]}`)

	// Named correctly, both load.
	if _, err := New([]Spec{{Name: "l", Kind: KindDomain, File: lines, Format: FormatLines}}); err != nil {
		t.Errorf("a lines file named as lines: %v", err)
	}
	if _, err := New([]Spec{{Name: "b", Kind: KindDomain, File: bundle, Format: FormatSTIX}}); err != nil {
		t.Errorf("a bundle named as stix: %v", err)
	}
	// Named wrongly, the load fails and says so -- rather than a list that
	// reads the bundle's braces as host names, or a plain feed as JSON.
	if _, err := New([]Spec{{Name: "l", Kind: KindDomain, File: lines, Format: FormatSTIX}}); err == nil {
		t.Error("a plain feed read as stix was accepted")
	}
	if _, err := New([]Spec{{Name: "b", Kind: KindDomain, File: bundle, Format: FormatLines}}); err == nil {
		t.Error("a bundle read as lines was accepted")
	}
	// And a format nobody has heard of is an error at load.
	if _, err := New([]Spec{{Name: "x", Kind: KindDomain, File: lines, Format: "csv"}}); err == nil {
		t.Error("an unknown format was accepted")
	}
}
