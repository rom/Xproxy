package waf

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

func wafConfig(learning *config.WAFLearning) *config.WAF {
	return &config.WAF{
		Profiles:               []config.WAFProfile{{Name: "default", CRS: &config.CRS{ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}}},
		DefaultMode:            "block",
		DefaultProfile:         "default",
		RequestBodyLimit:       4096,
		RequestBodyLimitAction: "reject",
		ResponseBodyLimit:      4096,
		Learning:               learning,
	}
}

func runInfo(t *testing.T, e *Engine, mode Mode, r *http.Request, in *filter.Info) filter.Verdict {
	t.Helper()
	f, err := e.Filter("default", mode)
	if err != nil {
		t.Fatal(err)
	}
	inst := f.Begin(context.Background(), in)
	v := inst.Request(r)
	inst.End()
	return v
}

func findRule(rep Report, id int) *RuleStat {
	for i := range rep.Rules {
		if rep.Rules[i].ID == id {
			return &rep.Rules[i]
		}
	}
	return nil
}

func TestRuleStatistics(t *testing.T) {
	st := NewStats()
	e, err := New(wafConfig(nil), Need{"default": {ModeBlock: true, ModeDetect: true}}, st, nolog)
	if err != nil {
		t.Fatal(err)
	}
	sqli := httptest.NewRequest("GET", "http://example.com/items?id=1%27%20OR%20%271%27=%271", nil)
	if v := runInfo(t, e, ModeBlock, sqli, info()); !v.Deny {
		t.Fatalf("sqli not blocked: %+v", v)
	}
	xss := httptest.NewRequest("GET", "http://example.com/?q=<script>alert(1)</script>", nil)
	if v := runInfo(t, e, ModeDetect, xss, info()); v.Deny {
		t.Fatal("detect mode denied")
	}
	clean := httptest.NewRequest("GET", "http://example.com/products?page=2", nil)
	runInfo(t, e, ModeBlock, clean, info())

	rep := st.Report(50, nil)
	if rep.Requests != 3 || rep.Blocked != 1 || rep.Detected != 1 {
		t.Fatalf("counters %+v", rep)
	}
	if rep.TotalRules == 0 || len(rep.Rules) != rep.TotalRules {
		t.Fatalf("rules %d/%d", len(rep.Rules), rep.TotalRules)
	}
	xssRule := findRule(rep, 941100)
	if xssRule == nil || xssRule.Matches != 1 || xssRule.Detects != 1 || xssRule.Blocks != 0 {
		t.Fatalf("941100 %+v", xssRule)
	}
	if xssRule.Severity == "" || xssRule.LastSeen.IsZero() || !strings.Contains(xssRule.LastURI, "/?q=") {
		t.Fatalf("941100 metadata %+v", xssRule)
	}
	if !hasTag(xssRule.Tags, "attack-xss") {
		t.Fatalf("tags %v", xssRule.Tags)
	}
	sqliRule := findRule(rep, 942100)
	if sqliRule == nil || sqliRule.Blocks != 1 {
		t.Fatalf("942100 %+v", sqliRule)
	}
	// Sorted by matches, then id; top bounds the list.
	for i := 1; i < len(rep.Rules); i++ {
		a, b := rep.Rules[i-1], rep.Rules[i]
		if a.Matches < b.Matches || (a.Matches == b.Matches && a.ID > b.ID) {
			t.Fatalf("unsorted at %d: %+v %+v", i, a, b)
		}
	}
	if got := st.Report(1, nil); len(got.Rules) != 1 || got.TotalRules != rep.TotalRules {
		t.Fatalf("top 1: %+v", got)
	}
	if rep.Learning == nil || rep.Learning.Enabled || len(rep.Learning.Proposals) != 0 {
		t.Fatalf("learning reported while off: %+v", rep.Learning)
	}
	st.Reset()
	if rep := st.Report(50, nil); rep.Requests != 0 || rep.TotalRules != 0 {
		t.Fatalf("after reset %+v", rep)
	}
}

func TestLearningProposals(t *testing.T) {
	st := NewStats()
	cfg := wafConfig(&config.WAFLearning{Enabled: true, MinHits: 2, MaxEntries: 1000})
	e, err := New(cfg, Need{"default": {ModeBlock: true, ModeDetect: true}}, st, nolog)
	if err != nil {
		t.Fatal(err)
	}
	xss := func() *http.Request {
		return httptest.NewRequest("GET", "http://example.com/app/search?q=<script>alert(1)</script>", nil)
	}
	appInfo := &filter.Info{RequestID: "r1", ClientIP: info().ClientIP, Route: "app", Host: "example.com", Path: "/app/search"}
	runInfo(t, e, ModeBlock, xss(), appInfo)
	paths := map[string]string{"app": "/app"}
	if props := st.Proposals(paths); len(props) != 0 {
		t.Fatalf("proposal below min_hits: %+v", props)
	}
	other := *appInfo
	other.ClientIP = other.ClientIP.Next()
	runInfo(t, e, ModeDetect, xss(), &other)

	rep := st.Report(10, paths)
	if rep.Learning == nil || !rep.Learning.Enabled || rep.Learning.MinHits != 2 || rep.Learning.Entries == 0 {
		t.Fatalf("learning %+v", rep.Learning)
	}
	var found *Proposal
	for i := range rep.Learning.Proposals {
		p := &rep.Learning.Proposals[i]
		if p.Rule == 941100 && p.Target == "ARGS:q" {
			found = p
		}
	}
	if found == nil {
		t.Fatalf("no proposal for 941100 ARGS:q in %+v", rep.Learning.Proposals)
	}
	if found.Hits != 2 || found.Clients != 2 || found.Route != "app" || found.Path != "/app" || found.Sample == "" {
		t.Fatalf("proposal %+v", found)
	}
	want := `SecRule REQUEST_URI "@beginsWith /app" "id:`
	if !strings.HasPrefix(found.Directive, want) || !strings.Contains(found.Directive, "ctl:ruleRemoveTargetById=941100;ARGS:q") {
		t.Fatalf("directive %q", found.Directive)
	}
	// Without a path the exclusion is profile wide, still as a ctl action
	// so that it compiles in a directive file loaded before the rules.
	global := st.Proposals(nil)
	var globalDirs strings.Builder
	for _, p := range global {
		if p.Rule == 941100 && p.Target == "ARGS:q" && !strings.HasPrefix(p.Directive, `SecAction "id:`) {
			t.Fatalf("global directive %q", p.Directive)
		}
		globalDirs.WriteString(p.Directive + "\n")
	}
	globalCfg := wafConfig(nil)
	globalCfg.Profiles[0].Directives = globalDirs.String()
	eg, err := New(globalCfg, Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatalf("global proposals do not compile: %v\n%s", err, globalDirs.String())
	}
	elsewhere := httptest.NewRequest("GET", "http://example.com/other?q=<script>alert(1)</script>", nil)
	if v := runInfo(t, eg, ModeBlock, elsewhere, info()); v.Deny {
		t.Fatalf("profile wide exclusion not applied: %+v", v)
	}
	// Generated ids are unique.
	seen := map[string]bool{}
	for _, p := range rep.Learning.Proposals {
		if i := strings.Index(p.Directive, "id:"); i >= 0 {
			id := p.Directive[i : i+9]
			if seen[id] {
				t.Fatalf("duplicate id %s", id)
			}
			seen[id] = true
		}
	}
	text := st.Exclusions(paths)
	if !strings.Contains(text, found.Directive) || !strings.Contains(text, "# rule 941100") {
		t.Fatalf("exclusions:\n%s", text)
	}

	// The proposed directives, once loaded, stop the same request from
	// being blocked by the excluded rules.
	var dirs strings.Builder
	for _, p := range rep.Learning.Proposals {
		dirs.WriteString(p.Directive)
		dirs.WriteString("\n")
	}
	tuned := wafConfig(nil)
	tuned.Profiles[0].Directives = dirs.String()
	e2, err := New(tuned, Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatalf("proposed directives do not compile: %v\n%s", err, dirs.String())
	}
	if v := runInfo(t, e2, ModeBlock, xss(), appInfo); v.Deny {
		t.Fatalf("still blocked after exclusions: %+v\n%s", v, dirs.String())
	}
	// Elsewhere the rules still apply.
	off := httptest.NewRequest("GET", "http://example.com/other?q=<script>alert(1)</script>", nil)
	if v := runInfo(t, e2, ModeBlock, off, info()); !v.Deny {
		t.Fatal("exclusion leaked outside its path")
	}

	st.Reset()
	if rep := st.Report(10, paths); rep.Learning == nil || rep.Learning.Entries != 0 || len(rep.Learning.Proposals) != 0 {
		t.Fatalf("after reset %+v", rep.Learning)
	}
}

func TestLearningTableBound(t *testing.T) {
	st := NewStats()
	e, err := New(wafConfig(&config.WAFLearning{Enabled: true, MinHits: 1, MaxEntries: 100}), Need{"default": {ModeDetect: true}}, st, nolog)
	if err != nil {
		t.Fatal(err)
	}
	st.Configure(&config.WAFLearning{Enabled: true, MinHits: 1, MaxEntries: 2}, nil)
	for _, q := range []string{"a", "b", "c", "d"} {
		r := httptest.NewRequest("GET", "http://example.com/?"+q+"=<script>alert(1)</script>", nil)
		runInfo(t, e, ModeDetect, r, info())
	}
	rep := st.Report(10, nil)
	if rep.Learning.Entries != 2 || rep.Learning.Dropped == 0 {
		t.Fatalf("bound not applied: %+v", rep.Learning)
	}
}

// TestStatsConcurrent hammers the hot path from many goroutines (the race
// detector checks the atomics and shards) and checks the totals.
func TestStatsConcurrent(t *testing.T) {
	st := NewStats()
	e, err := New(wafConfig(&config.WAFLearning{Enabled: true, MinHits: 1, MaxEntries: 1000}), Need{"default": {ModeBlock: true}}, st, nolog)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := e.Filter("default", ModeBlock)
	const workers, per = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				r := httptest.NewRequest("GET", fmt.Sprintf("http://example.com/p%d?q=<script>alert(%d)</script>", w, i), nil)
				in := f.Begin(context.Background(), info())
				in.Request(r)
				in.End()
			}
		}(w)
	}
	wg.Wait()
	rep := st.Report(5, nil)
	if rep.Requests != workers*per || rep.Blocked != workers*per {
		t.Fatalf("counters %+v", rep)
	}
	if rs := findRule(rep, 941100); rs == nil || rs.Matches != workers*per {
		t.Fatalf("941100 %+v", rs)
	}
	if rep.RulesDropped != 0 || rep.Learning.Dropped != 0 || rep.Learning.Entries == 0 {
		t.Fatalf("learning %+v dropped %d", rep.Learning, rep.RulesDropped)
	}
}

func TestQuoteTarget(t *testing.T) {
	if got := quoteTarget(`ARGS:a"b,c\d`); got != `ARGS:a\"b\,c\\d` {
		t.Fatalf("got %s", got)
	}
	p := &Proposal{Rule: 1, Target: "ARGS:x", Path: `/a"b`}
	if d := directive(p, 10000); strings.Contains(d, `"/a"b"`) {
		t.Fatalf("path quote not stripped: %s", d)
	}
}

// copyCRS writes the embedded rule set to dir in the release layout.
func copyCRS(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := fs.WalkDir(coreruleset.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(coreruleset.FS, p)
		if err != nil {
			return err
		}
		var dst string
		switch {
		case p == "@crs-setup.conf.example":
			dst = filepath.Join(dir, "crs-setup.conf.example")
		case strings.HasPrefix(p, "@owasp_crs/"):
			dst = filepath.Join(dir, "rules", strings.TrimPrefix(p, "@owasp_crs/"))
		default:
			return nil
		}
		return os.WriteFile(dst, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCRSDirectory(t *testing.T) {
	dir := t.TempDir()
	copyCRS(t, dir)
	cfg := wafConfig(nil)
	cfg.Profiles[0].CRS.Dir = dir
	e, err := New(cfg, Need{"default": {ModeBlock: true}}, NewStats(), nolog)
	if err != nil {
		t.Fatal(err)
	}
	ps := e.Profiles()
	if len(ps) != 1 || ps[0].CRS != dir || ps[0].Version == "" || ps[0].RuleFiles < 10 || len(ps[0].Modes) != 1 {
		t.Fatalf("profiles %+v", ps)
	}
	sqli := httptest.NewRequest("GET", "http://example.com/items?id=1%27%20OR%20%271%27=%271", nil)
	if v := runInfo(t, e, ModeBlock, sqli, info()); !v.Deny {
		t.Fatalf("directory rule set did not block: %+v", v)
	}
	// The embedded set reports itself and the same version.
	emb, err := New(wafConfig(nil), Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if ep := emb.Profiles(); ep[0].CRS != "embedded" || ep[0].Version != ps[0].Version {
		t.Fatalf("embedded %+v vs dir %+v", ep, ps)
	}

	// A rule update is a file change plus a new engine: a custom rule
	// dropped into the directory takes effect.
	custom := `SecRule REQUEST_HEADERS:X-Updated "@streq yes" "id:100002,phase:1,deny,status:418,msg:'updated rule set'"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "rules", "REQUEST-999-LOCAL.conf"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	e2, err := New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("X-Updated", "yes")
	if v := runInfo(t, e2, ModeBlock, r, info()); !v.Deny || v.Status != 418 {
		t.Fatalf("updated rule not applied: %+v", v)
	}
	if e2.Profiles()[0].RuleFiles != ps[0].RuleFiles+1 {
		t.Fatalf("rule files %d", e2.Profiles()[0].RuleFiles)
	}

	// A preferred crs-setup.conf wins over the example.
	setup := "SecAction \"id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=9999\"\n"
	if err := os.WriteFile(filepath.Join(dir, "crs-setup.conf"), []byte(setup), 0o644); err != nil {
		t.Fatal(err)
	}
	e3, err := New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if e3.Profiles()[0].Version != "9999" {
		t.Fatalf("version %q", e3.Profiles()[0].Version)
	}

	// A broken rule file fails the load.
	if err := os.WriteFile(filepath.Join(dir, "rules", "REQUEST-998-BROKEN.conf"), []byte("SecRule THIS IS NOT VALID\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog); err == nil {
		t.Fatal("broken directory rule set compiled")
	}
}

func TestCRSDirectoryErrors(t *testing.T) {
	cases := map[string]func(dir string){
		"missing":  func(dir string) { _ = os.RemoveAll(dir) },
		"file":     func(dir string) { _ = os.RemoveAll(dir); _ = os.WriteFile(dir, []byte("x"), 0o644) },
		"no setup": func(dir string) { _ = os.MkdirAll(filepath.Join(dir, "rules"), 0o755) },
		"no rules": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, "crs-setup.conf"), []byte("# empty\n"), 0o644)
		},
	}
	for name, prep := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "crs")
			_ = os.MkdirAll(dir, 0o755)
			prep(dir)
			cfg := wafConfig(nil)
			cfg.Profiles[0].CRS.Dir = dir
			if _, err := New(cfg, Need{"default": {ModeBlock: true}}, nil, nolog); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestProfilesWithoutCRS(t *testing.T) {
	cfg := &config.WAF{
		Profiles:    []config.WAFProfile{{Name: "custom", Directives: `SecRule REQUEST_HEADERS:X-Evil "@streq yes" "id:100001,phase:1,deny,status:406,msg:'evil header'"`}},
		DefaultMode: "block", DefaultProfile: "custom", RequestBodyLimit: 4096, RequestBodyLimitAction: "reject", ResponseBodyLimit: 4096,
		Learning: &config.WAFLearning{Enabled: true, MinHits: 1, MaxEntries: 100},
	}
	st := NewStats()
	e, err := New(cfg, Need{"custom": {ModeBlock: true}}, st, nolog)
	if err != nil {
		t.Fatal(err)
	}
	if ps := e.Profiles(); len(ps) != 1 || ps[0].CRS != "" || ps[0].Version != "" {
		t.Fatalf("profiles %+v", ps)
	}
	f, _ := e.Filter("custom", ModeBlock)
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("X-Evil", "yes")
	in := f.Begin(context.Background(), info())
	in.Request(r)
	in.End()
	rep := st.Report(10, nil)
	if rs := findRule(rep, 100001); rs == nil || rs.Blocks != 1 || rs.Message != "evil header" {
		t.Fatalf("custom rule stats %+v", rs)
	}
	// Custom rules learn too, keyed by their matched header.
	if len(rep.Learning.Proposals) != 1 || rep.Learning.Proposals[0].Target != "REQUEST_HEADERS:X-Evil" {
		t.Fatalf("proposals %+v", rep.Learning.Proposals)
	}
}
