// Package waf integrates the Coraza web application firewall engine and the
// OWASP Core Rule Set as an xproxy filter.
//
// One Engine is built per configuration generation. Each configured profile
// compiles into up to two Coraza instances, one in blocking mode and one in
// detection-only mode, so that a route can run the same rules in "detect"
// (shadow) or "block" mode. Compilation happens at load time so that a
// broken rule set fails the reload rather than the first request
// (docs/AMR.md, AMR-008 and AMR-020).
package waf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

// Mode is a WAF evaluation mode.
type Mode string

const (
	ModeOff    Mode = "off"
	ModeDetect Mode = "detect"
	ModeBlock  Mode = "block"
)

// Engine holds compiled profiles.
type Engine struct {
	cfg      *config.WAF
	profiles map[string]*profile
	stats    *Stats
	log      *slog.Logger
}

type profile struct {
	name   string
	block  coraza.WAF
	detect coraza.WAF
	// source is "embedded", the CRS directory, or "" without the CRS;
	// version is the tx.crs_setup_version the setup file declares.
	source  string
	version string
	rules   int
	plugins []plugin
	schemas []*bodySchema
}

// ProfileStatus describes one compiled profile (GET /v1/waf).
type ProfileStatus struct {
	Name  string   `json:"name"`
	Modes []string `json:"modes"`
	// CRS is "embedded", the rule set directory, or "" when the profile
	// has no Core Rule Set.
	CRS string `json:"crs,omitempty"`
	// Version is the CRS setup version (for example "4250" for 4.25.0).
	Version string `json:"version,omitempty"`
	// RuleFiles counts the CRS rule files loaded.
	RuleFiles int `json:"rule_files,omitempty"`
	// Plugins names the CRS plugins loaded.
	Plugins []string `json:"plugins,omitempty"`
	// Schemas names the JSON body schemas enforced.
	Schemas []string `json:"schemas,omitempty"`
}

// Profiles lists the compiled profiles in configuration order.
func (e *Engine) Profiles() []ProfileStatus {
	out := make([]ProfileStatus, 0, len(e.profiles))
	for i := range e.cfg.Profiles {
		p, ok := e.profiles[e.cfg.Profiles[i].Name]
		if !ok {
			continue
		}
		st := ProfileStatus{Name: p.name, Modes: []string{}, CRS: p.source, Version: p.version, RuleFiles: p.rules}
		for _, pl := range p.plugins {
			st.Plugins = append(st.Plugins, pl.name)
		}
		for _, sc := range p.schemas {
			st.Schemas = append(st.Schemas, sc.name)
		}
		if p.block != nil {
			st.Modes = append(st.Modes, string(ModeBlock))
		}
		if p.detect != nil {
			st.Modes = append(st.Modes, string(ModeDetect))
		}
		out = append(out, st)
	}
	return out
}

// Need lists which (profile, mode) pairs the routes use, so that only those
// are compiled.
type Need map[string]map[Mode]bool

// New compiles the profiles required by need. stats receives per rule
// counters and learning observations; nil disables both.
func New(cfg *config.WAF, need Need, stats *Stats, log *slog.Logger) (*Engine, error) {
	e := &Engine{cfg: cfg, profiles: map[string]*profile{}, stats: stats, log: log.With("component", "waf")}
	if stats != nil {
		stats.Configure(cfg.Learning, cfg.Anomaly)
	}
	for i := range cfg.Profiles {
		pc := &cfg.Profiles[i]
		modes := need[pc.Name]
		if len(modes) == 0 {
			continue
		}
		p := &profile{name: pc.Name}
		src, err := openRuleSet(pc)
		if err != nil {
			return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
		}
		p.source, p.version, p.rules = src.name, src.version, src.files
		if pc.CRS != nil && pc.CRS.PluginsDir != "" {
			if p.plugins, err = loadPlugins(pc.CRS.PluginsDir, pc.CRS.Plugins); err != nil {
				return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
			}
			src.fs = newPluginFS(src.fs, p.plugins)
		}
		if p.schemas, err = loadSchemas(pc.JSONSchemas); err != nil {
			return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
		}
		base, err := e.directives(pc, src, p.plugins)
		if err != nil {
			return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
		}
		if modes[ModeBlock] {
			w, err := compile(src.fs, base, "On")
			if err != nil {
				return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
			}
			p.block = w
		}
		if modes[ModeDetect] {
			w, err := compile(src.fs, base, "DetectionOnly")
			if err != nil {
				return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
			}
			p.detect = w
		}
		e.profiles[pc.Name] = p
	}
	return e, nil
}

func compile(root fs.FS, base string, engine string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithRootFS(root).
		WithDirectives(base + "\nSecRuleEngine " + engine + "\n")
	return coraza.NewWAF(cfg)
}

// ruleSet is where a profile's Core Rule Set comes from: the embedded copy
// or an operator directory (crs.dir), which lets the rules be updated
// without rebuilding the binary.
type ruleSet struct {
	fs fs.FS
	// name is "embedded" or the directory path; "" without the CRS.
	name string
	// setup and rules are the include paths inside fs.
	setup   string
	rules   string
	version string
	files   int
}

// recommended is the engine configuration the embedded rule set ships;
// it is inlined so that a directory rule set does not need a copy.
var recommended = sync.OnceValues(func() (string, error) {
	data, err := fs.ReadFile(coreruleset.FS, "@coraza.conf-recommended")
	return string(data), err
})

// crsVersionRE finds the setup version declared by crs-setup.conf.
var crsVersionRE = regexp.MustCompile(`setvar:'?tx\.crs_setup_version=(\d+)`)

// openRuleSet locates the CRS for a profile and checks its layout.
func openRuleSet(pc *config.WAFProfile) (*ruleSet, error) {
	if pc.CRS == nil {
		return &ruleSet{fs: coreruleset.FS}, nil
	}
	if pc.CRS.Dir == "" {
		rs := &ruleSet{fs: coreruleset.FS, name: "embedded", setup: "@crs-setup.conf.example", rules: "@owasp_crs/*.conf"}
		return rs.inspect()
	}
	dir := pc.CRS.Dir
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("crs.dir: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("crs.dir: %s is not a directory", dir)
	}
	rs := &ruleSet{fs: os.DirFS(dir), name: dir, rules: "rules/*.conf"}
	for _, cand := range []string{"crs-setup.conf", "crs-setup.conf.example"} {
		if _, err := fs.Stat(rs.fs, cand); err == nil {
			rs.setup = cand
			break
		}
	}
	if rs.setup == "" {
		return nil, fmt.Errorf("crs.dir: %s has no crs-setup.conf or crs-setup.conf.example", dir)
	}
	return rs.inspect()
}

// inspect reads the setup version and counts the rule files.
func (rs *ruleSet) inspect() (*ruleSet, error) {
	data, err := fs.ReadFile(rs.fs, rs.setup)
	if err != nil {
		return nil, fmt.Errorf("crs setup: %w", err)
	}
	if m := crsVersionRE.FindSubmatch(data); m != nil {
		rs.version = string(m[1])
	}
	files, err := fs.Glob(rs.fs, rs.rules)
	if err != nil {
		return nil, fmt.Errorf("crs rules: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("crs rules: no %s files under %s", rs.rules, rs.name)
	}
	rs.files = len(files)
	return rs, nil
}

// directives assembles the SecLang for a profile. Order matters: engine
// recommendations, body limits, CRS setup, tuning, plugin configuration
// and before-rules, operator exclusions, CRS rules, plugin after-rules.
func (e *Engine) directives(pc *config.WAFProfile, src *ruleSet, plugins []plugin) (string, error) {
	var b strings.Builder
	rec, err := recommended()
	if err != nil {
		return "", fmt.Errorf("embedded engine configuration: %w", err)
	}
	b.WriteString("# --- coraza.conf-recommended ---\n")
	b.WriteString(rec)
	b.WriteString("\n# --- xproxy ---\n")
	b.WriteString("SecAuditEngine Off\n")
	fmt.Fprintf(&b, "SecRequestBodyLimit %d\n", e.cfg.RequestBodyLimit)
	fmt.Fprintf(&b, "SecRequestBodyInMemoryLimit %d\n", min(e.cfg.RequestBodyLimit, 1<<20))
	if e.cfg.RequestBodyLimitAction == "partial" {
		b.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	} else {
		b.WriteString("SecRequestBodyLimitAction Reject\n")
	}
	if e.cfg.InspectResponses {
		b.WriteString("SecResponseBodyAccess On\n")
		fmt.Fprintf(&b, "SecResponseBodyLimit %d\n", e.cfg.ResponseBodyLimit)
		b.WriteString("SecResponseBodyLimitAction ProcessPartial\n")
		fmt.Fprintf(&b, "SecResponseBodyMimeType %s\n", strings.Join(e.cfg.ResponseMIMETypes, " "))
	} else {
		b.WriteString("SecResponseBodyAccess Off\n")
	}
	if crs := pc.CRS; crs != nil {
		fmt.Fprintf(&b, "Include %s\n", src.setup)
		fmt.Fprintf(&b, "SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", crs.ParanoiaLevel)
		fmt.Fprintf(&b, "SecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n", crs.InboundThreshold, crs.OutboundThreshold)
	}
	if err := writePluginFiles(&b, plugins, func(p *plugin) string { return p.config }); err != nil {
		return "", err
	}
	if err := writePluginFiles(&b, plugins, func(p *plugin) string { return p.before }); err != nil {
		return "", err
	}
	for _, f := range pc.DirectiveFiles {
		data, err := os.ReadFile(f) //nolint:gosec // operator configured rule file
		if err != nil {
			return "", fmt.Errorf("read directive file: %w", err)
		}
		fmt.Fprintf(&b, "\n# --- %s ---\n", f)
		b.Write(data)
		b.WriteString("\n")
	}
	if strings.TrimSpace(pc.Directives) != "" {
		b.WriteString("\n# --- inline directives ---\n")
		b.WriteString(pc.Directives)
		b.WriteString("\n")
	}
	if pc.CRS != nil {
		fmt.Fprintf(&b, "Include %s\n", src.rules)
	}
	if err := writePluginFiles(&b, plugins, func(p *plugin) string { return p.after }); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Filter returns a filter for the profile in the given mode, or nil when
// the mode is off. It is an error to ask for a pair that was not compiled.
func (e *Engine) Filter(profileName string, mode Mode) (filter.Filter, error) {
	if mode == ModeOff || mode == "" {
		return nil, nil
	}
	p, ok := e.profiles[profileName]
	if !ok {
		return nil, fmt.Errorf("waf profile %q not compiled", profileName)
	}
	w := p.block
	if mode == ModeDetect {
		w = p.detect
	}
	if w == nil {
		return nil, fmt.Errorf("waf profile %q not compiled for mode %s", profileName, mode)
	}
	return &wafFilter{engine: e, waf: w, profile: profileName, mode: mode, schemas: p.schemas}, nil
}

type wafFilter struct {
	engine  *Engine
	waf     coraza.WAF
	profile string
	mode    Mode
	schemas []*bodySchema
}

func (f *wafFilter) Name() string { return "waf:" + f.profile + ":" + string(f.mode) }

func (f *wafFilter) Begin(_ context.Context, info *filter.Info) filter.Instance {
	tx := f.waf.NewTransactionWithID(info.RequestID)
	return &instance{f: f, tx: tx, info: info}
}

type instance struct {
	f    *wafFilter
	tx   types.Transaction
	info *filter.Info
	done bool
	// verdict is the request or response interruption, if any.
	verdict *types.Interruption
	// schema and schemaName record a JSON body schema violation (denied
	// in block mode, logged in detect mode).
	schema     *schemaResult
	schemaName string
	// flag is set when the client is flagged by anomaly detection.
	flag *flag
	// status is the upstream response status, 0 when none was seen.
	status int
}

// errResponseBlocked is returned through the reverse proxy when the
// response phase interrupts.
var errResponseBlocked = errors.New("waf: response blocked")

// IsResponseBlocked reports whether err is a WAF response interruption.
func IsResponseBlocked(err error) bool { return errors.Is(err, errResponseBlocked) }

func (in *instance) Request(r *http.Request) filter.Verdict {
	tx := in.tx
	clientPort := 0
	if _, p, ok := strings.Cut(r.RemoteAddr, "]:"); ok {
		clientPort, _ = strconv.Atoi(p)
	} else if i := strings.LastIndexByte(r.RemoteAddr, ':'); i >= 0 {
		clientPort, _ = strconv.Atoi(r.RemoteAddr[i+1:])
	}
	tx.ProcessConnection(in.info.ClientIP.String(), clientPort, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return in.interrupt(it, "request_headers")
	}
	if v, deny := in.anomalyCheck(); deny {
		return v
	}
	if v, deny := in.schemaCheck(r); deny {
		return v
	}
	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		rest := r.Body
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return filter.Verdict{Deny: true, Status: http.StatusRequestEntityTooLarge, Reason: "body_size", Detail: "body exceeds limit"}
			}
			return filter.Verdict{Deny: true, Status: http.StatusBadRequest, Reason: "waf", Detail: "reading request body: " + err.Error()}
		}
		if it != nil {
			return in.interrupt(it, "request_body")
		}
		body, err := tx.RequestBodyReader()
		if err != nil {
			return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: "waf", Detail: err.Error()}
		}
		// The inspected prefix followed by whatever the engine left unread:
		// with request_body_limit_action partial the body beyond the limit
		// is passed through as documented instead of being cut off (which
		// broke every request over the limit with a 502 or a truncated
		// upload).
		r.Body = io.NopCloser(io.MultiReader(body, rest))
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: "waf", Detail: err.Error()}
	} else if it != nil {
		return in.interrupt(it, "request_body")
	}
	return filter.Continue
}

// anomalyCheck applies the configured action when the client is flagged
// by behavioural anomaly detection.
func (in *instance) anomalyCheck() (filter.Verdict, bool) {
	s := in.f.engine.stats
	if s == nil {
		return filter.Continue, false
	}
	f := s.anomaly.lookup(in.info.ClientIP.String())
	if f == nil {
		return filter.Continue, false
	}
	in.flag = f
	detail := fmt.Sprintf("%s z=%.1f", f.feature, f.score)
	switch s.anomaly.config().action {
	case "block":
		return filter.Verdict{Deny: true, Status: http.StatusForbidden, Reason: "waf_anomaly", Detail: detail, Attrs: in.anomalyAttrs()}, true
	case "challenge":
		return filter.Verdict{Deny: true, Challenge: true, Status: http.StatusForbidden, Reason: "waf_anomaly", Detail: detail, Attrs: in.anomalyAttrs()}, true
	}
	return filter.Continue, false
}

func (in *instance) anomalyAttrs() []any {
	if in.flag == nil {
		return nil
	}
	return []any{"waf_anomaly", in.flag.feature, "waf_anomaly_score", round(in.flag.score)}
}

// schemaCheck enforces the profile's JSON body schema bound to the
// request, if any. In detect mode a violation is recorded and the
// request continues.
func (in *instance) schemaCheck(r *http.Request) (filter.Verdict, bool) {
	sc := matchSchema(in.f.schemas, r.Method, r.URL.Path)
	if sc == nil {
		return filter.Continue, false
	}
	res, err := sc.check(r, in.f.engine.cfg.RequestBodyLimit)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return filter.Verdict{Deny: true, Status: http.StatusRequestEntityTooLarge, Reason: "body_size", Detail: "body exceeds limit"}, true
		}
		return filter.Verdict{Deny: true, Status: http.StatusBadRequest, Reason: "waf", Detail: "reading request body: " + err.Error()}, true
	}
	if res == nil {
		return filter.Continue, false
	}
	in.schema, in.schemaName = res, sc.name
	if in.f.mode == ModeBlock {
		return res.verdict(sc.name, in.attrs()), true
	}
	return filter.Continue, false
}

func (in *instance) Response(resp *http.Response) filter.Verdict {
	tx := in.tx
	in.status = resp.StatusCode
	if !in.f.engine.cfg.InspectResponses {
		return filter.Continue
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			tx.AddResponseHeader(k, v)
		}
	}
	if it := tx.ProcessResponseHeaders(resp.StatusCode, resp.Proto); it != nil {
		return in.interrupt(it, "response_headers")
	}
	if tx.IsResponseBodyProcessable() && resp.Body != nil && (resp.ContentLength < 0 || resp.ContentLength <= in.f.engine.cfg.ResponseBodyLimit) {
		limit := in.f.engine.cfg.ResponseBodyLimit
		var buf bytes.Buffer
		n, err := io.CopyN(&buf, resp.Body, limit+1)
		if err != nil && !errors.Is(err, io.EOF) {
			_ = resp.Body.Close()
			return filter.Verdict{Deny: true, Status: http.StatusBadGateway, Reason: "waf", Detail: "reading response body: " + err.Error()}
		}
		if n > limit {
			// Too large to inspect: pass through the bytes we read plus the
			// rest of the stream, uninspected, as configured.
			resp.Body = &joinedBody{Reader: io.MultiReader(&buf, resp.Body), closer: resp.Body}
			return filter.Continue
		}
		_ = resp.Body.Close()
		if it, _, err := tx.ReadResponseBodyFrom(bytes.NewReader(buf.Bytes())); err != nil {
			return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: "waf", Detail: err.Error()}
		} else if it != nil {
			return in.interrupt(it, "response_body")
		}
		if it, err := tx.ProcessResponseBody(); err != nil {
			return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: "waf", Detail: err.Error()}
		} else if it != nil {
			return in.interrupt(it, "response_body")
		}
		resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		resp.ContentLength = int64(buf.Len())
		resp.Header.Set("Content-Length", strconv.Itoa(buf.Len()))
	}
	return filter.Continue
}

type joinedBody struct {
	io.Reader
	closer io.Closer
}

func (j *joinedBody) Close() error { return j.closer.Close() }

func (in *instance) interrupt(it *types.Interruption, phase string) filter.Verdict {
	in.verdict = it
	status := it.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	v := filter.Verdict{Deny: true, Status: status, Reason: "waf", Detail: phase, Attrs: in.attrs()}
	v.Attrs = append(v.Attrs, "waf_rule", it.RuleID, "waf_action", it.Action, "waf_phase", phase)
	return v
}

// relevant reports whether a matched rule is worth logging: a CRS attack
// detection rule, a CRS blocking evaluation rule, or any custom rule with
// a message. CRS initialisation and reporting rules are skipped.
func relevant(m types.MatchedRule) bool {
	if m.Message() == "" {
		return false
	}
	r := m.Rule()
	if r.ID() == 949110 || r.ID() == 959100 {
		return true
	}
	crs := false
	for _, t := range r.Tags() {
		if t == "OWASP_CRS" {
			crs = true
		}
		if strings.HasPrefix(t, "attack-") {
			return true
		}
	}
	return !crs
}

// attrs summarises matched rules for logging.
func (in *instance) attrs() []any {
	rules := in.tx.MatchedRules()
	ids := make([]int, 0, len(rules))
	var top string
	score := -1
	for _, m := range rules {
		if !relevant(m) {
			continue
		}
		r := m.Rule()
		msg := m.Message()
		ids = append(ids, r.ID())
		if r.ID() == 949110 || r.ID() == 959100 {
			if i := strings.LastIndex(msg, "Total Score: "); i >= 0 {
				score, _ = strconv.Atoi(strings.TrimRight(msg[i+len("Total Score: "):], ")"))
			}
			continue
		}
		if top == "" {
			top = msg
		}
	}
	out := []any{"waf_profile", in.f.profile, "waf_mode", string(in.f.mode)}
	if len(ids) > 0 {
		out = append(out, "waf_matched", ids)
	}
	if top != "" {
		out = append(out, "waf_message", top)
	}
	if score >= 0 {
		out = append(out, "waf_score", score)
	}
	if in.schema != nil {
		out = append(out, "waf_schema", in.schemaName, "waf_schema_issue", in.schema.issue)
	}
	out = append(out, in.anomalyAttrs()...)
	return out
}

// Detected reports whether any scoring rule matched (used in detect mode
// to log what block mode would have done).
func (in *instance) detected() bool {
	for _, m := range in.tx.MatchedRules() {
		if relevant(m) {
			return true
		}
	}
	return false
}

func (in *instance) End() []any {
	if in.done {
		return nil
	}
	in.done = true
	in.tx.ProcessLogging()
	if s := in.f.engine.stats; s != nil {
		s.record(in)
	}
	var out []any
	if in.verdict != nil || in.schema != nil || in.flag != nil || in.detected() {
		out = in.attrs()
		if in.verdict == nil && in.f.mode == ModeDetect && (in.schema != nil || in.detected()) {
			out = append(out, "waf_detected", true)
		}
	}
	_ = in.tx.Close()
	return out
}
