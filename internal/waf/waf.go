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
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

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
	log      *slog.Logger
}

type profile struct {
	name   string
	block  coraza.WAF
	detect coraza.WAF
}

// Need lists which (profile, mode) pairs the routes use, so that only those
// are compiled.
type Need map[string]map[Mode]bool

// New compiles the profiles required by need.
func New(cfg *config.WAF, need Need, log *slog.Logger) (*Engine, error) {
	e := &Engine{cfg: cfg, profiles: map[string]*profile{}, log: log.With("component", "waf")}
	for i := range cfg.Profiles {
		pc := &cfg.Profiles[i]
		modes := need[pc.Name]
		if len(modes) == 0 {
			continue
		}
		p := &profile{name: pc.Name}
		base, err := e.directives(pc)
		if err != nil {
			return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
		}
		if modes[ModeBlock] {
			w, err := compile(base, "On")
			if err != nil {
				return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
			}
			p.block = w
		}
		if modes[ModeDetect] {
			w, err := compile(base, "DetectionOnly")
			if err != nil {
				return nil, fmt.Errorf("waf profile %s: %w", pc.Name, err)
			}
			p.detect = w
		}
		e.profiles[pc.Name] = p
	}
	return e, nil
}

func compile(base string, engine string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(base + "\nSecRuleEngine " + engine + "\n")
	return coraza.NewWAF(cfg)
}

// directives assembles the SecLang for a profile. Order matters: engine
// recommendations, body limits, CRS setup, tuning, operator exclusions,
// CRS rules.
func (e *Engine) directives(pc *config.WAFProfile) (string, error) {
	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\n")
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
		b.WriteString("Include @crs-setup.conf.example\n")
		fmt.Fprintf(&b, "SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", crs.ParanoiaLevel)
		fmt.Fprintf(&b, "SecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n", crs.InboundThreshold, crs.OutboundThreshold)
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
		b.WriteString("Include @owasp_crs/*.conf\n")
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
	return &wafFilter{engine: e, waf: w, profile: profileName, mode: mode}, nil
}

type wafFilter struct {
	engine  *Engine
	waf     coraza.WAF
	profile string
	mode    Mode
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
	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
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
		r.Body = io.NopCloser(body)
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: "waf", Detail: err.Error()}
	} else if it != nil {
		return in.interrupt(it, "request_body")
	}
	return filter.Continue
}

func (in *instance) Response(resp *http.Response) filter.Verdict {
	tx := in.tx
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
	var out []any
	if in.verdict != nil || in.detected() {
		out = in.attrs()
		if in.verdict == nil && in.f.mode == ModeDetect {
			out = append(out, "waf_detected", true)
		}
	}
	_ = in.tx.Close()
	return out
}
