// Package bodyrewrite is a built-in filter kind that rewrites request and
// response bodies with literal or regular expression rules, for the
// cases that need no WebAssembly: fixing absolute links an application
// emits, masking a field, renaming a JSON key on the way in.
//
//	filters:
//	  - name: links
//	    kind: body_rewrite
//	    options:
//	      response:
//	        types: [text/html, application/json]   # media types touched
//	        max_bytes: 4194304                      # larger bodies pass through unchanged
//	        rules:
//	          - {find: "http://intranet.example/", replace: "https://www.example.com/"}
//	          - {regex: `"ssn":\s*"\d{3}-\d{2}-(\d{4})"`, replace: `"ssn": "***-**-$1"`}
//	      request:
//	        types: [application/json]
//	        rules: [{regex: `"userName"`, replace: `"user_name"`}]
//
// A body is buffered up to max_bytes; a larger one, a body the upstream
// already encoded (Content-Encoding) and a media type outside the list
// pass through untouched, so the filter never breaks a download. After a
// change Content-Length is set, ETag and Content-MD5 are removed, and the
// access log carries body_rewrite with the phases that changed.
package bodyrewrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/filter"
)

// Rule is one substitution: Find (literal) or Regex (RE2, Replace may
// use $1 groups); at most Max replacements (0 means all).
type Rule struct {
	Find    string `json:"find"`
	Regex   string `json:"regex"`
	Replace string `json:"replace"`
	Max     int    `json:"max"`
	re      *regexp.Regexp
}

// Phase configures one direction.
type Phase struct {
	Types    []string `json:"types"`
	MaxBytes int64    `json:"max_bytes"`
	Rules    []Rule   `json:"rules"`
	types    map[string]bool
}

// Config is the options schema.
type Config struct {
	Request  *Phase `json:"request"`
	Response *Phase `json:"response"`
}

// DefaultTypes are the media types rewritten unless a phase lists its own.
var DefaultTypes = []string{"text/html", "text/plain", "text/css", "text/javascript", "text/xml", "text/csv",
	"application/json", "application/javascript", "application/xml", "application/xhtml+xml", "image/svg+xml",
	"application/x-www-form-urlencoded"}

const (
	defaultMaxBytes = 1 << 20
	maxMaxBytes     = 64 << 20
	maxRules        = 64
)

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.Request == nil && c.Response == nil {
		errs = append(errs, errors.New("request or response is required"))
	}
	for name, p := range map[string]*Phase{"request": c.Request, "response": c.Response} {
		if p == nil {
			continue
		}
		if len(p.Rules) == 0 || len(p.Rules) > maxRules {
			errs = append(errs, fmt.Errorf("%s.rules: 1 to %d rules", name, maxRules))
		}
		if p.MaxBytes == 0 {
			p.MaxBytes = defaultMaxBytes
		}
		if p.MaxBytes < 1 || p.MaxBytes > maxMaxBytes {
			errs = append(errs, fmt.Errorf("%s.max_bytes: must be between 1 and %d", name, maxMaxBytes))
		}
		if len(p.Types) == 0 {
			p.Types = append([]string(nil), DefaultTypes...)
		}
		p.types = make(map[string]bool, len(p.Types))
		for i, t := range p.Types {
			mt, _, err := mime.ParseMediaType(t)
			if err != nil || mt != strings.ToLower(t) || !strings.Contains(mt, "/") {
				errs = append(errs, fmt.Errorf("%s.types[%d]: %q is not a media type without parameters", name, i, t))
				continue
			}
			p.types[mt] = true
		}
		for i := range p.Rules {
			r := &p.Rules[i]
			switch {
			case r.Find != "" && r.Regex != "", r.Find == "" && r.Regex == "":
				errs = append(errs, fmt.Errorf("%s.rules[%d]: exactly one of find or regex", name, i))
			case len(r.Find) > 4096 || len(r.Regex) > 4096 || len(r.Replace) > 65536:
				errs = append(errs, fmt.Errorf("%s.rules[%d]: too long", name, i))
			case r.Regex != "":
				re, err := regexp.Compile(r.Regex)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s.rules[%d].regex: %w", name, i, err))
					continue
				}
				r.re = re
			}
			if r.Max < 0 {
				errs = append(errs, fmt.Errorf("%s.rules[%d].max: must not be negative", name, i))
			}
		}
	}
	return &c, errors.Join(errs...)
}

// apply runs the rules over body and reports whether anything changed.
func (p *Phase) apply(body []byte) ([]byte, bool) {
	changed := false
	for i := range p.Rules {
		r := &p.Rules[i]
		var out []byte
		if r.re != nil {
			if r.Max == 0 {
				out = r.re.ReplaceAll(body, []byte(r.Replace))
			} else {
				out = replaceN(r.re, body, r.Replace, r.Max)
			}
		} else {
			n := r.Max
			if n == 0 {
				n = -1
			}
			out = bytes.Replace(body, []byte(r.Find), []byte(r.Replace), n)
		}
		if !bytes.Equal(out, body) {
			changed = true
			body = out
		}
	}
	return body, changed
}

// replaceN is ReplaceAll bounded to n matches.
func replaceN(re *regexp.Regexp, src []byte, repl string, n int) []byte {
	var out []byte
	last := 0
	for _, m := range re.FindAllSubmatchIndex(src, n) {
		out = append(out, src[last:m[0]]...)
		out = re.Expand(out, []byte(repl), src, m)
		last = m[1]
	}
	return append(out, src[last:]...)
}

// eligible reports whether a header set describes a body the phase may
// rewrite: a listed media type and no content encoding.
func (p *Phase) eligible(h http.Header) bool {
	if h.Get("Content-Encoding") != "" || h.Get("Content-Range") != "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && p.types[mt]
}

// buffer reads up to limit+1 bytes. It returns the bytes, whether the
// whole body fit, and a reader that replays everything when it did not.
func buffer(rc io.ReadCloser, limit int64) ([]byte, bool, io.ReadCloser, error) {
	if rc == nil || rc == http.NoBody {
		return nil, true, rc, nil
	}
	buf, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, false, rc, err
	}
	if int64(len(buf)) > limit {
		return buf, false, struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), rc), rc}, nil
	}
	_ = rc.Close()
	return buf, true, nil, nil
}

type rewriter struct {
	name string
	cfg  *Config
}

func (f *rewriter) Name() string { return f.name }

func (f *rewriter) Begin(context.Context, *filter.Info) filter.Instance {
	return &instance{f: f}
}

type instance struct {
	f    *rewriter
	done []string
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	p := in.f.cfg.Request
	if p == nil || r.Body == nil || r.Body == http.NoBody || !p.eligible(r.Header) {
		return filter.Continue
	}
	if r.ContentLength > p.MaxBytes {
		return filter.Continue
	}
	body, whole, rest, err := buffer(r.Body, p.MaxBytes)
	if err != nil {
		return filter.Verdict{Deny: true, Status: http.StatusBadRequest, Reason: in.f.name, Detail: "request body: " + err.Error()}
	}
	if !whole {
		r.Body = rest
		return filter.Continue
	}
	out, changed := p.apply(body)
	r.Body = io.NopCloser(bytes.NewReader(out))
	if changed {
		r.ContentLength = int64(len(out))
		r.Header.Set("Content-Length", strconv.Itoa(len(out)))
		r.Header.Del("Content-MD5")
		in.done = append(in.done, "request")
	}
	return filter.Continue
}

func (in *instance) Response(resp *http.Response) filter.Verdict {
	p := in.f.cfg.Response
	if p == nil || resp.Body == nil || resp.Body == http.NoBody || !p.eligible(resp.Header) {
		return filter.Continue
	}
	if resp.ContentLength > p.MaxBytes {
		return filter.Continue
	}
	body, whole, rest, err := buffer(resp.Body, p.MaxBytes)
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body)) // what arrived; the client sees a short body
		return filter.Continue
	}
	if !whole {
		resp.Body = rest
		return filter.Continue
	}
	out, changed := p.apply(body)
	resp.Body = io.NopCloser(bytes.NewReader(out))
	if changed {
		resp.ContentLength = int64(len(out))
		resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
		resp.Header.Del("ETag")
		resp.Header.Del("Content-MD5")
		in.done = append(in.done, "response")
	}
	return filter.Continue
}

func (in *instance) End() []any {
	if len(in.done) == 0 {
		return nil
	}
	return []any{"body_rewrite", strings.Join(in.done, ",")}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "body_rewrite",
		Description: "Rewrite request and response bodies with literal or regular expression rules.",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return &rewriter{name: name, cfg: c}, nil
		},
	})
}
