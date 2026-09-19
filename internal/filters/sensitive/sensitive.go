// Package sensitive is a built-in filter kind that detects personal and
// secret data in requests and responses: payment card numbers (Luhn
// checked), Swedish personal identity numbers, IBANs (mod 97), US social
// security numbers, e-mail addresses, JSON Web Tokens, private keys,
// cloud and platform API keys, and passwords or tokens in query strings.
// Per direction it logs the findings, masks them or blocks the message.
//
//	filters:
//	  - name: dlp
//	    kind: sensitive_data
//	    options:
//	      detectors: [card, personnummer, iban, email, jwt, private_key, api_keys, password_query]
//	      custom: [{name: order_secret, regex: "OS-[0-9]{12}"}]
//	      request:  {action: log,   scan: [query, headers, body]}
//	      response: {action: mask,  scan: [headers, body]}
//	      block_status: 403
//
// Bodies are buffered up to max_bytes per direction (a larger or an
// encoded body passes unscanned; an unlisted media type too); masking
// rewrites bodies and header values and updates the content length;
// blocking answers block_status with a JSON problem naming the kinds
// found, never the values. The access log carries sensitive_types and
// sensitive_count for every message with a finding.
package sensitive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rom/xproxy/internal/filter"
)

// Phase configures one direction.
type Phase struct {
	// Action is log (default), mask or block.
	Action string `json:"action"`
	// Scan lists what is inspected: query, headers, body (request) or
	// headers, body (response). Default: everything of the direction.
	Scan []string `json:"scan"`
	// Types are the body media types scanned. Default: text and JSON,
	// XML, form and JavaScript types.
	Types []string `json:"types"`
	// MaxBytes bounds the body buffered. Default 1 MiB.
	MaxBytes int64 `json:"max_bytes"`
	// IgnoreHeaders are not scanned (request default: Authorization,
	// Cookie, X-Api-Key; response default: Set-Cookie).
	IgnoreHeaders []string `json:"ignore_headers"`
	// Encoded is scan (default: gzip, deflate, br and zstd bodies are
	// decoded for scanning, a masked or streamed one is forwarded
	// decoded) or skip.
	Encoded string `json:"encoded"`
	// Oversize is stream (default: a body larger than max_bytes is
	// scanned as it flows, holding back 4 KiB between chunks; a block
	// cuts the transfer) or skip.
	Oversize string `json:"oversize"`
	// MaxDecodedBytes bounds a decoded body buffered whole; a larger one
	// is streamed. Default four times max_bytes.
	MaxDecodedBytes int64 `json:"max_decoded_bytes"`
	scan            map[string]bool
	types           map[string]bool
	ignore          map[string]bool
}

// Custom is an operator detector.
type Custom struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// Config is the options schema.
type Config struct {
	Detectors   []string `json:"detectors"`
	Custom      []Custom `json:"custom"`
	Request     *Phase   `json:"request"`
	Response    *Phase   `json:"response"`
	BlockStatus int      `json:"block_status"`
	// MinFindings is how many findings a message needs before mask or
	// block act; fewer are logged only. Default 1.
	MinFindings int `json:"min_findings"`
}

// DefaultTypes are the body media types scanned unless a phase lists
// its own.
var DefaultTypes = []string{"text/plain", "text/html", "text/csv", "text/xml", "application/json", "application/xml", "application/x-www-form-urlencoded",
	"application/javascript", "application/problem+json", "application/graphql", "application/ld+json"}

const (
	defaultMaxBytes = 1 << 20
	maxMaxBytes     = 64 << 20
	maxFindings     = 64
)

type guard struct {
	name      string
	cfg       *Config
	detectors []*detector
}

func parsePhase(name string, p *Phase, request bool) error {
	var errs []error
	if p.Action == "" {
		p.Action = "log"
	}
	switch p.Action {
	case "log", "mask", "block":
	default:
		errs = append(errs, fmt.Errorf("%s.action: must be log, mask or block", name))
	}
	allowed := map[string]bool{"headers": true, "body": true}
	if request {
		allowed["query"] = true
	}
	if len(p.Scan) == 0 {
		for k := range allowed {
			p.Scan = append(p.Scan, k)
		}
		sort.Strings(p.Scan)
	}
	p.scan = map[string]bool{}
	for i, s := range p.Scan {
		if !allowed[s] {
			errs = append(errs, fmt.Errorf("%s.scan[%d]: %q is not query, headers or body for this direction", name, i, s))
			continue
		}
		p.scan[s] = true
	}
	if p.MaxBytes == 0 {
		p.MaxBytes = defaultMaxBytes
	}
	if p.MaxBytes < 1 || p.MaxBytes > maxMaxBytes {
		errs = append(errs, fmt.Errorf("%s.max_bytes: must be between 1 and %d", name, maxMaxBytes))
	}
	if p.MaxDecodedBytes == 0 {
		p.MaxDecodedBytes = 4 * p.MaxBytes
	}
	if p.MaxDecodedBytes < p.MaxBytes || p.MaxDecodedBytes > 1<<30 {
		errs = append(errs, fmt.Errorf("%s.max_decoded_bytes: must be between max_bytes and 1073741824", name))
	}
	switch p.Encoded {
	case "":
		p.Encoded = "scan"
	case "scan", "skip":
	default:
		errs = append(errs, fmt.Errorf("%s.encoded: must be scan or skip", name))
	}
	switch p.Oversize {
	case "":
		p.Oversize = "stream"
	case "stream", "skip":
	default:
		errs = append(errs, fmt.Errorf("%s.oversize: must be stream or skip", name))
	}
	if len(p.Types) == 0 {
		p.Types = append([]string(nil), DefaultTypes...)
	}
	p.types = map[string]bool{}
	for i, t := range p.Types {
		mt, _, err := mime.ParseMediaType(t)
		if err != nil || mt != strings.ToLower(t) || !strings.Contains(mt, "/") {
			errs = append(errs, fmt.Errorf("%s.types[%d]: %q is not a media type without parameters", name, i, t))
			continue
		}
		p.types[mt] = true
	}
	if p.IgnoreHeaders == nil {
		if request {
			p.IgnoreHeaders = []string{"Authorization", "Cookie", "X-Api-Key", "Proxy-Authorization"}
		} else {
			p.IgnoreHeaders = []string{"Set-Cookie"}
		}
	}
	p.ignore = map[string]bool{}
	for _, h := range p.IgnoreHeaders {
		p.ignore[http.CanonicalHeaderKey(h)] = true
	}
	return errors.Join(errs...)
}

func parse(opts filter.Options) (*guard, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.Request == nil && c.Response == nil {
		errs = append(errs, errors.New("request or response is required"))
	}
	if c.Request != nil {
		if err := parsePhase("request", c.Request, true); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Response != nil {
		if err := parsePhase("response", c.Response, false); err != nil {
			errs = append(errs, err)
		}
	}
	if c.BlockStatus == 0 {
		c.BlockStatus = http.StatusForbidden
	}
	if c.BlockStatus < 400 || c.BlockStatus > 599 {
		errs = append(errs, errors.New("block_status: must be a 4xx or 5xx status"))
	}
	if c.MinFindings == 0 {
		c.MinFindings = 1
	}
	if c.MinFindings < 1 || c.MinFindings > maxFindings {
		errs = append(errs, fmt.Errorf("min_findings: must be between 1 and %d", maxFindings))
	}
	g := &guard{cfg: &c}
	names := c.Detectors
	if len(names) == 0 {
		names = builtinNames
	}
	seen := map[string]bool{}
	for i, n := range names {
		d := builtin(n)
		if d == nil {
			errs = append(errs, fmt.Errorf("detectors[%d]: %q is not one of %s", i, n, strings.Join(builtinNames, ", ")))
			continue
		}
		if seen[n] {
			errs = append(errs, fmt.Errorf("detectors[%d]: duplicate %q", i, n))
			continue
		}
		seen[n] = true
		g.detectors = append(g.detectors, d)
	}
	if len(c.Custom) > 32 {
		errs = append(errs, errors.New("custom: at most 32 detectors"))
	}
	for i, cu := range c.Custom {
		if cu.Name == "" || len(cu.Name) > 32 || seen[cu.Name] {
			errs = append(errs, fmt.Errorf("custom[%d].name: required, unique, at most 32 characters", i))
			continue
		}
		if cu.Regex == "" || len(cu.Regex) > 1024 {
			errs = append(errs, fmt.Errorf("custom[%d].regex: required, at most 1024 bytes", i))
			continue
		}
		re, err := regexp.Compile(cu.Regex)
		if err != nil {
			errs = append(errs, fmt.Errorf("custom[%d].regex: %w", i, err))
			continue
		}
		seen[cu.Name] = true
		g.detectors = append(g.detectors, &detector{name: cu.Name, re: re, validate: func(string) bool { return true }, mask: keepFirst8})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return g, nil
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(context.Context, *filter.Info) filter.Instance {
	return &instance{g: g, kinds: map[string]int{}, where: map[string]bool{}}
}

type instance struct {
	g     *guard
	mu    sync.Mutex // streamed bodies record from the transport's goroutine
	kinds map[string]int
	where map[string]bool
	count int
}

// findings is what one scan over one text found.
type findings struct {
	kinds map[string]int
	n     int
}

// scanText finds every detector's validated matches in text; when mask
// is set the matches are replaced and the new text returned.
func (g *guard) scanText(text string, request bool, mask bool) (string, findings) {
	f := findings{kinds: map[string]int{}}
	for _, d := range g.detectors {
		if d.queryNames || (d.requestOnly && !request) {
			continue
		}
		if mask {
			text = d.re.ReplaceAllStringFunc(text, func(m string) string {
				if !d.validate(m) || f.n >= maxFindings {
					return m
				}
				f.kinds[d.name]++
				f.n++
				return d.mask(m)
			})
			continue
		}
		for _, m := range d.re.FindAllString(text, maxFindings) {
			if d.validate(m) {
				f.kinds[d.name]++
				f.n++
			}
		}
	}
	return text, f
}

func (in *instance) record(where string, f findings) {
	if f.n == 0 {
		return
	}
	in.mu.Lock()
	in.where[where] = true
	in.count += f.n
	for k, n := range f.kinds {
		in.kinds[k] += n
		countFinding(k, n)
	}
	in.mu.Unlock()
}

// total is the findings so far.
func (in *instance) total() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.count
}

// blockedStream counts a streamed body cut by a block.
func (in *instance) blockedStream(direction string) {
	countAction(direction, "blocked")
}

// body decides how a body is scanned and returns the body to forward
// (nil when the message must not be touched): a small body is buffered
// and scanned whole (decoded when compressed), a larger or larger-when-
// decoded one is streamed through the scanner. newLen is the new
// content length (-1 for a stream), plain whether the encoding header
// must go (the body is forwarded decoded) and masked whether bytes
// changed.
func (in *instance) body(direction string, p *Phase, h http.Header, rc io.ReadCloser, length int64, mask bool) (out io.ReadCloser, newLen int64, plain, masked bool) {
	enc, ok := encodingOf(h)
	if !ok || (enc != "" && p.Encoded == "skip") {
		return nil, 0, false, false
	}
	mt, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || !p.types[mt] {
		return nil, 0, false, false
	}
	request := direction == "request"
	where := "body"
	if !request {
		where = "response_body"
	}
	stream := func(src io.Reader) (io.ReadCloser, int64, bool, bool) {
		if p.Oversize == "skip" {
			return nil, 0, false, false
		}
		var r io.ReadCloser = struct {
			io.Reader
			io.Closer
		}{src, rc}
		if enc != "" {
			d, err := decoder(enc, src)
			if err != nil {
				return nil, 0, false, false
			}
			r = struct {
				io.Reader
				io.Closer
			}{d, rc}
		}
		return &streamScanner{src: r, in: in, direction: direction, where: where, mask: mask, block: p.Action == "block"}, -1, enc != "", mask
	}
	if length > p.MaxBytes {
		return stream(rc)
	}
	raw, whole, rest, err := buffer(rc, p.MaxBytes)
	if err != nil {
		return io.NopCloser(bytes.NewReader(raw)), int64(len(raw)), false, false
	}
	if !whole {
		return stream(rest)
	}
	text := raw
	if enc != "" {
		decoded, fits, derr := decode(enc, raw, p.MaxDecodedBytes)
		switch {
		case derr != nil:
			return io.NopCloser(bytes.NewReader(raw)), int64(len(raw)), false, false
		case !fits:
			return stream(bytes.NewReader(raw))
		}
		text = decoded
	}
	scanned, f := in.g.scanText(string(text), request, mask)
	in.record(where, f)
	if mask && f.n > 0 {
		return io.NopCloser(strings.NewReader(scanned)), int64(len(scanned)), enc != "", true
	}
	return io.NopCloser(bytes.NewReader(raw)), int64(len(raw)), false, false
}

// outcome counts what happened to a message with findings.
func (in *instance) outcome(direction string, found int, masked bool) {
	switch {
	case found == 0:
	case masked:
		countAction(direction, "masked")
	default:
		countAction(direction, "logged")
	}
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	p := in.g.cfg.Request
	if p == nil {
		return filter.Continue
	}
	mask := p.Action == "mask"
	if p.scan["query"] && r.URL.RawQuery != "" {
		_, f := in.g.scanText(r.URL.RawQuery, true, false)
		if dq, err := url.QueryUnescape(r.URL.RawQuery); err == nil && dq != r.URL.RawQuery {
			_, f2 := in.g.scanText(dq, true, false)
			if f2.n > f.n {
				f = f2
			}
		}
		// Parameter names that carry credentials.
		for _, d := range in.g.detectors {
			if !d.queryNames {
				continue
			}
			for name, vals := range r.URL.Query() {
				if d.re.MatchString(name) && len(vals) > 0 && vals[0] != "" {
					f.kinds[d.name]++
					f.n++
				}
			}
		}
		in.record("query", f)
	}
	if p.scan["headers"] {
		in.scanHeaders(r.Header, p, true, mask)
	}
	streamed := false
	if p.scan["body"] && r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0 {
		out, n, plain, masked := in.body("request", p, r.Header, r.Body, r.ContentLength, mask)
		if out != nil {
			r.Body = out
			streamed = n < 0
			if masked || plain || streamed {
				r.ContentLength = n
				if n < 0 {
					r.Header.Del("Content-Length")
				} else {
					r.Header.Set("Content-Length", strconv.FormatInt(n, 10))
				}
			}
			if plain {
				r.Header.Del("Content-Encoding")
			}
		}
	}
	count := in.total()
	if count == 0 || count < in.g.cfg.MinFindings {
		if !streamed {
			in.outcome("request", count, false)
		}
		return filter.Continue
	}
	if p.Action == "block" {
		countAction("request", "blocked")
		return in.deny(in.g.cfg.BlockStatus, "request")
	}
	in.outcome("request", count, mask)
	return filter.Continue
}

func (in *instance) Response(resp *http.Response) filter.Verdict {
	p := in.g.cfg.Response
	if p == nil {
		return filter.Continue
	}
	before := in.total()
	mask := p.Action == "mask"
	if p.scan["headers"] {
		in.scanHeaders(resp.Header, p, false, mask)
	}
	streamed := false
	if p.scan["body"] && resp.Body != nil && resp.Body != http.NoBody {
		out, n, plain, masked := in.body("response", p, resp.Header, resp.Body, resp.ContentLength, mask)
		if out != nil {
			resp.Body = out
			streamed = n < 0
			if masked || plain || streamed {
				resp.ContentLength = n
				if n < 0 {
					resp.Header.Del("Content-Length")
				} else {
					resp.Header.Set("Content-Length", strconv.FormatInt(n, 10))
				}
				resp.Header.Del("ETag")
				resp.Header.Del("Content-MD5")
			}
			if plain {
				resp.Header.Del("Content-Encoding")
			}
		}
	}
	found := in.total() - before
	if found == 0 || found < in.g.cfg.MinFindings {
		if !streamed {
			in.outcome("response", found, false)
		}
		return filter.Continue
	}
	if p.Action == "block" {
		countAction("response", "blocked")
		return in.deny(in.g.cfg.BlockStatus, "response")
	}
	in.outcome("response", found, mask)
	return filter.Continue
}

// scanHeaders scans header values, masking in place when asked.
func (in *instance) scanHeaders(h http.Header, p *Phase, request, mask bool) {
	total := findings{kinds: map[string]int{}}
	for name, vals := range h {
		if p.ignore[name] {
			continue
		}
		for i, v := range vals {
			out, f := in.g.scanText(v, request, mask)
			if f.n == 0 {
				continue
			}
			total.n += f.n
			for k, n := range f.kinds {
				total.kinds[k] += n
			}
			if mask {
				vals[i] = out
			}
		}
	}
	where := "headers"
	if !request {
		where = "response_headers"
	}
	in.record(where, total)
}

func (in *instance) deny(status int, phase string) filter.Verdict {
	kinds := in.kindList()
	msg := map[string]any{"error": "sensitive data refused", "phase": phase, "kinds": kinds}
	body, _ := json.Marshal(msg)
	resp := &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))} //nolint:bodyclose // sent by the data plane
	return filter.Verdict{Deny: true, Status: status, Reason: "sensitive_data", Detail: phase + ":" + strings.Join(kinds, ","), Response: resp,
		Attrs: []any{"sensitive_types", kinds, "sensitive_count", in.count, "sensitive_where", in.whereList()}}
}

func (in *instance) kindList() []string {
	out := make([]string, 0, len(in.kinds))
	for k := range in.kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (in *instance) whereList() []string {
	out := make([]string, 0, len(in.where))
	for k := range in.where {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (in *instance) End() []any {
	if in.count == 0 {
		return nil
	}
	return []any{"sensitive_types", strings.Join(in.kindList(), ","), "sensitive_count", in.count, "sensitive_where", strings.Join(in.whereList(), ",")}
}

// buffer reads up to limit+1 bytes; it returns the bytes, whether the
// whole body fit, and a replaying reader when it did not.
func buffer(rc io.ReadCloser, limit int64) ([]byte, bool, io.ReadCloser, error) {
	buf, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return buf, false, rc, err
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

func init() {
	filter.Register(filter.Kind{
		Name:        "sensitive_data",
		Description: "detection of payment cards, identity numbers, IBANs, e-mail addresses, tokens, keys and secrets in requests and responses, with log, mask or block per direction",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			g, err := parse(opts)
			if err != nil {
				return nil, err
			}
			g.name = name
			return g, nil
		},
	})
}
