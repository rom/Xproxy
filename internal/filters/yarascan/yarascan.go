// Package yarascan is a built-in filter kind that applies YARA rules to
// request and response bodies.
//
//	filters:
//	  - name: uploads
//	    kind: yara
//	    options:
//	      rules_file: /etc/xproxy/rules/malware.yar   # or rules_dir
//	      scan: [request, response]                    # default both
//	      action: block                                # block (default) or log
//	      max_bytes: 4194304                           # scanned per body
//	      max_window: 262144
//	      content_types: ["application/octet-stream", "multipart/form-data"]
//
// Unlike the layer 4 scanner, a body here is buffered to max_bytes
// before it is forwarded, so a match can refuse the request rather than
// only record it. A body larger than the bound is scanned to the bound
// and then streamed on: the alternative is holding an arbitrary upload
// in memory, which is a worse failure than an unscanned tail, and the
// access log says which bodies were only partly scanned.
package yarascan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/yara"
)

// Config is the options schema.
type Config struct {
	RulesFile    string   `json:"rules_file"`
	RulesDir     string   `json:"rules_dir"`
	Scan         []string `json:"scan"`
	Action       string   `json:"action"`
	MaxBytes     int64    `json:"max_bytes"`
	MaxWindow    int      `json:"max_window"`
	ContentTypes []string `json:"content_types"`

	scan map[string]bool
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	switch {
	case c.RulesFile != "" && c.RulesDir != "":
		errs = append(errs, errors.New("set rules_file or rules_dir, not both"))
	case c.RulesFile == "" && c.RulesDir == "":
		errs = append(errs, errors.New("rules_file or rules_dir is required"))
	}
	if c.Action == "" {
		c.Action = "block"
	}
	if c.Action != "block" && c.Action != "log" {
		errs = append(errs, errors.New("action: must be block or log"))
	}
	if len(c.Scan) == 0 {
		c.Scan = []string{"request", "response"}
	}
	c.scan = map[string]bool{}
	for _, s := range c.Scan {
		if s != "request" && s != "response" {
			errs = append(errs, fmt.Errorf("scan: %q is not request or response", s))
			continue
		}
		c.scan[s] = true
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 4 << 20
	}
	if c.MaxBytes < 4096 || c.MaxBytes > 256<<20 {
		errs = append(errs, errors.New("max_bytes: must be 4096..268435456"))
	}
	if c.MaxWindow == 0 {
		c.MaxWindow = 256 << 10
	}
	if c.MaxWindow < 4096 || c.MaxWindow > 1<<24 {
		errs = append(errs, errors.New("max_window: must be 4096..16777216"))
	}
	for i, ct := range c.ContentTypes {
		if _, _, err := mime.ParseMediaType(ct); err != nil && !strings.HasSuffix(ct, "/*") {
			errs = append(errs, fmt.Errorf("content_types[%d]: %q is not a media type", i, ct))
		}
	}
	return &c, errors.Join(errs...)
}

type scanner struct {
	name  string
	cfg   *Config
	rules *yara.Rules
	log   *slog.Logger

	matched atomic.Uint64
	partial atomic.Uint64
}

func (s *scanner) Name() string { return s.name }

func (s *scanner) Begin(context.Context, *filter.Info) filter.Instance {
	return &instance{s: s}
}

type instance struct {
	s       *scanner
	hits    []string
	partial bool
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	if !in.s.cfg.scan["request"] || !in.s.wanted(r.Header.Get("Content-Type")) {
		return filter.Continue
	}
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return filter.Continue
	}
	body, rest, matches, partial, err := in.s.scan(r.Body)
	if err != nil {
		return filter.Verdict{Deny: true, Status: http.StatusBadRequest, Reason: in.s.name, Detail: "unreadable body"}
	}
	r.Body = rest
	if partial {
		in.partial = true
		in.s.partial.Add(1)
	}
	if len(matches) == 0 {
		return filter.Continue
	}
	return in.hit("request", matches, int64(len(body)))
}

func (in *instance) Response(resp *http.Response) filter.Verdict {
	if !in.s.cfg.scan["response"] || !in.s.wanted(resp.Header.Get("Content-Type")) {
		return filter.Continue
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		return filter.Continue
	}
	body, rest, matches, partial, err := in.s.scan(resp.Body)
	if err != nil {
		return filter.Verdict{Deny: true, Status: http.StatusBadGateway, Reason: in.s.name, Detail: "unreadable body"}
	}
	resp.Body = rest
	if partial {
		in.partial = true
		in.s.partial.Add(1)
	}
	if len(matches) == 0 {
		return filter.Continue
	}
	return in.hit("response", matches, int64(len(body)))
}

// hit turns matches into a verdict. Under action: log the bytes go on
// their way and only the record is made, which is how a rule set is
// tried out before it decides anything.
func (in *instance) hit(direction string, matches []yara.Match, size int64) filter.Verdict {
	s := in.s
	s.matched.Add(1)
	names := make([]string, 0, len(matches))
	tags := map[string]bool{}
	for _, m := range matches {
		names = append(names, m.Rule)
		for _, t := range m.Tags {
			tags[t] = true
		}
	}
	in.hits = append(in.hits, names...)
	tagList := make([]string, 0, len(tags))
	for t := range tags {
		tagList = append(tagList, t)
	}
	attrs := []any{"direction", direction, "rules", strings.Join(names, ","), "bytes", size}
	if len(tagList) > 0 {
		attrs = append(attrs, "tags", strings.Join(tagList, ","))
	}
	if s.cfg.Action == "log" {
		s.log.Warn("yara match", "filter", s.name, "direction", direction,
			"rules", strings.Join(names, ","))
		return filter.Continue
	}
	status := http.StatusForbidden
	if direction == "response" {
		// The body is refused on the way back, so the client gets a
		// gateway error rather than a page that says it was forbidden
		// from asking.
		status = http.StatusBadGateway
	}
	return filter.Verdict{Deny: true, Status: status, Reason: s.name,
		Detail: "yara:" + strings.Join(names, ","), Attrs: attrs}
}

func (in *instance) End() []any {
	if len(in.hits) == 0 && !in.partial {
		return nil
	}
	out := []any{}
	if len(in.hits) > 0 {
		out = append(out, "yara", strings.Join(in.hits, ","))
	}
	if in.partial {
		out = append(out, "yara_partial", true)
	}
	return out
}

// wanted applies the content_types filter. An empty list scans
// everything, which is the honest default: the type is what the sender
// claims, not what the bytes are.
func (s *scanner) wanted(contentType string) bool {
	if len(s.cfg.ContentTypes) == 0 {
		return true
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.TrimSpace(strings.ToLower(contentType))
	}
	for _, want := range s.cfg.ContentTypes {
		w := strings.ToLower(want)
		if strings.HasSuffix(w, "/*") {
			if strings.HasPrefix(mt, strings.TrimSuffix(w, "*")) {
				return true
			}
			continue
		}
		if mt == w {
			return true
		}
	}
	return false
}

// scan reads up to max_bytes, scans them, and returns a body that
// replays what was read followed by whatever is left.
func (s *scanner) scan(rc io.ReadCloser) (head []byte, rest io.ReadCloser, matches []yara.Match, partial bool, err error) {
	head, err = io.ReadAll(io.LimitReader(rc, s.cfg.MaxBytes))
	if err != nil {
		_ = rc.Close()
		return nil, nil, nil, false, err
	}
	// One more byte says whether there was more; it is put back.
	var extra [1]byte
	n, rerr := io.ReadFull(rc, extra[:])
	partial = n > 0
	sc := s.rules.NewScanner(s.cfg.MaxWindow)
	_, _ = sc.Write(head)
	matches = sc.Close()
	tail := io.Reader(rc)
	if n > 0 {
		tail = io.MultiReader(bytes.NewReader(extra[:n]), rc)
	} else if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
		_ = rc.Close()
		return nil, nil, nil, false, rerr
	}
	return head, &joined{Reader: io.MultiReader(bytes.NewReader(head), tail), closer: rc}, matches, partial, nil
}

// joined is the replayed head plus the rest, closing the original.
type joined struct {
	io.Reader
	closer io.Closer
}

func (j *joined) Close() error { return j.closer.Close() }

func init() {
	filter.Register(filter.Kind{
		Name:        "yara",
		Description: "YARA rules over request and response bodies.",
		Validate: func(opts filter.Options) error {
			c, err := parse(opts)
			if err != nil {
				return err
			}
			_, err = load(c)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			rules, err := load(c)
			if err != nil {
				return nil, err
			}
			return &scanner{name: name, cfg: c, rules: rules, log: env.Log}, nil
		},
	})
}

func load(c *Config) (*yara.Rules, error) {
	if c.RulesDir != "" {
		return yara.LoadDir(c.RulesDir)
	}
	return yara.LoadFile(c.RulesFile)
}
