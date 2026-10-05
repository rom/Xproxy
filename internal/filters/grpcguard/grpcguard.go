// Package grpcguard is a built-in filter kind that reads gRPC messages
// rather than passing them through.
//
//	filters:
//	  - name: rpc
//	    kind: grpc_guard
//	    options:
//	      max_message_bytes: 4194304   # one message, not the whole stream
//	      max_messages: 0              # messages in one request; 0 is no bound
//	      max_depth: 16                # how deeply messages may nest
//	      max_fields: 2000             # fields at every level together
//	      allow_compressed: true       # a compressed message is one this cannot read
//	      deny_patterns: ["(?i)BEGIN (RSA )?PRIVATE KEY"]
//	      max_scan_bytes: 1048576      # of one request, walked
//	      action: block                # block (default) or log
//
// A proxy that routes gRPC by its path has read the envelope. The
// messages are length-prefixed frames of protobuf inside the body, and
// without reading them the proxy cannot say how large one message is —
// only how large the whole body is — cannot notice a stream that stops
// in the middle of a frame, and cannot see a message nested a thousand
// deep, which costs the backend's parser far more than it costs the
// sender to write.
//
// No schema is used, deliberately. A schema has to be kept in step with
// the service, and a check that is only as current as its schema is a
// check that quietly stops applying the week somebody adds a field. The
// protobuf wire format carries the field number and the wire type, which
// is enough for every bound here.
//
// What it does not do is understand the fields. deny_patterns are
// matched against the strings found in a message, not against a named
// field, so they are the blunt instrument they look like.
package grpcguard

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"context"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/grpcmsg"
)

// Config is the options schema.
type Config struct {
	MaxMessageBytes int      `json:"max_message_bytes"`
	MaxMessages     int      `json:"max_messages"`
	MaxDepth        int      `json:"max_depth"`
	MaxFields       int      `json:"max_fields"`
	AllowCompressed *bool    `json:"allow_compressed"`
	DenyPatterns    []string `json:"deny_patterns"`
	MaxScanBytes    int      `json:"max_scan_bytes"`
	MaxStringBytes  int      `json:"max_string_bytes"`
	Action          string   `json:"action"`

	deny []*regexp.Regexp
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.Action == "" {
		c.Action = "block"
	}
	if c.Action != "block" && c.Action != "log" {
		errs = append(errs, errors.New("action: must be block or log"))
	}
	if c.MaxMessageBytes == 0 {
		// What grpc-go defaults its receive limit to, which is the
		// number the backend is already living with.
		c.MaxMessageBytes = 4 << 20
	}
	if c.MaxMessageBytes < 1024 || c.MaxMessageBytes > 256<<20 {
		errs = append(errs, errors.New("max_message_bytes: must be 1024..268435456"))
	}
	if c.MaxMessages < 0 {
		errs = append(errs, errors.New("max_messages: must not be negative"))
	}
	if c.MaxDepth == 0 {
		c.MaxDepth = 16
	}
	if c.MaxDepth < 1 || c.MaxDepth > 256 {
		errs = append(errs, errors.New("max_depth: must be 1..256"))
	}
	if c.MaxFields == 0 {
		c.MaxFields = 2000
	}
	if c.MaxFields < 1 || c.MaxFields > 1<<20 {
		errs = append(errs, errors.New("max_fields: must be 1..1048576"))
	}
	if c.MaxScanBytes == 0 {
		c.MaxScanBytes = 1 << 20
	}
	if c.MaxScanBytes < 1024 || c.MaxScanBytes > 64<<20 {
		errs = append(errs, errors.New("max_scan_bytes: must be 1024..67108864"))
	}
	if c.MaxStringBytes == 0 {
		c.MaxStringBytes = 4096
	}
	if c.MaxStringBytes < 16 || c.MaxStringBytes > 1<<20 {
		errs = append(errs, errors.New("max_string_bytes: must be 16..1048576"))
	}
	if c.AllowCompressed == nil {
		t := true
		c.AllowCompressed = &t
	}
	for i, p := range c.DenyPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("deny_patterns[%d]: %w", i, err))
			continue
		}
		c.deny = append(c.deny, re)
	}
	if len(c.deny) > 0 && *c.AllowCompressed {
		// Saying so beats finding out: a compressed message is bytes
		// this filter does not decompress, so the patterns simply do
		// not run over it.
		errs = append(errs, errors.New("deny_patterns with allow_compressed: true, so a compressed message goes past them unread; set allow_compressed: false"))
	}
	return &c, errors.Join(errs...)
}

type guard struct {
	name string
	cfg  *Config
	log  *slog.Logger

	refused atomic.Uint64
	partial atomic.Uint64
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(context.Context, *filter.Info) filter.Instance {
	return &instance{g: g}
}

type instance struct {
	g      *guard
	report grpcmsg.Report
	msgs   int
	// partial says the body was longer than max_scan_bytes, so the
	// tail went past unread.
	partial bool
}

// isGRPC reports a body this filter reads: gRPC, or the gRPC-web forms of it.
//
// gRPC-web is included because the translation to gRPC happens in the reverse
// proxy's rewrite hook, which runs *after* the filter chain -- so a route with
// `grpc: {web: true}` had this filter see `application/grpc-web+proto`, return
// Continue, and the upstream nevertheless receive plain gRPC with the same
// frames. Every bound and content rule here was skipped by one header.
func isGRPC(ct string) bool {
	base := ct
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	switch {
	case base == "application/grpc", strings.HasPrefix(base, "application/grpc+"):
		return true
	case base == "application/grpc-web", strings.HasPrefix(base, "application/grpc-web+"):
		return true
	case base == "application/grpc-web-text", strings.HasPrefix(base, "application/grpc-web-text+"):
		return true
	}
	return false
}

// isGRPCWebText reports the base64 form, whose frames have to be decoded before
// they can be read as frames at all.
func isGRPCWebText(ct string) bool {
	base := ct
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	return base == "application/grpc-web-text" ||
		strings.HasPrefix(base, "application/grpc-web-text+")
}

// decodeWebText decodes what was read of a grpc-web-text body.
//
// Clients send one padded base64 chunk per frame, so the stream is split at the
// padding and each chunk decoded on its own -- the same shape the data plane's
// own decoder uses. A chunk that does not decode leaves the rest alone: this is a
// prefix of a stream, so the last chunk is usually incomplete, and the frames
// recovered before it are still worth inspecting.
func decodeWebText(head []byte) []byte {
	out := make([]byte, 0, len(head))
	for len(head) > 0 {
		end := len(head)
		if i := bytes.IndexByte(head, '='); i >= 0 {
			// Consume the padding too: one chunk is "...==" or "...=".
			end = i + 1
			for end < len(head) && head[end] == '=' {
				end++
			}
		}
		chunk := head[:end]
		head = head[end:]
		dec, err := base64.StdEncoding.DecodeString(string(chunk))
		if err != nil {
			break
		}
		out = append(out, dec...)
	}
	return out
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	if !isGRPC(r.Header.Get("Content-Type")) {
		return filter.Continue
	}
	if r.Body == nil || r.Body == http.NoBody {
		return filter.Continue
	}
	cfg := in.g.cfg
	head := make([]byte, 0, 4096)
	buf := make([]byte, 32<<10)
	var partial bool
	for len(head) < cfg.MaxScanBytes {
		n, err := r.Body.Read(buf)
		if n > 0 {
			head = append(head, buf[:n]...)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				r.Body = replay(head, r.Body)
				return in.refuse(r, http.StatusBadRequest, "unreadable_body", err.Error())
			}
			break
		}
	}
	if len(head) >= cfg.MaxScanBytes {
		// Past the bound the rest of the stream is forwarded unread,
		// which is stated here rather than left to be noticed.
		partial = true
		in.partial = true
		in.g.partial.Add(1)
	}
	// The frames are inspected in the encoding the upstream will see them in.
	read := head
	if isGRPCWebText(r.Header.Get("Content-Type")) {
		read = decodeWebText(head)
	}
	v := in.inspect(read, partial)
	r.Body = replay(head, r.Body)
	if v.Deny {
		return in.deny(r, v)
	}
	return filter.Continue
}

// inspect walks what was read. It returns a verdict with the reason
// filled in; the caller turns it into a refusal or a record.
func (in *instance) inspect(head []byte, partial bool) filter.Verdict {
	cfg := in.g.cfg
	frames, rest, err := grpcmsg.SplitFrames(head, cfg.MaxMessageBytes)
	if err != nil {
		return filter.Verdict{Deny: true, Status: http.StatusRequestEntityTooLarge,
			Reason: "message_too_large", Detail: err.Error()}
	}
	if len(rest) > 0 && !partial {
		// The body ended inside a frame. A client that finished sends
		// whole frames; one that stopped in the middle of a length it
		// declared is a client whose message nobody has.
		return filter.Verdict{Deny: true, Status: http.StatusBadRequest,
			Reason: "short_frame", Detail: grpcmsg.ErrShortFrame.Error()}
	}
	for _, f := range frames {
		in.msgs++
		if cfg.MaxMessages > 0 && in.msgs > cfg.MaxMessages {
			return filter.Verdict{Deny: true, Status: http.StatusRequestEntityTooLarge,
				Reason: "too_many_messages", Detail: strconv.Itoa(in.msgs)}
		}
		if f.Compressed {
			if !*cfg.AllowCompressed {
				return filter.Verdict{Deny: true, Status: http.StatusBadRequest,
					Reason: "compressed", Detail: "a compressed message is one this proxy cannot read"}
			}
			// Allowed, and not walked: there is nothing honest to say
			// about bytes that have not been decompressed.
			continue
		}
		var hit string
		rep, err := grpcmsg.Walk(f.Payload, grpcmsg.Limits{
			MaxDepth: cfg.MaxDepth, MaxFields: cfg.MaxFields, MaxStringBytes: cfg.MaxStringBytes,
		}, func(path []int32, s string) bool {
			for i, re := range cfg.deny {
				if re.MatchString(s) {
					hit = fmt.Sprintf("deny_patterns[%d] at %s", i, fieldPath(path))
					return false
				}
			}
			return true
		})
		in.report.Depth = max(in.report.Depth, rep.Depth)
		in.report.Fields += rep.Fields
		in.report.Strings += rep.Strings
		if hit != "" {
			return filter.Verdict{Deny: true, Status: http.StatusForbidden,
				Reason: "content", Detail: hit}
		}
		if err != nil {
			switch {
			case errors.Is(err, grpcmsg.ErrTooDeep):
				return filter.Verdict{Deny: true, Status: http.StatusBadRequest,
					Reason: "too_deep", Detail: err.Error()}
			case errors.Is(err, grpcmsg.ErrTooManyFields):
				return filter.Verdict{Deny: true, Status: http.StatusBadRequest,
					Reason: "too_many_fields", Detail: err.Error()}
			default:
				return filter.Verdict{Deny: true, Status: http.StatusBadRequest,
					Reason: "malformed", Detail: err.Error()}
			}
		}
	}
	return filter.Continue
}

// deny turns a verdict into a refusal, or into a record under
// action: log.
func (in *instance) deny(r *http.Request, v filter.Verdict) filter.Verdict {
	g := in.g
	g.refused.Add(1)
	svc, method, _ := grpcmsg.Method(r.URL.Path)
	if g.cfg.Action == "log" {
		g.log.Warn("grpc message refused (log only)", "filter", g.name,
			"service", svc, "method", method, "reason", v.Reason, "detail", v.Detail)
		return filter.Continue
	}
	g.log.Warn("grpc message refused", "filter", g.name,
		"service", svc, "method", method, "reason", v.Reason, "detail", v.Detail)
	v.Reason = g.name + ":" + v.Reason
	return v
}

func (in *instance) refuse(r *http.Request, status int, reason, detail string) filter.Verdict {
	return in.deny(r, filter.Verdict{Deny: true, Status: status, Reason: reason, Detail: detail})
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

// End adds what the walk found to the access line, so a route's shape
// is visible before anybody has to guess at a bound for it.
func (in *instance) End() []any {
	if in.msgs == 0 {
		return nil
	}
	out := []any{"grpc_messages", in.msgs, "grpc_depth", in.report.Depth,
		"grpc_fields", in.report.Fields}
	if in.partial {
		out = append(out, "grpc_partial", true)
	}
	return out
}

// fieldPath renders a field number path the way protoc reports one, so
// a refusal names somewhere a reader can look.
func fieldPath(path []int32) string {
	if len(path) == 0 {
		return "(root)"
	}
	parts := make([]string, len(path))
	for i, n := range path {
		parts[i] = strconv.Itoa(int(n))
	}
	return strings.Join(parts, ".")
}

// replay is the bytes that were read followed by whatever is left, so
// the request the backend receives is the request the client sent.
func replay(head []byte, rest io.ReadCloser) io.ReadCloser {
	return &joined{Reader: io.MultiReader(bytes.NewReader(head), rest), closer: rest}
}

type joined struct {
	io.Reader
	closer io.Closer
}

func (j *joined) Close() error { return j.closer.Close() }

func init() {
	filter.Register(filter.Kind{
		Name:        "grpc_guard",
		Description: "Reads gRPC messages: framing, per-message bounds and protobuf structure.",
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return &guard{name: name, cfg: c, log: env.Log}, nil
		},
	})
}
