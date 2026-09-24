// Package xmlguard is a built-in filter kind that decides whether an XML
// request body is one the application should see.
//
// The WAF reads bodies as text and the OpenAPI filter validates JSON, and
// between them sits every XML and SOAP API with none of it. XML is also the
// format with the oldest and most reliable parser attacks -- external
// entities that read files off the machine or make requests from inside the
// network, entity expansion that turns a kilobyte into gigabytes, parameter
// entity loops -- and all of them arrive as a document type declaration or
// an entity reference in the body. A gateway cannot know how the
// application's parser is configured (the defaults of most XML libraries
// were unsafe for years), so it refuses the shapes those attacks need
// before that parser sees them.
//
//	filters:
//	  - name: soap
//	    kind: xml_guard
//	    options:
//	      require_root: Envelope
//	      require_root_namespace: http://schemas.xmlsoap.org/soap/envelope/
//	      max_bytes: 262144
//	      max_depth: 32
//
// What it does not do is validate against a schema. XSD is a language with
// its own parser, its own imports and its own denial-of-service history,
// and a gateway that fetched and interpreted one would be adding a larger
// attack surface than it removed. `require_root`, `require_root_namespace`,
// `allow_elements` and `deny_elements` are a positive model of the document
// shape without a schema language in the middle; anything past that belongs
// in the application, which has the schema already.
package xmlguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/xmlsafe"
)

// Config is the options schema.
type Config struct {
	// ContentTypes are the media types this filter reads. The default is
	// every XML one: application/xml, text/xml, application/soap+xml and
	// anything ending in +xml.
	ContentTypes []string `json:"content_types"`
	// Methods are the methods with a body worth reading. Default POST,
	// PUT, PATCH.
	Methods []string `json:"methods"`
	// MaxBytes bounds the document. A larger body is refused rather than
	// passed uninspected: an XML API with megabyte requests is one where
	// the bound is the setting to change, not the inspection to skip.
	MaxBytes int `json:"max_bytes"`
	// The parser bounds. Each has a default a hand-written request stays
	// well inside.
	MaxDepth      int `json:"max_depth"`
	MaxElements   int `json:"max_elements"`
	MaxAttributes int `json:"max_attributes"`
	MaxNameBytes  int `json:"max_name_bytes"`
	MaxTextBytes  int `json:"max_text_bytes"`
	// AllowCDATA permits CDATA sections; default true, because ordinary
	// XML APIs use them.
	AllowCDATA *bool `json:"allow_cdata"`
	// AllowComments permits comments; default true.
	AllowComments *bool `json:"allow_comments"`
	// AllowProcessingInstructions permits processing instructions beyond
	// the XML declaration; default false.
	AllowProcessingInstructions bool `json:"allow_processing_instructions"`
	// RequireRoot and RequireRootNamespace are the root element the
	// document must have.
	RequireRoot          string `json:"require_root"`
	RequireRootNamespace string `json:"require_root_namespace"`
	// AllowElements, when set, is every element name the document may
	// use. DenyElements is names it may not, whatever the allow list says.
	AllowElements []string `json:"allow_elements"`
	DenyElements  []string `json:"deny_elements"`
	// Status is the status a refusal answers with; 4xx only.
	Status int `json:"status"`
	// Reason is the deny reason in logs, counters and ban triggers;
	// default the filter's name.
	Reason string `json:"reason"`
	// Report only logs what it would have refused, for turning the filter
	// on in front of traffic nobody has read yet.
	Report bool `json:"report"`

	limits  xmlsafe.Limits
	methods map[string]bool
	types   []string
}

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	lim := xmlsafe.Default()
	set := func(name string, dst *int, v, minimum, maximum int) {
		if v == 0 {
			return
		}
		if v < minimum || v > maximum {
			errs = append(errs, fmt.Errorf("%s: must be between %d and %d", name, minimum, maximum))
			return
		}
		*dst = v
	}
	set("max_bytes", &lim.MaxBytes, c.MaxBytes, 64, 64<<20)
	set("max_depth", &lim.MaxDepth, c.MaxDepth, 1, 10000)
	set("max_elements", &lim.MaxElements, c.MaxElements, 1, 10_000_000)
	set("max_attributes", &lim.MaxAttributes, c.MaxAttributes, 1, 10000)
	set("max_name_bytes", &lim.MaxNameBytes, c.MaxNameBytes, 1, 65536)
	set("max_text_bytes", &lim.MaxTextBytes, c.MaxTextBytes, 1, 64<<20)
	if c.AllowCDATA != nil {
		lim.AllowCDATA = *c.AllowCDATA
	}
	if c.AllowComments != nil {
		lim.AllowComments = *c.AllowComments
	}
	lim.AllowProcessingInstructions = c.AllowProcessingInstructions
	lim.Root, lim.RootNamespace = c.RequireRoot, c.RequireRootNamespace
	if c.RequireRootNamespace != "" && c.RequireRoot == "" {
		errs = append(errs, errors.New("require_root_namespace: needs require_root; a namespace with no name allows any element of it"))
	}
	for _, name := range []string{c.RequireRoot} {
		if name != "" && !nameOK(name) {
			errs = append(errs, fmt.Errorf("require_root: %q is not an element name", name))
		}
	}
	if len(c.AllowElements) > 0 {
		lim.AllowElements = map[string]bool{}
		for _, name := range c.AllowElements {
			if !nameOK(name) {
				errs = append(errs, fmt.Errorf("allow_elements: %q is not an element name", name))
				continue
			}
			lim.AllowElements[name] = true
		}
		// A root the allow list does not contain is a policy that refuses
		// every document, which is a configuration mistake rather than a
		// decision.
		if c.RequireRoot != "" && !lim.AllowElements[c.RequireRoot] {
			errs = append(errs, errors.New("allow_elements: does not contain require_root, so every document would be refused"))
		}
	}
	if len(c.DenyElements) > 0 {
		lim.DenyElements = map[string]bool{}
		for _, name := range c.DenyElements {
			if !nameOK(name) {
				errs = append(errs, fmt.Errorf("deny_elements: %q is not an element name", name))
				continue
			}
			lim.DenyElements[name] = true
		}
	}
	c.limits = lim
	c.methods = map[string]bool{}
	if len(c.Methods) == 0 {
		c.Methods = []string{http.MethodPost, http.MethodPut, http.MethodPatch}
	}
	for _, m := range c.Methods {
		up := strings.ToUpper(m)
		switch up {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			c.methods[up] = true
		default:
			errs = append(errs, fmt.Errorf("methods: %q has no body worth reading", m))
		}
	}
	c.types = c.ContentTypes
	if len(c.types) == 0 {
		c.types = []string{"application/xml", "text/xml", "application/soap+xml", "+xml"}
	}
	for i, t := range c.types {
		c.types[i] = strings.ToLower(strings.TrimSpace(t))
		if c.types[i] == "" || strings.ContainsAny(c.types[i], " \r\n") {
			errs = append(errs, fmt.Errorf("content_types[%d]: %q is not a media type", i, t))
		}
	}
	if c.Status == 0 {
		c.Status = http.StatusBadRequest
	}
	if c.Status < 400 || c.Status > 499 {
		errs = append(errs, errors.New("status: must be a 4xx"))
	}
	return &c, errors.Join(errs...)
}

// nameOK is a local element name in the configuration: this is an operator
// naming an element, so it is checked rather than trusted.
func nameOK(s string) bool {
	if s == "" || len(s) > 256 || strings.ContainsAny(s, " \t\r\n<>&\"'/:") {
		return false
	}
	return true
}

type guard struct {
	name string
	cfg  *Config

	// counters
	Inspected, Refused, Reported, Skipped atomic.Uint64
}

func (g *guard) Name() string { return g.name }

func (g *guard) Begin(context.Context, *filter.Info) filter.Instance { return &instance{g: g} }

type instance struct {
	g     *guard
	attrs []any
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	g := in.g
	if !g.cfg.methods[r.Method] || !g.isXML(r.Header.Get("Content-Type")) {
		return filter.Continue
	}
	if r.Body == nil || r.Body == http.NoBody {
		return filter.Continue
	}
	// The body is read whole and replayed byte for byte: the application
	// receives exactly what the client sent, and the scan happens on the
	// same bytes rather than on a re-serialisation of them.
	// One byte over the bound, so an oversize body is *seen* to be
	// oversize: the scanner refuses it for its size rather than reading a
	// truncated document and calling it malformed. Nothing past the bound
	// is ever parsed either way.
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(g.cfg.limits.MaxBytes)+1))
	if err != nil {
		return g.deny("read", "the body could not be read")
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	g.Inspected.Add(1)
	if err := xmlsafe.Check(body, g.cfg.limits); err != nil {
		reason := string(xmlsafe.ReasonOf(err))
		if reason == "" {
			reason = "malformed"
		}
		if g.cfg.Report {
			g.Reported.Add(1)
			in.attrs = append(in.attrs, "xml_would_refuse", reason)
			return filter.Continue
		}
		g.Refused.Add(1)
		return g.deny(reason, err.Error())
	}
	return filter.Continue
}

// isXML decides whether this is a document to read. A charset or boundary
// parameter is ignored, and a suffix entry (+xml) matches any media type
// that ends in it, which is how the registry says an XML format is one.
func (g *guard) isXML(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return false
	}
	for _, want := range g.cfg.types {
		if strings.HasPrefix(want, "+") {
			if strings.HasSuffix(ct, want) {
				return true
			}
			continue
		}
		if ct == want {
			return true
		}
	}
	return false
}

func (g *guard) deny(detail, message string) filter.Verdict {
	reason := g.cfg.Reason
	if reason == "" {
		reason = g.name
	}
	return filter.Verdict{Deny: true, Status: g.cfg.Status, Reason: reason, Detail: "xml_" + detail,
		Attrs: []any{"xml_refusal", message}}
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any { return in.attrs }

// Status is the management view.
type Status struct {
	Inspected uint64 `json:"inspected"`
	Refused   uint64 `json:"refused"`
	Reported  uint64 `json:"reported"`
}

// Status reports the counters.
func (g *guard) Status() Status {
	return Status{Inspected: g.Inspected.Load(), Refused: g.Refused.Load(), Reported: g.Reported.Load()}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "xml_guard",
		Description: "Refuses XML request bodies that carry a document type declaration, an entity reference or more structure than the policy allows.",
		BuffersBody: true,
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, _ filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return &guard{name: name, cfg: c}, nil
		},
	})
}
