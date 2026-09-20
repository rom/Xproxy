package waf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/jsonschema"
	"github.com/rom/xproxy/internal/netutil"
)

// bodySchema is one compiled json_schemas entry of a profile.
type bodySchema struct {
	name     string
	paths    []string
	methods  map[string]bool
	required bool
	v        *jsonschema.Validator
	root     map[string]any
}

// maxSchemaBytes bounds a schema document.
const maxSchemaBytes = 8 << 20

func loadSchemas(list []config.WAFJSONSchema) ([]*bodySchema, error) {
	out := make([]*bodySchema, 0, len(list))
	for i := range list {
		c := &list[i]
		doc, err := jsonschema.LoadDocument(c.SchemaFile, maxSchemaBytes)
		if err != nil {
			return nil, fmt.Errorf("json_schemas %s: %w", c.Name, err)
		}
		s := &bodySchema{name: c.Name, paths: c.Paths, methods: map[string]bool{}, required: c.Required, v: jsonschema.New(doc), root: doc}
		for _, m := range c.Methods {
			s.methods[m] = true
		}
		out = append(out, s)
	}
	return out, nil
}

// match returns the first schema bound to the request's method and path.
func matchSchema(schemas []*bodySchema, method, path string) *bodySchema {
	for _, s := range schemas {
		if !s.methods[method] {
			continue
		}
		for _, p := range s.paths {
			if strings.HasPrefix(path, p) {
				return s
			}
		}
	}
	return nil
}

// schemaResult is what a schema check found.
type schemaResult struct {
	// issue is the first problem ("" when the body validated); status is
	// the response for a denial.
	issue  string
	status int
	issues []jsonschema.Issue
}

// errBodyTooLarge marks a body over the WAF request body limit.
var errBodyTooLarge = errors.New("body exceeds limit")

// check validates a JSON body against s. It buffers the body (bounded by
// limit) so that the rules can read it afterwards. A nil result means
// the body validated or the request carries no JSON body and the schema
// is not required.
func (s *bodySchema) check(r *http.Request, limit int64) (*schemaResult, error) {
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	if !hasBody {
		if s.required {
			return &schemaResult{issue: "body is required", status: http.StatusBadRequest}, nil
		}
		return nil, nil
	}
	ct := netutil.MediaType(r.Header.Get("Content-Type"))
	if !strings.HasSuffix(ct, "/json") && !strings.HasSuffix(ct, "+json") {
		if s.required {
			return &schemaResult{issue: "body must be JSON", status: http.StatusUnsupportedMediaType}, nil
		}
		return nil, nil
	}
	if r.ContentLength > limit {
		return nil, errBodyTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	value, err := jsonschema.Decode(data)
	if err != nil {
		return &schemaResult{issue: "body " + err.Error(), status: http.StatusBadRequest}, nil
	}
	rep := &jsonschema.Report{}
	if s.v.Validate(s.root, value, "body", rep, 0) {
		return nil, nil
	}
	first := rep.Issues[0]
	return &schemaResult{issue: first.Path + " " + first.Msg, status: http.StatusBadRequest, issues: rep.Issues}, nil
}

// response renders the denial the client sees.
func (res *schemaResult) response(name string) *http.Response {
	msg := map[string]any{"error": "request body does not match the schema", "schema": name}
	if len(res.issues) > 0 {
		msg["details"] = res.issues
	} else {
		msg["details"] = []jsonschema.Issue{{Path: "body", Msg: res.issue}}
	}
	body, _ := json.Marshal(msg)
	return &http.Response{StatusCode: res.status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

// verdict is the denial for a schema violation in block mode.
func (res *schemaResult) verdict(name string, attrs []any) filter.Verdict {
	resp := res.response(name) //nolint:bodyclose // sent to the client by the data plane
	return filter.Verdict{Deny: true, Status: res.status, Reason: "waf", Detail: "json_schema:" + name + ":" + res.issue,
		Attrs: attrs, Response: resp}
}
