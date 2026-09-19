// Package jsonschema evaluates JSON values against the subset of JSON
// Schema that OpenAPI 3.0 and 3.1 documents use: types, enums and
// constants, string lengths, patterns and formats, numeric bounds, array
// and object bounds, properties, pattern and additional properties,
// allOf/anyOf/oneOf/not and local $ref pointers. Keywords it does not
// know are ignored, as the specification prescribes. The openapi filter
// and the WAF's JSON body schemas share it.
package jsonschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Schema is one resolved schema node.
type Schema struct {
	// Raw is the node's keywords.
	Raw map[string]any
	ref *Schema // resolved $ref, when the node is a reference
}

// Validator validates values against the schemas of one document with a
// bounded regexp cache and a depth limit. It is safe for concurrent use
// once built.
type Validator struct {
	spec  map[string]any
	reMu  sync.Mutex
	res   map[string]*regexp.Regexp
	cache map[string]*Schema
}

const (
	// MaxErrors bounds the issues one Report collects.
	MaxErrors = 20
	maxDepth  = 64
)

// New returns a validator whose local references ($ref "#/...") resolve
// inside doc.
func New(doc map[string]any) *Validator {
	return &Validator{spec: doc, res: map[string]*regexp.Regexp{}, cache: map[string]*Schema{}}
}

// Resolve follows local references (#/components/schemas/Name).
func (v *Validator) Resolve(node any) *Schema {
	m, ok := node.(map[string]any)
	if !ok {
		if b, ok := node.(bool); ok {
			if b {
				return &Schema{Raw: map[string]any{}}
			}
			return &Schema{Raw: map[string]any{"not": map[string]any{}}}
		}
		return &Schema{Raw: map[string]any{}}
	}
	ref, _ := m["$ref"].(string)
	if ref == "" {
		return &Schema{Raw: m}
	}
	if s, ok := v.cache[ref]; ok {
		return s
	}
	s := &Schema{Raw: map[string]any{}}
	v.cache[ref] = s // guards cycles
	target := v.lookup(ref)
	if target != nil {
		resolved := v.Resolve(target)
		s.Raw, s.ref = resolved.Raw, resolved.ref
	}
	return s
}

// lookup returns the node a local JSON pointer names.
func (v *Validator) lookup(ref string) any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = v.spec
	for _, part := range strings.Split(ref[2:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		part, _ = url.PathUnescape(part)
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

// Issue is one validation problem.
type Issue struct {
	Path string `json:"path"`
	Msg  string `json:"message"`
}

// Report collects the issues of one validation, at most MaxErrors.
type Report struct {
	Issues []Issue
}

// Add records an issue and returns false, so that a check can return
// its result in one expression.
func (r *Report) Add(path, format string, args ...any) bool {
	if len(r.Issues) < MaxErrors {
		r.Issues = append(r.Issues, Issue{Path: path, Msg: fmt.Sprintf(format, args...)})
	}
	return false
}

// Validate checks value against the schema node (a map, a boolean schema
// or a $ref) and appends problems to rep, whose paths start at path.
// value must come from Decode or Jsonify (json.Number numbers). depth is
// the current nesting, 0 at the top.
func (v *Validator) Validate(node any, value any, path string, rep *Report, depth int) bool {
	if depth > maxDepth {
		return rep.Add(path, "nesting deeper than %d", maxDepth)
	}
	s := v.Resolve(node)
	raw := s.Raw
	ok := true
	if all, has := raw["allOf"].([]any); has {
		for _, sub := range all {
			ok = v.Validate(sub, value, path, rep, depth+1) && ok
		}
	}
	if any_, has := raw["anyOf"].([]any); has {
		matched := false
		for _, sub := range any_ {
			if v.Validate(sub, value, path, &Report{}, depth+1) {
				matched = true
				break
			}
		}
		if !matched {
			ok = rep.Add(path, "matches none of the alternatives")
		}
	}
	if one, has := raw["oneOf"].([]any); has {
		n := 0
		for _, sub := range one {
			if v.Validate(sub, value, path, &Report{}, depth+1) {
				n++
			}
		}
		if n != 1 {
			ok = rep.Add(path, "matches %d alternatives, expected exactly one", n)
		}
	}
	if not, has := raw["not"]; has {
		if v.Validate(not, value, path, &Report{}, depth+1) {
			ok = rep.Add(path, "matches a forbidden schema")
		}
	}
	if value == nil {
		if nullable, _ := raw["nullable"].(bool); nullable || TypeAllows(raw["type"], "null") || raw["type"] == nil && raw["enum"] == nil {
			return ok
		}
		return rep.Add(path, "must not be null")
	}
	if e, has := raw["enum"].([]any); has {
		found := false
		for _, x := range e {
			if jsonEqual(x, value) {
				found = true
				break
			}
		}
		if !found {
			ok = rep.Add(path, "is not one of the allowed values")
		}
	}
	if c, has := raw["const"]; has && !jsonEqual(c, value) {
		ok = rep.Add(path, "must equal the constant")
	}
	switch x := value.(type) {
	case string:
		if raw["type"] != nil && !TypeAllows(raw["type"], "string") {
			return rep.Add(path, "must be %s, got string", typeName(raw["type"]))
		}
		ok = v.validateString(raw, x, path, rep) && ok
	case json.Number:
		f, _ := x.Float64()
		isInt := !strings.ContainsAny(x.String(), ".eE") || f == math.Trunc(f)
		numberOK := TypeAllows(raw["type"], "number") || TypeAllows(raw["type"], "integer") && isInt
		if raw["type"] != nil && !numberOK {
			return rep.Add(path, "must be %s, got number", typeName(raw["type"]))
		}
		ok = validateNumber(raw, f, path, rep) && ok
	case bool:
		if raw["type"] != nil && !TypeAllows(raw["type"], "boolean") {
			return rep.Add(path, "must be %s, got boolean", typeName(raw["type"]))
		}
	case []any:
		if raw["type"] != nil && !TypeAllows(raw["type"], "array") {
			return rep.Add(path, "must be %s, got array", typeName(raw["type"]))
		}
		ok = v.validateArray(raw, x, path, rep, depth) && ok
	case map[string]any:
		if raw["type"] != nil && !TypeAllows(raw["type"], "object") {
			return rep.Add(path, "must be %s, got object", typeName(raw["type"]))
		}
		ok = v.validateObject(raw, x, path, rep, depth) && ok
	}
	return ok
}

// TypeAllows reports whether a type keyword (a string or a list) admits
// want; "number" admits integers.
func TypeAllows(t any, want string) bool {
	switch x := t.(type) {
	case string:
		return x == want || x == "number" && want == "integer"
	case []any:
		for _, e := range x {
			if s, _ := e.(string); s == want || s == "number" && want == "integer" {
				return true
			}
		}
	}
	return false
}

func typeName(t any) string {
	switch x := t.(type) {
	case string:
		return x
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, " or ")
	}
	return "unknown"
}

func (v *Validator) validateString(raw map[string]any, s, path string, rep *Report) bool {
	ok := true
	n := len([]rune(s))
	if m, has := number(raw["minLength"]); has && float64(n) < m {
		ok = rep.Add(path, "shorter than %v characters", m)
	}
	if m, has := number(raw["maxLength"]); has && float64(n) > m {
		ok = rep.Add(path, "longer than %v characters", m)
	}
	if p, has := raw["pattern"].(string); has {
		re := v.regexp(p)
		if re != nil && !re.MatchString(s) {
			ok = rep.Add(path, "does not match the pattern")
		}
	}
	if f, has := raw["format"].(string); has && !formatOK(f, s) {
		ok = rep.Add(path, "is not a valid %s", f)
	}
	return ok
}

func (v *Validator) regexp(p string) *regexp.Regexp {
	v.reMu.Lock()
	defer v.reMu.Unlock()
	if re, ok := v.res[p]; ok {
		return re
	}
	re, err := regexp.Compile(p)
	if err != nil {
		re = nil
	}
	if len(v.res) < 4096 {
		v.res[p] = re
	}
	return re
}

func formatOK(format, s string) bool {
	switch format {
	case "date-time":
		_, err := time.Parse(time.RFC3339, s)
		return err == nil
	case "date":
		_, err := time.Parse("2006-01-02", s)
		return err == nil
	case "email":
		_, err := mail.ParseAddress(s)
		return err == nil && !strings.ContainsAny(s, " <>")
	case "uuid":
		if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return false
		}
		for i, c := range s {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				continue
			}
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
		return true
	case "ipv4":
		ip := net.ParseIP(s)
		return ip != nil && ip.To4() != nil && strings.Count(s, ".") == 3
	case "ipv6":
		ip := net.ParseIP(s)
		return ip != nil && strings.Contains(s, ":")
	case "uri":
		u, err := url.Parse(s)
		return err == nil && u.Scheme != ""
	case "hostname":
		return len(s) <= 253 && s != "" && !strings.ContainsAny(s, " /:")
	}
	return true // unknown formats are annotations
}

func validateNumber(raw map[string]any, f float64, path string, rep *Report) bool {
	ok := true
	if m, has := number(raw["minimum"]); has {
		if excl, _ := raw["exclusiveMinimum"].(bool); excl && f <= m || !excl && f < m {
			ok = rep.Add(path, "below the minimum %v", m)
		}
	}
	if m, has := number(raw["exclusiveMinimum"]); has && f <= m {
		ok = rep.Add(path, "not above %v", m)
	}
	if m, has := number(raw["maximum"]); has {
		if excl, _ := raw["exclusiveMaximum"].(bool); excl && f >= m || !excl && f > m {
			ok = rep.Add(path, "above the maximum %v", m)
		}
	}
	if m, has := number(raw["exclusiveMaximum"]); has && f >= m {
		ok = rep.Add(path, "not below %v", m)
	}
	if m, has := number(raw["multipleOf"]); has && m > 0 {
		if q := f / m; math.Abs(q-math.Round(q)) > 1e-9 {
			ok = rep.Add(path, "not a multiple of %v", m)
		}
	}
	return ok
}

func (v *Validator) validateArray(raw map[string]any, a []any, path string, rep *Report, depth int) bool {
	ok := true
	if m, has := number(raw["minItems"]); has && float64(len(a)) < m {
		ok = rep.Add(path, "fewer than %v items", m)
	}
	if m, has := number(raw["maxItems"]); has && float64(len(a)) > m {
		ok = rep.Add(path, "more than %v items", m)
	}
	if u, _ := raw["uniqueItems"].(bool); u {
		seen := map[string]bool{}
		for _, e := range a {
			b, _ := json.Marshal(e)
			if seen[string(b)] {
				ok = rep.Add(path, "items are not unique")
				break
			}
			seen[string(b)] = true
		}
	}
	if items, has := raw["items"]; has {
		for i, e := range a {
			ok = v.Validate(items, e, path+"["+strconv.Itoa(i)+"]", rep, depth+1) && ok
		}
	}
	return ok
}

func (v *Validator) validateObject(raw map[string]any, o map[string]any, path string, rep *Report, depth int) bool {
	ok := true
	props, _ := raw["properties"].(map[string]any)
	if req, has := raw["required"].([]any); has {
		for _, r := range req {
			name, _ := r.(string)
			if _, present := o[name]; !present {
				ok = rep.Add(joinPath(path, name), "is required")
			}
		}
	}
	if m, has := number(raw["minProperties"]); has && float64(len(o)) < m {
		ok = rep.Add(path, "fewer than %v properties", m)
	}
	if m, has := number(raw["maxProperties"]); has && float64(len(o)) > m {
		ok = rep.Add(path, "more than %v properties", m)
	}
	var patterns map[string]any
	patterns, _ = raw["patternProperties"].(map[string]any)
	// Properties are visited in name order so that the first reported
	// issue, which names the denial, is stable.
	names := make([]string, 0, len(o))
	for name := range o {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		val := o[name]
		if sub, has := props[name]; has {
			ok = v.Validate(sub, val, joinPath(path, name), rep, depth+1) && ok
			continue
		}
		matched := false
		for p, sub := range patterns {
			if re := v.regexp(p); re != nil && re.MatchString(name) {
				matched = true
				ok = v.Validate(sub, val, joinPath(path, name), rep, depth+1) && ok
			}
		}
		if matched {
			continue
		}
		switch ap := raw["additionalProperties"].(type) {
		case bool:
			if !ap {
				ok = rep.Add(joinPath(path, name), "is not allowed")
			}
		case map[string]any:
			ok = v.Validate(ap, val, joinPath(path, name), rep, depth+1) && ok
		}
	}
	return ok
}

func joinPath(base, name string) string {
	if base == "" {
		return name
	}
	return base + "." + name
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

func jsonEqual(a, b any) bool {
	if an, ok := a.(json.Number); ok {
		if bn, ok := b.(json.Number); ok {
			af, _ := an.Float64()
			bf, _ := bn.Float64()
			return af == bf
		}
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

// Coerce turns a parameter string into the JSON value its schema
// expects, so query and header parameters validate like body fields.
func Coerce(raw map[string]any, s string) any {
	switch {
	case TypeAllows(raw["type"], "integer") || TypeAllows(raw["type"], "number"):
		if _, err := strconv.ParseFloat(s, 64); err == nil {
			return json.Number(s)
		}
	case TypeAllows(raw["type"], "boolean"):
		if s == "true" {
			return true
		}
		if s == "false" {
			return false
		}
	case TypeAllows(raw["type"], "array"):
		parts := strings.Split(s, ",")
		out := make([]any, 0, len(parts))
		items, _ := raw["items"].(map[string]any)
		for _, p := range parts {
			if items != nil {
				out = append(out, Coerce(items, p))
			} else {
				out = append(out, p)
			}
		}
		return out
	}
	return s
}

// Decode parses one JSON document with numbers kept as json.Number; it
// rejects trailing data.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, errors.New("is not valid JSON")
	}
	if dec.More() {
		return nil, errors.New("has trailing data")
	}
	return value, nil
}

// Jsonify converts YAML decoded values to the shapes json produces
// (string keys, json.Number numbers) so one validator serves both.
func Jsonify(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = Jsonify(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = Jsonify(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = Jsonify(val)
		}
		return out
	case int:
		return json.Number(fmt.Sprint(x))
	case int64:
		return json.Number(fmt.Sprint(x))
	case float64:
		return json.Number(fmt.Sprint(x))
	}
	return v
}

// LoadDocument reads a JSON or YAML document of at most maxBytes into
// the shapes the validator expects.
func LoadDocument(path string, maxBytes int64) (map[string]any, error) {
	data, err := os.ReadFile(path) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxBytes)
	}
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	m, ok := Jsonify(doc).(map[string]any)
	if !ok {
		return nil, errors.New("not a document")
	}
	return m, nil
}
