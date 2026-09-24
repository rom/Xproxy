package openapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/rom/xproxy/internal/jsonschema"
)

// The shapes OpenAPI lets one parameter arrive in, and why reading them
// matters.
//
// A parameter is not always one string. An array may arrive as repeated
// names (`?ids=1&ids=2`), as one comma-separated value (`?ids=1,2`),
// pipe-separated (`?ids=1|2`) or space-separated; an object may arrive as
// bracketed names (`?filter[from]=x&filter[to]=y`). `style` and `explode`
// say which, and a validator that assumes one of them refuses every
// request in the others.
//
// That is a worse failure than not checking at all. The request was
// correct, the description said so, and the gateway refused it -- which
// is how a validating gateway gets taken out of the path. So the styles
// are read, and where two spellings of the same thing are both
// unambiguous, both are accepted.
const (
	styleForm      = "form"
	styleSimple    = "simple"
	styleSpace     = "spaceDelimited"
	stylePipe      = "pipeDelimited"
	styleDeep      = "deepObject"
	styleLabel     = "label"
	styleMatrix    = "matrix"
	maxDeepObjects = 200
)

// styleOf fills in the style and explode defaults OpenAPI gives a
// parameter by where it sits: form for query and cookie, simple for path
// and header, and explode true only for form.
func styleOf(m map[string]any, in string) (style string, explode bool) {
	style, _ = m["style"].(string)
	if style == "" {
		switch in {
		case "query", "cookie":
			style = styleForm
		default:
			style = styleSimple
		}
	}
	explode = style == styleForm
	if e, ok := m["explode"].(bool); ok {
		explode = e
	}
	return style, explode
}

// wants reports whether a parameter's schema declares this type.
func (p *parameter) wants(t string) bool {
	return p.schema != nil && jsonschema.TypeAllows(p.schema["type"], t)
}

// items is the schema of an array parameter's elements.
func (p *parameter) items(v *jsonschema.Validator) map[string]any {
	if p.schema == nil {
		return nil
	}
	if s := v.Resolve(p.schema["items"]); s != nil {
		return s.Raw
	}
	return nil
}

// values assembles what one parameter carries: one value for a declared
// array or object, and one value per occurrence for a scalar.
//
// A repeated scalar yields one value per occurrence on purpose. Everything
// behind a proxy reads `?limit=10&limit=999` differently -- PHP and Rails
// take the last, ASP.NET joins them with commas, Spring binds an array --
// so judging only one of them would leave the application reading a value
// nothing had checked.
func (in *instance) values(p parameter, r *http.Request, query url.Values, pathVals map[string]string) ([]any, bool) {
	v := in.api.v
	switch p.in {
	case "path":
		raw, has := pathVals[p.name]
		if !has {
			return nil, false
		}
		return in.one(p, raw, pathSeparator(p.style)), true
	case "query":
		if p.wants("object") && p.style == styleDeep {
			obj, has := deepObject(p, query, v)
			if !has {
				return nil, false
			}
			return []any{obj}, true
		}
		vals, has := query[p.name]
		if !has {
			return nil, false
		}
		return in.many(p, vals), true
	case "header":
		var vals []string
		for _, h := range r.Header.Values(p.name) {
			if h != "" {
				vals = append(vals, h)
			}
		}
		if len(vals) == 0 {
			return nil, false
		}
		return in.many(p, vals), true
	case "cookie":
		var vals []string
		for _, c := range r.Cookies() {
			if c.Name == p.name {
				vals = append(vals, c.Value)
			}
		}
		if len(vals) == 0 {
			return nil, false
		}
		return in.many(p, vals), true
	}
	return nil, false
}

// pathSeparator is what splits an array in a path parameter. label and
// matrix are accepted as their own separators; the leading "." or ";"
// they carry has already been eaten by the path template's match.
func pathSeparator(style string) string {
	switch style {
	case styleLabel:
		return "."
	case styleMatrix:
		return ","
	default:
		return ","
	}
}

// one builds the values of a single occurrence.
func (in *instance) one(p parameter, raw, sep string) []any {
	if !p.wants("array") {
		return []any{jsonschema.Coerce(p.schema, raw)}
	}
	return []any{in.array(p, strings.Split(raw, sep))}
}

// many builds the values of every occurrence of a parameter.
//
// For an array, all the occurrences are one array: a client that repeats
// the name and a client that separates the values inside one occurrence
// are asking for the same thing, and both spellings are unambiguous, so
// both are read. For a scalar each occurrence is its own value.
func (in *instance) many(p parameter, vals []string) []any {
	if !p.wants("array") {
		out := make([]any, 0, len(vals))
		for _, raw := range vals {
			out = append(out, jsonschema.Coerce(p.schema, raw))
		}
		return out
	}
	sep := ","
	switch p.style {
	case stylePipe:
		sep = "|"
	case styleSpace:
		sep = " "
	}
	var parts []string
	for _, raw := range vals {
		if p.style == styleForm && p.explode {
			// An exploded form array repeats the name, so an occurrence
			// is one element -- but a comma inside it is still the other
			// spelling of the same list, and splitting it is what every
			// framework behind the proxy does.
			parts = append(parts, strings.Split(raw, ",")...)
			continue
		}
		parts = append(parts, strings.Split(raw, sep)...)
	}
	return []any{in.array(p, parts)}
}

// array coerces the elements of an array parameter by the item schema.
func (in *instance) array(p parameter, parts []string) []any {
	items := p.items(in.api.v)
	out := make([]any, 0, len(parts))
	for _, s := range parts {
		out = append(out, jsonschema.Coerce(items, s))
	}
	return out
}

// deepObject assembles `name[key]=value` into the object the description
// declares, coercing each property by its own schema.
//
// It is bounded because the keys come from the query string: a client can
// write as many as the URL holds, and an unbounded map built from them is
// one more thing a request can grow.
func deepObject(p parameter, query url.Values, v *jsonschema.Validator) (map[string]any, bool) {
	prefix := p.name + "["
	props, _ := p.schema["properties"].(map[string]any)
	out := map[string]any{}
	for name, vals := range query {
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, "]") || len(vals) == 0 {
			continue
		}
		key := name[len(prefix) : len(name)-1]
		if key == "" {
			continue
		}
		if len(out) >= maxDeepObjects {
			break
		}
		var ps map[string]any
		if s := v.Resolve(props[key]); s != nil {
			ps = s.Raw
		}
		out[key] = jsonschema.Coerce(ps, vals[len(vals)-1])
	}
	return out, len(out) > 0
}

// deepPrefixes are the `name[` prefixes a strict query check must accept,
// because those names belong to a declared parameter even though none of
// them is its name.
func deepPrefixes(op *operation) []string {
	var out []string
	for _, p := range op.params {
		if p.in == "query" && p.style == styleDeep {
			out = append(out, p.name+"[")
		}
	}
	return out
}

// hasAnyPrefix reports whether s starts with one of the prefixes.
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
