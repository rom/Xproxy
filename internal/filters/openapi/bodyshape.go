package openapi

import (
	"net/url"
	"strings"

	"github.com/rom/xproxy/internal/jsonschema"
)

// What a request body may not contain, and the bodies that are not JSON.

// maxShapeVisits bounds the readOnly walk. The schema is an operator's
// own document, but it can reference itself, and a body is a client's.
const maxShapeVisits = 20000

// maxFormFields bounds a urlencoded body's field count.
const maxFormFields = 1000

// readOnly reports the properties a body carries that the description
// marks readOnly.
//
// OpenAPI says a readOnly property "MUST NOT be sent as part of the
// request", and the reason is mass assignment: an object with `id`,
// `owner` and `role` marked readOnly is an object whose server-controlled
// fields a client is not supposed to choose. An application that binds
// the whole body onto its model -- which is what every framework's
// convenience path does -- lets the client choose them anyway. The
// description already says which fields those are.
//
// The walk follows properties, array items, additionalProperties and
// allOf, and deliberately does not follow anyOf or oneOf. allOf is a
// conjunction, so a readOnly there applies to the value whatever else
// matches; anyOf and oneOf are alternatives, and a property that is
// readOnly in one branch and writable in another says nothing certain
// about the value in hand. Refusing on the strength of a branch the value
// may not even be matching would refuse correct requests.
func (a *api) readOnly(node any, value any, path string, rep *jsonschema.Report, visits *int, depth int) {
	if depth > 32 || value == nil {
		return
	}
	*visits++
	if *visits > maxShapeVisits {
		return
	}
	s := a.v.Resolve(node)
	if s == nil || len(s.Raw) == 0 {
		return
	}
	raw := s.Raw
	for _, sub := range toAny(raw["allOf"]) {
		a.readOnly(sub, value, path, rep, visits, depth+1)
	}
	switch v := value.(type) {
	case map[string]any:
		props, _ := raw["properties"].(map[string]any)
		for name, child := range v {
			if pn, ok := props[name]; ok {
				ps := a.v.Resolve(pn)
				if ps != nil && ps.Raw["readOnly"] == true {
					rep.Add(joinField(path, name), "is read-only and must not be sent")
					continue
				}
				a.readOnly(pn, child, joinField(path, name), rep, visits, depth+1)
				continue
			}
			if ap, ok := raw["additionalProperties"]; ok {
				a.readOnly(ap, child, joinField(path, name), rep, visits, depth+1)
			}
		}
	case []any:
		items, ok := raw["items"]
		if !ok {
			return
		}
		for i, child := range v {
			if *visits > maxShapeVisits {
				return
			}
			a.readOnly(items, child, path+"["+itoa(i)+"]", rep, visits, depth+1)
		}
	}
}

func toAny(v any) []any {
	l, _ := v.([]any)
	return l
}

func joinField(base, name string) string {
	if base == "" {
		return name
	}
	return base + "." + name
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// formValue turns a urlencoded body into the value its schema describes,
// so a declared form body is checked like a declared JSON one.
//
// A form carries strings and nothing else, so each field is coerced by
// what its property schema says it is -- the same coercion the query and
// path parameters already get, for the same reason: "limit=abc" against
// `type: integer` has to be a type error rather than a string that
// happens not to be a number.
//
// A repeated field becomes an array when the schema says the property is
// one, and stays the last value otherwise, which is what a form parser
// behind the proxy does with it.
func formValue(body []byte, node any, v *jsonschema.Validator) (map[string]any, bool) {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, false
	}
	if len(vals) > maxFormFields {
		return nil, false
	}
	props := map[string]any{}
	if s := v.Resolve(node); s != nil {
		if p, ok := s.Raw["properties"].(map[string]any); ok {
			props = p
		}
	}
	out := make(map[string]any, len(vals))
	for name, list := range vals {
		if len(list) == 0 {
			continue
		}
		var ps map[string]any
		if s := v.Resolve(props[name]); s != nil {
			ps = s.Raw
		}
		if ps != nil && jsonschema.TypeAllows(ps["type"], "array") {
			items := map[string]any{}
			if is := v.Resolve(ps["items"]); is != nil {
				items = is.Raw
			}
			arr := make([]any, 0, len(list))
			for _, one := range list {
				arr = append(arr, jsonschema.Coerce(items, one))
			}
			out[name] = arr
			continue
		}
		out[name] = jsonschema.Coerce(ps, list[len(list)-1])
	}
	return out, true
}

// isForm reports a urlencoded media type.
func isForm(mt string) bool { return mt == "application/x-www-form-urlencoded" }

// isJSON reports a JSON media type, including the +json suffix forms.
func isJSON(mt string) bool {
	return mt == "application/json" || strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "/json")
}
