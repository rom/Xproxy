// Package schemagen derives the JSON schema of the xproxy configuration
// from the Go types in internal/config/config.go: field names from the
// yaml tags, descriptions from the doc comments, enumerations from typed
// constants and a short table of documented value sets and required keys.
// The gen command writes it; a test in package schema fails when the
// committed file is stale.
package schemagen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strings"
)

// enums lists documented value sets that the types do not encode.
var enums = map[string][]string{
	"Listener.kind":           {"http", "tcp", "forward", "dns"},
	"Discovery.type":          {"dns", "srv"},
	"Compression.encodings[]": {"gzip", "br", "zstd"},
	"TLS.min_version":         {"1.2", "1.3"},
	"TLS.client_auth":         {"none", "request", "require"},
	"Upstream.balancer":       {"round_robin", "weighted", "least_conn", "hash"},
	"Route.action":            {"proxy", "redirect", "respond", "deny", "static", "honeypot"},
	"Logging.level":           {"debug", "info", "warn", "error"},
}

// required lists the keys a document or item cannot omit.
var required = map[string][]string{
	"Config":       {"version"},
	"Listener":     {"name", "address"},
	"Upstream":     {"name"},
	"Endpoint":     {"address"},
	"Route":        {"name"},
	"RateLimit":    {"name"},
	"FilterConfig": {"name", "kind"},
	"Certificate":  {"cert_file", "key_file"},
}

const durationPattern = `^(|-?([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+)$`

type generator struct {
	structs map[string]*ast.StructType
	docs    map[string]string   // type name -> doc
	consts  map[string][]string // named string type -> constant values
	defs    map[string]any
	order   []string
}

// Generate renders the schema for the types in src.
func Generate(src string) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	g := &generator{structs: map[string]*ast.StructType{}, docs: map[string]string{}, consts: map[string][]string{}, defs: map[string]any{}}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, sp := range gd.Specs {
			switch s := sp.(type) {
			case *ast.TypeSpec:
				doc := gd.Doc
				if s.Doc != nil {
					doc = s.Doc
				}
				g.docs[s.Name.Name] = cleanDoc(doc, s.Name.Name)
				if st, ok := s.Type.(*ast.StructType); ok {
					g.structs[s.Name.Name] = st
				}
			case *ast.ValueSpec:
				if gd.Tok != token.CONST || s.Type == nil {
					continue
				}
				id, ok := s.Type.(*ast.Ident)
				if !ok {
					continue
				}
				for _, v := range s.Values {
					if lit, ok := v.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						g.consts[id.Name] = append(g.consts[id.Name], strings.Trim(lit.Value, `"`))
					}
				}
			}
		}
	}
	if _, ok := g.structs["Config"]; !ok {
		return nil, fmt.Errorf("%s: type Config not found", src)
	}
	root, err := g.object("Config")
	if err != nil {
		return nil, err
	}
	schema := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://xproxy.sysctl.se/schema/xproxy.schema.json",
		"title":       "xproxy configuration",
		"description": "One YAML document read by xproxy. Unknown keys are errors; omitted values take the documented defaults. See docs/CONFIG.md and xproxy.yaml(5).",
	}
	for k, v := range root {
		if k != "description" {
			schema[k] = v
		}
	}
	defs := map[string]any{}
	for _, name := range g.order {
		defs[name] = g.defs[name]
	}
	schema["$defs"] = defs
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(orderedMap(schema)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// object renders a struct type as an object schema (properties from the
// yaml tags, no additional properties).
func (g *generator) object(name string) (map[string]any, error) {
	st := g.structs[name]
	props := map[string]any{}
	req := required[name]
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 || field.Tag == nil {
			return nil, fmt.Errorf("%s: field without a name or yaml tag", name)
		}
		tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("yaml")
		key := strings.Split(tag, ",")[0]
		if key == "-" {
			continue
		}
		if key == "" {
			return nil, fmt.Errorf("%s.%s: empty yaml key", name, field.Names[0].Name)
		}
		prop, err := g.typeSchema(field.Type, name+"."+key)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", name, key, err)
		}
		doc := cleanDoc(field.Doc, field.Names[0].Name)
		if doc != "" {
			prop = withDescription(prop, doc)
		}
		props[key] = prop
	}
	obj := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if d := g.docs[name]; d != "" {
		obj["description"] = d
	}
	if len(req) > 0 {
		obj["required"] = req
	}
	return obj, nil
}

// ref returns a reference to the named struct, rendering it once.
func (g *generator) ref(name string) (map[string]any, error) {
	if _, done := g.defs[name]; !done {
		g.defs[name] = nil // guards recursion
		obj, err := g.object(name)
		if err != nil {
			return nil, err
		}
		g.defs[name] = obj
		g.order = append(g.order, name)
	}
	return map[string]any{"$ref": "#/$defs/" + name}, nil
}

func (g *generator) typeSchema(t ast.Expr, path string) (map[string]any, error) {
	switch x := t.(type) {
	case *ast.StarExpr:
		return g.typeSchema(x.X, path)
	case *ast.ArrayType:
		items, err := g.typeSchema(x.Elt, path+"[]")
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "array", "items": items}, nil
	case *ast.MapType:
		if id, ok := x.Key.(*ast.Ident); !ok || id.Name != "string" {
			return nil, fmt.Errorf("map key must be string")
		}
		if id, ok := x.Value.(*ast.Ident); ok && id.Name == "any" {
			return map[string]any{"type": "object"}, nil
		}
		val, err := g.typeSchema(x.Value, path+"{}")
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "object", "additionalProperties": val}, nil
	case *ast.InterfaceType:
		return map[string]any{}, nil
	case *ast.SelectorExpr:
		return nil, fmt.Errorf("unsupported external type %s", x.Sel.Name)
	case *ast.Ident:
		return g.identSchema(x.Name, path)
	}
	return nil, fmt.Errorf("unsupported type %T", t)
}

func (g *generator) identSchema(name, path string) (map[string]any, error) {
	if vals, ok := enums[path]; ok {
		return map[string]any{"type": "string", "enum": vals}, nil
	}
	switch name {
	case "string":
		return map[string]any{"type": "string"}, nil
	case "bool":
		return map[string]any{"type": "boolean"}, nil
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64":
		return map[string]any{"type": "integer"}, nil
	case "float32", "float64":
		return map[string]any{"type": "number"}, nil
	case "any":
		return map[string]any{}, nil
	case "Duration":
		return map[string]any{"type": "string", "pattern": durationPattern, "description": "Go duration such as 500ms, 10s, 5m or 1h; empty or omitted means the default"}, nil
	}
	if vals, ok := g.consts[name]; ok {
		return map[string]any{"type": "string", "enum": vals}, nil
	}
	if _, ok := g.structs[name]; ok {
		return g.ref(name)
	}
	return nil, fmt.Errorf("unsupported type %s", name)
}

// withDescription adds a description to a property; a $ref gets it
// through allOf so the reference stays valid for every validator.
func withDescription(prop map[string]any, doc string) map[string]any {
	if _, isRef := prop["$ref"]; isRef {
		return map[string]any{"description": doc, "allOf": []any{prop}}
	}
	out := map[string]any{}
	for k, v := range prop {
		out[k] = v
	}
	if _, has := out["description"]; !has {
		out["description"] = doc
	}
	return out
}

// cleanDoc turns a Go doc comment into one line.
func cleanDoc(cg *ast.CommentGroup, _ string) string {
	if cg == nil {
		return ""
	}
	text := strings.Join(strings.Fields(cg.Text()), " ")
	if text != "" && !strings.HasSuffix(text, ".") {
		text += "."
	}
	return text
}

// orderedMap makes json.Marshal emit keys in a stable, readable order:
// the schema header first, then everything else alphabetically.
type orderedMap map[string]any

var headOrder = []string{"$schema", "$id", "title", "description", "type", "enum", "pattern", "required", "properties", "additionalProperties", "items", "allOf", "$ref", "$defs"}

func (m orderedMap) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	rank := func(k string) int {
		for i, h := range headOrder {
			if h == k {
				return i
			}
		}
		return len(headOrder)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := rank(keys[i]), rank(keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(wrap(m[k]))
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func wrap(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return orderedMap(x)
	case orderedMap:
		return x
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = wrap(x[i])
		}
		return out
	}
	return v
}
