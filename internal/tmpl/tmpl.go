// Package tmpl is the small variable expansion used for header values,
// redirect targets and error pages: "${name}" and "${name:arg}"
// placeholders in an otherwise literal string, "$$" for a literal dollar.
// The set of names is fixed at load time so that a typo fails validation
// rather than producing an empty header at run time. Values come from a
// Resolver the caller supplies per request.
package tmpl

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Part is a literal or a variable reference.
type Part struct {
	Lit  string
	Name string // "" for a literal
	Arg  string // the part after ':' (header, cookie and query names)
}

// Template is a parsed string.
type Template struct {
	parts  []Part
	static bool
	raw    string
	flat   string // the rendered form of a static template ("$$" unescaped)
}

// Resolver returns the value of a variable for one request. ok is false
// when the variable has no value here (a missing header, an unset
// capture); the placeholder then expands to "".
type Resolver interface {
	Resolve(name, arg string) (value string, ok bool)
}

// Vars are the variable names a template may use, with their meaning;
// header, cookie and query take an argument after a colon, and a
// numeric or named capture of the route's rewrite_regex or path_regex
// is referenced by its number (1 to 9) or its name.
var Vars = map[string]string{
	"client_ip":   "client address after trusted proxy handling",
	"request_id":  "request identifier",
	"host":        "request host without port",
	"path":        "request path as received",
	"raw_query":   "query string without the question mark",
	"method":      "request method",
	"scheme":      "http or https as seen by the client",
	"route":       "route name",
	"upstream":    "upstream pool name",
	"tenant":      "route tenant label",
	"country":     "client country code from GeoIP",
	"ja4":         "TLS client fingerprint",
	"tls_version": "TLS version of the client connection",
	"tls_cipher":  "TLS cipher suite of the client connection",
	"status":      "response status (error pages)",
	"status_text": "response status phrase (error pages)",
	"reason":      "denial reason category (error pages)",
	"time":        "current time, RFC 3339",
	"date":        "current date, YYYY-MM-DD, UTC",
	"hour":        "current hour, 0 to 23, UTC",
	"minute":      "current minute, 0 to 59",
	"weekday":     "current weekday, Mon to Sun, UTC",
	"header":      "request header value: ${header:Name}",
	"cookie":      "request cookie value: ${cookie:name}",
	"query":       "query parameter value: ${query:name}",
	"cert":        "client certificate field: ${cert:cn}, subject, issuer, serial, fingerprint, sans, not_after, xfcc, pem",
}

// withArg are the names that take an argument.
var withArg = map[string]bool{"header": true, "cookie": true, "query": true, "cert": true}

// TakesArg reports whether the variable takes an argument after a colon
// (and is a function, not a bare variable, in expressions).
func TakesArg(name string) bool { return withArg[name] }

// ErrUnknown is returned for a name outside Vars and the captures.
var ErrUnknown = errors.New("unknown variable")

// Parse parses s strictly: unknown variables are errors. captures names
// the named groups a route's regular expression defines and may be
// empty; numeric groups 1 to 9 are always accepted.
func Parse(s string, captures ...string) (*Template, error) { return parse(s, captures, false) }

// ParseLenient parses s keeping unknown placeholders literally, for
// documents such as error pages that may contain "${...}" for other
// reasons.
func ParseLenient(s string, captures ...string) (*Template, error) { return parse(s, captures, true) }

func parse(s string, captures []string, lenient bool) (*Template, error) {
	t := &Template{raw: s, static: true}
	named := map[string]bool{}
	for _, c := range captures {
		named[c] = true
	}
	var lit strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' {
			lit.WriteByte(c)
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			lit.WriteByte('$')
			i++
			continue
		}
		if i+1 >= len(s) || s[i+1] != '{' {
			lit.WriteByte('$')
			continue
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			if lenient {
				lit.WriteString(s[i:])
				break
			}
			return nil, fmt.Errorf("%q: unterminated placeholder at %d", s, i)
		}
		ref := s[i+2 : i+2+end]
		name, arg, hasArg := strings.Cut(ref, ":")
		if !validName(name, arg, hasArg, named) {
			if lenient {
				lit.WriteString(s[i : i+3+end])
				i += 2 + end
				continue
			}
			return nil, fmt.Errorf("%q: %w %q", s, ErrUnknown, ref)
		}
		if lit.Len() > 0 {
			t.parts = append(t.parts, Part{Lit: lit.String()})
			lit.Reset()
		}
		t.parts = append(t.parts, Part{Name: name, Arg: arg})
		t.static = false
		i += 2 + end
	}
	if lit.Len() > 0 {
		t.parts = append(t.parts, Part{Lit: lit.String()})
	}
	if t.static {
		var b strings.Builder
		for _, p := range t.parts {
			b.WriteString(p.Lit)
		}
		t.flat = b.String()
	}
	return t, nil
}

func validName(name, arg string, hasArg bool, named map[string]bool) bool {
	if name == "" {
		return false
	}
	if _, ok := Vars[name]; ok {
		if withArg[name] {
			return hasArg && arg != "" && len(arg) <= 128
		}
		return !hasArg
	}
	if hasArg {
		return false
	}
	if n, err := strconv.Atoi(name); err == nil {
		return n >= 1 && n <= 9
	}
	return named[name]
}

// Static reports whether the template has no variables.
func (t *Template) Static() bool { return t == nil || t.static }

// Raw returns the source string.
func (t *Template) Raw() string {
	if t == nil {
		return ""
	}
	return t.raw
}

// Expand renders the template with r. A nil template renders "".
func (t *Template) Expand(r Resolver) string {
	if t == nil {
		return ""
	}
	if t.static {
		return t.flat
	}
	var b strings.Builder
	b.Grow(len(t.raw) + 32)
	for _, p := range t.parts {
		if p.Name == "" {
			b.WriteString(p.Lit)
			continue
		}
		if r != nil {
			if v, ok := r.Resolve(p.Name, p.Arg); ok {
				b.WriteString(v)
			}
		}
	}
	return b.String()
}

// Names returns the variable names the template references (without
// arguments), for tests and documentation.
func (t *Template) Names() []string {
	var out []string
	for _, p := range t.parts {
		if p.Name != "" {
			out = append(out, p.Name)
		}
	}
	return out
}
