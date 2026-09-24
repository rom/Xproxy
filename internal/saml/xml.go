package saml

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The XML this package reads arrives from an identity provider through a
// browser, which means it arrives from whoever is logging in. The parser
// below is therefore not a general one: it refuses a document type
// declaration, an entity declaration, any entity reference but the five
// XML predefines, a processing instruction, a CDATA section and a name
// outside ASCII. Everything it refuses is something no identity provider
// needs to emit and something that has been used to make two readers of
// one document disagree -- which is the whole game in a signed document,
// where the reader that verifies and the reader that consumes must see
// exactly the same thing.
//
// It keeps namespace prefixes as written, because Exclusive
// Canonical XML renders them and a signature is over the rendering. A
// parser that resolves prefixes away (encoding/xml does) cannot
// canonicalize a document back to the bytes the signer hashed.

const (
	// maxDocBytes bounds a document. A SAML response with a handful of
	// attribute statements is a few kilobytes; a megabyte is already
	// generous, and the parser is linear in the input.
	maxDocBytes = 1 << 20
	maxDepth    = 40
	maxNodes    = 20000
	maxNameLen  = 128
	maxAttrs    = 64

	nsXML = "http://www.w3.org/XML/1998/namespace"
)

// errProfile is what everything this parser refuses looks like from
// outside: a document outside the accepted profile, not a document that
// failed a check.
var errProfile = errors.New("saml: outside the accepted XML profile")

type nodeKind uint8

const (
	kindElem nodeKind = iota
	kindText
)

// attr is one attribute as written, namespace declarations included: a
// declaration is an attribute whose prefix is "xmlns" (or whose whole
// name is "xmlns").
type attr struct {
	prefix, local, value string
}

func (a attr) qname() string { return qname(a.prefix, a.local) }

// node is an element or a run of character data. Elements keep their
// children in document order, text included, because canonicalization
// writes them out in that order.
type node struct {
	kind          nodeKind
	prefix, local string
	attrs         []attr
	kids          []*node
	text          string
	parent        *node
}

func qname(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

// lookup resolves a prefix in the scope of n, as written in the document.
// The empty prefix is the default namespace; "xml" is bound whether or
// not anybody declared it.
func (n *node) lookup(prefix string) string {
	if prefix == "xml" {
		return nsXML
	}
	for e := n; e != nil; e = e.parent {
		if e.kind != kindElem {
			continue
		}
		for _, a := range e.attrs {
			switch {
			case prefix == "" && a.prefix == "" && a.local == "xmlns":
				return a.value
			case prefix != "" && a.prefix == "xmlns" && a.local == prefix:
				return a.value
			}
		}
	}
	return ""
}

// ns is the namespace of the element's own name.
func (n *node) ns() string { return n.lookup(n.prefix) }

// is reports whether n is an element with this namespace and local name.
func (n *node) is(uri, local string) bool {
	return n != nil && n.kind == kindElem && n.local == local && n.ns() == uri
}

// attrValue is the value of an unprefixed attribute. SAML's own
// attributes (ID, Version, Destination, and the rest) are all unprefixed.
func (n *node) attrValue(local string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.attrs {
		if a.prefix == "" && a.local == local && a.local != "xmlns" {
			return a.value
		}
	}
	return ""
}

// child is the first child element with this name, or nil.
func (n *node) child(uri, local string) *node {
	if n == nil {
		return nil
	}
	for _, k := range n.kids {
		if k.is(uri, local) {
			return k
		}
	}
	return nil
}

// children are the child elements with this name, in document order.
func (n *node) children(uri, local string) []*node {
	if n == nil {
		return nil
	}
	var out []*node
	for _, k := range n.kids {
		if k.is(uri, local) {
			out = append(out, k)
		}
	}
	return out
}

// elements are every child element, whatever its name.
func (n *node) elements() []*node {
	if n == nil {
		return nil
	}
	var out []*node
	for _, k := range n.kids {
		if k.kind == kindElem {
			out = append(out, k)
		}
	}
	return out
}

// chars is the element's own character data, trimmed. Text inside child
// elements is not included: an attribute value that arrives wrapped in
// markup is not a value this package reads.
func (n *node) chars() string {
	if n == nil {
		return ""
	}
	var sb strings.Builder
	for _, k := range n.kids {
		if k.kind == kindText {
			sb.WriteString(k.text)
		}
	}
	return strings.TrimSpace(sb.String())
}

// findAll appends every element in the subtree with this name, n included.
func findAll(n *node, uri, local string, out *[]*node) {
	if n == nil || n.kind != kindElem {
		return
	}
	if n.is(uri, local) {
		*out = append(*out, n)
	}
	for _, k := range n.kids {
		findAll(k, uri, local, out)
	}
}

// parseDocument reads one XML document inside the profile above.
func parseDocument(b []byte) (*node, error) {
	switch {
	case len(b) == 0:
		return nil, fmt.Errorf("%w: empty document", errProfile)
	case len(b) > maxDocBytes:
		return nil, fmt.Errorf("%w: document larger than %d bytes", errProfile, maxDocBytes)
	case !utf8.Valid(b):
		return nil, fmt.Errorf("%w: document is not valid UTF-8", errProfile)
	}
	p := &parser{b: b}
	if err := p.prolog(); err != nil {
		return nil, err
	}
	root, err := p.element(nil, 0)
	if err != nil {
		return nil, err
	}
	if err := p.epilog(); err != nil {
		return nil, err
	}
	if err := checkNamespaces(root); err != nil {
		return nil, err
	}
	return root, nil
}

type parser struct {
	b     []byte
	i     int
	nodes int
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("%w: %s at byte %d", errProfile, fmt.Sprintf(format, args...), p.i)
}

func (p *parser) has(s string) bool { return bytes.HasPrefix(p.b[p.i:], []byte(s)) }

// space consumes XML whitespace and reports whether any was there.
func (p *parser) space() bool {
	start := p.i
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		default:
			return p.i > start
		}
	}
	return p.i > start
}

// prolog consumes an optional XML declaration and any comments before
// the root element. Canonicalization drops both.
func (p *parser) prolog() error {
	p.space()
	if p.has("<?xml") {
		end := bytes.Index(p.b[p.i:], []byte("?>"))
		if end < 0 {
			return p.errf("unterminated XML declaration")
		}
		p.i += end + 2
	}
	return p.trivia()
}

// epilog allows whitespace and comments after the root element and
// nothing else.
func (p *parser) epilog() error {
	if err := p.trivia(); err != nil {
		return err
	}
	if p.i != len(p.b) {
		return p.errf("content after the root element")
	}
	return nil
}

// trivia consumes whitespace and comments and refuses a declaration or
// a processing instruction.
func (p *parser) trivia() error {
	for {
		p.space()
		switch {
		case p.has("<!--"):
			if err := p.comment(); err != nil {
				return err
			}
		case p.has("<!"):
			return p.errf("a document type or entity declaration is not accepted")
		case p.has("<?"):
			return p.errf("a processing instruction is not accepted")
		default:
			return nil
		}
	}
}

func (p *parser) comment() error {
	end := bytes.Index(p.b[p.i+4:], []byte("-->"))
	if end < 0 {
		return p.errf("unterminated comment")
	}
	p.i += 4 + end + 3
	return nil
}

func (p *parser) count() error {
	p.nodes++
	if p.nodes > maxNodes {
		return p.errf("more than %d nodes", maxNodes)
	}
	return nil
}

func (p *parser) element(parent *node, depth int) (*node, error) {
	if depth > maxDepth {
		return nil, p.errf("nested deeper than %d elements", maxDepth)
	}
	if err := p.count(); err != nil {
		return nil, err
	}
	if !p.has("<") {
		return nil, p.errf("expected an element")
	}
	p.i++
	prefix, local, err := p.name()
	if err != nil {
		return nil, err
	}
	n := &node{kind: kindElem, prefix: prefix, local: local, parent: parent}
	closed := false
	for !closed {
		ws := p.space()
		switch {
		case p.has("/>"):
			p.i += 2
			return n, nil
		case p.has(">"):
			p.i++
			closed = true
		default:
			if !ws {
				return nil, p.errf("expected whitespace before an attribute name")
			}
			a, err := p.attribute()
			if err != nil {
				return nil, err
			}
			for _, x := range n.attrs {
				if x.prefix == a.prefix && x.local == a.local {
					return nil, p.errf("duplicate attribute %q", a.qname())
				}
			}
			if len(n.attrs) >= maxAttrs {
				return nil, p.errf("more than %d attributes", maxAttrs)
			}
			n.attrs = append(n.attrs, a)
		}
	}
	for {
		if p.i >= len(p.b) {
			return nil, p.errf("unterminated element %q", qname(prefix, local))
		}
		switch {
		case p.has("</"):
			p.i += 2
			ep, el, err := p.name()
			if err != nil {
				return nil, err
			}
			if ep != prefix || el != local {
				return nil, p.errf("end tag %q does not close %q", qname(ep, el), qname(prefix, local))
			}
			p.space()
			if !p.has(">") {
				return nil, p.errf("unterminated end tag")
			}
			p.i++
			return n, nil
		case p.has("<!--"):
			if err := p.comment(); err != nil {
				return nil, err
			}
		case p.has("<![CDATA["):
			return nil, p.errf("a CDATA section is not accepted")
		case p.has("<!"):
			return nil, p.errf("a declaration inside an element is not accepted")
		case p.has("<?"):
			return nil, p.errf("a processing instruction is not accepted")
		case p.has("<"):
			kid, err := p.element(n, depth+1)
			if err != nil {
				return nil, err
			}
			n.kids = append(n.kids, kid)
		default:
			t, err := p.text()
			if err != nil {
				return nil, err
			}
			if t == "" {
				continue
			}
			if err := p.count(); err != nil {
				return nil, err
			}
			n.kids = append(n.kids, &node{kind: kindText, text: t, parent: n})
		}
	}
}

func (p *parser) name() (prefix, local string, err error) {
	start := p.i
	for p.i < len(p.b) && isNameByte(p.b[p.i]) {
		p.i++
	}
	raw := string(p.b[start:p.i])
	switch {
	case raw == "":
		return "", "", p.errf("expected a name")
	case len(raw) > maxNameLen:
		return "", "", p.errf("name longer than %d bytes", maxNameLen)
	}
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		prefix, local = raw[:i], raw[i+1:]
		if strings.IndexByte(local, ':') >= 0 {
			return "", "", p.errf("name %q has more than one colon", raw)
		}
	} else {
		local = raw
	}
	if local == "" || !isNameStart(local[0]) || (prefix != "" && !isNameStart(prefix[0])) {
		return "", "", p.errf("%q is not a name", raw)
	}
	return prefix, local, nil
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameByte(c byte) bool {
	return isNameStart(c) || c == '-' || c == '.' || c == ':' || (c >= '0' && c <= '9')
}

func (p *parser) attribute() (attr, error) {
	prefix, local, err := p.name()
	if err != nil {
		return attr{}, err
	}
	p.space()
	if !p.has("=") {
		return attr{}, p.errf("expected = after attribute %q", qname(prefix, local))
	}
	p.i++
	p.space()
	if p.i >= len(p.b) || (p.b[p.i] != '"' && p.b[p.i] != '\'') {
		return attr{}, p.errf("attribute %q has an unquoted value", qname(prefix, local))
	}
	quote := p.b[p.i]
	p.i++
	var sb strings.Builder
	for {
		if p.i >= len(p.b) {
			return attr{}, p.errf("unterminated value of attribute %q", qname(prefix, local))
		}
		c := p.b[p.i]
		if c == quote {
			p.i++
			return attr{prefix: prefix, local: local, value: sb.String()}, nil
		}
		switch c {
		case '<':
			return attr{}, p.errf("< in the value of attribute %q", qname(prefix, local))
		case '&':
			s, err := p.reference()
			if err != nil {
				return attr{}, err
			}
			sb.WriteString(s)
		case '\t', '\n', '\r':
			// Attribute value normalization (XML 1.0 section 3.3.3): a
			// literal tab, line feed or carriage return in the source
			// becomes a space. So a tab left in a parsed value can only
			// have come from a character reference -- which is exactly
			// what canonicalization writes back as one.
			sb.WriteByte(' ')
			if c == '\r' && p.i+1 < len(p.b) && p.b[p.i+1] == '\n' {
				p.i++
			}
			p.i++
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
}

func (p *parser) text() (string, error) {
	var sb strings.Builder
	for p.i < len(p.b) && p.b[p.i] != '<' {
		switch c := p.b[p.i]; c {
		case '&':
			s, err := p.reference()
			if err != nil {
				return "", err
			}
			sb.WriteString(s)
		case '\r':
			// Line-end normalization (XML 1.0 section 2.11): CRLF and a
			// lone CR both become LF, so a CR left in parsed text came
			// from a character reference.
			sb.WriteByte('\n')
			p.i++
			if p.i < len(p.b) && p.b[p.i] == '\n' {
				p.i++
			}
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
	return sb.String(), nil
}

// reference decodes one entity or character reference. The five
// predefined entities and character references are all this parser
// takes: a document that declares its own entities is refused before it
// gets here, and one that references an undeclared entity is refused
// rather than read as empty.
func (p *parser) reference() (string, error) {
	end := bytes.IndexByte(p.b[p.i:], ';')
	if end < 0 || end > 16 {
		return "", p.errf("unterminated entity reference")
	}
	body := string(p.b[p.i+1 : p.i+end])
	p.i += end + 1
	switch body {
	case "lt":
		return "<", nil
	case "gt":
		return ">", nil
	case "amp":
		return "&", nil
	case "quot":
		return "\"", nil
	case "apos":
		return "'", nil
	}
	if !strings.HasPrefix(body, "#") {
		return "", p.errf("entity reference &%s; is not accepted", body)
	}
	digits, base := body[1:], 10
	if strings.HasPrefix(digits, "x") || strings.HasPrefix(digits, "X") {
		digits, base = digits[1:], 16
	}
	v, err := strconv.ParseInt(digits, base, 32)
	if err != nil || !validChar(rune(v)) {
		return "", p.errf("character reference &%s; is not a character", body)
	}
	return string(rune(v)), nil
}

func validChar(r rune) bool {
	switch {
	case r == 0x9, r == 0xA, r == 0xD:
		return true
	case r >= 0x20 && r <= 0xD7FF, r >= 0xE000 && r <= 0xFFFD:
		return true
	case r >= 0x10000 && r <= 0x10FFFF:
		return true
	}
	return false
}

// checkNamespaces refuses a document with a prefix nobody declared, a
// prefix declaration that undeclares, or a declaration of the reserved
// prefixes. An unresolvable prefix would make the name of an element
// depend on the reader, and the reader that verifies the signature must
// name elements the same way as the one that reads the assertion.
func checkNamespaces(n *node) error {
	if n.kind != kindElem {
		return nil
	}
	for _, a := range n.attrs {
		switch {
		case a.prefix == "" && a.local == "xmlns":
			continue // undeclaring the default namespace is legal
		case a.prefix != "xmlns":
			continue
		case a.local == "xmlns":
			return fmt.Errorf("%w: xmlns:xmlns cannot be declared", errProfile)
		case a.local == "xml" && a.value != nsXML:
			return fmt.Errorf("%w: the xml prefix cannot be rebound", errProfile)
		case a.value == "":
			return fmt.Errorf("%w: prefix %q is undeclared by an empty namespace", errProfile, a.local)
		}
	}
	if n.prefix != "" && n.lookup(n.prefix) == "" {
		return fmt.Errorf("%w: prefix %q of element %q is not declared", errProfile, n.prefix, n.qname())
	}
	for _, a := range n.attrs {
		if a.prefix == "" || a.prefix == "xmlns" || a.prefix == "xml" {
			continue
		}
		if n.lookup(a.prefix) == "" {
			return fmt.Errorf("%w: prefix %q of attribute %q is not declared", errProfile, a.prefix, a.qname())
		}
	}
	for _, k := range n.kids {
		if err := checkNamespaces(k); err != nil {
			return err
		}
	}
	return nil
}

func (n *node) qname() string { return qname(n.prefix, n.local) }

// c14n writes the Exclusive XML Canonicalization (without comments,
// http://www.w3.org/2001/10/xml-exc-c14n#) of the subtree at n. omit,
// when not nil, is a subtree left out: that is the enveloped-signature
// transform, which removes the signature from the element it signs.
// inclusive are the prefixes of an InclusiveNamespaces PrefixList, which
// are rendered as if every element used them.
func c14n(n *node, omit *node, inclusive []string) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeC14N(&buf, n, omit, inclusive, map[string]string{"": ""}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeC14N(buf *bytes.Buffer, n, omit *node, inclusive []string, rendered map[string]string) error {
	if n == omit {
		return nil
	}
	if n.kind == kindText {
		buf.WriteString(escapeText(n.text))
		return nil
	}
	// Exclusive canonicalization renders a namespace only where it is
	// visibly utilized: by the element's own prefix or by the prefix of
	// one of its attributes. This is what makes a signed element
	// survive being moved between documents that declare namespaces it
	// never uses -- and what makes the rendering depend on the
	// prefixes as written, not on the namespaces they resolve to.
	used := map[string]bool{n.prefix: true}
	for _, a := range n.attrs {
		if a.prefix == "" || a.prefix == "xmlns" || a.prefix == "xml" {
			continue
		}
		used[a.prefix] = true
	}
	for _, pfx := range inclusive {
		if pfx == "#default" {
			pfx = ""
		}
		if pfx == "xml" {
			continue
		}
		if pfx == "" || n.lookup(pfx) != "" {
			used[pfx] = true
		}
	}
	decls := make([]string, 0, len(used))
	for pfx := range used {
		uri := n.lookup(pfx)
		if pfx != "" && uri == "" {
			return fmt.Errorf("%w: prefix %q is not declared", errProfile, pfx)
		}
		if rendered[pfx] == uri {
			continue
		}
		decls = append(decls, pfx)
	}
	sort.Strings(decls) // the default namespace sorts first, as the empty prefix
	child := rendered
	if len(decls) > 0 {
		child = make(map[string]string, len(rendered)+len(decls))
		for k, v := range rendered {
			child[k] = v
		}
	}
	buf.WriteByte('<')
	buf.WriteString(n.qname())
	for _, pfx := range decls {
		uri := n.lookup(pfx)
		child[pfx] = uri
		if pfx == "" {
			buf.WriteString(` xmlns="`)
		} else {
			buf.WriteString(" xmlns:" + pfx + `="`)
		}
		buf.WriteString(escapeAttr(uri))
		buf.WriteByte('"')
	}
	type sortedAttr struct{ uri, local, name, value string }
	list := make([]sortedAttr, 0, len(n.attrs))
	for _, a := range n.attrs {
		if a.prefix == "xmlns" || (a.prefix == "" && a.local == "xmlns") {
			continue
		}
		uri := ""
		if a.prefix != "" {
			uri = n.lookup(a.prefix)
		}
		list = append(list, sortedAttr{uri: uri, local: a.local, name: a.qname(), value: a.value})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].uri != list[j].uri {
			return list[i].uri < list[j].uri
		}
		return list[i].local < list[j].local
	})
	for _, a := range list {
		buf.WriteString(" " + a.name + `="` + escapeAttr(a.value) + `"`)
	}
	buf.WriteByte('>')
	for _, k := range n.kids {
		if err := writeC14N(buf, k, omit, inclusive, child); err != nil {
			return err
		}
	}
	buf.WriteString("</" + n.qname() + ">")
	return nil
}

func escapeText(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '\r':
			sb.WriteString("&#xD;")
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func escapeAttr(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			sb.WriteString("&amp;")
		case '<':
			sb.WriteString("&lt;")
		case '"':
			sb.WriteString("&quot;")
		case '\t':
			sb.WriteString("&#x9;")
		case '\n':
			sb.WriteString("&#xA;")
		case '\r':
			sb.WriteString("&#xD;")
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}
