// Package xmlsafe decides whether an XML document is safe to hand to a
// parser, and says which rule refused it.
//
// XML is the format that brought external entities, billion laughs,
// quadratic blowup and parameter entity loops, and every one of them lives
// in the same place: a document type declaration, or an entity reference
// that resolves to something the document did not contain. A gateway in
// front of an XML API cannot know which parser the application uses or how
// that parser is configured -- and the defaults of most XML libraries were
// unsafe for most of their history -- so the useful thing to do is refuse
// the shapes those attacks need before the application's parser ever sees
// them.
//
// This is a scanner, not a parser: it reads the document once, keeps a
// stack of open element names and nothing else, and reports the first rule
// broken. Nothing is built, so a document that would expand to gigabytes
// is refused at the declaration that would have done it, in the bytes it
// arrived as.
//
// It is deliberately not the parser in internal/saml, which has a
// different job: that one keeps namespace prefixes as written because a
// signature is over the canonical rendering, and it refuses things a
// general XML API needs (CDATA, non-ASCII names) because an identity
// provider never sends them. This one has to accept an ordinary document
// and only refuse what is dangerous.
package xmlsafe

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Reason names the rule a document broke. It is what a refusal is logged
// and counted as, so each one is a thing an operator can act on.
type Reason string

// The reasons, in the order they matter. The first four are the attacks;
// the bounds after them are the shapes that make a parser expensive; the
// last is a document that is not one.
const (
	// DOCTYPE is a document type declaration: where entity declarations,
	// parameter entities and external references live. Refused whole,
	// because a declaration this scanner does not fully model is one
	// whose effect on the application's parser it cannot predict.
	DOCTYPE Reason = "doctype"
	// Entity is a reference to an entity the five XML predefines do not
	// cover, which is a reference to something the document did not
	// contain.
	Entity Reason = "entity"
	// CDATA is a CDATA section, refused only where the policy says so:
	// ordinary XML APIs use them.
	CDATA Reason = "cdata"
	// ProcessingInstruction is a processing instruction other than the
	// XML declaration.
	ProcessingInstruction Reason = "processing_instruction"
	// Comment is a comment, refused only where the policy says so.
	Comment Reason = "comment"

	// Size, Depth, Elements, Attributes, NameLength and TextLength are
	// the bounds.
	Size       Reason = "size"
	Depth      Reason = "depth"
	Elements   Reason = "elements"
	Attributes Reason = "attributes"
	NameLength Reason = "name_length"
	TextLength Reason = "text_length"

	// Encoding is a document that is not valid UTF-8.
	Encoding Reason = "encoding"
	// Malformed is a document that is not well formed: an unterminated
	// tag, a mismatched end tag, a duplicate attribute, a character
	// reference that is not a character. A gateway refuses these because
	// two parsers disagree about them, and the application's answer to a
	// malformed document is not this proxy's to guess.
	Malformed Reason = "malformed"
	// Root is a document whose root element the policy does not allow.
	Root Reason = "root"
	// Element is an element the policy does not allow.
	Element Reason = "element"
)

// Error is a refusal: the rule, where it happened and what it was about.
type Error struct {
	Reason Reason
	Detail string
	Offset int
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("xml: %s at byte %d", e.Reason, e.Offset)
	}
	return fmt.Sprintf("xml: %s: %s (at byte %d)", e.Reason, e.Detail, e.Offset)
}

// ReasonOf returns the rule an error names, or "" for anything else.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// Limits is the policy. The zero value refuses everything interesting, so
// callers start from Default.
type Limits struct {
	// MaxBytes bounds the document. 0 leaves it to the caller, which has
	// usually already bounded the body.
	MaxBytes int
	// MaxDepth bounds element nesting: the first thing an expansion
	// attack spends.
	MaxDepth int
	// MaxElements bounds the element count.
	MaxElements int
	// MaxAttributes bounds the attributes of one element.
	MaxAttributes int
	// MaxNameBytes bounds an element or attribute name.
	MaxNameBytes int
	// MaxTextBytes bounds one run of character data.
	MaxTextBytes int
	// AllowCDATA permits CDATA sections. Ordinary XML APIs use them, so
	// this is on by default; a policy that has no use for them loses
	// nothing by turning it off.
	AllowCDATA bool
	// AllowProcessingInstructions permits processing instructions beyond
	// the XML declaration, which is always allowed.
	AllowProcessingInstructions bool
	// AllowComments permits comments.
	AllowComments bool
	// Root, when set, is the local name the root element must have.
	Root string
	// RootNamespace, when set with Root, is the namespace URI the root
	// element's name must resolve to.
	RootNamespace string
	// AllowElements, when not empty, is the set of local names any
	// element may have: a positive model for a document shape, without a
	// schema language to parse.
	AllowElements map[string]bool
	// DenyElements is the set of local names no element may have,
	// whatever AllowElements says.
	DenyElements map[string]bool
}

// Default is a policy for an XML API: no document type declaration, no
// entity references, comments and CDATA as they come, and bounds a
// hand-written request stays well inside.
func Default() Limits {
	return Limits{
		MaxBytes:      1 << 20,
		MaxDepth:      64,
		MaxElements:   50000,
		MaxAttributes: 64,
		MaxNameBytes:  256,
		MaxTextBytes:  1 << 16,
		AllowCDATA:    true,
		AllowComments: true,
	}
}

// Check reads the document once and returns the first rule it breaks.
func Check(b []byte, lim Limits) error {
	s := &scanner{b: b, lim: lim}
	if lim.MaxBytes > 0 && len(b) > lim.MaxBytes {
		return &Error{Reason: Size, Detail: fmt.Sprintf("%d bytes over the %d byte bound", len(b), lim.MaxBytes)}
	}
	if !utf8.Valid(b) {
		return &Error{Reason: Encoding, Detail: "not valid UTF-8"}
	}
	return s.document()
}

type scanner struct {
	b   []byte
	i   int
	lim Limits
	// stack holds the open elements' qualified names, and ns the
	// namespace declarations in scope, so a root check can name a
	// namespace and an end tag can be matched to its start.
	stack    []string
	ns       []map[string]string
	elements int
	sawRoot  bool
}

func (s *scanner) errf(r Reason, format string, args ...any) error {
	return &Error{Reason: r, Detail: fmt.Sprintf(format, args...), Offset: s.i}
}

func (s *scanner) has(t string) bool { return bytes.HasPrefix(s.b[s.i:], []byte(t)) }

func (s *scanner) space() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\r', '\n':
			s.i++
		default:
			return
		}
	}
}

func (s *scanner) document() error {
	s.space()
	if s.has("<?xml") {
		end := bytes.Index(s.b[s.i:], []byte("?>"))
		if end < 0 {
			return s.errf(Malformed, "unterminated XML declaration")
		}
		s.i += end + 2
	}
	for {
		s.space()
		if s.i >= len(s.b) {
			if !s.sawRoot {
				return s.errf(Malformed, "no root element")
			}
			return nil
		}
		switch {
		case s.has("<!--"):
			if err := s.comment(); err != nil {
				return err
			}
		case s.has("<!DOCTYPE"), s.has("<!doctype"):
			// The declaration is refused whole, and named, because this
			// is the one an operator will see in a log and need to
			// recognise: it is where an external entity or a billion
			// laughs would have been.
			return s.errf(DOCTYPE, "a document type declaration is not accepted")
		case s.has("<!"):
			return s.errf(DOCTYPE, "a declaration is not accepted")
		case s.has("<?"):
			if err := s.instruction(); err != nil {
				return err
			}
		case s.has("<"):
			if s.sawRoot {
				return s.errf(Malformed, "a second root element")
			}
			s.sawRoot = true
			if err := s.element(); err != nil {
				return err
			}
		default:
			return s.errf(Malformed, "content outside the root element")
		}
	}
}

func (s *scanner) comment() error {
	if !s.lim.AllowComments {
		return s.errf(Comment, "a comment is not accepted")
	}
	end := bytes.Index(s.b[s.i+4:], []byte("-->"))
	if end < 0 {
		return s.errf(Malformed, "unterminated comment")
	}
	s.i += 4 + end + 3
	return nil
}

func (s *scanner) instruction() error {
	if !s.lim.AllowProcessingInstructions {
		return s.errf(ProcessingInstruction, "a processing instruction is not accepted")
	}
	end := bytes.Index(s.b[s.i:], []byte("?>"))
	if end < 0 {
		return s.errf(Malformed, "unterminated processing instruction")
	}
	s.i += end + 2
	return nil
}

// element reads one element and everything inside it, iteratively: the
// depth bound is the stack's length, so a document cannot spend this
// process's own stack before reaching it.
func (s *scanner) element() error {
	for {
		if s.i >= len(s.b) {
			if len(s.stack) > 0 {
				return s.errf(Malformed, "unterminated element %q", s.stack[len(s.stack)-1])
			}
			return nil
		}
		switch {
		case s.has("</"):
			s.i += 2
			name, _, err := s.name()
			if err != nil {
				return err
			}
			if len(s.stack) == 0 || s.stack[len(s.stack)-1] != name {
				open := "nothing"
				if len(s.stack) > 0 {
					open = s.stack[len(s.stack)-1]
				}
				return s.errf(Malformed, "end tag %q closes %s", name, open)
			}
			s.stack = s.stack[:len(s.stack)-1]
			s.ns = s.ns[:len(s.ns)-1]
			s.space()
			if !s.has(">") {
				return s.errf(Malformed, "unterminated end tag")
			}
			s.i++
			if len(s.stack) == 0 {
				return nil
			}
		case s.has("<!--"):
			if err := s.comment(); err != nil {
				return err
			}
		case s.has("<![CDATA["):
			if !s.lim.AllowCDATA {
				return s.errf(CDATA, "a CDATA section is not accepted")
			}
			end := bytes.Index(s.b[s.i:], []byte("]]>"))
			if end < 0 {
				return s.errf(Malformed, "unterminated CDATA section")
			}
			if s.lim.MaxTextBytes > 0 && end-9 > s.lim.MaxTextBytes {
				return s.errf(TextLength, "a CDATA section of %d bytes over the %d byte bound", end-9, s.lim.MaxTextBytes)
			}
			s.i += end + 3
		case s.has("<!"):
			return s.errf(DOCTYPE, "a declaration inside an element is not accepted")
		case s.has("<?"):
			if err := s.instruction(); err != nil {
				return err
			}
		case s.has("<"):
			if err := s.startTag(); err != nil {
				return err
			}
			if len(s.stack) == 0 {
				return nil // an empty root element
			}
		default:
			if err := s.text(); err != nil {
				return err
			}
		}
	}
}

// startTag reads a start tag, pushing it unless it closes itself.
func (s *scanner) startTag() error {
	s.i++ // '<'
	name, prefix, err := s.name()
	if err != nil {
		return err
	}
	s.elements++
	if s.lim.MaxElements > 0 && s.elements > s.lim.MaxElements {
		return s.errf(Elements, "more than %d elements", s.lim.MaxElements)
	}
	if s.lim.MaxDepth > 0 && len(s.stack)+1 > s.lim.MaxDepth {
		return s.errf(Depth, "nested deeper than %d elements", s.lim.MaxDepth)
	}
	decls := map[string]string{}
	seen := map[string]bool{}
	attrs := 0
	closed := false
	for {
		ws := s.i
		s.space()
		hadSpace := s.i > ws
		switch {
		case s.has("/>"):
			s.i += 2
			closed = true
		case s.has(">"):
			s.i++
		default:
			if !hadSpace {
				return s.errf(Malformed, "expected whitespace before an attribute of %q", name)
			}
			an, ap, err := s.name()
			if err != nil {
				return err
			}
			if seen[an] {
				// Two attributes with one name is the oldest way to make
				// two readers of a document disagree.
				return s.errf(Malformed, "duplicate attribute %q on %q", an, name)
			}
			seen[an] = true
			attrs++
			if s.lim.MaxAttributes > 0 && attrs > s.lim.MaxAttributes {
				return s.errf(Attributes, "%q has more than %d attributes", name, s.lim.MaxAttributes)
			}
			value, err := s.attrValue(an)
			if err != nil {
				return err
			}
			switch {
			case an == "xmlns":
				decls[""] = value
			case ap == "xmlns":
				decls[strings.TrimPrefix(an, "xmlns:")] = value
			}
			continue
		}
		break
	}
	// The policy on names, once the element is known to be well formed.
	local := name
	if i := strings.IndexByte(local, ':'); i >= 0 {
		local = local[i+1:]
	}
	if len(s.stack) == 0 {
		if err := s.checkRoot(name, local, prefix, decls); err != nil {
			return err
		}
	}
	if s.lim.DenyElements[local] {
		return s.errf(Element, "element %q is not accepted here", local)
	}
	if len(s.lim.AllowElements) > 0 && !s.lim.AllowElements[local] {
		return s.errf(Element, "element %q is not in the allowed set", local)
	}
	if !closed {
		s.stack = append(s.stack, name)
		s.ns = append(s.ns, decls)
	}
	return nil
}

// checkRoot applies the root policy, resolving the root's prefix against
// its own declarations (a root cannot inherit any).
func (s *scanner) checkRoot(name, local, prefix string, decls map[string]string) error {
	if s.lim.Root != "" && local != s.lim.Root {
		return s.errf(Root, "the root element is %q, not %q", local, s.lim.Root)
	}
	if s.lim.RootNamespace != "" && decls[prefix] != s.lim.RootNamespace {
		return s.errf(Root, "the root element %q is not in namespace %q", name, s.lim.RootNamespace)
	}
	return nil
}

// name reads a qualified name and returns it whole and its prefix.
func (s *scanner) name() (string, string, error) {
	start := s.i
	for s.i < len(s.b) && isNameByte(s.b[s.i]) {
		s.i++
	}
	raw := string(s.b[start:s.i])
	switch {
	case raw == "":
		return "", "", s.errf(Malformed, "expected a name")
	case s.lim.MaxNameBytes > 0 && len(raw) > s.lim.MaxNameBytes:
		return "", "", s.errf(NameLength, "a name of %d bytes over the %d byte bound", len(raw), s.lim.MaxNameBytes)
	}
	prefix := ""
	if i := strings.IndexByte(raw, ':'); i >= 0 {
		prefix = raw[:i]
	}
	return raw, prefix, nil
}

// isNameByte accepts what an XML name may contain, including the bytes of
// a multi-byte character: unlike the SAML reader, a general document may
// have names outside ASCII.
func isNameByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_', c == '-', c == '.', c == ':', c >= 0x80:
		return true
	}
	return false
}

func (s *scanner) attrValue(name string) (string, error) {
	s.space()
	if !s.has("=") {
		return "", s.errf(Malformed, "attribute %q has no value", name)
	}
	s.i++
	s.space()
	if s.i >= len(s.b) || (s.b[s.i] != '"' && s.b[s.i] != '\'') {
		return "", s.errf(Malformed, "attribute %q has an unquoted value", name)
	}
	quote := s.b[s.i]
	s.i++
	var sb strings.Builder
	for {
		if s.i >= len(s.b) {
			return "", s.errf(Malformed, "unterminated value of attribute %q", name)
		}
		c := s.b[s.i]
		if c == quote {
			s.i++
			return sb.String(), nil
		}
		switch c {
		case '<':
			return "", s.errf(Malformed, "< in the value of attribute %q", name)
		case '&':
			r, err := s.reference()
			if err != nil {
				return "", err
			}
			sb.WriteString(r)
		default:
			if s.lim.MaxTextBytes > 0 && sb.Len() > s.lim.MaxTextBytes {
				return "", s.errf(TextLength, "a value of attribute %q over the %d byte bound", name, s.lim.MaxTextBytes)
			}
			sb.WriteByte(c)
			s.i++
		}
	}
}

func (s *scanner) text() error {
	start := s.i
	for s.i < len(s.b) && s.b[s.i] != '<' {
		if s.b[s.i] == '&' {
			if _, err := s.reference(); err != nil {
				return err
			}
			continue
		}
		s.i++
		if s.lim.MaxTextBytes > 0 && s.i-start > s.lim.MaxTextBytes {
			return s.errf(TextLength, "a run of %d bytes of character data over the %d byte bound", s.i-start, s.lim.MaxTextBytes)
		}
	}
	return nil
}

// reference reads one entity or character reference. The five predefined
// entities and character references are all that is accepted: everything
// else is a reference to something the document did not carry, which is
// the whole of the external entity attack and most of the expansion ones.
func (s *scanner) reference() (string, error) {
	end := bytes.IndexByte(s.b[s.i:], ';')
	if end < 0 || end > 24 {
		return "", s.errf(Malformed, "unterminated entity reference")
	}
	body := string(s.b[s.i+1 : s.i+end])
	s.i += end + 1
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
		return "", s.errf(Entity, "entity reference &%s; is not accepted", clip(body))
	}
	digits, base := body[1:], 10
	if strings.HasPrefix(digits, "x") || strings.HasPrefix(digits, "X") {
		digits, base = digits[1:], 16
	}
	v, err := strconv.ParseInt(digits, base, 32)
	if err != nil || !validChar(rune(v)) {
		return "", s.errf(Malformed, "character reference &%s; is not a character", clip(body))
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

func clip(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}
