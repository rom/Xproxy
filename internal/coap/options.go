package coap

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The option layer. A CoAP request's meaning is entirely in its options: the
// method is one octet in the header and everything else -- which resource, which
// representation, which part of it, whether to keep sending -- is an option.

// Option is one option as it arrived.
type Option struct {
	Number uint16
	Value  []byte
}

// The option numbers, from RFC 7252 s12.2 and the extensions that matter to a
// relay. Each number's own low bits carry how a proxy must treat it, which is
// what Critical, UnSafe and NoCacheKey read.
const (
	OptionIfMatch       uint16 = 1
	OptionURIHost       uint16 = 3
	OptionETag          uint16 = 4
	OptionIfNoneMatch   uint16 = 5
	OptionObserve       uint16 = 6 // RFC 7641
	OptionURIPort       uint16 = 7
	OptionLocationPath  uint16 = 8
	OptionOSCORE        uint16 = 9 // RFC 8613
	OptionURIPath       uint16 = 11
	OptionContentFormat uint16 = 12
	OptionMaxAge        uint16 = 14
	OptionURIQuery      uint16 = 15
	OptionHopLimit      uint16 = 16 // RFC 8768
	OptionAccept        uint16 = 17
	OptionLocationQuery uint16 = 20
	OptionBlock2        uint16 = 23 // RFC 7959
	OptionBlock1        uint16 = 27 // RFC 7959
	OptionSize2         uint16 = 28 // RFC 7959
	OptionProxyURI      uint16 = 35
	OptionProxyScheme   uint16 = 39
	OptionSize1         uint16 = 60
	OptionEcho          uint16 = 252 // RFC 9175
	OptionNoResponse    uint16 = 258 // RFC 7967
	OptionRequestTag    uint16 = 292 // RFC 9175
)

// spec is what the standard says about one option: its name, the length range
// its value may take, and whether more than one instance is meaningful.
type spec struct {
	name     string
	min, max int
	repeats  bool
}

var options = map[uint16]spec{
	OptionIfMatch:       {"if_match", 0, 8, true},
	OptionURIHost:       {"uri_host", 1, 255, false},
	OptionETag:          {"etag", 1, 8, true},
	OptionIfNoneMatch:   {"if_none_match", 0, 0, false},
	OptionObserve:       {"observe", 0, 3, false},
	OptionURIPort:       {"uri_port", 0, 2, false},
	OptionLocationPath:  {"location_path", 0, 255, true},
	OptionOSCORE:        {"oscore", 0, 255, false},
	OptionURIPath:       {"uri_path", 0, 255, true},
	OptionContentFormat: {"content_format", 0, 2, false},
	OptionMaxAge:        {"max_age", 0, 4, false},
	OptionURIQuery:      {"uri_query", 0, 255, true},
	OptionHopLimit:      {"hop_limit", 1, 1, false},
	OptionAccept:        {"accept", 0, 2, false},
	OptionLocationQuery: {"location_query", 0, 255, true},
	OptionBlock2:        {"block2", 0, 3, false},
	OptionBlock1:        {"block1", 0, 3, false},
	OptionSize2:         {"size2", 0, 4, false},
	OptionProxyURI:      {"proxy_uri", 1, 1034, false},
	OptionProxyScheme:   {"proxy_scheme", 1, 255, false},
	OptionSize1:         {"size1", 0, 4, false},
	OptionEcho:          {"echo", 1, 40, false},
	OptionNoResponse:    {"no_response", 0, 1, false},
	OptionRequestTag:    {"request_tag", 0, 8, true},
}

// OptionName is an option's name for a log line and a configuration file, or its
// number where nobody has defined one.
func OptionName(n uint16) string {
	if s, ok := options[n]; ok {
		return s.name
	}
	return fmt.Sprintf("option_%d", n)
}

// OptionOf reads a name or a number back.
func OptionOf(name string) (uint16, bool) {
	for n, s := range options {
		if s.name == name {
			return n, true
		}
	}
	return 0, false
}

// KnownOption says this package can name the option, which is what decides
// whether the Critical and UnSafe rules below apply to it.
func KnownOption(n uint16) bool { _, ok := options[n]; return ok }

// Critical says an option must be understood or the message refused: RFC 7252
// s5.4.1. The rule is the option number's own low bit, so it holds for options
// nobody has registered yet -- which is the point of encoding it in the number.
func Critical(n uint16) bool { return n&1 == 1 }

// UnSafe says a proxy must not forward the option if it does not recognise it:
// RFC 7252 s5.4.2 and s5.7.1. The answer is 5.02 Bad Gateway for a request,
// because forwarding an option whose meaning is unknown is forwarding a request
// whose meaning is unknown.
func UnSafe(n uint16) bool { return n&2 == 2 }

// NoCacheKey says a Safe-to-Forward option is not part of a cache key, so a
// cache may ignore its value. It is only meaningful for an option that is safe to
// forward (RFC 7252 s5.4.6).
func NoCacheKey(n uint16) bool { return !UnSafe(n) && n&0x1e == 0x1c }

// Repeatable says more than one instance is meaningful. The path and the query
// are built out of repeated options, so this is not a detail: a relay that
// refused a second Uri-Path would refuse every request with more than one
// segment in it.
func Repeatable(n uint16) bool {
	if s, ok := options[n]; ok {
		return s.repeats
	}
	// An option nobody has defined is not assumed to repeat. It is also not
	// refused for repeating here: whether an unknown option travels at all is
	// decided by Critical and UnSafe above, which is the rule the standard gives.
	return false
}

// ValidateOptions checks each option's value against the length range the
// standard gives it, and refuses an option repeated where a second instance has
// no meaning.
//
// This is not pedantry. RFC 7252 s5.4.3 makes a value outside the range a format
// error, and the reason is that two implementations read such a value
// differently: a three-octet Content-Format is a number to one library and an
// error to another, so a relay that had a policy about the first reading while
// the server acted on the second would be the reason nobody could find the bug.
func (m *Message) ValidateOptions() error {
	seen := map[uint16]int{}
	for _, o := range m.Options {
		seen[o.Number]++
		s, ok := options[o.Number]
		if !ok {
			continue
		}
		if len(o.Value) < s.min || len(o.Value) > s.max {
			return fmt.Errorf("%w: %s of %d octets, outside %d to %d",
				ErrOption, s.name, len(o.Value), s.min, s.max)
		}
	}
	for n, count := range seen {
		if count > 1 && !Repeatable(n) {
			return fmt.Errorf("%w: %s %d times", ErrOption, OptionName(n), count)
		}
	}
	if n := seen[OptionURIPath]; n > MaxPathSegments {
		return fmt.Errorf("%w: %d path segments", ErrTooLong, n)
	}
	if n := seen[OptionURIQuery]; n > MaxQueryParts {
		return fmt.Errorf("%w: %d query parts", ErrTooLong, n)
	}
	return nil
}

// Repeated lists the options carried more than once where a second instance has
// no meaning, for the refusal's detail.
func (m *Message) Repeated() []uint16 {
	seen := map[uint16]int{}
	var out []uint16
	for _, o := range m.Options {
		seen[o.Number]++
		if seen[o.Number] == 2 && !Repeatable(o.Number) {
			out = append(out, o.Number)
		}
	}
	return out
}

// Get returns the first instance of an option.
func (m *Message) Get(n uint16) ([]byte, bool) {
	for _, o := range m.Options {
		if o.Number == n {
			return o.Value, true
		}
	}
	return nil, false
}

// All returns every instance, in order, which is what the path and the query
// need.
func (m *Message) All(n uint16) [][]byte {
	var out [][]byte
	for _, o := range m.Options {
		if o.Number == n {
			out = append(out, o.Value)
		}
	}
	return out
}

// Has says the option is present.
func (m *Message) Has(n uint16) bool { _, ok := m.Get(n); return ok }

// Numbers lists the option numbers present, once each, in order.
func (m *Message) Numbers() []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, o := range m.Options {
		if !seen[o.Number] {
			seen[o.Number] = true
			out = append(out, o.Number)
		}
	}
	return out
}

// UnknownCritical lists the Critical options this package cannot name, which
// RFC 7252 s5.4.1 answers with 4.02 Bad Option in a request and a reset in a
// response.
func (m *Message) UnknownCritical() []uint16 {
	var out []uint16
	for _, n := range m.Numbers() {
		if !KnownOption(n) && Critical(n) {
			out = append(out, n)
		}
	}
	return out
}

// UnknownUnSafe lists the UnSafe options this package cannot name, which
// RFC 7252 s5.7.1 says a proxy must not forward: 5.02 Bad Gateway for a request.
//
// A Critical option is also UnSafe about half the time, so an option can appear
// in both lists; the refusal that names the stronger reason is the one to give.
func (m *Message) UnknownUnSafe() []uint16 {
	var out []uint16
	for _, n := range m.Numbers() {
		if !KnownOption(n) && UnSafe(n) {
			out = append(out, n)
		}
	}
	return out
}

// Segments are the Uri-Path options as they arrived, which is the honest form: a
// segment is a string of octets a client chose, and joining them into a path is a
// rendering rather than the thing itself.
func (m *Message) Segments() []string {
	raw := m.All(OptionURIPath)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, string(v))
	}
	return out
}

// Path renders the segments as a path, for a log line and for matching.
//
// It is only safe to match on because SuspiciousPath refuses the segments that
// would make the rendering lie. See there for why that matters.
func (m *Message) Path() string {
	segs := m.Segments()
	if len(segs) == 0 {
		return "/"
	}
	return "/" + strings.Join(segs, "/")
}

// Query renders the Uri-Query options the way a URI writes them.
func (m *Message) Query() string {
	parts := m.All(OptionURIQuery)
	out := make([]string, 0, len(parts))
	for _, v := range parts {
		out = append(out, string(v))
	}
	return strings.Join(out, "&")
}

// SuspiciousPath says why the path options cannot be rendered into a path that
// means what it looks like, or "" when they can.
//
// This is the check that keeps a path policy from being decorative, and it exists
// because on the wire a Uri-Path segment is an arbitrary string of octets. Nothing
// stops a client sending one segment whose content is "a/b", and RFC 7252 s6.4
// only percent-encodes the separator when a URI is *written* -- so a relay that
// joined the segments with slashes and matched the result would let one segment
// satisfy a rule about two, and a rule that allows "/sensors/*" and refuses
// "/config/*" be walked straight across with a segment of "../config/x". The same
// goes for "." and "..", which a server may resolve, and for a NUL, which changes
// where a C implementation thinks the path ends.
//
// So the relay refuses these rather than normalising them. Normalising would mean
// deciding what the device would have done with the original, and a guess about
// that is the whole bug.
func (m *Message) SuspiciousPath() string {
	for i, s := range m.Segments() {
		switch {
		case strings.ContainsAny(s, "/\\"):
			return fmt.Sprintf("path segment %d contains a separator", i)
		case s == "." || s == "..":
			return fmt.Sprintf("path segment %d is %q", i, s)
		case strings.ContainsRune(s, 0):
			return fmt.Sprintf("path segment %d contains a NUL", i)
		case !utf8.ValidString(s):
			return fmt.Sprintf("path segment %d is not UTF-8", i)
		}
	}
	return ""
}

// URIHost, URIPort, ProxyURI and ProxyScheme are the options that say the request
// is not about the server it was sent to.
func (m *Message) URIHost() string { v, _ := m.Get(OptionURIHost); return string(v) }

func (m *Message) URIPort() uint16 {
	v, ok := m.Get(OptionURIPort)
	if !ok {
		return 0
	}
	return uint16(num(v)) //nolint:gosec // the length range bounds it to two octets
}

// ProxyURI is the whole URI a client asked the far end to fetch, which is what
// turns a CoAP server into a forward proxy.
func (m *Message) ProxyURI() string { v, _ := m.Get(OptionProxyURI); return string(v) }

// ProxyScheme is the other half of the same request: the scheme, with the rest of
// the URI built from Uri-Host, Uri-Port, Uri-Path and Uri-Query. A relay that
// refused Proxy-Uri and carried Proxy-Scheme would have refused nothing.
func (m *Message) ProxyScheme() string { v, _ := m.Get(OptionProxyScheme); return string(v) }

// Proxying says the request asks the far end to fetch something, by either
// option.
func (m *Message) Proxying() bool {
	return m.Has(OptionProxyURI) || m.Has(OptionProxyScheme)
}

// ContentFormat is what the payload is, and Accept is what the client will take.
// Both return false when the option is absent, which is different from zero:
// content format 0 is text/plain.
func (m *Message) ContentFormat() (uint16, bool) { return num16(m, OptionContentFormat) }
func (m *Message) Accept() (uint16, bool)        { return num16(m, OptionAccept) }

func num16(m *Message, n uint16) (uint16, bool) {
	v, ok := m.Get(n)
	if !ok {
		return 0, false
	}
	return uint16(num(v)), true //nolint:gosec // the length range bounds it to two octets
}

// MaxAge is how long a response may be cached, Size1 the size of the request
// body a client is about to send and Size2 the size of the response body it
// expects. The last two are declarations rather than facts, which is exactly why
// they are worth reading: a client declaring a megabyte is telling the relay what
// it intends before it sends it.
func (m *Message) MaxAge() (uint32, bool) { return num32(m, OptionMaxAge) }
func (m *Message) Size1() (uint32, bool)  { return num32(m, OptionSize1) }
func (m *Message) Size2() (uint32, bool)  { return num32(m, OptionSize2) }

func num32(m *Message, n uint16) (uint32, bool) {
	v, ok := m.Get(n)
	if !ok {
		return 0, false
	}
	return num(v), true
}

// Observe is RFC 7641's registration. In a request 0 registers and 1
// deregisters; in a notification the value is a sequence number, so the same
// option means two different things depending on the direction.
func (m *Message) Observe() (uint32, bool) { return num32(m, OptionObserve) }

// Registering says the request asks to be sent notifications until further
// notice, which is the one request on this protocol whose answer has no end.
func (m *Message) Registering() bool {
	v, ok := m.Observe()
	return ok && v == 0 && m.Code.IsRequest()
}

// Deregistering says the request asks for the notifications to stop.
func (m *Message) Deregistering() bool {
	v, ok := m.Observe()
	return ok && v == 1 && m.Code.IsRequest()
}

// HopLimit is RFC 8768's loop bound for a chain of proxies.
func (m *Message) HopLimit() (uint8, bool) {
	v, ok := m.Get(OptionHopLimit)
	if !ok || len(v) != 1 {
		return 0, false
	}
	return v[0], true
}

// ETags are the validators a request carries, one option each.
func (m *Message) ETags() [][]byte { return m.All(OptionETag) }

// num reads a CoAP numeric option value: a big-endian integer with its leading
// zero octets left out, so an empty value is zero (RFC 7252 s3.2).
func num(v []byte) uint32 {
	var out uint32
	for _, b := range v {
		out = out<<8 | uint32(b)
	}
	return out
}
