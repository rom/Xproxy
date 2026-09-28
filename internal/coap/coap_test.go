package coap

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// hdr builds the fixed header.
func hdr(t Type, code Code, mid uint16, tkl int) []byte {
	return []byte{Version<<6 | byte(t)<<4 | byte(tkl), byte(code), byte(mid >> 8), byte(mid)}
}

// A request off the wire, byte for byte, because a parser is only as good as the
// one case somebody wrote out by hand.
func TestARequestIsReadAsItWasSent(t *testing.T) {
	raw := hdr(Confirmable, GET, 0x1234, 2)
	raw = append(raw, 0xab, 0xcd) // the token
	raw = append(raw, 0xb7)       // delta 11 (uri_path), length 7
	raw = append(raw, "sensors"...)
	raw = append(raw, 0x04) // delta 0, length 4: another path segment
	raw = append(raw, "temp"...)
	raw = append(raw, 0x46) // delta 4 (uri_query), length 6
	raw = append(raw, "unit=c"...)

	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Type != Confirmable || m.Code != GET || m.MessageID != 0x1234 {
		t.Errorf("type %s code %s id %#x", m.Type, m.Code, m.MessageID)
	}
	if !bytes.Equal(m.Token, []byte{0xab, 0xcd}) {
		t.Errorf("token %x", m.Token)
	}
	if got := m.Path(); got != "/sensors/temp" {
		t.Errorf("path %q", got)
	}
	if got := m.Query(); got != "unit=c" {
		t.Errorf("query %q", got)
	}
	if len(m.Payload) != 0 {
		t.Errorf("payload %q", m.Payload)
	}
	if err := m.ValidateOptions(); err != nil {
		t.Errorf("validate: %v", err)
	}
	// And back out the same way, which is what a relay that took nothing out
	// must produce.
	out, err := Encode(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Errorf("re-encoded to %x, from %x", out, raw)
	}
}

// The option encoding at every boundary of its two extension forms, in both
// directions. Thirteen and fourteen in a nibble mean "one more octet" and "two
// more octets", so the interesting values are the ones either side of where the
// form changes -- which is exactly where a hand-written parser is wrong.
func TestTheOptionExtensionsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		number uint16
		length int
	}{
		{1, 0}, {1, 1}, {1, 12}, {1, 13}, {1, 268}, {1, 269}, {1, 1034},
		{12, 0}, {13, 1}, {14, 1}, {269, 1}, {270, 1}, {65535, 1},
		{OptionProxyURI, 1034},
	} {
		t.Run(fmt.Sprintf("option_%d_len_%d", tc.number, tc.length), func(t *testing.T) {
			m := &Message{Type: NonConfirmable, Code: GET, MessageID: 1}
			m.Add(tc.number, bytes.Repeat([]byte{'x'}, tc.length))
			raw, err := Encode(m)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := Parse(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got.Options) != 1 {
				t.Fatalf("%d options came back", len(got.Options))
			}
			o := got.Options[0]
			if o.Number != tc.number || len(o.Value) != tc.length {
				t.Errorf("option %d of %d octets came back as %d of %d",
					tc.number, tc.length, o.Number, len(o.Value))
			}
		})
	}
}

// The message layer's refusals, each of which RFC 7252 makes a format error.
func TestAMalformedMessageIsRefused(t *testing.T) {
	good := func() []byte {
		raw := hdr(Confirmable, GET, 1, 0)
		raw = append(raw, 0xb4)
		return append(raw, "temp"...)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"a header short of four octets", []byte{0x40, 0x01, 0x00}, ErrShort},
		{"nothing at all", nil, ErrShort},
		{"a version nobody defined", []byte{0x80, 0x01, 0x00, 0x01}, ErrVersion},
		{"a token length RFC 7252 reserves", []byte{0x49, 0x01, 0x00, 0x01}, ErrToken},
		{"the largest reserved token length", []byte{0x4f, 0x01, 0x00, 0x01}, ErrToken},
		{"a token shorter than it says", []byte{0x48, 0x01, 0x00, 0x01, 1, 2, 3}, ErrShort},
		{"a reserved option delta nibble",
			append(hdr(Confirmable, GET, 1, 0), 0xf0, 0x00), ErrOption},
		{"a reserved option length nibble",
			append(hdr(Confirmable, GET, 1, 0), 0x1f, 0x00), ErrOption},
		{"an extended delta with no octet after it",
			append(hdr(Confirmable, GET, 1, 0), 0xd0), ErrShort},
		{"an extended length with one octet where two follow",
			append(hdr(Confirmable, GET, 1, 0), 0x0e, 0x00), ErrShort},
		{"an option value shorter than its length",
			append(hdr(Confirmable, GET, 1, 0), 0xb4, 'a', 'b'), ErrShort},
		{"a payload marker with nothing after it",
			append(hdr(Confirmable, POST, 1, 0), PayloadMarker), ErrPayload},
		{"an empty message with a payload",
			append(hdr(Acknowledgement, Empty, 1, 0), PayloadMarker, 'x'), ErrEmpty},
		{"an empty message with an option",
			append(hdr(Acknowledgement, Empty, 1, 0), 0xb4, 't', 'e', 'm', 'p'), ErrEmpty},
		{"an empty message with a token",
			append(hdr(Reset, Empty, 1, 2), 0xab, 0xcd), ErrEmpty},
		{"a message past the bound", make([]byte, MaxMessage+1), ErrTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.raw); !errors.Is(err, tc.want) {
				t.Errorf("got %v, wanted %v", err, tc.want)
			}
		})
	}
	// And the message the refusals were built from parses, so each refusal above
	// is about the thing it names.
	if _, err := Parse(good()); err != nil {
		t.Errorf("the good message was refused: %v", err)
	}
}

// Every prefix of a valid message either is refused or is a whole message in its
// own right.
//
// Unlike a protocol with a length in its header, a CoAP message simply ends: cut
// one after a complete option and what is left is shorter but well formed, with
// one option fewer or no payload. So "every truncation is refused" would be the
// wrong property to test and the wrong thing to implement. What must hold is that
// a prefix never parses into a message that was read past where the octets
// stopped -- which re-encoding checks exactly, because a message read correctly
// writes back to the octets it was read from.
func TestEveryTruncationIsEitherRefusedOrWholeInItself(t *testing.T) {
	m := &Message{Type: Confirmable, Code: PUT, MessageID: 0x4242, Token: []byte{1, 2, 3, 4}}
	m.Add(OptionURIPath, []byte("actuators"))
	m.Add(OptionURIPath, []byte("valve1"))
	m.Set(OptionContentFormat, []byte{0})
	m.Payload = []byte("open")
	raw, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	parsed := 0
	for n := 0; n <= len(raw); n++ {
		got, err := Parse(raw[:n])
		if err != nil {
			continue
		}
		parsed++
		back, err := Encode(got)
		if err != nil {
			t.Errorf("a prefix of %d octets parsed but would not write back: %v", n, err)
			continue
		}
		if !bytes.Equal(back, raw[:n]) {
			t.Errorf("a prefix of %d octets parsed to something else: %x from %x",
				n, back, raw[:n])
		}
	}
	// The whole message is one of them, so the loop was doing something.
	if parsed < 2 {
		t.Errorf("only %d prefixes parsed at all", parsed)
	}
	if _, err := Parse(raw); err != nil {
		t.Errorf("the whole message was refused: %v", err)
	}
}

// An option number is sixteen bits, and the deltas accumulate, so a chain of
// large ones runs off the end of the registry.
func TestAnOptionNumberPastTheRegistryIsRefused(t *testing.T) {
	raw := hdr(Confirmable, GET, 1, 0)
	// Three options each 65535+269 past the last, which is past sixteen bits.
	for i := 0; i < 3; i++ {
		raw = append(raw, 0xe0, 0xff, 0xff)
	}
	if _, err := Parse(raw); !errors.Is(err, ErrOption) {
		t.Errorf("got %v", err)
	}
}

// The option count bound, with options that are otherwise valid.
func TestTooManyOptionsIsRefused(t *testing.T) {
	raw := hdr(Confirmable, GET, 1, 0)
	for i := 0; i <= MaxOptions; i++ {
		raw = append(raw, 0x00) // delta 0, length 0
	}
	if _, err := Parse(raw); !errors.Is(err, ErrTooLong) {
		t.Errorf("got %v", err)
	}
}

// The codes, and the one distinction an estate cares about most.
func TestTheCodesSayWhatTheyAre(t *testing.T) {
	for _, tc := range []struct {
		code                          Code
		text                          string
		request, response, writes     bool
		success, clientErr, serverErr bool
	}{
		{Empty, "0.00 Empty", false, false, false, false, false, false},
		{GET, "0.01 GET", true, false, false, false, false, false},
		{POST, "0.02 POST", true, false, true, false, false, false},
		{PUT, "0.03 PUT", true, false, true, false, false, false},
		{DELETE, "0.04 DELETE", true, false, true, false, false, false},
		{FETCH, "0.05 FETCH", true, false, false, false, false, false},
		{PATCH, "0.06 PATCH", true, false, true, false, false, false},
		{IPATCH, "0.07 iPATCH", true, false, true, false, false, false},
		{Content, "2.05 Content", false, true, false, true, false, false},
		{Continue, "2.31 Continue", false, true, false, true, false, false},
		{BadOption, "4.02 Bad Option", false, true, false, false, true, false},
		{NotFound, "4.04 Not Found", false, true, false, false, true, false},
		{TooManyRequests, "4.29 Too Many Requests", false, true, false, false, true, false},
		{BadGateway, "5.02 Bad Gateway", false, true, false, false, false, true},
		{HopLimitReached, "5.08 Hop Limit Reached", false, true, false, false, false, true},
	} {
		t.Run(tc.text, func(t *testing.T) {
			if got := tc.code.String(); got != tc.text {
				t.Errorf("rendered %q", got)
			}
			if tc.code.IsRequest() != tc.request || tc.code.IsResponse() != tc.response {
				t.Errorf("request %v response %v", tc.code.IsRequest(), tc.code.IsResponse())
			}
			if tc.code.Writes() != tc.writes {
				t.Errorf("writes %v", tc.code.Writes())
			}
			if tc.code.IsSuccess() != tc.success || tc.code.IsClientError() != tc.clientErr ||
				tc.code.IsServerError() != tc.serverErr {
				t.Errorf("success %v client %v server %v", tc.code.IsSuccess(),
					tc.code.IsClientError(), tc.code.IsServerError())
			}
			if !tc.code.Known() {
				t.Error("not known")
			}
		})
	}
	// A code nobody defined renders as its number and is not known, so a policy
	// refuses it by name rather than guessing which method it meant.
	unknown := Code(0<<5 | 12)
	if got := unknown.String(); got != "0.12" {
		t.Errorf("an undefined method rendered %q", got)
	}
	if unknown.Known() || unknown.Writes() {
		t.Error("an undefined method was known, or assumed to write")
	}
	// The signalling codes of RFC 8323's stream transports, which have no
	// business over UDP and are named so they can be refused by name.
	if !CSM.IsSignalling() || CSM.IsRequest() || CSM.IsResponse() {
		t.Error("the CSM code was classified as a request or a response")
	}
	for name, want := range map[string]Code{
		"GET": GET, "get": GET, "PUT": PUT, "iPATCH": IPATCH, "fetch": FETCH,
	} {
		if got, ok := MethodOf(name); !ok || got != want {
			t.Errorf("%q read back as %s", name, got)
		}
	}
	if _, ok := MethodOf("CONNECT"); ok {
		t.Error("a method nobody defined read back")
	}
}

// The class bits of an option number, which are what tell a proxy what to do with
// an option it does not know. The rule is the number's own low bits, so the check
// is against the standard's own table for the options it names -- otherwise the
// test would be the implementation restated.
func TestTheOptionClassesAreTheNumbersOwnBits(t *testing.T) {
	for _, tc := range []struct {
		number             uint16
		critical, unsafe   bool
		nocachekey, repeat bool
	}{
		{OptionIfMatch, true, false, false, true},
		{OptionURIHost, true, true, false, false},
		{OptionETag, false, false, false, true},
		{OptionIfNoneMatch, true, false, false, false},
		{OptionObserve, false, true, false, false},
		{OptionURIPort, true, true, false, false},
		{OptionLocationPath, false, false, false, true},
		{OptionOSCORE, true, false, false, false},
		{OptionURIPath, true, true, false, true},
		{OptionContentFormat, false, false, false, false},
		{OptionMaxAge, false, true, false, false},
		{OptionURIQuery, true, true, false, true},
		{OptionAccept, true, false, false, false},
		{OptionLocationQuery, false, false, false, true},
		{OptionBlock2, true, true, false, false},
		{OptionBlock1, true, true, false, false},
		{OptionSize2, false, false, true, false},
		{OptionProxyURI, true, true, false, false},
		{OptionProxyScheme, true, true, false, false},
		{OptionSize1, false, false, true, false},
		{OptionNoResponse, false, true, false, false},
	} {
		t.Run(OptionName(tc.number), func(t *testing.T) {
			if Critical(tc.number) != tc.critical {
				t.Errorf("critical %v", Critical(tc.number))
			}
			if UnSafe(tc.number) != tc.unsafe {
				t.Errorf("unsafe %v", UnSafe(tc.number))
			}
			if NoCacheKey(tc.number) != tc.nocachekey {
				t.Errorf("nocachekey %v", NoCacheKey(tc.number))
			}
			if Repeatable(tc.number) != tc.repeat {
				t.Errorf("repeatable %v", Repeatable(tc.number))
			}
			if !KnownOption(tc.number) {
				t.Error("not known")
			}
			if got, ok := OptionOf(OptionName(tc.number)); !ok || got != tc.number {
				t.Errorf("the name %q read back as %d", OptionName(tc.number), got)
			}
		})
	}
	if KnownOption(0xbeef) {
		t.Error("an option nobody registered is known")
	}
	if got := OptionName(0xbeef); got != "option_48879" {
		t.Errorf("an unknown option rendered %q", got)
	}
	if Repeatable(0xbeef) {
		t.Error("an unknown option was assumed to repeat")
	}
}

// What a proxy does with an option it does not know, which is the one place this
// protocol tells a relay what to do instead of leaving it a judgement call.
func TestAnUnknownOptionIsSortedByItsOwnBits(t *testing.T) {
	m := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	m.Add(OptionURIPath, []byte("temp"))
	m.Add(1000, []byte("elective, safe"))   // even, bit one clear
	m.Add(1001, []byte("critical, safe"))   // odd
	m.Add(1002, []byte("elective, unsafe")) // bit one set
	m.Add(1003, []byte("critical, unsafe")) // both

	crit, unsafe := m.UnknownCritical(), m.UnknownUnSafe()
	if len(crit) != 2 || crit[0] != 1001 || crit[1] != 1003 {
		t.Errorf("unknown critical: %v", crit)
	}
	if len(unsafe) != 2 || unsafe[0] != 1002 || unsafe[1] != 1003 {
		t.Errorf("unknown unsafe: %v", unsafe)
	}
	// An option this package names is in neither list however its bits read,
	// because the rule is about options a proxy cannot understand.
	plain := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	plain.Add(OptionURIPath, []byte("temp"))
	plain.Set(OptionProxyURI, []byte("coap://elsewhere.example/x"))
	if len(plain.UnknownCritical()) != 0 || len(plain.UnknownUnSafe()) != 0 {
		t.Error("an option this package names was counted as unknown")
	}
}

// Each option's value has a length range, and a value outside it is a format
// error rather than a number to round.
func TestAnOptionValueOutsideItsRangeIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		number uint16
		length int
		ok     bool
	}{
		{"a content format of three octets", OptionContentFormat, 3, false},
		{"a content format of two", OptionContentFormat, 2, true},
		{"a content format of none, which is text/plain", OptionContentFormat, 0, true},
		{"an etag of nine octets", OptionETag, 9, false},
		{"an etag of none", OptionETag, 0, false},
		{"an etag of one", OptionETag, 1, true},
		{"an if-none-match with a value", OptionIfNoneMatch, 1, false},
		{"an if-none-match with none", OptionIfNoneMatch, 0, true},
		{"a uri-host of none", OptionURIHost, 0, false},
		{"a block option of four octets", OptionBlock2, 4, false},
		{"a hop limit of two octets", OptionHopLimit, 2, false},
		{"an echo of forty-one octets", OptionEcho, 41, false},
		{"an echo of forty", OptionEcho, 40, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Message{Type: Confirmable, Code: GET, MessageID: 1}
			m.Add(tc.number, bytes.Repeat([]byte{'x'}, tc.length))
			err := m.ValidateOptions()
			if tc.ok && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrOption) {
				t.Errorf("accepted, or wrong error: %v", err)
			}
		})
	}
	// An option nobody registered has no range to be outside of, so the length
	// check says nothing about it: what decides is Critical and UnSafe.
	un := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	un.Add(1000, bytes.Repeat([]byte{'x'}, 500))
	if err := un.ValidateOptions(); err != nil {
		t.Errorf("an unregistered option was length-checked: %v", err)
	}
}

// An option twice where a second instance has no meaning, and the two where it
// does -- because the path and the query are built out of repetition, and a relay
// that refused a second Uri-Path would refuse every request with a path.
func TestARepeatedOptionIsRefusedExceptWhereItIsThePoint(t *testing.T) {
	twice := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	twice.Add(OptionContentFormat, []byte{0})
	twice.Add(OptionContentFormat, []byte{50})
	if err := twice.ValidateOptions(); !errors.Is(err, ErrOption) {
		t.Errorf("two content formats: %v", err)
	}
	if rep := twice.Repeated(); len(rep) != 1 || rep[0] != OptionContentFormat {
		t.Errorf("repeated: %v", rep)
	}

	path := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	for _, s := range []string{"a", "b", "c", "d"} {
		path.Add(OptionURIPath, []byte(s))
	}
	for _, s := range []string{"x=1", "y=2"} {
		path.Add(OptionURIQuery, []byte(s))
	}
	path.Add(OptionETag, []byte{1})
	path.Add(OptionETag, []byte{2})
	if err := path.ValidateOptions(); err != nil {
		t.Errorf("a path of four segments: %v", err)
	}
	if rep := path.Repeated(); len(rep) != 0 {
		t.Errorf("repeated: %v", rep)
	}
	if got := path.Path(); got != "/a/b/c/d" {
		t.Errorf("path %q", got)
	}
	if got := path.Query(); got != "x=1&y=2" {
		t.Errorf("query %q", got)
	}

	// And the repetition itself is bounded, because a path of ten thousand
	// segments is not a path.
	many := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	for i := 0; i <= MaxPathSegments; i++ {
		many.Add(OptionURIPath, []byte("x"))
	}
	if err := many.ValidateOptions(); !errors.Is(err, ErrTooLong) {
		t.Errorf("%d segments: %v", MaxPathSegments+1, err)
	}
}

// The path segments a relay must not join into a path, because the join would
// mean something the segments do not.
func TestAPathThatWouldLieIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		segs []string
		bad  bool
	}{
		{"an ordinary path", []string{"sensors", "temp"}, false},
		{"an empty segment, which is legal", []string{"a", "", "b"}, false},
		{"a segment with a dash and a dot", []string{"well-known", "core.json"}, false},
		{"a segment containing a separator", []string{"a/b"}, true},
		{"a segment that walks out", []string{"sensors", "..", "config"}, true},
		{"a segment that is a dot", []string{"."}, true},
		{"a segment with a backslash", []string{`a\b`}, true},
		{"a segment with a NUL", []string{"a\x00b"}, true},
		{"a segment that is not UTF-8", []string{"a\xffb"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Message{Type: Confirmable, Code: GET, MessageID: 1}
			for _, s := range tc.segs {
				m.Add(OptionURIPath, []byte(s))
			}
			why := m.SuspiciousPath()
			if tc.bad && why == "" {
				t.Errorf("%q was accepted, and renders as %q", tc.segs, m.Path())
			}
			if !tc.bad && why != "" {
				t.Errorf("%q was refused: %s", tc.segs, why)
			}
		})
	}
	// The case worth stating outright: one segment rendering as two is how a
	// rule about /sensors/* would be satisfied by a request to /config.
	one := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	one.Add(OptionURIPath, []byte("sensors/../config/secret"))
	if one.Path() != "/sensors/../config/secret" {
		t.Fatalf("the rendering changed: %q", one.Path())
	}
	if one.SuspiciousPath() == "" {
		t.Error("one segment that renders as four was not flagged")
	}
	if got := (&Message{}).Path(); got != "/" {
		t.Errorf("a message with no path options rendered %q", got)
	}
}

// Block-wise transfer: the sizes, the reserved exponent, and the arithmetic a
// bound depends on.
func TestABlockOptionSaysWhereTheTransferIs(t *testing.T) {
	for _, tc := range []struct {
		name          string
		value         []byte
		num           uint32
		more          bool
		size, offset  int64
		end           int64
		wantErrorOnly bool
	}{
		{name: "an empty value is block zero of sixteen", value: nil,
			num: 0, more: false, size: 16, offset: 0, end: 16},
		{name: "block zero of a kilobyte, more to come", value: []byte{0x0e},
			num: 0, more: true, size: 1024, offset: 0, end: 1024},
		{name: "block one of a kilobyte", value: []byte{0x16},
			num: 1, more: false, size: 1024, offset: 1024, end: 2048},
		{name: "a twelve-bit block number", value: []byte{0xff, 0xf6},
			num: 4095, more: false, size: 1024, offset: 4095 * 1024, end: 4096 * 1024},
		{name: "a twenty-bit block number", value: []byte{0xff, 0xff, 0xf6},
			num: 1048575, more: false, size: 1024,
			offset: 1048575 * 1024, end: 1048576 * 1024},
		{name: "a reserved size exponent", value: []byte{0x07}, wantErrorOnly: true},
		{name: "four octets is not a block option",
			value: []byte{1, 2, 3, 4}, wantErrorOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := ParseBlock(tc.value)
			if tc.wantErrorOnly {
				if !errors.Is(err, ErrOption) {
					t.Fatalf("got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if b.Num != tc.num || b.More != tc.more {
				t.Errorf("num %d more %v", b.Num, b.More)
			}
			if b.Size() != tc.size || b.Offset() != tc.offset || b.End() != tc.end {
				t.Errorf("size %d offset %d end %d", b.Size(), b.Offset(), b.End())
			}
			// And the value renders back to itself, leading zeros left out.
			if got := b.AppendTo(nil); !bytes.Equal(got, tc.value) {
				t.Errorf("rendered %x, from %x", got, tc.value)
			}
		})
	}
	// Every exponent the standard defines maps to its size.
	for exp := uint8(0); exp <= MaxSizeExp; exp++ {
		want := int64(16) << exp
		if got := (Block{SizeExp: exp}).Size(); got != want {
			t.Errorf("exponent %d is %d octets, wanted %d", exp, got, want)
		}
	}
}

// What the relay bounds a transfer against: the block that arrived and the size a
// client declared, whichever is larger. The declaration is the useful one,
// because it is the intent before the transfer rather than after it.
func TestTheTransferSizeTakesTheLarger(t *testing.T) {
	// Block zero of sixteen octets, declaring a megabyte to come.
	m := &Message{Type: Confirmable, Code: PUT, MessageID: 1}
	m.Set(OptionBlock1, []byte{0x08}) // block 0, more, sixteen octets
	m.Set(OptionSize1, []byte{0x10, 0x00, 0x00})
	if got, want := m.TransferSize(), int64(0x100000); got != want {
		t.Errorf("transfer size %d, wanted the declared %d", got, want)
	}
	// And a transfer already further along than it declared: the fact wins over
	// the declaration.
	m.Set(OptionSize1, []byte{0x10})
	m.Set(OptionBlock1, []byte{0x16}) // block 1 of a kilobyte
	if got, want := m.TransferSize(), int64(2048); got != want {
		t.Errorf("transfer size %d, wanted %d", got, want)
	}
	// Nothing said at all is nothing to bound.
	if got := (&Message{}).TransferSize(); got != 0 {
		t.Errorf("a message with no block options said %d", got)
	}
	// A block option that does not parse contributes nothing rather than
	// panicking; the message is refused elsewhere for being malformed.
	bad := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	bad.Set(OptionBlock2, []byte{0x07})
	if _, _, err := bad.Block2(); err == nil {
		t.Error("a reserved exponent parsed")
	}
	if got := bad.TransferSize(); got != 0 {
		t.Errorf("an unreadable block option contributed %d", got)
	}
}

// Observe, which is the one request whose answer has no end, and which means two
// different things in the two directions.
func TestObserveIsReadInBothDirections(t *testing.T) {
	reg := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	reg.Set(OptionObserve, nil) // zero, with the leading zeros left out
	if !reg.Registering() || reg.Deregistering() {
		t.Error("a registration was not read as one")
	}
	dereg := &Message{Type: Confirmable, Code: GET, MessageID: 2}
	dereg.Set(OptionObserve, []byte{1})
	if dereg.Registering() || !dereg.Deregistering() {
		t.Error("a deregistration was not read as one")
	}
	// In a notification the same option is a sequence number, so it is neither.
	note := &Message{Type: NonConfirmable, Code: Content, MessageID: 3}
	note.Set(OptionObserve, []byte{0x00, 0x00, 0x2a})
	if note.Registering() || note.Deregistering() {
		t.Error("a notification was read as a registration")
	}
	if v, ok := note.Observe(); !ok || v != 42 {
		t.Errorf("the sequence number came back as %d (%v)", v, ok)
	}
}

// The options that say the request is not about the server it was sent to, which
// is the one option pair that turns the far end into an open forward proxy.
func TestProxyingIsSeenByEitherOption(t *testing.T) {
	uri := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	uri.Set(OptionProxyURI, []byte("coap://192.0.2.1/admin"))
	if !uri.Proxying() || uri.ProxyURI() != "coap://192.0.2.1/admin" {
		t.Errorf("proxy_uri: %v %q", uri.Proxying(), uri.ProxyURI())
	}
	// Proxy-Scheme is the same request written the other way: the scheme in one
	// option and the rest of the URI in Uri-Host, Uri-Port, Uri-Path and
	// Uri-Query. A relay that refused only Proxy-Uri would have refused nothing.
	scheme := &Message{Type: Confirmable, Code: GET, MessageID: 2}
	scheme.Set(OptionProxyScheme, []byte("http"))
	scheme.Set(OptionURIHost, []byte("elsewhere.example"))
	scheme.Set(OptionURIPort, []byte{0x1f, 0x90})
	scheme.Add(OptionURIPath, []byte("admin"))
	if !scheme.Proxying() || scheme.ProxyScheme() != "http" {
		t.Errorf("proxy_scheme: %v %q", scheme.Proxying(), scheme.ProxyScheme())
	}
	if scheme.URIHost() != "elsewhere.example" || scheme.URIPort() != 8080 {
		t.Errorf("host %q port %d", scheme.URIHost(), scheme.URIPort())
	}
	plain := &Message{Type: Confirmable, Code: GET, MessageID: 3}
	plain.Add(OptionURIPath, []byte("temp"))
	if plain.Proxying() {
		t.Error("an ordinary request was read as proxying")
	}
}

// The numeric options, whose leading zero octets are left out on the wire -- so
// absent and zero are different things and the accessors have to say which.
func TestANumericOptionLeavesOutItsLeadingZeros(t *testing.T) {
	m := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	if _, ok := m.ContentFormat(); ok {
		t.Error("an absent content format read as present")
	}
	// Content format zero is text/plain, and an empty value is how it is sent.
	m.Set(OptionContentFormat, nil)
	if v, ok := m.ContentFormat(); !ok || v != 0 {
		t.Errorf("content format %d (%v), wanted 0 present", v, ok)
	}
	if got := ContentFormatName(0); got != "text/plain" {
		t.Errorf("format 0 is %q", got)
	}
	m.Set(OptionContentFormat, []byte{0x2d, 0x16}) // 11542
	if v, _ := m.ContentFormat(); v != 11542 {
		t.Errorf("content format %d", v)
	}
	if got := ContentFormatName(11542); !strings.Contains(got, "lwm2m") {
		t.Errorf("format 11542 is %q", got)
	}
	if got := ContentFormatName(9999); got != "format_9999" {
		t.Errorf("an unnamed format is %q", got)
	}
	if KnownContentFormat(9999) {
		t.Error("an unnamed format is known")
	}
	if got, ok := ContentFormatOf("application/link-format"); !ok || got != LinkFormat {
		t.Errorf("the link format read back as %d", got)
	}
	m.Set(OptionMaxAge, []byte{0xff, 0xff, 0xff, 0xff})
	if v, ok := m.MaxAge(); !ok || v != 0xffffffff {
		t.Errorf("max age %d", v)
	}
	m.Set(OptionHopLimit, []byte{16})
	if v, ok := m.HopLimit(); !ok || v != 16 {
		t.Errorf("hop limit %d (%v)", v, ok)
	}
}

// The resource whose whole purpose is to list every other resource, which is the
// largest answer on a device for the smallest question.
func TestTheDiscoveryPathIsRecognised(t *testing.T) {
	yes := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	yes.Add(OptionURIPath, []byte(".well-known"))
	yes.Add(OptionURIPath, []byte("core"))
	if !yes.IsWellKnownCore() {
		t.Error("/.well-known/core was not recognised")
	}
	for _, segs := range [][]string{
		{".well-known"},
		{".well-known", "core", "extra"},
		{"well-known", "core"},
		{},
	} {
		m := &Message{Type: Confirmable, Code: GET, MessageID: 1}
		for _, s := range segs {
			m.Add(OptionURIPath, []byte(s))
		}
		if m.IsWellKnownCore() {
			t.Errorf("%q was read as the discovery path", segs)
		}
	}
}

// The answers a relay sends itself, which is what the standard gives it instead of
// a judgement call -- and better than silence, because a device that got an answer
// stops retransmitting.
func TestARelaysOwnAnswerIsAddressedToTheRequest(t *testing.T) {
	// A confirmable request is answered by an acknowledgement carrying the
	// response, with the request's own message identifier so that it
	// acknowledges it too.
	con := &Message{Type: Confirmable, Code: GET, MessageID: 0x1111, Token: []byte{9, 8}}
	a := Answer(con, BadOption, 0x2222)
	if a.Type != Acknowledgement || a.MessageID != 0x1111 || a.Code != BadOption {
		t.Errorf("type %s id %#x code %s", a.Type, a.MessageID, a.Code)
	}
	if !bytes.Equal(a.Token, con.Token) {
		t.Errorf("token %x, wanted the request's %x", a.Token, con.Token)
	}
	// A non-confirmable one gets a non-confirmable answer with an identifier of
	// its own, and still the request's token: the token is the only thing that
	// pairs them.
	non := &Message{Type: NonConfirmable, Code: GET, MessageID: 0x3333, Token: []byte{7}}
	b := Answer(non, BadGateway, 0x4444)
	if b.Type != NonConfirmable || b.MessageID != 0x4444 {
		t.Errorf("type %s id %#x", b.Type, b.MessageID)
	}
	if !bytes.Equal(b.Token, non.Token) {
		t.Errorf("token %x", b.Token)
	}
	// A reset carries nothing at all, which is why it is the right answer to a
	// message whose token could not be read.
	r := ResetFor(0x5555)
	if r.Type != Reset || r.Code != Empty || len(r.Token) != 0 || len(r.Options) != 0 {
		t.Errorf("reset: %+v", r)
	}
	for _, m := range []*Message{a, b, r, AckFor(1)} {
		raw, err := Encode(m)
		if err != nil {
			t.Fatalf("encode %s: %v", m.Code, err)
		}
		back, err := Parse(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", m.Code, err)
		}
		if back.Code != m.Code || back.Type != m.Type || back.MessageID != m.MessageID {
			t.Errorf("%s came back as %s %s %#x", m.Code, back.Type, back.Code, back.MessageID)
		}
	}
}

// The editing a relay does: taking an option out, and leaving the message it
// arrived as alone while doing it.
func TestEditingACopyLeavesTheOriginalAlone(t *testing.T) {
	m := &Message{Type: Confirmable, Code: GET, MessageID: 1, Token: []byte{1}}
	m.Add(OptionURIPath, []byte("temp"))
	m.Set(OptionProxyURI, []byte("coap://elsewhere.example/x"))
	m.Payload = []byte("body")

	c := m.Clone()
	if gone := c.Remove(OptionProxyURI); gone != 1 {
		t.Errorf("%d options removed", gone)
	}
	if c.Has(OptionProxyURI) {
		t.Error("the option is still on the copy")
	}
	if !m.Has(OptionProxyURI) {
		t.Error("removing it from the copy removed it from the original")
	}
	c.Payload[0] = 'B'
	if m.Payload[0] != 'b' {
		t.Error("the payloads share an array")
	}
	c.Token[0] = 2
	if m.Token[0] != 1 {
		t.Error("the tokens share an array")
	}
	if gone := c.Remove(OptionAccept); gone != 0 {
		t.Errorf("removing an absent option removed %d", gone)
	}

	// Set replaces every instance, which is what makes it safe on an option a
	// message arrived carrying twice.
	twice := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	twice.Add(OptionContentFormat, []byte{0})
	twice.Add(OptionContentFormat, []byte{50})
	twice.Set(OptionContentFormat, []byte{60})
	if got := twice.All(OptionContentFormat); len(got) != 1 || got[0][0] != 60 {
		t.Errorf("content formats: %v", got)
	}
}

// Encode refuses what it must not write, which matters because the messages it
// writes are the ones this relay is the author of.
func TestEncodeRefusesWhatItMustNotWrite(t *testing.T) {
	long := &Message{Type: Confirmable, Code: GET, MessageID: 1,
		Token: bytes.Repeat([]byte{1}, MaxToken+1)}
	if _, err := Encode(long); !errors.Is(err, ErrToken) {
		t.Errorf("a nine-octet token: %v", err)
	}
	empty := &Message{Type: Acknowledgement, Code: Empty, MessageID: 1, Payload: []byte("x")}
	if _, err := Encode(empty); !errors.Is(err, ErrEmpty) {
		t.Errorf("an empty message with a payload: %v", err)
	}
	big := &Message{Type: Confirmable, Code: PUT, MessageID: 1,
		Payload: bytes.Repeat([]byte{'x'}, MaxMessage)}
	if _, err := Encode(big); !errors.Is(err, ErrTooLong) {
		t.Errorf("a message past the bound: %v", err)
	}
	wide := &Message{Type: Confirmable, Code: PUT, MessageID: 1}
	wide.Add(OptionProxyURI, bytes.Repeat([]byte{'x'}, MaxOptionLen+1))
	if _, err := Encode(wide); !errors.Is(err, ErrTooLong) {
		t.Errorf("an option past the bound: %v", err)
	}
}

// The options go out in ascending number order because the encoding is a delta,
// and the instances of a repeated option keep the order they were added in,
// because for the path that order is the meaning.
func TestTheOptionsGoOutInOrderAndThePathKeepsIts(t *testing.T) {
	m := &Message{Type: Confirmable, Code: GET, MessageID: 1}
	m.Set(OptionAccept, []byte{50})
	m.Add(OptionURIPath, []byte("sensors"))
	m.Set(OptionURIHost, []byte("device.example"))
	m.Add(OptionURIPath, []byte("temperature"))
	m.Add(OptionURIQuery, []byte("unit=c"))

	raw, err := Encode(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []uint16{OptionURIHost, OptionURIPath, OptionURIPath,
		OptionURIQuery, OptionAccept}
	got := make([]uint16, 0, len(back.Options))
	for _, o := range back.Options {
		got = append(got, o.Number)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("option order %v, wanted %v", got, want)
	}
	if p := back.Path(); p != "/sensors/temperature" {
		t.Errorf("the path came back as %q", p)
	}
}

// Types read back from their names, for a configuration file.
func TestTheTypesReadBack(t *testing.T) {
	for name, want := range map[string]Type{
		"con": Confirmable, "confirmable": Confirmable,
		"non": NonConfirmable, "non_confirmable": NonConfirmable,
		"ack": Acknowledgement, "rst": Reset, "reset": Reset,
	} {
		if got, ok := TypeOf(name); !ok || got != want {
			t.Errorf("%q read back as %s", name, got)
		}
	}
	if _, ok := TypeOf("nonsense"); ok {
		t.Error("a name nobody uses read back")
	}
	for _, tc := range []struct {
		t    Type
		want string
	}{{Confirmable, "con"}, {NonConfirmable, "non"},
		{Acknowledgement, "ack"}, {Reset, "rst"}} {
		if got := tc.t.String(); got != tc.want {
			t.Errorf("%d rendered %q", tc.t, got)
		}
	}
}

// An option value larger than the longest the standard defines, refused at parse
// rather than allocated for.
//
// Encode refuses it too, which is right for a message this package writes and no
// help against one it receives, so the octets are assembled by hand.
func TestAnOptionValuePastTheBoundIsRefused(t *testing.T) {
	build := func(length int) []byte {
		raw := hdr(Confirmable, PUT, 1, 0)
		// Option 35 (proxy_uri), with a two-octet extended length.
		raw = append(raw, 0xde, 22, byte((length-269)>>8), byte(length-269))
		return append(raw, bytes.Repeat([]byte{'x'}, length)...)
	}
	// The longest the standard defines parses.
	ok, err := Parse(build(MaxOptionLen))
	if err != nil {
		t.Fatalf("an option of %d octets was refused: %v", MaxOptionLen, err)
	}
	if v, present := ok.Get(OptionProxyURI); !present || len(v) != MaxOptionLen {
		t.Fatalf("the option came back as %d octets (%v)", len(v), present)
	}
	// One octet more does not, and neither does anything up to the message bound.
	for _, n := range []int{MaxOptionLen + 1, 2000, 4000, MaxMessage - 16} {
		if _, err := Parse(build(n)); !errors.Is(err, ErrTooLong) {
			t.Errorf("an option of %d octets: %v", n, err)
		}
	}
}

// NoCacheKey's expression, against the standard's own rule rather than against
// itself: an option the mask matches is never UnSafe, which is why the function
// tests one thing.
func TestNoCacheKeyImpliesSafeToForward(t *testing.T) {
	matched := 0
	for n := 0; n <= 0xffff; n++ {
		num := uint16(n) //nolint:gosec // bounded by the loop
		if !NoCacheKey(num) {
			continue
		}
		matched++
		if UnSafe(num) {
			t.Fatalf("option %d is NoCacheKey and UnSafe, which the mask should forbid", num)
		}
	}
	if matched == 0 {
		t.Error("no option number matched the NoCacheKey pattern")
	}
}
