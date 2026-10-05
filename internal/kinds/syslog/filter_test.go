package syslog

import (
	"regexp"
	"testing"

	wire "github.com/rom/xproxy/internal/syslog"
)

// What a message claims to be, and what the relay does with the claim.
//
// Every field the filter reads is the sender's own assertion: the facility, the
// severity and the text. That is the point of the filter rather than an
// objection to it -- a syslog relay cannot verify any of it, so what it can do
// is refuse to carry the claims an estate has not asked for, and the test is
// about which claim each refusal names. The reason is a counter label, so a
// facility refused as "severity" would be a dashboard that lies.

func TestWhatAMessageClaimsDecidesWhetherItIsCarried(t *testing.T) {
	// A relay with no lists carries everything: a collector in front of
	// nothing is still a collector.
	open := &server{minSev: 7}
	for _, m := range []wire.Message{
		{Facility: 1, Severity: 6, Message: "an ordinary line"},
		{Facility: 23, Severity: 7, Message: "a debug line from local7"},
	} {
		if got := open.filter(m); got != "" {
			t.Errorf("%+v was dropped as %q", m, got)
		}
	}

	// The facility allow list, which is how "this collector takes the
	// network kit's records and nothing else" is written down.
	only := &server{facOK: map[int]bool{4: true, 10: true}, minSev: 7}
	for _, c := range []struct {
		facility int
		want     string
	}{
		{4, ""},
		{10, ""},
		{1, "facility"},
		{23, "facility"},
	} {
		got := only.filter(wire.Message{Facility: c.facility, Severity: 6})
		if got != c.want {
			t.Errorf("facility %d was decided %q, want %q", c.facility, got, c.want)
		}
	}

	// The deny list, which is read as well as the allow list rather than
	// instead of it: a facility on both is refused, because a deny list a
	// listener could be talked out of is not a deny list.
	both := &server{facOK: map[int]bool{4: true, 10: true},
		facDeny: map[int]bool{10: true}, minSev: 7}
	if got := both.filter(wire.Message{Facility: 10, Severity: 6}); got != "facility" {
		t.Errorf("a facility on both lists was decided %q", got)
	}
	if got := both.filter(wire.Message{Facility: 4, Severity: 6}); got != "" {
		t.Errorf("a facility only on the allow list was decided %q", got)
	}

	// The severity floor, which is a number that runs the other way: 0 is an
	// emergency and 7 is debug, so "at least this important" is "no greater
	// than this number".
	warn := &server{minSev: 4}
	for _, c := range []struct {
		severity int
		want     string
	}{
		{0, ""}, // emergency
		{4, ""}, // warning, the floor itself
		{5, "severity"},
		{7, "severity"}, // debug
	} {
		got := warn.filter(wire.Message{Facility: 1, Severity: c.severity})
		if got != c.want {
			t.Errorf("severity %d was decided %q, want %q", c.severity, got, c.want)
		}
	}

	// The text patterns, which are the last thing read: a message refused for
	// its facility is refused as that rather than scanned.
	pat := &server{minSev: 7, deny: []*regexp.Regexp{
		regexp.MustCompile(`(?i)password=\S+`),
		regexp.MustCompile(`BEGIN (RSA )?PRIVATE KEY`),
	}}
	for _, c := range []struct {
		text string
		want string
	}{
		{"login ok for bob", ""},
		{"connect password=hunter2", "pattern"},
		{"connect PASSWORD=hunter2", "pattern"},
		{"-----BEGIN RSA PRIVATE KEY-----", "pattern"},
		{"-----BEGIN PRIVATE KEY-----", "pattern"},
	} {
		got := pat.filter(wire.Message{Facility: 1, Severity: 6, Message: c.text})
		if got != c.want {
			t.Errorf("%q was decided %q, want %q", c.text, got, c.want)
		}
	}
	// And the order: a message that would match a pattern and is also outside
	// the facility list is reported as the facility, because that is the
	// cheaper fact and the one an operator is filtering on.
	ordered := &server{facOK: map[int]bool{4: true}, minSev: 7,
		deny: []*regexp.Regexp{regexp.MustCompile("password")}}
	if got := ordered.filter(wire.Message{Facility: 1, Severity: 6,
		Message: "password=hunter2"}); got != "facility" {
		t.Errorf("a message outside the facility list was decided %q", got)
	}
}

// The framing names, which decide how a stream is cut into messages. Getting
// this wrong is not a cosmetic error: under the wrong framing one record's tail
// is the next record's head.
func TestTheFramingNamesCompileToTheFramings(t *testing.T) {
	for _, c := range []struct {
		name string
		want wire.Framing
	}{
		{"octet_counting", wire.OctetCounting},
		{"non_transparent", wire.NonTransparent},
		{"auto", wire.Auto},
	} {
		got, err := framingOf(c.name)
		if err != nil {
			t.Errorf("%q: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q compiled to %v, want %v", c.name, got, c.want)
		}
	}
	// A name nothing implements is a load error rather than a framing chosen
	// for the operator.
	for _, name := range []string{"", "octet-counting", "OCTET_COUNTING", "rfc3164"} {
		if _, err := framingOf(name); err == nil {
			t.Errorf("%q was accepted as a framing", name)
		}
	}
}
