package opcua

import (
	"testing"

	wire "github.com/rom/xproxy/internal/opcua"
)

// What a learned rule is grouped and named by.
//
// The learning report writes rules somebody will paste into a
// configuration, so the grouping has to be something a person would
// have written. A string identifier groups by its path, which is what
// makes `ns=4;s=Line1/Pump1/*` a sentence; a numeric one has no
// structure to group by, so the honest answer is the namespace with the
// identifiers listed inside it rather than a prefix invented from
// digits.
func TestANodeIsGroupedOnlyWhereItHasAPath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ref       NodeRef
		ns, group string
	}{
		{"a path groups by everything above its last element", NodeRef{Namespace: 4, Key: "ns=4;s=Line1/Pump1/Speed"}, "ns=4", "Line1/Pump1"},
		{"one element is a path with nothing above it", NodeRef{Namespace: 4, Key: "ns=4;s=Speed"}, "ns=4", ""},
		{"a leading separator groups nothing", NodeRef{Namespace: 4, Key: "ns=4;s=/Speed"}, "ns=4", ""},
		{"a numeric identifier has no path", NodeRef{Namespace: 2, Key: "ns=2;i=2258"}, "ns=2", ""},
		{"a GUID has none either", NodeRef{Namespace: 3, Key: "ns=3;g=09087e75-8e5e-499b-954f-f2a9603db28a"}, "ns=3", ""},
		{"an identifier with no kind at all", NodeRef{Namespace: 5, Key: "ns=5;Line1/Pump1"}, "ns=5", ""},
		{"a key with no identifier at all", NodeRef{Namespace: 6, Key: "ns=6"}, "ns=6", ""},
	} {
		ns, group := groupOf(tc.ref)
		if ns != tc.ns || group != tc.group {
			t.Errorf("%s: groupOf(%q) = %q, %q, want %q, %q", tc.name, tc.ref.Key, ns, group, tc.ns, tc.group)
		}
	}
}

// Who a learned rule is about. Each of the three placeholders says
// something different, and a report that left them blank would read as
// missing data rather than as the truth it is.
func TestTheSubjectOfALearnedRuleNamesWhatIsMissing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		in        Session
		app, user string
	}{
		{"a session that never arrived", Session{}, "<no session>", "<not activated>"},
		{"one that arrived and was not activated", Session{ApplicationURI: "urn:scada:hmi"}, "urn:scada:hmi", "<not activated>"},
		{"an activated session with a user name", Session{ApplicationURI: "urn:scada:hmi", Activated: true, User: "operator"}, "urn:scada:hmi", "operator"},
		{
			// Anonymous is a session with rights and no user name, which
			// is not the same as a user name nobody observed.
			"an activated session with no user name",
			Session{ApplicationURI: "urn:scada:hmi", Activated: true, TokenKind: wire.TokenAnonymous},
			"urn:scada:hmi", "<" + wire.TokenAnonymous.String() + ">",
		},
	} {
		app, user := identityOf(tc.in)
		if app != tc.app || user != tc.user {
			t.Errorf("%s: identityOf = %q, %q, want %q, %q", tc.name, app, user, tc.app, tc.user)
		}
	}
}

// Every service this relay reads falls in exactly one class, and the
// classes are what a learned rule is written in terms of.
func TestEveryServiceHasALearningClass(t *testing.T) {
	for svc, want := range map[wire.Service]serviceClass{
		wire.SvcOpenChannel:     classSession,
		wire.SvcActivateSession: classSession,
		wire.SvcRead:            classRead,
		wire.SvcHistoryRead:     classRead,
		wire.SvcBrowse:          classBrowse,
		wire.SvcRegisterNodes:   classBrowse,
		wire.SvcUnregisterNodes: classBrowse,
		wire.SvcPublish:         classSubscribe,
		wire.SvcWrite:           classWrite,
		wire.SvcCall:            classWrite,
	} {
		if got := classOf(svc); got != want {
			t.Errorf("classOf(%s) = %s, want %s", svc, got, want)
		}
	}
	// A service that reads and is in none of those groups is "other".
	if got := classOf(wire.SvcQueryFirst); got != classOther {
		t.Errorf("classOf(query_first) = %s, want %s", got, classOther)
	}
	// And one this build does not know at all counts as a write, which
	// is the safe end to be wrong at: an unknown service is treated as
	// one that could change the plant.
	if got := classOf(wire.Service(0)); got != classWrite {
		t.Errorf("an unknown service is classed %s, want %s", got, classWrite)
	}
}

// What a learned rule is called, which is the name an engineer reads in
// a log line six months later.
func TestALearnedRuleIsNamedAfterWhoItIsAbout(t *testing.T) {
	for _, tc := range []struct{ name, app, user, want string }{
		{"an application and a user", "urn:plant:scada:hmi1", "operator", "hmi1-operator"},
		{"a path-shaped URI", "urn:plant/scada/hmi2", "operator", "hmi2-operator"},
		{"a placeholder user names nobody", "urn:plant:scada:hmi1", "<not activated>", "hmi1"},
		{"an anonymous session the same", "urn:plant:scada:hmi1", "<anonymous>", "hmi1"},
		{"no application at all", "", "operator", "learned-operator"},
		{"and neither", "", "<no session>", "learned"},
	} {
		if got := ruleName(&proposal{app: tc.app, user: tc.user}); got != tc.want {
			t.Errorf("%s: ruleName = %q, want %q", tc.name, got, tc.want)
		}
	}
}
