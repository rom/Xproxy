package attack

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/listener"
)

// The table is data, so the tests are about the table being consistent
// with itself and with the rest of the project: a mapping naming a
// technique no catalogue has, or a kind this project does not implement,
// is a row that tags nothing at run time and would be found only by
// somebody reading a log line that should have carried a technique and
// did not.

func TestEveryMappingNamesAKnownTechnique(t *testing.T) {
	for _, m := range mappings {
		if len(m.ids) == 0 {
			t.Errorf("%s/%s maps to no technique at all", m.kind, m.reason)
		}
		for _, id := range m.ids {
			if !Known(id) {
				t.Errorf("%s/%s names %s, which no catalogue has", m.kind, m.reason, id)
			}
		}
	}
}

func TestEveryMappingNamesAKindThisProjectServes(t *testing.T) {
	for _, m := range mappings {
		if _, ok := listener.RoleOf(m.kind); !ok {
			t.Errorf("%s/%s is about kind %q, which no daemon serves", m.kind, m.reason, m.kind)
		}
	}
}

func TestNoMappingIsWrittenTwice(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range mappings {
		k := m.kind + "/" + m.reason
		if seen[k] {
			t.Errorf("%s is mapped twice, and the second row is the one that wins silently", k)
		}
		seen[k] = true
	}
}

func TestNoTechniqueIsCataloguedTwice(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range [][]entry{icsCatalogue, enterpriseCatalogue} {
		for _, e := range c {
			if seen[e.id] {
				t.Errorf("%s is in a catalogue twice, and the second row is dropped silently", e.id)
			}
			seen[e.id] = true
		}
	}
}

// A technique in a catalogue that nothing maps to is a detection this
// project claims and does not have. It is the failure that matters most
// here, because attack.All() is what a coverage answer is built from.
func TestEveryTechniqueIsReachable(t *testing.T) {
	used := map[string]bool{}
	for _, m := range mappings {
		for _, id := range m.ids {
			used[id] = true
		}
	}
	for id := range techniques {
		if !used[id] {
			t.Errorf("%s is in a catalogue and nothing maps to it: either map it or take it out, "+
				"because All() is read as what this relay can detect", id)
		}
	}
}

var identifier = regexp.MustCompile(`^T[01][0-9]{3}(\.[0-9]{3})?$`)

func TestEveryTechniqueIsDescribed(t *testing.T) {
	for _, tech := range All() {
		if !identifier.MatchString(tech.ID) {
			t.Errorf("%q is not an ATT&CK identifier", tech.ID)
		}
		switch tech.Matrix {
		case MatrixICS:
			if !strings.HasPrefix(tech.ID, "T0") {
				t.Errorf("%s is filed under ATT&CK for ICS and is not a T0 identifier", tech.ID)
			}
			if strings.Contains(tech.ID, ".") {
				t.Errorf("%s: ATT&CK for ICS has no sub-techniques", tech.ID)
			}
		case MatrixEnterprise:
			if !strings.HasPrefix(tech.ID, "T1") {
				t.Errorf("%s is filed under Enterprise ATT&CK and is not a T1 identifier", tech.ID)
			}
		default:
			t.Errorf("%s belongs to no matrix", tech.ID)
		}
		if tech.Name == "" {
			t.Errorf("%s has no name", tech.ID)
		}
		if len(tech.Tactics) == 0 {
			t.Errorf("%s sits under no tactic", tech.ID)
		}
		if len(tech.Why) < 40 {
			t.Errorf("%s: the justification is %d characters, which is not one",
				tech.ID, len(tech.Why))
		}
	}
	if len(InMatrix(MatrixICS))+len(InMatrix(MatrixEnterprise)) != len(All()) {
		t.Error("a technique is in All() and in neither matrix")
	}
}

// The sub-technique identifier and the sub-technique URL are written
// differently, which is the one thing a link has to get right.
func TestTheLinkToMitreIsTheRightShape(t *testing.T) {
	ics, _ := Get("T0855")
	if got := ics.URL(); got != "https://attack.mitre.org/techniques/T0855/" {
		t.Errorf("ics url %q", got)
	}
	sub, _ := Get("T1021.004")
	if got := sub.URL(); got != "https://attack.mitre.org/techniques/T1021/004/" {
		t.Errorf("sub-technique url %q", got)
	}
}

// Lookup works from both ends, because the counter has the kind in hand
// and the log line has the event name.
func TestLookupFromAKindAndFromAnEventName(t *testing.T) {
	ts := Of("modbus", "read_only")
	if len(ts) == 0 || ts[0].ID != "T0855" {
		t.Fatalf("modbus/read_only: %v", ts)
	}
	// The kinds spell the prefix both ways, so both have to resolve.
	if got := Of("iec104", "iec104_control"); len(got) == 0 || got[0].ID != "T0855" {
		t.Errorf("a reason carrying its own kind prefix did not resolve: %v", got)
	}
	if got := OfEvent("modbus_read_only"); len(got) != len(ts) {
		t.Errorf("the event index and the kind index disagree: %v against %v", got, ts)
	}
	if got := OfEvent("modbus_tls_handshake"); got != nil {
		t.Errorf("a reason that is protocol hygiene was tagged %v", got)
	}
	if got := OfEvent("s7_malformed"); got != nil {
		t.Errorf("a malformed frame was tagged %v", got)
	}
}

// The HTTP side logs a bare reason, and a reason with the rule that fired
// after a colon. Both have to resolve, because they are what is actually
// in the log.
func TestTheHTTPEventNamesResolveWithoutAKindPrefix(t *testing.T) {
	for _, event := range []string{"waf", "http_waf", "waf:942100"} {
		ts := OfEvent(event)
		if len(ts) != 1 || ts[0].ID != "T1190" {
			t.Errorf("OfEvent(%q) = %v", event, IDs(ts))
		}
	}
	if got := OfEvent("rate_limit:api"); len(got) != 1 || got[0].ID != "T1499" {
		t.Errorf("a tarpit event was tagged %v", IDs(got))
	}
	// A bare reason no kind claims still carries nothing.
	if got := OfEvent("acl_deny"); got != nil {
		t.Errorf("an access-list refusal was tagged %v", IDs(got))
	}
}

func TestTheLogFieldsAreJoinedAndDeduplicated(t *testing.T) {
	ts := Of("modbus", "unsafe_sub_function")
	if len(ts) != 2 {
		t.Fatalf("unsafe_sub_function carries %d techniques", len(ts))
	}
	if got := IDs(ts); got != "T0816,T0804" {
		t.Errorf("ids %q", got)
	}
	if got := Tactics(ts); got != "inhibit-response-function" {
		t.Errorf("two techniques under one tactic should read as one tactic, got %q", got)
	}
	if got := Names(ts); !strings.Contains(got, "Device Restart/Shutdown") {
		t.Errorf("names %q", got)
	}
	if got := IDs(Of("modbus", "read_only")); got != "T0855,T0835" {
		t.Errorf("a single reason with two techniques: %q", got)
	}
}

// The matrix field, which is the whole point of carrying two catalogues:
// a plant refusal reads as ICS, an estate refusal as enterprise, and the
// refusals that are both say so.
func TestTheMatrixFieldSaysWhichCataloguesAnEventIsIn(t *testing.T) {
	for _, c := range []struct{ kind, reason, want string }{
		{"modbus", "read_only", "ics"},
		{"ldap", "leading_wildcard", "enterprise"},
		{"ssh", "no_grant", "ics,enterprise"},
		{"coap", "client_not_allowed", "ics,enterprise"},
	} {
		if got := Matrices(Of(c.kind, c.reason)); got != c.want {
			t.Errorf("%s/%s matrix %q, want %q", c.kind, c.reason, got, c.want)
		}
	}
	if got := Matrices(nil); got != "" {
		t.Errorf("no techniques should be no matrix, got %q", got)
	}
}

func TestGetIsForgivingAboutHowAPackWritesAnIdentifier(t *testing.T) {
	for _, s := range []string{"T0855", "t0855", " T0855 ", "t1021.004"} {
		if _, ok := Get(s); !ok {
			t.Errorf("Get(%q) found nothing", s)
		}
	}
	if _, ok := Get("T9999"); ok {
		t.Error("an identifier nothing here can observe was accepted")
	}
}

// Every kind a daemon of this project serves tags something. A kind with
// no mapping at all is a kind whose refusals reach a SIEM as strings
// nobody can catalogue, which is the gap this package exists to close --
// and the reason the table covers the estate rather than only the plant.
func TestEveryKindThisProjectServesTagsSomething(t *testing.T) {
	for _, kind := range listener.Kinds() {
		if len(byKindReason[kind]) == 0 {
			t.Errorf("kind %s tags nothing", kind)
		}
	}
}

// The gate's own kinds carry both readings, because a bastion is how an
// OT estate is entered and how an IT estate is moved through.
func TestTheGateCarriesBothMatrices(t *testing.T) {
	for _, kind := range grantKinds {
		ts := Of(kind, "no_grant")
		if len(ts) == 0 {
			t.Fatalf("%s: a session with no access grant is not tagged", kind)
		}
		if got := Matrices(ts); got != "ics,enterprise" {
			t.Errorf("%s/no_grant matrix %q", kind, got)
		}
	}
	// And the ledger's other refusals are tagged like the first: a grant
	// that expired mid-session is the same behaviour as none at all.
	if got := IDs(Of("ssh", "grant_expired")); got != "T0886,T1133,T1078" {
		t.Errorf("ssh/grant_expired: %q", got)
	}
}
