package tftp

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/learn"
	wire "github.com/rom/xproxy/internal/tftp"
)

// The order the learned subjects are written in.
//
// A learning report is a file an engineer reads and then pastes rules
// out of, so the order has to be stable and it has to be one a person
// can follow: by client, then by what the client did, then by what the
// path was, then by the directory. An unstable order would make every
// report a diff against the last one for no reason, and a reader who
// cannot find a client in it writes the rules from memory instead.
func TestTheLearnedSubjectsSortByClientThenByWhatItDid(t *testing.T) {
	base := learnKey{client: "10.0.0.5", op: wire.OpRead, class: wire.ClassPlain, dir: "boot"}
	for _, tc := range []struct {
		name string
		a, b learnKey
		less bool
	}{
		{"the same key is not less than itself", base, base, false},
		{
			"a lower address first",
			learnKey{client: "10.0.0.4"}, learnKey{client: "10.0.0.5"}, true,
		},
		{
			"and the address decides before anything else",
			learnKey{client: "10.0.0.5", op: wire.OpRead},
			learnKey{client: "10.0.0.4", op: wire.OpWrite},
			false,
		},
		{
			"then the operation",
			learnKey{client: "10.0.0.5", op: wire.OpRead},
			learnKey{client: "10.0.0.5", op: wire.OpWrite},
			wire.OpRead < wire.OpWrite,
		},
		{
			"then the path class",
			learnKey{client: "10.0.0.5", op: wire.OpRead, class: wire.ClassPlain},
			learnKey{client: "10.0.0.5", op: wire.OpRead, class: wire.ClassAbsolute},
			wire.ClassPlain < wire.ClassAbsolute,
		},
		{
			"and last the directory",
			learnKey{client: "10.0.0.5", op: wire.OpRead, class: wire.ClassPlain, dir: "boot"},
			learnKey{client: "10.0.0.5", op: wire.OpRead, class: wire.ClassPlain, dir: "config"},
			true,
		},
	} {
		if got := learnLessTFTP(tc.a, tc.b); got != tc.less {
			t.Errorf("%s: less = %v, want %v", tc.name, got, tc.less)
		}
	}
}

// The three options a learning report records are bounds, and they
// arrive as text from a client -- so a value that is not a number is
// the option not being asked for rather than a zero that reads as one.
func TestTheRecordedOptionsAreReadFromTheClientsOwnText(t *testing.T) {
	for _, tc := range []struct {
		in   string
		def  int
		want int
	}{
		{"512", 0, 512},
		{"", 0, 0},
		{"", 7, 7},
		{"not a number", 0, 0},
		{"512x", 3, 3},
		{"-1", 0, 0},
		// Past a terabyte the value is refused rather than carried: a
		// transfer size is a bound, and a bound nobody could mean is
		// the default instead.
		{"99999999999999", 0, 0},
	} {
		if got := atoiOr(tc.in, tc.def); got != tc.want {
			t.Errorf("atoiOr(%q, %d) = %d, want %d", tc.in, tc.def, got, tc.want)
		}
	}
	// No request at all records no options, which is the ordinary case
	// for the acknowledgements and the data that follow one.
	if block, window, size := askedFor(nil); block != 0 || window != 0 || size != 0 {
		t.Errorf("askedFor(nil) = %d, %d, %d", block, window, size)
	}
}

// A report of nothing, which is what a listener that learned in a quiet
// window writes. It says so in a line a reader can tell from a report
// that failed to write, and nothing downstream has to special-case an
// empty file.
func TestALearningReportOfNothingSaysSo(t *testing.T) {
	out := renderLearnedTFTP("boot", nil, learn.Stats{})
	if !strings.Contains(out, "observed:\n  []\n") {
		t.Errorf("an empty report does not say it is empty:\n%s", out)
	}
	// And the learner is not built at all without a configuration that
	// asked for one, so nothing records when nothing was requested.
	if l := newLearner(nil); l != nil {
		t.Error("a learner was built from no configuration")
	}
	if l := newLearner(&learnConfig{}); l != nil {
		t.Error("a learner was built from a disabled configuration")
	}
}
