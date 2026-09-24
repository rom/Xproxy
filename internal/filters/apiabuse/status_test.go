package apiabuse

import (
	"testing"

	"github.com/rom/xproxy/internal/filter"
)

// The data plane reports the filters by asking the package, because it
// has no handle on the instances a generation built. So a filter has to
// join the registry when it is built and leave it when its generation is
// torn down: one that stayed would be reported to an operator long after
// the reload that removed it.
func TestALiveFilterIsReportedAndAClosedOneIsNot(t *testing.T) {
	if got := Statuses(); len(got) != 0 {
		t.Fatalf("the registry starts with %d filters: %v", len(got), got)
	}
	f := build(t, filter.Options{"max_objects": 4})
	ask(f, "1", 0)
	ask(f, "2", 0)
	st := Statuses()
	if len(st) != 1 {
		t.Fatalf("%d filters reported, want the one built", len(st))
	}
	if st[0].Name != "abuse" || st[0].Requests != 2 || st[0].Objects != 2 {
		t.Errorf("reported %+v, want the filter's own counts", st[0])
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := Statuses(); len(got) != 0 {
		t.Errorf("a closed filter is still reported: %v", got)
	}
}

// The report is ordered by name, so two filters do not swap places
// between two scrapes of the same process.
func TestFiltersAreReportedByName(t *testing.T) {
	for _, name := range []string{"zulu", "alpha"} {
		f, err := New(name, filter.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
	}
	st := Statuses()
	if len(st) != 2 || st[0].Name != "alpha" || st[1].Name != "zulu" {
		t.Errorf("reported %+v, want alpha before zulu", st)
	}
}
