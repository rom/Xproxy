package iec104

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
)

// group builds one compiled group, the way a listener would.
func oneGroup(t *testing.T, in config.IEC104RedundancyGroup) *group {
	t.Helper()
	g, err := compileRedundancy(&config.IEC104Redundancy{
		Groups: []config.IEC104RedundancyGroup{in}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(g.list) != 1 {
		t.Fatalf("compiled %d groups", len(g.list))
	}
	return g.list[0]
}

var (
	pathA = netip.MustParseAddr("10.40.0.1")
	pathB = netip.MustParseAddr("10.40.0.2")
	pathC = netip.MustParseAddr("10.40.0.3")
)

// Exactly one connection in a group carries data at a time. That is the
// standard's own rule, and it is what makes a group a control rather than
// bookkeeping: the group's other connections are open, and they may not
// command anything.
func TestOnlyOneConnectionInAGroupCarriesDataAtATime(t *testing.T) {
	g := oneGroup(t, config.IEC104RedundancyGroup{Name: "centre", Clients: []string{"10.40.0.0/24"}})
	if !g.join(1, pathA) || !g.join(2, pathB) {
		t.Fatal("the group refused its own paths")
	}
	// Before any STARTDT nobody holds it, so no connection may carry data.
	for _, id := range []uint64{1, 2} {
		if g.holds(id) {
			t.Errorf("connection %d holds data transfer before any STARTDT", id)
		}
	}
	if _, failover, ok := g.start(1, pathA); !ok || failover {
		t.Errorf("the first STARTDT was a failover (%t) or refused (%t)", failover, !ok)
	}
	if !g.holds(1) || g.holds(2) {
		t.Error("the wrong connection holds data transfer")
	}
	// A second STARTDT on the connection that already has it means nothing
	// happened, and the standard allows it.
	if prev, failover, ok := g.start(1, pathA); !ok || failover || prev.IsValid() {
		t.Errorf("a repeated STARTDT reported a failover: %v %t %t", prev, failover, ok)
	}
	// And a STOPDT from a standby connection releases nothing, which is
	// what it means.
	if g.stop(2) {
		t.Error("a standby connection stopped data transfer")
	}
	if !g.holds(1) {
		t.Error("a standby connection's STOPDT took data transfer away")
	}
	if !g.stop(1) || g.holds(1) {
		t.Error("the active connection could not stop data transfer")
	}
}

// A takeover is either a failover, logged and counted, or a refusal. Which
// one is the operator's choice, because on some estates the paths are moved
// deliberately and a concurrent takeover means something is wrong.
func TestATakeoverIsAFailoverOrARefusal(t *testing.T) {
	g := oneGroup(t, config.IEC104RedundancyGroup{Name: "centre", Clients: []string{"10.40.0.0/24"}})
	g.join(1, pathA)
	g.join(2, pathB)
	g.start(1, pathA)
	prev, failover, ok := g.start(2, pathB)
	if !ok || !failover || prev != pathA {
		t.Errorf("the takeover was %v %t %t, want a failover from %v", prev, failover, ok, pathA)
	}
	if !g.holds(2) || g.holds(1) {
		t.Error("data transfer did not move")
	}
	if g.failovers != 1 {
		t.Errorf("failovers %d", g.failovers)
	}

	strict := oneGroup(t, config.IEC104RedundancyGroup{Name: "centre",
		Clients: []string{"10.40.0.0/24"}, Takeover: "refuse"})
	strict.join(1, pathA)
	strict.join(2, pathB)
	strict.start(1, pathA)
	prev, _, ok = strict.start(2, pathB)
	if ok {
		t.Error("takeover: refuse allowed a concurrent takeover")
	}
	if prev != pathA {
		t.Errorf("the refusal named %v as the holder, want %v", prev, pathA)
	}
	if !strict.holds(1) || strict.holds(2) {
		t.Error("a refused takeover moved data transfer anyway")
	}
	if strict.refused != 1 {
		t.Errorf("refused %d", strict.refused)
	}
	// Once the path that held it is gone, the next STARTDT is not a
	// takeover at all: that is what a failover after a real outage is.
	strict.leave(1)
	if _, failover, ok := strict.start(2, pathB); !ok || failover {
		t.Errorf("a STARTDT after the holder left was %t %t", failover, ok)
	}
}

// The bound on a group's connections is a bound. A group holding more paths
// than the operator described is a client list that has caught something it
// should not, and the connection past it is refused rather than admitted
// into the set.
func TestAGroupIsFullAtItsBound(t *testing.T) {
	g := oneGroup(t, config.IEC104RedundancyGroup{Name: "centre",
		Clients: []string{"10.40.0.0/24"}, MaxConnections: 2})
	if !g.join(1, pathA) || !g.join(2, pathB) {
		t.Fatal("the group refused the paths it has room for")
	}
	if g.join(3, pathC) {
		t.Error("the bound was not a bound")
	}
	if g.crowded != 1 {
		t.Errorf("crowded %d", g.crowded)
	}
	// And a path that closes makes room, which is what a group whose
	// connections come and go needs.
	if empty := g.leave(1); empty {
		t.Error("a group with a connection left reported empty")
	}
	if !g.join(3, pathC) {
		t.Error("a closed path left no room")
	}
	if empty := g.leave(2); empty {
		t.Error("a group with a connection left reported empty")
	}
	if empty := g.leave(3); !empty {
		t.Error("a group with no connections did not report empty")
	}
}

// of is which group a client belongs to, and a client in no group is the
// ordinary case every listener written before this has.
func TestWhichGroupAClientBelongsTo(t *testing.T) {
	g, err := compileRedundancy(&config.IEC104Redundancy{
		Groups: []config.IEC104RedundancyGroup{
			{Name: "north", Clients: []string{"10.40.0.0/24"}},
			{Name: "south", Clients: []string{"10.41.0.0/24", "10.42.0.1/32"}},
		}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, c := range []struct {
		ip   string
		want string
	}{
		{"10.40.0.9", "north"},
		{"10.41.0.9", "south"},
		{"10.42.0.1", "south"},
		{"10.43.0.1", ""},
	} {
		got := g.of(netip.MustParseAddr(c.ip))
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%s was put in group %q", c.ip, got.name)
		case c.want != "" && (got == nil || got.name != c.want):
			t.Errorf("%s is in %v, want %q", c.ip, got, c.want)
		}
	}
	// A listener with no section at all.
	var none *groups
	if none.of(pathA) != nil || none.Active() != 0 || none.Status() != nil {
		t.Error("a listener with no redundancy section has a group")
	}
}

// A group is an assertion that a set of addresses is one controlling
// station. Each of these is a way of writing one that would not be an
// assertion at all.
func TestCompileRedundancyRefusesWhatWouldNotBeAnAssertion(t *testing.T) {
	for _, c := range []struct {
		what string
		in   config.IEC104RedundancyGroup
	}{
		{"no name", config.IEC104RedundancyGroup{Clients: []string{"10.40.0.0/24"}}},
		{"no clients", config.IEC104RedundancyGroup{Name: "centre"}},
		{"a client that is not a network", config.IEC104RedundancyGroup{
			Name: "centre", Clients: []string{"10.40.0.1"}}},
		{"no room for a connection", config.IEC104RedundancyGroup{
			Name: "centre", Clients: []string{"10.40.0.0/24"}, MaxConnections: -1}},
		{"more paths than a group has", config.IEC104RedundancyGroup{
			Name: "centre", Clients: []string{"10.40.0.0/24"}, MaxConnections: 99}},
		{"a takeover that is neither", config.IEC104RedundancyGroup{
			Name: "centre", Clients: []string{"10.40.0.0/24"}, Takeover: "maybe"}},
	} {
		if _, err := compileRedundancy(&config.IEC104Redundancy{
			Groups: []config.IEC104RedundancyGroup{c.in}}); err == nil {
			t.Errorf("%s: compiled", c.what)
		}
	}
	// Two groups with the same name would be one group with two client
	// lists, which is not what the file says.
	if _, err := compileRedundancy(&config.IEC104Redundancy{
		Groups: []config.IEC104RedundancyGroup{
			{Name: "centre", Clients: []string{"10.40.0.0/24"}},
			{Name: "centre", Clients: []string{"10.41.0.0/24"}},
		}}); err == nil {
		t.Error("two groups with one name compiled")
	}
	// And no section, or a section with no groups, is no redundancy
	// handling at all.
	for _, c := range []*config.IEC104Redundancy{nil, {}} {
		g, err := compileRedundancy(c)
		if err != nil || g != nil {
			t.Errorf("an empty section compiled to %v, %v", g, err)
		}
	}
	// The defaults are the ones the reference promises.
	g := oneGroup(t, config.IEC104RedundancyGroup{Name: "centre", Clients: []string{"10.40.0.0/24"}})
	if g.max != 4 || g.takeover != "switch" || !g.carry {
		t.Errorf("defaults: max %d, takeover %q, carry %t", g.max, g.takeover, g.carry)
	}
}

// The concession, and the reason the group has to be declared: a selection
// survives a failover inside it, so a two-step command whose select and
// execute land either side of one is not refused.
func TestASelectionSurvivesAFailoverInsideItsGroup(t *testing.T) {
	now := time.Now()
	s := newSelects(16, time.Minute, func() time.Time { return now })
	a := sc(1, 4321, wire.CauseActivation, true)
	// Both connections are in the group, and the group carries selections,
	// so they own their selections together.
	pathOne := selectOwner{group: "centre"}
	pathTwo := selectOwner{group: "centre"}

	if !s.Select(pathOne, a) {
		t.Fatal("the selection was not recorded")
	}
	// The path that made it goes. Its selection stays, because another path
	// in the group is still up.
	s.Close(1, "")
	if held, _ := s.Status(); held != 1 {
		t.Fatalf("the failover dropped the selection: %d held", held)
	}
	if took := s.Take(pathTwo, a); took != TakeOK {
		t.Errorf("the execute after the failover was %v", took)
	}
	// And one selection still authorises one execution, not a stream.
	if took := s.Take(pathTwo, a); took != TakeNone {
		t.Errorf("a consumed selection was consumed twice: %v", took)
	}
}

// When the whole association goes, so does the selection. One outliving a
// connection is the point of the group; one outliving the control centre is
// a selection nobody is waiting on.
func TestAGroupsSelectionsGoWithItsLastConnection(t *testing.T) {
	now := time.Now()
	s := newSelects(16, time.Minute, func() time.Time { return now })
	a := sc(1, 4321, wire.CauseActivation, true)
	owner := selectOwner{group: "centre"}
	if !s.Select(owner, a) {
		t.Fatal("select")
	}
	// The group's last connection names the group, which is what drops it.
	s.Close(2, "centre")
	if held, _ := s.Status(); held != 0 {
		t.Errorf("the last connection left %d selections", held)
	}
	if took := s.Take(owner, a); took != TakeNone {
		t.Errorf("a selection survived its whole group: %v", took)
	}
	// Another group's selection is not touched by this one's last
	// connection.
	other := selectOwner{group: "south"}
	if !s.Select(other, a) {
		t.Fatal("select")
	}
	s.Close(3, "centre")
	if held, _ := s.Status(); held != 1 {
		t.Errorf("closing one group dropped another's selection: %d held", held)
	}
}

// The interlock the user of a control room needs: an execute with no
// selection anywhere is somebody sending a bare command, and an execute
// whose selection was made on another connection in the same group is a
// two-step command that a failover dropped. Those are different things.
func TestASelectionOnAnotherConnectionInTheGroupIsItsOwnDiagnosis(t *testing.T) {
	now := time.Now()
	s := newSelects(16, time.Minute, func() time.Time { return now })
	a := sc(1, 4321, wire.CauseActivation, true)
	// A group that does *not* carry selections: each connection owns its
	// own, and the group name is still in the owner so that the refusal can
	// say which refusal it is.
	pathOne := selectOwner{group: "centre", session: 1}
	pathTwo := selectOwner{group: "centre", session: 2}

	if !s.Select(pathOne, a) {
		t.Fatal("select")
	}
	if took := s.Take(pathTwo, a); took != TakeOther {
		t.Errorf("the execute on the other path was %v, want TakeOther", took)
	}
	// And it did not consume the other path's selection: a refusal must not
	// spend the intention it refused.
	if held, _ := s.Status(); held != 1 {
		t.Errorf("a refused execute consumed another path's selection: %d held", held)
	}
	// A different point on the same path is still nothing at all.
	if took := s.Take(pathTwo, sc(1, 9999, wire.CauseActivation, false)); took != TakeNone {
		t.Errorf("an unselected point was %v", took)
	}
}

// And the guard that keeps the diagnosis from leaking: connections in no
// group all have the empty group name, and they must not be told about each
// other's selections.
func TestConnectionsInNoGroupDoNotShareTheDiagnosis(t *testing.T) {
	now := time.Now()
	s := newSelects(16, time.Minute, func() time.Time { return now })
	a := sc(1, 4321, wire.CauseActivation, true)
	if !s.Select(selectOwner{session: 1}, a) {
		t.Fatal("select")
	}
	// An unrelated client executing the same point on the same station is
	// told the point was never selected -- not that somebody else selected
	// it, which would be this relay reporting one client's intentions to
	// another.
	if took := s.Take(selectOwner{session: 2}, a); took != TakeNone {
		t.Errorf("an unrelated client was told about another's selection: %v", took)
	}
}

// The status view: the groups, whether each has a path carrying data, and
// the counts an operator reads after an incident.
func TestTheGroupStatusSaysWhatAnOperatorNeeds(t *testing.T) {
	g, err := compileRedundancy(&config.IEC104Redundancy{
		Groups: []config.IEC104RedundancyGroup{
			{Name: "north", Clients: []string{"10.40.0.0/24"}},
			{Name: "south", Clients: []string{"10.41.0.0/24"}},
		}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	north := g.list[0]
	north.join(1, pathA)
	north.join(2, pathB)
	north.start(1, pathA)
	north.start(2, pathB)
	if g.Active() != 1 {
		t.Errorf("%d groups carrying data, want 1", g.Active())
	}
	st := g.Status()
	if len(st) != 2 {
		t.Fatalf("%d groups in the status", len(st))
	}
	if st[0].Name != "north" || st[0].Members != 2 || !st[0].Active ||
		st[0].ActiveClient != pathB.String() || st[0].Failovers != 1 {
		t.Errorf("north: %+v", st[0])
	}
	if st[1].Active || st[1].Members != 0 {
		t.Errorf("south: %+v", st[1])
	}
}
