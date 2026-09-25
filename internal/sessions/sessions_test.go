package sessions

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The table is what a bastion's "who is on, and get them off" comes down
// to, so the tests are about exactly that: a session appears, an operator
// closes it by name or by filter, the kind is told, and nothing the table
// does can be used to close a session somebody never saw.

func TestASessionAppearsAndCanBeClosed(t *testing.T) {
	tab := New()
	closed := make(chan struct{})
	s := tab.Register(Info{Kind: "ssh", Listener: "bastion", Client: "10.0.0.9:52344"},
		func() { close(closed) })
	if s == nil {
		t.Fatal("the table refused a session")
	}
	s.Annotate("alice", "db-1:22", "deploy")
	live := tab.List()
	if len(live) != 1 {
		t.Fatalf("%d sessions listed", len(live))
	}
	got := live[0]
	if got.Kind != "ssh" || got.User != "alice" || got.Target != "db-1:22" || got.Detail != "deploy" {
		t.Fatalf("listed %+v", got)
	}
	if got.ID != s.ID || len(got.ID) != 16 {
		t.Fatalf("id %q", got.ID)
	}
	if _, ok := tab.Kill(got.ID); !ok {
		t.Fatal("the session was not there to close")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the kind was never told to close the session")
	}
	if !s.Killed() {
		t.Error("the session does not know an operator closed it")
	}
	// The table still holds it: the kind removes it when its own
	// goroutine notices the socket close, and a table that forgot first
	// would report a session gone while it was still draining.
	if tab.Len() != 1 {
		t.Errorf("%d live after a kill", tab.Len())
	}
	s.Done()
	if tab.Len() != 0 {
		t.Errorf("%d live after Done", tab.Len())
	}
	st := tab.Status()
	if st.Opened != 1 || st.Closed != 1 || st.Killed != 1 {
		t.Errorf("status %+v", st)
	}
}

func TestClosingTwiceCallsTheKindOnce(t *testing.T) {
	tab := New()
	var n int
	var mu sync.Mutex
	s := tab.Register(Info{Kind: "vnc"}, func() { mu.Lock(); n++; mu.Unlock() })
	for i := 0; i < 3; i++ {
		tab.Kill(s.ID)
	}
	mu.Lock()
	defer mu.Unlock()
	if n != 1 {
		t.Fatalf("the kind was told to close %d times", n)
	}
	if got := tab.Status().Killed; got != 1 {
		t.Errorf("killed counted %d times", got)
	}
}

func TestAFilterClosesASetAndNothingElse(t *testing.T) {
	tab := New()
	var closed sync.Map
	for _, tc := range []struct{ kind, listener, user string }{
		{"ssh", "bastion", "alice"},
		{"ssh", "bastion", "bob"},
		{"vnc", "desks", "alice"},
		{"modbus", "line-2", "engineer"},
	} {
		info := Info{Kind: tc.kind, Listener: tc.listener}
		s := tab.Register(info, func() {})
		s.Annotate(tc.user, "", "")
		closed.Store(s.ID, false)
	}
	got := tab.KillWhere(func(v View) bool { return v.Kind == "ssh" })
	if len(got) != 2 {
		t.Fatalf("closed %d sessions, want the two ssh ones", len(got))
	}
	for _, v := range got {
		if v.Kind != "ssh" {
			t.Errorf("closed a %s session", v.Kind)
		}
	}
	// By login, across kinds.
	byUser := tab.KillWhere(func(v View) bool { return v.User == "alice" })
	if len(byUser) != 1 || byUser[0].Kind != "vnc" {
		t.Fatalf("by user: %+v", byUser)
	}
	if got := tab.Status().Killed; got != 3 {
		t.Errorf("killed %d", got)
	}
}

func TestAnIdentifierThatIsNotThereIsNotAKill(t *testing.T) {
	tab := New()
	if _, ok := tab.Kill("0000000000000000"); ok {
		t.Error("a session nobody registered was closed")
	}
	if _, ok := tab.Kill(""); ok {
		t.Error("an empty identifier closed something")
	}
	// The identifiers are random rather than sequential: two in a row
	// must not be guessable from each other, because an id appears in
	// logs an operator may share.
	a := tab.Register(Info{Kind: "ssh"}, func() {})
	b := tab.Register(Info{Kind: "ssh"}, func() {})
	if a.ID == b.ID {
		t.Fatal("two sessions share an identifier")
	}
	if strings.TrimLeft(a.ID, "0123456789abcdef") != "" {
		t.Errorf("the identifier is not hex: %q", a.ID)
	}
	// And they are random rather than a counter. A counter would pass
	// every check above while telling anybody who sees one identifier
	// what the next one is, and telling anybody who sees any of them how
	// many sessions this daemon has served. Sixteen in a row must not
	// come out in order, which a counter's would, and must fill the
	// whole width rather than leaving the high bytes at zero.
	ids := make([]string, 0, 16)
	for i := 0; i < 16; i++ {
		s := tab.Register(Info{Kind: "ssh"}, func() {})
		if s == nil {
			t.Fatal("the table refused a session")
		}
		ids = append(ids, s.ID)
	}
	if slices.IsSorted(ids) {
		t.Errorf("the identifiers came out in order, so they are a counter: %v", ids)
	}
	var varies bool
	for _, id := range ids {
		if id[:8] != ids[0][:8] {
			varies = true
		}
	}
	if !varies {
		t.Errorf("the identifiers share their first half: %v", ids)
	}
}

func TestANilTableIsSafeEverywhere(t *testing.T) {
	var tab *Table
	if s := tab.Register(Info{Kind: "ssh"}, func() {}); s != nil {
		t.Error("a nil table registered a session")
	}
	if got := tab.List(); got != nil {
		t.Error("a nil table listed sessions")
	}
	if _, ok := tab.Kill("x"); ok {
		t.Error("a nil table killed a session")
	}
	if tab.Len() != 0 || tab.Status().Live != 0 {
		t.Error("a nil table counts sessions")
	}
	if got := tab.KillWhere(func(View) bool { return true }); got != nil {
		t.Error("a nil table killed a set")
	}
	// And a nil session, which is what Register returns when a table
	// refused: every method on it is a no-op rather than a panic, so a
	// kind writes no conditionals.
	var s *Session
	s.Annotate("a", "b", "c")
	s.Done()
	if s.Killed() || s.Name() != "" {
		t.Error("a nil session answers as if it were one")
	}
}

func TestTheTableIsBoundedAndSaysSo(t *testing.T) {
	tab := New()
	// The bound is large, so this drives the check rather than the
	// constant: fill the map to the bound with cheap sessions.
	tab.mu.Lock()
	for i := 0; i < MaxSessions; i++ {
		tab.byID[strconv.Itoa(i)] = &Session{}
	}
	tab.mu.Unlock()
	if s := tab.Register(Info{Kind: "ssh"}, func() {}); s != nil {
		t.Fatal("a session past the bound was registered")
	}
	if got := tab.Status().Refused; got != 1 {
		t.Errorf("refused %d", got)
	}
}

func TestListIsOldestFirst(t *testing.T) {
	tab := New()
	now := time.Now()
	for i, at := range []time.Time{now.Add(-time.Minute), now.Add(-time.Hour), now} {
		s := tab.Register(Info{Kind: "ssh", Started: at}, func() {})
		if s == nil {
			t.Fatalf("session %d refused", i)
		}
	}
	live := tab.List()
	if len(live) != 3 {
		t.Fatalf("%d listed", len(live))
	}
	if live[0].DurationMS < live[1].DurationMS || live[1].DurationMS < live[2].DurationMS {
		t.Errorf("not oldest first: %v", []int64{live[0].DurationMS, live[1].DurationMS, live[2].DurationMS})
	}
}

// Registering, listing and killing happen on different goroutines in a
// real daemon, so the table is driven from several at once under -race.
func TestTheTableIsSafeFromSeveralGoroutines(t *testing.T) {
	tab := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s := tab.Register(Info{Kind: "ssh", Listener: "bastion"}, func() {})
				s.Annotate("alice", "db:22", "")
				_ = tab.List()
				tab.Kill(s.ID)
				s.Done()
			}
		}()
	}
	wg.Wait()
	if tab.Len() != 0 {
		t.Errorf("%d sessions left", tab.Len())
	}
	if got := tab.Status().Opened; got != 400 {
		t.Errorf("opened %d", got)
	}
}
