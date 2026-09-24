// Package sessions is the table of sessions a daemon is serving now, and
// the one operation an operator needs on them: close this one.
//
// A bastion without this is a bastion where the answer to "who is on the
// production database right now, and can you get them off" is "restart
// the daemon, which drops everybody". Every kind that holds a session for
// longer than a request -- the four remote access gateways, the FTP relay
// and the machine protocols that keep a connection per device -- registers
// here, and the management plane lists and closes them.
//
// Three rules shape it. A session is registered with its own closer,
// because only the kind knows what ending its session means -- an SSH
// connection, an RFB stream, a Modbus device's serialised queue -- and a
// table that closed sockets itself would be racing the kind that owns
// them. The table is bounded, since a session is one connection and
// connections are what an attacker sends. And everything it reports came
// off the network -- a login, a desktop name, a device identifier -- so
// what it prints is clipped and filtered by the caller that prints it.
package sessions

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// MaxSessions bounds the table. It is far above any real bastion's
// concurrency and far below what would cost memory worth counting; a
// listener's own max_connections is the bound that matters in practice.
const MaxSessions = 65536

// Info is what a kind says about a session when it registers one.
type Info struct {
	// Kind is the listener kind, Listener its name.
	Kind, Listener string
	// Client is where it came from and Target where it went, as the
	// addresses they were: a listener's peer address is a string
	// everywhere else in this proxy, and parsing one here to print it
	// again would only add a way to fail.
	Client, Target string
	// User is the login or principal, where the protocol has one.
	User string
	// Detail is one field the kind chooses: the desktop's name, the unit
	// identifier, the subsystem.
	Detail string
	// Started is when the session began. Zero means now.
	Started time.Time
}

// Session is one live session, as the table holds it. It is the handle a
// kind keeps: Done when the session ends, Killed to tell an operator's
// closure apart from either end hanging up.
type Session struct {
	// ID is what an operator names to close it: short, random and
	// unguessable, so an identifier seen in a log cannot be used to
	// close a session by somebody who never saw the table.
	ID string
	Info

	closed atomic.Bool
	close  func()
	table  *Table
}

// View is a session in a form that can be written to JSON, with the
// duration resolved so a reader does not have to subtract timestamps.
type View struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Listener   string `json:"listener"`
	Client     string `json:"client"`
	Target     string `json:"target,omitempty"`
	User       string `json:"user,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Started    string `json:"started"`
	DurationMS int64  `json:"duration_ms"`
}

// Table is every live session of one daemon.
type Table struct {
	mu   sync.Mutex
	byID map[string]*Session
	// Opened and Closed count the whole history, so a status view can
	// say how many sessions a daemon has served and not only how many it
	// is serving.
	Opened, Closed, Killed, Refused atomic.Uint64
}

// New returns an empty table. A nil table is safe for every method, so a
// kind that is not registered anywhere writes no conditionals.
func New() *Table { return &Table{byID: map[string]*Session{}} }

// Register adds a session and returns it. The closer is called by Kill
// and must be safe to call from another goroutine and more than once.
// A table at its bound refuses, and the caller carries on: refusing to
// serve a session because it could not be listed would be the table
// deciding policy, which is not its job.
func (t *Table) Register(info Info, close func()) *Session {
	if t == nil {
		return nil
	}
	id, err := newID()
	if err != nil {
		t.Refused.Add(1)
		return nil
	}
	if info.Started.IsZero() {
		info.Started = time.Now()
	}
	s := &Session{ID: id, Info: info, close: close, table: t}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.byID) >= MaxSessions {
		t.Refused.Add(1)
		return nil
	}
	t.byID[id] = s
	t.Opened.Add(1)
	return s
}

// Annotate fills in what was not known when the session was registered:
// the login after authentication, the target after it is dialled, the
// desktop's name or the unit identifier once the protocol says it. Empty
// values leave what is there, so a caller can set one field.
//
// A session is registered before the handshake on purpose -- a session
// stuck in one is a session an operator wants to see and close -- which
// is why the interesting fields arrive later.
func (s *Session) Annotate(user, target, detail string) {
	if s == nil || s.table == nil {
		return
	}
	s.table.mu.Lock()
	defer s.table.mu.Unlock()
	if user != "" {
		s.User = user
	}
	if target != "" {
		s.Target = target
	}
	if detail != "" {
		s.Detail = detail
	}
}

// Done removes a session that ended on its own. It is safe on a nil
// session, which is what Register returns when the table refused.
func (s *Session) Done() {
	if s == nil || s.table == nil {
		return
	}
	s.table.mu.Lock()
	delete(s.table.byID, s.ID)
	s.table.mu.Unlock()
	s.table.Closed.Add(1)
}

// Killed reports whether this session was closed by an operator rather
// than by either end. A kind logs the difference: a session an operator
// cut is not a client that hung up.
func (s *Session) Killed() bool { return s != nil && s.closed.Load() }

// Name is the identifier a kind puts in its own log lines, so a line and
// the table can be tied together. It is empty when nothing registered.
func (s *Session) Name() string {
	if s == nil {
		return ""
	}
	return s.ID
}

// List is every live session, oldest first: the order an operator reads.
//
// The views are built while the lock is held, because Annotate writes the
// login and the target from the goroutine serving the session, and a view
// assembled outside the lock would be reading those fields as they are
// written.
func (t *Table) List() []View {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*Session, 0, len(t.byID))
	for _, s := range t.byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	views := make([]View, 0, len(out))
	now := time.Now()
	for _, s := range out {
		views = append(views, s.view(now))
	}
	return views
}

// Kill closes one session by identifier and reports whether this call is
// what closed it. A session already closing is not closed again, so an
// operator who repeats the command, and a filter that overlaps one, get
// the truth rather than a second closure the kind never saw.
//
// The session is removed from the table by whichever goroutine notices
// its socket close, not here: a table that forgot a session before it
// ended would say the session was gone while it was still draining.
func (t *Table) Kill(id string) (View, bool) {
	if t == nil || id == "" {
		return View{}, false
	}
	// The view is taken under the lock, because Annotate writes those
	// fields from the goroutine serving the session.
	t.mu.Lock()
	s := t.byID[id]
	var v View
	if s != nil {
		v = s.view(time.Now())
	}
	t.mu.Unlock()
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return View{}, false
	}
	t.Killed.Add(1)
	if s.close != nil {
		s.close()
	}
	return v, true
}

// KillWhere closes every session matching a filter and returns what it
// closed. It is how an operator gets one person, one listener or one
// device off at once, which is the shape of a real incident.
func (t *Table) KillWhere(match func(View) bool) []View {
	if t == nil || match == nil {
		return nil
	}
	var out []View
	for _, v := range t.List() {
		if !match(v) {
			continue
		}
		if killed, ok := t.Kill(v.ID); ok {
			out = append(out, killed)
		}
	}
	return out
}

// view is one session as JSON. It reads the annotated fields, so every
// caller holds the table's lock.
func (s *Session) view(now time.Time) View {
	return View{
		ID: s.ID, Kind: s.Kind, Listener: s.Listener,
		Client: s.Client, Target: s.Target, User: s.User, Detail: s.Detail,
		Started: s.Started.UTC().Format(time.RFC3339Nano), DurationMS: now.Sub(s.Started).Milliseconds(),
	}
}

// Len is how many sessions are live.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.byID)
}

// Status is the counters, for the status view.
type Status struct {
	Live    int    `json:"live"`
	Opened  uint64 `json:"opened"`
	Closed  uint64 `json:"closed"`
	Killed  uint64 `json:"killed"`
	Refused uint64 `json:"refused"`
}

// Status reports the totals.
func (t *Table) Status() Status {
	if t == nil {
		return Status{}
	}
	return Status{Live: t.Len(), Opened: t.Opened.Load(), Closed: t.Closed.Load(),
		Killed: t.Killed.Load(), Refused: t.Refused.Load()}
}

// newID is eight random bytes as hex. Random rather than sequential
// because the identifier appears in logs an operator may share, and a
// counter would say how many sessions a daemon has served.
func newID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
