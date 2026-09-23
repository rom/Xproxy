package mfa

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/passwd"
)

// Enrolment is one user's second factor.
type Enrolment struct {
	User   string
	Secret []byte
	Params Params
	// Recovery are hashes of single-use recovery codes, in the same
	// form as a users file. A code that is used is spent: the file is
	// not rewritten, so the guard remembers which, and the operator
	// re-enrols the user afterwards.
	Recovery []string
}

// Store is the enrolment file, read once. The format is one user per
// line:
//
//	alice:JBSWY3DPEHPK3PXPJBSWY3DPEH
//	bob:JBSWY3DPEHPK3PXPJBSWY3DPEH:digits=6,period=30,algo=SHA1
//	carol:JBSWY3DPEHPK3PXPJBSWY3DPEH::pbkdf2$...,pbkdf2$...
//
// The secret is base32 and at least 128 bits, which is what RFC 4226
// asks for and what the example above is: a shorter one is refused
// rather than accepted and quietly weaker.
//
// Fields after the secret are optional: parameters, then recovery code
// hashes. Blank lines and lines beginning with # are ignored.
type Store struct {
	// path is the file, and empty for a store built in memory.
	path string
	mu   sync.RWMutex
	// writeMu serialises changes: a read-modify-write of the file that
	// two callers interleaved would lose one of them.
	writeMu sync.Mutex
	byUser  map[string]*Enrolment
	// stat is what the file looked like when byUser was read from it,
	// and checked when that was last confirmed.
	stat    fileStamp
	checked time.Time
	// Warn receives a re-read that failed. What is in memory stays in
	// force in that case, so a half-written file does not enrol or
	// un-enrol anybody. It is set once before serving.
	Warn func(error)
}

// Load reads an enrolment file. A line that does not parse fails the
// load: a user who was meant to be enrolled and silently is not is a
// door left open, and one who was meant to be removed and is not is
// worse.
func Load(path string) (*Store, error) {
	byUser, stamp, err := readFile(path, false)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, byUser: byUser, stat: stamp, checked: time.Now()}, nil
}

// readFile parses the file. allowEmpty is false for the first read and
// true for every one after it: a configuration pointing at an empty
// file is almost certainly the wrong file, while a file that has become
// empty while the proxy runs is an operator who removed the last
// enrolment -- and refusing to notice that would leave the person
// enrolled, which is the failure this package exists to avoid.
func readFile(path string, allowEmpty bool) (map[string]*Enrolment, fileStamp, error) {
	// The stamp is taken before the read, so a file rewritten during it
	// is re-read next time rather than remembered as current.
	stamp := stampOf(path)
	f, err := os.Open(path) //nolint:gosec // a path from the configuration
	if err != nil {
		return nil, stamp, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o004 != 0 {
		return nil, stamp, fmt.Errorf("%s must not be world readable: it holds every second factor", path)
	}
	byUser := map[string]*Enrolment{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		e, err := parseLine(text)
		if err != nil {
			return nil, stamp, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if _, dup := byUser[e.User]; dup {
			return nil, stamp, fmt.Errorf("%s:%d: %q is enrolled twice", path, line, e.User)
		}
		byUser[e.User] = e
	}
	if err := sc.Err(); err != nil {
		return nil, stamp, err
	}
	if len(byUser) == 0 && !allowEmpty {
		return nil, stamp, errors.New("no enrolments in the file")
	}
	return byUser, stamp, nil
}

func parseLine(text string) (*Enrolment, error) {
	parts := strings.Split(text, ":")
	if len(parts) < 2 || parts[0] == "" {
		return nil, errors.New("expected user:secret")
	}
	e := &Enrolment{User: parts[0]}
	secret, err := ParseSecret(parts[1])
	if err != nil {
		return nil, err
	}
	e.Secret = secret
	if len(parts) > 2 && parts[2] != "" {
		p, err := parseParams(parts[2])
		if err != nil {
			return nil, err
		}
		e.Params = p
	}
	if len(parts) > 3 && parts[3] != "" {
		for _, h := range strings.Split(parts[3], ",") {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			if !passwd.IsHash(h) {
				return nil, errors.New("recovery codes must be stored as hashes, not in clear")
			}
			e.Recovery = append(e.Recovery, h)
		}
	}
	if len(parts) > 4 {
		return nil, errors.New("too many fields")
	}
	return e, nil
}

func parseParams(s string) (Params, error) {
	var p Params
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return p, fmt.Errorf("parameter %q is not key=value", kv)
		}
		switch k {
		case "digits":
			n, err := strconv.Atoi(v)
			if err != nil || n < 6 || n > 10 {
				return p, errors.New("digits must be 6..10")
			}
			p.Digits = n
		case "period":
			n, err := strconv.Atoi(v)
			if err != nil || n < 10 || n > 300 {
				return p, errors.New("period must be 10..300 seconds")
			}
			p.Period = time.Duration(n) * time.Second
		case "algo":
			if _, err := newHash(v); err != nil {
				return p, err
			}
			p.Algo = strings.ToUpper(v)
		default:
			return p, fmt.Errorf("unknown parameter %q", k)
		}
	}
	return p, nil
}

// Get returns a user's enrolment, re-reading the file first if it has
// changed.
func (s *Store) Get(user string) (*Enrolment, bool) {
	if s == nil {
		return nil, false
	}
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byUser[user]
	return e, ok
}

// Users returns the enrolled names, for a status view.
func (s *Store) Users() []string {
	if s == nil {
		return nil
	}
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.byUser))
	for u := range s.byUser {
		out = append(out, u)
	}
	return out
}

// Guard verifies codes and holds the state a one-time password needs:
// which step a user last spent, which recovery codes are gone, and how
// many recent failures there have been.
//
// The state is per process. In a cluster each node holds its own, so a
// code can be replayed once per node; where that matters, put the
// bastion or the listener behind a single node, or accept the window
// and keep the skew at zero.
type Guard struct {
	store   *Store
	skew    int
	lockout Lockout

	mu    sync.Mutex
	users map[string]*userState
}

// Lockout bounds guessing. A six-digit code has a million values and a
// step lasts thirty seconds, so without a bound a client that can try
// fast enough gets a real chance at each step.
type Lockout struct {
	// MaxFailures within Window locks the user out for Duration.
	MaxFailures int
	Window      time.Duration
	Duration    time.Duration
	// MaxUsers bounds the state table. When it is full the oldest
	// entries are dropped, which loses replay memory for those users
	// rather than refusing everyone.
	MaxUsers int
}

type userState struct {
	lastStep  uint64
	spent     map[int]bool // recovery codes used
	failures  []time.Time
	lockUntil time.Time
	seen      time.Time
}

// NewGuard builds a guard over a store.
func NewGuard(s *Store, skew int, l Lockout) *Guard {
	if l.MaxFailures <= 0 {
		l.MaxFailures = 5
	}
	if l.Window <= 0 {
		l.Window = 5 * time.Minute
	}
	if l.Duration <= 0 {
		l.Duration = 15 * time.Minute
	}
	if l.MaxUsers <= 0 {
		l.MaxUsers = 10000
	}
	return &Guard{store: s, skew: skew, lockout: l, users: map[string]*userState{}}
}

// Enrolled reports whether a user has a second factor.
func (g *Guard) Enrolled(user string) bool {
	_, ok := g.store.Get(user)
	return ok
}

// Verify checks one code for a user at a moment. The error says why it
// failed, for the log; what the client is told never distinguishes an
// unknown user from a wrong code.
func (g *Guard) Verify(user, code string, now time.Time) error {
	e, ok := g.store.Get(user)
	if !ok {
		// A name with no enrolment costs what one with an enrolment
		// costs. The reply already refuses to say which it was; timing
		// must not answer it either.
		equaliseVerify(code, g.skew)
		return ErrUnknownUser
	}
	g.mu.Lock()
	st := g.state(user, now)
	if now.Before(st.lockUntil) {
		g.mu.Unlock()
		return ErrLocked
	}
	lastStep := st.lastStep
	spent := make(map[int]bool, len(st.spent))
	for k, v := range st.spent {
		spent[k] = v
	}
	g.mu.Unlock()

	step, ok := Check(e.Secret, code, now, e.Params, g.skew)
	switch {
	case ok && step <= lastStep && lastStep != 0:
		// Verified, but this step is spent. Counted as a failure:
		// replaying is not a typo.
		g.fail(user, now)
		return ErrReplay
	case ok:
		g.succeed(user, now, step, -1)
		return nil
	}
	// Recovery codes are tried only when the time-based code failed, so
	// a working authenticator never spends one -- and only when what
	// arrived is shaped like one. A code of digits is not a recovery
	// code, and comparing it against every stored hash is work a
	// client could ask for by sending anything.
	// Every attempt does the same number of comparisons, whatever the
	// enrolment holds: the codes it has, padded with a hash nothing
	// matches. Spent codes are compared too, and the first unspent
	// match wins. So neither how many codes a person has, nor how many
	// they have spent, can be read off a clock -- and nor, with the
	// same work done for a name that has no enrolment at all, can
	// whether they are enrolled.
	matched := -1
	for i := 0; i < max(RecoveryCodes, len(e.Recovery)); i++ {
		h := dummyRecovery
		if i < len(e.Recovery) {
			h = e.Recovery[i]
		}
		if passwd.Verify(h, code) && i < len(e.Recovery) && !spent[i] && matched < 0 {
			matched = i
		}
	}
	if matched >= 0 {
		g.succeed(user, now, lastStep, matched)
		return nil
	}
	g.fail(user, now)
	return ErrBadCode
}

// dummySecret is a secret that verifies nothing, used to spend on an
// unknown name what a known one costs.
var dummySecret = []byte{
	0x78, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x64,
	0x75, 0x6d, 0x6d, 0x79, 0x2d, 0x6d, 0x66, 0x61,
}

// dummyRecovery is a hash nothing will match, at what a real one
// costs. The password package has a dummy of its own, but it is a
// password's hash: using it here made an unknown name cost six hundred
// times what a known one did, which is the same oracle upside down.
var dummyRecovery = func() string {
	h, err := passwd.HashWithIterations("xproxy: no such recovery code", recoveryIterations)
	if err != nil {
		panic(err)
	}
	return h
}()

// equaliseVerify does the work a real verification does, and throws it
// away. It is the same arrangement the password checks use: the point
// is not that the answer is useful, it is that the two paths cost the
// same.
func equaliseVerify(code string, skew int) {
	_, _ = Check(dummySecret, code, time.Now(), Params{}, skew)
	// As many comparisons as an enrolment's worth of codes, since that
	// is what the real path does.
	for i := 0; i < RecoveryCodes; i++ {
		_ = passwd.Verify(dummyRecovery, code)
	}
}

// state returns the user's entry, making one and evicting if needed.
// Caller holds mu.
func (g *Guard) state(user string, now time.Time) *userState {
	if st, ok := g.users[user]; ok {
		st.seen = now
		return st
	}
	if len(g.users) >= g.lockout.MaxUsers {
		// Drop the least recently seen quarter rather than refusing new
		// users: losing replay memory for an idle user is a bounded
		// harm, and refusing everyone is not.
		oldest := time.Time{}
		for _, st := range g.users {
			if oldest.IsZero() || st.seen.Before(oldest) {
				oldest = st.seen
			}
		}
		cut := oldest.Add(now.Sub(oldest) / 4)
		for u, st := range g.users {
			if st.seen.Before(cut) {
				delete(g.users, u)
			}
		}
		if len(g.users) >= g.lockout.MaxUsers {
			g.users = map[string]*userState{}
		}
	}
	st := &userState{spent: map[int]bool{}, seen: now}
	g.users[user] = st
	return st
}

func (g *Guard) succeed(user string, now time.Time, step uint64, recovery int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(user, now)
	if step > st.lastStep {
		st.lastStep = step
	}
	if recovery >= 0 {
		st.spent[recovery] = true
	}
	st.failures = nil
}

func (g *Guard) fail(user string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state(user, now)
	cut := now.Add(-g.lockout.Window)
	kept := st.failures[:0]
	for _, t := range st.failures {
		if t.After(cut) {
			kept = append(kept, t) //nolint:gocritic // filtering in place, which is why the target is the same slice
		}
	}
	kept = append(kept, now)
	st.failures = kept
	if len(st.failures) >= g.lockout.MaxFailures {
		st.lockUntil = now.Add(g.lockout.Duration)
		st.failures = nil
	}
}

// Locked reports whether a user is currently locked out, for a status
// view; it does not change the state.
func (g *Guard) Locked(user string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.users[user]
	return ok && now.Before(st.lockUntil)
}

// Unlock clears a user's lockout and their recent failures, which is
// what an operator does for somebody whose authenticator was out of
// step. It does not clear the replay memory: a code that was spent
// stays spent, because unlocking is forgiveness for guessing wrong and
// not permission to reuse one.
func (g *Guard) Unlock(user string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.users[user]
	if !ok {
		return false
	}
	was := !st.lockUntil.IsZero() || len(st.failures) > 0
	st.lockUntil, st.failures = time.Time{}, nil
	return was
}

// Store is the enrolment file behind the guard, which is what a control
// plane changes.
func (g *Guard) Store() *Store {
	if g == nil {
		return nil
	}
	return g.store
}

// GuardStatus is one user as a status view sees them.
type GuardStatus struct {
	Status
	// Locked says the user cannot try again yet, and LockedUntil when
	// that ends.
	Locked      bool      `json:"locked"`
	LockedUntil time.Time `json:"locked_until,omitzero"`
	// Failures is how many recent wrong codes are remembered, and Spent
	// how many recovery codes this process has seen used.
	Failures int `json:"failures"`
	Spent    int `json:"recovery_spent"`
}

// List describes every enrolment with what this process remembers
// about it. The secret is never in it.
func (g *Guard) List(now time.Time) []GuardStatus {
	if g == nil {
		return nil
	}
	enrolled := g.store.List()
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]GuardStatus, 0, len(enrolled))
	for _, e := range enrolled {
		gs := GuardStatus{Status: e}
		if st, ok := g.users[e.User]; ok {
			gs.Failures, gs.Spent = len(st.failures), len(st.spent)
			if now.Before(st.lockUntil) {
				gs.Locked, gs.LockedUntil = true, st.lockUntil
			}
		}
		out = append(out, gs)
	}
	return out
}

// Forget drops what this process remembers about a user, which is what
// removing an enrolment should also do: leaving the state behind would
// lock out the next person enrolled under the same name.
func (g *Guard) Forget(user string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.users, user)
}
