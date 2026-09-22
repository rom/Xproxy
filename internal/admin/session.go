package admin

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/rom/xproxy/internal/bound"
	"sync"
	"time"
)

// Session is one logged-in browser.
type Session struct {
	User    string
	Role    Role
	Via     string // "password" or "certificate"
	Created time.Time
	Last    time.Time
}

// sessions is the in-memory session store. Tokens are 32 random bytes; the
// store keeps at most maxSessions and evicts the least recently used one.
type sessions struct {
	mu   sync.Mutex
	by   map[string]*Session
	idle time.Duration
	max  time.Duration
	now  func() time.Time
	full bound.Notice
}

const maxSessions = 1000

func newSessions(idle, maxAge time.Duration) *sessions {
	return &sessions{by: map[string]*Session{}, idle: idle, max: maxAge, now: time.Now}
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *sessions) create(user string, role Role, via string) (string, error) {
	tok, err := newToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.by) >= maxSessions {
		s.full.Hit(nil, "admin session table full; the least recently used session is evicted", "table", "admin_sessions", "max", maxSessions)
		var oldest string
		var oldestAt time.Time
		for k, v := range s.by {
			if oldest == "" || v.Last.Before(oldestAt) {
				oldest, oldestAt = k, v.Last
			}
		}
		delete(s.by, oldest)
	}
	s.by[tok] = &Session{User: user, Role: role, Via: via, Created: now, Last: now}
	return tok, nil
}

// get returns a copy of the session and touches it; expired sessions are
// removed.
func (s *sessions) get(tok string) (Session, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.by[tok]
	if !ok {
		return Session{}, false
	}
	if now.Sub(v.Last) > s.idle || now.Sub(v.Created) > s.max {
		delete(s.by, tok)
		return Session{}, false
	}
	v.Last = now
	return *v, true
}

// setRole records a role change for a live session and returns the role
// now in force. A session whose token has gone keeps the role passed in,
// which the caller then uses for this one request only.
func (s *sessions) setRole(tok string, role Role) Role {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.by[tok]; ok {
		v.Role = role
	}
	return role
}

func (s *sessions) drop(tok string) {
	s.mu.Lock()
	delete(s.by, tok)
	s.mu.Unlock()
}

// loginLimiter counts failed logins per source and account, inside
// `window`.
//
// Keying on the source alone locked every operator out for the window
// after five bad logins from one place, and a client over the Unix
// socket or an SSH tunnel is one place: "local" for everybody. Keying
// on the account alone would trade that for unlimited password spraying
// across names. The key is therefore both, with a global ceiling so a
// spray across many names is still stopped — at which point the GUI is
// closed to everyone for the window, which is the right answer when
// that many logins are failing at once.
type loginLimiter struct {
	mu     sync.Mutex
	fails  map[string][]time.Time // source \x00 account
	all    []time.Time            // every failure, for the global ceiling
	limit  int
	window time.Duration
	now    func() time.Time
}

// globalFactor sets the global ceiling as a multiple of the per-key
// limit: enough that a handful of operators mistyping passwords never
// reach it, few enough that a spray across names does.
const globalFactor = 20

func newLoginLimiter(limit int, window time.Duration) *loginLimiter {
	return &loginLimiter{fails: map[string][]time.Time{}, limit: limit, window: window, now: time.Now}
}

func limiterKey(src, user string) string { return src + "\x00" + user }

// blocked reports whether this source and account are locked out, or
// the whole GUI is, and for how long.
func (l *loginLimiter) blocked(src, user string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.all = pruneTimes(l.all, now, l.window)
	if len(l.all) >= l.limit*globalFactor {
		return true, l.all[0].Add(l.window).Sub(now)
	}
	f := l.prune(limiterKey(src, user), now)
	if len(f) >= l.limit {
		return true, f[0].Add(l.window).Sub(now)
	}
	return false, 0
}

func (l *loginLimiter) fail(src, user string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	key := limiterKey(src, user)
	f := l.prune(key, now)
	l.fails[key] = append(f, now)
	l.all = append(pruneTimes(l.all, now, l.window), now)
	if len(l.fails) > 10000 { // bound the map under a distributed attack
		for k := range l.fails {
			delete(l.fails, k)
			break
		}
	}
}

func (l *loginLimiter) reset(src, user string) {
	l.mu.Lock()
	delete(l.fails, limiterKey(src, user))
	l.mu.Unlock()
}

// prune drops entries outside the window; caller holds the lock.
func (l *loginLimiter) prune(key string, now time.Time) []time.Time {
	f := pruneTimes(l.fails[key], now, l.window)
	if len(f) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = f
	}
	return f
}

func pruneTimes(f []time.Time, now time.Time, window time.Duration) []time.Time {
	i := 0
	for i < len(f) && now.Sub(f[i]) > window {
		i++
	}
	return f[i:]
}
