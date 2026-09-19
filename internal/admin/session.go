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

func (s *sessions) drop(tok string) {
	s.mu.Lock()
	delete(s.by, tok)
	s.mu.Unlock()
}

// loginLimiter counts failed logins per source and locks the source out
// after `limit` failures inside `window`.
type loginLimiter struct {
	mu     sync.Mutex
	fails  map[string][]time.Time
	limit  int
	window time.Duration
	now    func() time.Time
}

func newLoginLimiter(limit int, window time.Duration) *loginLimiter {
	return &loginLimiter{fails: map[string][]time.Time{}, limit: limit, window: window, now: time.Now}
}

// blocked reports whether the source is locked out and for how long.
func (l *loginLimiter) blocked(src string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.prune(src, now)
	if len(f) >= l.limit {
		return true, f[0].Add(l.window).Sub(now)
	}
	return false, 0
}

func (l *loginLimiter) fail(src string) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.prune(src, now)
	l.fails[src] = append(f, now)
	if len(l.fails) > 10000 { // bound the map under a distributed attack
		for k := range l.fails {
			delete(l.fails, k)
			break
		}
	}
}

func (l *loginLimiter) reset(src string) {
	l.mu.Lock()
	delete(l.fails, src)
	l.mu.Unlock()
}

// prune drops entries outside the window; caller holds the lock.
func (l *loginLimiter) prune(src string, now time.Time) []time.Time {
	f := l.fails[src]
	i := 0
	for i < len(f) && now.Sub(f[i]) > l.window {
		i++
	}
	f = f[i:]
	if len(f) == 0 {
		delete(l.fails, src)
	} else {
		l.fails[src] = f
	}
	return f
}
