package webauthn

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
)

// The challenge is the whole of the replay protection.
//
// An assertion is a signature over a challenge this server chose. Take
// away the "this server chose, once, recently" and the same assertion
// works forever, from anywhere, which is where a bearer token started.
//
// So a challenge is: random (32 bytes from the system source), issued to a
// particular account, valid for a short window, and spent on first use
// whether the ceremony that used it succeeded or not -- because a failed
// attempt that leaves the challenge alive is an attacker's retry budget.
type Challenges struct {
	mu   sync.Mutex
	max  int
	ttl  time.Duration
	open map[string]issued
	now  func() time.Time
}

type issued struct {
	user  string
	value []byte
	until time.Time
}

// ErrChallenge is a challenge that was never issued, has expired, was
// already used, or belongs to another account.
var ErrChallenge = errors.New("webauthn: challenge is not one that was issued")

// NewChallenges bounds the outstanding challenges and their lifetime.
func NewChallenges(max int, ttl time.Duration) *Challenges {
	if max < 1 {
		max = 1024
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &Challenges{max: max, ttl: ttl, open: make(map[string]issued, min(max, 64)), now: time.Now}
}

// Issue mints a challenge for a user and returns its identifier and value.
//
// The identifier is what travels in the page and comes back in the form;
// the value is what the authenticator signs. Keeping them apart means the
// page does not have to be trusted to return the same value it was given:
// the server looks the challenge up by identifier and compares the value
// itself.
func (c *Challenges) Issue(user string) (id string, value []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return "", nil, err
	}
	id = encodeID(idb)
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.open) >= c.max {
		// Outstanding challenges are one per page load, so the table
		// grows with traffic and not with anything an attacker controls
		// beyond that. Expired ones go first; if that is not enough the
		// oldest do, which costs somebody a retry rather than the server.
		c.sweep(now)
		for k := range c.open {
			if len(c.open) < c.max {
				break
			}
			delete(c.open, k)
		}
	}
	c.open[id] = issued{user: user, value: raw, until: now.Add(c.ttl)}
	return id, raw, nil
}

// Spend takes a challenge out of the table and returns its value. It fails
// for an identifier that was never issued, has expired, was already used,
// or was issued to another account.
//
// Spending before the ceremony is verified is deliberate: a challenge that
// survives a failed attempt is an attacker's retry budget, and the cost of
// spending early is that a genuine user whose key misfires reloads the
// page.
func (c *Challenges) Spend(id, user string) ([]byte, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	got, ok := c.open[id]
	if !ok {
		return nil, ErrChallenge
	}
	delete(c.open, id)
	if now.After(got.until) {
		return nil, ErrChallenge
	}
	// The account is compared because a challenge issued to one user must
	// not complete a ceremony for another: without it, an attacker who can
	// see a page load for their own account could use its challenge
	// against somebody else's credential.
	if subtle.ConstantTimeCompare([]byte(got.user), []byte(user)) != 1 {
		return nil, ErrChallenge
	}
	return got.value, nil
}

// sweep drops what has expired.
func (c *Challenges) sweep(now time.Time) {
	for k, v := range c.open {
		if now.After(v.until) {
			delete(c.open, k)
		}
	}
}

// Len is the number outstanding, for the status view and the tests.
func (c *Challenges) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.open)
}

// encodeID renders a challenge identifier as lower case hexadecimal, which
// is safe in a URL, in an HTML attribute and in a log line without
// escaping.
func encodeID(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hex[x>>4], hex[x&0xf])
	}
	return string(out)
}
