package mfa

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/passwd"
)

// Changing enrolments while the proxy runs.
//
// The file is the authority rather than the copy in memory: it is
// re-read when it has changed on disk, at most once a second, the same
// way the GUI's own users file is. Enrolment that needs a restart is
// enrolment nobody does; removal that needs one is worse, because the
// person is still enrolled while everyone believes they are not.

// recheck is the shortest interval between two stats of the file.
const recheck = time.Second

// RecoveryCodes is how many single-use codes an enrolment gets.
const RecoveryCodes = 10

// MaxUserName bounds a name, which has to fit in one field of one line
// and appear in a log.
const MaxUserName = 128

// ErrNoSuchUser says the file has no such enrolment.
var ErrNoSuchUser = errors.New("mfa: no such enrolment")

// ErrBadUserName says a name cannot go in the file.
var ErrBadUserName = errors.New("mfa: name")

// fileStamp is the change detector: an atomic rename replaces the file,
// which SameFile sees, and an editor writing in place changes the size
// or the modification time.
type fileStamp struct{ info os.FileInfo }

func (a fileStamp) same(b fileStamp) bool {
	if a.info == nil || b.info == nil {
		return a.info == nil && b.info == nil
	}
	return os.SameFile(a.info, b.info) && a.info.Size() == b.info.Size() &&
		a.info.ModTime().Equal(b.info.ModTime())
}

func stampOf(path string) fileStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{info: fi}
}

// Path is the file this store reads.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// refresh re-reads the file when it has changed. It runs before every
// lookup; the stat is skipped unless a second has passed, so a burst of
// sessions costs one syscall.
func (s *Store) refresh() {
	if s == nil || s.path == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	if now.Sub(s.checked) < recheck {
		s.mu.Unlock()
		return
	}
	s.checked = now
	current := s.stat
	s.mu.Unlock()
	if stampOf(s.path).same(current) {
		return
	}
	byUser, stamp, err := readFile(s.path, true)
	if err != nil {
		// Keep what is in memory: a half-written file must not enrol
		// or un-enrol anybody. The stamp is not stored, so the next
		// check tries again.
		if s.Warn != nil {
			s.Warn(err)
		}
		return
	}
	s.mu.Lock()
	s.byUser, s.stat = byUser, stamp
	s.mu.Unlock()
}

// Reload re-reads the file now, whatever the stamp says. It is what a
// writer calls after replacing it, so the change is in force before the
// call that made it returns.
func (s *Store) Reload() error {
	byUser, stamp, err := readFile(s.path, true)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.byUser, s.stat, s.checked = byUser, stamp, time.Now()
	s.mu.Unlock()
	return nil
}

// Enrol gives a user a new second factor, replacing any they had, and
// returns the secret and the recovery codes. Both are returned once and
// stored in a form that cannot give them back: the secret is in the
// file because a one-time password needs it there, and the recovery
// codes are hashed.
func (s *Store) Enrol(user string, p Params) (secret string, recovery []string, err error) {
	if err := ValidName(user); err != nil {
		return "", nil, err
	}
	secret, err = NewSecret()
	if err != nil {
		return "", nil, err
	}
	recovery, hashes, err := newRecovery(RecoveryCodes)
	if err != nil {
		return "", nil, err
	}
	e := &Enrolment{User: user, Params: p, Recovery: hashes}
	if e.Secret, err = ParseSecret(secret); err != nil {
		return "", nil, err
	}
	if err := s.write(func(byUser map[string]*Enrolment) error {
		byUser[user] = e
		return nil
	}); err != nil {
		return "", nil, err
	}
	return secret, recovery, nil
}

// Recovery replaces a user's recovery codes and returns the new ones.
// The old ones stop working, which is the point: codes are replaced
// because the operator no longer knows who has the old list.
func (s *Store) Recovery(user string) ([]string, error) {
	codes, hashes, err := newRecovery(RecoveryCodes)
	if err != nil {
		return nil, err
	}
	err = s.write(func(byUser map[string]*Enrolment) error {
		e, ok := byUser[user]
		if !ok {
			return fmt.Errorf("%w: %s", ErrNoSuchUser, user)
		}
		e.Recovery = hashes
		return nil
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// Remove takes a user's enrolment out of the file.
func (s *Store) Remove(user string) error {
	return s.write(func(byUser map[string]*Enrolment) error {
		if _, ok := byUser[user]; !ok {
			return fmt.Errorf("%w: %s", ErrNoSuchUser, user)
		}
		delete(byUser, user)
		return nil
	})
}

// write applies a change to the file: read it, change it, replace it
// atomically, and re-read. The read is inside the lock so two changes
// arriving together cannot lose one another, and it is a fresh read
// rather than the copy in memory so an edit made outside is not undone.
func (s *Store) write(change func(map[string]*Enrolment) error) error {
	if s == nil || s.path == "" {
		return errors.New("mfa: this store has no file to write")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	byUser, _, err := readFile(s.path, true)
	if err != nil {
		return err
	}
	if err := change(byUser); err != nil {
		return err
	}
	if err := replaceFile(s.path, byUser); err != nil {
		return err
	}
	return s.Reload()
}

// replaceFile writes the enrolments and moves them into place. The
// temporary file is created in the same directory, so the rename cannot
// cross a filesystem and leave the old file behind.
func replaceFile(path string, byUser map[string]*Enrolment) error {
	users := make([]string, 0, len(byUser))
	for u := range byUser {
		users = append(users, u)
	}
	sort.Strings(users)

	var b strings.Builder
	b.WriteString("# xproxy second factors: user:secret:parameters:recovery hashes\n")
	b.WriteString("# Written by the control plane. Hand edits are read too.\n")
	for _, u := range users {
		b.WriteString(byUser[u].line())
		b.WriteByte('\n')
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".mfa-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		return err
	}
	// The contents reach the disk before the rename: a file that is
	// renamed into place and then found empty after a crash is every
	// second factor gone.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// line renders one enrolment.
func (e *Enrolment) line() string {
	out := e.User + ":" + base32Enc.EncodeToString(e.Secret)
	params := e.Params.fields()
	if params == "" && len(e.Recovery) == 0 {
		return out
	}
	out += ":" + params
	if len(e.Recovery) > 0 {
		out += ":" + strings.Join(e.Recovery, ",")
	}
	return out
}

// fields renders the parameters that differ from the defaults, which is
// what keeps an ordinary line short.
func (p Params) fields() string {
	var out []string
	if p.Digits != 0 {
		out = append(out, "digits="+strconv.Itoa(p.Digits))
	}
	if p.Period != 0 {
		out = append(out, "period="+strconv.Itoa(int(p.Period/time.Second)))
	}
	if p.Algo != "" {
		out = append(out, "algo="+p.Algo)
	}
	return strings.Join(out, ",")
}

// ValidName says whether a name can go in the file. The separators are
// what the format is made of, so a name cannot contain one; control
// characters and spaces are refused because the name appears in logs
// and in the GUI.
func ValidName(user string) error {
	if user == "" {
		return fmt.Errorf("%w: a name is required", ErrBadUserName)
	}
	if len(user) > MaxUserName {
		return fmt.Errorf("%w: %d characters, over the %d bound", ErrBadUserName, len(user), MaxUserName)
	}
	if strings.HasPrefix(user, "#") {
		return fmt.Errorf("%w: a name cannot begin with #, which starts a comment", ErrBadUserName)
	}
	for _, r := range user {
		switch {
		case r == ':' || r == ',':
			return fmt.Errorf("%w: a name cannot contain %q, which separates the fields", ErrBadUserName, string(r))
		case r < 0x20 || r == 0x7F:
			return fmt.Errorf("%w: a name cannot contain control characters", ErrBadUserName)
		case r == ' ' || r == '\t':
			return fmt.Errorf("%w: a name cannot contain spaces", ErrBadUserName)
		}
	}
	return nil
}

// recoveryAlphabet leaves out the characters a person reads back
// wrongly: no 0 and O, no 1 and I and l.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// recoveryCodeGroups and recoveryGroupLen shape a code into something
// somebody can read off a printout without losing their place.
const (
	recoveryCodeGroups = 3
	recoveryGroupLen   = 5
)

// recoveryCode draws one single-use code.
func recoveryCode() (string, error) {
	groups := make([]string, 0, recoveryCodeGroups)
	for g := 0; g < recoveryCodeGroups; g++ {
		out := make([]byte, recoveryGroupLen)
		for i := range out {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(recoveryAlphabet))))
			if err != nil {
				return "", err
			}
			out[i] = recoveryAlphabet[n.Int64()]
		}
		groups = append(groups, string(out))
	}
	return strings.Join(groups, "-"), nil
}

// newRecovery draws single-use codes and the hashes that go in the
// file. The codes are shown once; the file keeps only what can check
// them.
func newRecovery(n int) (codes, hashes []string, err error) {
	for i := 0; i < n; i++ {
		c, err := recoveryCode()
		if err != nil {
			return nil, nil, err
		}
		h, err := passwd.Hash(c)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, c)
		hashes = append(hashes, h)
	}
	return codes, hashes, nil
}

// Status is what a status view shows about one enrolment. It never
// carries the secret.
type Status struct {
	User string `json:"user"`
	// Recovery is how many recovery codes the file holds, which is not
	// how many are still unspent: which have been used is in the
	// guard's memory rather than in the file.
	Recovery int    `json:"recovery"`
	Digits   int    `json:"digits"`
	Period   int    `json:"period_seconds"`
	Algo     string `json:"algo"`
}

// List describes every enrolment, sorted, for a status view.
func (s *Store) List() []Status {
	if s == nil {
		return nil
	}
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Status, 0, len(s.byUser))
	for _, e := range s.byUser {
		p := e.Params.normalise()
		out = append(out, Status{
			User: e.User, Recovery: len(e.Recovery),
			Digits: p.Digits, Period: int(p.Period / time.Second), Algo: p.Algo,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}
