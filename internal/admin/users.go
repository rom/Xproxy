// Package admin implements xproxy-admin, the web GUI: a separate process
// that serves embedded static assets, authenticates operators and viewers,
// and forwards every action to the management socket of the data plane.
package admin

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/passwd"
)

// Role is what a user may do. Viewers read; operators also change things.
type Role string

// Roles.
const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
)

// ParseRole validates a role name.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleViewer, RoleOperator:
		return Role(s), nil
	}
	return "", fmt.Errorf("unknown role %q (viewer or operator)", s)
}

// User is one line of the users file.
type User struct {
	Name string
	Role Role
	// Hash is the password hash, or "x509" for a user that only logs in
	// with a client certificate whose common name equals Name.
	Hash string
}

// CertOnly reports whether the user has no password.
func (u User) CertOnly() bool { return u.Hash == "x509" }

// HashPassword derives a stored hash for a password (see passwd).
func HashPassword(password string) (string, error) { return passwd.Hash(password) }

// VerifyPassword checks a password against a stored hash.
func VerifyPassword(hash, password string) bool { return passwd.Verify(hash, password) }

// Users is the users file: "name:role:hash" per line, '#' comments.
//
// The file is the authority, not the copy in memory: it is re-read
// whenever it has changed on disk (at most once a second), so removing a
// user, downgrading a role or changing a password takes effect without
// restarting the GUI. Revocation that needs a restart is revocation that
// silently does not happen.
type Users struct {
	path string
	mu   sync.RWMutex
	byN  map[string]User
	// stat is what the file looked like when byN was read from it.
	stat    fileStamp
	checked time.Time
	now     func() time.Time
	// Warn receives a re-read that failed. The previous set stays in
	// force in that case, so a truncated write or a permission blip does
	// not lock every operator out. It is set once before serving.
	Warn func(error)
}

// fileStamp is the cheap change detector. An atomic rename (what Set and
// Delete do, and what configuration management does) replaces the file,
// which SameFile sees; an editor writing in place keeps the identity but
// changes the size or the modification time.
type fileStamp struct {
	info os.FileInfo // nil when the file is not there
}

func (a fileStamp) same(b fileStamp) bool {
	if a.info == nil || b.info == nil {
		return a.info == nil && b.info == nil
	}
	return os.SameFile(a.info, b.info) && a.info.Size() == b.info.Size() && a.info.ModTime().Equal(b.info.ModTime())
}

// recheck is the shortest interval between two stats of the file.
const recheck = time.Second

// LoadUsers reads the file. A missing file yields an empty set (the GUI
// then refuses every login until a user is added).
func LoadUsers(path string) (*Users, error) {
	u := &Users{path: path, byN: map[string]User{}, now: time.Now}
	byN, stamp, err := readUsers(path)
	if err != nil {
		return nil, err
	}
	u.byN, u.stat, u.checked = byN, stamp, u.now()
	return u, nil
}

// stampOf describes the file for change detection. A missing file is a
// stamp of its own: it means every user has been revoked.
func stampOf(path string) fileStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{info: fi}
}

// readUsers parses the file and returns it with the stamp it had. The
// stamp is taken before the read, so a file rewritten during the read is
// re-read on the next check rather than remembered as current.
func readUsers(path string) (map[string]User, fileStamp, error) {
	stamp := stampOf(path)
	byN := map[string]User{}
	f, err := os.Open(path) //nolint:gosec // operator supplied path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return byN, fileStamp{}, nil
		}
		return nil, stamp, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4096)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		parts := strings.SplitN(t, ":", 3)
		if len(parts) != 3 {
			return nil, stamp, fmt.Errorf("%s:%d: expected name:role:hash", path, line)
		}
		if err := validName(parts[0]); err != nil {
			return nil, stamp, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		role, err := ParseRole(parts[1])
		if err != nil {
			return nil, stamp, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if strings.TrimSpace(parts[2]) == "" {
			// An empty hash can never verify, so the user would be there
			// and unable to log in. That is a truncated line or a botched
			// edit, not a deliberate account: say so instead of leaving
			// the operator to find out at the login page.
			return nil, stamp, fmt.Errorf("%s:%d: user %q has an empty hash (use \"x509\" for a certificate-only user)", path, line, parts[0])
		}
		if _, dup := byN[parts[0]]; dup {
			return nil, stamp, fmt.Errorf("%s:%d: duplicate user %q", path, line, parts[0])
		}
		byN[parts[0]] = User{Name: parts[0], Role: role, Hash: parts[2]}
	}
	if err := sc.Err(); err != nil {
		return nil, stamp, fmt.Errorf("%s: %w", path, err)
	}
	return byN, stamp, nil
}

// refresh re-reads the file when it has changed since the last read. It
// is called before every lookup; the stat is skipped unless a second has
// passed, so a burst of requests costs one syscall.
func (u *Users) refresh() {
	now := u.now()
	u.mu.Lock()
	if now.Sub(u.checked) < recheck {
		u.mu.Unlock()
		return
	}
	u.checked = now
	current := u.stat
	u.mu.Unlock()
	if stampOf(u.path).same(current) {
		return
	}
	byN, stamp, err := readUsers(u.path)
	if err != nil {
		// Keep what we have: a half-written file must not lock everyone
		// out. The stamp is not stored, so the next check retries.
		if u.Warn != nil {
			u.Warn(err)
		}
		return
	}
	u.mu.Lock()
	u.byN, u.stat = byN, stamp
	u.mu.Unlock()
}

func validName(n string) error {
	if n == "" || len(n) > 64 {
		return errors.New("user name must be 1 to 64 characters")
	}
	for _, r := range n {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' || r == '@'
		if !ok {
			return fmt.Errorf("user name %q: only letters, digits, '.', '-', '_' and '@'", n)
		}
	}
	return nil
}

// Lookup returns a user by name, from the file as it is now.
func (u *Users) Lookup(name string) (User, bool) {
	u.refresh()
	u.mu.RLock()
	defer u.mu.RUnlock()
	x, ok := u.byN[name]
	return x, ok
}

// List returns the users sorted by name, without hashes.
func (u *Users) List() []User {
	u.refresh()
	u.mu.RLock()
	defer u.mu.RUnlock()
	out := make([]User, 0, len(u.byN))
	for _, x := range u.byN {
		x.Hash = ""
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Set adds or replaces a user and writes the file (0600, atomic).
func (u *Users) Set(x User) error {
	if err := validName(x.Name); err != nil {
		return err
	}
	if _, err := ParseRole(string(x.Role)); err != nil {
		return err
	}
	if x.Hash == "" {
		return errors.New("empty hash")
	}
	u.refresh() // write against the file as it is, not a stale copy
	u.mu.Lock()
	defer u.mu.Unlock()
	u.byN[x.Name] = x
	return u.writeLocked()
}

// Delete removes a user and writes the file.
func (u *Users) Delete(name string) error {
	u.refresh()
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.byN[name]; !ok {
		return fmt.Errorf("no user %q", name)
	}
	delete(u.byN, name)
	return u.writeLocked()
}

func (u *Users) writeLocked() error {
	names := make([]string, 0, len(u.byN))
	for n := range u.byN {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("# xproxy-admin users: name:role:hash (managed by xproxy-admin user)\n")
	for _, n := range names {
		x := u.byN[n]
		fmt.Fprintf(&b, "%s:%s:%s\n", x.Name, x.Role, x.Hash)
	}
	tmp, err := os.CreateTemp(filepath.Dir(u.path), "."+filepath.Base(u.path)+".*.tmp") // O_EXCL, never follows a link
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), u.path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	// The map and the file now agree; record what we just wrote so the
	// next refresh does not re-read our own change.
	u.stat, u.checked = stampOf(u.path), u.now()
	return nil
}
