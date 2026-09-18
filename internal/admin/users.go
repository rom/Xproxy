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

func hashPassword(password string, iterations int) (string, error) {
	return passwd.HashWithIterations(password, iterations)
}

// VerifyPassword checks a password against a stored hash.
func VerifyPassword(hash, password string) bool { return passwd.Verify(hash, password) }

// Users is the users file: "name:role:hash" per line, '#' comments.
type Users struct {
	path string
	mu   sync.RWMutex
	byN  map[string]User
}

// LoadUsers reads the file. A missing file yields an empty set (the GUI
// then refuses every login until a user is added).
func LoadUsers(path string) (*Users, error) {
	u := &Users{path: path, byN: map[string]User{}}
	f, err := os.Open(path) //nolint:gosec // operator supplied path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return u, nil
		}
		return nil, err
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
			return nil, fmt.Errorf("%s:%d: expected name:role:hash", path, line)
		}
		if err := validName(parts[0]); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		role, err := ParseRole(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if _, dup := u.byN[parts[0]]; dup {
			return nil, fmt.Errorf("%s:%d: duplicate user %q", path, line, parts[0])
		}
		u.byN[parts[0]] = User{Name: parts[0], Role: role, Hash: parts[2]}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return u, nil
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

// Lookup returns a user by name.
func (u *Users) Lookup(name string) (User, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	x, ok := u.byN[name]
	return x, ok
}

// List returns the users sorted by name, without hashes.
func (u *Users) List() []User {
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
	u.mu.Lock()
	defer u.mu.Unlock()
	u.byN[x.Name] = x
	return u.writeLocked()
}

// Delete removes a user and writes the file.
func (u *Users) Delete(name string) error {
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
	tmp := filepath.Join(filepath.Dir(u.path), "."+filepath.Base(u.path)+".tmp")
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, u.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
