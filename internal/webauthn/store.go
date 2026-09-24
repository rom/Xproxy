package webauthn

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The credential file, and why it is written rather than only read.
//
// A registration produces a credential the proxy has to remember, so this
// store is the one place in the identity code that the proxy writes. The
// file is the record: one line per credential, replaced atomically, and
// re-read when it changes on disk so an operator removing a lost key with
// an editor takes effect without a restart.
//
// The sign count is written on every successful assertion, which is the
// only way the clone check means anything -- a count kept in memory is a
// count a restart forgets. That makes the file a write-per-login, which is
// why the write is batched behind a lock and the whole file is small by
// construction: a credential is a couple of hundred bytes and people have
// two or three.
//
// The format is one credential per line, colon separated:
//
//	alice:AQIDBA:pQECAyYgASFYIA...:7:yubikey-5c
//
// the user, the credential identifier, the COSE public key (both base64url
// without padding), the sign count, and an optional label. Blank lines and
// lines beginning with # are ignored.
type Store struct {
	path string
	mu   sync.RWMutex
	// byUser is every credential of an account, in file order.
	byUser map[string][]*Credential
	// byID finds a credential by identifier, which is what an assertion
	// arrives with.
	byID map[string]*Credential

	writeMu sync.Mutex
	stat    stamp
	checked time.Time
	// Warn receives a re-read that failed; what is in memory stays in
	// force, so a half-written file does not un-enrol anybody.
	Warn func(error)
}

// maxCredentialsPerUser bounds how many keys one account may register.
// People have a laptop, a phone and a spare; a hundred is somebody using
// the endpoint for something else.
const maxCredentialsPerUser = 10

// maxStoreBytes bounds the file.
const maxStoreBytes = 8 << 20

// maxCredentialIDBytes is the specification's cap on a credential
// identifier.
const maxCredentialIDBytes = 1023

// maxPublicKeyBytes bounds a stored COSE key.
const maxPublicKeyBytes = 4096

var errTooMany = errors.New("webauthn: too many credentials for this user")

// stamp is what the file looked like when it was read.
type stamp struct{ info os.FileInfo }

func (a stamp) same(b stamp) bool {
	if a.info == nil || b.info == nil {
		return a.info == nil && b.info == nil
	}
	return a.info.Size() == b.info.Size() && a.info.ModTime().Equal(b.info.ModTime())
}

func stampOf(path string) stamp {
	info, err := os.Stat(path)
	if err != nil {
		return stamp{}
	}
	return stamp{info: info}
}

// Load reads a credential file. A missing file is an empty store: a
// deployment that has enrolled nobody yet is not a broken one, and the
// first registration creates it.
func Load(path string) (*Store, error) {
	s := &Store{path: path, byUser: map[string][]*Credential{}, byID: map[string]*Credential{}}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		s.checked = time.Now()
		return s, nil
	}
	byUser, byID, st, err := readFile(path)
	if err != nil {
		return nil, err
	}
	s.byUser, s.byID, s.stat, s.checked = byUser, byID, st, time.Now()
	return s, nil
}

// readFile parses the file. A line that does not parse fails the read: a
// credential that was meant to be there and silently is not locks somebody
// out, and one that was meant to be removed and is not is worse.
func readFile(path string) (map[string][]*Credential, map[string]*Credential, stamp, error) {
	st := stampOf(path)
	f, err := os.Open(path) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, nil, stamp{}, err
	}
	defer func() { _ = f.Close() }()
	byUser := map[string][]*Credential{}
	byID := map[string]*Credential{}
	sc := bufio.NewScanner(&limitReader{r: f, left: maxStoreBytes})
	sc.Buffer(make([]byte, 0, 8192), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		c, err := parseLine(text)
		if err != nil {
			return nil, nil, stamp{}, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		key := string(c.ID)
		if _, dup := byID[key]; dup {
			return nil, nil, stamp{}, fmt.Errorf("%s line %d: credential is already registered", path, line)
		}
		if len(byUser[c.User]) >= maxCredentialsPerUser {
			return nil, nil, stamp{}, fmt.Errorf("%s line %d: %w", path, line, errTooMany)
		}
		byUser[c.User] = append(byUser[c.User], c)
		byID[key] = c
	}
	if err := sc.Err(); err != nil {
		return nil, nil, stamp{}, err
	}
	return byUser, byID, st, nil
}

// limitReader is io.LimitReader that reports the bound as an error rather
// than as a clean end of file, so a file past it is refused instead of
// being read as the part that fitted.
type limitReader struct {
	r    *os.File
	left int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, fmt.Errorf("credential file larger than %d bytes", int64(maxStoreBytes))
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

func parseLine(text string) (*Credential, error) {
	parts := strings.Split(text, ":")
	if len(parts) < 4 || len(parts) > 5 {
		return nil, errors.New("want user:credential_id:public_key:sign_count[:label]")
	}
	user := strings.TrimSpace(parts[0])
	if user == "" || len(user) > 256 || strings.ContainsAny(user, " \t") {
		return nil, errors.New("bad user name")
	}
	id, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(id) == 0 || len(id) > maxCredentialIDBytes {
		return nil, errors.New("credential_id is not base64url of 1 to 1023 bytes")
	}
	key, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(key) == 0 || len(key) > maxPublicKeyBytes {
		return nil, errors.New("public_key is not base64url of a COSE key")
	}
	// The key is parsed at load, so a credential nothing can verify with
	// is a configuration error an operator sees rather than a login that
	// fails later for no visible reason.
	if _, err := parseCOSEKey(key); err != nil {
		return nil, err
	}
	count, err := strconv.ParseUint(strings.TrimSpace(parts[3]), 10, 32)
	if err != nil {
		return nil, errors.New("sign_count is not a number")
	}
	c := &Credential{User: user, ID: id, PublicKey: key, SignCount: uint32(count)}
	if len(parts) == 5 {
		c.Label = strings.TrimSpace(parts[4])
		if len(c.Label) > 64 || strings.ContainsAny(c.Label, ":\r\n") {
			return nil, errors.New("label must be at most 64 characters and carry no colon")
		}
	}
	return c, nil
}

func (c *Credential) line() string {
	out := c.User + ":" + base64.RawURLEncoding.EncodeToString(c.ID) + ":" +
		base64.RawURLEncoding.EncodeToString(c.PublicKey) + ":" + strconv.FormatUint(uint64(c.SignCount), 10)
	if c.Label != "" {
		out += ":" + c.Label
	}
	return out
}

// refresh re-reads the file when it has changed, at most once a second.
func (s *Store) refresh() {
	if s.path == "" {
		return
	}
	now := time.Now()
	s.mu.RLock()
	fresh := now.Sub(s.checked) < time.Second
	s.mu.RUnlock()
	if fresh {
		return
	}
	st := stampOf(s.path)
	s.mu.Lock()
	s.checked = now
	same := st.same(s.stat)
	s.mu.Unlock()
	if same {
		return
	}
	byUser, byID, got, err := readFile(s.path)
	if err != nil {
		if s.Warn != nil {
			s.Warn(err)
		}
		return
	}
	s.mu.Lock()
	s.byUser, s.byID, s.stat = byUser, byID, got
	s.mu.Unlock()
}

// Credentials returns a user's registered keys.
func (s *Store) Credentials(user string) []Credential {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := s.byUser[user]
	out := make([]Credential, 0, len(list))
	for _, c := range list {
		out = append(out, *c)
	}
	return out
}

// ByID finds a credential by identifier and checks it belongs to the user
// the request authenticated as.
//
// The account is part of the lookup on purpose: a credential identifier is
// public -- it travels in the allow list on every login page -- so finding
// one and using it for whatever account the request claims would let
// anybody log in as anybody whose identifier they had seen.
func (s *Store) ByID(user string, id []byte) (Credential, bool) {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.byID[string(id)]
	if !ok || c.User != user {
		return Credential{}, false
	}
	return *c, true
}

// Enrolled reports whether a user has any credential.
func (s *Store) Enrolled(user string) bool {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byUser[user]) > 0
}

// Users lists the accounts with credentials.
func (s *Store) Users() []string {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.byUser))
	for u := range s.byUser {
		out = append(out, u)
	}
	return out
}

// Add registers a credential.
func (s *Store) Add(c Credential) error {
	if c.User == "" || len(c.ID) == 0 || len(c.PublicKey) == 0 {
		return errors.New("webauthn: incomplete credential")
	}
	if _, err := parseCOSEKey(c.PublicKey); err != nil {
		return err
	}
	return s.write(func(byUser map[string][]*Credential, byID map[string]*Credential) error {
		if _, dup := byID[string(c.ID)]; dup {
			// The same authenticator registering twice. Refusing is right:
			// the second registration would reset the sign count, which
			// is the clone check thrown away.
			return errors.New("webauthn: this credential is already registered")
		}
		if len(byUser[c.User]) >= maxCredentialsPerUser {
			return errTooMany
		}
		cp := c
		byUser[c.User] = append(byUser[c.User], &cp)
		byID[string(cp.ID)] = &cp
		return nil
	})
}

// Remove deletes one credential of a user, by identifier.
func (s *Store) Remove(user string, id []byte) error {
	return s.write(func(byUser map[string][]*Credential, byID map[string]*Credential) error {
		c, ok := byID[string(id)]
		if !ok || c.User != user {
			return errors.New("webauthn: no such credential for this user")
		}
		delete(byID, string(id))
		kept := byUser[user][:0]
		for _, x := range byUser[user] {
			if !bytes.Equal(x.ID, id) {
				kept = append(kept, x)
			}
		}
		if len(kept) == 0 {
			delete(byUser, user)
		} else {
			byUser[user] = kept
		}
		return nil
	})
}

// RemoveUser deletes every credential of a user.
func (s *Store) RemoveUser(user string) error {
	return s.write(func(byUser map[string][]*Credential, byID map[string]*Credential) error {
		list, ok := byUser[user]
		if !ok {
			return errors.New("webauthn: no credentials for this user")
		}
		for _, c := range list {
			delete(byID, string(c.ID))
		}
		delete(byUser, user)
		return nil
	})
}

// Touch records a new sign count.
//
// A count kept only in memory is a count a restart forgets, and a
// forgotten count is a clone check that passes. So it is written, and a
// write that fails is an error the caller sees rather than a silent
// downgrade of the check.
func (s *Store) Touch(id []byte, count uint32) error {
	return s.write(func(_ map[string][]*Credential, byID map[string]*Credential) error {
		c, ok := byID[string(id)]
		if !ok {
			return errors.New("webauthn: no such credential")
		}
		c.SignCount = count
		return nil
	})
}

// write applies a change and replaces the file.
func (s *Store) write(change func(byUser map[string][]*Credential, byID map[string]*Credential) error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// The file on disk is the truth: another process may have changed it,
	// and a read-modify-write from a stale copy would undo that.
	byUser, byID := map[string][]*Credential{}, map[string]*Credential{}
	if s.path != "" {
		if _, err := os.Stat(s.path); err == nil {
			u, i, _, err := readFile(s.path)
			if err != nil {
				return err
			}
			byUser, byID = u, i
		}
	} else {
		s.mu.RLock()
		for u, list := range s.byUser {
			for _, c := range list {
				cp := *c
				byUser[u] = append(byUser[u], &cp)
				byID[string(cp.ID)] = &cp
			}
		}
		s.mu.RUnlock()
	}
	if err := change(byUser, byID); err != nil {
		return err
	}
	if s.path != "" {
		if err := replaceFile(s.path, byUser); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.byUser, s.byID, s.stat, s.checked = byUser, byID, stampOf(s.path), time.Now()
	s.mu.Unlock()
	return nil
}

// replaceFile writes the whole file and renames it into place, so a
// crash leaves the previous file rather than half of a new one.
func replaceFile(path string, byUser map[string][]*Credential) error {
	users := make([]string, 0, len(byUser))
	for u := range byUser {
		users = append(users, u)
	}
	sortStrings(users)
	var b strings.Builder
	b.WriteString("# xproxy webauthn credentials: user:credential_id:public_key:sign_count[:label]\n")
	for _, u := range users {
		for _, c := range byUser[u] {
			b.WriteString(c.line())
			b.WriteByte('\n')
		}
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".webauthn-*")
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
	// Flushed before the rename: a rename that lands before the bytes do
	// is a file the next start reads as empty.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// sortStrings sorts in place; the file is written in a stable order so a
// diff of two versions is the change and nothing else.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Path is the file, for the status view.
func (s *Store) Path() string { return s.path }
