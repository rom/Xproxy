package scim

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/filters/apikey"
	"github.com/rom/xproxy/internal/mfa"
)

// The SCIM resources live in a file of their own, because they are not
// the credentials: the enrolment file and the keys file hold those, and
// a resource has to survive a deactivation that takes both away. One
// user per line, fields separated by "|", "-" for an empty field:
//
//	id|userName|externalId|displayName|active|created|modified|keyIds|scopes
//
// Blank lines and lines beginning with # are ignored, so an operator can
// annotate the file, and the whole file is replaced atomically on every
// change.

// maxUsers bounds the file. A directory pushing more provisioning
// requests than this at one proxy is a mistake worth an error rather
// than a file nobody can read.
const maxUsers = 65536

// stateFields is the number of fields in a line.
const stateFields = 9

// MaxUserName bounds a provisioned name. It is longer than an e-mail
// address and shorter than an attack.
const MaxUserName = 256

// Provisioner keeps the resources and provisions the credentials.
type Provisioner struct {
	opts Options
	// mu serialises a read-modify-write of the state file: two
	// operations arriving together must not lose one another.
	mu sync.Mutex
}

// Options configures a provisioner.
type Options struct {
	// StateFile holds the SCIM resources. Required.
	StateFile string
	// MFA is the enrolment store to provision a second factor in, and
	// nil when this endpoint provisions no factor.
	MFA *mfa.Store
	// Issuer names this estate in the otpauth URI.
	Issuer string
	// KeysFile is the API key file to issue and revoke in, and empty
	// when this endpoint issues no keys.
	KeysFile string
	// KeyScopes are the scopes a key gets when the request names none.
	KeyScopes []string
	// KeyTTL expires an issued key; zero never expires it.
	KeyTTL time.Duration
	// Now is the clock, for tests.
	Now func() time.Time
}

// NewProvisioner checks the options and returns a store.
func NewProvisioner(o Options) (*Provisioner, error) {
	if o.StateFile == "" {
		return nil, errors.New("scim: no state file")
	}
	if !filepath.IsAbs(o.StateFile) {
		return nil, fmt.Errorf("scim: state file %q must be an absolute path", o.StateFile)
	}
	if o.MFA == nil && o.KeysFile == "" {
		return nil, errors.New("scim: nothing to provision: name an enrolment file, a keys file, or both")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Issuer == "" {
		o.Issuer = "xproxy"
	}
	return &Provisioner{opts: o}, nil
}

// List returns the resources, filtered by name when one is given.
func (p *Provisioner) List(userName string) ([]User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	users, err := p.read()
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(users))
	for _, u := range users {
		if userName != "" && u.UserName != userName {
			continue
		}
		out = append(out, p.decorate(u))
	}
	return out, nil
}

// Get returns one resource by id.
func (p *Provisioner) Get(id string) (User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	users, err := p.read()
	if err != nil {
		return User{}, err
	}
	for _, u := range users {
		if u.ID == id {
			return p.decorate(u), nil
		}
	}
	return User{}, Errorf(http.StatusNotFound, "", "no user with id %s", clip(id))
}

// Create provisions a user: the resource, an enrolment and a key.
func (p *Provisioner) Create(in User) (User, error) {
	if err := ValidUserName(in.UserName); err != nil {
		return User{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	users, err := p.read()
	if err != nil {
		return User{}, err
	}
	if len(users) >= maxUsers {
		return User{}, Errorf(http.StatusInsufficientStorage, "", "this endpoint holds %d users", maxUsers)
	}
	for _, u := range users {
		if u.UserName == in.UserName {
			return User{}, Errorf(http.StatusConflict, TypeUniqueness, "userName %s already exists", clip(in.UserName))
		}
	}
	id, err := newID()
	if err != nil {
		return User{}, err
	}
	now := p.opts.Now().UTC().Truncate(time.Second)
	rec := User{
		ID: id, UserName: in.UserName, ExternalID: in.ExternalID,
		DisplayName: in.DisplayName, Active: in.Active,
		Created: now, Modified: now, Scopes: in.Scopes,
	}
	if rec.Active {
		if rec.Secrets, rec.KeyIDs, err = p.provision(rec); err != nil {
			return User{}, err
		}
	}
	if err := p.save(append(users, rec)); err != nil {
		return User{}, err
	}
	return p.decorate(rec), nil
}

// Replace applies a whole resource. The name and the scopes are not
// changed here: both are what a credential was issued for, and this
// endpoint does not replace a credential nobody asked it to replace.
func (p *Provisioner) Replace(id string, in User) (User, error) {
	return p.change(id, func(cur *User) error {
		if in.UserName != "" && in.UserName != cur.UserName {
			return Errorf(http.StatusBadRequest, TypeMutability,
				"userName cannot be changed; create the new user and deprovision this one")
		}
		if len(in.Scopes) > 0 && !sameStrings(in.Scopes, cur.Scopes) {
			return Errorf(http.StatusBadRequest, TypeMutability,
				"the scopes of an issued key cannot be changed here; deprovision and provision again, or rotate the key with xproxyctl")
		}
		cur.ExternalID = in.ExternalID
		cur.DisplayName = in.DisplayName
		return p.setActive(cur, in.Active)
	})
}

// Patch applies the attributes an operation named.
func (p *Provisioner) Patch(id string, v PatchValues) (User, error) {
	return p.change(id, func(cur *User) error {
		if v.ExternalID != nil {
			cur.ExternalID = *v.ExternalID
		}
		if v.DisplayName != nil {
			cur.DisplayName = *v.DisplayName
		}
		if v.Active == nil {
			return nil
		}
		return p.setActive(cur, *v.Active)
	})
}

// Delete deprovisions the user and forgets the resource.
func (p *Provisioner) Delete(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	users, err := p.read()
	if err != nil {
		return err
	}
	for i, u := range users {
		if u.ID != id {
			continue
		}
		if err := p.deprovision(u); err != nil {
			return err
		}
		return p.save(append(users[:i:i], users[i+1:]...))
	}
	return Errorf(http.StatusNotFound, "", "no user with id %s", clip(id))
}

// change reads, applies fn to one resource, and writes the file back.
func (p *Provisioner) change(id string, fn func(*User) error) (User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	users, err := p.read()
	if err != nil {
		return User{}, err
	}
	for i := range users {
		if users[i].ID != id {
			continue
		}
		cur := users[i]
		if err := fn(&cur); err != nil {
			return User{}, err
		}
		cur.Modified = p.opts.Now().UTC().Truncate(time.Second)
		users[i] = cur
		if err := p.save(users); err != nil {
			return User{}, err
		}
		return p.decorate(cur), nil
	}
	return User{}, Errorf(http.StatusNotFound, "", "no user with id %s", clip(id))
}

// setActive moves a user between provisioned and deprovisioned. It is
// the whole point of the endpoint, so it does the work rather than
// recording an intention: deactivating revokes the keys and removes the
// enrolment, and activating mints new ones -- the old secret is gone and
// cannot be handed back.
func (p *Provisioner) setActive(cur *User, active bool) error {
	switch {
	case active == cur.Active:
		return nil
	case !active:
		if err := p.deprovision(*cur); err != nil {
			return err
		}
		cur.Active = false
		return nil
	default:
		secrets, keys, err := p.provision(*cur)
		if err != nil {
			return err
		}
		cur.Active, cur.Secrets, cur.KeyIDs = true, secrets, append(cur.KeyIDs, keys...)
		return nil
	}
}

// provision enrols a second factor and issues a key, returning the
// secrets that exist only now and the key ids to record.
func (p *Provisioner) provision(u User) (*Secrets, []string, error) {
	out := &Secrets{}
	var keys []string
	if p.opts.MFA != nil {
		secret, recovery, err := p.opts.MFA.Enrol(u.UserName, mfa.Params{})
		if err != nil {
			return nil, nil, p.storeError("the enrolment could not be written", err)
		}
		out.OTPAuthURI = mfa.URI(p.opts.Issuer, u.UserName, secret, mfa.Params{})
		out.RecoveryCodes = recovery
	}
	if p.opts.KeysFile != "" {
		scopes := u.Scopes
		if len(scopes) == 0 {
			scopes = p.opts.KeyScopes
		}
		var expires time.Time
		if p.opts.KeyTTL > 0 {
			expires = p.opts.Now().UTC().Add(p.opts.KeyTTL).Truncate(time.Second)
		}
		id, err := KeyID(u.UserName)
		if err != nil {
			return nil, nil, err
		}
		plain, err := apikey.Add(p.opts.KeysFile, id, scopes, expires, "scim:"+clip(u.UserName))
		if err != nil {
			return nil, nil, p.storeError("the key could not be issued", err)
		}
		out.APIKey = plain
		keys = append(keys, id)
	}
	return out, keys, nil
}

// deprovision revokes what was provisioned. A credential that is
// already gone is not an error: the endpoint's job is that nothing is
// left, not that it was the one to remove it.
func (p *Provisioner) deprovision(u User) error {
	if p.opts.MFA != nil {
		if err := p.opts.MFA.Remove(u.UserName); err != nil && !errors.Is(err, mfa.ErrNoSuchUser) {
			return p.storeError("the enrolment could not be removed", err)
		}
	}
	if p.opts.KeysFile == "" {
		return nil
	}
	for _, id := range u.KeyIDs {
		// Revoked, not deleted: the record is how an operator answers
		// "what did that key reach, and when did it stop".
		if err := apikey.Revoke(p.opts.KeysFile, id); err != nil {
			if strings.Contains(err.Error(), "no key ") || errors.Is(err, os.ErrNotExist) {
				continue
			}
			return p.storeError("the key could not be revoked", err)
		}
	}
	return nil
}

// storeError keeps the reason in this proxy's log and out of the
// response: a provider learns that the change did not happen, not which
// file could not be written.
func (p *Provisioner) storeError(what string, err error) error {
	return &storeFailure{detail: what, err: err}
}

// storeFailure is a 500 that carries the cause for the error log.
type storeFailure struct {
	detail string
	err    error
}

func (s *storeFailure) Error() string { return s.detail + ": " + s.err.Error() }
func (s *storeFailure) Unwrap() error { return s.err }

// decorate fills the read-only attributes from the credential stores, so
// a read says what is actually in place rather than what was provisioned
// once. An enrolment removed with xproxyctl shows as not enrolled.
func (p *Provisioner) decorate(u User) User {
	out := u
	if p.opts.MFA != nil {
		_, out.Enrolled = p.opts.MFA.Get(u.UserName)
	}
	if p.opts.KeysFile != "" && len(u.KeyIDs) > 0 {
		keys, err := apikey.Load(p.opts.KeysFile)
		if err == nil {
			active := make([]string, 0, len(u.KeyIDs))
			scopes := out.Scopes
			for _, k := range keys {
				for _, id := range u.KeyIDs {
					if k.ID == id && k.State == "active" {
						active = append(active, k.ID)
						if len(scopes) == 0 {
							scopes = k.Scopes
						}
					}
				}
			}
			out.KeyIDs, out.Scopes = active, scopes
		}
	}
	return out
}

// read loads the state file. A missing file is an empty store: the first
// provisioning creates it.
func (p *Provisioner) read() ([]User, error) {
	data, err := os.ReadFile(p.opts.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, p.storeError("the user file could not be read", err)
	}
	lines := strings.Split(string(data), "\n")
	out := make([]User, 0, len(lines))
	for n, line := range lines {
		text := strings.TrimSpace(line)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		u, err := parseUserLine(text)
		if err != nil {
			return nil, p.storeError(fmt.Sprintf("the user file is unreadable at line %d", n+1), err)
		}
		out = append(out, u)
	}
	return out, nil
}

// save replaces the file atomically.
func (p *Provisioner) save(users []User) error {
	sort.Slice(users, func(i, j int) bool { return users[i].UserName < users[j].UserName })
	var b strings.Builder
	b.WriteString("# SCIM provisioned users. id|userName|externalId|displayName|active|created|modified|keyIds|scopes\n")
	for _, u := range users {
		b.WriteString(userLine(u))
		b.WriteByte('\n')
	}
	dir := filepath.Dir(p.opts.StateFile)
	tmp, err := os.CreateTemp(dir, ".scim-users-*")
	if err != nil {
		return p.storeError("the user file could not be written", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return p.storeError("the user file could not be written", err)
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		_ = tmp.Close()
		return p.storeError("the user file could not be written", err)
	}
	if err := tmp.Close(); err != nil {
		return p.storeError("the user file could not be written", err)
	}
	if err := os.Rename(name, p.opts.StateFile); err != nil {
		return p.storeError("the user file could not be replaced", err)
	}
	return nil
}

func userLine(u User) string {
	field := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	active := "false"
	if u.Active {
		active = "true"
	}
	joined := func(v []string) string {
		if len(v) == 0 {
			return "-"
		}
		return strings.Join(v, ",")
	}
	return strings.Join([]string{
		u.ID, u.UserName, field(u.ExternalID), field(u.DisplayName), active,
		u.Created.UTC().Format(time.RFC3339), u.Modified.UTC().Format(time.RFC3339),
		joined(u.KeyIDs), joined(u.Scopes),
	}, "|")
}

func parseUserLine(text string) (User, error) {
	f := strings.Split(text, "|")
	if len(f) != stateFields {
		return User{}, fmt.Errorf("%d fields, want %d", len(f), stateFields)
	}
	u := User{ID: f[0], UserName: f[1]}
	if u.ID == "" || u.UserName == "" {
		return User{}, errors.New("a line needs an id and a name")
	}
	if err := ValidUserName(u.UserName); err != nil {
		return User{}, err
	}
	if f[2] != "-" {
		u.ExternalID = f[2]
	}
	if f[3] != "-" {
		u.DisplayName = f[3]
	}
	switch f[4] {
	case "true":
		u.Active = true
	case "false":
	default:
		return User{}, fmt.Errorf("active: %q is neither true nor false", f[4])
	}
	var err error
	if u.Created, err = time.Parse(time.RFC3339, f[5]); err != nil {
		return User{}, fmt.Errorf("created: %w", err)
	}
	if u.Modified, err = time.Parse(time.RFC3339, f[6]); err != nil {
		return User{}, fmt.Errorf("modified: %w", err)
	}
	if f[7] != "-" {
		u.KeyIDs = strings.Split(f[7], ",")
	}
	if f[8] != "-" {
		u.Scopes = strings.Split(f[8], ",")
	}
	return u, nil
}

// ValidUserName says whether a name can be provisioned. The separators
// are what the file is made of, so a name cannot contain one, and a name
// appears in logs, so it carries no control characters.
func ValidUserName(name string) error {
	switch {
	case name == "":
		return Errorf(http.StatusBadRequest, TypeInvalidValue, "userName is required")
	case len(name) > MaxUserName:
		return Errorf(http.StatusBadRequest, TypeInvalidValue, "userName is longer than %d characters", MaxUserName)
	case name != strings.TrimSpace(name):
		return Errorf(http.StatusBadRequest, TypeInvalidValue, "userName has leading or trailing whitespace")
	case strings.HasPrefix(name, "#"):
		return Errorf(http.StatusBadRequest, TypeInvalidValue, "userName cannot begin with #, which starts a comment")
	}
	for _, r := range name {
		switch {
		case r == '|' || r == ',':
			return Errorf(http.StatusBadRequest, TypeInvalidValue, "userName cannot contain %q, which separates the fields", string(r))
		case r < 0x20 || r == 0x7F:
			return Errorf(http.StatusBadRequest, TypeInvalidValue, "userName cannot contain control characters")
		}
	}
	// The enrolment file has its own rules, and a name this proxy cannot
	// enrol is refused at the door rather than half provisioned.
	if err := mfa.ValidName(name); err != nil {
		return Errorf(http.StatusBadRequest, TypeInvalidValue, "userName: %v", err)
	}
	return nil
}

// KeyID derives an API key id from a user name: the key file accepts 1
// to 32 characters of a-z, 0-9, - and _, which an e-mail address is not,
// and a random suffix keeps a reprovisioned user from colliding with the
// revoked key of the last one.
func KeyID(name string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 24 {
			break
		}
	}
	stem := strings.Trim(b.String(), "-")
	if stem == "" {
		stem = "user"
	}
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	return stem + "-" + hex.EncodeToString(suffix), nil
}

// newID is the opaque, server-assigned resource id RFC 7643 asks for.
func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// clip bounds what of a caller's own string is echoed back or logged.
func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
