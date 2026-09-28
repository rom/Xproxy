package ntske

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rom/xproxy/internal/siv"
)

// Keeping the cookie keys across a restart.
//
// A cookie is sealed under a key this relay holds, so a restart that started
// with fresh keys would invalidate every cookie in the estate at the same
// moment. Every client would find its cookies refused and would have to
// establish keys again -- a TLS handshake each, all at once, which is exactly
// the load a restart should not create. Worse, a client that could not get
// through would have no time source until it did.
//
// So the keys are written down. They are the secret that every cookie's secrecy
// rests on: the file is 0600, it is written through a temporary file in the same
// directory and renamed, so a crash leaves either the whole old set or the whole
// new one, and it is flushed before the rename because a rename that lands
// before the bytes do is a file the next start reads as empty.

// stateVersion is the format's version, so that a later one can be recognised
// rather than misread.
const stateVersion = 1

type storedKey struct {
	ID  uint32 `json:"id"`
	Key string `json:"key"`
}

type state struct {
	Version int         `json:"version"`
	Current storedKey   `json:"current"`
	Old     []storedKey `json:"old"`
}

// ErrState is a state file this cannot use. A relay that read a broken one and
// carried on with fresh keys would be doing the thing the file exists to
// prevent, quietly.
var ErrState = errors.New("ntske: the cookie key state cannot be read")

func store(k CookieKey) storedKey {
	return storedKey{ID: k.ID, Key: base64.StdEncoding.EncodeToString(k.Key)}
}

func load(s storedKey) (CookieKey, error) {
	b, err := base64.StdEncoding.DecodeString(s.Key)
	if err != nil {
		return CookieKey{}, fmt.Errorf("%w: key %d is not base64", ErrState, s.ID)
	}
	if len(b) != siv.KeySize256 {
		return CookieKey{}, fmt.Errorf("%w: key %d is %d octets, not %d",
			ErrState, s.ID, len(b), siv.KeySize256)
	}
	return CookieKey{ID: s.ID, Key: b}, nil
}

// Save writes the key set.
func (k *CookieKeys) Save(path string) error {
	cur, old := k.Keys()
	st := state{Version: stateVersion, Current: store(cur), Old: make([]storedKey, 0, len(old))}
	for _, o := range old {
		st.Old = append(st.Old, store(o))
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".nts-cookies-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load restores a key set written by Save.
//
// A file that is not there is reported as it is, so that a first start can tell
// it apart from a file it could not read: one is ordinary and the other is worth
// an operator's attention.
func (k *CookieKeys) Load(path string) error {
	b, err := os.ReadFile(path) //nolint:gosec // the path is the operator's
	if err != nil {
		return err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("%w: %w", ErrState, err)
	}
	if st.Version != stateVersion {
		return fmt.Errorf("%w: version %d, not %d", ErrState, st.Version, stateVersion)
	}
	cur, err := load(st.Current)
	if err != nil {
		return err
	}
	old := make([]CookieKey, 0, len(st.Old))
	for _, o := range st.Old {
		ck, err := load(o)
		if err != nil {
			return err
		}
		old = append(old, ck)
	}
	return k.Restore(cur, old)
}
