package packs

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Loading packs from a directory, and what makes a file trustworthy.
//
// # Why signatures matter here and not everywhere
//
// A configuration file is read from a path an administrator chose, and if
// somebody can write to it they can already write the whole policy: a
// signature there would be theatre. A pack directory is different in two ways.
// It is meant to be *updated out of band* -- dropped in by a package, a
// configuration management run, a download -- which is exactly the supply
// chain a signature is for. And a pack changes what the proxy alerts on and
// may quarantine, so a forged one is a way to make a plant's relay refuse its
// own master.
//
// So the rule is: a pack is loaded when a key this estate trusts signed it.
// `allow_unsigned` exists for the pack an engineer wrote this morning against
// their own plant, and it warns every time, because an estate that turned it on
// to try something and left it on has a directory anybody can write detections
// into.
//
// # The signature
//
// A detached file beside the pack: `<pack>.yaml.sig`, one line,
//
//	ed25519 <key name> <base64 signature>
//
// over the pack file's exact bytes. Detached and textual on purpose: the pack
// stays a file an engineer can read and diff, `sha256sum`-style tooling works
// on it, and the signature can be produced by anything that can sign 32 bytes
// -- including the same signer helper the rest of this project uses for keys it
// must not hold (docs/SIGNER.md).
//
// Ed25519 and nothing else. A format with a choice of algorithm is a format
// with a downgrade, and there is no interoperability requirement here to pay
// for one with.

// SigExt is the extension of the detached signature beside a pack.
const SigExt = ".sig"

// sigAlgorithm is the one algorithm a signature may name.
const sigAlgorithm = "ed25519"

// Key is a public key this estate trusts to sign packs.
type Key struct {
	// Name is what the signature names, and what a loaded pack reports as
	// its signer. It is not a secret and it is not a path.
	Name string
	// Public is the ed25519 public key.
	Public ed25519.PublicKey
}

// ParseKey reads a public key from its base64 encoding, which is what both the
// configuration and a key file carry. A key of the wrong length is refused
// rather than padded.
func ParseKey(name, encoded string) (Key, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Key{}, errors.New("a trusted key needs a name, because a signature names one")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return Key{}, fmt.Errorf("key %s: not base64: %w", name, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return Key{}, fmt.Errorf("key %s: %d bytes, an ed25519 public key is %d",
			name, len(raw), ed25519.PublicKeySize)
	}
	return Key{Name: name, Public: ed25519.PublicKey(raw)}, nil
}

// ReadKeyFile reads a public key from a file holding its base64 encoding, with
// blank lines and `#` comments allowed so a key file can say what it is.
func ReadKeyFile(name, path string) (Key, error) {
	b, err := os.ReadFile(path) //nolint:gosec // an operator's own path, like every other file in the configuration
	if err != nil {
		return Key{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A file written by `ssh-keygen`-shaped tooling has the algorithm
		// first; take the last field either way.
		fields := strings.Fields(line)
		return ParseKey(name, fields[len(fields)-1])
	}
	return Key{}, fmt.Errorf("key %s: %s holds no key", name, path)
}

// Trust is what the loader will accept.
type Trust struct {
	// Keys are the public keys a signature may name. A signature naming a key
	// that is not here is refused: an unknown signer is not a weaker
	// signature, it is no signature.
	Keys []Key
	// AllowUnsigned loads a pack with no signature file beside it. Each one
	// is reported so the caller can warn.
	AllowUnsigned bool
}

// key finds a trusted key by name.
func (t Trust) key(name string) (Key, bool) {
	for _, k := range t.Keys {
		if k.Name == name {
			return k, true
		}
	}
	return Key{}, false
}

// Sign produces the signature line for a pack's bytes. It is here rather than
// in a tool so that the tests sign the way the loader verifies, and so there is
// one definition of what is signed.
func Sign(name string, priv ed25519.PrivateKey, pack []byte) string {
	return fmt.Sprintf("%s %s %s\n", sigAlgorithm, name,
		base64.StdEncoding.EncodeToString(ed25519.Sign(priv, pack)))
}

// verify checks a signature line against a pack's bytes and returns the name of
// the key that signed it.
func (t Trust) verify(sig, pack []byte) (string, error) {
	line := strings.TrimSpace(string(sig))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return "", errors.New("signature: expected `ed25519 <key name> <base64>`")
	}
	if fields[0] != sigAlgorithm {
		return "", fmt.Errorf("signature algorithm %q: this build verifies %s only", fields[0], sigAlgorithm)
	}
	k, ok := t.key(fields[1])
	if !ok {
		return "", fmt.Errorf("signature names key %q, which this estate does not trust", fields[1])
	}
	raw, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return "", fmt.Errorf("signature: not base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return "", fmt.Errorf("signature: %d bytes, ed25519 is %d", len(raw), ed25519.SignatureSize)
	}
	if !ed25519.Verify(k.Public, pack, raw) {
		return "", fmt.Errorf("signature by %q does not verify: the file has changed since it was signed, "+
			"or it was signed by a different key of that name", k.Name)
	}
	return k.Name, nil
}

// Report is what a load produced: the packs, and everything worth telling an
// operator about the directory.
type Report struct {
	// Packs are the packs that loaded, sorted by identifier.
	Packs []*Pack
	// Unsigned are the files loaded with no signature, when AllowUnsigned let
	// them. Each is worth a warning.
	Unsigned []string
	// Superseded are the files a higher revision of the same identifier
	// replaced, so dropping an update in beside what is there says so rather
	// than silently doing one of the two.
	Superseded []string
	// Skipped are the files that are not packs at all -- a README, a
	// signature, an editor's leftover -- so a directory can hold them.
	Skipped []string
}

// Load reads every pack in a directory.
//
// A file that does not load is an error and stops the load, with the file
// named. That is deliberate and it is the opposite of what a rule-set loader
// usually does: a pack directory is small, hand-curated and signed, so a file
// in it that does not parse is a mistake somebody made minutes ago and wants to
// hear about -- not a reason to start with a detection missing and no mention of
// it anywhere but a counter.
func Load(dir string, t Trust) (*Report, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rep := &Report{}
	byID := map[string]*Pack{}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	// Sorted, so two files with one identifier resolve the same way on every
	// machine whatever order the directory happens to be read in.
	sort.Strings(names)
	for _, name := range names {
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			rep.Skipped = append(rep.Skipped, name)
			continue
		}
		path := filepath.Join(dir, name)
		p, signer, unsigned, err := loadOne(path, t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if unsigned {
			rep.Unsigned = append(rep.Unsigned, name)
		}
		p.Source = name
		p.Signer = signer
		if old, ok := byID[p.ID]; ok {
			switch {
			case p.Revision > old.Revision:
				rep.Superseded = append(rep.Superseded, old.Source)
				byID[p.ID] = p
			case p.Revision < old.Revision:
				rep.Superseded = append(rep.Superseded, name)
			default:
				return nil, fmt.Errorf("%s: pack %s revision %d is also in %s: "+
					"a corrected pack takes a higher revision, so that an estate can tell which one it is running",
					name, p.ID, p.Revision, old.Source)
			}
			continue
		}
		byID[p.ID] = p
	}
	for _, p := range byID {
		rep.Packs = append(rep.Packs, p)
	}
	sort.Slice(rep.Packs, func(i, j int) bool { return rep.Packs[i].ID < rep.Packs[j].ID })
	return rep, nil
}

// loadOne reads and verifies one file.
func loadOne(path string, t Trust) (*Pack, string, bool, error) {
	body, err := os.ReadFile(path) //nolint:gosec // an operator's own directory
	if err != nil {
		return nil, "", false, err
	}
	signer, unsigned := "", false
	sig, err := os.ReadFile(path + SigExt) //nolint:gosec // beside the pack
	switch {
	case err == nil:
		if len(t.Keys) == 0 {
			return nil, "", false, errors.New("a signature is beside this pack and no trusted key is configured, " +
				"so nothing can say whether it is the right one")
		}
		if signer, err = t.verify(sig, body); err != nil {
			return nil, "", false, err
		}
	case errors.Is(err, os.ErrNotExist):
		if !t.AllowUnsigned {
			return nil, "", false, fmt.Errorf("no signature (%s%s): a pack directory is read at start and "+
				"changes what this daemon alerts on, so an unsigned file is refused unless allow_unsigned says otherwise",
				filepath.Base(path), SigExt)
		}
		unsigned = true
	default:
		return nil, "", false, err
	}

	var p Pack
	dec := yaml.NewDecoder(strings.NewReader(string(body)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, "", false, err
	}
	if err := p.Check(); err != nil {
		return nil, "", false, err
	}
	return &p, signer, unsigned, nil
}
