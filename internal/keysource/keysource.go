// Package keysource resolves a configured reference to secret material.
//
// A proxy holds a great many secrets: TLS private keys, an upstream client
// key, a Consul token, a bind password, the keyring behind every cookie it
// seals. Until now every one of them was a path, and a path means the material
// is on the file system of the machine -- readable by whatever else can read
// that machine, present in its backups, and replaced by whatever writes there.
//
// A reference says *where* a secret comes from instead:
//
//	/etc/xproxy/tls/edge.key          a path, as before
//	file:/etc/xproxy/tls/edge.key     the same, said explicitly
//	env:EDGE_KEY                      the environment of this process
//	vault:secret/tls/edge#key         a field of a secret in HashiCorp Vault
//
// What this buys is not secrecy from the kernel -- the material is in this
// process's memory either way -- but custody: who holds the master copy, who
// may read it, how it is rotated, and what an attacker gets from the file
// system alone. The strongest arrangement here is the one where the private key
// never enters this process at all, which is what the external signer is for
// (see signer.go); a vault is the middle ground, and a file is the base case.
//
// Three rules the package holds to, because a secret resolver that breaks them
// is worse than a path:
//
//   - **A value is never logged, wrapped in an error, or put in a dump.** Errors
//     name the reference. The configuration holds references rather than
//     material, so `xproxyctl dump`, the history and a diff show where a secret
//     comes from and never what it is.
//   - **A resolved value is cached and refreshed on a TTL**, so a rotation in
//     the vault reaches a running proxy without a reload.
//   - **A failed refresh keeps the previous value** and warns. A vault that is
//     down must not take a TLS key away from a proxy that is serving with it;
//     the whole point of the arrangement is that the estate keeps working while
//     somebody fixes the vault.
package keysource

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Scheme prefixes a reference may carry.
const (
	SchemeFile  = "file"
	SchemeEnv   = "env"
	SchemeVault = "vault"
)

var (
	// ErrNoVault is a vault reference with no vault configured.
	ErrNoVault = errors.New("keysource: a vault reference needs a secrets.vault section")
	// ErrUnknownScheme is a reference this package does not understand. It is
	// an error rather than a fallback to "file", because a typo in a scheme
	// must not become a path nobody meant.
	ErrUnknownScheme = errors.New("keysource: unknown reference scheme")
	// ErrEmpty is a reference that resolved to nothing. A secret file an
	// operator truncated is an outage either way; saying so beats a key of
	// length zero reaching a TLS stack.
	ErrEmpty = errors.New("keysource: the reference resolved to nothing")
)

// maxSecretBytes bounds what a reference may hand back. The largest legitimate
// secret here is a key bundle of a few kilobytes; a megabyte is a wrong path or
// a vault returning something else entirely.
const maxSecretBytes = 1 << 20

// A Reference is a parsed reference: which source, and what within it.
type Reference struct {
	// Scheme is file, env or vault.
	Scheme string
	// Target is the path, the variable name, or the vault path.
	Target string
	// Field is the field within a vault secret; empty for the other schemes.
	Field string
}

// Parse reads a reference. A value with no scheme is a path, so every
// configuration written before this existed keeps its meaning.
func Parse(ref string) (Reference, error) {
	s := strings.TrimSpace(ref)
	if s == "" {
		return Reference{}, ErrEmpty
	}
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || strings.HasPrefix(s, "/") {
		// A bare path, including the absolute paths every existing
		// configuration uses.
		return Reference{Scheme: SchemeFile, Target: s}, nil
	}
	switch scheme {
	case SchemeFile:
		if rest == "" {
			return Reference{}, fmt.Errorf("%w: file: with no path", ErrEmpty)
		}
		return Reference{Scheme: SchemeFile, Target: rest}, nil
	case SchemeEnv:
		if rest == "" {
			return Reference{}, fmt.Errorf("%w: env: with no variable", ErrEmpty)
		}
		return Reference{Scheme: SchemeEnv, Target: rest}, nil
	case SchemeVault:
		path, field, hasField := strings.Cut(rest, "#")
		if path == "" {
			return Reference{}, fmt.Errorf("%w: vault: with no path", ErrEmpty)
		}
		if !hasField || field == "" {
			// Which field is not a detail to guess at: a secret usually
			// holds several, and picking one for the operator is how the
			// wrong key gets served.
			return Reference{}, fmt.Errorf("%w: vault:%s needs a field (vault:mount/path#field)", ErrEmpty, path)
		}
		return Reference{Scheme: SchemeVault, Target: path, Field: field}, nil
	}
	return Reference{}, fmt.Errorf("%w: %q (file, env or vault)", ErrUnknownScheme, scheme)
}

// String renders the reference as it was written, which is what a log line or
// an error may carry. It never contains the material.
func (r Reference) String() string {
	switch {
	case r.Scheme == SchemeVault && r.Field != "":
		return r.Scheme + ":" + r.Target + "#" + r.Field
	case r.Scheme == "":
		return r.Target
	}
	return r.Scheme + ":" + r.Target
}

// IsFile says whether the reference is an ordinary path, which is what the
// sandbox rules and the "does this file exist" checks at load are about.
func (r Reference) IsFile() bool { return r.Scheme == SchemeFile }

// A Warner receives a refresh that failed while the previous value stays in
// force. It is a function rather than a logger so that this package does not
// have to know how the daemon logs.
type Warner func(ref string, err error)

// A Resolver turns references into material, caching what it resolves.
type Resolver struct {
	// vault answers vault references; nil when none is configured, and then
	// a vault reference is an error rather than a silent miss.
	vault *Vault
	// ttl is how long a resolved value is used before it is fetched again.
	// 0 means a value is resolved once and kept, which is what a file
	// reference has always done.
	ttl time.Duration
	// warn receives a refresh that failed.
	warn Warner
	now  func() time.Time

	mu    sync.Mutex
	cache map[string]*entry
}

// entry is one cached value.
type entry struct {
	value []byte
	at    time.Time
	// stale records that the last refresh failed, so a status view can say
	// the proxy is serving material older than its TTL.
	stale bool
}

// New builds a resolver. A nil vault is fine; a vault reference then fails
// rather than falling back to anything.
func New(v *Vault, ttl time.Duration, warn Warner) *Resolver {
	return &Resolver{vault: v, ttl: ttl, warn: warn, now: time.Now, cache: map[string]*entry{}}
}

// SetClockForTest replaces the clock.
func (r *Resolver) SetClockForTest(f func() time.Time) { r.now = f }

// Bytes resolves a reference to material.
//
// Within the TTL the cached value is returned. Past it the source is asked
// again, and a failure keeps the previous value: a vault that is down must not
// take a key away from a proxy that is already serving with it.
func (r *Resolver) Bytes(ref string) ([]byte, error) {
	parsed, err := Parse(ref)
	if err != nil {
		return nil, err
	}
	key := parsed.String()
	r.mu.Lock()
	cached, ok := r.cache[key]
	fresh := ok && (r.ttl == 0 || r.now().Sub(cached.at) < r.ttl)
	r.mu.Unlock()
	if fresh {
		return append([]byte(nil), cached.value...), nil
	}
	value, err := r.fetch(parsed)
	if err != nil {
		if ok {
			// Serve what we have and say so, once per failure rather than
			// once per read: the caller is often a handshake.
			r.mu.Lock()
			if !cached.stale {
				cached.stale = true
				if r.warn != nil {
					r.warn(key, err)
				}
			}
			out := append([]byte(nil), cached.value...)
			r.mu.Unlock()
			return out, nil
		}
		return nil, err
	}
	r.mu.Lock()
	r.cache[key] = &entry{value: value, at: r.now()}
	r.mu.Unlock()
	return append([]byte(nil), value...), nil
}

// StringValue resolves a reference to a string with surrounding space removed,
// which is what a token or a password in a file wants: an editor's trailing
// newline is not part of the credential.
func (r *Resolver) StringValue(ref string) (string, error) {
	b, err := r.Bytes(ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Stale lists the references whose last refresh failed, for the status view. An
// operator has to be able to see that the proxy is serving material it could
// not confirm.
func (r *Resolver) Stale() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for k, e := range r.cache {
		if e.stale {
			out = append(out, k)
		}
	}
	return out
}

// fetch asks the source, bounded and without ever returning the value in an
// error.
func (r *Resolver) fetch(ref Reference) ([]byte, error) {
	switch ref.Scheme {
	case SchemeFile:
		b, err := os.ReadFile(ref.Target) //nolint:gosec // the path is the operator's own configuration
		if err != nil {
			return nil, fmt.Errorf("keysource %s: %w", ref, err)
		}
		return bound(ref, b)
	case SchemeEnv:
		v, ok := os.LookupEnv(ref.Target)
		if !ok {
			return nil, fmt.Errorf("keysource %s: the variable is not set", ref)
		}
		return bound(ref, []byte(v))
	case SchemeVault:
		if r.vault == nil {
			return nil, fmt.Errorf("%w (%s)", ErrNoVault, ref)
		}
		v, err := r.vault.Read(ref.Target, ref.Field)
		if err != nil {
			return nil, fmt.Errorf("keysource %s: %w", ref, err)
		}
		return bound(ref, v)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownScheme, ref.Scheme)
}

// bound refuses an empty or oversize value, naming the reference and not the
// material.
func bound(ref Reference, b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmpty, ref)
	}
	if len(b) > maxSecretBytes {
		return nil, fmt.Errorf("keysource %s: %d bytes is more than a secret (bound %d); is that the right path?",
			ref, len(b), maxSecretBytes)
	}
	return b, nil
}
