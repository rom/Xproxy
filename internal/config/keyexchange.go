package config

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
)

// Key agreement groups. The names live here, beside the cipher suite
// validation, because they are configuration vocabulary: the TLS
// package resolves them through CurveIDs.
//
// Go picks a sensible set on its own, but only while CurvePreferences is
// left unset — naming any group replaces the whole list, which is how a
// configuration that meant to prefer X25519 silently dropped the
// post-quantum hybrid Go added in 1.24. The groups are configuration
// here so that the choice is written down, validated and visible in
// `xproxyctl tls`, rather than being a side effect of a line nobody
// re-read after a toolchain upgrade.
//
// The default leads with X25519MLKEM768 for one reason: traffic
// recorded today is decrypted by whoever has the key in ten years. A
// hybrid key exchange costs about a kilobyte in the handshake and
// removes that record-now-decrypt-later trade entirely, while the
// classical half keeps the exchange at least as strong as X25519 alone
// if the lattice half is ever broken.

// keyExchangeNames maps the configuration spelling to the group. The
// names are the ones the TLS registry and every other implementation
// use, not Go's identifiers: P-256, not CurveP256.
var keyExchangeNames = map[string]tls.CurveID{
	"X25519MLKEM768": tls.X25519MLKEM768,
	"X25519":         tls.X25519,
	"P-256":          tls.CurveP256,
	"P-384":          tls.CurveP384,
	"P-521":          tls.CurveP521,
}

// postQuantum lists the groups that survive a quantum adversary.
var postQuantum = map[tls.CurveID]bool{tls.X25519MLKEM768: true}

// DefaultKeyExchange is the offered list when the configuration names
// none: the hybrid first, then the classical groups every client has.
func DefaultKeyExchange() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}
}

// KeyExchangeNames lists the accepted spellings, sorted, for error
// messages and the documentation test.
func KeyExchangeNames() []string {
	out := make([]string, 0, len(keyExchangeNames))
	for n := range keyExchangeNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// KeyExchangeID resolves one name.
func KeyExchangeID(name string) (tls.CurveID, bool) {
	id, ok := keyExchangeNames[name]
	return id, ok
}

// IsPostQuantum reports whether a group resists a quantum adversary.
func IsPostQuantum(id tls.CurveID) bool { return postQuantum[id] }

// HasPostQuantum reports whether a configured list offers one.
func HasPostQuantum(names []string) bool {
	for _, n := range names {
		if id, ok := keyExchangeNames[n]; ok && postQuantum[id] {
			return true
		}
	}
	return false
}

// CurveIDs resolves a configured list, or returns the default for an
// empty one.
func CurveIDs(names []string) ([]tls.CurveID, error) {
	if len(names) == 0 {
		return DefaultKeyExchange(), nil
	}
	out := make([]tls.CurveID, 0, len(names))
	for _, n := range names {
		id, ok := keyExchangeNames[n]
		if !ok {
			return nil, fmt.Errorf("unknown key exchange group %q (known: %s)", n, strings.Join(KeyExchangeNames(), ", "))
		}
		out = append(out, id)
	}
	return out, nil
}

// GroupName is the name for a negotiated group, for logs and metrics.
// An unknown group is reported by its number rather than as unknown, so
// a new one a future Go negotiates is still identifiable in a log.
func GroupName(id tls.CurveID) string {
	for n, v := range keyExchangeNames {
		if v == id {
			return n
		}
	}
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("group-%d", uint16(id))
}
