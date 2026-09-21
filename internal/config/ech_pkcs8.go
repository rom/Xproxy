package config

import "crypto/ecdh"

// ecdhBytes extracts the raw scalar from a parsed PKCS#8 key when it is
// an X25519 one.
func ecdhBytes(k any) ([]byte, bool) {
	if p, ok := k.(*ecdh.PrivateKey); ok && p.Curve() == ecdh.X25519() {
		return p.Bytes(), true
	}
	return nil, false
}
