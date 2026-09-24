package ntp

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// aesBlock is the test's own way to the subkey derivation, so the RFC
// 4493 vectors can be checked half at a time.
func aesBlock(t *testing.T, key []byte) cipher.Block {
	t.Helper()
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
