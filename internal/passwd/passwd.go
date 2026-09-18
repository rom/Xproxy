// Package passwd hashes and verifies passwords with PBKDF2-HMAC-SHA256
// from the standard library. The stored form is
// "pbkdf2-sha256$<iterations>$<salt>$<hash>" with base64 (no padding)
// fields, so the iteration count can be raised without a format change.
package passwd

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	prefix     = "pbkdf2-sha256"
	Iterations = 600_000
	hashLen    = 32
	// MinLength is the shortest password Hash accepts.
	MinLength = 12
	maxLength = 1024
)

// Hash derives a stored hash with the default iteration count.
func Hash(password string) (string, error) {
	return HashWithIterations(password, Iterations)
}

// HashWithIterations derives a stored hash with a chosen iteration count
// (tests use a low count; production uses Iterations).
func HashWithIterations(password string, iterations int) (string, error) {
	if len(password) < MinLength {
		return "", fmt.Errorf("password must be at least %d characters", MinLength)
	}
	if len(password) > maxLength {
		return "", errors.New("password too long")
	}
	if iterations < 1000 {
		return "", errors.New("iterations too low")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, iterations, hashLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", prefix, iterations,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

// Verify checks a password against a stored hash in constant time with
// respect to the hash contents. Malformed hashes never verify.
func Verify(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != prefix {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 || iter > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != hashLen {
		return false
	}
	if len(password) > maxLength {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, hashLen)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// IsHash reports whether s has the stored form (not whether it verifies).
func IsHash(s string) bool {
	parts := strings.Split(s, "$")
	return len(parts) == 4 && parts[0] == prefix
}
