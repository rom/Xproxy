// Package mfa is the second factor, shared by every protocol that can
// ask for one.
//
// It is one package rather than one per protocol because a second
// factor that means different things on different ports is not a second
// factor: the same enrolment, the same replay rule and the same lockout
// have to hold whether the user is opening an SSH session or a web
// page, or the weakest door decides.
//
// Time-based one-time passwords (RFC 6238 over the HMAC-OTP of RFC
// 4226) are what it implements: every authenticator application speaks
// them, they need no network call at verification time, and the secret
// never leaves the estate.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 4226 specifies HMAC-SHA-1, and every authenticator implements it
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Defaults every authenticator application assumes when the enrolment
// URI does not say otherwise.
const (
	DefaultDigits = 6
	DefaultPeriod = 30 * time.Second
	DefaultAlgo   = "SHA1"
	// SecretBytes is the length of a generated secret. RFC 4226 section
	// 4 requires at least 128 bits and recommends 160, which is also
	// the output length of the default HMAC.
	SecretBytes = 20
)

var (
	// ErrUnknownUser is a name with no enrolment.
	ErrUnknownUser = errors.New("mfa: no enrolment for this user")
	// ErrBadCode is a code that does not verify.
	ErrBadCode = errors.New("mfa: code is not valid")
	// ErrReplay is a code that verified but was already used. A
	// one-time password used twice is not one-time, and the window that
	// makes a code usable at all is the window an observer has to
	// replay it in.
	ErrReplay = errors.New("mfa: code was already used")
	// ErrLocked is a user with too many recent failures.
	ErrLocked = errors.New("mfa: too many failed attempts")
)

// base32Enc is the unpadded encoding authenticator applications use.
var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a fresh secret and its base32 form.
func NewSecret() (string, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32Enc.EncodeToString(b), nil
}

// ParseSecret decodes a base32 secret, tolerating the spaces and
// lowercase people paste from a screen.
func ParseSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	if s == "" {
		return nil, errors.New("mfa: empty secret")
	}
	b, err := base32Enc.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("mfa: secret is not base32: %w", err)
	}
	if len(b) < 16 {
		return nil, errors.New("mfa: secret is shorter than the 128 bits RFC 4226 requires")
	}
	return b, nil
}

// Params are the parameters of one enrolment.
type Params struct {
	Digits int
	Period time.Duration
	Algo   string
}

func (p Params) normalise() Params {
	if p.Digits == 0 {
		p.Digits = DefaultDigits
	}
	if p.Period == 0 {
		p.Period = DefaultPeriod
	}
	if p.Algo == "" {
		p.Algo = DefaultAlgo
	}
	return p
}

func newHash(algo string) (func() hash.Hash, error) {
	switch strings.ToUpper(algo) {
	case "SHA1":
		return sha1.New, nil //nolint:gosec // RFC 4226 specifies it; the HMAC construction is what carries the security
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("mfa: unknown algorithm %q", algo)
	}
}

// Code is the HOTP value for a counter (RFC 4226 section 5.3).
func Code(secret []byte, counter uint64, p Params) (string, error) {
	p = p.normalise()
	nh, err := newHash(p.Algo)
	if err != nil {
		return "", err
	}
	mac := hmac.New(nh, secret)
	_, _ = mac.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < p.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", p.Digits, value%mod), nil
}

// Counter is the time step a moment falls in (RFC 6238 section 4.2).
func Counter(t time.Time, period time.Duration) uint64 {
	if period <= 0 {
		period = DefaultPeriod
	}
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return uint64(s) / uint64(period/time.Second) //nolint:gosec // non-negative
}

// Check verifies a code against the steps within skew of now, and
// returns the step it matched. The comparison is constant time and
// every candidate step is tried, so neither the answer nor the time
// taken says which step matched.
func Check(secret []byte, code string, now time.Time, p Params, skew int) (uint64, bool) {
	p = p.normalise()
	if len(code) != p.Digits {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	base := Counter(now, p.Period)
	var matched uint64
	found := 0
	for d := -skew; d <= skew; d++ {
		step := base
		switch {
		case d < 0:
			u := uint64(-d)
			if u > base {
				continue
			}
			step = base - u
		case d > 0:
			step = base + uint64(d)
		}
		want, err := Code(secret, step, p)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			matched = step
			found++
		}
	}
	return matched, found > 0
}

// URI is the otpauth:// enrolment URI an authenticator reads from a QR
// code (the de facto Key URI format).
func URI(issuer, account, secret string, p Params) string {
	p = p.normalise()
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	q := url.Values{}
	q.Set("secret", secret)
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	q.Set("algorithm", strings.ToUpper(p.Algo))
	q.Set("digits", strconv.Itoa(p.Digits))
	q.Set("period", strconv.Itoa(int(p.Period/time.Second)))
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + label, RawQuery: q.Encode()}
	return u.String()
}
