package mfa_test

import (
	"encoding/base32"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/passwd"
)

// The RFC 4226 appendix D test vectors, which every other implementation
// is checked against too.
func TestHOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		got, err := mfa.Code(secret, uint64(i), mfa.Params{})
		if err != nil {
			t.Fatal(err)
		}
		if got != w {
			t.Errorf("counter %d: got %s want %s", i, got, w)
		}
	}
}

// The RFC 6238 appendix B vectors, which also pin the counter
// derivation and the other two hashes.
func TestTOTPVectors(t *testing.T) {
	seed := "12345678901234567890"
	seed32 := strings.Repeat("12345678901234567890", 2)[:32]
	seed64 := strings.Repeat("12345678901234567890", 4)[:64]
	cases := []struct {
		unix   int64
		algo   string
		secret string
		want   string
	}{
		{59, "SHA1", seed, "94287082"},
		{59, "SHA256", seed32, "46119246"},
		{59, "SHA512", seed64, "90693936"},
		{1111111109, "SHA1", seed, "07081804"},
		{1111111111, "SHA1", seed, "14050471"},
		{1234567890, "SHA1", seed, "89005924"},
		{2000000000, "SHA1", seed, "69279037"},
		{20000000000, "SHA1", seed, "65353130"},
		{1111111109, "SHA256", seed32, "68084774"},
		{1111111109, "SHA512", seed64, "25091201"},
	}
	for _, c := range cases {
		p := mfa.Params{Digits: 8, Algo: c.algo}
		step := mfa.Counter(time.Unix(c.unix, 0), mfa.DefaultPeriod)
		got, err := mfa.Code([]byte(c.secret), step, p)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%d %s: got %s want %s", c.unix, c.algo, got, c.want)
		}
	}
}

func TestCheckSkew(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	p := mfa.Params{}
	prev, _ := mfa.Code(secret, mfa.Counter(now, mfa.DefaultPeriod)-1, p)
	if _, ok := mfa.Check(secret, prev, now, p, 1); !ok {
		t.Fatal("the previous step should verify with skew 1")
	}
	if _, ok := mfa.Check(secret, prev, now, p, 0); ok {
		t.Fatal("the previous step should not verify with skew 0")
	}
	// Anything that is not the right shape is refused before any HMAC
	// is computed.
	for _, bad := range []string{"", "12345", "1234567", "12345a", "     "} {
		if _, ok := mfa.Check(secret, bad, now, p, 1); ok {
			t.Errorf("%q verified", bad)
		}
	}
}

func TestSecretRoundTrip(t *testing.T) {
	s, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := mfa.ParseSecret(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != mfa.SecretBytes {
		t.Fatalf("secret is %d bytes", len(b))
	}
	// The forms people paste from a screen.
	if _, err := mfa.ParseSecret(strings.ToLower(s[:8] + " " + s[8:])); err != nil {
		t.Fatalf("a spaced lowercase secret should parse: %v", err)
	}
	for _, bad := range []string{"", "not base32!", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("short"))} {
		if _, err := mfa.ParseSecret(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestURI(t *testing.T) {
	u := mfa.URI("xproxy", "alice", "JBSWY3DPEHPK3PXP", mfa.Params{})
	for _, want := range []string{"otpauth://totp/xproxy:alice", "secret=JBSWY3DPEHPK3PXP", "issuer=xproxy", "digits=6", "period=30", "algorithm=SHA1"} {
		if !strings.Contains(u, want) {
			t.Errorf("%q missing from %s", want, u)
		}
	}
}

func writeStore(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mfa")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	hash, err := passwd.Hash("recovery-code-1")
	if err != nil {
		t.Fatal(err)
	}
	path := writeStore(t,
		"# a comment",
		"",
		"alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"bob:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP:digits=8,period=60,algo=SHA256",
		"carol:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP::"+hash)
	s, err := mfa.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Users()) != 3 {
		t.Fatalf("users: %v", s.Users())
	}
	b, _ := s.Get("bob")
	if b.Params.Digits != 8 || b.Params.Period != time.Minute || b.Params.Algo != "SHA256" {
		t.Fatalf("bob: %+v", b.Params)
	}
	c, _ := s.Get("carol")
	if len(c.Recovery) != 1 {
		t.Fatalf("carol: %+v", c.Recovery)
	}
}

// A line that does not parse fails the load: a user who was meant to be
// enrolled and silently is not is a door left open.
func TestLoadRefusesBadLines(t *testing.T) {
	bad := [][]string{
		{"alice"},
		{"alice:not-base32!"},
		{"alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP:digits=99"},
		{"alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP:period=1"},
		{"alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP:algo=MD5"},
		{"alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP::plaintext-recovery"},
		{"alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"},
		{":JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"},
	}
	for _, lines := range bad {
		if _, err := mfa.Load(writeStore(t, lines...)); err == nil {
			t.Errorf("%v should not load", lines)
		}
	}
	// An empty file is not an enrolment file.
	if _, err := mfa.Load(writeStore(t, "# nothing")); err == nil {
		t.Error("an empty file should not load")
	}
}

// A file anyone can read holds every second factor.
func TestLoadRefusesWorldReadable(t *testing.T) {
	p := writeStore(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mfa.Load(p); err == nil {
		t.Fatal("a world readable enrolment file should not load")
	}
}

func guardFor(t *testing.T, lines ...string) (*mfa.Guard, []byte) {
	t.Helper()
	s, err := mfa.Load(writeStore(t, lines...))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := s.Get("alice")
	return mfa.NewGuard(s, 1, mfa.Lockout{MaxFailures: 3, Window: time.Minute, Duration: time.Hour}), e.Secret
}

// A one-time password used twice is not one-time.
func TestGuardReplay(t *testing.T) {
	g, secret := guardFor(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	now := time.Unix(1700000000, 0)
	code, err := mfa.Code(secret, mfa.Counter(now, mfa.DefaultPeriod), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Verify("alice", code, now); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := g.Verify("alice", code, now); !errors.Is(err, mfa.ErrReplay) {
		t.Fatalf("second use: want ErrReplay, got %v", err)
	}
	// The next step still works: only the spent one is refused.
	later := now.Add(mfa.DefaultPeriod)
	next, _ := mfa.Code(secret, mfa.Counter(later, mfa.DefaultPeriod), mfa.Params{})
	if err := g.Verify("alice", next, later); err != nil {
		t.Fatalf("next step: %v", err)
	}
	// And an earlier step is refused even within the skew window,
	// because it is behind the one already spent.
	earlier, _ := mfa.Code(secret, mfa.Counter(later, mfa.DefaultPeriod)-1, mfa.Params{})
	if err := g.Verify("alice", earlier, later); !errors.Is(err, mfa.ErrReplay) {
		t.Fatalf("earlier step: want ErrReplay, got %v", err)
	}
}

func TestGuardLockout(t *testing.T) {
	g, _ := guardFor(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	now := time.Unix(1700000000, 0)
	for i := 0; i < 3; i++ {
		if err := g.Verify("alice", "000000", now); !errors.Is(err, mfa.ErrBadCode) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if !g.Locked("alice", now) {
		t.Fatal("the user should be locked out")
	}
	// Even the right code is refused while locked.
	_, secret := guardFor(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	code, _ := mfa.Code(secret, mfa.Counter(now, mfa.DefaultPeriod), mfa.Params{})
	if err := g.Verify("alice", code, now); !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("while locked: want ErrLocked, got %v", err)
	}
	// The lock lifts.
	after := now.Add(time.Hour + time.Second)
	code2, _ := mfa.Code(secret, mfa.Counter(after, mfa.DefaultPeriod), mfa.Params{})
	if err := g.Verify("alice", code2, after); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
}

// A recovery code works once, and only when the authenticator does not.
func TestGuardRecovery(t *testing.T) {
	hash, err := passwd.Hash("rescue-me-with-a-longer-code")
	if err != nil {
		t.Fatal(err)
	}
	g, _ := guardFor(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP::"+hash)
	now := time.Unix(1700000000, 0)
	if err := g.Verify("alice", "rescue-me-with-a-longer-code", now); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	if err := g.Verify("alice", "rescue-me-with-a-longer-code", now); !errors.Is(err, mfa.ErrBadCode) {
		t.Fatalf("a spent recovery code: want ErrBadCode, got %v", err)
	}
}

func TestGuardUnknownUser(t *testing.T) {
	g, _ := guardFor(t, "alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	if err := g.Verify("mallory", "000000", time.Now()); !errors.Is(err, mfa.ErrUnknownUser) {
		t.Fatalf("want ErrUnknownUser, got %v", err)
	}
	if g.Enrolled("mallory") {
		t.Fatal("mallory is not enrolled")
	}
}

func FuzzCheck(f *testing.F) {
	f.Add([]byte("12345678901234567890"), "755224")
	f.Fuzz(func(t *testing.T, secret []byte, code string) {
		if len(secret) == 0 {
			return
		}
		// Nothing but a six digit string can ever verify.
		if _, ok := mfa.Check(secret, code, time.Unix(1700000000, 0), mfa.Params{}, 1); ok {
			if len(code) != mfa.DefaultDigits {
				t.Fatalf("accepted %q", code)
			}
			for _, c := range code {
				if c < '0' || c > '9' {
					t.Fatalf("accepted %q", code)
				}
			}
		}
	})
}
