package passwd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This package holds every password check in the proxy: the GUI's
// logins, basic authentication on a route, and the users file behind
// both. Its properties are the boring ones that must never break.

func TestHashAndVerify(t *testing.T) {
	const pw = "correct horse battery staple"
	h, err := HashWithIterations(pw, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(h, pw) {
		t.Fatal("a fresh hash did not verify")
	}
	if Verify(h, pw+" ") || Verify(h, pw[:len(pw)-1]) || Verify(h, "") {
		t.Fatal("a wrong password verified")
	}
	// The stored form: four fields, the prefix, the iteration count, and
	// base64 without padding.
	parts := strings.Split(h, "$")
	if len(parts) != 4 || parts[0] != prefix || parts[1] != "1000" {
		t.Fatalf("stored form %q", h)
	}
	for _, p := range parts[2:] {
		if strings.ContainsAny(p, "=\n\r ") {
			t.Errorf("field %q needs quoting", p)
		}
	}
	if !IsHash(h) {
		t.Error("IsHash refused a hash it produced")
	}
	// Two hashes of one password differ: the salt is fresh each time, so
	// a stolen file does not show which accounts share a password.
	h2, err := HashWithIterations(pw, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if h == h2 {
		t.Fatal("two hashes of one password are identical")
	}
	if !Verify(h2, pw) {
		t.Fatal("the second hash did not verify")
	}
	// The default cost is the one the package documents.
	def, err := Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(def, prefix+"$600000$") {
		t.Errorf("the default hash is %q", def[:min(30, len(def))])
	}
	if !Verify(def, pw) {
		t.Error("the default hash did not verify")
	}
}

func TestHashRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		pw   string
		iter int
	}{
		{"an empty password", "", 1000},
		{"one character", "x", 1000},
		{"one short of the minimum", strings.Repeat("x", MinLength-1), 1000},
		{"a password past the maximum", strings.Repeat("x", maxLength+1), 1000},
		{"no iterations", strings.Repeat("x", MinLength), 0},
		{"too few iterations", strings.Repeat("x", MinLength), 999},
		{"negative iterations", strings.Repeat("x", MinLength), -1},
	} {
		if h, err := HashWithIterations(tc.pw, tc.iter); err == nil {
			t.Errorf("%s was hashed as %q", tc.name, h)
		}
	}
	// Exactly at the minimum and the maximum, it works.
	for _, pw := range []string{strings.Repeat("x", MinLength), strings.Repeat("x", maxLength)} {
		h, err := HashWithIterations(pw, 1000)
		if err != nil {
			t.Fatalf("a %d character password: %v", len(pw), err)
		}
		if !Verify(h, pw) {
			t.Fatalf("a %d character password did not verify", len(pw))
		}
	}
	// A password of arbitrary bytes, including NUL and invalid UTF-8,
	// hashes and verifies as itself.
	for _, pw := range []string{
		"pass\x00word etc",
		"\xff\xfe not utf-8 at all",
		"éàü a long enough one",
		strings.Repeat("你", 20),
		"   leading and trailing   ",
		"line\nbreaks\rin\tit",
	} {
		h, err := HashWithIterations(pw, 1000)
		if err != nil {
			t.Fatalf("%q: %v", pw, err)
		}
		if !Verify(h, pw) {
			t.Errorf("%q did not verify", pw)
		}
		if Verify(h, strings.TrimSpace(pw)) && strings.TrimSpace(pw) != pw {
			t.Errorf("%q verified with its whitespace trimmed", pw)
		}
	}
}

func TestVerifyRefusesMalformedHashes(t *testing.T) {
	good, err := HashWithIterations("a long enough password", 1000)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, "$")
	with := func(i int, v string) string {
		out := append([]string{}, parts...)
		out[i] = v
		return strings.Join(out, "$")
	}
	bad := map[string]string{
		"empty":                     "",
		"no fields":                 "hash",
		"three fields":              strings.Join(parts[:3], "$"),
		"five fields":               good + "$extra",
		"another algorithm":         with(0, "pbkdf2-sha512"),
		"no algorithm":              with(0, ""),
		"iterations not a number":   with(1, "many"),
		"zero iterations":           with(1, "0"),
		"too few iterations":        with(1, "999"),
		"ten million iterations":    with(1, "10000001"),
		"a negative count":          with(1, "-1000"),
		"a huge count":              with(1, "99999999999999999999"),
		"a salt that is not base64": with(2, "!!!!"),
		"a hash that is not base64": with(3, "!!!!"),
		"a short hash":              with(3, "AAAA"),
		"a long hash":               with(3, parts[3]+parts[3]),
		"an empty salt":             with(2, ""),
		"an empty hash":             with(3, ""),
		"base64 with padding":       with(3, parts[3]+"=="),
		"a crypt hash":              "$2y$10$abcdefghijklmnopqrstuv",
		"a bare sha256":             strings.Repeat("a", 64),
	}
	for name, h := range bad {
		if Verify(h, "a long enough password") {
			t.Errorf("%s verified", name)
		}
		if name != "empty" && IsHash(h) && strings.Count(h, "$") != 3 {
			t.Errorf("%s was reported as a hash", name)
		}
	}
	// A password longer than the maximum never reaches the derivation.
	if Verify(good, strings.Repeat("x", maxLength+1)) {
		t.Error("an oversize password verified")
	}
	// The real hash still verifies after all of that.
	if !Verify(good, "a long enough password") {
		t.Error("the valid hash stopped verifying")
	}
}

func TestIsHash(t *testing.T) {
	good, err := HashWithIterations("a long enough password", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !IsHash(good) {
		t.Error("a real hash was refused")
	}
	// IsHash is a shape check, not a verification: it says nothing about
	// whether the fields decode.
	if !IsHash(prefix + "$1000$!!!$!!!") {
		t.Error("a hash shaped string was refused")
	}
	for _, s := range []string{"", "x", "a$b$c", "a$b$c$d", prefix, prefix + "$1000$a", "x509"} {
		if IsHash(s) {
			t.Errorf("%q was reported as a hash", s)
		}
	}
}

func TestVerifyDummy(t *testing.T) {
	// It always fails, whatever it is given, and it costs about what a
	// real verification costs: an unknown user name must not be a
	// faster answer than a wrong password.
	if VerifyDummy("anything") || VerifyDummy("") {
		t.Fatal("the dummy verification succeeded")
	}
	real, err := Hash("a long enough password")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	Verify(real, "the wrong password")
	realCost := time.Since(start)
	start = time.Now()
	VerifyDummy("the wrong password")
	dummyCost := time.Since(start)
	// Within an order of magnitude either way; the point is that it is
	// not free, not that it is exact.
	if dummyCost*10 < realCost {
		t.Errorf("an unknown user costs %v where a wrong password costs %v", dummyCost, realCost)
	}
	// It is safe from many goroutines at once, which is where its
	// one-time initialisation lives.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if VerifyDummy("x") {
				t.Error("the dummy verification succeeded")
			}
		}()
	}
	wg.Wait()
}

func TestAcquire(t *testing.T) {
	sem := make(chan struct{}, 2)
	var waiting atomic.Int32

	// A free slot is taken at once and given back.
	if !Acquire(t.Context(), sem, &waiting) {
		t.Fatal("a free slot was refused")
	}
	<-sem
	if waiting.Load() != 0 {
		t.Fatalf("%d callers are still counted as waiting", waiting.Load())
	}

	// Fill both slots, then queue the maximum and one more. The one more
	// is refused outright rather than queued, because a caller that
	// waits holds a request slot of the process while it does.
	for i := 0; i < cap(sem); i++ {
		if !Acquire(t.Context(), sem, &waiting) {
			t.Fatalf("slot %d was refused", i)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var queued sync.WaitGroup
	results := make(chan bool, MaxQueuePerSlot*cap(sem)+2)
	for i := 0; i < MaxQueuePerSlot*cap(sem); i++ {
		queued.Add(1)
		go func() {
			defer queued.Done()
			results <- Acquire(ctx, sem, &waiting)
		}()
	}
	// Wait until the queue is full, then one more must be refused.
	deadline := time.After(10 * time.Second)
	for waiting.Load() < int32(MaxQueuePerSlot*cap(sem)) {
		select {
		case <-deadline:
			t.Fatalf("only %d callers queued", waiting.Load())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if Acquire(t.Context(), sem, &waiting) {
		t.Error("a caller past the queue bound was admitted")
		<-sem
	}
	// Releasing the two held slots lets two of the queued callers in;
	// cancelling the context releases the rest.
	<-sem
	<-sem
	cancel()
	queued.Wait()
	close(results)
	var admitted int
	for ok := range results {
		if ok {
			admitted++
			<-sem
		}
	}
	if admitted < 2 {
		t.Errorf("%d queued callers were admitted after two slots freed", admitted)
	}
	if waiting.Load() != 0 {
		t.Errorf("%d callers are still counted as waiting", waiting.Load())
	}
	// A context that is already done never takes a slot, even when one
	// is free: a caller that has gone away must not cost a hash.
	done, cancelDone := context.WithCancel(t.Context())
	cancelDone()
	empty := make(chan struct{}, 1)
	for i := 0; i < 100; i++ {
		if Acquire(done, empty, &waiting) {
			t.Fatal("a caller whose context was done took a slot")
		}
	}
	if len(empty) != 0 {
		t.Errorf("%d slots were taken", len(empty))
	}
	if waiting.Load() != 0 {
		t.Errorf("%d callers left counted as waiting", waiting.Load())
	}
}

func TestLoadUsers(t *testing.T) {
	dir := t.TempDir()
	h1, err := HashWithIterations("a long enough password", 1000)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashWithIterations("another long password", 1000)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "users")
	body := "# a comment\n\n   \nalice:" + h1 + "\nbob:" + h2 + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err := LoadUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || !Verify(users["alice"], "a long enough password") || !Verify(users["bob"], "another long password") {
		t.Fatalf("users %v", users)
	}
	// Lines the format cannot hold are errors naming the file and the
	// line, not users that can never log in.
	for name, line := range map[string]string{
		"no colon":               "alice" + h1,
		"no name":                ":" + h1,
		"no hash":                "alice:",
		"a hash of another kind": "alice:$2y$10$abcdefghij",
		"a bare password":        "alice:hunter2",
		"a name with spaces":     "alice smith:" + h1,
	} {
		p := filepath.Join(dir, "bad")
		if err := os.WriteFile(p, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadUsers(p)
		if err == nil {
			if name != "a name with spaces" {
				t.Errorf("%s was accepted", name)
			}
			continue
		}
		if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), ":1:") {
			t.Errorf("%s: the error does not name the file and line: %v", name, err)
		}
	}
	// A missing file and a directory are errors; an empty file is an
	// empty set, which is a users file with nobody in it.
	if _, err := LoadUsers(filepath.Join(dir, "nope")); err == nil {
		t.Error("a missing file was read")
	}
	if _, err := LoadUsers(dir); err == nil {
		t.Error("a directory was read as a users file")
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if users, err := LoadUsers(empty); err != nil || len(users) != 0 {
		t.Errorf("an empty file: %v %v", users, err)
	}
	// The last line wins for a repeated name, and a line with a colon in
	// the hash keeps the whole hash.
	dup := filepath.Join(dir, "dup")
	if err := os.WriteFile(dup, []byte("alice:"+h1+"\nalice:"+h2+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err = LoadUsers(dup)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(users["alice"], "another long password") {
		t.Error("the repeated name did not take the last line")
	}
}
