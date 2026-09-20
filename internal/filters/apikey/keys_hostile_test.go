package apikey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The keys file is a credential store. It is written by the tool, read
// on every reload, and edited by hand more often than anyone admits.
// A line it misreads is a key that works when it should not.

func TestParseLineRefusals(t *testing.T) {
	hash := strings.Repeat("a", 64)
	good := "k1|active|-|-|" + hash + "|-|-|-|-"
	if _, err := parseLine(good); err != nil {
		t.Fatalf("a well-formed line was refused: %v", err)
	}
	bad := map[string]string{
		"empty":                           "",
		"no fields":                       "k1",
		"eight fields":                    "k1|active|-|-|" + hash + "|-|-|-",
		"ten fields":                      good + "|extra",
		"an empty id":                     "|active|-|-|" + hash + "|-|-|-|-",
		"an id with a slash":              "a/b|active|-|-|" + hash + "|-|-|-|-",
		"an id with a space":              "a b|active|-|-|" + hash + "|-|-|-|-",
		"an upper case id":                "K1|active|-|-|" + hash + "|-|-|-|-",
		"an id of 33 characters":          strings.Repeat("a", 33) + "|active|-|-|" + hash + "|-|-|-|-",
		"a state nobody defines":          "k1|enabled|-|-|" + hash + "|-|-|-|-",
		"an empty state":                  "k1||-|-|" + hash + "|-|-|-|-",
		"a state in another case":         "k1|Active|-|-|" + hash + "|-|-|-|-",
		"a short hash":                    "k1|active|-|-|" + strings.Repeat("a", 63) + "|-|-|-|-",
		"a long hash":                     "k1|active|-|-|" + strings.Repeat("a", 65) + "|-|-|-|-",
		"a hash that is not hex":          "k1|active|-|-|" + strings.Repeat("z", 64) + "|-|-|-|-",
		"an empty hash":                   "k1|active|-|-||-|-|-|-",
		"a dash for the hash":             "k1|active|-|-|-|-|-|-|-",
		"a previous hash that is not hex": "k1|active|-|-|" + hash + "|" + strings.Repeat("z", 64) + "|-|-|-",
		"a short previous hash":           "k1|active|-|-|" + hash + "|" + strings.Repeat("a", 10) + "|-|-|-",
		"an expiry that is not a time":    "k1|active|soon|-|" + hash + "|-|-|-|-",
		"an expiry in another format":     "k1|active|2026-09-20|-|" + hash + "|-|-|-|-",
		"a grace end that is not a time":  "k1|active|-|-|" + hash + "|" + hash + "|never|-|-",
		"a creation that is not a time":   "k1|active|-|-|" + hash + "|-|-|-|yesterday",
	}
	for name, line := range bad {
		if k, err := parseLine(line); err == nil {
			t.Errorf("%s was parsed as %+v", name, k)
		}
	}
	// The fields that may be a dash, and the ones that may not.
	k, err := parseLine("k-1_2|revoked|2030-01-02T03:04:05Z|read,write|" + hash + "|" + hash + "|2030-01-02T03:04:05Z|a note|2020-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != "k-1_2" || k.State != "revoked" || len(k.Scopes) != 2 || k.Scopes[1] != "write" || k.Note != "a note" {
		t.Fatalf("parsed key: %+v", k)
	}
	if k.Expires.IsZero() || k.PrevUntil.IsZero() || k.Created.IsZero() {
		t.Fatalf("times: %+v", k)
	}
	// A line round trips through its own rendering.
	round, err := parseLine(k.line())
	if err != nil {
		t.Fatal(err)
	}
	if round.line() != k.line() {
		t.Errorf("round trip:\n%s\n%s", k.line(), round.line())
	}
	// A note containing the separator cannot split the line.
	withPipe := Key{ID: "k1", State: "active", Hash: hash, Note: "a|b|c"}
	parsed, err := parseLine(withPipe.line())
	if err != nil {
		t.Fatalf("a note with separators: %v", err)
	}
	if strings.Contains(parsed.Note, "|") {
		t.Errorf("the note kept its separators: %q", parsed.Note)
	}
}

func TestParseFileRefusals(t *testing.T) {
	hash := strings.Repeat("a", 64)
	good := "k1|active|-|-|" + hash + "|-|-|-|-"
	keys, err := Parse([]byte("# a comment\n\n   \n"+good+"\n"), "keys")
	if err != nil || len(keys) != 1 {
		t.Fatalf("a good file: %v %d", err, len(keys))
	}
	// A duplicate id is an error rather than a last-one-wins, because
	// one of the two lines is somebody's revocation.
	dup := good + "\n" + strings.Replace(good, "aaaa", "bbbb", 1) + "\n"
	if _, err := Parse([]byte(dup), "keys"); err == nil {
		t.Error("a duplicate key id was accepted")
	}
	// A malformed line anywhere fails the whole file: a typo must not
	// silently drop a key or its revocation.
	for _, body := range []string{
		good + "\nrubbish\n",
		"rubbish\n" + good + "\n",
		good + "\n" + good + "extra\n",
	} {
		if _, err := Parse([]byte(body), "keys"); err == nil {
			t.Errorf("a file with a malformed line was accepted: %q", body)
		} else if !strings.Contains(err.Error(), "keys:") {
			t.Errorf("the error does not name the file and line: %v", err)
		}
	}
	// A line longer than the scanner's buffer is an error, not a
	// truncated key.
	long := "k1|active|-|" + strings.Repeat("s", 70<<10) + "|" + hash + "|-|-|-|-"
	if _, err := Parse([]byte(long), "keys"); err == nil {
		t.Error("a 70 KiB line was accepted")
	}
	// Line endings: a file written on another platform still reads.
	if keys, err := Parse([]byte(good+"\r\n"), "keys"); err != nil || len(keys) != 1 {
		t.Errorf("CRLF: %v %d", err, len(keys))
	}
	// An empty file is an empty set, not an error.
	if keys, err := Parse(nil, "keys"); err != nil || len(keys) != 0 {
		t.Errorf("an empty file: %v %d", err, len(keys))
	}
}

func TestGenerateAndIDOf(t *testing.T) {
	plain, err := Generate("orders")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, KeyPrefix+"orders_") {
		t.Fatalf("key %q", plain)
	}
	if IDOf(plain) != "orders" {
		t.Errorf("IDOf(%q) = %q", plain, IDOf(plain))
	}
	// The secret part is long enough to be a secret, and two keys never
	// collide.
	secret := strings.TrimPrefix(plain, KeyPrefix+"orders_")
	if len(secret) < 40 {
		t.Errorf("the secret is %d characters", len(secret))
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := Generate("orders")
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatal("two generated keys are identical")
		}
		seen[p] = true
	}
	// A key is safe in a header value and in a URL as it stands.
	for p := range seen {
		if strings.ContainsAny(p, " \t\r\n\"\\/+=;,") {
			t.Fatalf("a generated key needs escaping: %q", p)
		}
	}
	// IDOf on things that are not keys.
	for _, s := range []string{
		"", "xpk_", "xpk_orders", "orders_abc", "XPK_orders_abc", "xpk__abc",
		"xpk_" + strings.Repeat("a", 33) + "_abc", "xpk_UPPER_abc", "xpk_a b_abc", "xpk_a/b_abc",
		"Bearer xpk_orders_abc",
	} {
		if id := IDOf(s); id != "" {
			t.Errorf("IDOf(%q) = %q", s, id)
		}
	}
	// The hash of a key is a hex SHA-256 and is not the key.
	h := HashKey(plain)
	if len(h) != 64 || !isHex(h) || strings.Contains(h, "orders") {
		t.Errorf("HashKey: %q", h)
	}
	if HashKey(plain) != h || HashKey(plain+"x") == h {
		t.Error("the hash is not a function of the key alone")
	}
}

func TestKeyFileLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")

	// Add: the plaintext is returned once, the file holds only the hash.
	plain, err := Add(path, "orders", []string{"read"}, time.Time{}, "the orders service")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), plain) {
		t.Fatal("the plaintext key was written to the file")
	}
	if !strings.Contains(string(data), HashKey(plain)) {
		t.Fatal("the hash is not in the file")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("the keys file is mode %v", st.Mode().Perm())
	}
	// The same id twice is refused: reusing an id would make one key
	// answer for another.
	if _, err := Add(path, "orders", nil, time.Time{}, ""); err == nil {
		t.Error("a duplicate id was issued")
	}
	// Ids the format cannot hold.
	for _, id := range []string{"", "UPPER", "a b", "a/b", strings.Repeat("a", 33), "a|b", "a\nb"} {
		if _, err := Add(path, id, nil, time.Time{}, ""); err == nil {
			t.Errorf("the id %q was issued", id)
		}
	}

	// Rotate with a grace period keeps the previous hash; without one it
	// drops it immediately.
	rotated, err := Rotate(path, "orders", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == plain {
		t.Fatal("rotation returned the same key")
	}
	keys, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Hash != HashKey(rotated) || keys[0].PrevHash != HashKey(plain) || keys[0].PrevUntil.IsZero() {
		t.Fatalf("after rotation: %+v", keys[0])
	}
	if _, err := Rotate(path, "orders", 0); err != nil {
		t.Fatal(err)
	}
	keys, _ = Load(path)
	if keys[0].PrevHash != "" || !keys[0].PrevUntil.IsZero() {
		t.Fatalf("rotation without a grace period kept the previous key: %+v", keys[0])
	}

	// Revoke clears the grace key as well, so a revocation is immediate.
	if _, err := Rotate(path, "orders", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := Revoke(path, "orders"); err != nil {
		t.Fatal(err)
	}
	keys, _ = Load(path)
	if keys[0].State != "revoked" || keys[0].PrevHash != "" || !keys[0].PrevUntil.IsZero() {
		t.Fatalf("after revocation: %+v", keys[0])
	}
	// A revoked key cannot be rotated back into service.
	if _, err := Rotate(path, "orders", time.Hour); err == nil {
		t.Error("a revoked key was rotated")
	}
	// Operations on a key that is not there.
	for _, op := range []struct {
		name string
		err  error
	}{
		{"rotate", func() error { _, err := Rotate(path, "nope", 0); return err }()},
		{"revoke", Revoke(path, "nope")},
		{"remove", Remove(path, "nope")},
	} {
		if op.err == nil {
			t.Errorf("%s of a key that does not exist succeeded", op.name)
		}
	}
	// Remove takes the entry out; the file stays readable.
	if err := Remove(path, "orders"); err != nil {
		t.Fatal(err)
	}
	keys, err = Load(path)
	if err != nil || len(keys) != 0 {
		t.Fatalf("after removal: %v %d", err, len(keys))
	}
	// The file is still a keys file, with its header.
	data, _ = os.ReadFile(path)
	if !strings.HasPrefix(string(data), "# xproxy API keys:") {
		t.Errorf("the file lost its header:\n%s", data)
	}
	if err := Save(filepath.Join(dir, "nope", "keys"), nil); err == nil {
		t.Error("a save into a missing directory succeeded")
	}
	// Operations against a file that cannot be read.
	if _, err := Rotate(filepath.Join(dir, "missing"), "x", 0); err == nil {
		t.Error("a rotation against a missing file succeeded")
	}
	if err := Revoke(dir, "x"); err == nil {
		t.Error("a revocation against a directory succeeded")
	}
	// Many keys keep their order and their content across a save.
	for _, id := range []string{"zebra", "alpha", "mid"} {
		if _, err := Add(path, id, []string{"read", "write"}, time.Now().Add(time.Hour), "note for "+id); err != nil {
			t.Fatal(err)
		}
	}
	keys, err = Load(path)
	if err != nil || len(keys) != 3 {
		t.Fatalf("%v %d", err, len(keys))
	}
	if keys[0].ID != "alpha" || keys[2].ID != "zebra" {
		t.Errorf("the file is not sorted: %s %s %s", keys[0].ID, keys[1].ID, keys[2].ID)
	}
	for _, k := range keys {
		if len(k.Scopes) != 2 || k.Note != "note for "+k.ID || k.Expires.IsZero() {
			t.Errorf("key %s lost a field: %+v", k.ID, k)
		}
	}
}
