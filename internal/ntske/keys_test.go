package ntske

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/siv"
	"github.com/rom/xproxy/internal/testutil"
)

// recorder is an exporter that keeps what it was asked for, so that the inputs
// RFC 8915 s5.1 prescribes can be checked octet by octet rather than inferred
// from the keys coming out differently.
type recorder struct {
	labels   []string
	contexts [][]byte
	lengths  []int
	err      error
}

func (r *recorder) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	r.labels = append(r.labels, label)
	r.contexts = append(r.contexts, append([]byte(nil), context...))
	r.lengths = append(r.lengths, length)
	if r.err != nil {
		return nil, r.err
	}
	out := make([]byte, length)
	// Enough of a stand-in for a key schedule that two different contexts give
	// two different keys; what is being checked here is the inputs.
	for i := range out {
		out[i] = byte(i) ^ byte(len(context))
		if len(context) > 0 {
			out[i] ^= context[len(context)-1]
		}
	}
	return out, nil
}

func TestTheDerivationAsksForWhatTheStandardSays(t *testing.T) {
	r := &recorder{}
	if _, err := Derive(r, NextProtoNTPv4, AEADAESSIVCMAC256); err != nil {
		t.Fatal(err)
	}
	if len(r.labels) != 2 {
		t.Fatalf("%d exports, want one per direction", len(r.labels))
	}
	for i := range r.labels {
		if r.labels[i] != "EXPORTER-network-time-security" {
			t.Errorf("export %d label %q", i, r.labels[i])
		}
		if r.lengths[i] != siv.KeySize256 {
			t.Errorf("export %d length %d, want %d", i, r.lengths[i], siv.KeySize256)
		}
	}
	// next protocol (2) || AEAD (2) || direction (1), big endian.
	wantC2S := []byte{0x00, 0x00, 0x00, 0x0f, 0x00}
	wantS2C := []byte{0x00, 0x00, 0x00, 0x0f, 0x01}
	if !bytes.Equal(r.contexts[0], wantC2S) {
		t.Errorf("client-to-server context %x, want %x", r.contexts[0], wantC2S)
	}
	if !bytes.Equal(r.contexts[1], wantS2C) {
		t.Errorf("server-to-client context %x, want %x", r.contexts[1], wantS2C)
	}
}

func TestTheDerivationRefusesWhatItCannotDo(t *testing.T) {
	if _, err := Derive(nil, NextProtoNTPv4, AEADAESSIVCMAC256); err == nil {
		t.Error("derived from no exporter")
	}
	want := errors.New("no exporting here")
	if _, err := Derive(&recorder{err: want}, NextProtoNTPv4, AEADAESSIVCMAC256); !errors.Is(err, want) {
		t.Errorf("got %v, want %v", err, want)
	}
}

// tlsPair is a finished TLS connection, so that the derivation is exercised
// against the real exporter and not only against a stand-in.
func tlsPair(t *testing.T) (client, server *tls.Conn) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "ke.example")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	client = tls.Client(c, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // a pipe to the server in this test
		ServerName:         "ke.example",
		NextProtos:         []string{"ntske/1"},
		MinVersion:         tls.VersionTLS13,
	})
	server = tls.Server(s, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"ntske/1"},
		MinVersion:   tls.VersionTLS13,
	})
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestBothEndsOfATLSConnectionDeriveTheSameKeys(t *testing.T) {
	client, server := tlsPair(t)
	if client.ConnectionState().NegotiatedProtocol != "ntske/1" {
		t.Fatalf("ALPN %q", client.ConnectionState().NegotiatedProtocol)
	}
	ck, err := DeriveFromTLS(client, NextProtoNTPv4, AEADAESSIVCMAC256)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := DeriveFromTLS(server, NextProtoNTPv4, AEADAESSIVCMAC256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ck.C2S, sk.C2S) || !bytes.Equal(ck.S2C, sk.S2C) {
		t.Fatal("the two ends derived different keys, so nothing either of them sends will verify")
	}
	if len(ck.C2S) != KeyLen || len(ck.S2C) != KeyLen {
		t.Fatalf("key lengths %d and %d, want %d", len(ck.C2S), len(ck.S2C), KeyLen)
	}
	// The two directions must differ, or a packet the server sent could be
	// replayed to the server as one the client sent.
	if bytes.Equal(ck.C2S, ck.S2C) {
		t.Fatal("the two directions derived the same key")
	}
}

// The keys depend on every input the standard says they depend on. A derivation
// that ignored the algorithm would hand the same key material to two
// negotiations that agreed on different ciphers.
func TestTheKeysDependOnEveryNegotiatedTerm(t *testing.T) {
	client, _ := tlsPair(t)
	base, err := DeriveFromTLS(client, NextProtoNTPv4, AEADAESSIVCMAC256)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		proto, aead uint16
	}{
		{"another next protocol", NextProtoNTPv4 + 1, AEADAESSIVCMAC256},
		{"another algorithm", NextProtoNTPv4, AEADAESSIVCMAC256 + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other, err := DeriveFromTLS(client, tc.proto, tc.aead)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(other.C2S, base.C2S) || bytes.Equal(other.S2C, base.S2C) {
				t.Fatal("the keys did not change with the negotiated terms")
			}
		})
	}
}

func TestDerivingBeforeTheHandshakeIsRefused(t *testing.T) {
	if _, err := DeriveFromTLS(nil, NextProtoNTPv4, AEADAESSIVCMAC256); err == nil {
		t.Error("derived from no connection")
	}
	c, s := net.Pipe()
	defer func() { _ = c.Close(); _ = s.Close() }()
	go func() { _, _ = io.Copy(io.Discard, s) }()
	conn := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // never handshakes
	// Refused as a connection used too early, not as an export that failed: the
	// listener logs the two differently, because one is its own bug and the
	// other is the TLS stack's.
	if _, err := DeriveFromTLS(conn, NextProtoNTPv4, AEADAESSIVCMAC256); !errors.Is(err, ErrNoHandshake) {
		t.Errorf("got %v, want %v", err, ErrNoHandshake)
	}
}

// keys is a fixed pair, so a cookie test is about the cookie and not about TLS.
func testKeys() *Keys {
	c2s := make([]byte, KeyLen)
	s2c := make([]byte, KeyLen)
	for i := range c2s {
		c2s[i] = byte(i)
		s2c[i] = byte(255 - i)
	}
	return &Keys{C2S: c2s, S2C: s2c}
}

func sealed(t *testing.T, k *CookieKeys) []byte {
	t.Helper()
	c, err := k.Seal(AEADAESSIVCMAC256, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newKeys(t *testing.T, keep int) *CookieKeys {
	t.Helper()
	k, err := NewCookieKeys(keep)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestACookieRoundTrips(t *testing.T) {
	k := newKeys(t, 2)
	want := testKeys()
	cookie := sealed(t, k)
	aead, got, err := k.Open(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if aead != AEADAESSIVCMAC256 {
		t.Errorf("algorithm %d", aead)
	}
	if !bytes.Equal(got.C2S, want.C2S) || !bytes.Equal(got.S2C, want.S2C) {
		t.Error("the keys that came out are not the keys that went in")
	}
	// The cookie is what a client holds and what an attacker sees. Neither key
	// may be readable in it.
	if bytes.Contains(cookie, want.C2S) || bytes.Contains(cookie, want.S2C) {
		t.Error("the cookie carries a key in the clear")
	}
	if len(cookie) > MaxCookie {
		t.Errorf("a cookie of %d octets is past the bound this will open", len(cookie))
	}
	// A cookie comes back inside an NTP extension field, whose length is padded
	// to a multiple of four with nothing to say how much is padding. A cookie
	// that was not a multiple of four would come back longer than it left and
	// would not open.
	if len(cookie)%4 != 0 {
		t.Errorf("a cookie of %d octets does not fit an extension field without padding", len(cookie))
	}
}

// Two cookies for the same association must differ, or a cookie would identify
// the association it belongs to and a passive observer could follow one client
// across addresses.
func TestTwoCookiesForOneAssociationDiffer(t *testing.T) {
	k := newKeys(t, 2)
	a, b := sealed(t, k), sealed(t, k)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same keys produced the same cookie")
	}
	if !bytes.Equal(a[:cookieKeyIDLen], b[:cookieKeyIDLen]) {
		t.Fatal("two cookies sealed under one key name different keys")
	}
}

func TestAnEditedCookieDoesNotOpen(t *testing.T) {
	k := newKeys(t, 2)
	cookie := sealed(t, k)
	for i := range cookie {
		edited := append([]byte(nil), cookie...)
		edited[i] ^= 0x01
		if _, _, err := k.Open(edited); !errors.Is(err, ErrCookie) {
			t.Fatalf("octet %d of %d flipped and the cookie still opened: %v", i, len(cookie), err)
		}
	}
}

// The key identifier is associated data, not a lookup hint that the seal
// ignores: moving a cookie to another identifier must not be a way to ask for
// it to be decrypted under a different key.
func TestTheKeyIdentifierIsAuthenticated(t *testing.T) {
	k := newKeys(t, 2)
	cookie := sealed(t, k)
	cur, _ := k.Keys()
	moved := append([]byte(nil), cookie...)
	binary.BigEndian.PutUint32(moved, cur.ID+1)
	if _, _, err := k.Open(moved); !errors.Is(err, ErrCookie) {
		t.Fatalf("a cookie moved to an unknown key opened: %v", err)
	}
	// And with the identifier pointing at a key that does exist.
	if err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	next, _ := k.Keys()
	moved = append([]byte(nil), cookie...)
	binary.BigEndian.PutUint32(moved, next.ID)
	if _, _, err := k.Open(moved); !errors.Is(err, ErrCookie) {
		t.Fatalf("a cookie moved to another held key opened: %v", err)
	}
}

func TestAMisshapenCookieDoesNotOpen(t *testing.T) {
	k := newKeys(t, 2)
	cookie := sealed(t, k)
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"nothing", nil},
		{"shorter than the prefix", cookie[:cookieKeyIDLen]},
		{"the prefix and no seal", cookie[:cookieKeyIDLen+cookieNonceLen]},
		{"a seal shorter than a tag", cookie[:cookieKeyIDLen+cookieNonceLen+siv.TagSize-1]},
		{"cut short", cookie[:len(cookie)-1]},
		{"past the bound", make([]byte, MaxCookie+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := k.Open(tc.in); !errors.Is(err, ErrCookie) {
				t.Fatalf("got %v, want %v", err, ErrCookie)
			}
		})
	}
}

// Rotation is the point of the key identifier. A client holds days of cookies,
// so a rotation that invalidated them at once would take the time service down
// for as long as it took every client to re-establish.
func TestACookieSurvivesRotationUntilItsKeyIsRetired(t *testing.T) {
	k := newKeys(t, 1)
	cookie := sealed(t, k)
	if err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Open(cookie); err != nil {
		t.Fatalf("a cookie issued before one rotation no longer opens: %v", err)
	}
	// A new cookie is sealed under the new key, which the old one is not.
	fresh := sealed(t, k)
	if bytes.Equal(fresh[:cookieKeyIDLen], cookie[:cookieKeyIDLen]) {
		t.Error("a cookie sealed after the rotation names the old key")
	}
	if err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Open(cookie); !errors.Is(err, ErrCookie) {
		t.Fatalf("a cookie two rotations old still opens with a history of one: %v", err)
	}
	if _, _, err := k.Open(fresh); err != nil {
		t.Fatalf("the cookie from one rotation ago no longer opens: %v", err)
	}
}

func TestNoHistoryMeansARotationInvalidatesEveryCookie(t *testing.T) {
	k := newKeys(t, 0)
	cookie := sealed(t, k)
	if err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Open(cookie); !errors.Is(err, ErrCookie) {
		t.Fatalf("got %v, want %v", err, ErrCookie)
	}
	if _, old := k.Keys(); len(old) != 0 {
		t.Errorf("a history of none kept %d keys", len(old))
	}
}

// Keys and Restore are how a restart keeps the cookies it issued working. A
// relay that generated fresh keys on start would make every client's cookies
// worthless at exactly the moment it came back.
func TestKeysSurviveARestart(t *testing.T) {
	first := newKeys(t, 2)
	cookie := sealed(t, first)
	if err := first.Rotate(); err != nil {
		t.Fatal(err)
	}
	cur, old := first.Keys()

	second := newKeys(t, 2)
	if _, _, err := second.Open(cookie); !errors.Is(err, ErrCookie) {
		t.Fatal("a fresh key set opened a cookie it never sealed")
	}
	if err := second.Restore(cur, old); err != nil {
		t.Fatal(err)
	}
	if _, _, err := second.Open(cookie); err != nil {
		t.Fatalf("the restored set does not open the cookie: %v", err)
	}
	// Keys hands out a copy: a caller that edited what it got must not be
	// editing the live set.
	_, old2 := second.Keys()
	if len(old2) > 0 {
		old2[0] = CookieKey{}
		if _, _, err := second.Open(cookie); err != nil {
			t.Fatalf("editing the returned history broke the set: %v", err)
		}
	}
}

func TestRestoreRefusesAKeyOfTheWrongLength(t *testing.T) {
	k := newKeys(t, 2)
	good := make([]byte, siv.KeySize256)
	if err := k.Restore(CookieKey{ID: 1, Key: good[:16]}, nil); err == nil {
		t.Error("restored a current key of 16 octets")
	}
	if err := k.Restore(CookieKey{ID: 1, Key: good}, []CookieKey{{ID: 2, Key: good[:8]}}); err == nil {
		t.Error("restored a retired key of 8 octets")
	}
	// And the set still works, because a refused restore must leave it alone.
	if _, _, err := k.Open(sealed(t, k)); err != nil {
		t.Errorf("the set broke after a refused restore: %v", err)
	}
}

func TestRestoreHonoursTheHistoryBound(t *testing.T) {
	k := newKeys(t, 1)
	good := make([]byte, siv.KeySize256)
	old := []CookieKey{{ID: 2, Key: good}, {ID: 3, Key: good}, {ID: 4, Key: good}}
	if err := k.Restore(CookieKey{ID: 1, Key: good}, old); err != nil {
		t.Fatal(err)
	}
	if _, got := k.Keys(); len(got) != 1 {
		t.Fatalf("a history of one kept %d keys", len(got))
	}
}

// The body inside a cookie is authenticated, so a short one cannot come from a
// client -- but it can come from a key set restored from something that wrote a
// different format. The parser says no rather than indexing past the end.
func TestAShortCookieBodyIsRefused(t *testing.T) {
	full := cookieBody(AEADAESSIVCMAC256, testKeys())
	if _, _, err := parseCookieBody(full); err != nil {
		t.Fatalf("a whole body did not parse: %v", err)
	}
	// Everything short of the algorithm, the two lengths and the two keys. What
	// follows those is padding to a multiple of four, which the parser ignores
	// because an extension field's padding is indistinguishable from it.
	need := 6 + len(testKeys().C2S) + len(testKeys().S2C)
	for i := 0; i < need; i++ {
		if _, _, err := parseCookieBody(full[:i]); !errors.Is(err, ErrCookie) {
			t.Fatalf("%d octets of %d parsed: %v", i, need, err)
		}
	}
}

func TestSealingWithoutKeysIsRefused(t *testing.T) {
	k := newKeys(t, 2)
	for _, tc := range []struct {
		name string
		in   *Keys
	}{
		{"none at all", nil},
		{"no client key", &Keys{S2C: make([]byte, KeyLen)}},
		{"no server key", &Keys{C2S: make([]byte, KeyLen)}},
		{"empty", &Keys{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := k.Seal(AEADAESSIVCMAC256, tc.in); err == nil {
				t.Fatal("sealed a cookie with nothing in it")
			}
		})
	}
}

func TestANegativeHistoryIsRefused(t *testing.T) {
	if _, err := NewCookieKeys(-1); err == nil {
		t.Fatal("started a key set with a negative history")
	}
}

func TestRotatedReportsWhenTheKeyChanged(t *testing.T) {
	k := newKeys(t, 2)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	k.now = func() time.Time { return at }
	before := k.Rotated()
	if err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	if got := k.Rotated(); !got.Equal(at) {
		t.Fatalf("rotated at %v, want %v (was %v)", got, at, before)
	}
}

// The key set is read on every time exchange and written by whatever rotates
// it, so it is used concurrently by construction.
//
// The history is deeper than the number of rotations this does, so that a
// cookie sealed at the start still opens at the end: otherwise the test would
// be racing its own rotations rather than checking the locking.
func TestTheKeySetIsUsedFromManyGoroutines(t *testing.T) {
	const rotations = 20
	k := newKeys(t, rotations+1)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 16)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := k.Seal(AEADAESSIVCMAC256, testKeys())
				if err != nil {
					errs <- err
					return
				}
				if _, _, err := k.Open(c); err != nil {
					// A cookie sealed and opened across a rotation is still
					// within the history, so this must not happen.
					errs <- fmt.Errorf("sealed then did not open: %w", err)
					return
				}
			}
		}()
	}
	for i := 0; i < rotations; i++ {
		if err := k.Rotate(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestTheKeySetSurvivesAProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cookies.json")
	first := newKeys(t, 2)
	cookie := sealed(t, first)
	if err := first.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	// The keys are the secret every cookie's secrecy rests on.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the state file is mode %v", fi.Mode().Perm())
	}
	second := newKeys(t, 2)
	if err := second.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := second.Open(cookie); err != nil {
		t.Fatalf("a cookie issued before the restart no longer opens: %v", err)
	}
	// And the restored set is the same set, not just one that happens to open
	// this cookie: the current key is the one that was current.
	c1, o1 := first.Keys()
	c2, o2 := second.Keys()
	if c1.ID != c2.ID || !bytes.Equal(c1.Key, c2.Key) || len(o1) != len(o2) {
		t.Fatalf("the restored set differs: %d/%d current, %d/%d retired", c1.ID, c2.ID, len(o1), len(o2))
	}
}

func TestSavingOverAnExistingStateFileReplacesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.json")
	k := newKeys(t, 1)
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := k.Rotate(); err != nil {
		t.Fatal(err)
	}
	fresh := sealed(t, k)
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	other := newKeys(t, 1)
	if err := other.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.Open(fresh); err != nil {
		t.Fatalf("the second save did not take: %v", err)
	}
	// Nothing is left behind: a temporary file in the directory would be a
	// secret nobody knows is there.
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("%d files in the directory", len(ents))
	}
}

func TestAStateFileThatCannotBeReadIsAnError(t *testing.T) {
	dir := t.TempDir()
	k := newKeys(t, 2)
	if err := k.Load(filepath.Join(dir, "absent.json")); !errors.Is(err, fs.ErrNotExist) {
		// A first start has no file, and that is not the same thing as a file
		// that is there and wrong.
		t.Fatalf("got %v, want a not-exist error", err)
	}
	good := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name string
		body string
	}{
		{"not JSON", "{"},
		{"a version from the future", `{"version":2,"current":{"id":1,"key":"` + good + `"}}`},
		{"a key that is not base64", `{"version":1,"current":{"id":1,"key":"!!!"}}`},
		{"a key of the wrong length", `{"version":1,"current":{"id":1,"key":"AAAA"}}`},
		{"a retired key of the wrong length",
			`{"version":1,"current":{"id":1,"key":"` + good + `"},"old":[{"id":2,"key":"AAAA"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "state.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := k.Load(path); !errors.Is(err, ErrState) {
				t.Fatalf("got %v, want %v", err, ErrState)
			}
		})
	}
	// And a refused load left the set alone, because a relay that lost its keys
	// to a bad file would be doing what the file exists to prevent.
	if _, _, err := k.Open(sealed(t, k)); err != nil {
		t.Errorf("the set broke after a refused load: %v", err)
	}
}

// A save that fails leaves nothing behind. The temporary file holds the same
// secret the state file does, so one left in the directory would be a copy of
// the estate's cookie keys that nobody knows about.
func TestASaveThatFailsLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file belongs: the write succeeds and the rename
	// cannot.
	path := filepath.Join(dir, "cookies.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := newKeys(t, 1).Save(path); err == nil {
		t.Fatal("saved over a directory")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "cookies.json" {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("the directory holds %v", names)
	}
}
