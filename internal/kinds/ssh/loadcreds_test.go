package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
)

// Every way the credential files can be wrong, refused at load.
//
// This is the half of a bastion's configuration that decides who may log in,
// and the one place where failing quietly is worse than failing loudly: a key
// that was meant to be accepted and is not is an outage somebody will
// telephone about, and a key that was meant to be removed and is not is an
// account nobody closed. So each of these is refused while an operator is
// watching the daemon start, rather than at the first handshake at three in
// the morning -- and the error names the file, because "ssh: invalid format"
// on its own does not say which of four files to look at.

// pubLine is an authorized_keys line for a fresh ed25519 key.
func pubLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := cssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(cssh.MarshalAuthorizedKey(k)))
}

// write puts content in a file under the test's own directory and returns its
// path. An empty name means a path that does not exist, which is the
// unreadable case.
func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if content == "\x00missing" {
		return path
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const missing = "\x00missing"

// creds runs loadCredentials against a listener, which is what newServer does
// with the configuration before it binds anything.
func creds(h *config.SSHListener) error {
	t := &server{h: h, keys: map[string]bool{}, caKeys: map[string]bool{},
		revoked: map[string]bool{}, noTouch: map[string]bool{}}
	return t.loadCredentials()
}

func TestEveryWayTheCredentialFilesAreRefusedAtLoad(t *testing.T) {
	good := pubLine(t)

	for _, tc := range []struct {
		name string
		// listener is built per case because each needs its own file.
		listener func(*testing.T) *config.SSHListener
		want     string
	}{
		{name: "an authorized_keys file that is not there",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{AuthorizedKeys: write(t, "ak", missing)}
			},
			want: "ssh authorized_keys:"},
		{name: "an authorized_keys line that is not a key",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{AuthorizedKeys: write(t, "ak", "ssh-ed25519 not-base64\n")}
			},
			want: "ssh authorized_keys:"},
		// A file of nothing but comments is the shape of a key list somebody
		// emptied by commenting it out, which would otherwise be a listener
		// that silently accepts nobody.
		{name: "an authorized_keys file holding no keys",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{AuthorizedKeys: write(t, "ak",
					"# the contractors' keys, removed 2026-03-01\n\n")}
			},
			want: "ssh authorized_keys: no keys in the file"},
		// The one option in this file that is not ignored. A line asking for
		// the presence check to be waived, on a listener that requires
		// presence, is a credential that could never work.
		{name: "a line waiving presence where presence is required",
			listener: func(t *testing.T) *config.SSHListener {
				yes := true
				return &config.SSHListener{RequireTouch: &yes,
					AuthorizedKeys: write(t, "ak", "no-touch-required "+good+"\n")}
			},
			want: "requires user presence"},
		// And the listener that nobody could log in to: tokens required, no
		// token key in the file, and no authority to issue one.
		{name: "hardware keys required and none that could be one",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{RequireHardwareKey: true,
					AuthorizedKeys: write(t, "ak", good+"\n")}
			},
			want: "no sk-ssh-ed25519"},

		{name: "a trusted_user_ca_keys file that is not there",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{TrustedUserCAKeys: write(t, "ca", missing)}
			},
			want: "ssh trusted_user_ca_keys:"},
		{name: "a trusted_user_ca_keys line that is not a key",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{TrustedUserCAKeys: write(t, "ca", "garbage\n")}
			},
			want: "ssh trusted_user_ca_keys:"},
		{name: "a trusted_user_ca_keys file holding no keys",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{TrustedUserCAKeys: write(t, "ca", "# none\n")}
			},
			want: "ssh trusted_user_ca_keys: no keys in the file"},
		{name: "a trusted_user_ca_keys file that is empty",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{TrustedUserCAKeys: write(t, "ca", "")}
			},
			want: "ssh trusted_user_ca_keys: no keys in the file"},

		{name: "a revoked_keys file that is not there",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{RevokedKeys: write(t, "rev", missing)}
			},
			want: "ssh revoked_keys:"},
		{name: "a revoked_keys line that is not a key",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{RevokedKeys: write(t, "rev", "nonsense\n")}
			},
			want: "ssh revoked_keys:"},
		// An empty revocation list is almost certainly a file that was meant
		// to have something in it, and taking it as "nothing is revoked" is
		// the reading that lets a sacked contractor back in.
		{name: "a revoked_keys file holding no keys",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{RevokedKeys: write(t, "rev", "\n\n")}
			},
			want: "ssh revoked_keys: no keys in the file"},

		{name: "a users_file that is not there",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{UsersFile: write(t, "users", missing)}
			},
			want: "ssh users_file:"},

		{name: "an upstream_key_file that is not there",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{UpstreamKeyFile: write(t, "id", missing)}
			},
			want: "ssh upstream_key_file:"},
		{name: "an upstream_key_file that is not a private key",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{UpstreamKeyFile: write(t, "id",
					"-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n-----END OPENSSH PRIVATE KEY-----\n")}
			},
			want: "ssh upstream_key_file:"},

		{name: "an upstream_known_hosts file that is not there",
			listener: func(t *testing.T) *config.SSHListener {
				return &config.SSHListener{UpstreamKnownHosts: write(t, "kh", missing)}
			},
			want: "ssh upstream_known_hosts:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := creds(tc.listener(t))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want one naming %q", err, tc.want)
			}
		})
	}
}

// And the configurations that are right, so the refusals above are about the
// flaw rather than about the file being read at all.
func TestTheCredentialFilesThatAreRight(t *testing.T) {
	good := pubLine(t)

	t.Run("a key list, a CA, a revocation list and a users file", func(t *testing.T) {
		users := filepath.Join(t.TempDir(), "users")
		if err := os.WriteFile(users, []byte("alice:$2a$10$"+strings.Repeat("x", 53)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		h := &config.SSHListener{
			AuthorizedKeys:    write(t, "ak", good+"\n"),
			TrustedUserCAKeys: write(t, "ca", pubLine(t)+"\n"),
			RevokedKeys:       write(t, "rev", pubLine(t)+"\n"),
		}
		srv := &server{h: h, keys: map[string]bool{}, caKeys: map[string]bool{},
			revoked: map[string]bool{}, noTouch: map[string]bool{}}
		if err := srv.loadCredentials(); err != nil {
			t.Fatalf("a configuration with nothing wrong with it: %v", err)
		}
		if len(srv.keys) != 1 || len(srv.caKeys) != 1 || len(srv.revoked) != 1 {
			t.Errorf("keys %d, ca %d, revoked %d", len(srv.keys), len(srv.caKeys), len(srv.revoked))
		}
		// With no known-hosts file the check is the one validation refuses
		// unless allow_insecure is set, and it is installed rather than left
		// nil -- a nil callback would panic on the first dial.
		if srv.hostKeyCheck == nil {
			t.Error("no host key callback was installed")
		}
	})

	// The waiver is remembered rather than refused where the listener does
	// not require presence, which is the other half of the refusal above:
	// the option means something, so it is read either way.
	t.Run("a line waiving presence where presence is not required", func(t *testing.T) {
		no := false
		h := &config.SSHListener{RequireTouch: &no,
			AuthorizedKeys: write(t, "ak", "no-touch-required "+good+"\n")}
		srv := &server{h: h, keys: map[string]bool{}, caKeys: map[string]bool{},
			revoked: map[string]bool{}, noTouch: map[string]bool{}}
		if err := srv.loadCredentials(); err != nil {
			t.Fatalf("the waiver was refused: %v", err)
		}
		if len(srv.noTouch) != 1 {
			t.Errorf("the waiver was not remembered: %v", srv.noTouch)
		}
	})

	// A token key satisfies require_hardware_key, which is the case the
	// refusal above exists to distinguish.
	t.Run("hardware keys required and one in the file", func(t *testing.T) {
		line, _ := SKTestKey(t)
		h := &config.SSHListener{RequireHardwareKey: true,
			AuthorizedKeys: write(t, "ak", line)}
		srv := &server{h: h, keys: map[string]bool{}, caKeys: map[string]bool{},
			revoked: map[string]bool{}, noTouch: map[string]bool{}}
		if err := srv.loadCredentials(); err != nil {
			t.Fatalf("a token key was refused: %v", err)
		}
	})

	// A certificate authority is the other way to satisfy it: the file holds
	// no token key, but the listener can be handed one in a certificate.
	t.Run("hardware keys required with an authority to issue them", func(t *testing.T) {
		h := &config.SSHListener{RequireHardwareKey: true,
			AuthorizedKeys:    write(t, "ak", good+"\n"),
			TrustedUserCAKeys: write(t, "ca", pubLine(t)+"\n")}
		srv := &server{h: h, keys: map[string]bool{}, caKeys: map[string]bool{},
			revoked: map[string]bool{}, noTouch: map[string]bool{}}
		if err := srv.loadCredentials(); err != nil {
			t.Fatalf("refused although a CA can issue a token certificate: %v", err)
		}
	})
}

// The shapes an ordinary key file has around its keys.
//
// Each of these used to refuse the listener at load with "ssh
// authorized_keys: ssh: no key found" -- a message saying no key was found
// in a file that has one -- because the walk took a remainder of comments
// and blank lines for an unreadable line. They are what a key file looks
// like after somebody removes a key and writes down why, which is the
// practice an audit asks for.
func TestAKeyFileMayEndInACommentOrABlankLine(t *testing.T) {
	good := pubLine(t)
	for _, tc := range []struct {
		name, body string
		keys       int
	}{
		{"a trailing blank line", good + "\n\n", 1},
		{"several trailing blank lines", good + "\n\n\n\n", 1},
		{"a trailing comment", good + "\n# bob left 2026-02-01, key removed\n", 1},
		{"a comment and then a blank line", good + "\n# removed\n\n", 1},
		{"a comment between two keys", good + "\n# the contractors\n" + pubLine(t) + "\n", 2},
		{"no trailing newline at all", good, 1},
		{"leading comments", "# alice, laptop\n" + good + "\n", 1},
		{"indented trailing comment", good + "\n   # removed\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &config.SSHListener{AuthorizedKeys: write(t, "ak", tc.body)}
			srv := &server{h: h, keys: map[string]bool{}, caKeys: map[string]bool{},
				revoked: map[string]bool{}, noTouch: map[string]bool{}}
			if err := srv.loadCredentials(); err != nil {
				t.Fatalf("refused: %v", err)
			}
			if len(srv.keys) != tc.keys {
				t.Errorf("read %d keys, want %d", len(srv.keys), tc.keys)
			}
		})
	}

	// And the line that is meant to be a key and is not is still refused,
	// which is the property the walk exists to defend: a key that was meant
	// to be accepted and is not is an outage, and one that was meant to be
	// removed and is not is worse.
	t.Run("a broken line after a good one is still refused", func(t *testing.T) {
		h := &config.SSHListener{AuthorizedKeys: write(t, "ak",
			good+"\nssh-ed25519 this-is-not-base64 bob@laptop\n")}
		srv := &server{h: h, keys: map[string]bool{}, caKeys: map[string]bool{},
			revoked: map[string]bool{}, noTouch: map[string]bool{}}
		if err := srv.loadCredentials(); err == nil {
			t.Fatal("a line that is not a key was accepted")
		} else if !strings.Contains(err.Error(), "ssh authorized_keys:") {
			t.Errorf("error %q does not name the file", err)
		}
	})
}

// Which principal a key is matched to.
//
// This is the lookup every per-principal policy hangs off, and the rule
// worth pinning is the one a reader would not guess: a certificate is also a
// key, so it is offered to the match both ways -- by the principals the
// authority wrote into it, and by the fingerprint of the key inside it. A
// listener that matched only one of the two would silently give a
// certificate holder the default policy instead of their own.
func TestWhichPrincipalAKeyIsMatchedTo(t *testing.T) {
	alice := newSigner(t)
	bob := newSigner(t)
	aliceFP := cssh.FingerprintSHA256(alice.PublicKey())

	byFingerprint := func(name, fp string, users ...string) *sshPrincipal {
		pr := &sshPrincipal{name: name, fingerprints: map[string]bool{fp: true},
			certs: map[string]bool{}, users: map[string]bool{}}
		for _, u := range users {
			pr.users[u] = true
		}
		return pr
	}
	byCert := func(name, principal string) *sshPrincipal {
		return &sshPrincipal{name: name, fingerprints: map[string]bool{},
			certs: map[string]bool{principal: true}, users: map[string]bool{}}
	}
	fallback := func(name string) *sshPrincipal {
		return &sshPrincipal{name: name, isDefault: true,
			fingerprints: map[string]bool{}, certs: map[string]bool{},
			users: map[string]bool{}}
	}

	// A certificate for alice's key, naming the principal "oncall".
	cert := &cssh.Certificate{Key: alice.PublicKey(), CertType: cssh.UserCert,
		ValidPrincipals: []string{"oncall"}}
	if err := cert.SignCert(rand.Reader, bob); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		principals []*sshPrincipal
		user       string
		key        cssh.PublicKey
		want       string // the principal's name, or "" for no match
		ok         bool
	}{
		// With no principals configured there is nothing to match and the
		// listener's own policy applies, which is not a refusal.
		{name: "no principals at all", user: "alice", key: alice.PublicKey(), ok: true},

		{name: "a key named by its fingerprint",
			principals: []*sshPrincipal{byFingerprint("admins", aliceFP)},
			user:       "alice", key: alice.PublicKey(), want: "admins", ok: true},
		{name: "a key nothing names and no fallback",
			principals: []*sshPrincipal{byFingerprint("admins", aliceFP)},
			user:       "bob", key: bob.PublicKey(), ok: false},
		{name: "a key nothing names, with a fallback",
			principals: []*sshPrincipal{byFingerprint("admins", aliceFP), fallback("everyone")},
			user:       "bob", key: bob.PublicKey(), want: "everyone", ok: true},

		// The user list narrows a principal: the same key under a different
		// login is a different request.
		{name: "the right key under a login the principal does not name",
			principals: []*sshPrincipal{byFingerprint("admins", aliceFP, "root")},
			user:       "alice", key: alice.PublicKey(), ok: false},
		{name: "the right key under a login it does name",
			principals: []*sshPrincipal{byFingerprint("admins", aliceFP, "root")},
			user:       "root", key: alice.PublicKey(), want: "admins", ok: true},

		// The two halves of a certificate.
		{name: "a certificate matched by the principal in it",
			principals: []*sshPrincipal{byCert("oncall-team", "oncall")},
			user:       "alice", key: cert, want: "oncall-team", ok: true},
		{name: "a certificate matched by the fingerprint of the key inside it",
			principals: []*sshPrincipal{byFingerprint("admins", aliceFP)},
			user:       "alice", key: cert, want: "admins", ok: true},
		{name: "a certificate naming a principal nothing matches",
			principals: []*sshPrincipal{byCert("oncall-team", "someone-else")},
			user:       "alice", key: cert, ok: false},
		// Order decides, so a narrower entry placed first wins over a
		// fallback placed after it.
		{name: "the first match wins",
			principals: []*sshPrincipal{byFingerprint("admins", aliceFP), fallback("everyone")},
			user:       "alice", key: alice.PublicKey(), want: "admins", ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &server{principals: tc.principals}
			pr, ok := srv.principalFor(tc.user, tc.key)
			if ok != tc.ok {
				t.Fatalf("admitted = %v, want %v (principal %+v)", ok, tc.ok, pr)
			}
			switch {
			case tc.want == "" && pr != nil:
				t.Errorf("matched %q, want no principal", pr.name)
			case tc.want != "" && pr == nil:
				t.Errorf("matched nothing, want %q", tc.want)
			case tc.want != "" && pr.name != tc.want:
				t.Errorf("matched %q, want %q", pr.name, tc.want)
			}
		})
	}
}

// newSigner is a fresh ed25519 signer.
func newSigner(t *testing.T) cssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := cssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
