package ssh_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	sshkind "github.com/rom/xproxy/internal/kinds/ssh"
	"github.com/rom/xproxy/internal/proxytest"
)

// End to end through the real handshake: with require_hardware_key the token's
// key gets in and the ordinary key in the same file does not.
//
// The client's half of FIDO2 is sshkind.SKTestKey, which builds the signature a
// token builds. What verifies it is the same code that verifies a real token's,
// so this is the gateway's policy under test rather than a stand-in for it.
func TestOnlyAKeyInATokenAuthenticates(t *testing.T) {
	line, signer := sshkind.SKTestKey(t)
	s, addr, fileKey, tg := bastionWith(t, "        require_hardware_key: true\n", "", line)
	c := dialBastion(t, addr, signer)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sess.Output("uptime"); err != nil || string(out) != "ran uptime" {
		t.Fatalf("a hardware key could not use the bastion: %q %v", out, err)
	}
	if len(tg.seen()) == 0 {
		t.Error("the target saw nothing")
	}
	if n := s.Counters().SSHHardwareAuths.Load(); n == 0 {
		t.Error("ssh_hardware_auths did not move")
	}
	// The ordinary key is in the same authorized_keys and is refused for being
	// a file: a listener that requires a token means it.
	if _, err := cssh.Dial("tcp", addr, skClientConfig(fileKey)); err == nil {
		t.Fatal("a key in a file authenticated where a token is required")
	}
	if n := s.Counters().SSHHardwareRefused.Load(); n == 0 {
		t.Error("ssh_hardware_refused did not move")
	}
}

// A token whose user did not touch it signs with the presence flag clear, and
// that is not a credential here: the touch is what an attacker who has reached
// the client's machine cannot supply.
func TestASignatureWithoutTheTouchIsRefused(t *testing.T) {
	line, signer := sshkind.SKTestKey(t)
	signer.Presence = false
	_, addr, _, _ := bastionWith(t, "        require_hardware_key: true\n", "", line)
	if _, err := cssh.Dial("tcp", addr, skClientConfig(signer)); err == nil {
		t.Fatal("a signature with no user presence authenticated")
	}
}

// And with the requirement off, a security key is still welcome -- and still
// has to assert presence, because that is the key's own protocol rather than
// this listener's policy.
func TestATokenIsAcceptedWithoutTheRequirement(t *testing.T) {
	line, signer := sshkind.SKTestKey(t)
	s, addr, _, _ := bastionWith(t, "", "", line)
	c := dialBastion(t, addr, signer)
	if _, err := c.NewSession(); err != nil {
		t.Fatal(err)
	}
	if n := s.Counters().SSHHardwareAuths.Load(); n == 0 {
		t.Error("a hardware authentication was not counted")
	}
	signer.Presence = false
	if _, err := cssh.Dial("tcp", addr, skClientConfig(signer)); err == nil {
		t.Fatal("a signature with no user presence authenticated")
	}
}

func skClientConfig(signer cssh.Signer) *cssh.ClientConfig {
	return &cssh.ClientConfig{
		User:            "alice",
		Auth:            []cssh.AuthMethod{cssh.PublicKeys(signer)},
		HostKeyCallback: cssh.InsecureIgnoreHostKey(), //nolint:gosec // the test pins nothing
		Timeout:         5 * time.Second,
	}
}

// What a listener refuses to start with: the two arrangements that would leave
// an operator believing in a control that is not there.
func TestAHardwareKeyListenerRefusesWhatCouldNotWork(t *testing.T) {
	line, _ := sshkind.SKTestKey(t)
	ordinary := ordinaryKeyLine(t)
	for _, tc := range []struct{ name, keys, extra, want string }{
		// A requirement with nothing that could satisfy it: no sk- key in the
		// file and no authority to issue a certificate.
		{name: "no token key and no authority", keys: ordinary,
			extra: "        require_hardware_key: true\n", want: "no client could authenticate"},
		// A line asking for the presence check to be waived, on a listener
		// that requires presence: the credential would never work.
		{name: "a line waiving the touch", keys: "no-touch-required " + strings.TrimSpace(line),
			want: "requires user presence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tryBastion(t, tc.extra, tc.keys)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want one about %q", err, tc.want)
			}
		})
	}
	// The same waiver on a listener that has said it will honour it loads.
	if err := tryBastion(t, "        require_touch: false\n", "no-touch-required "+strings.TrimSpace(line)); err != nil {
		t.Errorf("a waived line where the waiver is honoured: %v", err)
	}
	// And the requirement is satisfied by an authority alone, because a fleet
	// on certificates has no authorized_keys to put a token key in.
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pub")
	if err := os.WriteFile(ca, []byte(ordinaryKeyLine(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tryBastion(t, "        require_hardware_key: true\n        trusted_user_ca_keys: "+ca+"\n", ordinary); err != nil {
		t.Errorf("a requirement with an authority to satisfy it: %v", err)
	}
}

// ordinaryKeyLine is an authorized_keys line for a key in a file.
func ordinaryKeyLine(t *testing.T) string {
	t.Helper()
	_, _, line := sshKey(t, t.TempDir(), "other")
	return strings.TrimSpace(line)
}

// tryBastion starts a bastion whose authorized_keys holds exactly what it is
// given, and returns the load error.
func tryBastion(t *testing.T, extra, keys string) error {
	t.Helper()
	dir := t.TempDir()
	hostKeyPath, _, _ := sshKey(t, dir, "host")
	upKeyPath, _, _ := sshKey(t, dir, "upstream")
	_, peer, _ := sshKey(t, dir, "peer")
	authorized := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(keys+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(dir, "known_hosts")
	line := "127.0.0.1 " + strings.TrimSpace(string(cssh.MarshalAuthorizedKey(peer.PublicKey())))
	if err := os.WriteFile(known, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: bastion
      address: "127.0.0.1:0"
      kind: ssh
      ssh:
        upstream: hosts
        host_keys: [%s]
        authorized_keys: %s
        upstream_key_file: %s
        upstream_known_hosts: %s
        upstream_user: operator
%s
logging: {access: {enabled: false}}
upstreams:
  - name: hosts
    endpoints: [{address: "127.0.0.1:22"}]
routes: []
`, hostKeyPath, authorized, upKeyPath, known, extra)
	srv, err := proxytest.TryStart(yaml)
	if err != nil {
		return err
	}
	// The credentials are read when the listener binds, so the load error this
	// is about comes from Start rather than from building the server.
	err = srv.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	return err
}
