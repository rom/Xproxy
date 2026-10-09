package vnc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/rfb"
)

// Which security types this gateway will use, in each direction. Both
// are decisions taken from the configuration rather than from anything
// on the wire, and both are the place where a missing credential has to
// be noticed: a type offered with nothing behind it is a negotiation
// that gets as far as asking the person for a password and then cannot
// check it, and one used towards a desktop with nothing behind it is a
// connection that cannot be authenticated at all.

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Every type this gateway offers a client needs something behind it:
// vncauth a password to check, VeNCrypt a certificate to present, the
// named types a password or a factor, rsa-aes a key of its own as well.
// Offering one without that is offering an authentication this gateway
// cannot complete.
func TestATypeWithNothingBehindItIsNotOffered(t *testing.T) {
	all := []uint8{rfb.SecNone, rfb.SecVNCAuth, rfb.SecVeNCrypt, rfb.SecTLS,
		rfb.SecMSLogon2, rfb.SecRSAAES, rfb.SecRSAAESne, rfb.SecRSAAES256, rfb.SecARD}

	t.Run("with nothing configured at all", func(t *testing.T) {
		se := &session{t: &server{v: &config.VNCListener{}, offered: all}}
		got := se.offerable()
		if len(got) != 1 || got[0] != rfb.SecNone {
			t.Errorf("offerable is %v; only none needs nothing behind it", names(got))
		}
	})

	t.Run("with a password", func(t *testing.T) {
		se := &session{t: &server{v: &config.VNCListener{}, offered: all, password: "desk"}}
		got := se.offerable()
		// vncauth, mslogon2 and ard are the three a password alone is
		// enough for; VeNCrypt still needs a certificate and the
		// rsa-aes family still needs this gateway's own key.
		want := []uint8{rfb.SecNone, rfb.SecVNCAuth, rfb.SecMSLogon2, rfb.SecARD}
		if names(got) != names(want) {
			t.Errorf("offerable is %v, want %v", names(got), names(want))
		}
	})

	t.Run("with a certificate", func(t *testing.T) {
		se := &session{t: &server{v: &config.VNCListener{}, offered: all, tlsCfg: &tls.Config{MinVersion: tls.VersionTLS12}}}
		got := se.offerable()
		want := []uint8{rfb.SecNone, rfb.SecVeNCrypt, rfb.SecTLS}
		if names(got) != names(want) {
			t.Errorf("offerable is %v, want %v", names(got), names(want))
		}
	})

	t.Run("with a key and a factor instead of a password", func(t *testing.T) {
		enrolled, err := mfa.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		store, err := mfa.Load(secret(t, "mfa", "ops:"+enrolled+"\n", 0o600))
		if err != nil {
			t.Fatal(err)
		}
		se := &session{t: &server{v: &config.VNCListener{}, offered: all,
			rsaKey: key(t), mfaGuard: mfa.NewGuard(store, 0, mfa.Lockout{})}}
		got := se.offerable()
		// A factor stands in for the password on every type that
		// carries a name, which is what makes those the types a
		// one-time code can be asked for.
		want := []uint8{rfb.SecNone, rfb.SecMSLogon2, rfb.SecRSAAES, rfb.SecRSAAESne, rfb.SecRSAAES256, rfb.SecARD}
		if names(got) != names(want) {
			t.Errorf("offerable is %v, want %v", names(got), names(want))
		}
	})
}

// And in the other direction: what the gateway will answer a desktop
// with. An operator can name one, and otherwise the strongest the
// desktop offers that this gateway has the credential for is taken --
// never a weaker one because the stronger one's credential is missing.
func TestTheUpstreamTypeIsTheStrongestThereIsACredentialFor(t *testing.T) {
	k := key(t)
	everything := []uint8{rfb.SecNone, rfb.SecVNCAuth, rfb.SecVeNCrypt, rfb.SecMSLogon2,
		rfb.SecRSAAES, rfb.SecRSAAES256, rfb.SecARD, rfb.SecTight}

	for _, c := range []struct {
		name    string
		v       config.VNCListener
		pw      string
		rsa     *rsa.PrivateKey
		offered []uint8
		want    uint8
		none    bool
	}{
		{
			name: "the one the operator named", v: config.VNCListener{UpstreamSecurity: "vncauth"},
			pw: "desk", offered: everything, want: rfb.SecVNCAuth,
		},
		{
			// Named and not offered is a refusal, not a fallback: the
			// operator said which one, and a weaker one is not it.
			name: "named and not offered", v: config.VNCListener{UpstreamSecurity: "rsa-aes"},
			pw: "desk", offered: []uint8{rfb.SecNone, rfb.SecVNCAuth}, none: true,
		},
		{
			name: "a name that is not a type", v: config.VNCListener{UpstreamSecurity: "nonsense"},
			offered: everything, none: true,
		},
		{
			// Tight with no authentication asks for no credential, so
			// it is usable where nothing is configured -- and it is
			// preferred to none, which does not even say who the
			// desktop is.
			name:    "nothing configured, so only what needs no credential",
			offered: everything, want: rfb.SecTight,
		},
		{
			name:    "and none where that is all there is",
			offered: []uint8{rfb.SecNone, rfb.SecVNCAuth}, want: rfb.SecNone,
		},
		{
			name: "a password reaches vncauth but not the named types",
			pw:   "desk", offered: everything, want: rfb.SecVNCAuth,
		},
		{
			name:    "vencrypt only where the mode asks for it",
			v:       config.VNCListener{UpstreamTLSMode: "vencrypt"},
			offered: []uint8{rfb.SecVeNCrypt, rfb.SecTight}, want: rfb.SecVeNCrypt,
		},
		{
			name:    "and the tunnel is not used when the mode does not",
			offered: []uint8{rfb.SecVeNCrypt, rfb.SecTight}, want: rfb.SecTight,
		},
		{
			name: "a name and a password reach mslogon2",
			v:    config.VNCListener{UpstreamUser: "service"}, pw: "desk",
			offered: []uint8{rfb.SecMSLogon2, rfb.SecTight}, want: rfb.SecMSLogon2,
		},
		{
			name: "and ard, which carries the same two",
			v:    config.VNCListener{UpstreamUser: "service"}, pw: "desk",
			offered: []uint8{rfb.SecARD, rfb.SecMSLogon2}, want: rfb.SecARD,
		},
		{
			name: "rsa-aes needs the key, the credential and the pin",
			v:    config.VNCListener{UpstreamUser: "service", UpstreamRSAFingerprint: "aa:bb"},
			pw:   "desk", rsa: k, offered: []uint8{rfb.SecRSAAES256, rfb.SecVNCAuth}, want: rfb.SecRSAAES256,
		},
		{
			// The pin is what authenticates the far end of that
			// exchange, so without it the family is skipped and the
			// weaker type is used instead.
			name: "and is skipped without the pin",
			v:    config.VNCListener{UpstreamUser: "service"}, pw: "desk", rsa: k,
			offered: []uint8{rfb.SecRSAAES256, rfb.SecVNCAuth}, want: rfb.SecVNCAuth,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := c.v
			se := &session{t: &server{v: &v, upPassword: c.pw, rsaKey: c.rsa}}
			got, ok := se.pickUpstream(c.offered)
			if c.none {
				if ok {
					t.Fatalf("picked %s where there is nothing usable", rfb.SecurityName(got))
				}
				return
			}
			if !ok {
				t.Fatalf("nothing was picked from %v", names(c.offered))
			}
			if got != c.want {
				t.Errorf("picked %s, want %s", rfb.SecurityName(got), rfb.SecurityName(c.want))
			}
		})
	}
}

// The name the gateway verifies the desktop's certificate against is
// the endpoint it dialled, unless the configuration pinned one. A
// client-side default of none would verify nothing.
func TestTheUpstreamCertificateIsCheckedAgainstTheEndpointDialled(t *testing.T) {
	se := &session{target: "desk7.lab.test:5900"}
	if got := se.upstreamTLSFor(&tls.Config{MinVersion: tls.VersionTLS12}).ServerName; got != "desk7.lab.test" {
		t.Errorf("server name %q, want the host of the endpoint", got)
	}
	// A pinned name wins: an estate that dials by address still
	// verifies the name on the certificate.
	pinned := &tls.Config{ServerName: "desks.lab.test", MinVersion: tls.VersionTLS12}
	if got := se.upstreamTLSFor(pinned).ServerName; got != "desks.lab.test" {
		t.Errorf("server name %q, want the configured one", got)
	}
	// And an endpoint that is not host:port leaves it empty rather
	// than making a name up out of the whole string.
	se2 := &session{target: "/run/vnc.sock"}
	if got := se2.upstreamTLSFor(&tls.Config{MinVersion: tls.VersionTLS12}).ServerName; got != "" {
		t.Errorf("server name %q for an endpoint with no host", got)
	}
}

// The door: who may open a connection at all, whether a refusal is
// recorded or enforced, and whether it is worth a security event. These
// are the decisions taken before any RFB is read, which is why they are
// the ones a listener cannot afford to get wrong.
func TestTheDoorAndTheLedger(t *testing.T) {
	host := engine(t)
	inside := netip.MustParseAddr("192.0.2.9")
	outside := netip.MustParseAddr("198.51.100.4")

	t.Run("an empty allow list admits everybody", func(t *testing.T) {
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.VNCListener{}}
		if !srv.clientAllowed(outside) {
			t.Error("a listener with no allow_clients refused a client")
		}
	})

	t.Run("and a list admits only what it names", func(t *testing.T) {
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.VNCListener{},
			allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
		if !srv.clientAllowed(inside) {
			t.Error("a client inside allow_clients was refused")
		}
		if srv.clientAllowed(outside) {
			t.Error("a client outside allow_clients was admitted")
		}
	})

	t.Run("enforcing, a refusal is a refusal", func(t *testing.T) {
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.VNCListener{}}
		if srv.shadowed(outside, "client_refused", "") {
			t.Error("a listener that is not shadowing recorded instead of refusing")
		}
	})

	t.Run("shadowing, it is recorded and not enforced", func(t *testing.T) {
		srv := &server{engine: host, v: &config.VNCListener{},
			cfg: config.Listener{Name: "desks", Policy: &config.ListenerPolicy{Mode: "shadow"}}}
		before := host.Counters().WouldRefusalCounts()["vnc"]["client_refused"]
		if !srv.shadowed(outside, "client_refused", "198.51.100.4") {
			t.Fatal("a shadowing listener enforced a policy refusal")
		}
		if got := host.Counters().WouldRefusalCounts()["vnc"]["client_refused"]; got != before+1 {
			t.Errorf("would_refuse counted %d, want %d", got, before+1)
		}
	})

	t.Run("alert_on_deny decides only the security event", func(t *testing.T) {
		no := false
		quiet := &server{engine: host, cfg: config.Listener{Name: "desks"},
			v: &config.VNCListener{AlertOnDeny: &no}}
		if quiet.alerts() {
			t.Error("alert_on_deny: false still alerts")
		}
		// The counters are not what it silences, so a refusal on a
		// quiet listener is still counted.
		before := host.Counters().RefusalCounts()["vnc"]["client_refused"]
		quiet.deny(&session{t: quiet, ip: outside}, "client_refused", "198.51.100.4")
		if got := host.Counters().RefusalCounts()["vnc"]["client_refused"]; got != before+1 {
			t.Errorf("a refusal on a quiet listener counted %d, want %d", got, before+1)
		}
		loud := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.VNCListener{}}
		if !loud.alerts() {
			t.Error("a listener with no alert_on_deny does not alert")
		}
	})

	t.Run("an upstream that does not exist is not dialled", func(t *testing.T) {
		srv := &server{engine: host, cfg: config.Listener{Name: "desks"},
			v: &config.VNCListener{Upstream: "nowhere"}}
		se := &session{t: srv, ip: inside}
		err := se.connect()
		if err == nil {
			t.Fatal("a session connected to an upstream that is not configured")
		}
		if !strings.Contains(err.Error(), "no pool") {
			t.Errorf("the error says %q", err)
		}
	})
}

// jumpKeys writes a key for the gateway to authenticate with and a
// known_hosts for it to pin the jump host by, which are the two files
// an SSH-reached desktop needs.
func jumpKeys(t *testing.T) (keyFile, knownHosts string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := cssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts = filepath.Join(dir, "known_hosts")
	line := "[127.0.0.1]:22 " + string(cssh.MarshalAuthorizedKey(signer))
	if err := os.WriteFile(knownHosts, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, knownHosts
}

// Where the tunnel goes. An estate that names one jump host uses it for
// every desktop; one that does not reaches each desktop's own host,
// derived from the endpoint rather than guessed.
func TestTheTunnelReachesTheHostTheEndpointNames(t *testing.T) {
	keyFile, knownHosts := jumpKeys(t)
	d, err := newSSHDialer(&config.VNCOverSSH{User: "jump", KeyFile: keyFile, KnownHosts: knownHosts})
	if err != nil {
		t.Fatal(err)
	}

	// With no address configured the endpoint's host is used, on the
	// SSH port: nothing is listening there in a test, so what this
	// asserts is which host was dialled.
	_, err = d.dial("127.0.0.1:5901")
	if err == nil {
		t.Fatal("a tunnel was opened to a host that is not there")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:22") {
		t.Errorf("the error says %q, which does not name the host derived from the endpoint", err)
	}

	// An endpoint that is not host:port is refused rather than passed
	// to the dialler as a hostname.
	if _, err := d.dial("/run/vnc.sock"); err == nil {
		t.Error("an endpoint with no host was dialled anyway")
	}
}

// The types this gateway does not mediate are refused rather than
// relayed blind. Being able to name the type is the reason this is a
// listener kind and not a port forward: anything it cannot name, it
// cannot police.
func TestASecurityTypeThisGatewayDoesNotMediateIsRefused(t *testing.T) {
	host := engine(t)
	srv := &server{engine: host, cfg: config.Listener{Name: "desks"}, v: &config.VNCListener{}}
	conn, drop := peer(t)
	drop()
	_ = conn.Close()

	se := &session{t: srv, client: conn, clientSec: 0x7f, clientVersion: rfb.V38}
	if reason := se.clientAuth(); reason != "security_unsupported" {
		t.Errorf("an unmediated client type ended %q, want security_unsupported", reason)
	}
	se2 := &session{t: srv, up: conn, upSec: 0x7f, upVersion: rfb.V38}
	if reason := se2.upstreamAuth(); reason != "upstream_security_unusable" {
		t.Errorf("an unmediated desktop type ended %q, want upstream_security_unusable", reason)
	}
}

// A factor can only be asked for where the credential carried a name,
// and a session that got this far without one is a client that chose a
// type which proves knowledge of a shared password and says nothing
// about who holds it.
func TestAFactorNeedsANameToLookTheEnrolmentUpBy(t *testing.T) {
	host := engine(t)
	enrolled, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	store, err := mfa.Load(secret(t, "mfa", "ops:"+enrolled+"\n", 0o600))
	if err != nil {
		t.Fatal(err)
	}
	// A guard exists only where the listener has an mfa section, so
	// the fixture has both.
	srv := &server{engine: host, cfg: config.Listener{Name: "desks"},
		v:        &config.VNCListener{MFA: &config.MFAPolicy{MaxFailures: 1}},
		mfaGuard: mfa.NewGuard(store, 0, mfa.Lockout{MaxFailures: 1, Window: time.Minute, Duration: time.Hour})}
	se := &session{t: srv, ip: netip.MustParseAddr("192.0.2.9")}
	if reason := se.askFactor(); reason != "mfa_no_identity" {
		t.Errorf("a session with no name ended %q, want mfa_no_identity", reason)
	}

	// A name nobody enrolled is not asked for a code it could not
	// have: it is refused.
	se2 := &session{t: srv, ip: se.ip, factorUser: "nobody", factorCode: "000000"}
	if reason := se2.askFactor(); reason == "" {
		t.Error("an unenrolled name was let through")
	}

	// And one that is enrolled but locked out is refused without the
	// code being checked at all.
	locked := &session{t: srv, ip: se.ip, factorUser: "ops", factorCode: "000000"}
	if reason := locked.askFactor(); reason != "mfa_failed" {
		t.Fatalf("a wrong code ended %q, want mfa_failed", reason)
	}
	again := &session{t: srv, ip: se.ip, factorUser: "ops", factorCode: "000000"}
	if reason := again.askFactor(); reason != "mfa_locked" {
		t.Errorf("the second wrong code ended %q, want mfa_locked", reason)
	}
}
