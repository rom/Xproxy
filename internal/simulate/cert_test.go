package simulate

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The certificate a simulated TLS listener presents, and the file names it
// lands under.
//
// It is generated rather than read from the configuration on purpose: a
// simulation that opened a production listener's private key to answer a
// question about a WAF rule would be a simulation nobody should run. So what
// has to hold is that the thing it generates instead cannot be mistaken for,
// or used as, anything else -- it is self-signed, it names localhost, and it
// lasts an hour.

func TestTheSimulationCertificateCannotBeUsedAsAnythingElse(t *testing.T) {
	certPEM, keyPEM, err := selfSigned()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("the pair does not load: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	// Self-signed: there is no authority behind it, so nothing trusts it.
	if err := leaf.CheckSignatureFrom(leaf); err != nil {
		t.Errorf("not self-signed: %v", err)
	}
	// It names localhost and itself, and nothing an estate owns: a
	// certificate carrying a real service's name is one somebody could be
	// tempted to reuse, or mistake for the listener's own.
	harmless := map[string]bool{"localhost": true, "xproxy-simulation": true}
	if len(leaf.DNSNames) == 0 {
		t.Error("the certificate names nothing")
	}
	for _, n := range leaf.DNSNames {
		if !harmless[n] {
			t.Errorf("the certificate names %q", n)
		}
	}
	if !slices.Contains(leaf.DNSNames, "localhost") {
		t.Errorf("names = %v, want localhost among them", leaf.DNSNames)
	}
	// An hour: a certificate left behind in a simulation directory is not
	// usable tomorrow.
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life > 2*time.Hour {
		t.Errorf("valid for %v, want about an hour", life)
	}
	// And it verifies as the server of a handshake in this process, which
	// is the one thing it is for.
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "localhost", Roots: pool,
		CurrentTime: leaf.NotBefore.Add(time.Minute)}); err != nil {
		t.Errorf("it does not verify against itself: %v", err)
	}
}

// A listener's name becomes part of a file name, and a listener may be called
// anything the configuration allows -- including things a path may not hold.
// A name that escaped into a path would be a simulation writing outside its
// own directory, which is the one thing the simulation must never do.
func TestAListenerNameCannotEscapeIntoAPath(t *testing.T) {
	for _, c := range []struct {
		name string
		want string
	}{
		{"edge", "edge"},
		{"edge-1_tls", "edge-1_tls"},
		{"../../etc/passwd", "______etc_passwd"},
		{"with space", "with_space"},
		{"a/b", "a_b"},
		{"", "listener"},
		{"/", "_"},
	} {
		if got := safeName(c.name); got != c.want {
			t.Errorf("safeName(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// The throwaway certificate is written once and reused, because a simulation
// run twice over the same directory should not pile up key material.
func TestTheThrowawayCertificateIsWrittenOnceAndReused(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := throwawayCert(dir, "edge/1")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{cert, key} {
		if filepath.Dir(p) != dir {
			t.Errorf("%s is outside the simulation directory", p)
		}
		if strings.Contains(filepath.Base(p), "/") {
			t.Errorf("%s has a separator in its name", p)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", p, info.Mode().Perm())
		}
	}
	before, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := throwawayCert(dir, "edge/1")
	if err != nil {
		t.Fatal(err)
	}
	if again != cert {
		t.Errorf("a second call named a different file: %s", again)
	}
	after, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the certificate was regenerated over itself")
	}
}

// The report's one-line form is what the command prints, so it has to name
// what the simulation changed about the configuration before it ran it -- a
// run that silently switched something off would be a run whose answer is
// about a different configuration than the operator thinks.
func TestTheReportSummaryNamesWhatWasChanged(t *testing.T) {
	for _, c := range []struct {
		name string
		r    Report
		want []string
	}{
		{"nothing but listeners", Report{Listeners: []string{"edge"}}, []string{"1 listeners"}},
		{
			"sections switched off",
			Report{Listeners: []string{"edge", "api"}, SwitchedOff: []string{"fleet", "cluster"}},
			[]string{"2 listeners", "switched off: fleet cluster"},
		},
		{
			"state copied in",
			Report{Listeners: []string{"edge"}, Copied: []string{"bans: /var/lib/x/bans.db"}},
			[]string{"1 listeners", "copied: 1 state file(s)"},
		},
	} {
		got := c.r.summary()
		for _, want := range c.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: summary %q does not carry %q", c.name, got, want)
			}
		}
	}
}

// A treatment names itself, because a test failure about the wrong treatment
// has to be readable: "kept" against "switched off" says what went wrong where
// two integers would not.
func TestEveryTreatmentNamesItself(t *testing.T) {
	for _, c := range []struct {
		t    treatment
		want string
	}{
		{keepPolicy, "kept"},
		{copyState, "copied"},
		{switchOff, "switched off"},
		{replaced, "replaced"},
		{treatment(99), "unknown"},
	} {
		if got := c.t.String(); got != c.want {
			t.Errorf("treatment %d = %q, want %q", c.t, got, c.want)
		}
	}
}
