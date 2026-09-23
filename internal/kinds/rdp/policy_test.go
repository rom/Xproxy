package rdp_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/rdp"
)

// A session reaches the desktop, and what the desktop shows comes
// back.
func TestSessionReachesTheDesktop(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	if got := cl.negotiate(rdp.ProtocolSSL, pool); got != rdp.ProtocolSSL {
		t.Fatalf("the gateway chose %s", rdp.ProtocolName(got))
	}
	cl.conference()
	if got := cl.update(); string(got) != string(d.shown) {
		t.Errorf("the desktop's stream did not arrive: %q", got)
	}
	if sn := s.Stats(); sn.RDPSessions != 1 {
		t.Errorf("rdp_sessions %d, want 1", sn.RDPSessions)
	}
}

// A client asking for network level authentication is answered with
// TLS, which is the downgrade that lets a gateway read the credential
// at all.
func TestNLAIsAnsweredWithTLS(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	_, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	got := cl.negotiate(rdp.ProtocolSSL|rdp.ProtocolHybrid, pool)
	if got != rdp.ProtocolSSL {
		t.Fatalf("a client asking for nla got %s", rdp.ProtocolName(got))
	}
}

// A client that can only speak the legacy protocol is refused where
// the listener does not offer it, and told which way to come back.
func TestALegacyOnlyClientIsRefusedWhereItIsNotOffered(t *testing.T) {
	cert, key, _ := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	req, err := rdp.ConnectionRequest{HasNegotiation: true, Protocols: rdp.ProtocolRDP}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cl.write(req)
	pdu, err := rdp.ReadPDU(cl.c)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := rdp.ParseConnectionConfirm(pdu.Body)
	if err != nil {
		t.Fatal(err)
	}
	if cc.Failure != rdp.FailSSLRequiredByServer {
		t.Errorf("failure %#x, want ssl-required", cc.Failure)
	}
	waitFor(t, "the refusal to be counted", func() bool { return s.Stats().RDPRefused > 0 })
}

// A channel the policy refuses is not the channel the desktop is asked
// for, and nothing the client sends on it arrives.
func TestARefusedChannelReachesNothing(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        channels: {allow: [rdpsnd]}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference("rdpdr", "cliprdr", "rdpsnd")
	cl.update()

	// The desktop was asked for three channels, but only the allowed
	// one under its own name.
	waitFor(t, "the desktop to have the channel list", func() bool { return len(d.asked()) == 3 })
	asked := d.asked()
	if asked[2].Name != "rdpsnd" {
		t.Errorf("the allowed channel reached the desktop as %q", asked[2].Name)
	}
	for _, i := range []int{0, 1} {
		if asked[i].Name == "rdpdr" || asked[i].Name == "cliprdr" {
			t.Errorf("a refused channel was asked for under its own name: %q", asked[i].Name)
		}
		if !strings.HasPrefix(asked[i].Name, "xpdeny") {
			t.Errorf("a refused channel is named %q", asked[i].Name)
		}
	}
	// And the identifiers still line up, so the client is not confused.
	if len(cl.ids) != 3 {
		t.Fatalf("the client got %d identifiers for 3 channels", len(cl.ids))
	}

	// Data on a refused channel goes nowhere.
	cl.send(cl.ids[0], []byte("file contents"))
	cl.send(cl.ids[2], []byte("audio"))
	waitFor(t, "the allowed channel's data", func() bool { return len(d.seen(cl.ids[2])) > 0 })
	if got := d.seen(cl.ids[0]); len(got) != 0 {
		t.Errorf("a refused channel carried %q", got)
	}
	waitFor(t, "the refusals to be counted", func() bool { return s.Stats().RDPChannelsRefused >= 2 })
}

// With the redirection channel allowed, the device policy decides
// which kinds of device a session gets -- which is what enabling or
// disabling file transfer and ports comes down to.
func TestTheDevicePolicyDecidesWhatIsRedirected(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        channels: {allow: [rdpdr]}\n"+
		"        devices: {allow: [printer]}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference("rdpdr")
	cl.update()
	cl.sendDevices(cl.ids[0],
		rdp.Device{Type: rdp.DeviceFilesystem, ID: 1, Name: "C:"},
		rdp.Device{Type: rdp.DevicePrinter, ID: 2, Name: "PRN"},
		rdp.Device{Type: rdp.DeviceSerial, ID: 3, Name: "COM1"},
		rdp.Device{Type: rdp.DeviceParallel, ID: 4, Name: "LPT1"},
	)
	waitFor(t, "the announcement to arrive", func() bool { _, ok := d.redirected(); return ok })
	got, _ := d.redirected()
	if len(got) != 1 || got[0].Type != rdp.DevicePrinter {
		t.Fatalf("the desktop was offered %+v", got)
	}
	waitFor(t, "the refusals to be counted", func() bool { return s.Stats().RDPDevicesRefused == 3 })
}

// With no device kind allowed, an announcement arrives empty: the
// session has the channel and no redirection on it.
func TestNoDeviceKindMeansNoRedirection(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	_, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        channels: {allow: [rdpdr]}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference("rdpdr")
	cl.update()
	cl.sendDevices(cl.ids[0], rdp.Device{Type: rdp.DeviceFilesystem, ID: 1, Name: "C:"})
	waitFor(t, "the announcement to arrive", func() bool { _, ok := d.redirected(); return ok })
	if got, _ := d.redirected(); len(got) != 0 {
		t.Errorf("the desktop was offered %+v", got)
	}
}

// The credential the desktop is opened with is the one an operator
// configured, not the one the person typed.
func TestTheDesktopIsOpenedWithTheGatewaysCredential(t *testing.T) {
	cert, key, pool := certs(t)
	pw := filepath.Join(t.TempDir(), "svc.pw")
	write(t, pw, "service-secret")
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	_, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        upstream_user: svc\n        upstream_domain: LAB\n"+
		"        upstream_password_file: "+pw+"\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("HOME", "alice", "her-own-password")
	waitFor(t, "the credential to arrive", func() bool { return d.credential() != nil })
	info := d.credential()
	if info.Username != "svc" || info.Password != "service-secret" || info.Domain != "LAB" {
		t.Errorf("the desktop was opened with %q/%q/%q", info.Domain, info.Username, info.Password)
	}
	if info.Flags&rdp.InfoAutologon == 0 {
		t.Error("a credential the gateway supplied was not marked for automatic logon")
	}
}

// Without one, the person's own credential is forwarded as it
// arrived, which is what an estate that wants its own accounts used
// needs.
func TestWithoutOneThePersonsCredentialIsForwarded(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	_, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("HOME", "alice", "her-own-password")
	waitFor(t, "the credential to arrive", func() bool { return d.credential() != nil })
	info := d.credential()
	if info.Username != "alice" || info.Password != "her-own-password" || info.Domain != "HOME" {
		t.Errorf("the desktop was opened with %q/%q/%q", info.Domain, info.Username, info.Password)
	}
}

func enrol(t *testing.T, user string) (string, string) {
	t.Helper()
	secret, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mfa")
	if err := os.WriteFile(path, []byte(user+":"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, secret
}

func totp(t *testing.T, secret string) string {
	t.Helper()
	raw, err := mfa.ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	c, err := mfa.Code(raw, mfa.Counter(time.Now(), 30*time.Second), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The factor travels with the password, is checked before the
// credential goes any further, and never reaches the desktop.
func TestTheFactorRidesThePasswordAndIsStripped(t *testing.T) {
	cert, key, pool := certs(t)
	file, secret := enrol(t, "alice")
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        mfa: {file: "+file+"}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")

	// A wrong code: the credential never reaches the desktop.
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	cl.sendInfo("LAB", "alice", "her-password,000000")
	waitFor(t, "the failure to be counted", func() bool { return s.Stats().RDPMFAFailed == 1 })
	if info := d.credential(); info != nil {
		t.Errorf("a wrong code reached the desktop as %q", info.Username)
	}

	// The right one goes through, with the code taken off.
	cl2 := dial(t, addr)
	cl2.negotiate(rdp.ProtocolSSL, pool)
	cl2.conference()
	cl2.update()
	cl2.sendInfo("LAB", "alice", "her-password,"+totp(t, secret))
	waitFor(t, "the credential to arrive", func() bool { return d.credential() != nil })
	info := d.credential()
	if info.Password != "her-password" {
		t.Errorf("the desktop was given %q", info.Password)
	}
	waitFor(t, "the factor to be counted", func() bool { return s.Stats().RDPMFAOK == 1 })
}

// A name with no enrolment cannot decline the factor by not having
// one, and a credential with no code at all is refused too.
func TestAnUnenrolledNameAndAMissingCodeAreRefused(t *testing.T) {
	cert, key, pool := certs(t)
	file, _ := enrol(t, "alice")
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        mfa: {file: "+file+"}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	for _, c := range []struct{ user, pass string }{
		{"mallory", "whatever,123456"},
		{"alice", "her-password"},
	} {
		cl := dial(t, addr)
		cl.negotiate(rdp.ProtocolSSL, pool)
		cl.conference()
		cl.update()
		cl.sendInfo("LAB", c.user, c.pass)
	}
	waitFor(t, "both refusals", func() bool { return s.Stats().RDPMFAFailed == 2 })
	if info := d.credential(); info != nil {
		t.Errorf("a refused credential reached the desktop as %q", info.Username)
	}
}

// The recording holds what the desktop showed, and says what it is.
func TestTheRecordingHoldsTheStream(t *testing.T) {
	dir := t.TempDir()
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key), shown: []byte("PIXELS-FOR-THE-RECORD")})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        recording: {directory: "+dir+"}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference()
	cl.update()
	_ = cl.c.Close()

	waitFor(t, "the recording to be finished", func() bool { return s.Stats().RDPRecorded == 1 })
	files, _ := filepath.Glob(filepath.Join(dir, "*.rdp.cast"))
	if len(files) != 1 {
		t.Fatalf("%d recordings, want 1", len(files))
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{"PIXELS-FOR-THE-RECORD", "rdp-server-to-client", "XPROXY_PROTOCOL"} {
		if !strings.Contains(text, want) {
			t.Errorf("the recording does not carry %q", want)
		}
	}
}

// Settings that would quietly do nothing, or that this gateway cannot
// honour, are refused at load.
func TestTheConfigurationIsChecked(t *testing.T) {
	cases := []struct{ name, rdp, want string }{
		{"nla towards a client", `{upstream: farm, security: [nla]}`, "own password"},
		{"nla with no credential to prove", `{upstream: farm, upstream_security: nla}`, "upstream_user"},
		{"the legacy protocol towards a client", `{upstream: farm, security: [rdp]}`, "not implemented"},
		{"the legacy protocol towards a desktop", `{upstream: farm, upstream_security: rdp}`, "not implemented"},
		{"devices without their channel", `{upstream: farm, devices: {allow: [drive]}}`, "could announce"},
		{"a device kind that is not one", `{upstream: farm, channels: {allow: [rdpdr]}, devices: {allow: [webcam]}}`, "not a device kind"},
		{"half a credential", `{upstream: farm, upstream_user: svc}`, "half a credential"},
		{"tls with no certificate", `{upstream: farm, security: [tls]}`, "tls section"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := `
version: 1
server:
  listeners:
    - name: desks
      address: "127.0.0.1:0"
      kind: rdp
      rdp: ` + c.rdp + `
upstreams:
  - name: farm
    endpoints: [{address: 127.0.0.1:3389}]
`
			_, err := config.Parse([]byte(yaml))
			if err == nil {
				t.Fatal("it was accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not say %q", err, c.want)
			}
		})
	}
}
