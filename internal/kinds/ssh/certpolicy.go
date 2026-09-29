package ssh

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/textsafe"
)

// What the certificate authority said about a certificate.
//
// A user certificate is not only a signature over a public key and a
// list of principals. It carries the CA's own restrictions, and a
// gateway that checks the signature and ignores the rest is a gateway
// where those restrictions do not exist:
//
//   - source-address is a critical option naming the networks the
//     certificate may be used from. CheckCert does not evaluate it --
//     naming it in SupportedCriticalOptions says only that somebody
//     will -- because the check needs the client's address, which the
//     callback here has and CheckCert does not.
//   - force-command is a critical option fixing the command the session
//     runs, whatever the client asks for. OpenSSH replaces the client's
//     command with it, and so does this: a certificate issued to run one
//     thing is issued for a reason.
//   - The extensions are permissions, and their absence is a denial.
//     A certificate made with "ssh-keygen -O clear -O permit-pty" grants
//     a terminal and nothing else; a gateway reading only the listener's
//     own allow_channels would still give it a port forward.
//
// None of this replaces the listener's policy. Both apply, and the
// narrower wins: the CA says what this credential may do and the
// listener says what anybody may do here.

// certExtension names the OpenSSH extensions this gateway reads, and
// the request or channel each one is the permission for.
const (
	extPTY     = "permit-pty"
	extPortFwd = "permit-port-forwarding"
	extAgent   = "permit-agent-forwarding"
	extX11     = "permit-X11-forwarding"
	extUserRC  = "permit-user-rc"
)

// The Permissions extension keys this gateway puts its findings in, to
// be read once the session is up. Permissions is the only thing the
// crypto library carries from the authentication to the connection.
const (
	permForceCommand = "force_command"
	permCertGrants   = "cert_grants"
	permCertID       = "cert_id"
)

// certDecision is what a certificate allows, as the CA wrote it.
type certDecision struct {
	// forceCommand is the command the session must run, or empty.
	forceCommand string
	// grants are the extensions present on the certificate. A nil map
	// means the key was not a certificate, so nothing is restricted by
	// one.
	grants map[string]bool
	// id is the certificate's key id, which is what a CA puts a name in.
	id string
}

// allows reports whether a certificate grants an extension. A plain key
// (nil grants) restricts nothing: the listener's policy is the only one
// there is.
func (d certDecision) allows(ext string) bool {
	if d.grants == nil {
		return true
	}
	return d.grants[ext]
}

// checkCertificate applies the CA's own restrictions. It runs after
// CheckCert, which has already verified the signature, the window and
// the principal list.
func (t *server) checkCertificate(c cssh.ConnMetadata, cert *cssh.Certificate) (certDecision, error) {
	var d certDecision
	if err := t.certLifetime(cert); err != nil {
		return d, err
	}
	if err := certSourceAddress(c, cert); err != nil {
		return d, err
	}
	d.id = textsafe.Clip64(cert.KeyId)
	d.forceCommand = cert.CriticalOptions["force-command"]
	d.grants = make(map[string]bool, len(cert.Extensions))
	for ext := range cert.Extensions {
		d.grants[ext] = true
	}
	return d, nil
}

// certLifetime refuses a certificate whose validity window is longer
// than this listener accepts. A CA that issues for a year has made a
// credential nobody can take back for a year; the point of certificates
// over authorized_keys is that they expire, and a bastion is entitled to
// say how soon.
func (t *server) certLifetime(cert *cssh.Certificate) error {
	max := t.h.MaxCertificateLifetime.D()
	if max <= 0 {
		return nil
	}
	if cert.ValidBefore == cssh.CertTimeInfinity {
		return fmt.Errorf("the certificate never expires, and this listener accepts at most %s", max)
	}
	// Both are seconds since the epoch, unsigned on the wire.
	if cert.ValidBefore < cert.ValidAfter {
		return fmt.Errorf("the certificate's validity window ends before it begins")
	}
	// The difference is bounded before it becomes a duration: both are
	// unsigned seconds on the wire, and a window wider than the bound
	// stated in seconds is over it whatever the arithmetic would do.
	seconds := cert.ValidBefore - cert.ValidAfter
	if seconds > uint64(max/time.Second) { //nolint:gosec // max is positive here
		return fmt.Errorf("the certificate is valid for %d seconds, and this listener accepts at most %s", seconds, max)
	}
	return nil
}

// certSourceAddress enforces the source-address critical option, which
// CheckCert leaves to the caller: it is the one option whose check needs
// the client's address, and CheckCert does not have it.
//
// The library enforces it too, from Permissions.CriticalOptions, which
// this gateway's callback does not fill in -- so this is the only place
// it happens, and it is the place whose refusal carries this listener's
// own reason and counter.
//
// A gateway that skipped it would accept from anywhere a certificate the
// CA restricted to one network, which is the opposite of what issuing it
// that way meant.
func certSourceAddress(c cssh.ConnMetadata, cert *cssh.Certificate) error {
	list, ok := cert.CriticalOptions["source-address"]
	if !ok {
		return nil
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("the certificate names source-address and this connection has no address to check")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("the certificate names source-address and %q is not an address", textsafe.Clip64(host))
	}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			// A bare address, which OpenSSH allows.
			if want, err := netip.ParseAddr(entry); err == nil && want.Unmap() == addr.Unmap() {
				return nil
			}
			continue
		}
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			// A list this gateway cannot read is a restriction it cannot
			// apply, and a restriction it cannot apply must not be
			// treated as absent.
			return fmt.Errorf("the certificate's source-address list carries %q, which is not a CIDR", textsafe.Clip64(entry))
		}
		if p.Contains(addr.Unmap()) {
			return nil
		}
	}
	return fmt.Errorf("the certificate is restricted to %s and this connection is from %s",
		textsafe.Clip256(list), addr)
}

// forcedCommand is the command a session must run, and whether one was
// fixed at all. It is read from Permissions, which is what the crypto
// library carries from the authentication into the connection.
func forcedCommand(p *cssh.Permissions) (string, bool) {
	if p == nil {
		return "", false
	}
	cmd, ok := p.Extensions[permForceCommand]
	return cmd, ok && cmd != ""
}

// certGrants reads back the extensions the certificate carried. A
// session authenticated by a plain key has none recorded, and nothing is
// restricted by a certificate that does not exist.
func certGrants(p *cssh.Permissions) certDecision {
	if p == nil {
		return certDecision{}
	}
	list, ok := p.Extensions[permCertGrants]
	if !ok {
		return certDecision{}
	}
	d := certDecision{grants: map[string]bool{}, id: p.Extensions[permCertID]}
	for _, e := range strings.Split(list, ",") {
		if e != "" {
			d.grants[e] = true
		}
	}
	return d
}

// encodeGrants renders the extension set for Permissions, which carries
// strings and nothing else.
func encodeGrants(grants map[string]bool) string {
	out := make([]string, 0, len(grants))
	for _, e := range []string{extPTY, extPortFwd, extAgent, extX11, extUserRC} {
		if grants[e] {
			out = append(out, e)
		}
	}
	// An empty set is meaningful -- a certificate that grants nothing --
	// and has to be told apart from no certificate at all, so the caller
	// sets the key whenever grants is non-nil.
	return strings.Join(out, ",")
}

// certRequestGrant maps a channel request to the certificate extension
// that permits it, and reports whether a certificate governs it at all.
// A request nothing here names is the listener's business alone.
func certRequestGrant(req string) (string, bool) {
	switch req {
	case "pty-req":
		return extPTY, true
	case "x11-req":
		return extX11, true
	case "auth-agent-req@openssh.com", "auth-agent-req":
		return extAgent, true
	}
	return "", false
}

// shellOperators are the characters that make one command line into two,
// or into something other than a command with arguments.
const shellOperators = ";&|<>`$(){}\n\r*?[]!~"

// shellSyntax reports the shell operator a command line carries, or
// empty. It is what stands between a regular expression over a command
// line and the shell that will actually run it.
//
// The test is deliberately crude and deliberately broad. A bastion does
// not need to know what "journalctl -u x; rm -rf /" would do; it needs to
// know that the line is not a command with arguments, which is the only
// shape a list of patterns can be written against. A listener that means
// to allow shell syntax says so and writes its patterns knowing it.
func shellSyntax(cmd string) string {
	for _, r := range cmd {
		if strings.ContainsRune(shellOperators, r) {
			return fmt.Sprintf("the shell operator %q", string(r))
		}
		if r < 0x20 || r == 0x7f {
			return "a control character"
		}
	}
	// A quote with nothing to quote is either a line a shell would read
	// differently from this policy or a line no shell would run.
	if strings.Count(cmd, `"`)%2 != 0 || strings.Count(cmd, "'")%2 != 0 {
		return "an unbalanced quote"
	}
	return ""
}

// runForced sends the command the certificate fixed, instead of what the
// client asked for. OpenSSH replaces the client's command with
// force-command and says nothing about it; this does the same and writes
// a line saying what was asked and what ran, because a session that runs
// something other than what was typed should be explainable afterwards.
func (se *session) runForced(clientCh, upCh cssh.Channel, r *cssh.Request, startPump func(), st *sshChannel) bool {
	_ = clientCh
	payload := cssh.Marshal(struct{ Command string }{se.forceCommand})
	forced := &cssh.Request{Type: "exec", WantReply: r.WantReply, Payload: payload}
	se.startRecording(st, forced)
	startPump()
	ok, err := upCh.SendRequest("exec", r.WantReply, payload)
	if err != nil {
		_ = r.Reply(false, nil)
		return false
	}
	_ = r.Reply(ok, nil)
	return true
}

// principalKey is what a per-principal bound counts by: the principal
// entry when one matched, otherwise the login. A session with neither is
// counted under the empty name, which is one bucket for everybody --
// which is what max_sessions already is.
func (se *session) principalKey() string {
	if se.principal != "" {
		return se.principal
	}
	return textsafe.Clip64(se.user)
}

// admitPrincipal takes a slot for one principal, returning the release
// to run when the session ends. It reports false when the principal is
// already at max_sessions_per_principal.
func (t *server) admitPrincipal(key string) (func(), bool) {
	max := t.h.MaxSessionsPerPrincipal
	if max <= 0 {
		return nil, true
	}
	t.principalMu.Lock()
	defer t.principalMu.Unlock()
	if t.perPrincipal[key] >= max {
		return nil, false
	}
	t.perPrincipal[key]++
	return func() {
		t.principalMu.Lock()
		defer t.principalMu.Unlock()
		if n := t.perPrincipal[key] - 1; n > 0 {
			t.perPrincipal[key] = n
			return
		}
		// The last session of a principal takes its entry with it, so
		// the table is the principals connected now rather than every
		// principal that ever connected.
		delete(t.perPrincipal, key)
	}, true
}
