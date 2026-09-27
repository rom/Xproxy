package ssh

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/sessionrec"
)

// sshPolicy is the compiled form of a listener's policy, or of a
// principal's override of it.
//
// listener's policy, or of a principal's override of it.
type sshPolicy struct {
	upstreamUser string
	channels     map[string]bool
	requests     map[string]bool
	subsystems   map[string]bool
	commands     []*regexp.Regexp
	// rules are the structured command rules, nil when the policy has
	// none and every command is held to the patterns above instead.
	rules         *cmdRules
	env           []string
	forwards      []sshForward
	remoteForward bool
	sftp          *sftpPolicy
	// recorder writes what a session shows, when one is configured.
	recorder *sessionrec.Policy
	// transfers reports whether exec may run a file transfer helper.
	transfers bool
}

// sshPrincipal is one entry of the principals list: who it covers and
// what they may do.
type sshPrincipal struct {
	name         string
	fingerprints map[string]bool
	certs        map[string]bool
	users        map[string]bool
	isDefault    bool
	deny         bool
	policy       *sshPolicy
	// hardware is this principal's own answer to whether the key has to be
	// held in a token: nil takes the listener's.
	hardware *bool
}

// compileSSHPolicy builds a policy. base is what an unset field falls
// back to, or nil for the listener's own policy, where unset means
// empty.
func compileSSHPolicy(c *config.SSHPolicy, base *sshPolicy, secrets *keysource.Resolver) (*sshPolicy, error) {
	p := &sshPolicy{
		channels:   map[string]bool{},
		requests:   map[string]bool{},
		subsystems: map[string]bool{},
	}
	set := func(dst map[string]bool, list []string, fallback map[string]bool) {
		if len(list) == 0 && base != nil {
			for k, v := range fallback {
				dst[k] = v
			}
			return
		}
		for _, s := range list {
			dst[s] = true
		}
	}
	var baseChans, baseReqs, baseSubs map[string]bool
	if base != nil {
		baseChans, baseReqs, baseSubs = base.channels, base.requests, base.subsystems
	}
	set(p.channels, c.AllowChannels, baseChans)
	set(p.requests, c.AllowRequests, baseReqs)
	set(p.subsystems, c.AllowSubsystems, baseSubs)

	switch {
	case len(c.AllowCommands) > 0:
		for _, re := range c.AllowCommands {
			r, err := regexp.Compile(re)
			if err != nil {
				return nil, fmt.Errorf("allow_commands: %w", err)
			}
			p.commands = append(p.commands, r)
		}
	case base != nil:
		p.commands = base.commands
	}

	switch {
	case len(c.CommandRules) > 0:
		rs, err := compileCmdRules(c.CommandRules)
		if err != nil {
			return nil, err
		}
		p.rules = rs
	case base != nil:
		p.rules = base.rules
	}

	switch {
	case len(c.Forward) > 0:
		for _, d := range c.Forward {
			f, err := parseSSHForward(d)
			if err != nil {
				return nil, fmt.Errorf("forward %q: %w", d, err)
			}
			p.forwards = append(p.forwards, f)
		}
	case base != nil:
		p.forwards = base.forwards
	}

	switch {
	case len(c.AllowEnv) > 0:
		p.env = append([]string(nil), c.AllowEnv...)
	case base != nil:
		p.env = base.env
	}

	switch {
	case c.UpstreamUser != "":
		p.upstreamUser = c.UpstreamUser
	case base != nil:
		p.upstreamUser = base.upstreamUser
	}

	switch {
	case c.RemoteForward != nil:
		p.remoteForward = *c.RemoteForward
	case base != nil:
		p.remoteForward = base.remoteForward
	}

	switch {
	case c.SFTP != nil:
		sp, err := newSFTPPolicy(c.SFTP)
		if err != nil {
			return nil, err
		}
		p.sftp = sp
	case base != nil:
		p.sftp = base.sftp
	}

	switch {
	case c.Recording != nil:
		p.recorder = newSSHRecorder(c.Recording, secrets)
	case base != nil:
		p.recorder = base.recorder
	}

	if base != nil {
		p.transfers = base.transfers
		// A principal that brings its own sftp policy to a listener
		// that had none gets the same default the listener would have:
		// scp and rsync never open the subsystem, so leaving them on
		// would hand this principal the bypass its own policy exists
		// to close.
		if c.SFTP != nil && base.sftp == nil {
			p.transfers = false
		}
	}
	return p, nil
}

// envAllowed applies the environment policy. The denied list wins over
// every allow list: each of those variables is a way to run code before
// the command the policy approved, so "allow everything" must not be
// expressible by accident.
func (p *sshPolicy) envAllowed(name string) bool {
	if name == "" || strings.ContainsAny(name, "=\x00") {
		return false
	}
	for _, d := range config.SSHDeniedEnv {
		if envGlob(d, name) {
			return false
		}
	}
	for _, a := range p.env {
		if envGlob(a, name) {
			return true
		}
	}
	return false
}

// envGlob applies one pattern, which is a name or a prefix ending in
// "*", to one variable name.
func envGlob(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// sshEnvRequest is the payload of an env request: a name and a value.
func sshEnvRequest(payload []byte) (string, bool) {
	name, rest, ok := sshString(payload)
	if !ok {
		return "", false
	}
	if _, _, ok := sshString(rest); !ok {
		return "", false
	}
	return name, true
}

// fileTransferCommand reports whether an exec command runs a helper
// that moves files. It is the hole an sftp policy has without it: scp
// and rsync never touch the sftp subsystem, so every path and
// operation rule there is simply not on their path.
//
// Every word is read, not only the first, after shell quotes and escapes
// have been removed; the directory part is removed and a "VAR=value" prefix
// skipped. A wrapper is otherwise all it takes to walk past the check
// — "env scp -t", "sudo rsync", "sh -c 'scp -t /etc'" — and there is
// no reading of a shell word that would catch those from the first
// word alone. It refuses more than it must (a command whose argument
// merely says "scp"), which is the direction to be wrong in: a bastion
// that guesses permissively is a bastion with the door beside it.
func fileTransferCommand(cmd string) bool {
	normalized, ok := literalShellCommand(cmd)
	if !ok {
		// Expansions and shell operators can synthesize a command name in
		// ways that cannot be checked without running the target's shell.
		// When transfers are disabled, fail closed rather than pretending
		// to understand that shell.
		return true
	}
	for _, word := range strings.Fields(normalized) {
		// Skip VAR=value prefixes, which is how a shell is asked to run
		// something with an environment.
		if i := strings.IndexByte(word, '='); i > 0 && !strings.ContainsAny(word[:i], "/\\.") {
			continue
		}
		name := path.Base(strings.Trim(word, "'\"`;|&()"))
		if config.SSHFileTransferCommands[strings.TrimSuffix(name, ".exe")] {
			return true
		}
	}
	return false
}

// literalShellCommand removes quoting and backslash escaping from the
// literal subset of shell syntax. It rejects expansions and operators: their
// result depends on the upstream shell, environment and filesystem, so a
// proxy cannot safely decide whether they will produce a transfer helper.
func literalShellCommand(cmd string) (string, bool) {
	var out strings.Builder
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == '\x00':
			return "", false
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				out.WriteByte(c)
			}
		case c == '\'' || c == '"':
			switch quote {
			case 0:
				quote = c
			case c:
				quote = 0
			default:
				out.WriteByte(c)
			}
		case c == '\\':
			if i+1 == len(cmd) {
				return "", false
			}
			i++
			out.WriteByte(cmd[i])
		case strings.ContainsRune("$`;|&<>(){}[]*?!~", rune(c)):
			return "", false
		default:
			out.WriteByte(c)
		}
	}
	return out.String(), quote == 0
}

// principalFor picks the entry that covers a key, and the name to log
// it under. A certificate is matched by its principals, a plain key by
// its fingerprint. With no entries configured the listener's own policy
// applies to everyone.
func (t *server) principalFor(user string, key cssh.PublicKey) (*sshPrincipal, bool) {
	if len(t.principals) == 0 {
		return nil, true
	}
	fp := cssh.FingerprintSHA256(key)
	var certNames []string
	if cert, ok := key.(*cssh.Certificate); ok {
		certNames = cert.ValidPrincipals
		// A certificate is also a key; both are offered to the match.
		fp = cssh.FingerprintSHA256(cert.Key)
	}
	for _, pr := range t.principals {
		if len(pr.users) > 0 && !pr.users[user] {
			continue
		}
		switch {
		case pr.isDefault:
			return pr, true
		case pr.fingerprints[fp]:
			return pr, true
		}
		for _, n := range certNames {
			if pr.certs[n] {
				return pr, true
			}
		}
	}
	return nil, false
}

// acceptKey decides whether a key may authenticate at all, before any
// question of policy: it is in authorized_keys, or it is a certificate
// signed by a trusted user CA that is valid now and names the login the
// client is connecting as.
func (t *server) acceptKey(c cssh.ConnMetadata, key cssh.PublicKey) (string, certDecision, error) {
	var none certDecision
	cert, isCert := key.(*cssh.Certificate)
	if t.revoked[string(key.Marshal())] {
		return "", none, fmt.Errorf("the key offered for %q is revoked", c.User())
	}
	if !isCert {
		if t.keys[string(key.Marshal())] {
			return "publickey", none, nil
		}
		return "", none, fmt.Errorf("unknown public key for %q", c.User())
	}
	// A revocation covers the certificate's own key and the CA that
	// signed it, so one line takes back either a credential or every
	// credential an authority ever issued.
	if t.revoked[string(cert.Key.Marshal())] {
		return "", none, fmt.Errorf("the certificate offered for %q is revoked", c.User())
	}
	if cert.SignatureKey != nil && t.revoked[string(cert.SignatureKey.Marshal())] {
		return "", none, fmt.Errorf("the authority that signed the certificate for %q is revoked", c.User())
	}
	if len(t.caKeys) == 0 {
		return "", none, fmt.Errorf("a certificate was offered for %q and no user CA is configured", c.User())
	}
	checker := &cssh.CertChecker{
		IsUserAuthority: func(auth cssh.PublicKey) bool { return t.caKeys[string(auth.Marshal())] },
		// A critical option is critical: the CA meant it to be honoured
		// or the credential refused. CheckCert rejects any option not
		// named here, which is the behaviour to want -- an option this
		// gateway does not implement must not be quietly ignored -- so
		// the list is exactly what it does implement. source-address is
		// not in it because the library skips that one itself, leaving
		// it to the caller who has the client's address.
		SupportedCriticalOptions: []string{"force-command"},
	}
	// CheckCert verifies the signature, the validity window, that every
	// critical option is one it knows, and that the principal list covers
	// this login. What it deliberately leaves out is source-address,
	// which needs the client's address, and it says nothing about the
	// extensions -- so the rest is here.
	if err := checker.CheckCert(c.User(), cert); err != nil {
		return "", none, fmt.Errorf("certificate for %q: %w", c.User(), err)
	}
	d, err := t.checkCertificate(c, cert)
	if err != nil {
		return "", none, fmt.Errorf("certificate for %q: %w", c.User(), err)
	}
	return "certificate", d, nil
}
