package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/fakeshell"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/textsafe"
)

// addrOfConn is the client's address, which is all a connection has said about
// itself at the point the authentication callbacks run.
func addrOfConn(c cssh.ConnMetadata) netip.Addr {
	return netutil.AddrOf(c.RemoteAddr().String())
}

// A bastion that is not there.
//
// See internal/fakeshell for the shell and internal/deception for why. What is
// specific to SSH is that port 22 is the most attacked port on the internet and
// the traffic is not one thing: a dictionary walking root and admin and oracle, a
// list of stolen keys being tried against everything, and -- the reason this
// listener is worth fabricating rather than only refusing -- somebody who already
// has a credential and is looking for the machine it opens.
//
// A refusal tells all three the same thing. The first learns the address is alive,
// which it knew. The second learns that key is not this one, which narrows their
// search. The third learns to try the next bastion. Answering tells you which of
// the three you are looking at, and then what they do with a shell.
//
// Three things are deliberate and all three are refusals rather than answers.
//
// **It forwards nothing.** A `direct-tcpip` channel on a fabricated bastion is a
// client asking to use this proxy as an open relay, and granting one would put
// this estate's address on somebody else's credential stuffing. It is refused and
// raises the tripwire, which is the one channel type where the refusal is the
// interesting event.
//
// **It runs nothing.** An `exec` request is answered from the same command table
// an interactive session uses, with an exit status, and the shell runs nothing --
// see internal/fakeshell for what that means for `wget`.
//
// **It adds no authentication method the listener did not already offer.** In
// mode answer the fabrication wraps the callbacks that exist; it does not install
// a password callback on a key-only bastion. A listener that advertised passwords
// because a deception section was added would have had its front door changed by a
// logging feature, which is not a trade anybody agreed to. A bastion that only
// takes keys therefore collects key fingerprints here, and mode decoy is how an
// estate collects passwords on purpose.

// maxDecoyCommands bounds one visitor's shell. The listener's own timeouts bound
// the time; this bounds the work.
const maxDecoyCommands = 500

// maxDecoyTries bounds the table of per-connection attempt counts, which is keyed
// by a session identifier the client's own handshake produces.
const maxDecoyTries = 4096

// permDeceived marks a session the fabrication answered. It rides in the
// Permissions extensions because that is the only thing the crypto library carries
// from the authentication into the connection.
const permDeceived = "xproxy-deceived"

// decoy is the fabricated bastion.
type decoy struct {
	// whole says the listener is a honeypot: there is no machine behind it.
	whole bool
	sh    *fakeshell.Shell

	// mu guards tries, which counts the credentials one connection has
	// offered so far. The key is the session identifier from the transport
	// handshake, which is unique per connection and not chosen by the client.
	mu    sync.Mutex
	tries map[string]int
}

// newDecoy compiles the fabrication, or nil where the section is absent or off.
func newDecoy(c *config.SSHDeception, name string) (*decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(c.Clients))
	for _, s := range c.Clients {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, pfx.Masked())
	}
	profile := c.Profile
	if profile == "" {
		// An SSH port fronts a server, so the small-server profile is the
		// default here. The telnet trap's default is the recorder, because a
		// recorder is what is actually on port 23.
		profile = "linux"
	}
	sh, err := fakeshell.New(fakeshell.Options{
		Profile: profile, Hostname: c.Hostname, Attempts: c.Attempts,
		Tripwire: c.Tripwire, Clients: prefixes, Seed: c.Seed, Name: name,
		Period: c.Period.D(), MaxClients: c.MaxClients,
	})
	if err != nil {
		return nil, err
	}
	return &decoy{whole: c.Mode == "decoy", sh: sh, tries: map[string]int{}}, nil
}

// admits says whether this client gets the fabrication.
func (d *decoy) admits(ip netip.Addr) bool { return d != nil && d.sh.Admits(ip) }

func decoyMode(whole bool) string {
	if whole {
		return "decoy"
	}
	return "answer"
}

// DecoyStatus implements proxy.Decoy: what this listener's fabrication has seen.
func (t *server) DecoyStatus() (proxy.DecoyStatus, bool) {
	d := t.decoy
	if d == nil {
		return proxy.DecoyStatus{}, false
	}
	pol := d.sh.Policy()
	st := proxy.DecoyStatus{
		Listener: t.cfg.Name, Kind: "ssh", Mode: decoyMode(d.whole),
		Profile: d.sh.Profile(), Served: pol.Served(), Tripped: pol.Tripped(),
		Anyone: pol.Anyone(),
	}
	for _, c := range pol.Clients(32) {
		st.Visitors = append(st.Visitors, proxy.DecoyVisitor{
			ClientIP: c.Addr.String(), FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
			Frames: c.Frames, Tripped: c.Tripped,
		})
	}
	return st, true
}

// takes counts the credentials this connection has offered and says whether this
// one is the last: the login is accepted then, and never on which credential it
// was.
func (d *decoy) takes(sessionID []byte) bool {
	want := d.sh.Attempts()
	if want <= 1 {
		return true
	}
	key := string(sessionID)
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.tries) >= maxDecoyTries {
		// The table is full, which means a great many connections are part way
		// through a login. Accepting is the safe direction: it collects one
		// credential rather than none, and it cannot refuse anybody.
		return true
	}
	d.tries[key]++
	if d.tries[key] >= want {
		delete(d.tries, key)
		return true
	}
	return false
}

// forget drops a connection's attempt count once its handshake is over, so the
// table holds only logins in progress.
func (d *decoy) forget(sessionID []byte) {
	d.mu.Lock()
	delete(d.tries, string(sessionID))
	d.mu.Unlock()
}

// installDecoyAuth is the authentication of a listener that is nothing but a
// fabrication: every credential is taken and recorded, and the login is accepted
// once enough have been.
//
// Public keys are refused rather than accepted. A client that offered one and was
// let in would have proved only that it holds a key, and would then be in without
// having said a password -- and the password is what a trap on port 22 is for. The
// fingerprint is recorded, because a key being tried against an estate is worth
// knowing about, and the client falls back to a password as it would against a
// server that takes no keys.
func (t *server) installDecoyAuth(cfg *cssh.ServerConfig) {
	d := t.decoy
	cfg.NoClientAuth = false
	cfg.PublicKeyCallback = func(c cssh.ConnMetadata, key cssh.PublicKey) (*cssh.Permissions, error) {
		if !d.admits(addrOfConn(c)) {
			return nil, errors.New("authentication failed")
		}
		t.recordKey(c, key)
		return nil, errors.New("authentication failed")
	}
	cfg.PasswordCallback = func(c cssh.ConnMetadata, pass []byte) (*cssh.Permissions, error) {
		// A client the section does not cover gets the refusal a bastion with
		// no account for them gets. The clients list means the same thing here
		// as everywhere else: who the fabrication is for.
		if !d.admits(addrOfConn(c)) {
			return nil, errors.New("authentication failed")
		}
		accepted := d.takes(c.SessionID())
		t.recordCredential(c, "password", d.sh.Take(c.User(), string(pass)), accepted)
		if !accepted {
			return nil, errors.New("authentication failed")
		}
		return &cssh.Permissions{Extensions: map[string]string{
			"auth": "password", permDeceived: "decoy",
		}}, nil
	}
	cfg.KeyboardInteractiveCallback = func(c cssh.ConnMetadata, challenge cssh.KeyboardInteractiveChallenge) (*cssh.Permissions, error) {
		if !d.admits(addrOfConn(c)) {
			return nil, errors.New("authentication failed")
		}
		answers, err := challenge("", "", []string{"Password: "}, []bool{false})
		if err != nil {
			return nil, err
		}
		pass := ""
		if len(answers) > 0 {
			pass = answers[0]
		}
		accepted := d.takes(c.SessionID())
		t.recordCredential(c, "keyboard-interactive", d.sh.Take(c.User(), pass), accepted)
		if !accepted {
			return nil, errors.New("authentication failed")
		}
		return &cssh.Permissions{Extensions: map[string]string{
			"auth": "keyboard-interactive", permDeceived: "decoy",
		}}, nil
	}
}

// wrapDecoyAuth is mode answer: the listener's own callbacks decide, and a
// credential they refuse gets the fabrication instead of a refusal.
//
// It wraps what is there and installs nothing. A listener that started
// advertising password authentication because a deception section was added would
// have had its front door changed by a logging feature.
func (t *server) wrapDecoyAuth(cfg *cssh.ServerConfig) {
	cb := cssh.ServerAuthCallbacks{
		PasswordCallback:            cfg.PasswordCallback,
		PublicKeyCallback:           cfg.PublicKeyCallback,
		KeyboardInteractiveCallback: cfg.KeyboardInteractiveCallback,
	}
	t.wrapDecoyCallbacks(&cb)
	cfg.PasswordCallback = cb.PasswordCallback
	cfg.PublicKeyCallback = cb.PublicKeyCallback
	cfg.KeyboardInteractiveCallback = cb.KeyboardInteractiveCallback
}

// wrapDecoyCallbacks wraps one round of authentication: whatever the listener
// offers in this round keeps deciding, and a credential it refuses gets the
// fabrication.
func (t *server) wrapDecoyCallbacks(cb *cssh.ServerAuthCallbacks) {
	if pw := cb.PasswordCallback; pw != nil {
		cb.PasswordCallback = func(c cssh.ConnMetadata, pass []byte) (*cssh.Permissions, error) {
			perm, err := pw(c, pass)
			if err == nil {
				return perm, err
			}
			if partial(err) {
				return perm, t.wrapNextFactor(err)
			}
			cred := t.decoy.sh.Take(c.User(), string(pass))
			return t.deceiveAuth(c, "password", err, func(accepted bool) {
				t.recordCredential(c, "password", cred, accepted)
			})
		}
	}
	if pk := cb.PublicKeyCallback; pk != nil {
		cb.PublicKeyCallback = func(c cssh.ConnMetadata, key cssh.PublicKey) (*cssh.Permissions, error) {
			perm, err := pk(c, key)
			if err == nil {
				return perm, err
			}
			if partial(err) {
				return perm, t.wrapNextFactor(err)
			}
			return t.deceiveAuth(c, "publickey", err, func(bool) { t.recordKey(c, key) })
		}
	}
	if ki := cb.KeyboardInteractiveCallback; ki != nil {
		cb.KeyboardInteractiveCallback = func(c cssh.ConnMetadata, ch cssh.KeyboardInteractiveChallenge) (*cssh.Permissions, error) {
			perm, err := ki(c, ch)
			if err == nil {
				return perm, err
			}
			if partial(err) {
				return perm, t.wrapNextFactor(err)
			}
			return t.deceiveAuth(c, "keyboard-interactive", err, func(bool) {})
		}
	}
}

// wrapNextFactor carries the wrapping into the round the protocol has asked for
// next.
//
// The second factor is where a bastion refuses most often, and it lives in the
// partial success rather than in the listener's own callbacks -- so without this
// the one refusal the section most wants to replace would be the one it never
// saw. The rule does not change on the way through: the credential that was
// right is still answered by the real bastion, and only the factor after it can
// be fabricated.
func (t *server) wrapNextFactor(err error) error {
	var ps *cssh.PartialSuccessError
	if !errors.As(err, &ps) {
		return err
	}
	next := ps.Next
	t.wrapDecoyCallbacks(&next)
	return &cssh.PartialSuccessError{Next: next}
}

// partial says an error is the protocol's partial success -- the first factor was
// right and another method comes next -- rather than a refusal. A fabrication that
// answered one would be answering a credential that was accepted.
func partial(err error) bool {
	var ps *cssh.PartialSuccessError
	return errors.As(err, &ps)
}

// deceiveAuth accepts a credential the listener refused, for the clients the
// section covers, and marks the session so it reaches the fabrication instead of
// a machine.
func (t *server) deceiveAuth(c cssh.ConnMetadata, method string, refused error, record func(accepted bool)) (*cssh.Permissions, error) {
	d := t.decoy
	ip := addrOfConn(c)
	if !d.admits(ip) {
		// Nothing is taken and nothing is recorded: a client the section does
		// not cover was refused by the listener and told so, which is an
		// ordinary refusal that the authentication log already carries. A
		// fabricated exchange it is not, and counting it as one would put
		// clients in the deception record that never saw the deception.
		return nil, refused
	}
	accepted := d.takes(c.SessionID())
	record(accepted)
	if !accepted {
		return nil, refused
	}
	// The refusal still happened, and the operator's counters still say so: the
	// fabrication replaces what the client is told, not what the estate is
	// told. AuthLogCallback will not see this attempt, because as far as the
	// protocol is concerned it succeeded.
	t.engine.Counters().SSHAuthFailed.Add(1)
	t.deny(ip, "auth_failed", method+" for "+textsafe.Clip64(c.User()))
	return &cssh.Permissions{Extensions: map[string]string{
		"auth": method, permDeceived: "auth_failed",
	}}, nil
}

// recordKey notes a public key that was offered and refused. The fingerprint is
// the whole record: a key being tried against an estate is worth knowing about,
// and the key itself is public.
func (t *server) recordKey(c cssh.ConnMetadata, key cssh.PublicKey) {
	t.engine.Counters().SSHDeceived.Add(1)
	t.engine.Logs().SecurityEvent(context.Background(), "deceive", "ssh_credential",
		"listener", t.cfg.Name, "client_ip", addrOfConn(c).String(),
		"mode", decoyMode(t.decoy.whole), "user", textsafe.Clip64(c.User()),
		"method", "publickey", "key_type", key.Type(),
		"fingerprint", cssh.FingerprintSHA256(key), "outcome", "refused")
}

// recordCredential notes one login attempt where an operator looks: the user
// name, the credential's length and a correlation handle. Not the credential --
// fakeshell.Take has already reduced it to something no reader of this log can
// test a guess against.
func (t *server) recordCredential(c cssh.ConnMetadata, method string, cred fakeshell.Credential, accepted bool) {
	t.engine.Counters().SSHDeceived.Add(1)
	outcome := "refused"
	if accepted {
		outcome = "accepted"
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deceive", "ssh_credential",
		"listener", t.cfg.Name, "client_ip", addrOfConn(c).String(),
		"mode", decoyMode(t.decoy.whole), "user", cred.User, "method", method,
		"credential_len", cred.Length, "credential_id", cred.ID,
		"client_version", textsafe.Clip64(string(c.ClientVersion())),
		"outcome", outcome)
}

// recordDeception notes one fabricated exchange.
func (t *server) recordDeception(se *session, why, detail string, tripped bool) {
	d := t.decoy
	d.sh.Policy().Record(se.ip, tripped, time.Now())
	t.engine.Counters().SSHDeceived.Add(1)
	event := "ssh_deceived"
	if tripped {
		t.engine.Counters().SSHTripwire.Add(1)
		event = "ssh_tripwire"
		// The tripwire feeds the ban ladder and the ordinary fabricated
		// exchange does not: a client that typed wget into a bastion that is
		// not there, or asked it to forward a connection, has said something
		// every other listener would want to act on.
		if bl := t.engine.Bans(); bl != nil && se.ip.IsValid() {
			bl.Observe(se.ip, "ssh_tripwire")
		}
	}
	attrs := []any{
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "reason", why,
		"mode", decoyMode(d.whole), "user", textsafe.Clip64(se.user),
	}
	if detail != "" {
		attrs = append(attrs, "command", textsafe.Clip256(oneLine(detail)))
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deceive", event, attrs...)
}

// oneLine reduces a command to one log field, because a pasted payload carries
// newlines and a record built out of them would be several records.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, s)
}

// serveDecoy runs a connection against the fabrication and returns the reason for
// the access log.
//
// Nothing is dialled: that is the invariant this rests on, and it is a test rather
// than a comment. A session that reaches here was either never going to reach a
// machine (a refused credential) or has no machine to reach (a decoy listener).
func (t *server) serveDecoy(se *session, chans <-chan cssh.NewChannel, reqs <-chan *cssh.Request) string {
	se.target = fabricatedTarget
	t.recordDeception(se, se.deceived, "", false)
	// Global requests, which on a fabrication are all refused. tcpip-forward is
	// a client asking this listener to open a port on its behalf, which is the
	// same open-relay request as direct-tcpip from the other direction.
	go func() {
		for r := range reqs {
			if r.Type == "tcpip-forward" || r.Type == "streamlocal-forward@openssh.com" {
				t.recordDeception(se, "forward_refused", r.Type, true)
			}
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	for nc := range chans {
		if se.channels.Load() >= int64(t.h.MaxChannels) {
			_ = nc.Reject(cssh.ResourceShortage, "too many channels")
			se.refused.Add(1)
			continue
		}
		se.channels.Add(1)
		se.wg.Add(1)
		go func(nc cssh.NewChannel) {
			defer se.wg.Done()
			defer se.channels.Add(-1)
			defer safe.Guard("ssh fabricated channel")
			t.decoyChannel(se, nc)
		}(nc)
	}
	se.wg.Wait()
	return "deceived"
}

// decoyChannel answers one channel.
func (t *server) decoyChannel(se *session, nc cssh.NewChannel) {
	kind := nc.ChannelType()
	if kind != "session" {
		// A fabrication forwards nothing. direct-tcpip is a client asking to
		// use this proxy as a relay, and granting one would put this estate's
		// address on somebody else's work -- so it is refused, and the refusal
		// is the interesting event rather than an inconvenience.
		t.recordDeception(se, "channel_refused", kind, kind == "direct-tcpip" || kind == "x11")
		se.refused.Add(1)
		_ = nc.Reject(cssh.Prohibited, "administratively prohibited")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	se.opened.Add(1)
	t.engine.Counters().SSHChannels.Add(1)
	st := &sshChannel{cols: 80, rows: 24}
	defer func() {
		if st.rec != nil {
			st.rec.Close()
		}
	}()
	for r := range reqs {
		switch r.Type {
		case "pty-req":
			st.term, st.cols, st.rows = parsePTY(r.Payload)
			t.reply(r, true)
		case "window-change":
			if c, rows, ok := parseWindow(r.Payload); ok {
				st.cols, st.rows = c, rows
			}
			t.reply(r, true)
		case "env":
			// Accepted and recorded: the variables a payload sets on its way in
			// are as much a part of what it is doing as the command.
			t.recordDeception(se, "env", envPair(r.Payload), false)
			t.reply(r, true)
		case "shell":
			t.reply(r, true)
			t.decoyShell(se, ch, st)
			return
		case "exec":
			cmd := sshStringPayload(r.Payload)
			t.reply(r, true)
			t.decoyExec(se, ch, st, cmd)
			return
		case "subsystem":
			// sftp, which is how a payload is uploaded rather than fetched.
			// There is no fabricated file system to put it in, so the request
			// is refused -- and a visitor asking for one is escalating.
			t.recordDeception(se, "subsystem_refused", sshStringPayload(r.Payload), true)
			t.reply(r, false)
		case "signal", "keepalive@openssh.com":
			t.reply(r, false)
		default:
			t.recordDeception(se, "request_refused", r.Type, false)
			t.reply(r, false)
		}
	}
}

func (t *server) reply(r *cssh.Request, ok bool) {
	if r.WantReply {
		_ = r.Reply(ok, nil)
	}
}

// decoyShell runs the interactive fabrication over a channel.
func (t *server) decoyShell(se *session, ch cssh.Channel, st *sshChannel) {
	sh := t.decoy.sh.Open(se.user)
	rec := t.openDecoyRecording(se, st, "")
	write := func(s string) bool {
		if s == "" {
			return true
		}
		if rec != nil {
			rec.Out([]byte(s))
		}
		_, err := ch.Write([]byte(s))
		return err == nil
	}
	if !write(t.decoy.sh.MOTD()) {
		return
	}
	in := newLineReader(ch)
	for n := 0; n < maxDecoyCommands; n++ {
		if !write(sh.Prompt()) {
			return
		}
		line, ok := in.line(write)
		if !ok {
			return
		}
		tripped := sh.Tripped(line)
		t.recordDeception(se, "command", line, tripped)
		if rec != nil {
			rec.In([]byte(line + "\r\n"))
		}
		out, closed := sh.Run(line)
		if !write(out) || closed {
			return
		}
	}
	// The bound, reached: a script in a loop. What was worth collecting was
	// collected several hundred commands ago.
	write("\r\n")
}

// decoyExec answers one command and ends the channel, which is the shape an
// automated payload takes: ssh host 'wget ...; chmod +x ...; ./x'.
func (t *server) decoyExec(se *session, ch cssh.Channel, st *sshChannel, cmd string) {
	sh := t.decoy.sh.Open(se.user)
	tripped := sh.Tripped(cmd)
	t.recordDeception(se, "exec", cmd, tripped)
	rec := t.openDecoyRecording(se, st, cmd)
	out, _ := sh.Run(cmd)
	if rec != nil {
		rec.In([]byte(cmd + "\r\n"))
		rec.Out([]byte(out))
	}
	_, _ = ch.Write([]byte(out))
	// The exit status, because a client that ran a command and was told nothing
	// reports that the connection broke rather than that the command finished.
	// Zero, because every command the fabrication answers it answers -- and one
	// that failed says so in its output, as the real one does.
	var status [4]byte
	_, _ = ch.SendRequest("exit-status", false, status[:])
	_ = ch.CloseWrite()
}

// openDecoyRecording opens the transcript, where the listener's policy asks for
// one. The credential exchange is not in it: it happened in the authentication,
// which this file reduced to a length and a handle before the channel existed.
func (t *server) openDecoyRecording(se *session, st *sshChannel, command string) *sessionrec.Recording {
	p := se.policy.recorder
	if p == nil {
		return nil
	}
	f, err := openSSHRecording(p, se, st.cols, st.rows, st.term, command)
	if err != nil {
		se.sshRecordFailed(err)
		return nil
	}
	st.rec = f
	return f
}

// lineReader reads commands from a channel, echoing as a server with a pty does.
//
// It is a line reader rather than a terminal: enough to take a command, a
// backspace and an interrupt, and nothing that would make it worth sending escape
// sequences at.
//
// It keeps what arrived past the end of a line, because a payload is pasted or
// piped in one write -- `ssh host < script` is one read here -- and a reader that
// dropped the rest of the buffer would collect the first line of it and lose
// every line after, which is the part worth having.
type lineReader struct {
	ch cssh.Channel
	// buf is where a read lands; pending is the part of it not yet consumed,
	// which is why the next read only happens once pending is empty.
	buf     []byte
	pending []byte
	err     error
}

func newLineReader(ch cssh.Channel) *lineReader {
	return &lineReader{ch: ch, buf: make([]byte, 64)}
}

// line returns one command and whether the session is still open.
func (r *lineReader) line(write func(string) bool) (string, bool) {
	var line []byte
	for {
		for len(r.pending) > 0 {
			c := r.pending[0]
			r.pending = r.pending[1:]
			switch c {
			case '\r', '\n':
				if !write("\r\n") {
					return "", false
				}
				return string(line), true
			case 0x7f, 0x08: // backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					if !write("\b \b") {
						return "", false
					}
				}
			case 0x03: // interrupt
				if !write("^C\r\n") {
					return "", false
				}
				return "", true
			case 0x04: // end of input
				return "", false
			default:
				if c < 0x20 || len(line) >= maxCommandLine {
					continue
				}
				line = append(line, c)
				if !write(string(rune(c))) {
					return "", false
				}
			}
		}
		if r.err != nil {
			return "", false
		}
		n, err := r.ch.Read(r.buf)
		r.pending, r.err = r.buf[:n], err
	}
}

// maxCommandLine bounds one command, because it comes off the network.
const maxCommandLine = 4096

// parsePTY reads a pty-req payload: the terminal name and the window size.
func parsePTY(b []byte) (term string, cols, rows int) {
	term, rest, ok := sshString(b)
	if !ok || len(rest) < 8 {
		return "", 80, 24
	}
	cols = int(binary.BigEndian.Uint32(rest[0:4]))
	rows = int(binary.BigEndian.Uint32(rest[4:8]))
	return textsafe.Clip64(term), bound(cols, 80), bound(rows, 24)
}

// parseWindow reads a window-change payload.
func parseWindow(b []byte) (cols, rows int, ok bool) {
	if len(b) < 8 {
		return 0, 0, false
	}
	return bound(int(binary.BigEndian.Uint32(b[0:4])), 80),
		bound(int(binary.BigEndian.Uint32(b[4:8])), 24), true
}

// bound keeps a client's window size inside what a terminal is, because the
// numbers come off the network and a recording is drawn from them.
func bound(v, def int) int {
	if v < 1 || v > 1000 {
		return def
	}
	return v
}

// envPair is what an env request set, for the record.
func envPair(b []byte) string {
	name, rest, ok := sshString(b)
	if !ok {
		return ""
	}
	value, _, _ := sshString(rest)
	return textsafe.Clip64(name) + "=" + textsafe.Clip64(value)
}

// fabricatedTarget is what the log and the recording name instead of a machine,
// because there is no machine.
const fabricatedTarget = "(fabricated)"
