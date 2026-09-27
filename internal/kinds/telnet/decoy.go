package telnet

import (
	"context"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/fakeshell"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/textsafe"
)

// A device that is not there.
//
// See internal/fakeshell for the shell itself and internal/deception for why any
// of this. What is specific to telnet is the arithmetic of the refusal.
//
// A telnet port on a public address is found within the hour, and what finds it
// is a dictionary: the Mirai family and everything after it walk a list of the
// credentials that shipped on recorders, cameras and routers, a few thousand
// pairs, tried a handful at a time from a great many addresses. Refusing collects
// the address, which every firewall log already has. Answering collects the
// *list* -- which pairs are in circulation this month, and whether any of them is
// one of yours -- and then, because the login is accepted, what the thing came to
// do: the busybox probe, the echo liveness check, and the wget that names the
// payload and the address serving it.
//
// The refusal this replaces on a real listener is the one after the proxy has
// spoken: a failed second factor, the estate's authorisation policy, a missing
// grant. It does not replace allow_clients or a ban -- an address that may not
// connect gets nothing, which is what the list means -- and it never replaces an
// outage, because an operator who cannot reach the equipment during an incident
// must not be handed a fabricated device instead.

// maxDecoyCommands bounds one visitor's session. The listener's idle and session
// timeouts already bound the time; this bounds the work, so that a script in a
// loop cannot hold a worker on a listener that exists to be found.
const maxDecoyCommands = 500

// fabricatedTarget is what the logs and the recording name instead of a machine,
// because there is no machine.
const fabricatedTarget = "(fabricated)"

// decoy is the fabricated device.
type decoy struct {
	// whole says the listener is a honeypot: there is no equipment behind it.
	whole bool
	sh    *fakeshell.Shell
}

// newDecoy compiles the fabrication, or nil where the section is absent or off.
func newDecoy(c *config.TelnetDeception, name string) (*decoy, error) {
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
	sh, err := fakeshell.New(fakeshell.Options{
		Profile: c.Profile, Hostname: c.Hostname, Attempts: c.Attempts,
		Tripwire: c.Tripwire, Clients: prefixes, Seed: c.Seed, Name: name,
		Period: c.Period.D(), MaxClients: c.MaxClients,
	})
	if err != nil {
		return nil, err
	}
	return &decoy{whole: c.Mode == "decoy", sh: sh}, nil
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
		Listener: t.cfg.Name, Kind: "telnet", Mode: decoyMode(d.whole),
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

// serveDecoy runs a session against the fabrication, and returns the reason for
// the access log.
//
// It is reached only where the session was never going to reach the equipment: a
// listener with none behind it, or a refusal already decided. That is the
// invariant the whole feature rests on, and it is a test rather than a comment.
func (t *server) serveDecoy(se *session, why string) string {
	d := t.decoy
	se.target = fabricatedTarget
	t.recordDeception(se, why, "", false)
	if reason := se.fabricatedLogin(); reason != "" {
		return reason
	}
	// After the login, because the recording is named after the visitor and the
	// name is what the login just produced. The credential exchange is not in
	// the file either way -- the prompts are written with say, which does not
	// record -- and that is the rule every kind here follows: a transcript is
	// an artefact, and no password reaches one.
	se.openRecording()
	sh := d.sh.Open(se.user)
	se.say(d.sh.MOTD())
	se.recordOutput([]byte(d.sh.MOTD()))
	for n := 0; n < maxDecoyCommands; n++ {
		line, reason := se.prompt(sh.Prompt(), true)
		if reason != "" {
			return reason
		}
		tripped := sh.Tripped(line)
		t.recordDeception(se, "command", line, tripped)
		out, closed := sh.Run(line)
		se.recordInput([]byte(line + "\r\n"))
		se.say(out)
		se.recordOutput([]byte(out))
		if closed {
			return "deceived"
		}
	}
	// The bound, reached: a script in a loop. It is not an error and not a
	// refusal -- what was worth collecting has been collected several hundred
	// commands ago.
	return "deceived_bounded"
}

// fabricatedLogin runs the login exchange and records what it was offered.
//
// Every credential is accepted once the configured number of attempts has been
// taken, and which credential it was makes no difference to what happens next: a
// login that accepted the right password and refused the wrong one would be a
// credential oracle, which is the one thing a password list needs.
func (se *session) fabricatedLogin() string {
	t := se.t
	d := t.decoy
	se.say(d.sh.Banner())
	attempts := d.sh.Attempts()
	for i := 0; i < attempts; i++ {
		name, reason := se.prompt(d.sh.LoginPrompt(), true)
		if reason != "" {
			return reason
		}
		pass, reason := se.prompt(d.sh.PasswordPrompt(), false)
		if reason != "" {
			return reason
		}
		cred := d.sh.Take(name, pass)
		t.recordCredential(se, cred, i+1 == attempts)
		if i+1 < attempts {
			se.say(d.sh.Refusal())
			continue
		}
		se.user = cred.User
	}
	if se.live != nil {
		se.live.Annotate(se.user, "", "")
	}
	return ""
}

// recordCredential notes one login attempt where an operator looks.
//
// The user name, the credential's length and a correlation handle. Not the
// credential: fakeshell.Take has already reduced it to something no reader of
// this log can test a guess against.
func (t *server) recordCredential(se *session, cred fakeshell.Credential, accepted bool) {
	t.engine.Counters().TelnetDeceived.Add(1)
	outcome := "refused"
	if accepted {
		outcome = "accepted"
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deceive", "telnet_credential",
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "mode", decoyMode(t.decoy.whole),
		"db_user", cred.User, "credential_len", cred.Length, "credential_id", cred.ID,
		"outcome", outcome)
}

// recordDeception notes one fabricated exchange.
func (t *server) recordDeception(se *session, why, detail string, tripped bool) {
	d := t.decoy
	d.sh.Policy().Record(se.ip, tripped, time.Now())
	t.engine.Counters().TelnetDeceived.Add(1)
	event := "telnet_deceived"
	if tripped {
		t.engine.Counters().TelnetTripwire.Add(1)
		event = "telnet_tripwire"
		// The tripwire feeds the ban ladder, and the ordinary fabricated
		// exchange does not. A client that typed `wget` into a machine that is
		// not there has said something about itself that every other listener
		// on this proxy would want to act on; one that was merely answered has
		// said only that it connected, and banning it would end the collection
		// that was about to say more.
		if bl := t.engine.Bans(); bl != nil && se.ip.IsValid() {
			bl.Observe(se.ip, "telnet_tripwire")
		}
	}
	attrs := []any{
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "reason", why,
		"mode", decoyMode(d.whole),
	}
	if se.user != "" {
		attrs = append(attrs, "user", textsafe.Clip64(se.user))
	}
	if detail != "" {
		attrs = append(attrs, "command", textsafe.Clip256(oneLine(detail)))
	}
	t.engine.Logs().SecurityEvent(context.Background(), "deceive", event, attrs...)
}

// oneLine reduces a command to one log field. A pasted payload carries newlines,
// and a record built out of them would be several records.
func oneLine(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\r' || r == '\n' || r == 0 {
			r = ' '
		}
		out = append(out, r)
	}
	return string(out)
}

// deceive answers a refused session as the fabricated device, and reports whether
// it did. It is called only where the refusal has already been decided.
func (se *session) deceive(start time.Time, why string) bool {
	t := se.t
	d := t.decoy
	// No d.whole here, and it would be redundant: a listener with nothing
	// behind it has already answered in handle for every client it admits, so
	// the only way one reaches this is a client the section does not cover --
	// which the next clause refuses anyway.
	if d == nil || !d.admits(se.ip) {
		return false
	}
	t.log(se, start, t.serveDecoy(se, why))
	return true
}
