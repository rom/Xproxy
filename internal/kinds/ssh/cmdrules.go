package ssh

import (
	"context"
	"fmt"
	"strings"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/sftp"
	"github.com/rom/xproxy/internal/sshcmd"
	"github.com/rom/xproxy/internal/textsafe"
)

// Structured command rules: what the file transfer families may do,
// decided on what their command line means rather than on how it is
// spelled.
//
// internal/sshcmd reads the line; this decides. The split matters,
// because the reading is checkable against the programs' own documented
// invocations while this is checkable against a configuration, and
// neither check is worth much when the two are the same function.
//
// The refusal labels below are counters and log events as well as
// decisions, so each one names a property of the command rather than a
// rule number: an operator reading `command_direction` knows a download
// was attempted where only uploads are allowed, without having to find
// which rule said so.
const (
	refuseSyntax    = "command_syntax"
	refuseNoRule    = "command_no_rule"
	refuseEnv       = "command_env"
	refuseServer    = "command_server"
	refuseDirection = "command_direction"
	refuseRecursive = "command_recursive"
	refuseDelete    = "command_delete"
	refusePath      = "command_path"
)

// cmdRule is one family's rule.
type cmdRule struct {
	kind      sshcmd.Kind
	upload    bool
	download  bool
	recursive bool
	deletes   bool
	paths     []string
	denyPaths []string
	sftp      bool
}

// cmdRules are a policy's rules, at most one per family.
type cmdRules struct{ byKind map[sshcmd.Kind]*cmdRule }

// cmdDecision is what the rules made of one command. matched false
// means no rule names this family, so the caller's other gates decide.
type cmdDecision struct {
	matched bool
	allow   bool
	reason  string
	detail  string
	// sftp asks the caller to relay this exec through the sftp policy,
	// which is what makes allowing the sftp server binary safe.
	sftp bool
}

// families maps a configured name to the kind the parser reports.
var families = map[string]sshcmd.Kind{
	"scp": sshcmd.KindSCP, "rsync": sshcmd.KindRsync,
	"sftp_server": sshcmd.KindSFTPServer, "git": sshcmd.KindGit,
}

// compileCmdRules builds the rules of one policy.
func compileCmdRules(list []config.SSHCommandRule) (*cmdRules, error) {
	if len(list) == 0 {
		return nil, nil
	}
	rs := &cmdRules{byKind: map[sshcmd.Kind]*cmdRule{}}
	for _, c := range list {
		kind, ok := families[c.Command]
		if !ok {
			return nil, fmt.Errorf("command_rules: %q is not a command family", c.Command)
		}
		if _, dup := rs.byKind[kind]; dup {
			return nil, fmt.Errorf("command_rules: %q appears twice", c.Command)
		}
		r := &cmdRule{kind: kind, recursive: c.Recursive, deletes: c.Delete,
			paths: c.Paths, denyPaths: c.DenyPaths, sftp: c.EnforceSFTPPolicy}
		for _, d := range c.Directions {
			switch strings.ToLower(d) {
			case string(sshcmd.Upload):
				r.upload = true
			case string(sshcmd.Download):
				r.download = true
			default:
				return nil, fmt.Errorf("command_rules: %q is not a direction", d)
			}
		}
		rs.byKind[kind] = r
	}
	return rs, nil
}

// decide applies the rules to one parsed command.
func (rs *cmdRules) decide(c *sshcmd.Command) cmdDecision {
	if rs == nil || c == nil {
		return cmdDecision{}
	}
	if c.Kind == sshcmd.KindOther {
		// Wrappers are deliberately not parsed as the family they carry:
		// allowing an "env scp" line under an scp rule would pretend we
		// had inspected env's semantics. They must not, however, fall
		// through to the older and possibly permissive command gates. Use
		// the shell-normalized words so spellings such as s''cp cannot hide
		// a transfer helper from this conservative check.
		for _, word := range c.Words {
			if looksLikeTransfer(word.Text) {
				return cmdDecision{matched: true, reason: refuseNoRule, detail: c.Name}
			}
		}
		return cmdDecision{}
	}
	r := rs.byKind[c.Kind]
	if r == nil {
		// A family this gateway can read, with no rule for it, while
		// other families have one: the operator has said which
		// transfers are intended, and this is not one of them.
		return cmdDecision{matched: true, reason: refuseNoRule, detail: string(c.Kind)}
	}
	if len(c.Env) > 0 {
		// VAR=value in front of a transfer command is a way to change
		// what the command does, and the env policy this gateway
		// applies covers the env *requests*, not a shell assignment.
		return cmdDecision{matched: true, reason: refuseEnv, detail: c.Env[0]}
	}
	switch c.Kind {
	case sshcmd.KindSCP:
		return r.decideSCP(c.SCP)
	case sshcmd.KindRsync:
		return r.decideRsync(c.Rsync)
	case sshcmd.KindGit:
		return r.decideGit(c.Git)
	case sshcmd.KindSFTPServer:
		// The direction is the sftp policy's to decide -- read_only is
		// where it is said -- so the rule's own question is only
		// whether the exec may run at all, and it may only run
		// inspected.
		return cmdDecision{matched: true, allow: true, sftp: r.sftp}
	}
	return cmdDecision{}
}

func (r *cmdRule) decideSCP(s *sshcmd.SCP) cmdDecision {
	if s.Direction == sshcmd.Neither {
		// Neither -t nor -f: not the far side of a client's copy but an
		// scp doing something else on the target, which is a command
		// this cannot reason about.
		return cmdDecision{matched: true, reason: refuseServer, detail: "scp -" + s.Flags}
	}
	if d := r.direction(s.Direction); d != "" {
		return cmdDecision{matched: true, reason: refuseDirection, detail: d}
	}
	if s.Recursive && !r.recursive {
		return cmdDecision{matched: true, reason: refuseRecursive, detail: "scp -r"}
	}
	if reason, detail := r.checkPaths(s.Paths); reason != "" {
		return cmdDecision{matched: true, reason: reason, detail: detail}
	}
	return cmdDecision{matched: true, allow: true}
}

func (r *cmdRule) decideRsync(s *sshcmd.Rsync) cmdDecision {
	if !s.Server {
		// An rsync without --server is a client: it dials somewhere
		// from the target, and what it copies is not on this session.
		return cmdDecision{matched: true, reason: refuseServer, detail: "rsync without --server"}
	}
	if d := r.direction(s.Direction); d != "" {
		return cmdDecision{matched: true, reason: refuseDirection, detail: d}
	}
	if s.Deletes && !r.deletes {
		return cmdDecision{matched: true, reason: refuseDelete, detail: strings.Join(s.Options, " ")}
	}
	if reason, detail := r.checkPaths(s.Paths); reason != "" {
		return cmdDecision{matched: true, reason: reason, detail: detail}
	}
	return cmdDecision{matched: true, allow: true}
}

func (r *cmdRule) decideGit(g *sshcmd.Git) cmdDecision {
	if d := r.direction(g.Direction); d != "" {
		return cmdDecision{matched: true, reason: refuseDirection, detail: g.Verb + " (" + d + ")"}
	}
	if reason, detail := r.checkPaths([]sshcmd.Word{g.Path}); reason != "" {
		return cmdDecision{matched: true, reason: reason, detail: detail}
	}
	return cmdDecision{matched: true, allow: true}
}

// direction reports the refusal detail when a direction is not allowed,
// or empty when it is.
func (r *cmdRule) direction(d sshcmd.Direction) string {
	switch d {
	case sshcmd.Upload:
		if !r.upload {
			return "upload"
		}
	case sshcmd.Download:
		if !r.download {
			return "download"
		}
	}
	return ""
}

// checkPaths applies the path lists to every path a command names.
//
// A path is resolved before it is judged, because "/srv/incoming/../..
// /etc/ssh" is a path inside /srv/incoming to a pattern and a path in
// /etc to the target. One that climbs above its own root is refused
// outright: what it means depends on the working directory the command
// will run in, which this gateway cannot see.
func (r *cmdRule) checkPaths(paths []sshcmd.Word) (string, string) {
	for _, w := range paths {
		// rsync's own "." argument is the protocol's, not a path in the
		// file system: the transfer root is the argument after it.
		if w.Text == "." || w.Text == "" {
			continue
		}
		clean, ok := sftp.CleanPath(w.Text)
		if !ok {
			return refusePath, "relative to a root this gateway cannot see: " + w.Text
		}
		if w.Glob {
			// A glob is the target shell's to expand, so the only
			// honest check is whether every name it could produce is
			// inside an allowed directory. A deny list makes even that
			// impossible: a pattern cannot be proven not to match one
			// of its entries.
			if reason, detail := r.checkGlob(clean); reason != "" {
				return reason, detail
			}
			continue
		}
		for _, d := range r.denyPaths {
			if sftp.MatchPath(d, clean) {
				return refusePath, "denied: " + clean
			}
		}
		if len(r.paths) == 0 {
			continue
		}
		allowed := false
		for _, a := range r.paths {
			if sftp.MatchPath(a, clean) {
				allowed = true
				break
			}
		}
		if !allowed {
			return refusePath, "outside the allowed paths: " + clean
		}
	}
	return "", ""
}

// checkGlob admits a pattern only when the directory it expands inside
// is covered by an allow pattern that covers everything below it. A
// shell's * does not cross a slash, so every name the pattern can
// produce is in that directory.
func (r *cmdRule) checkGlob(clean string) (string, string) {
	if len(r.denyPaths) > 0 {
		return refusePath, "a glob cannot be proven clear of deny_paths: " + clean
	}
	if len(r.paths) == 0 {
		return "", ""
	}
	dir := clean
	if i := strings.IndexAny(clean, "*?[]~"); i >= 0 {
		dir = clean[:i]
		if j := strings.LastIndexByte(dir, '/'); j >= 0 {
			dir = dir[:j]
		}
	}
	if dir == "" {
		dir = "/"
	}
	for _, a := range r.paths {
		// Only a pattern that covers a whole subtree can cover names
		// this gateway has not seen.
		if (strings.HasSuffix(a, "/**") || strings.HasSuffix(a, "/") || a == "/" || a == "**") &&
			sftp.MatchPath(a, dir) {
			return "", ""
		}
	}
	return refusePath, "a glob outside a subtree the rule allows: " + clean
}

// cmdOutcome is what the structured rules made of an exec request.
type cmdOutcome int

const (
	// cmdFallThrough: no rule covers this command, so the gates that
	// were there before rules existed decide it.
	cmdFallThrough cmdOutcome = iota
	// cmdAllowed: a rule allows it, and the rule is the decision.
	cmdAllowed
	// cmdAnswered: the request has been answered and the session goes
	// on.
	cmdAnswered
	// cmdStop: the request has been answered and this channel's request
	// loop is finished, because the channel now carries sftp or the
	// upstream refused.
	cmdStop
)

// structuredCommand applies the structured rules to an exec command.
//
// It runs after the shell syntax gate and before the blanket file
// transfer refusal, which is the order the three mean something in: a
// line that cannot be read as one simple command is refused whatever
// the rules say, and a rule is what turns "no scp at all" into "scp,
// into this directory, one way". A family with no rule of its own is
// refused here rather than falling through, so adding a rule for scp
// does not quietly leave rsync to the patterns.
func (se *session) structuredCommand(clientCh, upCh cssh.Channel, r *cssh.Request, cmd string) cmdOutcome {
	if se.policy.rules == nil {
		return cmdFallThrough
	}
	parsed, err := sshcmd.Parse(cmd)
	if err != nil {
		// Only a line naming a family this gateway reads is refused for
		// being unreadable. An ordinary command line this parser cannot
		// split is still held to the patterns, as it was before there
		// were rules, and the shell syntax gate has already had its say
		// about the operators.
		if !looksLikeTransfer(cmd) {
			return cmdFallThrough
		}
		se.refuseRequest(r, refuseSyntax, textsafe.Clip256(err.Error()+" in "+cmd))
		return cmdAnswered
	}
	d := se.policy.rules.decide(parsed)
	switch {
	case !d.matched:
		return cmdFallThrough
	case !d.allow:
		se.refuseRequest(r, d.reason, textsafe.Clip256(d.detail+" in "+cmd))
		return cmdAnswered
	}
	se.t.engine.Logs().SecurityEvent(context.Background(), "allow", "ssh_command_rule",
		"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user),
		"target", se.target, "family", string(parsed.Kind), "command", textsafe.Clip256(cmd))
	if !d.sftp {
		return cmdAllowed
	}
	// An exec of the sftp server binary carries the sftp protocol on
	// this channel, the same protocol the subsystem carries. Relaying it
	// through the sftp policy is what makes allowing it safe: the path,
	// operation and scanning rules apply to a transfer that would
	// otherwise be an opaque byte stream.
	sp, err := se.policy.sftp.forSession(se.user, se.principal)
	if err != nil {
		se.refuseRequest(r, "sftp_identity_refused", err.Error())
		return cmdAnswered
	}
	ok, err := upCh.SendRequest(r.Type, r.WantReply, r.Payload)
	if err != nil || !ok {
		_ = r.Reply(false, nil)
		return cmdStop
	}
	_ = r.Reply(true, nil)
	se.relaySFTP(clientCh, upCh, sp)
	return cmdStop
}

// looksLikeTransfer reports whether a line this parser could not read
// names a family the rules cover. A line with no readable words has no
// first word to trust, so it is read the way the blanket check reads
// one -- every word, directory parts removed -- because a policy with
// rules should refuse "scp -t $(id)" as an scp rather than hand it to a
// pattern.
func looksLikeTransfer(cmd string) bool {
	if fileTransferCommand(cmd) {
		return true
	}
	for _, v := range []string{"git-upload-pack", "git-receive-pack", "git-upload-archive"} {
		if strings.Contains(cmd, v) {
			return true
		}
	}
	return false
}
