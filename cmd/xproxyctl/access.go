package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/textsafe"
)

// Just-in-time access from the command line: asking for a window, approving
// somebody else's ask, refusing one, taking one back, and reading the list.
//
// The -by name is who the act is recorded as, and four eyes is enforced on it:
// the person who asked may not approve, and one approver cannot count twice. It
// defaults to the account running the command -- SUDO_USER first, because
// somebody who reached the socket through sudo is still a person and root is not
// a name -- so the ordinary case needs no flag and the trail still names
// somebody.
//
// Every string shown here was written by an operator into a reason or a note, so
// it is clipped through textsafe before it reaches a terminal.

const accessUsage = "usage: xproxyctl access [-state S]\n" +
	"       xproxyctl access show ID\n" +
	"       xproxyctl access ask -subject NAME -listener L -target T -reason WHY -for 2h [-start RFC3339] [-uses N] [-by NAME]\n" +
	"       xproxyctl access approve ID [-note TEXT] [-by NAME]\n" +
	"       xproxyctl access deny ID [-note TEXT] [-by NAME]\n" +
	"       xproxyctl access revoke ID [-note TEXT] [-by NAME]"

func accessCommand(c *mgmt.Client, fs *flag.FlagSet, out, errOut io.Writer, asJSON bool) int {
	args := fs.Args()[1:]
	if len(args) > 0 {
		switch args[0] {
		case "show":
			return accessShow(c, args[1:], out, errOut, asJSON)
		case "ask":
			return accessAsk(c, args[1:], out, errOut, asJSON)
		case "approve", "deny", "revoke":
			return accessAct(c, args[0], args[1:], out, errOut, asJSON)
		}
	}
	af := flag.NewFlagSet("access", flag.ContinueOnError)
	af.SetOutput(errOut)
	state := af.String("state", "", "only grants in this state (pending, scheduled, active, spent, expired, denied, revoked)")
	if err := af.Parse(args); err != nil {
		return 2
	}
	if af.NArg() > 0 {
		_, _ = fmt.Fprintln(errOut, accessUsage)
		return 2
	}
	rep, err := c.Access(*state)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if asJSON {
		return printJSON(out, rep)
	}
	accessSummary(out, rep.Stats)
	if len(rep.Grants) == 0 {
		_, _ = fmt.Fprintln(out, "no grant matched")
		return 0
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tSTATE\tSUBJECT\tLISTENER\tTARGET\tAPPROVALS\tWINDOW\tASKED BY\tREASON")
	for _, g := range rep.Grants {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d/%d\t%s\t%s\t%s\n",
			shortID(g.ID), g.State, textsafe.Clip64(g.Subject), textsafe.Clip64(g.Listener),
			textsafe.Clip64(g.Target), len(g.Approvals), g.NeedApprovals, window(g.Grant),
			textsafe.Clip64(g.By), textsafe.Clip64(g.Reason))
	}
	_ = tw.Flush()
	return 0
}

func accessShow(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(errOut, accessUsage)
		return 2
	}
	g, err := c.Grant(args[0])
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if asJSON {
		return printJSON(out, g)
	}
	accessBlock(out, g)
	return 0
}

func accessAsk(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	af := flag.NewFlagSet("access ask", flag.ContinueOnError)
	af.SetOutput(errOut)
	subject := af.String("subject", "", "who the access is for: the login or principal that will connect")
	listener := af.String("listener", "", "the listener the access is on")
	target := af.String("target", "", "the upstream pool, or one host:port in it")
	reason := af.String("reason", "", "why: what an investigation reads first")
	forD := af.String("for", "", "how long the window lasts, e.g. 2h")
	start := af.String("start", "", "when the window opens (RFC 3339); now by default")
	uses := af.Int("uses", 0, "sessions this grant may open; 0 leaves the window as the only bound")
	by := af.String("by", "", "who is asking; the account running this command by default")
	if err := af.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || *listener == "" || *target == "" || *reason == "" || *forD == "" {
		_, _ = fmt.Fprintln(errOut, "access ask: -subject, -listener, -target, -reason and -for are all required")
		return 2
	}
	g, err := c.AskAccess(*subject, *listener, *target, *reason, actor(*by), *forD, *start, *uses)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if asJSON {
		return printJSON(out, g)
	}
	_, _ = fmt.Fprintf(out, "asked: %s\n", g.ID)
	if g.NeedApprovals > 0 {
		_, _ = fmt.Fprintf(out, "it needs %d approval(s) from somebody other than %s and %s:\n  xproxyctl access approve %s\n",
			g.NeedApprovals, textsafe.Clip64(g.By), textsafe.Clip64(g.Subject), g.ID)
	}
	return 0
}

func accessAct(c *mgmt.Client, what string, args []string, out, errOut io.Writer, asJSON bool) int {
	af := flag.NewFlagSet("access "+what, flag.ContinueOnError)
	af.SetOutput(errOut)
	note := af.String("note", "", "what to record beside the decision")
	by := af.String("by", "", "who is deciding; the account running this command by default")
	if err := af.Parse(args); err != nil {
		return 2
	}
	if af.NArg() != 1 {
		_, _ = fmt.Fprintf(errOut, "access %s: one grant id\n", what)
		return 2
	}
	id := af.Arg(0)
	var g *access.Grant
	var err error
	switch what {
	case "approve":
		g, err = c.ApproveAccess(id, actor(*by), *note)
	case "deny":
		g, err = c.DenyAccess(id, actor(*by), *note)
	default:
		g, err = c.RevokeAccess(id, actor(*by), *note)
	}
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if asJSON {
		return printJSON(out, g)
	}
	accessBlock(out, access.View{Grant: *g, State: g.State(time.Now())})
	return 0
}

// actor is the name an act is recorded under: what -by said, or the account
// running the command. SUDO_USER comes first because somebody who used sudo is
// still a person, and "root" is not a name four eyes can tell apart.
func actor(flagValue string) string {
	if s := strings.TrimSpace(flagValue); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("SUDO_USER")); s != "" {
		return s
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return ""
}

// accessSummary is the line above the table.
func accessSummary(out io.Writer, s access.Stats) {
	_, _ = fmt.Fprintf(out, "requests %d  approvals %d  denials %d  revocations %d  uses %d\n",
		s.Requests, s.Approvals, s.Denials, s.Revocations, s.Uses)
	if len(s.Refusals) > 0 {
		parts := make([]string, 0, len(s.Refusals))
		for _, r := range []string{access.ReasonNoGrant, access.ReasonPending, access.ReasonEarly,
			access.ReasonExpired, access.ReasonDenied, access.ReasonRevoked, access.ReasonSpent, access.ReasonNoTarget} {
			if n := s.Refusals[r]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", r, n))
			}
		}
		if len(parts) > 0 {
			_, _ = fmt.Fprintf(out, "sessions refused: %s\n", strings.Join(parts, "  "))
		}
	}
}

// accessBlock is one grant in full, which is what an operator reads before
// approving: who asked, for whom, where, why, and for how long.
func accessBlock(out io.Writer, g access.View) {
	_, _ = fmt.Fprintf(out, "%s  %s\n", g.ID, g.State)
	_, _ = fmt.Fprintf(out, "  subject   %s\n", textsafe.Clip64(g.Subject))
	_, _ = fmt.Fprintf(out, "  where     %s on %s\n", textsafe.Clip64(g.Target), textsafe.Clip64(g.Listener))
	_, _ = fmt.Fprintf(out, "  reason    %s\n", textsafe.Clip64(g.Reason))
	_, _ = fmt.Fprintf(out, "  asked by  %s at %s\n", textsafe.Clip64(g.By), g.At.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(out, "  window    %s\n", window(g.Grant))
	if g.MaxUses > 0 {
		_, _ = fmt.Fprintf(out, "  uses      %d of %d\n", g.Uses, g.MaxUses)
	} else if g.Uses > 0 {
		_, _ = fmt.Fprintf(out, "  uses      %d\n", g.Uses)
	}
	_, _ = fmt.Fprintf(out, "  approvals %d of %d needed\n", len(g.Approvals), g.NeedApprovals)
	for _, a := range g.Approvals {
		_, _ = fmt.Fprintf(out, "    %s at %s %s\n", textsafe.Clip64(a.By), a.At.UTC().Format(time.RFC3339),
			textsafe.Clip64(a.Note))
	}
	if d := g.Refusal; d != nil {
		_, _ = fmt.Fprintf(out, "  denied by %s at %s %s\n", textsafe.Clip64(d.By),
			d.At.UTC().Format(time.RFC3339), textsafe.Clip64(d.Note))
	}
	if d := g.Revocation; d != nil {
		_, _ = fmt.Fprintf(out, "  revoked by %s at %s %s\n", textsafe.Clip64(d.By),
			d.At.UTC().Format(time.RFC3339), textsafe.Clip64(d.Note))
	}
}

// window is the grant's window as an operator reads it: the two times, and how
// long is left of it.
func window(g access.Grant) string {
	s := g.NotBefore.UTC().Format("15:04") + "-" + g.Expires.UTC().Format("15:04Z")
	if left := time.Until(g.Expires); left > 0 {
		return s + fmt.Sprintf(" (%s left)", left.Round(time.Minute))
	}
	return s + " (closed)"
}

// shortID is the first eight characters, which is enough to tell grants apart in
// a table and enough to paste into an approve.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
