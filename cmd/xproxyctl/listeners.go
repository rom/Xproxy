package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
)

// The listener inventory from the command line: what this daemon is
// serving, in which mode, with which guards on, and what each protocol
// has refused.
//
// `status` already prints the addresses. This prints the two columns
// status cannot: the kind and the mode. "Which of my listeners is not
// enforcing" is the question an operator asks after a change window, and
// before this it could only be answered by reading the configuration --
// which is the file somebody may have got wrong in the first place.

const listenersUsage = "usage: xproxyctl listeners [-kind K] [-mode M] [-reasons]"

func listenersCommand(c *mgmt.Client, fs *flag.FlagSet, out, errOut io.Writer, asJSON bool) int {
	lf := flag.NewFlagSet("listeners", flag.ContinueOnError)
	lf.SetOutput(errOut)
	kind := lf.String("kind", "", "only listeners of this kind")
	mode := lf.String("mode", "", "only listeners in this mode (enforce, shadow, monitor)")
	reasons := lf.Bool("reasons", false, "break the refusals down by reason")
	if err := lf.Parse(fs.Args()[1:]); err != nil {
		return 2
	}
	if lf.NArg() > 0 {
		_, _ = fmt.Fprintln(errOut, listenersUsage)
		return 2
	}
	rep, err := c.Listeners()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if *kind != "" || *mode != "" {
		rep = filterListeners(rep, *kind, *mode)
	}
	if asJSON {
		return printJSON(out, rep)
	}
	printListeners(out, rep, *reasons)
	return 0
}

// filterListeners narrows the report, and the kind rows with it, so a
// -kind that matches nothing prints nothing rather than every kind's
// counters under an empty table.
func filterListeners(rep proxy.ListenersReport, kind, mode string) proxy.ListenersReport {
	out := rep
	out.Listeners = nil
	out.Enforcing, out.Shadowing, out.Monitoring = 0, 0, 0
	keep := make(map[string]bool)
	for _, l := range rep.Listeners {
		if kind != "" && l.Kind != kind {
			continue
		}
		if mode != "" && l.Mode != mode {
			continue
		}
		out.Listeners = append(out.Listeners, l)
		keep[l.Kind] = true
		switch l.Mode {
		case "shadow":
			out.Shadowing++
		case "monitor":
			out.Monitoring++
		default:
			out.Enforcing++
		}
	}
	out.Kinds = nil
	for _, k := range rep.Kinds {
		if keep[k.Kind] {
			out.Kinds = append(out.Kinds, k)
		}
	}
	return out
}

func printListeners(out io.Writer, rep proxy.ListenersReport, reasons bool) {
	if len(rep.Listeners) == 0 {
		_, _ = fmt.Fprintln(out, "no listeners")
		return
	}
	who := rep.Daemon
	if who == "" {
		who = "this daemon"
	}
	_, _ = fmt.Fprintf(out, "%s, generation %d: %d listeners, %d enforcing",
		who, rep.Generation, len(rep.Listeners), rep.Enforcing)
	if rep.Shadowing > 0 {
		_, _ = fmt.Fprintf(out, ", %d in shadow mode", rep.Shadowing)
	}
	if rep.Monitoring > 0 {
		_, _ = fmt.Fprintf(out, ", %d monitoring only", rep.Monitoring)
	}
	_, _ = fmt.Fprintln(out)

	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nLISTENER\tKIND\tADDRESS\tMODE\tTLS\tGUARDS")
	for _, l := range rep.Listeners {
		tls := "no"
		if l.TLS {
			tls = "yes"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			l.Name, l.Kind, l.Address, l.Mode, tls, guardList(l.Features))
	}
	_ = tw.Flush()

	for _, l := range rep.Listeners {
		for _, suffix := range sortedKeys(l.Extra) {
			_, _ = fmt.Fprintf(out, "  %s also listens on %s (%s)\n", l.Name, l.Extra[suffix], suffix)
		}
	}

	if len(rep.Kinds) == 0 {
		return
	}
	kw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(kw, "\nKIND\tLISTENERS\tREFUSED\tWOULD REFUSE")
	for _, k := range rep.Kinds {
		_, _ = fmt.Fprintf(kw, "%s\t%d\t%d\t%d\n", k.Kind, k.Listeners, k.Refused, k.WouldRefuse)
	}
	_ = kw.Flush()
	if !reasons {
		return
	}
	for _, k := range rep.Kinds {
		if len(k.Reasons) == 0 && len(k.ShadowReasons) == 0 {
			continue
		}
		_, _ = fmt.Fprintf(out, "\n%s\n", k.Kind)
		rw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
		for _, r := range k.Reasons {
			_, _ = fmt.Fprintf(rw, "  refused\t%s\t%d\n", r.Reason, r.Count)
		}
		for _, r := range k.ShadowReasons {
			_, _ = fmt.Fprintf(rw, "  would refuse\t%s\t%d\n", r.Reason, r.Count)
		}
		_ = rw.Flush()
	}
}

// guardList is the guards this listener has switched on, with what each
// one does where it says. A kind with guards and none of them on says so
// rather than leaving the column blank: "no anomaly detection here" is the
// finding, and an empty cell reads as "nothing to report".
func guardList(fs []proxy.FeatureView) string {
	if len(fs) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		if !f.Enabled {
			continue
		}
		if f.Mode != "" {
			parts = append(parts, f.Name+"="+f.Mode)
			continue
		}
		parts = append(parts, f.Name)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("none of %d", len(fs))
	}
	return strings.Join(parts, " ")
}
