package main

import (
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/textsafe"
)

// Work orders from the command line.
//
// The short version of why this exists beside `access`: a grant is an
// authorisation and a work order is a reference. `access` is how somebody is
// allowed to do something; this is how somebody says they were going to. It
// permits nothing, and the usage text says so, because the one mistake worth
// preventing is an operator filing a work order and believing the download is
// now approved.

const workorderUsage = "usage: xproxyctl workorder [-state S] [-device D]\n" +
	"       xproxyctl workorder file REFERENCE -device D -duration T [-listener L] [-note TEXT] [-by NAME] [-start RFC3339]\n" +
	"       xproxyctl workorder close REFERENCE [-note TEXT] [-by NAME]\n" +
	"\nFiling a work order permits nothing. A listener with engineering.require_grant\n" +
	"still refuses an operation with no approved grant; see xproxyctl access."

func workorderCommand(c *mgmt.Client, fs *flag.FlagSet, out, errOut io.Writer, asJSON bool) int {
	args := fs.Args()[1:]
	if len(args) > 0 {
		switch args[0] {
		case "file":
			return workorderFile(c, args[1:], out, errOut, asJSON)
		case "close":
			return workorderClose(c, args[1:], out, errOut, asJSON)
		}
	}
	wf := flag.NewFlagSet("workorder", flag.ContinueOnError)
	wf.SetOutput(errOut)
	state := wf.String("state", "", "only work orders in this state (open, scheduled, expired, closed)")
	device := wf.String("device", "", "only work orders against this device")
	if err := wf.Parse(args); err != nil {
		return 2
	}
	if wf.NArg() > 0 {
		_, _ = fmt.Fprintln(errOut, workorderUsage)
		return 2
	}
	rep, err := c.WorkOrders(*state, *device)
	if err != nil {
		return failWorkorder(errOut, err)
	}
	if asJSON {
		return printJSON(out, rep)
	}
	if len(rep.Orders) == 0 {
		_, _ = fmt.Fprintln(out, "no work orders are on file")
		return 0
	}
	_, _ = fmt.Fprintf(out, "%d work orders, %d open\n", len(rep.Orders), rep.Open)
	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nREFERENCE\tDEVICE\tLISTENER\tSTATE\tFROM\tUNTIL\tFILED BY\tWORK")
	for _, o := range rep.Orders {
		listener := o.Listener
		if listener == "" {
			listener = "any"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			textsafe.Clip64(o.Reference), textsafe.Clip64(o.Device), listener, o.State,
			o.NotBefore.Local().Format(time.RFC3339), o.Expires.Local().Format(time.RFC3339),
			textsafe.Clip64(o.By), textsafe.Clip64(o.Note))
	}
	_ = tw.Flush()
	return 0
}

// workorderFile files one.
func workorderFile(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	reference, args := leadingName(args)
	ff := flag.NewFlagSet("workorder file", flag.ContinueOnError)
	ff.SetOutput(errOut)
	device := ff.String("device", "", "the device the work is on: an upstream pool, an endpoint address or a device address")
	listener := ff.String("listener", "", "narrow to one listener; empty is every listener that reaches the device")
	note := ff.String("note", "", "what the work is")
	by := ff.String("by", "", "who is filing it")
	duration := ff.String("duration", "", "how long the work lasts, e.g. 8h")
	start := ff.String("start", "", "RFC 3339 time for work that begins later")
	if err := ff.Parse(args); err != nil {
		return 2
	}
	if reference == "" || ff.NArg() != 0 || *device == "" || *duration == "" {
		_, _ = fmt.Fprintln(errOut, workorderUsage)
		return 2
	}
	v, err := c.FileWorkOrder(reference, *device, *listener, *note, actor(*by), *duration, *start)
	if err != nil {
		return failWorkorder(errOut, err)
	}
	if asJSON {
		return printJSON(out, v)
	}
	_, _ = fmt.Fprintf(out, "work order %s on file for %s, %s until %s\n",
		v.Reference, v.Device, v.State, v.Expires.Local().Format(time.RFC3339))
	_, _ = fmt.Fprintln(out, "It permits nothing: engineering on that device is now reported as expected work "+
		"rather than as work nobody filed.")
	return 0
}

// workorderClose ends one early.
func workorderClose(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	reference, args := leadingName(args)
	cf := flag.NewFlagSet("workorder close", flag.ContinueOnError)
	cf.SetOutput(errOut)
	note := cf.String("note", "", "why it is being closed")
	by := cf.String("by", "", "who is closing it")
	if err := cf.Parse(args); err != nil {
		return 2
	}
	if reference == "" || cf.NArg() != 0 {
		_, _ = fmt.Fprintln(errOut, workorderUsage)
		return 2
	}
	v, err := c.CloseWorkOrder(reference, actor(*by), *note)
	if err != nil {
		return failWorkorder(errOut, err)
	}
	if asJSON {
		return printJSON(out, v)
	}
	_, _ = fmt.Fprintf(out, "work order %s closed; engineering on %s is unfiled again\n", v.Reference, v.Device)
	return 0
}

func failWorkorder(errOut io.Writer, err error) int {
	_, _ = fmt.Fprintln(errOut, "error:", err)
	return 1
}
