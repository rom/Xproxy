package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/textsafe"
)

// The device inventory, read from the daemon.
//
// Every string in an asset came from a device: a vendor class, a host name, an
// SNMP description. A terminal interprets what is written to it, so all of them
// are clipped through textsafe before they reach one. A proxy that let a device
// choose what an operator's terminal does would be a strange place to keep a
// security inventory.

const assetsUsage = "usage: xproxyctl assets [-role R] [-listener L] [-proto P] [-vendor V] [-new] [-changed] [-top N] [-long]\n" +
	"       xproxyctl assets show KEY\n" +
	"       xproxyctl assets baseline [-forget]"

func assetsCommand(c *mgmt.Client, fs *flag.FlagSet, out, errOut io.Writer, asJSON bool) int {
	args := fs.Args()[1:]
	if len(args) > 0 {
		switch args[0] {
		case "show":
			return assetShow(c, args[1:], out, errOut, asJSON)
		case "baseline":
			return assetBaseline(c, args[1:], out, errOut, asJSON)
		}
	}
	af := flag.NewFlagSet("assets", flag.ContinueOnError)
	af.SetOutput(errOut)
	q := mgmt.AssetQuery{}
	af.StringVar(&q.Role, "role", "", "only devices classified as this role")
	af.StringVar(&q.Listener, "listener", "", "only devices seen by this listener")
	af.StringVar(&q.Proto, "proto", "", "only devices that spoke this protocol")
	af.StringVar(&q.Vendor, "vendor", "", "only devices whose vendor name contains this")
	af.BoolVar(&q.New, "new", false, "only devices that were not in the frozen baseline")
	af.BoolVar(&q.Changed, "changed", false, "only devices whose identity has changed")
	af.IntVar(&q.Top, "top", 0, "show at most this many")
	long := af.Bool("long", false, "one block per device instead of one line")
	if err := af.Parse(args); err != nil {
		return 2
	}
	if af.NArg() > 0 {
		_, _ = fmt.Fprintln(errOut, assetsUsage)
		return 2
	}
	rep, err := c.Assets(q)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if asJSON {
		return printJSON(out, rep)
	}
	assetSummary(out, rep)
	if len(rep.Assets) == 0 {
		_, _ = fmt.Fprintln(out, "no device matched")
		return 0
	}
	if *long {
		for _, a := range rep.Assets {
			assetBlock(out, a)
		}
		return 0
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tADDRESS\tVENDOR\tROLE\tL\tCONF\tPROTOCOLS\tSEEN\tNAME")
	for _, a := range rep.Assets {
		mark := ""
		if a.New {
			mark = " new"
		}
		if len(a.Changes) > 0 {
			mark += " changed"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s%s\n",
			a.ID, firstAddr(a), textsafe.Clip64(a.Vendor), a.Class.Role,
			assetLevel(a), a.Class.Confidence, protoList(a),
			ago(a.LastSeen), textsafe.Clip64(assetName(a)), mark)
	}
	_ = tw.Flush()
	return 0
}

func assetShow(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(errOut, assetsUsage)
		return 2
	}
	a, err := c.Asset(args[0])
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if asJSON {
		return printJSON(out, a)
	}
	assetBlock(out, a)
	return 0
}

// assetBaseline is the one mutating operation: saying that what is here now is
// the estate. The confirmation prints the size, because "frozen" with no number
// does not tell an operator whether they froze an inventory or an empty one.
func assetBaseline(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	bf := flag.NewFlagSet("assets baseline", flag.ContinueOnError)
	bf.SetOutput(errOut)
	forget := bf.Bool("forget", false, "forget the baseline, so nothing is a new device again")
	if err := bf.Parse(args); err != nil {
		return 2
	}
	var (
		res map[string]any
		err error
	)
	if *forget {
		res, err = c.ThawAssets()
	} else {
		res, err = c.FreezeAssets()
	}
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if asJSON {
		return printJSON(out, res)
	}
	if *forget {
		_, _ = fmt.Fprintln(out, "baseline forgotten")
		return 0
	}
	_, _ = fmt.Fprintf(out, "baseline frozen: %v devices\n", res["baseline_size"])
	return 0
}

func assetSummary(out io.Writer, rep *mgmt.AssetReport) {
	s := rep.Summary
	if s == nil {
		return
	}
	base := "no baseline"
	if s.Frozen {
		base = fmt.Sprintf("baseline %d, new %d", s.Baseline, s.New)
	}
	_, _ = fmt.Fprintf(out, "%d devices, %d unclassified, %s, %d findings\n",
		s.Assets, s.Unknown, base, s.Findings)
	if s.Dropped > 0 || s.Expired > 0 || s.Refused > 0 {
		_, _ = fmt.Fprintf(out, "dropped %d, expired %d, unidentifiable observations %d\n",
			s.Dropped, s.Expired, s.Refused)
	}
	// The roles in the order the model puts them, so a reader sees the
	// process before the printers.
	var parts []string
	for _, r := range assets.RoleNames() {
		if n := s.ByRole[r]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", r, n))
		}
	}
	if len(parts) > 0 {
		_, _ = fmt.Fprintln(out, strings.Join(parts, ", "))
	}
	if rep.Matched > len(rep.Assets) {
		_, _ = fmt.Fprintf(out, "showing %d of %d matched\n", len(rep.Assets), rep.Matched)
	}
	_, _ = fmt.Fprintln(out)
}

// assetBlock is the long form: everything known about one device, with the
// evidence for the classification and the identity changes last, because those
// are the lines somebody is looking for.
func assetBlock(out io.Writer, a *assets.Asset) {
	_, _ = fmt.Fprintf(out, "%s\n", a.ID)
	row := func(k, v string) {
		if v != "" {
			_, _ = fmt.Fprintf(out, "  %-18s %s\n", k, textsafe.Clip64(v))
		}
	}
	row("hardware", a.Hardware)
	row("vendor", a.Vendor)
	if a.OUI != "" && a.Vendor == "" {
		row("oui", a.OUI)
	}
	row("addresses", strings.Join(a.Addrs, " "))
	row("hostname", a.Hostname)
	row("vendor class", a.VendorClass)
	row("user class", a.UserClass)
	row("client id", a.ClientID)
	row("description", a.Description)
	row("model", a.Model)
	row("firmware", a.Firmware)
	row("boot file", a.BootFile)
	row("user agent", a.UserAgent)
	row("role", fmt.Sprintf("%s (confidence %d, purdue %s)",
		a.Class.Role, a.Class.Confidence, assetLevel(a)))
	if a.Class.Ambiguous {
		row("ambiguous", "two rules of equal weight disagreed")
	}
	for i, why := range a.Class.Why {
		k := ""
		if i == 0 {
			k = "because"
		}
		_, _ = fmt.Fprintf(out, "  %-18s %s\n", k, textsafe.Clip64(why))
	}
	row("protocols", protoList(a))
	row("listeners", strings.Join(a.Listeners, " "))
	if a.AsServer > 0 || a.AsClient > 0 {
		row("exchanges", fmt.Sprintf("answered %d, asked %d", a.AsServer, a.AsClient))
	}
	row("modbus units", intList(a.Units))
	row("modbus functions", intList(a.Funcs))
	row("iec104 addresses", intList(a.Objects))
	if len(a.OIDs) > 0 {
		row("snmp oids", strings.Join(a.OIDs, " "))
	}
	row("seen", fmt.Sprintf("%d observations, first %s, last %s",
		a.Count, a.FirstSeen.Format(time.RFC3339), a.LastSeen.Format(time.RFC3339)))
	if a.New {
		row("baseline", "not in the frozen baseline")
	}
	for _, ch := range a.Changes {
		detail := ch.What
		switch {
		case ch.From != "" && ch.To != "":
			detail = fmt.Sprintf("%s: %s -> %s", ch.What, ch.From, ch.To)
		case ch.To != "":
			detail = fmt.Sprintf("%s: %s", ch.What, ch.To)
		case ch.From != "":
			detail = fmt.Sprintf("%s: %s", ch.What, ch.From)
		}
		_, _ = fmt.Fprintf(out, "  %-18s %s %s\n", "change",
			ch.At.Format(time.RFC3339), textsafe.Clip64(detail))
	}
	_, _ = fmt.Fprintln(out)
}

func firstAddr(a *assets.Asset) string {
	if len(a.Addrs) == 0 {
		return "-"
	}
	return a.Addrs[0]
}

// assetName is the best name the device offered for itself, which is not
// evidence of anything and is what an operator recognises it by.
func assetName(a *assets.Asset) string {
	for _, s := range []string{a.Hostname, a.Description, a.Model, a.VendorClass, a.ClientID} {
		if s != "" {
			return s
		}
	}
	return ""
}

func assetLevel(a *assets.Asset) string {
	if l := a.Class.Level; l >= 0 {
		return fmt.Sprintf("%d", l)
	}
	return "-"
}

// protoList is the protocols with their counts, busiest first: what a device
// mostly does comes before what it did once.
func protoList(a *assets.Asset) string {
	if len(a.Protos) == 0 {
		return "-"
	}
	names := make([]string, 0, len(a.Protos))
	for p := range a.Protos {
		names = append(names, p)
	}
	sort.Slice(names, func(i, j int) bool {
		if a.Protos[names[i]] == a.Protos[names[j]] {
			return names[i] < names[j]
		}
		return a.Protos[names[i]] > a.Protos[names[j]]
	})
	out := make([]string, 0, len(names))
	for _, p := range names {
		out = append(out, fmt.Sprintf("%s/%d", p, a.Protos[p]))
	}
	return strings.Join(out, " ")
}

func intList(v []int) string {
	if len(v) == 0 {
		return ""
	}
	out := make([]string, 0, len(v))
	for _, n := range v {
		out = append(out, fmt.Sprintf("%d", n))
	}
	return strings.Join(out, " ")
}
