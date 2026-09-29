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
	"github.com/rom/xproxy/internal/csaf"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
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
	"       xproxyctl assets baseline [-forget]\n" +
	"       xproxyctl assets advisories [-state S] [-documents] [-long]"

func assetsCommand(c *mgmt.Client, fs *flag.FlagSet, out, errOut io.Writer, asJSON bool) int {
	args := fs.Args()[1:]
	if len(args) > 0 {
		switch args[0] {
		case "show":
			return assetShow(c, args[1:], out, errOut, asJSON)
		case "baseline":
			return assetBaseline(c, args[1:], out, errOut, asJSON)
		case "advisories":
			return assetAdvisories(c, args[1:], out, errOut, asJSON)
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

// assetAdvisories is what the vendors' own advisories say about this estate.
//
// The summary comes first and says all six numbers, because the useful output
// of a first run is the *shape* of the exposure: how many devices an advisory
// names, and how many nobody can assess yet. A tool that printed only the
// affected ones would be answering a question nobody can act on without knowing
// the size of the gap beside it.
func assetAdvisories(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	af := flag.NewFlagSet("assets advisories", flag.ContinueOnError)
	af.SetOutput(errOut)
	state := af.String("state", "", "only devices in this state: "+strings.Join(csaf.States(), ", "))
	documents := af.Bool("documents", false, "list the advisories that are loaded")
	long := af.Bool("long", false, "one block per device, with every advisory that names it")
	if err := af.Parse(args); err != nil {
		return 2
	}
	rep, err := c.Advisories(strings.ToLower(*state), *documents)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if asJSON {
		return printJSON(out, rep)
	}
	advisorySummary(out, rep)
	if *documents {
		advisoryDocuments(out, rep)
	}
	if len(rep.Assessments) == 0 {
		_, _ = fmt.Fprintln(out, "no device matched")
		return 0
	}
	if *long {
		for _, one := range rep.Assessments {
			advisoryBlock(out, one)
		}
		return 0
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "DEVICE\tSTATE\tSEVERITY\tFIRMWARE\tADVISORY\tFIXED IN\tPRODUCT")
	for _, one := range rep.Assessments {
		advisory, fixed := "", ""
		if len(one.Hits) > 0 {
			advisory, fixed = one.Hits[0].Advisory, one.Hits[0].Fixed
			if one.Total > 1 {
				advisory += fmt.Sprintf(" +%d", one.Total-1)
			}
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			one.Asset, one.State, severityField(one), textsafe.Clip64(firmwareField(one)),
			advisory, textsafe.Clip64(fixed), textsafe.Clip64(one.Product))
	}
	_ = tw.Flush()
	return 0
}

// advisorySummary is the six numbers, then where the documents came from.
func advisorySummary(out io.Writer, rep *proxy.AdvisoryReport) {
	c := rep.Counts
	_, _ = fmt.Fprintf(out, "%d advisories, %d product records, read %s\n",
		c.Documents, c.Records, ago(c.Loaded))
	byState := map[string]int{}
	for _, one := range rep.Assessments {
		byState[one.State]++
	}
	var parts []string
	for _, st := range csaf.States() {
		if n := byState[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", st, n))
		}
	}
	if len(parts) > 0 {
		_, _ = fmt.Fprintln(out, strings.Join(parts, ", "))
	}
	for _, src := range c.Sources {
		line := fmt.Sprintf("%s: %d advisories from %s", src.Name, src.Documents,
			textsafe.Clip256(src.Path))
		if src.Ignored > 0 {
			line += fmt.Sprintf(", %d files ignored", src.Ignored)
		}
		if src.Failures > 0 {
			line += fmt.Sprintf(", %d unreadable", src.Failures)
		}
		if src.Error != "" {
			line += ": " + textsafe.Clip256(src.Error)
		}
		_, _ = fmt.Fprintln(out, line)
	}
	_, _ = fmt.Fprintln(out)
}

// advisoryDocuments lists what is loaded, which is the answer to "what does
// this proxy actually know about" -- the first question an operator asks of a
// directory somebody else fills.
func advisoryDocuments(out io.Writer, rep *proxy.AdvisoryReport) {
	if len(rep.Advisories) == 0 {
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ADVISORY\tRELEASED\tSEVERITY\tPUBLISHER\tTITLE")
	for _, a := range rep.Advisories {
		released := ""
		if !a.Released.IsZero() {
			released = a.Released.Format("2006-01-02")
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.ID, released,
			a.Severity, textsafe.Clip64(a.Publisher), textsafe.Clip256(a.Title))
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintln(out)
}

// advisoryBlock is one device with everything that names it, which is what
// somebody reads before deciding what to do about it.
func advisoryBlock(out io.Writer, one *csaf.Assessment) {
	_, _ = fmt.Fprintf(out, "%s: %s\n", one.Asset, one.State)
	if one.Product != "" {
		_, _ = fmt.Fprintf(out, "  product     %s\n", textsafe.Clip256(one.Product))
	}
	if one.Vendor != "" {
		_, _ = fmt.Fprintf(out, "  vendor      %s\n", textsafe.Clip64(one.Vendor))
	}
	_, _ = fmt.Fprintf(out, "  firmware    %s\n", textsafe.Clip64(firmwareField(one)))
	if one.Reason != "" {
		_, _ = fmt.Fprintf(out, "  reason      %s\n", textsafe.Clip256(one.Reason))
	}
	_, _ = fmt.Fprintf(out, "  compared    %d advisory records\n", one.Compared)
	for _, h := range one.Hits {
		line := fmt.Sprintf("  %s %s", h.Advisory, h.State)
		if h.CVE != "" {
			line += " " + h.CVE
		}
		if h.Severity != "" {
			line += fmt.Sprintf(" %s", h.Severity)
			if h.Score > 0 {
				line += fmt.Sprintf(" %.1f", h.Score)
			}
		}
		_, _ = fmt.Fprintln(out, line)
		if h.Versions != "" {
			_, _ = fmt.Fprintf(out, "    versions  %s\n", textsafe.Clip256(h.Versions))
		}
		if h.Fixed != "" {
			_, _ = fmt.Fprintf(out, "    fixed in  %s\n", textsafe.Clip256(h.Fixed))
		}
		if h.Fix != "" {
			_, _ = fmt.Fprintf(out, "    remedy    %s\n", textsafe.Clip256(h.Fix))
		}
		if h.URL != "" {
			_, _ = fmt.Fprintf(out, "    reference %s\n", textsafe.Clip256(h.URL))
		}
	}
	_, _ = fmt.Fprintln(out)
}

// severityField is the worst severity with the score beside it, or a dash: a
// blank column reads as a missing value rather than as a device nothing has
// scored.
func severityField(one *csaf.Assessment) string {
	if one.Worst == "" {
		return "-"
	}
	if one.Score > 0 {
		return fmt.Sprintf("%s %.1f", one.Worst, one.Score)
	}
	return one.Worst
}

// firmwareField says so when a device has never reported a version, because
// that is a different thing from a version this could not read.
func firmwareField(one *csaf.Assessment) string {
	if one.Firmware == "" {
		return "none reported"
	}
	return one.Firmware
}
