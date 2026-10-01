// Command xproxy-simulate answers one question about a configuration
// change: what would it decide differently.
//
// It is the offline half of the control surface, next to xproxy-replay(8).
// It opens no management socket and needs no running daemon: it loads a
// configuration, starts the engine itself in this process with everything
// that reaches outward switched off, sends the traffic somebody gave it,
// and reports the decision for each item. Given two configurations it
// reports only what moved between them, and exits non-zero when anything
// did, so a change can be gated on it.
//
// Every listener kind is linked into it, because the file it is asked
// about may name listeners belonging to any of the four daemons and an
// operator introducing a rule should not have to work out which binary
// would have served it. That is also why this is not a daemon: it is a
// tool somebody runs deliberately, on a workstation or in a pipeline.
//
// Usage:
//
//	xproxy-simulate -offline -a old.yaml -b new.yaml -requests corpus.http
//	xproxy-simulate -offline -a xot.yaml -frames plant.hex -listener line1
//	xproxy-simulate -offline -a old.yaml -b new.yaml -pcap capture.pcapng -listener edge
//
// Nothing reaches a real upstream: every pool is pointed at a sink in this
// process, the state files are copied rather than opened, and every section
// that reaches outside the machine is switched off and named in the output.
//
// -offline is required rather than assumed. The policy itself runs -- the
// filters, any WebAssembly modules, the rule files and the secrets provider
// are loaded as the daemon would load them -- and that is the operator's
// assertion to make, not this program's assumption.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/amqp"     // listener kind: amqp
	_ "github.com/rom/xproxy/internal/kinds/bacnet"   // listener kind: bacnet
	_ "github.com/rom/xproxy/internal/kinds/coap"     // listener kind: coap
	_ "github.com/rom/xproxy/internal/kinds/dhcp"     // listener kind: dhcp
	_ "github.com/rom/xproxy/internal/kinds/dhcp6"    // listener kind: dhcp6
	_ "github.com/rom/xproxy/internal/kinds/dns"      // listener kind: dns
	_ "github.com/rom/xproxy/internal/kinds/forward"  // listener kind: forward
	_ "github.com/rom/xproxy/internal/kinds/ftp"      // listener kind: ftp
	_ "github.com/rom/xproxy/internal/kinds/http"     // listener kind: http, and the data plane behind it
	_ "github.com/rom/xproxy/internal/kinds/iec104"   // listener kind: iec104
	_ "github.com/rom/xproxy/internal/kinds/ldap"     // listener kind: ldap
	_ "github.com/rom/xproxy/internal/kinds/mms"      // listener kind: mms
	_ "github.com/rom/xproxy/internal/kinds/modbus"   // listener kind: modbus
	_ "github.com/rom/xproxy/internal/kinds/mqtt"     // listener kind: mqtt
	_ "github.com/rom/xproxy/internal/kinds/mysql"    // listener kind: mysql
	_ "github.com/rom/xproxy/internal/kinds/ntp"      // listener kind: ntp
	_ "github.com/rom/xproxy/internal/kinds/ntske"    // listener kind: ntske
	_ "github.com/rom/xproxy/internal/kinds/opcua"    // listener kind: opcua
	_ "github.com/rom/xproxy/internal/kinds/postgres" // listener kind: postgres
	_ "github.com/rom/xproxy/internal/kinds/rdp"      // listener kind: rdp
	_ "github.com/rom/xproxy/internal/kinds/redis"    // listener kind: redis
	_ "github.com/rom/xproxy/internal/kinds/s7"       // listener kind: s7
	_ "github.com/rom/xproxy/internal/kinds/smtp"     // listener kind: smtp
	_ "github.com/rom/xproxy/internal/kinds/snmp"     // listener kind: snmp
	_ "github.com/rom/xproxy/internal/kinds/ssh"      // listener kind: ssh
	_ "github.com/rom/xproxy/internal/kinds/syslog"   // listener kind: syslog
	_ "github.com/rom/xproxy/internal/kinds/tcp"      // listener kind: tcp
	_ "github.com/rom/xproxy/internal/kinds/tds"      // listener kind: tds
	_ "github.com/rom/xproxy/internal/kinds/telnet"   // listener kind: telnet
	_ "github.com/rom/xproxy/internal/kinds/tftp"     // listener kind: tftp
	_ "github.com/rom/xproxy/internal/kinds/udp"      // listener kind: udp
	_ "github.com/rom/xproxy/internal/kinds/vnc"      // listener kind: vnc
	"github.com/rom/xproxy/internal/simulate"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/version"
)

const usage = "usage: xproxy-simulate -offline -a FILE [-b FILE]\n" +
	"                      (-requests FILE | -frames FILE | -pcap FILE -listener NAME)\n" +
	"                      [-listener NAME] [-quiet] [-json]\n" +
	"\n" +
	"Sends traffic through one configuration, or through two and reports the\n" +
	"decisions that differ. Nothing reaches a real upstream: every pool is\n" +
	"pointed at a sink in this process, the state files are copied, and every\n" +
	"section that reaches outside is switched off and named in the output.\n" +
	"\n" +
	"-offline is required. It is the operator asserting that this configuration\n" +
	"is one they are willing to have started here -- with its filters, its\n" +
	"WebAssembly modules, its rule files and its secrets provider, all of which\n" +
	"run as they would in the daemon. Exit status is 1 when the two\n" +
	"configurations decide anything differently, so it can gate a change."

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	sf := flag.NewFlagSet("xproxy-simulate", flag.ContinueOnError)
	sf.SetOutput(errOut)
	before := sf.String("a", "", "the configuration to ask about")
	after := sf.String("b", "", "a second configuration; with it only the decisions that differ are reported")
	requests := sf.String("requests", "", "a corpus of HTTP requests")
	frames := sf.String("frames", "", "a corpus of protocol frames as hex")
	pcap := sf.String("pcap", "", "a pcapng file written by xproxyctl capture")
	listener := sf.String("listener", "", "the listener to send to, for inputs that do not name one")
	offline := sf.Bool("offline", false, "assert that this configuration may be started here")
	quiet := sf.Bool("quiet", false, "print only what changed")
	asJSON := sf.Bool("json", false, "print the whole answer as JSON")
	showVersion := sf.Bool("version", false, "print the version and exit")
	if err := sf.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(out, "xproxy-simulate", version.String())
		return 0
	}
	if sf.NArg() > 0 {
		_, _ = fmt.Fprintln(errOut, usage)
		return 2
	}
	if !*offline {
		_, _ = fmt.Fprintln(errOut, "error: -offline is required.\n\n"+
			"A simulation starts this configuration in this process. Everything that\n"+
			"reaches outward is switched off first and the output names what was, but\n"+
			"the policy itself runs: the filters, any WebAssembly modules, the rule\n"+
			"files and the secrets provider are loaded as the daemon would load them.\n"+
			"-offline is you saying that is acceptable for this configuration on this\n"+
			"machine.")
		return 2
	}
	if *before == "" {
		_, _ = fmt.Fprintln(errOut, "error: -a names the configuration to ask about")
		return 2
	}
	inputs, err := readInputs(*requests, *frames, *pcap, *listener)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 2
	}

	first, firstRep, err := simulateOne(*before, inputs)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if *after == "" {
		if *asJSON {
			return printJSON(out, errOut, map[string]any{"config": *before, "prepared": firstRep, "outcomes": first})
		}
		printPrepared(out, *before, firstRep)
		printOutcomes(out, first, *quiet)
		return 0
	}
	second, secondRep, err := simulateOne(*after, inputs)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	d := simulate.Compare(first, second)
	if *asJSON {
		if code := printJSON(out, errOut, map[string]any{
			"a": *before, "b": *after, "prepared_a": firstRep, "prepared_b": secondRep,
			"diff": d, "outcomes_a": first, "outcomes_b": second,
		}); code != 0 {
			return code
		}
		if d.Differs() {
			return 1
		}
		return 0
	}
	printPrepared(out, *before, firstRep)
	printPrepared(out, *after, secondRep)
	_, _ = fmt.Fprintf(out, "\n%s\n", d.Summary())
	if !d.Differs() {
		return 0
	}
	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nCHANGE\tLISTENER\tINPUT\tBEFORE\tAFTER")
	for _, c := range d.Changes {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.How, c.Listener,
			textsafe.Clip64(c.Input), c.Before, c.After)
	}
	_ = tw.Flush()
	return 1
}

// simulateOne loads a configuration, starts it offline and asks about every
// input in turn.
func simulateOne(path string, inputs []simulate.Input) ([]simulate.Outcome, simulate.Report, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, simulate.Report{}, fmt.Errorf("%s: %w", path, err)
	}
	dir, err := os.MkdirTemp("", "xproxy-simulate-")
	if err != nil {
		return nil, simulate.Report{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sim, err := simulate.Start(cfg, dir)
	if err != nil {
		return nil, simulate.Report{}, fmt.Errorf("%s: %w", path, err)
	}
	out := make([]simulate.Outcome, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, sim.Ask(in))
	}
	rep := sim.Report()
	if err := sim.Close(); err != nil {
		return out, rep, fmt.Errorf("%s: stopping the simulation: %w", path, err)
	}
	return out, rep, nil
}

// readInputs reads whichever corpus was named. Exactly one is allowed: a run
// over two kinds of input at once would report a diff nobody could line up
// against a file.
func readInputs(requests, frames, pcap, listener string) ([]simulate.Input, error) {
	named := 0
	for _, s := range []string{requests, frames, pcap} {
		if s != "" {
			named++
		}
	}
	switch {
	case named == 0:
		return nil, fmt.Errorf("name the traffic: -requests, -frames or -pcap")
	case named > 1:
		return nil, fmt.Errorf("name one of -requests, -frames and -pcap")
	}
	switch {
	case requests != "":
		f, err := os.Open(requests) //nolint:gosec // a corpus path the operator named on the command line
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		in, err := simulate.ParseRequests(f)
		return withListener(in, listener), err
	case frames != "":
		f, err := os.Open(frames) //nolint:gosec // a corpus path the operator named on the command line
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		in, err := simulate.ParseFrames(f)
		return withListener(in, listener), err
	}
	if listener == "" {
		return nil, fmt.Errorf("-pcap needs -listener: a capture file says which port the " +
			"proxy was listening on, not which listener in the configuration being simulated")
	}
	f, err := os.Open(pcap) //nolint:gosec // a corpus path the operator named on the command line
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	flows, err := simulate.ReadCapture(f)
	if err != nil {
		return nil, err
	}
	if len(flows) == 0 {
		return nil, fmt.Errorf("%s: no conversations in it", pcap)
	}
	return simulate.CaptureInputs(flows, listener), nil
}

// withListener fills in the listener for the items that did not name one.
func withListener(in []simulate.Input, listener string) []simulate.Input {
	if listener == "" {
		return in
	}
	for i := range in {
		if in[i].Listener == "" {
			in[i].Listener = listener
		}
	}
	return in
}

// printPrepared says what was done to a configuration before it was run. An
// operator is entitled to know what was taken out of the thing they asked about.
func printPrepared(out io.Writer, path string, rep simulate.Report) {
	_, _ = fmt.Fprintf(out, "%s: %s\n", path, reportLine(rep))
	for _, n := range rep.Notes {
		_, _ = fmt.Fprintf(out, "  %s\n", n)
	}
	for _, c := range rep.Copied {
		_, _ = fmt.Fprintf(out, "  copied, not opened: %s\n", c)
	}
}

func reportLine(rep simulate.Report) string {
	s := fmt.Sprintf("%d listeners", len(rep.Listeners))
	if len(rep.Listeners) == 1 {
		s = "1 listener"
	}
	if len(rep.SwitchedOff) > 0 {
		s += ", switched off:"
		for _, o := range rep.SwitchedOff {
			s += " " + o
		}
	}
	return s
}

// printOutcomes is the single-configuration form: what it decided, item by item.
func printOutcomes(out io.Writer, outcomes []simulate.Outcome, quiet bool) {
	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nDECISION\tLISTENER\tKIND\tREASON\tINPUT")
	for _, o := range outcomes {
		if quiet && o.Decision == simulate.Allowed {
			continue
		}
		reason := o.Reason
		if reason == "" && o.Err != "" {
			reason = o.Err
		}
		if reason == "" && o.Status != 0 {
			reason = fmt.Sprintf("status %d", o.Status)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", o.Decision, o.Listener, o.Kind,
			textsafe.Clip64(reason), textsafe.Clip64(o.Input))
	}
	_ = tw.Flush()
}

// printJSON writes the whole answer for a pipeline to read. An encoding error
// is reported rather than leaving a half-written document behind as success.
func printJSON(out, errOut io.Writer, v any) int {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	return 0
}
