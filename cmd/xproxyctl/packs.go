package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/packs"
	"github.com/rom/xproxy/internal/textsafe"
)

// Behaviour packs from the command line.
//
// Two halves, and they are separate on purpose. Reading what is in force and
// lifting a quarantine go to the running daemon over the management socket.
// Making a key, signing a directory and verifying one are *file* operations on a
// machine that need not be running anything -- a release host, a configuration
// management run, an air-gapped laptop with the packs on a stick -- so they never
// open the socket.

// packsFail prints an error the way every other command in this tool does.
func packsFail(errOut io.Writer, err error) int {
	_, _ = fmt.Fprintln(errOut, "error:", err)
	return 1
}

const packsUsage = "usage: xproxyctl packs [-severity S]\n" +
	"       xproxyctl packs show ID\n" +
	"       xproxyctl packs release ADDRESS [-note TEXT] [-by NAME]\n" +
	"       xproxyctl packs keygen -name NAME -out PREFIX\n" +
	"       xproxyctl packs sign -key FILE -name NAME DIR\n" +
	"       xproxyctl packs verify -key FILE -name NAME DIR"

func packsCommand(c *mgmt.Client, fs *flag.FlagSet, out, errOut io.Writer, asJSON bool) int {
	args := fs.Args()[1:]
	if len(args) > 0 {
		switch args[0] {
		case "show":
			return packsShow(c, args[1:], out, errOut, asJSON)
		case "release":
			return packsRelease(c, args[1:], out, errOut, asJSON)
		case "keygen":
			return packsKeygen(args[1:], out, errOut)
		case "sign":
			return packsSignOrVerify(true, args[1:], out, errOut)
		case "verify":
			return packsSignOrVerify(false, args[1:], out, errOut)
		}
	}
	pf := flag.NewFlagSet("packs", flag.ContinueOnError)
	pf.SetOutput(errOut)
	sev := pf.String("severity", "", "show packs at this severity or above (info, low, medium, high, critical)")
	if err := pf.Parse(args); err != nil {
		return 2
	}
	if pf.NArg() > 0 {
		_, _ = fmt.Fprintln(errOut, packsUsage)
		return 2
	}
	floor := -1
	if *sev != "" {
		if floor = packs.Severity(*sev).Rank(); floor < 0 {
			_, _ = fmt.Fprintf(errOut, "error: severity %q: info, low, medium, high or critical\n", *sev)
			return 2
		}
	}
	rep, err := c.Packs()
	if err != nil {
		return packsFail(errOut, err)
	}
	if asJSON {
		return printJSON(out, rep)
	}
	st := rep.Status
	if st.Packs == 0 {
		_, _ = fmt.Fprintln(out, "no behaviour packs are loaded (no packs section, or packs.enabled: false)")
		return 0
	}
	mode := "alert only"
	if st.Enforcing {
		mode = "enforcing: the packs that declare deny may quarantine"
	}
	_, _ = fmt.Fprintf(out, "%d packs, %s\n", st.Packs, mode)
	_, _ = fmt.Fprintf(out, "actors tracked %d  quarantined %d\n", st.Actors, st.Quarantined)
	if st.Evicted > 0 || st.Refused > 0 {
		_, _ = fmt.Fprintf(out, "bounds reached: %d actors evicted, %d quarantines not taken; "+
			"raise packs.max_actors or packs.max_quarantined\n", st.Evicted, st.Refused)
	}
	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "\nPACK\tREV\tTECHNIQUE\tSEVERITY\tMAY\tMATCHES\tSIGNER")
	for _, p := range rep.Packs {
		if floor >= 0 && packs.Severity(p.Severity).Rank() < floor {
			continue
		}
		signer := p.Signer
		if signer == "" {
			signer = "unsigned"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%d\t%s\n",
			p.ID, p.Revision, p.Technique, p.Severity, p.Enforcement, p.Matches,
			textsafe.Clip64(signer))
	}
	_ = tw.Flush()
	return 0
}

// packsShow is one pack in full, which is what somebody woken by a finding
// reads: what the pack is about, what it looked for, and where the behaviour was
// published.
func packsShow(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(errOut, packsUsage)
		return 2
	}
	rep, err := c.Packs()
	if err != nil {
		return packsFail(errOut, err)
	}
	for _, p := range rep.Packs {
		if p.ID != args[0] {
			continue
		}
		if asJSON {
			return printJSON(out, p)
		}
		_, _ = fmt.Fprintf(out, "%s  revision %d\n", p.ID, p.Revision)
		_, _ = fmt.Fprintf(out, "  name       %s\n", textsafe.Clip64(p.Name))
		_, _ = fmt.Fprintf(out, "  technique  %s (%s, %s)\n", p.Technique, p.Matrix, p.Tactic)
		_, _ = fmt.Fprintf(out, "  severity   %s, may %s\n", p.Severity, p.Enforcement)
		_, _ = fmt.Fprintf(out, "  kinds      %s\n", strings.Join(p.Kinds, ", "))
		order := "in any order"
		if p.Ordered {
			order = "in this order"
		}
		_, _ = fmt.Fprintf(out, "  window     %s, %s\n", p.Window, order)
		if p.AcrossKinds > 0 {
			_, _ = fmt.Fprintf(out, "  protocols  at least %d distinct\n", p.AcrossKinds)
		}
		_, _ = fmt.Fprintf(out, "  signals    %s\n", strings.Join(p.Signals, " then "))
		_, _ = fmt.Fprintf(out, "  matches    %d\n", p.Matches)
		_, _ = fmt.Fprintf(out, "  file       %s", p.Source)
		if p.Signer != "" {
			_, _ = fmt.Fprintf(out, ", signed by %s", textsafe.Clip64(p.Signer))
		} else {
			_, _ = fmt.Fprint(out, ", unsigned")
		}
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintf(out, "\n%s\n", textsafe.Clip(p.Summary, 1024))
		for _, r := range p.References {
			_, _ = fmt.Fprintf(out, "  see %s\n", textsafe.Clip(r, 200))
		}
		return 0
	}
	_, _ = fmt.Fprintf(errOut, "error: no pack %q is loaded\n", args[0])
	return 1
}

// packsRelease lifts a quarantine.
func packsRelease(c *mgmt.Client, args []string, out, errOut io.Writer, asJSON bool) int {
	address, args := leadingName(args)
	rf := flag.NewFlagSet("release", flag.ContinueOnError)
	rf.SetOutput(errOut)
	note := rf.String("note", "", "why, for the audit log")
	by := rf.String("by", "", "who is saying so; defaults to the account running the command")
	if err := rf.Parse(args); err != nil {
		return 2
	}
	if address == "" || rf.NArg() != 0 {
		_, _ = fmt.Fprintln(errOut, packsUsage)
		return 2
	}
	if err := c.ReleasePack(address, actor(*by), *note); err != nil {
		return packsFail(errOut, err)
	}
	if asJSON {
		return printJSON(out, map[string]any{"released": address})
	}
	_, _ = fmt.Fprintf(out, "%s released\n", address)
	return 0
}

// leadingName takes the name off the front of a subcommand's arguments.
//
// The usage text of this tool puts the name first -- "packs release ADDRESS
// [-note TEXT]", "workorder close REFERENCE [-by NAME]" -- because that is the
// order people type. Go's flag package stops parsing at the first non-flag
// argument, so parsing those arguments as they stand leaves every flag after
// the name unset and silently ignored: `packs release 10.0.0.1 -note why` used
// to print the usage rather than the note. Taking the name off first makes the
// documented form the form that works.
func leadingName(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// packsKeygen writes a signing keypair. The private half is 0600 and the public
// half is the thing that goes in a configuration.
func packsKeygen(args []string, out, errOut io.Writer) int {
	kf := flag.NewFlagSet("keygen", flag.ContinueOnError)
	kf.SetOutput(errOut)
	name := kf.String("name", "", "the key's name, which a signature carries and a configuration lists")
	prefix := kf.String("out", "", "write PREFIX.key and PREFIX.pub")
	if err := kf.Parse(args); err != nil {
		return 2
	}
	if *name == "" || *prefix == "" || kf.NArg() > 0 {
		_, _ = fmt.Fprintln(errOut, packsUsage)
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return packsFail(errOut, err)
	}
	keyPath, pubPath := *prefix+".key", *prefix+".pub"
	header := "# xproxy pack signing key " + *name + "\n"
	if err := os.WriteFile(keyPath,
		[]byte(header+base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return packsFail(errOut, err)
	}
	if err := os.WriteFile(pubPath, //nolint:gosec // a public key is meant to be readable
		[]byte(header+base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return packsFail(errOut, err)
	}
	_, _ = fmt.Fprintf(out, "private key %s (keep it off the machines that read packs)\npublic key  %s\n",
		keyPath, pubPath)
	_, _ = fmt.Fprintf(out, "\nconfiguration:\npacks:\n  keys:\n    - {name: %s, file: %s}\n", *name, pubPath)
	return 0
}

// packsSignOrVerify signs or verifies every pack in a directory.
//
// Verifying needs only the public key, which is the case that matters: an
// operator checking a directory they were given should not have to hold anything
// secret to do it.
func packsSignOrVerify(sign bool, args []string, out, errOut io.Writer) int {
	what := "verify"
	if sign {
		what = "sign"
	}
	sf := flag.NewFlagSet(what, flag.ContinueOnError)
	sf.SetOutput(errOut)
	keyFile := sf.String("key", "", "the key file: the private key to sign, the public key to verify")
	name := sf.String("name", "", "the key's name, which the signature carries")
	if err := sf.Parse(args); err != nil {
		return 2
	}
	if *keyFile == "" || *name == "" || sf.NArg() != 1 {
		_, _ = fmt.Fprintln(errOut, packsUsage)
		return 2
	}
	dir := sf.Arg(0)
	if sign {
		priv, err := readPrivateKey(*keyFile)
		if err != nil {
			return packsFail(errOut, err)
		}
		n, err := signDir(dir, *name, priv, out)
		if err != nil {
			return packsFail(errOut, err)
		}
		_, _ = fmt.Fprintf(out, "%d packs signed as %s\n", n, *name)
		return 0
	}
	key, err := packs.ReadKeyFile(*name, *keyFile)
	if err != nil {
		return packsFail(errOut, err)
	}
	rep, err := packs.Load(dir, packs.Trust{Keys: []packs.Key{key}})
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	for _, f := range rep.Superseded {
		_, _ = fmt.Fprintf(out, "superseded by a higher revision: %s\n", f)
	}
	_, _ = fmt.Fprintf(out, "%d packs verify under %s\n", len(rep.Packs), *name)
	return 0
}

// readPrivateKey reads an ed25519 private key from a file of its base64,
// tolerating the comment lines keygen writes.
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the operator's own path
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		raw, err := base64.StdEncoding.DecodeString(fields[len(fields)-1])
		if err != nil {
			return nil, fmt.Errorf("%s: not base64: %w", path, err)
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%s: %d bytes, an ed25519 private key is %d",
				path, len(raw), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("%s: holds no key", path)
}

// signDir writes a detached signature beside every pack in a directory.
func signDir(dir, name string, priv ed25519.PrivateKey, out io.Writer) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := strings.ToLower(filepath.Ext(e.Name())); ext == ".yaml" || ext == ".yml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		path := filepath.Join(dir, n)
		body, err := os.ReadFile(path) //nolint:gosec // the directory the operator named
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(path+packs.SigExt, //nolint:gosec // a signature is public and is read beside the pack
			[]byte(packs.Sign(name, priv, body)), 0o644); err != nil {
			return 0, err
		}
		_, _ = fmt.Fprintf(out, "signed %s\n", n)
	}
	return len(names), nil
}
