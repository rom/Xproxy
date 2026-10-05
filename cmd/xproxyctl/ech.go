package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rom/xproxy/internal/ech"
)

// echCommand generates Encrypted Client Hello keys and prints the DNS
// record to publish. It runs locally: no proxy needs to be running, and
// the private key it writes never leaves the machine.
//
//	xproxyctl ech keygen -public-name ech.example.com -id 1 -dir /etc/xproxy/ech
//	xproxyctl ech show /etc/xproxy/ech/1.echconfig [...]
//	xproxyctl ech record -name www.example.com /etc/xproxy/ech/*.echconfig
func echCommand(fs *flag.FlagSet, out, errOut io.Writer) int {
	usage := func() int {
		_, _ = fmt.Fprintln(errOut, "usage: xproxyctl ech keygen -public-name NAME [-id N] [-dir DIR]")
		_, _ = fmt.Fprintln(errOut, "       xproxyctl ech show CONFIG...")
		_, _ = fmt.Fprintln(errOut, "       xproxyctl ech record [-name NAME] [-ttl N] CONFIG...")
		return 2
	}
	if fs.NArg() < 2 {
		return usage()
	}
	args := fs.Args()[2:]
	switch fs.Arg(1) {
	case "keygen":
		return echKeygen(args, out, errOut)
	case "show":
		return echShow(args, out, errOut)
	case "record":
		return echRecord(args, out, errOut)
	default:
		return usage()
	}
}

func echKeygen(args []string, out, errOut io.Writer) int {
	sub := flag.NewFlagSet("ech keygen", flag.ContinueOnError)
	sub.SetOutput(errOut)
	name := sub.String("public-name", "", "the name visible on the wire, which needs a certificate on the listener")
	id := sub.Int("id", 1, "config id, 0-255, unique among the keys served together")
	dir := sub.String("dir", ".", "directory for the config and key files")
	if err := sub.Parse(args); err != nil {
		return 2
	}
	if *name == "" {
		_, _ = fmt.Fprintln(errOut, "ech keygen: -public-name is required")
		return 2
	}
	if *id < 0 || *id > 255 {
		_, _ = fmt.Fprintln(errOut, "ech keygen: -id must be between 0 and 255")
		return 2
	}
	cfg, priv, err := ech.Generate(*name, uint8(*id)) //nolint:gosec // bounded above
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "ech keygen:", err)
		return 1
	}
	enc, err := cfg.Marshal()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "ech keygen:", err)
		return 1
	}
	base := filepath.Join(*dir, strconv.Itoa(*id))
	// The key is written 0600 and the config 0644: one is a secret, the
	// other is published in DNS.
	if err := writeNew(base+".key", priv, 0o600); err != nil {
		_, _ = fmt.Fprintln(errOut, "ech keygen:", err)
		return 1
	}
	if err := writeNew(base+".echconfig", enc, 0o644); err != nil { //nolint:gosec // the config is public by design
		_, _ = fmt.Fprintln(errOut, "ech keygen:", err)
		return 1
	}
	list, err := ech.ListBase64([]ech.Config{cfg})
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "ech keygen:", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "wrote %s.echconfig and %s.key (config id %d, public name %s)\n\n", base, base, cfg.ID, cfg.PublicName)
	_, _ = fmt.Fprintf(out, "configure:\n  tls:\n    ech:\n      keys:\n        - {config_file: %s.echconfig, key_file: %s.key}\n\n", base, base)
	_, _ = fmt.Fprintf(out, "publish (one HTTPS record per name served behind this key):\n")
	_, _ = fmt.Fprintf(out, "  example.com. 300 IN HTTPS 1 . ech=\"%s\"\n\n", list)
	_, _ = fmt.Fprintf(out, "%s needs a certificate on the listener: a client with a stale key\nfalls back to it, and that fallback is what makes rotation safe.\n", cfg.PublicName)
	return 0
}

func echShow(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, "usage: xproxyctl ech show CONFIG...")
		return 2
	}
	rc := 0
	for _, path := range args {
		cs, err := readConfigs(path)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "%s: %v\n", path, err)
			rc = 1
			continue
		}
		for _, c := range cs {
			_, _ = fmt.Fprintf(out, "%s: config id %d, public name %s, max name length %d, %d cipher suites, key %s\n",
				path, c.ID, c.PublicName, c.MaxNameLength, len(c.Ciphers),
				base64.StdEncoding.EncodeToString(c.PublicKey))
		}
	}
	return rc
}

func echRecord(args []string, out, errOut io.Writer) int {
	sub := flag.NewFlagSet("ech record", flag.ContinueOnError)
	sub.SetOutput(errOut)
	name := sub.String("name", "example.com", "the name the record is published for")
	ttl := sub.Int("ttl", 300, "record TTL; keep it short while rotating")
	if err := sub.Parse(args); err != nil {
		return 2
	}
	if sub.NArg() == 0 {
		_, _ = fmt.Fprintln(errOut, "usage: xproxyctl ech record [-name NAME] [-ttl N] CONFIG...")
		return 2
	}
	var all []ech.Config
	for _, path := range sub.Args() {
		cs, err := readConfigs(path)
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "%s: %v\n", path, err)
			return 1
		}
		all = append(all, cs...)
	}
	list, err := ech.ListBase64(all)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "ech record:", err)
		return 1
	}
	fqdn := *name
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	_, _ = fmt.Fprintf(out, "%s %d IN HTTPS 1 . ech=\"%s\"\n", fqdn, *ttl, list)
	return 0
}

// readConfigs reads one file, which may hold a single config or a list.
func readConfigs(path string) ([]ech.Config, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a path the operator typed on their own command line
	if err != nil {
		return nil, err
	}
	if c, err := ech.Parse(raw); err == nil {
		return []ech.Config{c}, nil
	}
	if cs, err := ech.ParseList(raw); err == nil {
		return cs, nil
	}
	// A record pasted out of a zone file arrives as `ech="<base64>"`, so the
	// quotes have to come off on both sides of the prefix: trimming them first
	// and then stripping `ech=` leaves the opening quote in place, which is
	// the one form an operator is most likely to have to hand.
	text := strings.Trim(strings.Join(strings.Fields(string(raw)), ""), `"`)
	text = strings.Trim(strings.TrimPrefix(text, "ech="), `"`)
	dec, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, errors.New("not an ECHConfig, an ECHConfigList, or base64 of either")
	}
	if cs, err := ech.ParseList(dec); err == nil {
		return cs, nil
	}
	c, err := ech.Parse(dec)
	if err != nil {
		return nil, err
	}
	return []ech.Config{c}, nil
}

// writeNew refuses to overwrite: a key file replaced by accident is a
// listener that cannot decrypt what DNS still advertises.
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // a path the operator gave on their own command line
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; remove it or choose another -id", path)
		}
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Close()
}
