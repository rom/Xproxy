package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/passwd"
)

// mfaCommand manages the second factor. It runs locally: no proxy needs
// to be running, and the secret it prints is the one thing that must
// reach the user and nothing else.
//
//	xproxyctl mfa enrol -user alice [-issuer xproxy] [-recovery 5]
//	xproxyctl mfa verify -file /etc/xproxy/mfa -user alice -code 123456
//	xproxyctl mfa list -file /etc/xproxy/mfa
func mfaCommand(fs *flag.FlagSet, out, errOut io.Writer) int {
	usage := func() int {
		_, _ = fmt.Fprintln(errOut, "usage: xproxyctl mfa enrol -user NAME [-issuer NAME] [-digits N] [-period N] [-algo A] [-recovery N]")
		_, _ = fmt.Fprintln(errOut, "       xproxyctl mfa verify -file FILE -user NAME -code CODE [-skew N]")
		_, _ = fmt.Fprintln(errOut, "       xproxyctl mfa list -file FILE")
		return 2
	}
	if fs.NArg() < 2 {
		return usage()
	}
	args := fs.Args()[2:]
	switch fs.Arg(1) {
	case "enrol", "enroll":
		return mfaEnrol(args, out, errOut)
	case "verify":
		return mfaVerify(args, out, errOut)
	case "list":
		return mfaList(args, out, errOut)
	default:
		return usage()
	}
}

func mfaEnrol(args []string, out, errOut io.Writer) int {
	sub := flag.NewFlagSet("mfa enrol", flag.ContinueOnError)
	sub.SetOutput(errOut)
	user := sub.String("user", "", "the name the user authenticates as")
	issuer := sub.String("issuer", "xproxy", "the name an authenticator application shows")
	digits := sub.Int("digits", mfa.DefaultDigits, "code length, 6 to 10")
	period := sub.Int("period", int(mfa.DefaultPeriod/time.Second), "step in seconds")
	algo := sub.String("algo", mfa.DefaultAlgo, "SHA1, SHA256 or SHA512")
	recovery := sub.Int("recovery", 0, "how many single-use recovery codes to generate")
	if err := sub.Parse(args); err != nil {
		return 2
	}
	if *user == "" || strings.ContainsAny(*user, ":\r\n") {
		_, _ = fmt.Fprintln(errOut, "mfa enrol: -user is required and must not contain a colon")
		return 2
	}
	if *digits < 6 || *digits > 10 {
		_, _ = fmt.Fprintln(errOut, "mfa enrol: -digits must be 6..10")
		return 2
	}
	if *period < 10 || *period > 300 {
		_, _ = fmt.Fprintln(errOut, "mfa enrol: -period must be 10..300")
		return 2
	}
	if *recovery < 0 || *recovery > 20 {
		_, _ = fmt.Fprintln(errOut, "mfa enrol: -recovery must be 0..20")
		return 2
	}
	secret, err := mfa.NewSecret()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "mfa enrol:", err)
		return 1
	}
	p := mfa.Params{Digits: *digits, Period: time.Duration(*period) * time.Second, Algo: strings.ToUpper(*algo)}
	// Check the parameters by using them, so a bad algorithm fails here
	// rather than at the first login.
	if _, err := mfa.Code([]byte("check"), 0, p); err != nil {
		_, _ = fmt.Fprintln(errOut, "mfa enrol:", err)
		return 2
	}
	var codes []string
	var hashes []string
	for i := 0; i < *recovery; i++ {
		c, err := mfa.NewSecret()
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "mfa enrol:", err)
			return 1
		}
		// A recovery code is read and typed by a person, so it is short
		// enough to be usable and long enough not to be guessed.
		c = strings.ToLower(c[:6] + "-" + c[6:12] + "-" + c[12:18])
		h, err := passwd.Hash(c)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "mfa enrol:", err)
			return 1
		}
		codes = append(codes, c)
		hashes = append(hashes, h)
	}
	params := fmt.Sprintf("digits=%d,period=%d,algo=%s", *digits, *period, strings.ToUpper(*algo))
	line := *user + ":" + secret + ":" + params
	if len(hashes) > 0 {
		line += ":" + strings.Join(hashes, ",")
	}
	_, _ = fmt.Fprintf(out, "add this line to the enrolment file (0600, not world readable):\n\n%s\n\n", line)
	_, _ = fmt.Fprintf(out, "give the user this URI, or a QR code of it:\n\n%s\n\n", mfa.URI(*issuer, *user, secret, p))
	if len(codes) > 0 {
		_, _ = fmt.Fprintf(out, "recovery codes, each usable once, shown only now:\n\n")
		for _, c := range codes {
			_, _ = fmt.Fprintf(out, "  %s\n", c)
		}
		_, _ = fmt.Fprintln(out)
	}
	_, _ = fmt.Fprintln(out, "The secret is in this output and in the file and nowhere else. Send it\nto the user over a channel the user already controls, and not the one\nthe second factor is meant to protect.")
	return 0
}

func mfaVerify(args []string, out, errOut io.Writer) int {
	sub := flag.NewFlagSet("mfa verify", flag.ContinueOnError)
	sub.SetOutput(errOut)
	file := sub.String("file", "", "the enrolment file")
	user := sub.String("user", "", "the user")
	code := sub.String("code", "", "the code to check")
	skew := sub.Int("skew", 1, "steps either side of now to accept")
	if err := sub.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *user == "" || *code == "" {
		_, _ = fmt.Fprintln(errOut, "mfa verify: -file, -user and -code are required")
		return 2
	}
	store, err := mfa.Load(*file)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "mfa verify:", err)
		return 1
	}
	g := mfa.NewGuard(store, *skew, mfa.Lockout{})
	if err := g.Verify(*user, strings.TrimSpace(*code), time.Now()); err != nil {
		_, _ = fmt.Fprintln(out, "not accepted:", err)
		return 1
	}
	_, _ = fmt.Fprintln(out, "accepted")
	return 0
}

func mfaList(args []string, out, errOut io.Writer) int {
	sub := flag.NewFlagSet("mfa list", flag.ContinueOnError)
	sub.SetOutput(errOut)
	file := sub.String("file", "", "the enrolment file")
	if err := sub.Parse(args); err != nil {
		return 2
	}
	if *file == "" {
		_, _ = fmt.Fprintln(errOut, "mfa list: -file is required")
		return 2
	}
	store, err := mfa.Load(*file)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "mfa list:", err)
		return 1
	}
	users := store.Users()
	sort.Strings(users)
	for _, u := range users {
		e, _ := store.Get(u)
		p := e.Params
		if p.Digits == 0 {
			p.Digits = mfa.DefaultDigits
		}
		if p.Period == 0 {
			p.Period = mfa.DefaultPeriod
		}
		if p.Algo == "" {
			p.Algo = mfa.DefaultAlgo
		}
		_, _ = fmt.Fprintf(out, "%s\t%d digits\t%s\t%s\t%d recovery codes\n",
			u, p.Digits, p.Period, p.Algo, len(e.Recovery))
	}
	if st, err := os.Stat(*file); err == nil && st.Mode().Perm()&0o077 != 0 {
		_, _ = fmt.Fprintf(errOut, "\nwarning: %s is mode %04o; it holds every second factor and should be 0600\n", *file, st.Mode().Perm())
	}
	return 0
}
