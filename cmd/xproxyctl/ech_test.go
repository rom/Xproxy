package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The ECH commands run locally: no proxy, no socket, and the private key they
// write never leaves the machine. What they are for is a rotation an operator
// can carry out without taking the listener down, so the three of them have to
// agree about one thing -- the config the key file belongs to -- and the test
// below is a round trip rather than three separate assertions.

// echRun drives the command the way `run` does: a parsed flag set whose first
// two arguments are the command and its subcommand.
func echRun(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	fs := flag.NewFlagSet("xproxyctl", flag.ContinueOnError)
	fs.SetOutput(&errOut)
	_ = fs.Parse(append([]string{"ech"}, args...))
	return echCommand(fs, &out, &errOut), out.String(), errOut.String()
}

// TestEchKeygenShowAndRecordAgree: what keygen wrote, show reads back, and
// record publishes -- with the config id and the public name the same in all
// three. A mismatch anywhere here is a listener that cannot decrypt what DNS
// advertises, which is the one failure mode of ECH that looks like a network
// problem.
func TestEchKeygenShowAndRecordAgree(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := echRun("keygen", "-public-name", "ech.example.com", "-id", "7", "-dir", dir)
	if code != 0 {
		t.Fatalf("keygen: %d %q %q", code, out, errOut)
	}
	for _, want := range []string{"config id 7", "ech.example.com", "config_file:", "IN HTTPS 1 . ech="} {
		if !strings.Contains(out, want) {
			t.Errorf("keygen output has no %q:\n%s", want, out)
		}
	}
	// The key is a secret and the config is published, so they are not the
	// same mode. A key file anyone can read is the whole of ECH undone.
	key := filepath.Join(dir, "7.key")
	cfg := filepath.Join(dir, "7.echconfig")
	if st, err := os.Stat(key); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %04o", st.Mode().Perm())
	}
	if st, err := os.Stat(cfg); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0o644 {
		t.Errorf("config file mode %04o", st.Mode().Perm())
	}

	code, out, errOut = echRun("show", cfg)
	if code != 0 || !strings.Contains(out, "config id 7") || !strings.Contains(out, "ech.example.com") {
		t.Fatalf("show: %d %q %q", code, out, errOut)
	}
	if !strings.Contains(out, "cipher suites") {
		t.Errorf("show says nothing about the cipher suites:\n%s", out)
	}

	code, out, errOut = echRun("record", "-name", "www.example.com", "-ttl", "60", cfg)
	if code != 0 {
		t.Fatalf("record: %d %q %q", code, out, errOut)
	}
	// The name is published as a FQDN whether or not the operator typed the
	// trailing dot, because a zone file reading `www.example.com` without one
	// appends the zone to it.
	if !strings.HasPrefix(out, "www.example.com. 60 IN HTTPS 1 . ech=\"") {
		t.Errorf("record: %q", out)
	}
	// And the record keygen suggested carries the same list as the one record
	// prints for the same config, so following either is the same rotation.
	list := strings.TrimSuffix(strings.SplitN(out, `ech="`, 2)[1], "\"\n")
	if list == "" {
		t.Fatalf("no list in %q", out)
	}
	if code, again, _ := echRun("record", cfg); code != 0 || !strings.Contains(again, list) {
		t.Errorf("the default name publishes a different list:\n%s\n%s", out, again)
	}

	// Two configs in one record: a rotation publishes both while clients catch
	// up, which is the only reason record takes more than one file.
	if code, _, errOut := echRun("keygen", "-public-name", "ech.example.com", "-id", "8", "-dir", dir); code != 0 {
		t.Fatalf("second keygen: %s", errOut)
	}
	code, out, _ = echRun("record", cfg, filepath.Join(dir, "8.echconfig"))
	if code != 0 || out == "" {
		t.Fatalf("record of two: %d %q", code, out)
	}
	if two, one := len(out), len(list); two <= one {
		t.Errorf("a record of two configs is not longer than one: %d vs %d", two, one)
	}
}

// TestEchReadsTheFormsAnOperatorHasToHand: the config may be on disk as the
// binary this command wrote, or pasted back out of a zone file. Both are what
// somebody checking a rotation actually has, so both are read.
func TestEchReadsTheFormsAnOperatorHasToHand(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := echRun("keygen", "-public-name", "ech.example.com", "-id", "3", "-dir", dir); code != 0 {
		t.Fatalf("keygen: %s", errOut)
	}
	cfg := filepath.Join(dir, "3.echconfig")
	_, out, _ := echRun("record", cfg)
	list := strings.TrimSuffix(strings.SplitN(out, `ech="`, 2)[1], "\"\n")

	// The base64 of the list, as it appears in the zone file, with the quoting
	// and the `ech=` prefix a copy and paste brings along.
	pasted := filepath.Join(dir, "pasted.txt")
	if err := os.WriteFile(pasted, []byte("ech=\""+list+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, shown, errOut := echRun("show", pasted)
	if code != 0 || !strings.Contains(shown, "config id 3") {
		t.Fatalf("show of a pasted record: %d %q %q", code, shown, errOut)
	}
}

// TestEchRefusesWhatWouldBreakARotation: every refusal here is one an operator
// would otherwise discover from a client that cannot connect.
func TestEchRefusesWhatWouldBreakARotation(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		// A config with no public name has nothing for a stale client to fall
		// back to, and the fallback is what makes rotation safe.
		{"no public name", []string{"keygen", "-dir", dir}, 2, "-public-name is required"},
		{"id too large", []string{"keygen", "-public-name", "a.test", "-id", "256", "-dir", dir}, 2, "between 0 and 255"},
		{"id negative", []string{"keygen", "-public-name", "a.test", "-id", "-1", "-dir", dir}, 2, "between 0 and 255"},
		{"no subcommand", []string{}, 2, "usage: xproxyctl ech"},
		{"unknown subcommand", []string{"bogus"}, 2, "usage: xproxyctl ech"},
		{"show with no file", []string{"show"}, 2, "usage: xproxyctl ech show"},
		{"record with no file", []string{"record"}, 2, "usage: xproxyctl ech record"},
		{"show a missing file", []string{"show", filepath.Join(dir, "absent")}, 1, "absent"},
		{"record a missing file", []string{"record", filepath.Join(dir, "absent")}, 1, "absent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := echRun(c.args...)
			if code != c.code {
				t.Fatalf("code %d, want %d (%q %q)", code, c.code, out, errOut)
			}
			if !strings.Contains(errOut, c.want) {
				t.Errorf("stderr %q does not mention %q", errOut, c.want)
			}
		})
	}

	// A file that is neither a config nor base64 of one says so, rather than
	// reporting a config with nothing in it.
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("this is not an ECH config at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := echRun("show", junk); code != 1 || !strings.Contains(errOut, "not an ECHConfig") {
		t.Errorf("junk: %d %q", code, errOut)
	}

	// Writing over a key by accident is a listener that cannot decrypt what
	// DNS still advertises, so the second keygen on one id refuses.
	if code, _, errOut := echRun("keygen", "-public-name", "a.test", "-id", "9", "-dir", dir); code != 0 {
		t.Fatalf("keygen: %s", errOut)
	}
	code, _, errOut := echRun("keygen", "-public-name", "a.test", "-id", "9", "-dir", dir)
	if code != 1 || !strings.Contains(errOut, "already exists") {
		t.Errorf("overwrite: %d %q", code, errOut)
	}
	// And the refusal left the first key alone.
	if b, err := os.ReadFile(filepath.Join(dir, "9.key")); err != nil || len(b) == 0 {
		t.Errorf("the key was damaged by the refused second keygen: %v", err)
	}

	// A directory that does not exist is an error rather than a panic, and it
	// names the path.
	if code, _, errOut := echRun("keygen", "-public-name", "a.test", "-dir", filepath.Join(dir, "nope")); code != 1 {
		t.Errorf("a missing directory: %d %q", code, errOut)
	}
}
