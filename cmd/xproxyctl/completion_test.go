package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestCompletionCoversEveryDaemon reads cmd/ rather than trusting a list.
//
// Completion covered xproxyctl and xproxy, and xgate, xrelay and xot got none --
// although they are the same program's other three roles and take the identical
// flags. The gap was invisible because nothing compared the script with the
// commands that exist.
func TestCompletionCoversEveryDaemon(t *testing.T) {
	dirs, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		src, err := os.ReadFile(filepath.Join("..", d.Name(), "main.go"))
		if err != nil {
			continue
		}
		// A command that runs internal/daemon takes the daemon flag set, so it
		// belongs in the daemon completion.
		if strings.Contains(string(src), "internal/daemon") {
			want = append(want, d.Name())
		}
	}
	if len(want) == 0 {
		t.Fatal("no daemons found; the import this test looks for has moved")
	}
	got := append([]string{}, daemonNames...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("daemonNames = %v, but the commands running internal/daemon are %v", got, want)
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		script, ok := completionScript(shell)
		if !ok {
			t.Fatalf("%s: no script", shell)
		}
		for _, d := range want {
			if !strings.Contains(script, d) {
				t.Errorf("%s completion does not mention %s", shell, d)
			}
		}
	}
}

// TestCompletionFlagsMatchTheDaemon keeps the offered flags honest. A completion
// that offers a flag the daemon does not take is worse than none: it is a wrong
// answer with the authority of the shell behind it.
func TestCompletionFlagsMatchTheDaemon(t *testing.T) {
	src, err := os.ReadFile("../../internal/daemon/daemon.go")
	if err != nil {
		t.Fatal(err)
	}
	flagRE := regexp.MustCompile(`fs\.(?:String|Bool|Int|Duration)\("([a-z0-9-]+)"`)
	found := flagRE.FindAllStringSubmatch(string(src), -1)
	real := make([]string, 0, len(found))
	for _, m := range found {
		real = append(real, m[1])
	}
	if len(real) == 0 {
		t.Fatal("no flags found in internal/daemon; the flag set has moved")
	}
	offered := map[string]bool{}
	for _, f := range daemonFlags {
		offered[f.flag] = true
	}
	for _, f := range real {
		if !offered[f] {
			t.Errorf("the daemon takes -%s and completion does not offer it", f)
		}
		delete(offered, f)
	}
	for f := range offered {
		t.Errorf("completion offers -%s and the daemon does not take it", f)
	}
}
