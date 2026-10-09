package fakeshell

import (
	"fmt"
	"strings"
	"testing"
)

// The machine a visitor looks around.
//
// Everything below is reconnaissance: the commands somebody types in the first
// minute to decide whether what they have found is worth a payload. The
// answers have to agree with each other, because that is what the visitor is
// really testing -- a `free` that contradicts /proc/meminfo, or an interface
// with no address, is how a fabrication is recognised for one. None of them
// may invent a credential or a neighbour either: what is answered here is
// read by somebody who will act on it.

// answers runs a line on a fresh session and returns the output.
func answers(t *testing.T, s *Shell, line string) string {
	t.Helper()
	return run(t, s.Open("root"), line)
}

// TestTheMachineAnswersTheFirstMinuteOfReconnaissance: the commands and what
// each has to contain to be the device it is pretending to be.
func TestTheMachineAnswersTheFirstMinuteOfReconnaissance(t *testing.T) {
	s := shellFor(t, Options{Hostname: "dvr04"})
	for _, tc := range []struct {
		line string
		// want is a fragment the answer must contain; empty wants no output
		// at all, which for some of these is the honest answer.
		want string
	}{
		{line: "who", want: "pts/0"},
		{line: "w", want: "pts/0"},
		{line: "ps", want: "telnetd"},
		{line: "df", want: "/dev/root"},
		{line: "mount", want: "type ext4"},
		{line: "lsmod", want: "Module"},
		{line: "netstat", want: "Active Internet connections"},
		{line: "ss", want: "Proto Recv-Q"},
		{line: "ifconfig", want: "inet addr:192.0.2.50"},
		{line: "ip addr", want: "Link encap:Ethernet"},
		{line: "ls /", want: "proc"},
		{line: "ls /etc", want: "resolv.conf"},
		// /tmp is where a payload lands: a visitor who found something of
		// theirs there would be on a machine that had kept it, and somebody
		// else's would say other people have been here.
		{line: "ls /tmp", want: ""},
		{line: "cat /proc/mounts", want: "/dev/root / ext4"},
		{line: "cat /etc/hosts", want: "127.0.1.1\tdvr04"},
		{line: "cat /etc/resolv.conf", want: "nameserver 192.0.2.1"},
		// cat with nothing to read says nothing, the way a shell waiting on
		// standard input says nothing.
		{line: "cat", want: ""},
		{line: "cat /etc/nonsense", want: "No such file or directory"},
		// The commands that do something on a real machine do nothing here,
		// and say nothing about it: an error would tell the visitor the file
		// system is not what they think it is.
		{line: "rm -rf /tmp/x", want: ""},
		{line: "kill -9 412", want: ""},
		{line: "", want: ""},
	} {
		got := answers(t, s, tc.line)
		if tc.want == "" {
			if got != "" {
				t.Errorf("%q answered %q, want nothing", tc.line, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%q answered %q, want it to carry %q", tc.line, got, tc.want)
		}
	}
}

// TestTheFabricatedMachineAgreesWithItself: the numbers a visitor can read two
// ways read the same both ways. This is the cheapest check anybody makes and
// the one a fabrication assembled command by command fails.
func TestTheFabricatedMachineAgreesWithItself(t *testing.T) {
	s := shellFor(t, Options{Hostname: "dvr04"})
	total := profiles[DefaultProfile].MemKB

	meminfo := answers(t, s, "cat /proc/meminfo")
	if !strings.Contains(meminfo, fmt.Sprintf("MemTotal:       %8d kB", total)) {
		t.Errorf("/proc/meminfo says %q", meminfo)
	}
	free := answers(t, s, "free")
	if !strings.Contains(free, fmt.Sprintf("%8d", total)) {
		t.Errorf("free says %q, which does not agree with /proc/meminfo", free)
	}
	if !strings.Contains(free, "Swap:") {
		t.Errorf("free left out swap: %q", free)
	}

	// The interface and the address table agree about the hardware address,
	// and it is derived from the hostname: two traps are two machines, and
	// one trap is the same machine on every visit.
	ifc := answers(t, s, "ifconfig")
	mac := s.Open("root").mac()
	if !strings.Contains(ifc, mac) {
		t.Errorf("ifconfig says %q, which does not carry the address %q", ifc, mac)
	}
	if !strings.HasPrefix(mac, "00:00:5E:") {
		t.Errorf("the hardware address %q is not in the documentation range", mac)
	}
	if again := s.Open("root").mac(); again != mac {
		t.Errorf("the same machine answered %q and then %q", mac, again)
	}
	other := shellFor(t, Options{Hostname: "dvr05"})
	if other.Open("root").mac() == mac {
		t.Error("two hostnames share one hardware address")
	}
}

// TestTheHomeDirectoryIsWhereTheUserLeftIt: cd with nothing, and cd ~, go
// home rather than to the root, which is where a shell goes and therefore
// what the prompt has to show.
func TestTheHomeDirectoryIsWhereTheUserLeftIt(t *testing.T) {
	s := shellFor(t, Options{})
	se := s.Open("alice")
	if out := run(t, se, "cd /etc"); out != "" {
		t.Errorf("cd answered %q", out)
	}
	if !strings.Contains(se.Prompt(), "etc") {
		t.Errorf("the prompt after cd /etc is %q", se.Prompt())
	}
	for _, line := range []string{"cd", "cd ~"} {
		_ = run(t, se, "cd /etc")
		if out := run(t, se, line); out != "" {
			t.Errorf("%q answered %q", line, out)
		}
		if p := se.Prompt(); !strings.Contains(p, home("alice")) && !strings.Contains(p, "~") {
			t.Errorf("after %q the prompt is %q, not the home directory", line, p)
		}
	}
	// A session opened with no user at all is the profile's own user, not an
	// empty prompt that says the shell does not know who is logged in.
	if u := s.Open("").Prompt(); u == "" || strings.HasPrefix(u, "@") {
		t.Errorf("a session with no user prompts %q", u)
	}
}

// TestWhatAnUnknownCommandSaysDependsOnTheShellItPretendsToBe: busybox and
// bash do not word it the same, and the wording is the first thing a visitor
// reads. Both are the device's own answer, neither is this proxy's.
func TestWhatAnUnknownCommandSaysDependsOnTheShellItPretendsToBe(t *testing.T) {
	for _, tc := range []struct{ profile, want string }{
		{"busybox", "not found"},
		{"linux", "command not found"},
	} {
		s := shellFor(t, Options{Profile: tc.profile})
		got := answers(t, s, "definitely-not-a-command")
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s answered %q, want it to say %q", tc.profile, got, tc.want)
		}
		if strings.Contains(got, "xproxy") {
			t.Errorf("%s named the proxy: %q", tc.profile, got)
		}
	}

	// And the process table is the one that shell would print: busybox
	// init and telnetd on the device, systemd on the server.
	if got := answers(t, shellFor(t, Options{Profile: "linux"}), "ps"); !strings.Contains(got, "systemd") {
		t.Errorf("ps on the server answered %q", got)
	}

	// busybox itself: the multi-call binary announces its version on the
	// device that has it, and is not a command at all on the one that does
	// not -- answering the version on a server would be the giveaway.
	if got := answers(t, shellFor(t, Options{Profile: "busybox"}), "busybox"); !strings.Contains(got, "BusyBox v1.20.2") {
		t.Errorf("busybox on the device answered %q", got)
	}
	if got := answers(t, shellFor(t, Options{Profile: "linux"}), "busybox"); !strings.Contains(got, "not found") {
		t.Errorf("busybox on the server answered %q", got)
	}
}
