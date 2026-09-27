// Package fakeshell is a login and a shell that are not there.
//
// It is the shared half of the telnet and SSH credential traps. Both protocols
// ask the same two questions of a visitor -- who are you, and then what did you
// want -- and neither answer is worth anything without the other. A trap that
// only collected credentials would have the dictionary and no idea what it was
// for; one that only collected commands would not know whose password opened the
// door.
//
// Three decisions shape everything here.
//
// **It never runs anything and never fetches anything.** A visitor who types
// `wget http://…/x` has handed over the one artefact that matters, and a
// fabrication that then fetched it would be doing the download on the attacker's
// behalf -- from this estate's address, with this estate's reputation. The URL is
// recorded and the command answers the failure a host with no route answers.
//
// **No password is recorded, in any form a guess can be tested against.** What is
// kept is the user name, which is an identity; the credential's length; and a
// correlation handle computed under a key this process made at startup and never
// writes down. That answers the question an operator actually has -- how many
// distinct passwords did this client try, and has this one been seen before -- and
// answers nothing to anybody who later reads the log. After a restart the handles
// are new, which is correct: the question is about a session or a campaign, not
// about the password.
//
// **The login never succeeds by accident and never fails on the credential.** A
// trap that refused the wrong password and accepted the right one would be a
// credential oracle, which is the one thing a password list needs. Every
// credential is accepted after the configured number of attempts, and which
// credential it was makes no difference to what happens next.
package fakeshell

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/deception"
	"github.com/rom/xproxy/internal/textsafe"
)

// credKey keys the credential correlation handles. It is made once per process
// from the system random source and never leaves it: nothing that reads a log can
// test a guess against a handle, and nothing that survives a restart can either.
var credKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		// A process with no random source cannot produce handles that are worth
		// anything. Falling back to a constant would produce handles a reader
		// could test guesses against, so the fallback is a key that makes every
		// handle useless instead -- which is the safe direction.
		return nil
	}
	return k
}()

// Profile is the shape of the machine being impersonated.
type Profile struct {
	Name string
	// Uname is what `uname -a` answers, which is the first thing a script asks
	// and the line a human recognises.
	Uname string
	// Machine is `uname -m`, Release is `uname -r`, Kernel is `uname -s`.
	Machine, Release, Kernel string
	// Hostname is the name in the prompt and in `hostname`.
	Hostname string
	// User is the account a visitor is told they are.
	User string
	// Busybox says the shell is busybox, which changes what an unknown
	// command says and makes `/bin/busybox APPLET` meaningful.
	Busybox bool
	// Banner is what is printed before the login prompt: the greeting, not
	// the prompt itself, because a caller that has its own prompt machinery
	// needs the two separately.
	Banner string
	// MOTD is what is printed once the login is accepted. A machine that
	// says nothing at all after a login is a machine somebody has tidied,
	// which is not the machine being impersonated.
	MOTD string
	// CPU is what `cat /proc/cpuinfo` answers.
	CPU string
	// MemKB is the total memory, for /proc/meminfo and free.
	MemKB int
}

// The built-in profiles. Two, not six: an internet-facing telnet port is found by
// something looking for a small Linux device, and a bastion's SSH port is found by
// something looking for a server. A third shape done thinly would be a third shape
// that gets caught.
var profiles = map[string]Profile{
	// What is actually on port 23: a recorder, a camera, a router. This is the
	// shape the Mirai family and everything after it was written for.
	"busybox": {
		Name:     "busybox",
		Uname:    "Linux dvr 3.10.20 #1 SMP PREEMPT Tue Mar 5 11:40:22 CST 2019 armv7l GNU/Linux",
		Kernel:   "Linux",
		Release:  "3.10.20",
		Machine:  "armv7l",
		Hostname: "dvr",
		User:     "root",
		Busybox:  true,
		Banner:   "",
		MOTD: "\r\nBusyBox v1.20.2 (2019-03-05 11:42:19 CST) built-in shell (ash)\r\n" +
			"Enter 'help' for a list of built-in commands.\r\n\r\n",
		CPU: "processor\t: 0\nmodel name\t: ARMv7 Processor rev 5 (v7l)\n" +
			"BogoMIPS\t: 1590.78\nFeatures\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4\n" +
			"Hardware\t: Generic DT based system\n",
		MemKB: 262144,
	},
	// A small server, which is what an SSH trap is impersonating.
	"linux": {
		Name:     "linux",
		Uname:    "Linux app01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
		Kernel:   "Linux",
		Release:  "5.15.0-91-generic",
		Machine:  "x86_64",
		Hostname: "app01",
		User:     "root",
		Banner:   "\r\nUbuntu 22.04.3 LTS\r\n",
		MOTD: "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n" +
			" * Documentation:  https://help.ubuntu.com\r\n\r\n" +
			"Last login: Tue Nov 14 09:12:44 2023 from 192.0.2.31\r\n",
		CPU: "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n" +
			"cpu MHz\t\t: 2394.374\ncache size\t: 35840 KB\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic\n",
		MemKB: 4046528,
	},
}

// DefaultProfile is the profile a section that names none gets.
const DefaultProfile = "busybox"

// Profiles are the shapes a fabrication can have, for validation.
func Profiles() []string {
	out := make([]string, 0, len(profiles))
	for name := range profiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// The commands nothing legitimate types into a machine that is not there. They
// are the escalation, in the order it happens: fetch a payload, make it
// executable, run it, keep it running, and clear what would have stopped it.
var builtInTripwires = []string{
	"wget", "curl", "tftp", "ftpget", "ftpput", "nc", "ncat", "netcat",
	"chmod", "chattr", "dd", "nohup", "setsid", "insmod", "modprobe",
	"crontab", "iptables", "ip6tables", "nft", "ufw", "service", "systemctl",
	// shadow, authorized_keys and the key names are matched as the last element
	// of a path, so `cat /etc/shadow` and `cat ~/.ssh/id_rsa` raise the wire.
	// `passwd` is deliberately absent: /etc/passwd is the commonest
	// reconnaissance on any machine, and a tripwire that matched it would make
	// every session look like an escalation.
	"busybox", "shadow", "authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa",
	"tor", "xmrig", "minerd", "kinsing",
}

// The synthetic addresses the fabricated numbers live at.
const (
	addrLoad  = 1
	addrUsers = 2
)

// maxLine bounds one command, because it comes off the network.
const maxLine = 4096

// Shell is the fabrication as one listener configured it.
type Shell struct {
	profile  Profile
	hostname string
	attempts int
	trip     map[string]bool
	values   *deception.Values
	policy   *deception.Policy
	seed     uint64
	started  time.Time
	now      func() time.Time
}

// Options is a fabrication as an operator wrote it.
type Options struct {
	// Profile names a built-in shape; empty takes the default.
	Profile string
	// Hostname replaces the profile's, which is what a visitor sees in the
	// prompt and what they will quote when they tell somebody what they
	// found.
	Hostname string
	// Attempts is how many credentials are taken before the login is
	// accepted. Zero takes 1; a trap that accepted the first is a trap that
	// collects one password.
	Attempts int
	// Tripwire are command names that raise the tripwire in addition to the
	// built-in set.
	Tripwire []string
	// Clients are the networks the fabrication answers. Empty answers every
	// client.
	Clients []netip.Prefix
	// Seed makes the fabricated numbers reproducible; zero derives one from
	// the listener name.
	Seed uint64
	// Name is the listener's name, for the seed.
	Name string
	// Period is how long one sample of a fabricated number lasts.
	Period time.Duration
	// MaxClients bounds the record of who has been answered.
	MaxClients int
}

// New compiles a fabrication.
func New(o Options) (*Shell, error) {
	p, ok := profiles[o.Profile]
	if !ok {
		if o.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", o.Profile)
		}
		p = profiles[DefaultProfile]
	}
	s := &Shell{profile: p, hostname: p.Hostname, attempts: o.Attempts, trip: map[string]bool{},
		started: time.Now(), now: time.Now}
	if o.Hostname != "" {
		if !hostnameOK(o.Hostname) {
			return nil, fmt.Errorf("deception.hostname: %q is not a hostname", o.Hostname)
		}
		s.hostname = o.Hostname
	}
	if s.attempts <= 0 {
		s.attempts = 1
	}
	for _, c := range builtInTripwires {
		s.trip[c] = true
	}
	for i, c := range o.Tripwire {
		norm := strings.ToLower(strings.TrimSpace(c))
		if norm == "" || strings.ContainsAny(norm, " \t\r\n") {
			return nil, fmt.Errorf("deception.tripwire[%d]: %q is not a command name", i, c)
		}
		s.trip[norm] = true
	}
	s.seed = o.Seed
	if s.seed == 0 {
		s.seed = deception.SeedFor(o.Name)
	}
	period := o.Period
	if period <= 0 {
		period = deception.DefaultPeriod
	}
	s.values = deception.NewValues(s.seed, period, []deception.Band{
		{Lo: addrLoad, Hi: addrLoad, Shape: deception.ShapeAnalogue, Min: 1, Max: 180},
		{Lo: addrUsers, Hi: addrUsers, Shape: deception.ShapeAnalogue, Min: 1, Max: 4},
	})
	s.policy = deception.NewPolicy(o.Clients, o.MaxClients)
	return s, nil
}

func hostnameOK(s string) bool {
	if len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return s != ""
}

// Admits says whether this client gets the fabrication.
func (s *Shell) Admits(ip netip.Addr) bool { return s != nil && s.policy.Admits(ip) }

// Profile names the shape, for the status view.
func (s *Shell) Profile() string {
	if s == nil {
		return ""
	}
	return s.profile.Name
}

// Policy is the record of who has been answered, for the status view.
func (s *Shell) Policy() *deception.Policy {
	if s == nil {
		return nil
	}
	return s.policy
}

// Attempts is how many credentials are taken before the login is accepted.
func (s *Shell) Attempts() int { return s.attempts }

// Banner is the greeting written before the first login prompt.
//
// It carries no hostname, and neither does the MOTD: the machine's name reaches a
// visitor through the login prompt, the shell prompt, uname and /etc/hostname,
// which is where a real one puts it. A greeting that also carried it would be a
// fifth place to keep in step for no gain.
func (s *Shell) Banner() string { return s.profile.Banner }

// LoginPrompt is what asks for a name. It carries the hostname, because that is
// where a visitor reads it first and where they will quote it from.
func (s *Shell) LoginPrompt() string { return s.hostname + " login: " }

// PasswordPrompt is what asks for the credential.
func (s *Shell) PasswordPrompt() string { return "Password: " }

// Refusal is what a wrong credential is told, which is what every attempt
// before the last one is told -- and the last one is told it too if the caller
// is running a trap that never lets anybody in.
func (s *Shell) Refusal() string { return "\r\nLogin incorrect\r\n" }

// MOTD is what is written once a login is accepted.
func (s *Shell) MOTD() string { return s.profile.MOTD }

// SetClockForTest fixes the clock the fabricated numbers move on.
func (s *Shell) SetClockForTest(now func() time.Time, started time.Time) {
	s.now = now
	s.started = started
	s.values.SetClockForTest(now)
}

// Credential is what one login attempt leaves behind: an identity, a length, and
// a handle that correlates two attempts without disclosing either.
type Credential struct {
	// User is the name offered, clipped. It is an identity and is kept.
	User string
	// Length is the credential's length in octets. A length is worth having --
	// it separates a dictionary from a sprayed default -- and it is not the
	// credential.
	Length int
	// ID is a correlation handle, computed under a key this process made at
	// startup. Two attempts with the same credential share an ID for as long
	// as the process lives, and nothing that reads the ID afterwards can test
	// a guess against it. Empty when the process has no random source, which
	// is the safe direction: no handle rather than a testable one.
	ID string
}

// Take records one login attempt.
//
// The credential itself is used here and nowhere else: it goes into the keyed
// hash and is not returned, not stored and not logged.
func (s *Shell) Take(user, password string) Credential {
	return Credential{
		User: textsafe.Clip64(user), Length: len(password),
		ID: credentialID(credKey, password),
	}
}

// credentialID is the correlation handle, which is empty without a key.
//
// Empty is the safe direction and the reason this is a function of the key: a
// process with no random source would otherwise produce handles under a constant
// key, and a handle under a constant key is one anybody who reads the log can test
// a guess against. No handle is worth less than a testable one.
func credentialID(key []byte, password string) string {
	if len(key) == 0 {
		return ""
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(password))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:8])
}

// Session is one visitor's shell.
type Session struct {
	s *Shell
	// user is who they said they were, which is what the prompt shows.
	user string
	// dir is the working directory, because a visitor who types cd and then
	// pwd is checking.
	dir string
	// commands counts what has been typed, for the record.
	commands int
}

// Open starts a session for a visitor who has got past the login.
func (s *Shell) Open(user string) *Session {
	if user == "" {
		user = s.profile.User
	}
	return &Session{s: s, user: textsafe.Clip64(user), dir: home(user)}
}

func home(user string) string {
	if user == "root" {
		return "/root"
	}
	return "/home/" + user
}

// Prompt is what is written before each command.
func (se *Session) Prompt() string {
	mark := "$"
	if se.user == "root" {
		mark = "#"
	}
	dir := se.dir
	if dir == home(se.user) {
		dir = "~"
	}
	return fmt.Sprintf("%s@%s:%s%s ", se.user, se.s.hostname, dir, mark)
}

// Tripped says whether a command line reaches for something nothing legitimate
// types into a machine that is not there.
func (se *Session) Tripped(line string) bool {
	s := se.s
	for _, w := range words(line) {
		if s.trip[w] {
			return true
		}
		// A path names the command at its end: /bin/busybox is busybox, and
		// ../../wget is wget.
		if i := strings.LastIndexByte(w, '/'); i >= 0 && s.trip[w[i+1:]] {
			return true
		}
	}
	return false
}

// words splits a command line into the tokens a tripwire is matched against,
// lower-cased. It is deliberately not a shell parser: the point is to see the
// names, and a name inside a quoted string is still the name.
func words(line string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, strings.ToLower(b.String()))
			b.Reset()
		}
	}
	for i := 0; i < len(line) && i < maxLine; i++ {
		switch c := line[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-', c == '.', c == '/', c == '+':
			b.WriteByte(c)
		default:
			flush()
		}
	}
	flush()
	return out
}

// Run answers one command line.
//
// out is what is written back, closed says the visitor asked to leave, and the
// caller writes the prompt again unless it did.
func (se *Session) Run(line string) (out string, closed bool) {
	se.commands++
	line = strings.TrimSpace(line)
	if len(line) > maxLine {
		line = line[:maxLine]
	}
	if line == "" {
		return "", false
	}
	// A visitor's script sends several commands on one line, joined by ; or &&,
	// because that is how a one-shot payload arrives. Each is answered in turn:
	// a fabrication that answered only the first would drop the wget that came
	// after the chmod.
	parts := splitChain(line)
	if len(parts) == 0 {
		// A line of nothing but separators, which is not a command and is not
		// an error either: a shell reads it and prompts again.
		return "", false
	}
	if len(parts) > 1 {
		var b strings.Builder
		for _, p := range parts {
			o, c := se.Run(p)
			b.WriteString(o)
			if c {
				return b.String(), true
			}
		}
		return b.String(), false
	}
	fields := strings.Fields(line)
	cmd := fields[0]
	args := fields[1:]
	// A path is stripped to the command, because /bin/ls is ls -- except for
	// busybox, where the path is part of what is being asked.
	base := cmd
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	return se.answer(strings.ToLower(base), args)
}

// splitChain breaks a line at the separators a payload uses. It stops at a
// separator inside quotes, because a wget URL with a semicolon in it is one
// argument.
func splitChain(line string) []string {
	var out []string
	var b strings.Builder
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			b.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			b.WriteByte(c)
		case c == ';':
			out = append(out, b.String())
			b.Reset()
		case c == '&' && i+1 < len(line) && line[i+1] == '&':
			out = append(out, b.String())
			b.Reset()
			i++
		case c == '|' && i+1 < len(line) && line[i+1] == '|':
			out = append(out, b.String())
			b.Reset()
			i++
		default:
			b.WriteByte(c)
		}
	}
	out = append(out, b.String())
	kept := out[:0]
	for _, p := range out {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return kept
}

func (se *Session) answer(cmd string, args []string) (string, bool) {
	s := se.s
	switch cmd {
	case "exit", "logout", "quit":
		return "logout\r\n", true
	case "uname":
		return se.uname(args), false
	case "whoami":
		return se.user + "\r\n", false
	case "id":
		if se.user == "root" {
			return "uid=0(root) gid=0(root) groups=0(root)\r\n", false
		}
		return fmt.Sprintf("uid=1000(%s) gid=1000(%s) groups=1000(%s)\r\n", se.user, se.user, se.user), false
	case "hostname":
		return s.hostname + "\r\n", false
	case "pwd":
		return se.dir + "\r\n", false
	case "cd":
		if len(args) == 0 || args[0] == "~" {
			se.dir = home(se.user)
			return "", false
		}
		se.dir = cleanDir(se.dir, args[0])
		return "", false
	case "echo":
		// Answered because the Mirai family uses it as a liveness check: it
		// sends `echo <token>` and refuses to go on unless the token comes
		// back. There is nothing to run -- the argument is written out.
		return strings.Join(args, " ") + "\r\n", false
	case "ls", "dir":
		return se.ls(args), false
	case "cat":
		return se.cat(args), false
	case "uptime":
		return se.uptime(), false
	case "w", "who":
		return se.who(), false
	case "ps":
		return se.ps(), false
	case "free":
		return se.free(), false
	case "df":
		return "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n" +
			"/dev/root        1998672  743120   1150288  40% /\r\n" +
			"tmpfs             131072      64    131008   1% /tmp\r\n", false
	case "mount":
		return "/dev/root on / type ext4 (rw,relatime)\r\n" +
			"proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\r\n" +
			"tmpfs on /tmp type tmpfs (rw,nosuid,nodev)\r\n", false
	case "history":
		// Empty, which is what a machine nobody has used answers -- and a
		// fabricated history would be inventing a person.
		return "", false
	case "crontab":
		return "no crontab for " + se.user + "\r\n", false
	case "busybox":
		return se.busybox(args), false
	case "wget", "curl", "tftp", "ftpget", "ftpput":
		// The command that matters. The argument is the payload's address,
		// which is the whole reason to answer rather than refuse -- and it is
		// never fetched: a fabrication that downloaded it would be doing the
		// attacker's download, from this estate's address.
		return se.fetchFailed(cmd), false
	case "chmod", "chown", "chattr":
		return "", false
	case "nohup", "setsid":
		return "", false
	case "lsmod":
		return "Module                  Size  Used by\r\n", false
	case "rm":
		return "", false
	case "kill", "killall", "pkill":
		return "", false
	case "iptables", "ip6tables", "nft", "ufw":
		return "", false
	case "service", "systemctl", "insmod", "modprobe", "rmmod":
		return "", false
	case "ifconfig", "ip":
		return se.ifconfig(), false
	case "netstat", "ss":
		return "Active Internet connections (w/o servers)\r\n" +
			"Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n", false
	case "sh", "bash", "ash", "enable", "system", "shell", "linuxshell":
		// The sequence an IoT botnet sends the moment it is in, one word per
		// line, checking that each is accepted. Each is accepted silently,
		// which is what the real device does.
		return "", false
	case "":
		return "", false
	}
	return se.notFound(cmd), false
}

func cleanDir(cur, arg string) string {
	if strings.HasPrefix(arg, "/") {
		cur = ""
	}
	parts := strings.Split(strings.TrimSuffix(cur, "/")+"/"+arg, "/")
	var out []string
	for _, p := range parts {
		switch p {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			if len(out) < 16 {
				out = append(out, p)
			}
		}
	}
	return "/" + strings.Join(out, "/")
}

func (se *Session) uname(args []string) string {
	p := se.s.profile
	if len(args) == 0 {
		return p.Kernel + "\r\n"
	}
	flags := strings.Join(args, "")
	switch {
	case strings.Contains(flags, "a"):
		return strings.ReplaceAll(p.Uname, p.Hostname, se.s.hostname) + "\r\n"
	case strings.Contains(flags, "m"), strings.Contains(flags, "p"):
		return p.Machine + "\r\n"
	case strings.Contains(flags, "r"):
		return p.Release + "\r\n"
	case strings.Contains(flags, "n"):
		return se.s.hostname + "\r\n"
	}
	return p.Kernel + "\r\n"
}

func (se *Session) ls(args []string) string {
	dir := se.dir
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			dir = cleanDir(se.dir, a)
		}
	}
	switch dir {
	case "/":
		return "bin  dev  etc  home  lib  mnt  proc  root  sbin  sys  tmp  usr  var\r\n"
	case "/etc":
		return "hostname  hosts  init.d  passwd  resolv.conf  shadow\r\n"
	}
	// Empty, and it matters that it is. /tmp is where a payload lands, so a
	// visitor who found something of theirs there would be looking at a machine
	// that had kept it -- and one who found somebody else's would have found a
	// honeypot other people have used. A directory nobody has written to lists
	// nothing, which is both true here and the least interesting answer.
	return ""
}

func (se *Session) cat(args []string) string {
	if len(args) == 0 {
		return ""
	}
	p := se.s.profile
	switch cleanDir("/", args[0]) {
	case "/proc/cpuinfo":
		return crlf(p.CPU)
	case "/proc/meminfo":
		return crlf(fmt.Sprintf("MemTotal:       %8d kB\nMemFree:        %8d kB\nMemAvailable:   %8d kB\n",
			p.MemKB, p.MemKB/4, p.MemKB/3))
	case "/proc/mounts":
		return "/dev/root / ext4 rw,relatime 0 0\r\nproc /proc proc rw,nosuid,nodev,noexec 0 0\r\n"
	case "/etc/hostname":
		return se.s.hostname + "\r\n"
	case "/etc/hosts":
		return "127.0.0.1\tlocalhost\r\n127.0.1.1\t" + se.s.hostname + "\r\n"
	case "/etc/passwd":
		return "root:x:0:0:root:/root:/bin/sh\r\n" +
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n" +
			"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n"
	case "/etc/shadow":
		// The accounts, and no hash: `*` is what a real file says for an
		// account with no password login, so the shape is right and there is no
		// fabricated hash for anybody to spend a machine on -- or to mistake
		// for a real one later.
		return "root:*:19000:0:99999:7:::\r\ndaemon:*:19000:0:99999:7:::\r\n"
	case "/etc/resolv.conf":
		return "nameserver 192.0.2.1\r\nnameserver 192.0.2.2\r\n"
	}
	return "cat: " + textsafe.Clip64(args[0]) + ": No such file or directory\r\n"
}

func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

func (se *Session) uptime() string {
	s := se.s
	up := s.now().Sub(s.started)
	if up < time.Minute {
		up = time.Minute
	}
	load := float64(s.values.Register(0, addrLoad)) / 100
	return fmt.Sprintf(" %s up %s,  %d user,  load average: %.2f, %.2f, %.2f\r\n",
		s.now().UTC().Format("15:04:05"), humanUptime(up), s.users(), load, load*0.9, load*0.8)
}

// users is how many people the fabrication says are logged in. It moves between
// periods, because a machine that always has exactly one is a machine nobody is
// using -- and this visitor is one of them.
//
// The band's own minimum is 1, so there is no second floor to apply here and a
// guard for one would be a guard nothing reaches.
func (s *Shell) users() int { return int(s.values.Register(0, addrUsers)) }

func humanUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d days, %2d:%02d", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%2d:%02d", hours, mins)
	}
	return strconv.Itoa(mins) + " min"
}

func (se *Session) who() string {
	return fmt.Sprintf("%s     pts/0        %s (192.0.2.%d)\r\n",
		se.user, se.s.now().UTC().Format("15:04"), 10+se.s.users())
}

func (se *Session) ps() string {
	if se.s.profile.Busybox {
		return "  PID USER       VSZ STAT COMMAND\r\n" +
			"    1 root      2044 S    init\r\n" +
			"  128 root      1868 S    /sbin/syslogd -n\r\n" +
			"  310 root      2044 S    telnetd\r\n" +
			"  512 root      1996 R    ps\r\n"
	}
	return "  PID TTY          TIME CMD\r\n" +
		"    1 ?        00:00:04 systemd\r\n" +
		"  412 ?        00:00:00 sshd\r\n" +
		"  980 pts/0    00:00:00 bash\r\n" +
		"  994 pts/0    00:00:00 ps\r\n"
}

func (se *Session) free() string {
	kb := se.s.profile.MemKB
	return "              total        used        free      shared  buff/cache   available\r\n" +
		fmt.Sprintf("Mem:       %8d    %8d    %8d       %5d    %8d    %8d\r\n",
			kb, kb/2, kb/4, kb/64, kb/4, kb/3) +
		"Swap:             0           0           0\r\n"
}

func (se *Session) ifconfig() string {
	return "eth0      Link encap:Ethernet  HWaddr " + se.mac() + "\r\n" +
		"          inet addr:192.0.2.50  Bcast:192.0.2.255  Mask:255.255.255.0\r\n" +
		"          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n"
}

// mac is a fabricated hardware address out of the range reserved for
// documentation, so it cannot collide with a real device and cannot be looked up
// as a vendor.
func (se *Session) mac() string {
	h := se.s.hash("mac", se.s.hostname)
	return fmt.Sprintf("00:00:5E:%02X:%02X:%02X", byte(h>>16), byte(h>>8), byte(h))
}

func (se *Session) busybox(args []string) string {
	if !se.s.profile.Busybox {
		return se.notFound("busybox")
	}
	if len(args) == 0 {
		return "BusyBox v1.20.2 (2019-03-05 11:42:19 CST) multi-call binary.\r\n"
	}
	// What real busybox says for a word that is not an applet, which is exactly
	// what the botnet sends its own name as and checks for.
	return textsafe.Clip64(args[0]) + ": applet not found\r\n"
}

func (se *Session) fetchFailed(cmd string) string {
	switch cmd {
	case "wget":
		return "Connecting to 192.0.2.1:80 (192.0.2.1:80)\r\nwget: can't connect to remote host: Connection timed out\r\n"
	case "curl":
		return "curl: (7) Failed to connect: Connection timed out\r\n"
	case "tftp":
		return "tftp: can't connect to remote host: Connection timed out\r\n"
	}
	return cmd + ": can't connect to remote host: Connection timed out\r\n"
}

func (se *Session) notFound(cmd string) string {
	if se.s.profile.Busybox {
		return "-sh: " + textsafe.Clip64(cmd) + ": not found\r\n"
	}
	return "bash: " + textsafe.Clip64(cmd) + ": command not found\r\n"
}

// hash is the fabrication's source of derived values: the seed, a purpose and a
// name, so that two listeners answer differently and one answers the same way
// after a restart.
func (s *Shell) hash(purpose, name string) uint64 {
	f := fnv.New64a()
	var eight [8]byte
	binary.BigEndian.PutUint64(eight[:], s.seed)
	_, _ = f.Write(eight[:])
	_, _ = f.Write([]byte(purpose))
	_, _ = f.Write([]byte{0})
	_, _ = f.Write([]byte(strings.ToLower(name)))
	return f.Sum64()
}
