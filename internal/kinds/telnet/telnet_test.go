package telnet_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/telnet"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/sessions"
	wire "github.com/rom/xproxy/internal/telnet"
)

// targetTelnet is a minimal telnet server: it records what reached it
// and answers with what it was told to.
type targetTelnet struct {
	ln    net.Listener
	t     *testing.T
	mu    chan struct{}
	got   []byte
	greet string
}

func startTarget(t *testing.T) *targetTelnet {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg := &targetTelnet{ln: ln, t: t, mu: make(chan struct{}, 1), greet: "target ready\r\n"}
	tg.mu <- struct{}{}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.WriteString(c, tg.greet)
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						<-tg.mu
						tg.got = append(tg.got, buf[:n]...)
						tg.mu <- struct{}{}
						// Echo the data back so a recording has output.
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return tg
}

func (tg *targetTelnet) addr() string { return tg.ln.Addr().String() }

func (tg *targetTelnet) seen() []byte {
	<-tg.mu
	defer func() { tg.mu <- struct{}{} }()
	return append([]byte(nil), tg.got...)
}

// waitSeen waits for the target to have received something matching.
func (tg *targetTelnet) waitSeen(t *testing.T, want []byte) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if bytes.Contains(tg.seen(), want) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func gateway(t *testing.T, extra string) (*proxy.Server, string, *targetTelnet) {
	t.Helper()
	tg := startTarget(t)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: legacy
      address: "127.0.0.1:0"
      kind: telnet
      telnet:
        upstream: kit
%s
logging: {access: {enabled: false}}
upstreams:
  - name: kit
    endpoints: [{address: %s}]
`, extra, tg.addr())
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["legacy"], tg
}

// conn is a client that speaks enough telnet to be one.
type conn struct {
	t *testing.T
	c net.Conn
}

func dial(t *testing.T, addr string) *conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &conn{t: t, c: c}
}

func (c *conn) write(b []byte) {
	c.t.Helper()
	if _, err := c.c.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// readUntil reads until want appears or the deadline passes, and
// returns everything read.
func (c *conn) readUntil(want string) string {
	c.t.Helper()
	var got []byte
	buf := make([]byte, 1024)
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		n, err := c.c.Read(buf)
		got = append(got, buf[:n]...)
		if want != "" && bytes.Contains(got, []byte(want)) {
			return string(got)
		}
		if err != nil {
			return string(got)
		}
	}
}

// A session reaches the target and what was typed arrives.
func TestSessionReachesTheTarget(t *testing.T) {
	_, addr, tg := gateway(t, "")
	c := dial(t, addr)
	if out := c.readUntil("target ready"); !strings.Contains(out, "target ready") {
		t.Fatalf("no greeting: %q", out)
	}
	c.write([]byte("show version\r\n"))
	if !tg.waitSeen(t, []byte("show version")) {
		t.Errorf("the target did not get the command: %q", tg.seen())
	}
}

// An option the policy does not allow is refused here, and the side
// that asked is answered so it stops asking.
func TestARefusedOptionIsAnsweredAndNotForwarded(t *testing.T) {
	s, addr, tg := gateway(t, "        allow_options: [echo, suppress-go-ahead]")
	c := dial(t, addr)
	c.readUntil("target ready")

	// new-environ is not allowed: it carries variables to the target.
	c.write(wire.Negotiation(wire.WILL, wire.OptNewEnviron))
	// The proxy answers DONT.
	got := c.readUntil(string([]byte{wire.IAC, wire.DONT, wire.OptNewEnviron}))
	if !bytes.Contains([]byte(got), []byte{wire.IAC, wire.DONT, wire.OptNewEnviron}) {
		t.Errorf("the client was not answered: %v", []byte(got))
	}
	// And the target never heard of it.
	c.write([]byte("marker\r\n"))
	tg.waitSeen(t, []byte("marker"))
	if bytes.Contains(tg.seen(), []byte{wire.IAC, wire.WILL, wire.OptNewEnviron}) {
		t.Error("a refused option reached the target")
	}
	if sn := s.Stats(); sn.TelnetOptionsRefused == 0 {
		t.Error("the refusal was not counted")
	}
}

// An allowed option passes through both ways, so a terminal that needs
// one still works.
func TestAnAllowedOptionIsForwarded(t *testing.T) {
	_, addr, tg := gateway(t, "        allow_options: [echo, suppress-go-ahead, naws]")
	c := dial(t, addr)
	c.readUntil("target ready")
	c.write(wire.Negotiation(wire.WILL, wire.OptNAWS))
	if !tg.waitSeen(t, []byte{wire.IAC, wire.WILL, wire.OptNAWS}) {
		t.Errorf("an allowed option did not reach the target: %v", tg.seen())
	}
}

// A subnegotiation with no end would grow a buffer for as long as the
// peer keeps sending.
func TestAnEndlessSubnegotiationEndsTheSession(t *testing.T) {
	s, addr, _ := gateway(t, "        allow_options: [terminal-type]\n        max_subnegotiation: 128")
	c := dial(t, addr)
	c.readUntil("target ready")
	c.write(append([]byte{wire.IAC, wire.SB, wire.OptTerminalType}, bytes.Repeat([]byte{'x'}, 500)...))
	// The session ends rather than the buffer growing.
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	for {
		if _, err := c.c.Read(buf); err != nil {
			break
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Stats().TelnetRefused == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Stats().TelnetRefused == 0 {
		t.Error("an endless subnegotiation was not refused")
	}
}

// The recording holds what the session showed, named after the person.
func TestRecordingHoldsWhatWasShown(t *testing.T) {
	dir := t.TempDir()
	s, addr, _ := gateway(t, "        recording: {directory: "+dir+"}")
	c := dial(t, addr)
	c.readUntil("target ready")
	c.write([]byte("uptime\r\n"))
	c.readUntil("uptime")
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
	for _, want := range []string{"target ready", "uptime", "XPROXY_PROTOCOL"} {
		if !strings.Contains(text, want) {
			t.Errorf("the recording does not carry %q:\n%s", want, text)
		}
	}
}

func enrol(t *testing.T, user string) (string, string) {
	t.Helper()
	secret, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mfa")
	if err := os.WriteFile(path, []byte(user+":"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, secret
}

func totp(t *testing.T, secret string) string {
	t.Helper()
	raw, err := mfa.ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	c, err := mfa.Code(raw, mfa.Counter(time.Now(), 30*time.Second), mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The factor is asked for before the target is dialled, so a client
// that cannot answer never reaches the equipment.
func TestTheFactorIsAskedForBeforeTheTargetIsDialled(t *testing.T) {
	file, secret := enrol(t, "alice")
	s, addr, tg := gateway(t, "        mfa: {file: "+file+"}")

	// A wrong code: the target is never dialled.
	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	c.readUntil("code: ")
	c.write([]byte("000000\r\n"))
	if out := c.readUntil("not accepted"); !strings.Contains(out, "not accepted") {
		t.Errorf("a wrong code was not refused: %q", out)
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("the target was reached without the factor: %q", got)
	}
	if sn := s.Stats(); sn.TelnetMFAFailed != 1 {
		t.Errorf("telnet_mfa_failed %d, want 1", sn.TelnetMFAFailed)
	}

	// The right code: the session goes through.
	c2 := dial(t, addr)
	c2.readUntil("login: ")
	c2.write([]byte("alice\r\n"))
	c2.readUntil("code: ")
	c2.write([]byte(totp(t, secret) + "\r\n"))
	if out := c2.readUntil("target ready"); !strings.Contains(out, "target ready") {
		t.Errorf("the right code did not open the session: %q", out)
	}
	if sn := s.Stats(); sn.TelnetMFAOK != 1 {
		t.Errorf("telnet_mfa_ok %d, want 1", sn.TelnetMFAOK)
	}
}

// A name with no enrolment cannot decline the factor by not having one.
func TestUnenrolledNameIsRefused(t *testing.T) {
	file, _ := enrol(t, "alice")
	_, addr, tg := gateway(t, "        mfa: {file: "+file+"}")
	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("mallory\r\n"))
	c.readUntil("code: ")
	c.write([]byte("123456\r\n"))
	if out := c.readUntil("not accepted"); !strings.Contains(out, "not accepted") {
		t.Errorf("an unenrolled name was not refused: %q", out)
	}
	if got := tg.seen(); len(got) != 0 {
		t.Errorf("an unenrolled name reached the target: %q", got)
	}
}

// The code is not echoed, for the same reason a password is not.
func TestTheCodeIsNotEchoed(t *testing.T) {
	file, _ := enrol(t, "alice")
	_, addr, _ := gateway(t, "        mfa: {file: "+file+"}")
	c := dial(t, addr)
	c.readUntil("login: ")
	c.write([]byte("alice\r\n"))
	out := c.readUntil("code: ")
	// The proxy takes over echoing for the code line.
	if !bytes.Contains([]byte(out), []byte{wire.IAC, wire.WILL, wire.OptEcho}) {
		t.Errorf("the proxy did not take over echoing before the code: %v", []byte(out))
	}
}

// A live session appears in the table with the target it reached, and an
// operator closing it drops the client. This is the bastion operation
// the table exists for, tested through a real session rather than the
// table's own unit tests.
func TestALiveSessionIsListedAndCanBeClosed(t *testing.T) {
	s, addr, _ := gateway(t, "")
	c := dial(t, addr)
	c.readUntil("target ready")

	var v sessions.View
	deadline := time.Now().Add(5 * time.Second)
	for {
		live := s.Sessions().List()
		if len(live) == 1 && live[0].Target != "" {
			v = live[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the session was not listed: %+v", live)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if v.Kind != "telnet" || v.Listener != "legacy" || v.Client == "" {
		t.Fatalf("listed %+v", v)
	}
	if _, ok := s.Sessions().Kill(v.ID); !ok {
		t.Fatal("the session was not there to close")
	}
	// The client's connection ends.
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	for {
		if _, err := c.c.Read(buf); err != nil {
			break
		}
	}
	// And the table forgets it once the serving goroutine notices.
	for deadline = time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if s.Sessions().Len() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := s.Sessions().Len(); n != 0 {
		t.Errorf("%d sessions still listed after the session ended", n)
	}
	if st := s.Sessions().Status(); st.Killed != 1 || st.Opened != 1 || st.Closed != 1 {
		t.Errorf("status %+v", st)
	}
}
