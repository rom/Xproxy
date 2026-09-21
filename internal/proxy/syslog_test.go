package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// collector is a stand-in for a syslog collector: it reads
// octet-counted frames and records them.
type collector struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
}

func startCollector(t *testing.T) *collector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.read(conn)
		}
	}()
	return c
}

func (c *collector) addr() string { return c.ln.Addr().String() }

func (c *collector) read(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	for {
		var digits []byte
		for {
			b, err := br.ReadByte()
			if err != nil {
				return
			}
			if b == ' ' {
				break
			}
			digits = append(digits, b)
			if len(digits) > 10 {
				return
			}
		}
		n, err := strconv.Atoi(string(digits))
		if err != nil || n <= 0 || n > 1<<20 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		c.mu.Lock()
		c.msgs = append(c.msgs, string(buf))
		c.mu.Unlock()
	}
}

func (c *collector) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.msgs...)
}

// waitForRecords polls until the collector has at least n records, so
// the test waits for the relay rather than for a fixed pause.
func (c *collector) waitFor(t *testing.T, n int) []string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if got := c.seen(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the collector saw %d records, want %d", len(c.seen()), n)
	return nil
}

func syslogRelay(t *testing.T, extra string) (*Server, string, *collector) {
	t.Helper()
	col := startCollector(t)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: logs
      address: "127.0.0.1:0"
      kind: syslog
      syslog:
        upstream: collectors
        udp: false
%s
logging: {access: {enabled: false}}
upstreams:
  - name: collectors
    endpoints: [{address: %s}]
`, extra, col.addr())
	s, _ := startServer(t, yaml)
	return s, s.Addrs()["logs"], col
}

// sendSyslog writes one line-delimited message to the relay.
func sendSyslog(t *testing.T, addr string, lines ...string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	for _, l := range lines {
		if _, err := io.WriteString(c, l+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// Whatever arrives, one dialect leaves: the record the collector stores
// is the record the relay decided about.
func TestSyslogNormalises(t *testing.T) {
	_, addr, col := syslogRelay(t, "        hostname: keep")
	sendSyslog(t, addr,
		"<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed",
		`<13>1 2026-09-21T14:30:22Z host app 99 ID1 - structured message`)
	got := col.waitFor(t, 2)
	if !strings.HasPrefix(got[0], "<34>1 ") {
		t.Errorf("an RFC 3164 message was not re-emitted as 5424: %q", got[0])
	}
	if !strings.Contains(got[0], " mymachine su 1234 ") {
		t.Errorf("fields lost: %q", got[0])
	}
	if !strings.Contains(got[0], "'su root' failed") {
		t.Errorf("text lost: %q", got[0])
	}
	if !strings.HasPrefix(got[1], "<13>1 2026-09-21T14:30:22Z host app 99 ID1 ") {
		t.Errorf("a 5424 message was changed: %q", got[1])
	}
}

// A newline in the text would be two records in any collector that
// frames on newlines, and the second one says whatever the sender
// wanted a record to say.
func TestSyslogCannotInjectARecord(t *testing.T) {
	_, addr, col := syslogRelay(t, "        hostname: keep")
	// The injection has to reach the relay as one message, so it is
	// sent with a counted frame.
	payload := "<13>1 - host app - - - ok\\n<0>1 - evil - - - - the admin did it"
	sendSyslog(t, addr, payload)
	got := col.waitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("%d records reached the collector", len(got))
	}
	for _, m := range got {
		if strings.Contains(m, "\n") {
			t.Errorf("a forwarded record carries a newline: %q", m)
		}
		if strings.HasPrefix(m, "<0>") {
			t.Errorf("a forged record was emitted: %q", m)
		}
	}
}

// The sender's host name is never the true one. annotate keeps both and
// says which is which; observed replaces it.
func TestSyslogHostnamePolicy(t *testing.T) {
	_, addr, col := syslogRelay(t, "        hostname: annotate")
	sendSyslog(t, addr, "<13>1 - claimed-host app - - - hello")
	got := col.waitFor(t, 1)
	if !strings.Contains(got[0], "claimed-host") {
		t.Errorf("the claimed name was dropped: %q", got[0])
	}
	if !strings.Contains(got[0], "xproxyOrigin@0") || !strings.Contains(got[0], `ip="127.0.0.1"`) {
		t.Errorf("the observed address was not recorded: %q", got[0])
	}

	_, addr2, col2 := syslogRelay(t, "        hostname: observed")
	sendSyslog(t, addr2, "<13>1 - claimed-host app - - - hello")
	got2 := col2.waitFor(t, 1)
	if strings.Contains(got2[0], "claimed-host") {
		t.Errorf("the claimed name survived observed: %q", got2[0])
	}
	if !strings.Contains(got2[0], " 127.0.0.1 app ") {
		t.Errorf("the observed address is not the hostname: %q", got2[0])
	}
}

// Facility and severity are what a message claims to be, and a relay
// that cannot filter on them is a relay that forwards a flood of debug
// as readily as an auth failure.
func TestSyslogFilters(t *testing.T) {
	s, addr, col := syslogRelay(t, `        allow_facilities: [auth, authpriv]
        min_severity: warning`)
	sendSyslog(t, addr,
		"<34>1 - h a - - - kept: auth.crit",        // facility 4, severity 2
		"<38>1 - h a - - - dropped: auth.info",     // severity 6, less than warning
		"<13>1 - h a - - - dropped: user.notice",   // facility 1, not on the list
		"<84>1 - h a - - - kept: authpriv.warning", // facility 10, severity 4
	)
	col.waitFor(t, 1)
	// The dropped ones would arrive after the kept ones, so the pause
	// is what makes "they never arrived" mean something.
	time.Sleep(50 * time.Millisecond)
	got := col.seen()
	for _, m := range got {
		if strings.Contains(m, "dropped") {
			t.Errorf("a filtered record arrived: %q", m)
		}
		if strings.Contains(m, "auth.info") {
			t.Errorf("a record less severe than min_severity arrived: %q", m)
		}
	}
	if len(got) != 2 {
		t.Fatalf("%d records arrived, want 2: %v", len(got), got)
	}
	if sn := s.stats.snapshot(); sn.SyslogDropped != 2 {
		t.Errorf("dropped counted: %d", sn.SyslogDropped)
	}
}

// A message the relay could not read is a message whose facility,
// severity and host are unknown, which is every field a rule decides
// on.
func TestSyslogRefusesMalformed(t *testing.T) {
	s, addr, col := syslogRelay(t, "")
	sendSyslog(t, addr,
		"not a syslog message at all",
		"<999>1 - h a - - - priority out of range",
		"<13>1 - h a - - - fine",
	)
	col.waitFor(t, 1)
	if got := col.seen(); len(got) != 1 || !strings.Contains(got[0], "fine") {
		t.Fatalf("records: %v", got)
	}
	if sn := s.stats.snapshot(); sn.SyslogRefused < 2 {
		t.Errorf("refusals counted: %d", sn.SyslogRefused)
	}
}

// Redaction keeps the record and takes out the part that should not be
// stored, and says that it did.
func TestSyslogRedacts(t *testing.T) {
	_, addr, col := syslogRelay(t, `        redact:
          - {name: card, pattern: "[0-9]{13,16}", with: "[card]"}`)
	sendSyslog(t, addr, "<13>1 - h a - - - payment 4111111111111111 taken")
	got := col.waitFor(t, 1)
	if strings.Contains(got[0], "4111111111111111") {
		t.Errorf("the number survived: %q", got[0])
	}
	if !strings.Contains(got[0], "[card]") {
		t.Errorf("no replacement: %q", got[0])
	}
	if !strings.Contains(got[0], `xproxyRedaction@0 rule="card"`) {
		t.Errorf("the redaction was not recorded: %q", got[0])
	}
}

// Senders outside allow_senders write nothing.
func TestSyslogSenderPolicy(t *testing.T) {
	s, addr, col := syslogRelay(t, `        allow_senders: ["192.0.2.0/24"]`)
	sendSyslog(t, addr, "<13>1 - h a - - - from a stranger")
	time.Sleep(100 * time.Millisecond)
	if got := col.seen(); len(got) != 0 {
		t.Fatalf("a refused sender's records arrived: %v", got)
	}
	if sn := s.stats.snapshot(); sn.SyslogRefused == 0 {
		t.Error("the refusal was not counted")
	}
}

// A message over the bound does not take the connection or the message
// behind it with it.
func TestSyslogOversize(t *testing.T) {
	s, addr, col := syslogRelay(t, "        max_message_bytes: 512")
	sendSyslog(t, addr,
		"<13>1 - h a - - - "+strings.Repeat("x", 900),
		"<13>1 - h a - - - after the long one",
	)
	got := col.waitFor(t, 1)
	if len(got) != 1 || !strings.Contains(got[0], "after the long one") {
		t.Fatalf("records: %v", got)
	}
	if sn := s.stats.snapshot(); sn.SyslogRefused == 0 {
		t.Error("the oversize message was not counted")
	}
}

// A flood from one sender is a denial of service on the collector, so
// it is bounded per sender.
func TestSyslogRateLimit(t *testing.T) {
	s, addr, col := syslogRelay(t, `        rate_limit: 5
        rate_burst: 5`)
	lines := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		lines = append(lines, fmt.Sprintf("<13>1 - h a - - - message %d", i))
	}
	sendSyslog(t, addr, lines...)
	col.waitFor(t, 1)
	time.Sleep(100 * time.Millisecond)
	if got := col.seen(); len(got) > 12 {
		t.Fatalf("%d records got through a limit of 5 a second", len(got))
	}
	if sn := s.stats.snapshot(); sn.SyslogRateLimited == 0 {
		t.Error("nothing was rate limited")
	}
}
