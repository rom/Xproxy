package syslog_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The bounds and the modes around the relay, rather than the records through
// it: how many senders may be connected, what a sender that speaks TLS from
// its first octet gets, what shadow mode does with a policy drop, and where a
// refusal goes besides the counter.

// relayWith builds a listener with a block inside the syslog section and a
// block of its own beside it -- `tls:` and `policy:` are listener settings
// rather than syslog ones -- plus anything at the top of the file.
func relayWith(t *testing.T, section, listener, top string) (*proxy.Server, *collector) {
	t.Helper()
	col := startCollector(t)
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: logs
      address: "127.0.0.1:0"
      kind: syslog
%s
      syslog:
        upstream: collectors
%s
%s
logging: {access: {enabled: false}}
upstreams:
  - name: collectors
    endpoints: [{address: %s}]
`, listener, section, top, col.addr()))
	return s, col
}

// A syslog listener's senders are long-lived connections from kit nobody
// logs into, so the number of them is a bound an estate sets and the relay
// holds. The refusal is at accept, before a frame is read: a connection past
// the bound has not said anything yet, and reading it to find out would be the
// work the bound exists to avoid.
func TestNoMoreSendersThanTheBoundAllows(t *testing.T) {
	s, _ := relayWith(t, `        udp: false
        max_connections: 1`, "", "")
	addr := s.Addrs()["logs"]

	first, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	// A record, so the relay has certainly accepted and is holding it.
	if _, err := io.WriteString(first, "<13>1 - h a - - - the first sender\n"); err != nil {
		t.Fatal(err)
	}
	waitStat(t, s, "syslog_connections", func(sn proxy.Snapshot) uint64 { return sn.SyslogConnections }, 1)

	second, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	waitStat(t, s, "syslog_rejected", func(sn proxy.Snapshot) uint64 { return sn.SyslogRejected }, 1)
	if got := s.Stats().Refusals["syslog"]["max_connections"]; got == 0 {
		t.Errorf("the refusal was not labelled: %v", s.Stats().Refusals["syslog"])
	}
	// The connection the bound refused is closed rather than left open with
	// nobody reading it.
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Error("the refused connection was left open")
	}
}

// A sender that speaks TLS from its first octet, which is RFC 5425's own
// transport. The handshake is the admission: a sender that cannot complete it
// never reaches the framing, so a plain-text connection to this listener is
// refused rather than read as syslog.
func TestASenderOnTheTLSPortHasToSpeakIt(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "127.0.0.1")
	s, col := relayWith(t, `        udp: false
        tls_mode: implicit`,
		fmt.Sprintf("      tls:\n        certificates: [{cert_file: %s, key_file: %s}]", cert, key), "")
	addr := s.Addrs()["logs"]

	// The sender that does speak it: its record arrives.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		t.Fatal("the test CA did not read back")
	}
	tc, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("a TLS sender was refused: %v", err)
	}
	defer func() { _ = tc.Close() }()
	if _, err := io.WriteString(tc, "<13>1 - h a - - - over TLS\n"); err != nil {
		t.Fatal(err)
	}
	if got := col.waitFor(t, 1); !strings.Contains(got[0], "over TLS") {
		t.Errorf("records: %v", got)
	}

	// And the one that does not: the bytes it sent are not read as a record.
	plain, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	if _, err := io.WriteString(plain,
		"<13>1 - h a - - - in the clear on the TLS port\n"); err != nil {
		t.Fatal(err)
	}
	// The handshake fails rather than the record arriving, so what is waited
	// for is the absence: the connection the relay gave up on is closed.
	_ = plain.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = plain.Read(make([]byte, 1))
	for _, m := range col.seen() {
		if strings.Contains(m, "in the clear") {
			t.Errorf("a plain-text record reached the collector on an implicit TLS listener: %q", m)
		}
	}
}

// A datagram over the message bound is refused unread, the same as a counted
// frame is. On UDP there is nothing to resynchronise -- the datagram is the
// message -- so the only question is whether it is counted, and a bound that
// drops silently is a bound nobody can see working.
func TestAnOversizeDatagramIsRefusedAndCounted(t *testing.T) {
	s, col := relayWith(t, `        udp: true
        max_message_bytes: 480`, "", "")
	uc, err := net.Dial("udp", s.Addrs()["logs"])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = uc.Close() }()
	if _, err := uc.Write([]byte("<13>1 - h a - - - " + strings.Repeat("x", 900))); err != nil {
		t.Fatal(err)
	}
	waitStat(t, s, "syslog_refused", func(sn proxy.Snapshot) uint64 { return sn.SyslogRefused }, 1)
	if got := s.Stats().Refusals["syslog"]["too_large"]; got == 0 {
		t.Errorf("the refusal was not labelled too_large: %v", s.Stats().Refusals["syslog"])
	}
	if got := col.seen(); len(got) != 0 {
		t.Errorf("the oversize datagram arrived anyway: %v", got)
	}
}

// Shadow mode on this kind: the policy drops are recorded and the record is
// carried. That is how a filter is turned on in front of an estate's real log
// traffic -- a facility list written from a guess would otherwise take out the
// records somebody is paged on -- and it covers the policy only. A malformed
// message, the rate limit and a full queue are still refused, because none of
// them is a question about what this estate carries.
func TestInShadowModeTheFilterSaysWhatItWouldHaveDropped(t *testing.T) {
	s, col := relayWith(t, `        udp: false
        allow_facilities: [local4]`, "      policy: {mode: shadow}", "")
	// Facility 2 (mail), which the allow list does not name.
	sendSyslog(t, s.Addrs()["logs"], "<22>1 - h a - - - mail would have been dropped")
	got := col.waitFor(t, 1)
	if !strings.Contains(got[0], "would have been dropped") {
		t.Errorf("shadow mode dropped the record: %v", got)
	}
	waitStat(t, s, "syslog_would_deny", func(sn proxy.Snapshot) uint64 {
		return sn.WouldRefusals["syslog"]["facility"]
	}, 1)
	rep := s.Shadow().Report()
	if len(rep) == 0 {
		t.Fatal("the shadow report is empty")
	}
	for _, e := range rep {
		if e.Kind != "syslog" || e.Listener != "logs" || e.Reason != "facility" {
			t.Errorf("the shadow report: %+v", e)
		}
	}
}

// Where a refusal goes besides the counter: the ban ladder hears about it
// before alert_on_deny can silence the record, because turning the log down is
// not a decision to stop responding.
func TestARefusalReachesTheBanLadderEvenWithTheAlertsOff(t *testing.T) {
	dir := t.TempDir()
	s, col := relayWith(t, `        udp: false
        alert_on_deny: false
        allow_senders: ["192.0.2.0/24"]`, "",
		"bans:\n  action: reject\n  state_file: "+filepath.Join(dir, "bans.state"))
	sendSyslog(t, s.Addrs()["logs"], "<13>1 - h a - - - from a stranger")
	waitStat(t, s, "syslog_refused", func(sn proxy.Snapshot) uint64 { return sn.SyslogRefused }, 1)
	if got := col.seen(); len(got) != 0 {
		t.Errorf("a refused sender's record arrived: %v", got)
	}
}

// A section that loads and cannot be built. The listener's UDP socket is
// taken before the server is, so the failure has to give it back: a start
// that left the port bound would mean the next start of the same
// configuration failed for a reason that is not the reason.
func TestASectionThatLoadsAndCannotBeBuiltIsAFailedStart(t *testing.T) {
	dir := t.TempDir()
	// A file that exists, so the configuration loads, and is not a
	// certificate, so the trust store for the collector cannot be built.
	notACert := filepath.Join(dir, "not-a-certificate.pem")
	if err := os.WriteFile(notACert, []byte("this is not PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: logs
      address: "127.0.0.1:0"
      kind: syslog
      syslog:
        upstream: collectors
        udp: true
        upstream_tls_mode: verify
        upstream_tls: {ca_file: %s}
logging: {access: {enabled: false}}
upstreams:
  - name: collectors
    endpoints: [{address: "127.0.0.1:6514"}]
`, notACert)
	err := proxytest.StartError(t, yaml)
	if err == nil {
		t.Fatal("the listener was built")
	}
	if !strings.Contains(err.Error(), "upstream_tls") {
		t.Errorf("%v does not say which section", err)
	}
}

// A counted frame whose length header promises more than the bound allows
// ends the connection, because the stream is then at an offset nobody knows.
// That is the difference from the newline framing, where the reader can skip
// to the next boundary and the records behind the long one still arrive.
func TestACountedFrameOverTheBoundEndsTheConnection(t *testing.T) {
	s, col := relayWith(t, `        udp: false
        framing: octet_counting
        max_message_bytes: 480`, "", "")
	c, err := net.DialTimeout("tcp", s.Addrs()["logs"], 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	body := "<13>1 - h a - - - " + strings.Repeat("x", 900)
	if _, err := fmt.Fprintf(c, "%d %s", len(body), body); err != nil {
		t.Fatal(err)
	}
	waitStat(t, s, "syslog_refused", func(sn proxy.Snapshot) uint64 { return sn.SyslogRefused }, 1)
	if got := s.Stats().Refusals["syslog"]["framing"]; got == 0 {
		t.Errorf("the refusal was not labelled framing: %v", s.Stats().Refusals["syslog"])
	}
	if got := col.seen(); len(got) != 0 {
		t.Errorf("the oversize frame arrived anyway: %v", got)
	}
}
