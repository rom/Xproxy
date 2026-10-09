package syslog

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// What is refused at load, and the rate limiter's own arithmetic.
//
// Every list in this section is compiled once, when the listener is built, and
// a name or a pattern this relay cannot compile has to stop the start. The
// alternative is a relay running with a list that matches nothing: a deny
// pattern that failed to compile would be a redaction rule nobody notices is
// gone, and on this protocol the redaction is the only thing between a
// password in a log line and the collector.

func syslogServer(t *testing.T, l *config.SyslogListener) error {
	t.Helper()
	_, err := newServer(nil, config.Listener{Name: "relay", Syslog: l}, nil, nil, nil)
	return err
}

func TestEveryListIsCompiledWhenTheListenerIsBuilt(t *testing.T) {
	notACert := filepath.Join(t.TempDir(), "not-a-certificate.pem")
	if err := os.WriteFile(notACert, []byte("this is not PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		l    config.SyslogListener
		want string
	}{
		// The framings on each side are separate settings, and either one
		// naming something nothing implements is a load error rather than a
		// framing chosen for the operator -- under the wrong framing one
		// record's tail is the next record's head.
		{"the framing from the senders", config.SyslogListener{Framing: "newline"}, "framing"},
		{"the framing to the collector",
			config.SyslogListener{Framing: "auto", UpstreamFraming: "newline"}, "framing"},

		{"a facility to allow that is not one",
			config.SyslogListener{AllowFacilities: []string{"local8"}}, "allow_facilities"},
		{"a facility to deny that is not one",
			config.SyslogListener{DenyFacilities: []string{"kernel-ish"}}, "deny_facilities"},
		{"a severity that is not one",
			config.SyslogListener{MinSeverity: "quite bad"}, "min_severity"},
		{"a sender network that is not one",
			config.SyslogListener{AllowSenders: []string{"10.0.0.1"}}, "allow_senders"},
		{"a deny pattern that is not RE2",
			config.SyslogListener{DenyPatterns: []string{"(unclosed"}}, "deny_patterns"},
		// A redaction rule that did not compile is the dangerous one: it is
		// the only thing between a credential in a log line and the
		// collector, and the message names the rule so an operator knows
		// which.
		{"a redaction pattern that is not RE2",
			config.SyslogListener{Redact: []config.SyslogRedaction{
				{Name: "passwords", Pattern: "password=(?P<v>"}}}, `redact "passwords"`},
		{"a collector trust store that is not one",
			config.SyslogListener{UpstreamTLSMode: "verify",
				UpstreamTLS: &config.UpstreamTLS{CAFile: notACert}}, "upstream_tls"},
	} {
		if tc.l.Framing == "" {
			tc.l.Framing = "auto"
		}
		if tc.l.UpstreamFraming == "" {
			tc.l.UpstreamFraming = "auto"
		}
		if tc.l.UpstreamTLSMode == "" {
			tc.l.UpstreamTLSMode = "none"
		}
		err := syslogServer(t, &tc.l)
		if err == nil {
			t.Errorf("%s: built", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say %q", tc.name, err, tc.want)
		}
	}
}

// And the lists a good section produces, including the default replacement: a
// redaction rule with nothing to put in place of the match still has to take
// the match out.
func TestTheCompiledListsAreTheOnesTheSectionNamed(t *testing.T) {
	s, err := newServer(nil, config.Listener{Name: "relay", Syslog: &config.SyslogListener{
		Framing: "auto", UpstreamFraming: "octet_counting", UpstreamTLSMode: "none",
		AllowFacilities: []string{"local4"},
		DenyFacilities:  []string{"kern"},
		MinSeverity:     "warning",
		AllowSenders:    []string{"10.0.0.0/8"},
		DenyPatterns:    []string{"BEGIN RSA PRIVATE KEY"},
		Redact: []config.SyslogRedaction{
			{Name: "passwords", Pattern: `password=\S+`},
			{Name: "tokens", Pattern: `token=\S+`, With: "token=<gone>"},
		},
		RateLimit: 10,
	}}, nil, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !s.facOK[20] || !s.facDeny[0] {
		t.Errorf("the facility lists compiled to %v and %v", s.facOK, s.facDeny)
	}
	if s.minSev != 4 {
		t.Errorf("min_severity compiled to %d, want 4 (warning)", s.minSev)
	}
	if len(s.allow) != 1 || !s.allow[0].Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("the sender list compiled to %v", s.allow)
	}
	if len(s.deny) != 1 || !s.deny[0].MatchString("ssh: BEGIN RSA PRIVATE KEY leaked") {
		t.Errorf("the deny patterns compiled to %v", s.deny)
	}
	if len(s.redact) != 2 {
		t.Fatalf("the redactions compiled to %v", s.redact)
	}
	if s.redact[0].with != "[redacted]" {
		t.Errorf("a rule with no replacement got %q, want the default", s.redact[0].with)
	}
	if s.redact[1].with != "token=<gone>" {
		t.Errorf("a rule with a replacement got %q", s.redact[1].with)
	}
	if s.limiter == nil {
		t.Error("rate_limit built no limiter")
	}
}

// The per-sender rate limiter, which is this listener's amplification and
// flood control on a protocol whose senders are unauthenticated.
//
// The bound on the table is the part worth pinning: a new sender arriving to a
// full table is dropped rather than allowed to evict an entry, because the
// entries are what is doing the limiting and an attacker with a /16 of source
// addresses would otherwise clear them.
func TestTheRateLimiterHoldsItsBoundAndItsTable(t *testing.T) {
	// No burst named is the rate, and no table bound named is the default
	// rather than a table of nothing that refuses every sender.
	l := newSyslogLimiter(2, 0, 0)
	if l.burst != 2 || l.max != 65536 {
		t.Errorf("burst %v, max %d", l.burst, l.max)
	}

	one := netip.MustParseAddr("10.0.0.1")
	for i := range 2 {
		if !l.allow(one) {
			t.Errorf("message %d was refused inside a burst of 2", i+1)
		}
	}
	if l.allow(one) {
		t.Error("a third message inside the second was allowed on a burst of 2")
	}

	// The bucket refills, and it is clamped to the burst: a sender quiet for
	// an hour does not arrive with an hour's worth of credit.
	l.mu.Lock()
	l.buckets[one].last = time.Now().Add(-time.Hour)
	l.mu.Unlock()
	if !l.allow(one) {
		t.Error("the bucket did not refill")
	}
	l.mu.Lock()
	tokens := l.buckets[one].tokens
	l.mu.Unlock()
	if tokens > l.burst {
		t.Errorf("an hour of silence left %v tokens on a burst of %v", tokens, l.burst)
	}

	// A table with room for one sender: the second is refused rather than
	// taking the first one's place.
	small := newSyslogLimiter(10, 10, 1)
	if !small.allow(one) {
		t.Fatal("the first sender was refused")
	}
	if small.allow(netip.MustParseAddr("10.0.0.2")) {
		t.Error("a sender arriving to a full table was allowed")
	}
	if !small.allow(one) {
		t.Error("the sender already in the table was evicted")
	}
}
