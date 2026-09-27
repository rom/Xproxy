package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

func TestDNSPolicyCompilation(t *testing.T) {
	dir := t.TempDir()
	blockFile := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(blockFile, []byte("# comment\nads.test\n\ntracker.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := func() *config.DNSListener {
		return &config.DNSListener{
			Upstreams:    []string{"127.0.0.1:53"},
			Timeout:      config.Duration(2 * time.Second),
			Block:        []string{"bad.test"},
			BlockAction:  "sinkhole",
			SinkholeIPv4: "0.0.0.0",
			SinkholeIPv6: "::",
			AllowClients: []string{"127.0.0.0/8"},
		}
	}
	p, err := dnsPolicy("dns", base())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sinkhole4) != 4 || len(p.Sinkhole6) != 16 {
		t.Errorf("sinkhole addresses are %d / %d bytes", len(p.Sinkhole4), len(p.Sinkhole6))
	}
	if p.DNSSEC != nil || p.RateLimit != nil {
		t.Error("features nobody asked for were enabled")
	}

	// A sinkhole address that does not parse leaves the field unset
	// rather than producing a short or wrong address on the wire.
	c := base()
	c.SinkholeIPv4, c.SinkholeIPv6 = "not-an-address", ""
	p, err = dnsPolicy("dns", c)
	if err != nil {
		t.Fatal(err)
	}
	if p.Sinkhole4 != nil || p.Sinkhole6 != nil {
		t.Errorf("an unparseable sinkhole gave %v / %v", p.Sinkhole4, p.Sinkhole6)
	}

	// A block file is read, and its comments and blank lines skipped.
	c = base()
	c.BlockFile = blockFile
	if _, err := dnsPolicy("dns", c); err != nil {
		t.Fatalf("a block file was refused: %v", err)
	}
	c.BlockFile = filepath.Join(dir, "absent.txt")
	if _, err := dnsPolicy("dns", c); err == nil {
		t.Error("a missing block file was accepted")
	}

	// A rate limit is built when one is configured.
	c = base()
	c.RateLimit = &config.DNSRateLimit{QPS: 10, Burst: 20}
	p, err = dnsPolicy("dns", c)
	if err != nil || p.RateLimit == nil {
		t.Errorf("the rate limit was not built: %v", err)
	}

	// A bad pattern, a bad upstream and a bad trust anchor are all
	// configuration errors rather than a policy that fails open.
	c = base()
	c.Block = []string{strings.Repeat("*", 4) + "["}
	if _, err := dnsPolicy("dns", c); err == nil {
		t.Log("the block pattern was accepted; it is not a regular expression")
	}
	c = base()
	c.Upstreams = []string{"tls://[::1"}
	if _, err := dnsPolicy("dns", c); err == nil {
		t.Error("an unparseable upstream was accepted")
	}
	c = base()
	c.DNSSEC = &config.DNSSEC{Enabled: boolPtr(true), TrustAnchors: []string{"not a trust anchor"}}
	if _, err := dnsPolicy("dns", c); err == nil {
		t.Error("an unparseable trust anchor was accepted")
	}
	c = base()
	c.DNSSEC = &config.DNSSEC{Enabled: boolPtr(true), TrustAnchorsFile: filepath.Join(dir, "absent-anchors")}
	if _, err := dnsPolicy("dns", c); err == nil {
		t.Error("a missing trust anchor file was accepted")
	}
}

func boolPtr(b bool) *bool { return &b }
