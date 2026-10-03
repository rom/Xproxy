package dns

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dns"
)

// Compiling the three sections of a DNS listener that answer rather than
// forward: the local records, the per-client views, and the screen over what
// an upstream is allowed to point at.
//
// They are worth their own test because every refusal here is a refusal at
// load. A record a client cannot read, a view that selects nobody, a view
// that does nothing: each of those is an operator's mistake that would
// otherwise present as a name quietly not resolving in production, which is
// the hardest kind of mistake to find.

func TestARecordIsCompiledOrRefusedAtLoad(t *testing.T) {
	for _, c := range []struct {
		name string
		rec  config.DNSRecord
		want func(*testing.T, wire.LocalRecord)
	}{
		{"an A record", config.DNSRecord{Name: "a.corp.example", Type: "a",
			Address: "10.0.0.1", TTL: 60},
			func(t *testing.T, r wire.LocalRecord) {
				if r.Type != wire.TypeA || r.Addr != netip.MustParseAddr("10.0.0.1") || r.TTL != 60 {
					t.Errorf("compiled to %+v", r)
				}
			}},
		{"an AAAA record", config.DNSRecord{Name: "a.corp.example", Type: "aaaa",
			Address: "2001:db8::1"},
			func(t *testing.T, r wire.LocalRecord) {
				if r.Type != wire.TypeAAAA || r.TTL != 300 {
					t.Errorf("compiled to %+v, and the default TTL is 300", r)
				}
			}},
		{"an A record written as a mapped address", config.DNSRecord{Name: "a", Type: "a",
			Address: "::ffff:10.0.0.1"},
			func(t *testing.T, r wire.LocalRecord) {
				// Unmapped, because an A record carries four octets and a
				// mapped address is sixteen.
				if !r.Addr.Is4() {
					t.Errorf("the address stayed mapped: %v", r.Addr)
				}
			}},
		{"a TXT record", config.DNSRecord{Name: "t", Type: "txt", Text: "v=spf1 -all", TTL: 30},
			func(t *testing.T, r wire.LocalRecord) {
				if r.Type != wire.TypeTXT || r.Text != "v=spf1 -all" || r.TTL != 30 {
					t.Errorf("compiled to %+v", r)
				}
			}},
		{"a PTR record", config.DNSRecord{Name: "1.0.0.10.in-addr.arpa", Type: "ptr",
			Text: "host.corp.example"},
			func(t *testing.T, r wire.LocalRecord) {
				if r.Type != wire.TypePTR {
					t.Errorf("compiled to %+v", r)
				}
			}},
		{"an HTTPS record", config.DNSRecord{Name: "www", Priority: 1, Target: "svc.corp.example",
			Params: map[string]string{"alpn": "h3,h2", "port": "443"}},
			func(t *testing.T, r wire.LocalRecord) {
				if r.Type != wire.TypeHTTPS || r.SVCB.Priority != 1 ||
					r.SVCB.Target != "svc.corp.example" || len(r.SVCB.Params) != 2 {
					t.Errorf("compiled to %+v", r)
				}
				// Sorted, so the compiled record does not depend on map
				// order: a record that changed between reloads would
				// invalidate every cache that held it.
				if r.SVCB.Params[0].Key > r.SVCB.Params[1].Key {
					t.Errorf("the parameters are not in key order: %+v", r.SVCB.Params)
				}
			}},
		{"an HTTPS record with no target", config.DNSRecord{Name: "www", Type: "svcb"},
			func(t *testing.T, r wire.LocalRecord) {
				// RFC 9460's empty target means the owner name.
				if r.Type != wire.TypeSVCB || r.SVCB.Target != "." {
					t.Errorf("compiled to %+v", r)
				}
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := compileDNSRecord(c.rec)
			if err != nil {
				t.Fatal(err)
			}
			c.want(t, got)
		})
	}

	// And the refusals, each of which is a record somebody wrote and no
	// client could read.
	for _, c := range []struct {
		name string
		rec  config.DNSRecord
		want string
	}{
		{"an address that is not one", config.DNSRecord{Type: "a", Address: "ten.oh.oh.one"},
			"is not an address"},
		{"an A record of an IPv6 address", config.DNSRecord{Type: "a", Address: "2001:db8::1"},
			"an A record needs an IPv4 address"},
		{"an AAAA record of an IPv4 address", config.DNSRecord{Type: "aaaa", Address: "10.0.0.1"},
			"an AAAA record needs an IPv6 address"},
		{"a TXT string past 255 octets",
			config.DNSRecord{Type: "txt", Text: strings.Repeat("x", 256)}, "255"},
		{"a service parameter nothing defines",
			config.DNSRecord{Target: ".", Params: map[string]string{"quantum": "yes"}},
			"unknown service parameter"},
		{"an ALPN list with nothing in it",
			config.DNSRecord{Target: ".", Params: map[string]string{"alpn": ""}},
			"alpn"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := compileDNSRecord(c.rec); err == nil ||
				!strings.Contains(err.Error(), c.want) {
				t.Fatalf("error is %v, which does not contain %q", err, c.want)
			}
		})
	}
}

// A view selects clients and changes what they are told. One that does
// neither is a load error rather than a section that quietly does nothing.
func TestAViewHasToSelectSomebodyAndChangeSomething(t *testing.T) {
	if _, err := compileView(config.DNSView{Name: "inside"}); err == nil ||
		!strings.Contains(err.Error(), "at least one network is required") {
		t.Fatalf("a view with no clients compiled: %v", err)
	}
	if _, err := compileView(config.DNSView{Name: "inside", Clients: []string{"10.0.0.0/8"}}); err == nil ||
		!strings.Contains(err.Error(), "a view must change something") {
		t.Fatalf("a view that changes nothing compiled: %v", err)
	}
	// A record inside a view names its index, because a view with twenty
	// records needs to say which one.
	_, err := compileView(config.DNSView{Name: "inside", Clients: []string{"10.0.0.0/8"},
		Records: []config.DNSRecord{
			{Name: "ok", Type: "a", Address: "10.0.0.1"},
			{Name: "bad", Type: "a", Address: "nope"},
		}})
	if err == nil || !strings.Contains(err.Error(), "records[1]:") {
		t.Fatalf("a bad record inside a view reported %v", err)
	}
	// The four things a view may change, and the sinkhole addresses, which
	// are kept in their wire widths.
	dir := t.TempDir()
	path := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(path, []byte("ads.example\n*.tracker.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := compileView(config.DNSView{Name: "inside", Clients: []string{"10.0.0.0/8", "::1/128"},
		Records:      []config.DNSRecord{{Name: "a.corp.example", Type: "a", Address: "10.0.0.1"}},
		Block:        []string{"bad.example"},
		BlockFile:    path,
		BlockAction:  "nxdomain",
		SinkholeIPv4: "10.9.9.9", SinkholeIPv6: "2001:db8::9"})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Clients) != 2 || v.Name != "inside" || v.Action != "nxdomain" {
		t.Errorf("compiled to %+v", v)
	}
	if v.Local == nil || len(v.Local.Names()) != 1 {
		t.Error("the view's own records did not compile")
	}
	if v.Block == nil || !v.Block.Match("bad.example") || !v.Block.Match("ads.example") ||
		!v.Block.Match("www.tracker.example") {
		t.Error("the view's block list did not take both the inline entries and the file")
	}
	if len(v.Sinkhole4) != 4 || len(v.Sinkhole6) != 16 {
		t.Errorf("the sinkhole addresses are %d and %d octets", len(v.Sinkhole4), len(v.Sinkhole6))
	}
	// A block file that is not there is a load error: a listener that
	// started with an empty block list would be a listener blocking
	// nothing, silently.
	if _, err := compileView(config.DNSView{Name: "inside", Clients: []string{"10.0.0.0/8"},
		Block: []string{"bad.example"}, BlockFile: filepath.Join(dir, "absent.txt")}); err == nil ||
		!strings.Contains(err.Error(), "block_file:") {
		t.Fatalf("a missing block file compiled: %v", err)
	}
	// A name that is not a name is refused rather than stored as one that
	// can never match.
	if _, err := compileView(config.DNSView{Name: "inside", Clients: []string{"10.0.0.0/8"},
		Block: []string{"not a hostname"}}); err == nil {
		t.Fatal("a block entry that is not a name compiled")
	}
	// A sinkhole address that is not an address leaves the view without
	// one rather than refusing the listener: the block action decides what
	// happens, and a sinkhole is only one of the answers.
	v, err = compileView(config.DNSView{Name: "inside", Clients: []string{"10.0.0.0/8"},
		BlockAction: "sinkhole", SinkholeIPv4: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Sinkhole4 != nil {
		t.Errorf("an unreadable sinkhole address became %v", v.Sinkhole4)
	}
}

// The answer screen: where an upstream answer may point. The private ranges
// are denied unless somebody says otherwise, because the answer pointing
// into the estate's own network is the shape of DNS rebinding.
func TestTheAnswerScreenDeniesThePrivateRangesByDefault(t *testing.T) {
	if p, err := answerPolicy(nil); err != nil || p != nil {
		t.Fatalf("an absent section compiled to %+v, %v", p, err)
	}
	p, err := answerPolicy(&config.DNSAnswerPolicy{Action: "refuse",
		Deny: []string{"203.0.113.0/24"}, Allow: []string{"10.1.2.3/32"},
		AllowNames: []string{"router.corp.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Action != "refuse" {
		t.Errorf("the action compiled to %q", p.Action)
	}
	if len(p.Deny) < 2 || len(p.Allow) != 1 {
		t.Errorf("the lists compiled to %d denied and %d allowed", len(p.Deny), len(p.Allow))
	}
	if p.Exempt == nil || !p.Exempt.Match("router.corp.example") {
		t.Error("the exempt names did not compile")
	}
	// With the private ranges allowed, only what was named is denied --
	// which is what a split-horizon estate needs.
	off := false
	p, err = answerPolicy(&config.DNSAnswerPolicy{DenyPrivate: &off,
		Deny: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Deny) != 1 {
		t.Errorf("deny_private: false left %d denied ranges", len(p.Deny))
	}
	// A name that is not a name is refused here too, and the error says
	// which setting it was in.
	if _, err := answerPolicy(&config.DNSAnswerPolicy{
		AllowNames: []string{"not a hostname"}}); err == nil ||
		!strings.Contains(err.Error(), "answer_policy.allow_names:") {
		t.Fatalf("an unreadable exempt name compiled: %v", err)
	}
}

// The fabricated resolver, which is off unless the section says otherwise.
func TestTheDecoyResolverIsOffUnlessItIsAskedFor(t *testing.T) {
	if d, err := decoy("dns", nil); err != nil || d != nil {
		t.Fatalf("an absent deception section compiled to %+v, %v", d, err)
	}
	off := false
	if d, err := decoy("dns", &config.DNSDeception{Enabled: &off}); err != nil || d != nil {
		t.Fatalf("enabled: false compiled to %+v, %v", d, err)
	}
	d, err := decoy("dns", &config.DNSDeception{Mode: "decoy", Profile: "documentation",
		Addresses: []string{"10.77.0.0/16", "2001:db8:77::/48"}, Clients: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal("a configured decoy resolver compiled to nothing")
	}
	if _, err := decoy("dns", &config.DNSDeception{Mode: "decoy",
		Addresses: []string{"10.77.0.0/48"}}); err == nil ||
		!strings.Contains(err.Error(), "deception.addresses:") {
		t.Fatalf("an unreadable decoy network compiled: %v", err)
	}
}
