package kkdcp

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/kerberos"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// kkdcpWith starts a relay with its own top-level sections, which the
// shared helper does not reach: the ban ladder sits outside the
// listener.
func kkdcpWith(t *testing.T, section, top, kdcAddr string) (*proxy.Server, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "kdcproxy.test")
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
%s
server:
  listeners:
    - name: kdcproxy
      address: "127.0.0.1:0"
      kind: kkdcp
      tls:
        certificates:
          - cert_file: %q
            key_file: %q
      kkdcp:
        upstream: kdcs
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: kdcs, endpoints: [{address: %q}]}
`, top, cert, key, section, kdcAddr))
	return s, proxytest.Addr(t, s, "kdcproxy")
}

const banLadder = `bans:
  triggers:
    - {name: kdc, reasons: [kkdcp_denied], threshold: 1, window: 1m, duration: 10m}`

func banned(t *testing.T, s *proxy.Server) bool {
	t.Helper()
	ip := netip.MustParseAddr("127.0.0.1")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Bans().Banned(ip) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// A refusal this relay makes reaches the ban ladder, on both sides of
// the exchange.
//
// A KDC proxy is reachable from anywhere its HTTPS port is, which is the
// point of it -- so the ladder is the only thing that makes a client
// that keeps asking for what it cannot have stop arriving. Both the
// request side and the reply side feed it, because an attacker who gets
// a refusal on the reply has had the KDC do the work either way.
func TestARefusalOnEitherSideReachesTheBanLadder(t *testing.T) {
	t.Run("on the request", func(t *testing.T) {
		kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
			return tgsRep(m.Realm, user("svc"), svc("MSSQLSvc", "db.corp.example"), wire.ETypeAES256SHA1)
		}})
		s, addr := kkdcpWith(t, `        realms: [CORP.EXAMPLE]
        default_action: allow`, banLadder, kdc.addr())
		only := tgsReq("CORP.EXAMPLE", user("svc"), svc("MSSQLSvc", "db.corp.example"),
			[]wire.EType{wire.ETypeRC4HMAC})
		if _, m := dial(t, addr).post(only, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgError {
			t.Fatalf("an RC4-only request was carried: %v", m)
		}
		if !banned(t, s) {
			t.Error("the refusal never reached the ban ladder")
		}
	})

	t.Run("on the reply", func(t *testing.T) {
		// The KDC answers with a ticket in a weak encryption type, which
		// is a refusal about the reply: the ticket is the crackable
		// thing, and it is this relay's last chance to not hand it over.
		kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
			return tgsRep(m.Realm, user("svc"), svc("MSSQLSvc", "db.corp.example"), wire.ETypeRC4HMAC)
		}})
		s, addr := kkdcpWith(t, `        realms: [CORP.EXAMPLE]
        default_action: allow
        refuse_weak_ticket_etypes: true`, banLadder, kdc.addr())
		req := tgsReq("CORP.EXAMPLE", user("svc"), svc("MSSQLSvc", "db.corp.example"),
			[]wire.EType{wire.ETypeAES256SHA1, wire.ETypeRC4HMAC})
		if _, m := dial(t, addr).post(req, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgError {
			t.Fatalf("a weak ticket was handed to the client: %v", m)
		}
		if refusals(s, "weak_ticket_etype") == 0 {
			t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
		}
		if !banned(t, s) {
			t.Error("the refusal never reached the ban ladder")
		}
	})
}

// In shadow mode a refusal that is not hard is recorded and the traffic
// goes through, on both sides. This is the only way to find out what
// enforcing a Kerberos policy would cost an estate before enforcing it
// -- and on this protocol the cost lands on people signing in.
func TestShadowModeRecordsBothSidesWithoutRefusingEither(t *testing.T) {
	t.Run("the request", func(t *testing.T) {
		kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
			return tgsRep(m.Realm, user("svc"), svc("MSSQLSvc", "db.corp.example"), wire.ETypeAES256SHA1)
		}})
		s, addr := kkdcpWith(t, `        realms: [CORP.EXAMPLE]
        default_action: allow`, "policy: {mode: shadow}", kdc.addr())
		only := tgsReq("CORP.EXAMPLE", user("svc"), svc("MSSQLSvc", "db.corp.example"),
			[]wire.EType{wire.ETypeRC4HMAC})
		if _, m := dial(t, addr).post(only, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgTGSRep {
			t.Fatalf("a shadowed listener refused the request: %v", m)
		}
		if len(kdc.requests()) != 1 {
			t.Error("the request did not reach the KDC")
		}
		found := false
		for _, e := range s.Shadow().Report() {
			if e.Kind == "kkdcp" && e.Reason == "weak_etype_only" {
				found = true
			}
		}
		if !found {
			t.Errorf("no shadow entry: %+v", s.Shadow().Report())
		}
		if refusals(s, "weak_etype_only") != 0 {
			t.Error("a shadowed refusal was counted as a refusal")
		}
	})

	t.Run("the reply", func(t *testing.T) {
		kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
			return tgsRep(m.Realm, user("svc"), svc("MSSQLSvc", "db.corp.example"), wire.ETypeRC4HMAC)
		}})
		s, addr := kkdcpWith(t, `        realms: [CORP.EXAMPLE]
        default_action: allow
        refuse_weak_ticket_etypes: true`, "policy: {mode: shadow}", kdc.addr())
		req := tgsReq("CORP.EXAMPLE", user("svc"), svc("MSSQLSvc", "db.corp.example"),
			[]wire.EType{wire.ETypeAES256SHA1, wire.ETypeRC4HMAC})
		if _, m := dial(t, addr).post(req, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgTGSRep {
			t.Fatalf("a shadowed listener refused the reply: %v", m)
		}
		found := false
		for _, e := range s.Shadow().Report() {
			if e.Kind == "kkdcp" && e.Reason == "weak_ticket_etype" {
				found = true
			}
		}
		if !found {
			t.Errorf("no shadow entry: %+v", s.Shadow().Report())
		}
	})
}

// The request rate, which is the bound on a KDC proxy's whole purpose:
// every request it carries is work the KDC does with a key.
func TestTheRequestRateIsBoundedPerClient(t *testing.T) {
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return asRep(m.Realm, user("alice"), krbtgt(m.Realm), wire.ETypeAES256SHA1, nil)
	}})
	s, addr := kkdcpWith(t, `        realms: [CORP.EXAMPLE]
        default_action: allow
        rate_limit: 1
        rate_burst: 1`, "", kdc.addr())
	c := dial(t, addr)
	req := asReq("CORP.EXAMPLE", user("alice"), []wire.EType{wire.ETypeAES256SHA1}, withPreauth())
	// The burst is one, so the second request inside the same second is
	// past the rate whatever the first answered.
	for i := 0; i < 2; i++ {
		c.post(req, "CORP.EXAMPLE")
	}
	if refusals(s, "rate_limited") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}
}

// The access line is a setting, and turning it off turns off the line
// and nothing else: the exchange still happens and still counts.
func TestTheAccessLineCanBeTurnedOffWithoutTurningOffTheRelay(t *testing.T) {
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return asRep(m.Realm, user("alice"), krbtgt(m.Realm), wire.ETypeAES256SHA1, nil)
	}})
	s, addr := kkdcpWith(t, `        realms: [CORP.EXAMPLE]
        default_action: allow
        log_requests: false`, "", kdc.addr())
	req := asReq("CORP.EXAMPLE", user("alice"), []wire.EType{wire.ETypeAES256SHA1}, withPreauth())
	if _, m := dial(t, addr).post(req, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgASRep {
		t.Fatalf("the request was not carried: %v", m)
	}
	if len(kdc.requests()) != 1 {
		t.Error("the request did not reach the KDC")
	}
	_ = s
}

// The anomaly models, which are what notices a client doing something it
// has never done rather than something a rule named. On this protocol
// that is the signal that matters: a ticket request for a service nobody
// has asked for before is how lateral movement looks from here.
func TestTheAnomalyModelsSeeTheRequestsShape(t *testing.T) {
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return tgsRep(m.Realm, user("svc"), svc("MSSQLSvc", "db.corp.example"), wire.ETypeAES256SHA1)
	}})
	s, addr := kkdcpWith(t, `        realms: [CORP.EXAMPLE]
        default_action: allow
        anomaly:
          enabled: true
          settle: 0s`, banLadder, kdc.addr())
	req := tgsReq("CORP.EXAMPLE", user("svc"), svc("MSSQLSvc", "db.corp.example"),
		[]wire.EType{wire.ETypeAES256SHA1})
	dial(t, addr).post(req, "CORP.EXAMPLE")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n := len(s.Stats().Refusals["kkdcp"]); n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("the models reported nothing: %+v", s.Stats().Refusals["kkdcp"])
}
