package dns

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestSVCBRoundTrip: what is encoded is what is parsed back, including
// the presentation form an operator would recognise from a zone file.
func TestSVCBRoundTrip(t *testing.T) {
	params := []struct{ name, value string }{
		{"alpn", "h3,h2"},
		{"port", "8443"},
		{"ipv4hint", "192.0.2.1,192.0.2.2"},
		{"ipv6hint", "2001:db8::1"},
		{"ech", base64.StdEncoding.EncodeToString([]byte{0x00, 0x46, 0xfe, 0x0d})},
	}
	rec := SVCB{Priority: 1, Target: "svc.example.com"}
	for _, p := range params {
		got, err := ParseSVCBParam(p.name, p.value)
		if err != nil {
			t.Fatalf("%s=%s: %v", p.name, p.value, err)
		}
		rec.Params = append(rec.Params, got)
	}
	enc, err := rec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSVCB(enc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.Priority != 1 || back.Target != "svc.example.com" || len(back.Params) != len(params) {
		t.Fatalf("round trip = %+v", back)
	}
	s := back.String()
	for _, want := range []string{"1 svc.example.com", "alpn=h3,h2", "port=8443", "ipv4hint=192.0.2.1,192.0.2.2", "ipv6hint=2001:db8::1", "ech="} {
		if !strings.Contains(s, want) {
			t.Errorf("presentation form %q has no %q", s, want)
		}
	}
	// Parameters are encoded in key order whatever order they were
	// given in, which RFC 9460 requires.
	shuffled := SVCB{Priority: 1, Target: "svc.example.com"}
	for i := len(rec.Params) - 1; i >= 0; i-- {
		shuffled.Params = append(shuffled.Params, rec.Params[i])
	}
	other, err := shuffled.Encode()
	if err != nil || string(other) != string(enc) {
		t.Fatal("the encoding depends on the order the parameters were given")
	}
}

func TestSVCBParamsRefused(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"alpn", ""},
		{"port", "0"},
		{"port", "70000"},
		{"port", "https"},
		{"ipv4hint", "2001:db8::1"},
		{"ipv6hint", "192.0.2.1"},
		{"ipv4hint", "not-an-address"},
		{"ech", "not base64!"},
		{"ech", "AAA="},
		{"dohpath", "dns-query{?dns}"},
		{"dohpath", "/dns-query"},
		{"mandatory", "nonsense"},
		{"no-default-alpn", "true"},
		{"bogus", "x"},
	} {
		if _, err := ParseSVCBParam(c.name, c.value); err == nil {
			t.Errorf("%s=%q accepted", c.name, c.value)
		}
	}
	// An unknown parameter in the keyNNNNN form is legal and passes
	// through unchanged, which is how the format stays extensible.
	if p, err := ParseSVCBParam("key12345", "x"); err != nil || p.Key != 12345 {
		t.Errorf("key12345: %+v %v", p, err)
	}
}

func TestSVCBMalformed(t *testing.T) {
	good, err := SVCB{Priority: 1, Target: "a.test", Params: []SVCBParam{{Key: 1, Value: []byte{2, 'h', '2'}}}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// A record cut inside a parameter must be refused. Cutting exactly
	// after the target name leaves a valid parameterless record, which
	// is why the loop starts past it.
	nameEnd := 2 + len("a.test") + 2
	for i := nameEnd + 1; i < len(good); i++ {
		if _, err := ParseSVCB(good[:i]); err == nil {
			t.Errorf("a record truncated to %d bytes was accepted", i)
		}
	}
	for i := range nameEnd {
		if _, err := ParseSVCB(good[:i]); err == nil {
			t.Errorf("a record truncated to %d bytes, inside the header or name, was accepted", i)
		}
	}
	// Parameters out of order, which two different encodings of one
	// record would otherwise allow.
	unordered := append([]byte(nil), good[:len(good)-5]...)
	unordered = append(unordered, 0, 3, 0, 1, 9, 0, 1, 0, 1, 1)
	if _, err := ParseSVCB(unordered); err == nil {
		t.Error("parameters out of order accepted")
	}
	// An alias record with parameters.
	alias, err := SVCB{Priority: 0, Target: "a.test"}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	withParams := append(append([]byte(nil), alias...), 0, 1, 0, 1, 2)
	if _, err := ParseSVCB(withParams); err == nil {
		t.Error("an alias record with parameters accepted")
	}
	if _, err := (SVCB{Priority: 0, Target: "a.test", Params: []SVCBParam{{Key: 1}}}).Encode(); err == nil {
		t.Error("an alias record with parameters encoded")
	}
	if _, err := (SVCB{Priority: 1, Target: "a.test", Params: []SVCBParam{{Key: 1}, {Key: 1}}}).Encode(); err == nil {
		t.Error("a repeated parameter encoded")
	}
}

// TestDiscoveryRecords builds what RFC 9462 puts at
// _dns.resolver.arpa, which is what lets a client upgrade itself.
func TestDiscoveryRecords(t *testing.T) {
	recs, err := DiscoveryRecords([]Designated{
		{Transport: "doq", Name: "dns.example.com", Port: 853, IPv4: []string{"192.0.2.53"}},
		{Transport: "doh", Name: "dns.example.com", Port: 443, DoHPath: "/dns-query{?dns}"},
		{Transport: "dot", Name: "dns.example.com", Port: 853},
	}, 300)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("%d records", len(recs))
	}
	for i, r := range recs {
		if r.Name != DiscoveryName || r.Type != TypeSVCB || r.TTL != 300 {
			t.Fatalf("record %d = %+v", i, r)
		}
		if r.SVCB.Priority != uint16(i+1) {
			t.Errorf("record %d priority %d", i, r.SVCB.Priority)
		}
		if _, err := r.SVCB.Encode(); err != nil {
			t.Errorf("record %d does not encode: %v", i, err)
		}
	}
	if s := recs[0].SVCB.String(); !strings.Contains(s, "alpn=doq") || !strings.Contains(s, "ipv4hint=192.0.2.53") {
		t.Errorf("doq record = %q", s)
	}
	if s := recs[1].SVCB.String(); !strings.Contains(s, "alpn=h2,h3") || !strings.Contains(s, "dohpath=") {
		t.Errorf("doh record = %q", s)
	}
	if _, err := DiscoveryRecords([]Designated{{Transport: "dov", Name: "x.test"}}, 300); err == nil {
		t.Error("an unknown transport was accepted")
	}
}

// TestLocalRecordsAnswered: a name the resolver owns is answered from
// the local set and never forwarded, because a forwarded answer would
// contradict it.
func TestLocalRecordsAnswered(t *testing.T) {
	up := newFakeUpstream(t)
	alpn, err := ParseSVCBParam("alpn", "h3,h2")
	if err != nil {
		t.Fatal(err)
	}
	ech, err := ParseSVCBParam("ech", base64.StdEncoding.EncodeToString([]byte{0x00, 0x46, 0xfe, 0x0d, 0x00, 0x42}))
	if err != nil {
		t.Fatal(err)
	}
	disc, err := DiscoveryRecords([]Designated{{Transport: "dot", Name: "dns.example.com", Port: 853}}, 300)
	if err != nil {
		t.Fatal(err)
	}
	local := NewLocalRecords(append(disc, LocalRecord{
		Name: "www.example.com", Type: TypeHTTPS, TTL: 300,
		SVCB: SVCB{Priority: 1, Target: ".", Params: []SVCBParam{alpn, ech}},
	}))
	p := &Policy{Resolver: NewResolver([]string{up.addr()}, time.Second), MinTTL: time.Second,
		MaxTTL: time.Hour, NegativeTTL: time.Minute, Local: local}
	s := New("dns", nil, nil, 100, 8, p, Hooks{})

	// The HTTPS record of a name this proxy terminates: the ECH
	// configuration is in it, which is what a client needs before it
	// can encrypt its hello.
	resp := s.Handle(mustQuery(t, 1, "www.example.com", TypeHTTPS), netip.MustParseAddr("198.51.100.7"), true)
	h, err := ParseHeader(resp)
	if err != nil || h.Rcode() != RcodeNoError || h.ANCount != 1 {
		t.Fatalf("https answer: %+v %v", h, err)
	}
	if h.Flags&0x0400 == 0 {
		t.Error("the local answer is not marked authoritative")
	}
	m, err := ParseMessage(resp)
	if err != nil || len(m.Answer) != 1 {
		t.Fatalf("parse answer: %v", err)
	}
	rec, err := ParseSVCB(m.Answer[0].Data)
	if err != nil {
		t.Fatalf("the answer does not hold an SVCB record: %v", err)
	}
	if !strings.Contains(rec.String(), "ech=") || !strings.Contains(rec.String(), "alpn=h3,h2") {
		t.Fatalf("record = %q", rec.String())
	}

	// The discovery name.
	resp = s.Handle(mustQuery(t, 2, DiscoveryName, TypeSVCB), netip.MustParseAddr("198.51.100.7"), true)
	if h, err := ParseHeader(resp); err != nil || h.ANCount != 1 {
		t.Fatalf("discovery answer: %+v %v", h, err)
	}

	// An owned name asked for a type it does not have: NOERROR and no
	// answers, not a forwarded lookup.
	resp = s.Handle(mustQuery(t, 3, "www.example.com", TypeA), netip.MustParseAddr("198.51.100.7"), true)
	h, err = ParseHeader(resp)
	if err != nil || h.Rcode() != RcodeNoError || h.ANCount != 0 {
		t.Fatalf("nodata answer: %+v %v", h, err)
	}
	if st := s.Status(); st.QueriesLocal != 3 {
		t.Fatalf("local counter = %d", st.QueriesLocal)
	}
	if names := s.Status().LocalNames; len(names) != 2 {
		t.Fatalf("local names = %v", names)
	}

	// A name it does not own still goes upstream.
	resp = s.Handle(mustQuery(t, 4, "a.example.test", TypeA), netip.MustParseAddr("198.51.100.7"), true)
	if h, err := ParseHeader(resp); err != nil || h.ANCount == 0 {
		t.Fatalf("forwarded answer: %+v %v", h, err)
	}
}
