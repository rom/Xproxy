package dns

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A resolver that is not there.
//
// Two properties carry this kind and both are tested harder than the rest: a
// fabricated answer never amplifies, and a fabricated address is different for
// every name. The first is what keeps a honeypot on port 53 from being a weapon.
// The second is the difference between this and the sinkhole this listener
// already had -- a sinkhole answers one address for everything, so two lookups
// find it.

func decoyFor(t *testing.T, o DecoyOptions) *Decoy {
	t.Helper()
	if o.Name == "" {
		o.Name = "resolver"
	}
	d, err := NewDecoy(o)
	if err != nil {
		t.Fatalf("NewDecoy: %v", err)
	}
	at := time.Date(2025, 4, 2, 9, 0, 0, 0, time.UTC)
	d.SetClockForTest(func() time.Time { return at })
	return d
}

// ask puts one question to the fabrication and parses the reply.
func ask(t *testing.T, d *Decoy, name string, typ uint16, tcp bool) *Message {
	t.Helper()
	return askClass(t, d, name, typ, ClassIN, tcp)
}

func askClass(t *testing.T, d *Decoy, name string, typ, class uint16, tcp bool) *Message {
	t.Helper()
	q, err := Query(0x4242, name, typ)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if class != ClassIN {
		q[len(q)-1] = byte(class)
		q[len(q)-2] = byte(class >> 8)
	}
	h, err := ParseHeader(q)
	if err != nil {
		t.Fatal(err)
	}
	qq, qEnd, err := ParseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	resp := d.Answer(q, qEnd, h, qq, tcp, tcp)
	m, err := ParseMessage(resp)
	if err != nil {
		t.Fatalf("%s: the fabricated answer does not parse: %v", name, err)
	}
	if m.Question.Name != qq.Name || m.Question.Type != qq.Type {
		t.Errorf("%s: the reply asks %q %d", name, m.Question.Name, m.Question.Type)
	}
	if !m.Header.Response() {
		t.Errorf("%s: the reply is not marked as one", name)
	}
	if m.Header.Rcode() != RcodeNoError {
		t.Errorf("%s: rcode %d, and a fabrication that said the name does not exist would be a "+
			"refusal with extra steps", name, m.Header.Rcode())
	}
	return m
}

// The types the fabrication answers, and the ones it does not.
func TestTheFabricationAnswersTheTypesItCanAndNoOthers(t *testing.T) {
	d := decoyFor(t, DecoyOptions{Whole: true})
	a := ask(t, d, "c2.example.net", TypeA, true)
	if len(a.Answer) != 1 || a.Answer[0].Type != TypeA || len(a.Answer[0].Data) != 4 {
		t.Fatalf("an A query answered %+v", a.Answer)
	}
	if got, ok := netip.AddrFromSlice(a.Answer[0].Data); !ok ||
		!netip.MustParsePrefix("192.0.2.0/24").Contains(got) {
		t.Errorf("the A answer is %v, and the default pool is the documentation range", got)
	}
	quad := ask(t, d, "c2.example.net", TypeAAAA, true)
	if len(quad.Answer) != 1 || len(quad.Answer[0].Data) != 16 {
		t.Fatalf("an AAAA query answered %+v", quad.Answer)
	}
	got6, _ := netip.AddrFromSlice(quad.Answer[0].Data)
	if !netip.MustParsePrefix("2001:db8::/32").Contains(got6) {
		t.Errorf("the AAAA answer is %v", got6)
	}
	// A pool wider than 64 bits is still indexed by the name: the base address
	// of the prefix is the network, and answering it for everything would be
	// the sinkhole shape in a range big enough to hide in.
	if got6 == netip.MustParsePrefix("2001:db8::/32").Addr() {
		t.Errorf("the AAAA answer is the pool's own base address")
	}
	second, _ := netip.AddrFromSlice(ask(t, d, "other.example.net", TypeAAAA, true).Answer[0].Data)
	if second == got6 {
		t.Errorf("two names answered the same IPv6 address (%v)", got6)
	}
	// TXT is the answer a tunnel is waiting for, and the one shape on this
	// protocol that can be made large. It carries one character string.
	txt := ask(t, d, "abcdef.tunnel.example.net", TypeTXT, true)
	if len(txt.Answer) != 1 {
		t.Fatalf("a TXT query answered %+v", txt.Answer)
	}
	if data := txt.Answer[0].Data; len(data) == 0 || int(data[0]) != len(data)-1 {
		t.Errorf("the TXT rdata is %q, which is not one counted string", data)
	}
	ptr := ask(t, d, "7.2.0.192.in-addr.arpa", TypePTR, true)
	if len(ptr.Answer) != 1 {
		t.Fatalf("a PTR query answered %+v", ptr.Answer)
	}
	// Everything else is NODATA: an empty NOERROR, which is the commonest
	// truthful answer on this protocol. Inventing an MX would mean inventing a
	// mail host, and an NS or an SOA would be a claim of authority a forwarding
	// resolver is not making.
	for _, typ := range []uint16{TypeMX, TypeNS, TypeSOA, TypeCNAME, 33, 65} {
		m := ask(t, d, "c2.example.net", typ, true)
		if len(m.Answer) != 0 {
			t.Errorf("type %d answered %+v", typ, m.Answer)
		}
	}
}

// The answer is not authoritative, because a forwarding resolver is not.
func TestTheFabricatedAnswerDoesNotClaimAuthority(t *testing.T) {
	d := decoyFor(t, DecoyOptions{Whole: true})
	m := ask(t, d, "c2.example.net", TypeA, true)
	if m.Header.Flags&flagAA != 0 {
		t.Error("the fabrication claimed authority for a name it forwards for")
	}
	// The local record set does claim it, and that is the difference: those
	// names are this resolver's own.
	q, _ := Query(1, "a.test", TypeA)
	h, _ := ParseHeader(q)
	qq, qEnd, _ := ParseQuestion(q)
	local := AnswerLocal(q, qEnd, h, qq, []LocalRecord{{Type: TypeA, TTL: 60, Addr: netip.MustParseAddr("192.0.2.1")}})
	if lm, err := ParseMessage(local); err != nil || lm.Header.Flags&flagAA == 0 {
		t.Error("a local record answered without the authoritative bit")
	}
}

// The property that separates this from a sinkhole: a different address per
// name, and the same one every time for one name.
func TestTheFabricatedAddressIsPerNameAndStable(t *testing.T) {
	d := decoyFor(t, DecoyOptions{Whole: true, Seed: 99})
	pool := netip.MustParsePrefix("192.0.2.0/24")
	seen := map[string]string{}
	for _, name := range []string{
		"a.example.net", "b.example.net", "c.example.net", "d.example.net",
		"update.malware.example", "cdn.malware.example",
	} {
		m := ask(t, d, name, TypeA, true)
		got, _ := netip.AddrFromSlice(m.Answer[0].Data)
		if !pool.Contains(got) {
			t.Fatalf("%s answered %v, outside the pool", name, got)
		}
		// Neither the network address nor the broadcast: nobody is hosted at
		// either, and a visitor who noticed would have found the fabrication.
		if last := got.As4()[3]; last == 0 || last == 255 {
			t.Errorf("%s answered %v", name, got)
		}
		if again := ask(t, d, name, TypeA, true); string(again.Answer[0].Data) != string(m.Answer[0].Data) {
			t.Errorf("%s answered two different addresses", name)
		}
		seen[name] = got.String()
	}
	// Spread across the pool: a sinkhole answers one address for every name,
	// which is how a sinkhole is recognised in one extra lookup. Two names
	// sharing an address is not a fault -- a /24 holds 254 of them and a
	// hundred names cannot each have one -- so what is asserted is that the
	// answers fill the pool rather than collapse onto a value.
	distinct := map[string]bool{}
	for i := 0; i < 200; i++ {
		name := "n" + strconv.Itoa(i) + ".example.net"
		m := ask(t, d, name, TypeA, true)
		got, _ := netip.AddrFromSlice(m.Answer[0].Data)
		if !pool.Contains(got) {
			t.Fatalf("%s answered %v, outside the pool", name, got)
		}
		// Never the network address and never the broadcast: nobody is hosted
		// at either, and a visitor who was told one has found the fabrication.
		if last := got.As4()[3]; last == 0 || last == 255 {
			t.Fatalf("%s answered %v", name, got)
		}
		distinct[got.String()] = true
	}
	if len(distinct) < 100 {
		t.Errorf("200 names drew %d addresses out of 254", len(distinct))
	}
	// A different seed answers differently, so two listeners do not draw the
	// same map.
	other := decoyFor(t, DecoyOptions{Whole: true, Seed: 100})
	same := 0
	for name := range seen {
		m := ask(t, other, name, TypeA, true)
		got, _ := netip.AddrFromSlice(m.Answer[0].Data)
		if got.String() == seen[name] {
			same++
		}
	}
	if same == len(seen) {
		t.Error("two seeds answered every name identically")
	}
}

// The TTL: the configured one, and never zero.
func TestTheFabricatedTTLIsTheConfiguredOneAndNeverZero(t *testing.T) {
	d := decoyFor(t, DecoyOptions{Whole: true, TTL: 90 * time.Second})
	if got := ask(t, d, "a.example.net", TypeA, true).Answer[0].TTL; got != 90 {
		t.Errorf("TTL %d, want 90", got)
	}
	// A zero TTL is a tell, and it also makes every client ask again for every
	// lookup -- which turns the fabrication into the thing under load.
	zero := decoyFor(t, DecoyOptions{Whole: true, TTL: time.Millisecond})
	if got := ask(t, zero, "a.example.net", TypeA, true).Answer[0].TTL; got == 0 {
		t.Error("a sub-second TTL rounded to zero")
	}
	def := decoyFor(t, DecoyOptions{Whole: true})
	if got := ask(t, def, "a.example.net", TypeA, true).Answer[0].TTL; got != 300 {
		t.Errorf("the default TTL is %d", got)
	}
}

// A resolver is an amplifier, and this is the test that says the fabrication is
// not one.
func TestAFabricatedDatagramAnswerNeverAmplifies(t *testing.T) {
	d := decoyFor(t, DecoyOptions{Whole: true})
	// A short name with a TXT answer is the shape that grows most: the question
	// is tiny and the answer carries a string.
	q, err := Query(1, "a.io", TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := ParseHeader(q)
	qq, qEnd, err := ParseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	// Unverified datagram: bounded against the query, and truncated rather than
	// exceeded. A real client comes back over TCP; a spoofed source cannot.
	udp := d.Answer(q, qEnd, h, qq, false, false)
	if len(udp) > maxDecoyGrowth*len(q) {
		t.Fatalf("an unverified datagram answer is %d octets for a %d-octet query", len(udp), len(q))
	}
	m, err := ParseMessage(udp)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Flags&flagTC == 0 || len(m.Answer) != 0 {
		t.Errorf("the answer was neither truncated nor bounded: %d answers, flags %04x",
			len(m.Answer), m.Header.Flags)
	}
	// Over TCP the address is proved by the connection, so the answer is given.
	tcp := d.Answer(q, qEnd, h, qq, true, false)
	if tm, err := ParseMessage(tcp); err != nil || len(tm.Answer) != 1 {
		t.Errorf("the same question over TCP answered %v", err)
	}
	// And a datagram whose source a cookie proved is answered too: the bound is
	// about an address nothing has verified, not about UDP.
	if vm, err := ParseMessage(d.Answer(q, qEnd, h, qq, false, true)); err != nil || len(vm.Answer) != 1 {
		t.Errorf("a verified datagram was truncated: %v", err)
	}
	// No shape of question is answered with more than the bound allows, whatever
	// the client asked for.
	for _, typ := range []uint16{TypeA, TypeAAAA, TypeTXT, TypePTR, TypeANY, TypeMX} {
		q, err := Query(1, "a.io", typ)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := ParseHeader(q)
		qq, qEnd, err := ParseQuestion(q)
		if err != nil {
			t.Fatal(err)
		}
		if out := d.Answer(q, qEnd, h, qq, false, false); len(out) > maxDecoyGrowth*len(q) {
			t.Errorf("type %d: %d octets answered a %d-octet query", typ, len(out), len(q))
		}
	}
}

// The tripwires, which need no configuring: on this protocol the escalation is a
// type rather than a name.
func TestTheTripwiresNeedNoConfiguring(t *testing.T) {
	d := decoyFor(t, DecoyOptions{Whole: true, Tripwire: []string{"Payroll.Internal."}})
	for _, c := range []struct {
		name string
		typ  uint16
	}{
		{"example.net", typeAXFR},
		{"example.net", typeIXFR},
		{"example.net", typeDNSKEY},
		{"example.net", TypeNULL},
		{"example.net", TypeANY},
		{"version.bind", TypeTXT},
		{"hostname.bind", TypeTXT},
		{"id.server", TypeTXT},
		{"authors.bind", TypeTXT},
		// A name long enough to be the payload. A hostname somebody typed is
		// not a hundred octets long; a tunnel's is, every time.
		{strings.Repeat("abcdefghij.", 10) + "tunnel.example", TypeA},
		// A configured name, and a subdomain of it: a tripwire that matched
		// only the apex is a tripwire a subdomain walks past.
		{"payroll.internal", TypeA},
		{"reports.payroll.internal", TypeA},
	} {
		if !d.Tripped(Question{Name: c.name, Type: c.typ, Class: ClassIN}) {
			t.Errorf("%s %d did not trip", c.name, c.typ)
		}
	}
	// A class that is not IN, which is how the fingerprint names are really
	// asked. The name here is an ordinary one, so it is the class that has to
	// trip: nothing resolving a name asks in CH.
	if !d.Tripped(Question{Name: "www.example.net", Type: TypeA, Class: 3}) {
		t.Error("a query in class CH did not trip")
	}
	if !d.Tripped(Question{Name: "version.bind", Type: TypeTXT, Class: 3}) {
		t.Error("a fingerprint query did not trip")
	}
	// And the traffic a client sends, which must not trip.
	for _, c := range []struct {
		name string
		typ  uint16
	}{
		{"www.example.net", TypeA},
		{"www.example.net", TypeAAAA},
		{"example.net", TypeMX},
		{"_dmarc.example.net", TypeTXT},
		{"1.2.0.192.in-addr.arpa", TypePTR},
		{"internal", TypeA},
		{"notpayroll.internal", TypeA},
	} {
		if d.Tripped(Question{Name: c.name, Type: c.typ, Class: ClassIN}) {
			t.Errorf("%s %d tripped", c.name, c.typ)
		}
	}
	// The fingerprint names are tripped and never answered: a resolver that
	// names itself has handed over the list of what it is vulnerable to.
	if m := askClass(t, d, "version.bind", TypeTXT, 3, true); len(m.Answer) != 0 {
		t.Errorf("version.bind was answered: %+v", m.Answer)
	}
}

// The profiles, which on this protocol are the whole of the shape: there is no
// version string to get right, because the only thing a resolver discloses about
// itself is the answers it gives.
func TestTheProfilesPointWhereTheySay(t *testing.T) {
	for _, c := range []struct{ profile, v4, v6 string }{
		{"documentation", "192.0.2.0/24", "2001:db8::/32"},
		{"loopback", "127.0.0.0/8", "::1/128"},
		{"unroutable", "0.0.0.0/32", "::/128"},
	} {
		d := decoyFor(t, DecoyOptions{Whole: true, Profile: c.profile})
		if d.Profile() != c.profile {
			t.Errorf("profile %q reports %q", c.profile, d.Profile())
		}
		got, _ := netip.AddrFromSlice(ask(t, d, "a.example.net", TypeA, true).Answer[0].Data)
		if !netip.MustParsePrefix(c.v4).Contains(got) {
			t.Errorf("profile %q answered %v, want inside %s", c.profile, got, c.v4)
		}
		got6, _ := netip.AddrFromSlice(ask(t, d, "a.example.net", TypeAAAA, true).Answer[0].Data)
		if !netip.MustParsePrefix(c.v6).Contains(got6) {
			t.Errorf("profile %q answered %v, want inside %s", c.profile, got6, c.v6)
		}
	}
	// A single-address pool answers that address, which is the sinkhole shape
	// and is the one profile where it is deliberate.
	one := decoyFor(t, DecoyOptions{Whole: true, Profile: "unroutable"})
	a := ask(t, one, "a.example.net", TypeA, true).Answer[0].Data
	b := ask(t, one, "b.example.net", TypeA, true).Answer[0].Data
	if string(a) != string(b) {
		t.Error("a /32 pool answered two addresses")
	}
	if len(DecoyProfiles()) != len(decoyProfiles) {
		t.Errorf("DecoyProfiles names %d of %d", len(DecoyProfiles()), len(decoyProfiles))
	}
	for _, name := range DecoyProfiles() {
		if _, ok := decoyProfiles[name]; !ok {
			t.Errorf("DecoyProfiles names %q, which is not one", name)
		}
	}
	// An operator's own pool replaces the profile's.
	own := decoyFor(t, DecoyOptions{
		Whole: true,
		V4:    netip.MustParsePrefix("10.70.0.0/24"),
		V6:    netip.MustParsePrefix("fd00:dead::/48"),
	})
	got, _ := netip.AddrFromSlice(ask(t, own, "a.example.net", TypeA, true).Answer[0].Data)
	if !netip.MustParsePrefix("10.70.0.0/24").Contains(got) {
		t.Errorf("a configured pool answered %v", got)
	}
	got6, _ := netip.AddrFromSlice(ask(t, own, "a.example.net", TypeAAAA, true).Answer[0].Data)
	if !netip.MustParsePrefix("fd00:dead::/48").Contains(got6) {
		t.Errorf("a configured pool answered %v", got6)
	}
}

// The TXT answer a tunnel is given: a shape it accepts, changing between
// periods, and short enough that it is not an amplifier.
func TestTheTextAnswerChangesBetweenPeriodsAndStaysShort(t *testing.T) {
	d := decoyFor(t, DecoyOptions{Whole: true, Seed: 5, Period: time.Minute})
	at := time.Date(2025, 4, 2, 9, 0, 0, 0, time.UTC)
	d.SetClockForTest(func() time.Time { return at })
	first := d.text("chunk1.tunnel.example")
	// Forty-eight characters, written out rather than taken from the constant:
	// a TXT answer is the one shape on this protocol that can be made large,
	// and large is what an amplifier wants.
	if len(first) != 48 {
		t.Fatalf("the TXT string is %d characters", len(first))
	}
	if strings.ToLower(first) != first {
		t.Errorf("the TXT string is %q", first)
	}
	// Stable within a period: a tunnel that got two answers to one question
	// would have found something.
	if again := d.text("chunk1.tunnel.example"); again != first {
		t.Error("one question was answered twice in one period")
	}
	// Two questions differ, and so does the next period: a tunnel that received
	// the same answer to everything stops.
	if other := d.text("chunk2.tunnel.example"); other == first {
		t.Error("two questions were answered identically")
	}
	later := at.Add(10 * time.Minute)
	d.SetClockForTest(func() time.Time { return later })
	if next := d.text("chunk1.tunnel.example"); next == first {
		t.Error("the answer did not change between periods")
	}
	// And it fits a TXT record, which is one counted string of at most 255.
	rec := LocalRecord{Type: TypeTXT, Text: d.text("x")}
	if _, err := rec.Rdata(); err != nil {
		t.Errorf("the TXT string does not encode: %v", err)
	}
	// The three fabricated values for one name are derived separately, so a
	// visitor who learns the address a name was answered with cannot work out
	// the TXT string or the reverse name from it.
	for _, pair := range [][2]string{{"addr", "ptr"}, {"addr", "txt"}, {"ptr", "txt"}} {
		if d.hash(pair[0], "a.example.net") == d.hash(pair[1], "a.example.net") {
			t.Errorf("%s and %s derive one name's value from one number", pair[0], pair[1])
		}
	}
}

// Who is answered, and what the section refuses to compile.
func TestTheSectionDecidesWhoIsAnsweredAndRefusesWhatItCannotMean(t *testing.T) {
	d := decoyFor(t, DecoyOptions{Clients: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}})
	if !d.Admits(netip.MustParseAddr("10.0.0.9")) {
		t.Error("a client in the list is not admitted")
	}
	if d.Admits(netip.MustParseAddr("10.0.1.9")) {
		t.Error("a client outside the list is admitted")
	}
	open := decoyFor(t, DecoyOptions{Whole: true})
	if !open.Admits(netip.MustParseAddr("203.0.113.1")) || !open.Policy().Anyone() {
		t.Error("a decoy with no client list refused a client")
	}
	if d.Whole() {
		t.Error("mode answer reported itself a whole listener")
	}
	if !open.Whole() {
		t.Error("mode decoy did not report itself a whole listener")
	}
	// A nil decoy answers nobody and trips on nothing, because every call site
	// reaches it through a policy that may not have one.
	var none *Decoy
	if none.Admits(netip.MustParseAddr("10.0.0.1")) || none.Whole() ||
		none.Tripped(Question{Name: "a", Type: TypeANY}) || none.Profile() != "" {
		t.Error("a listener with no fabrication answered as one")
	}
	for _, c := range []struct {
		why string
		o   DecoyOptions
	}{
		{"a profile nobody has", DecoyOptions{Profile: "bind"}},
		{"a tripwire with a space in it", DecoyOptions{Tripwire: []string{"a b"}}},
		{"an empty tripwire", DecoyOptions{Tripwire: []string{"  "}}},
		{"an IPv6 pool given as the IPv4 one", DecoyOptions{V4: netip.MustParsePrefix("2001:db8::/32")}},
		{"an IPv4 pool given as the IPv6 one", DecoyOptions{V6: netip.MustParsePrefix("192.0.2.0/24")}},
	} {
		if _, err := NewDecoy(c.o); err == nil {
			t.Errorf("%s compiled", c.why)
		}
	}
}
