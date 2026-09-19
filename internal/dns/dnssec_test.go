package dns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// A signed test hierarchy: the root (trust anchor) delegates test, test
// holds www (A), a wildcard under wild, an insecure delegation
// (insecure) proven by NSEC, and a signed NSEC3 child (n3).
type signedZone struct {
	name string
	key  *ecdsa.PrivateKey
	tag  uint16
	rr   RR // DNSKEY record
}

func newSignedZone(t *testing.T, name string) *signedZone {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := append(leftPad(key.X.Bytes(), 32), leftPad(key.Y.Bytes(), 32)...)
	rdata := append([]byte{1, 1, 3, 13}, pub...) // flags 257, protocol 3, ECDSAP256SHA256
	z := &signedZone{name: name, key: key, rr: RR{Name: name, Type: TypeDNSKEY, Class: ClassIN, TTL: 3600, Data: rdata}}
	z.tag = keyTag(rdata)
	return z
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	return append(make([]byte, n-len(b)), b...)
}

// ds builds the DS record of the zone's key for its parent.
func (z *signedZone) ds() RR {
	owner, _ := packName(z.name)
	sum := sha256.Sum256(append(owner, z.rr.Data...))
	data := binary.BigEndian.AppendUint16(nil, z.tag)
	data = append(data, 13, 2)
	data = append(data, sum[:]...)
	return RR{Name: z.name, Type: TypeDS, Class: ClassIN, TTL: 3600, Data: data}
}

// sign produces the RRSIG of an RRset by this zone; wildcardLabels
// overrides the labels field (a wildcard owner).
func (z *signedZone) sign(t *testing.T, v *Validator, rrs []RR, labels int, corrupt bool) RR {
	t.Helper()
	set := &RRset{Name: rrs[0].Name, Type: rrs[0].Type, Class: ClassIN, TTL: rrs[0].TTL, RRs: rrs}
	now := v.now()
	data := binary.BigEndian.AppendUint16(nil, set.Type)
	data = append(data, 13, byte(labels)) //nolint:gosec // small
	data = binary.BigEndian.AppendUint32(data, set.TTL)
	data = binary.BigEndian.AppendUint32(data, uint32(now.Add(time.Hour).Unix()))  //nolint:gosec // test times
	data = binary.BigEndian.AppendUint32(data, uint32(now.Add(-time.Hour).Unix())) //nolint:gosec // test times
	data = binary.BigEndian.AppendUint16(data, z.tag)
	signer, _ := packName(z.name)
	data = append(data, signer...)
	s, err := parseRRSIG(append(data, make([]byte, 64)...))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(v.signedData(set, s))
	r, sg, err := ecdsa.Sign(rand.Reader, z.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(leftPad(r.Bytes(), 32), leftPad(sg.Bytes(), 32)...)
	if corrupt {
		sig[10] ^= 0xff
	}
	return RR{Name: rrs[0].Name, Type: TypeRRSIG, Class: ClassIN, TTL: set.TTL, Data: append(data, sig...)}
}

func bitmap(types ...uint16) []byte {
	var win [32]byte
	maxb := 0
	for _, t := range types {
		win[t/8] |= 0x80 >> (t % 8)
		if int(t/8)+1 > maxb {
			maxb = int(t/8) + 1
		}
	}
	return append([]byte{0, byte(maxb)}, win[:maxb]...) //nolint:gosec // small
}

func nsecRR(owner, next string, types ...uint16) RR {
	n, _ := packName(next)
	return RR{Name: owner, Type: TypeNSEC, Class: ClassIN, TTL: 300, Data: append(n, bitmap(types...)...)}
}

func aRR(name string, ip byte) RR {
	return RR{Name: name, Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{10, ip, ip, ip}}
}

func soaRR(zone string) RR {
	m, _ := packName("ns." + zone)
	r, _ := packName("hostmaster." + zone)
	data := append(append(m, r...), make([]byte, 20)...)
	binary.BigEndian.PutUint32(data[len(data)-4:], 300)
	return RR{Name: zone, Type: TypeSOA, Class: ClassIN, TTL: 300, Data: data}
}

// answer is what the signed upstream returns for one question.
type answer struct {
	rcode     int
	answer    []RR
	authority []RR
}

type signedUpstream struct {
	t       *testing.T
	udp     net.PacketConn
	tcp     net.Listener
	answers map[string]answer
	v       *Validator // for the time base when signing
}

func (u *signedUpstream) serve() {
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := u.udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := u.respond(buf[:n]); resp != nil {
				_, _ = u.udp.WriteTo(resp, addr)
			}
		}
	}()
	go func() {
		for {
			c, err := u.tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					q, err := ReadTCP(c, MaxMessage)
					if err != nil {
						return
					}
					if resp := u.respond(q); resp != nil {
						_ = WriteTCP(c, resp)
					}
				}
			}()
		}
	}()
}

func (u *signedUpstream) respond(query []byte) []byte {
	m, err := ParseMessage(query)
	if err != nil {
		return nil
	}
	key := m.Question.Name + "/" + TypeName(m.Question.Type)
	a, ok := u.answers[key]
	if !ok {
		a = answer{rcode: RcodeNXDomain}
	}
	do, _ := clientDO(m)
	out := &Message{Header: Header{ID: m.Header.ID, Flags: flagQR | flagRA | flagRD | uint16(a.rcode)}, Question: m.Question} //nolint:gosec // small
	for _, rr := range a.answer {
		if !do && rr.Type == TypeRRSIG {
			continue
		}
		out.Answer = append(out.Answer, rr)
	}
	for _, rr := range a.authority {
		if !do && (rr.Type == TypeRRSIG || rr.Type == TypeNSEC || rr.Type == TypeNSEC3) {
			continue
		}
		out.Authority = append(out.Authority, rr)
	}
	if do {
		out.Additional = append(out.Additional, RR{Type: TypeOPT, Class: 4096, TTL: ednsDO})
	}
	return out.Pack()
}

func buildHierarchy(t *testing.T) (*signedUpstream, *Validator, []TrustAnchor) {
	t.Helper()
	udp, tcp := listenPair(t)
	u := &signedUpstream{t: t, udp: udp, tcp: tcp, answers: map[string]answer{}}
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	res := NewResolver([]string{udp.LocalAddr().String()}, 2*time.Second)
	root, test, n3 := newSignedZone(t, ""), newSignedZone(t, "test"), newSignedZone(t, "n3.test")
	anchorDS := root.ds()
	anchors := []TrustAnchor{{Zone: "", KeyTag: root.tag, Algorithm: 13, DigestType: 2, Digest: anchorDS.Data[4:]}}
	v := NewValidator(res, anchors)
	u.v = v
	set := func(key string, a answer) { u.answers[key] = a }
	sign := func(z *signedZone, rrs ...RR) []RR {
		return append(rrs, z.sign(t, v, rrs, labelCount(rrs[0].Name), false))
	}
	// Root: its own DNSKEY and the DS of test.
	set("/DNSKEY", answer{answer: sign(root, root.rr)})
	set("test/DS", answer{answer: sign(root, test.ds())})
	// test zone.
	set("test/DNSKEY", answer{answer: sign(test, test.rr)})
	set("www.test/A", answer{answer: sign(test, aRR("www.test", 1))})
	bad := aRR("bad.test", 9)
	set("bad.test/A", answer{answer: []RR{bad, test.sign(t, v, []RR{bad}, 2, true)}})
	unsigned := aRR("plain.test", 8)
	set("plain.test/A", answer{answer: []RR{unsigned}}) // inside the signed zone without a signature
	// NSEC chain: test -> bad.test -> insecure.test -> n3.test -> *.wild.test -> www.test -> test
	nsecApex := nsecRR("test", "bad.test", TypeSOA, TypeNS, TypeDNSKEY, TypeRRSIG, TypeNSEC)
	nsecInsecure := nsecRR("insecure.test", "n3.test", TypeNS, TypeRRSIG, TypeNSEC)
	nsecN3 := nsecRR("n3.test", "*.wild.test", TypeNS, TypeDS, TypeRRSIG, TypeNSEC)
	nsecWild := nsecRR("*.wild.test", "www.test", TypeA, TypeRRSIG, TypeNSEC)
	nsecWWW := nsecRR("www.test", "test", TypeA, TypeRRSIG, TypeNSEC)
	soaTest := soaRR("test")
	set("nope.test/A", answer{rcode: RcodeNXDomain, authority: append(append(sign(test, soaTest), sign(test, nsecN3)...), sign(test, nsecApex)...)})
	set("www.test/AAAA", answer{authority: append(sign(test, soaTest), sign(test, nsecWWW)...)}) // NODATA
	set("insecure.test/DS", answer{authority: append(sign(test, soaTest), sign(test, nsecInsecure)...)})
	set("www.insecure.test/A", answer{answer: []RR{aRR("www.insecure.test", 2)}})
	set("www.insecure.test/DS", answer{authority: []RR{soaRR("insecure.test")}})
	set("insecure.test/DNSKEY", answer{authority: []RR{soaRR("insecure.test")}})
	// Wildcard expansion: the answer carries the owner asked for with the
	// wildcard's signature and the NSEC covering the name.
	wildA := aRR("*.wild.test", 3)
	wildSig := test.sign(t, v, []RR{wildA}, 2, false)
	// In a wildcard answer the RRSIG's owner is the expanded name; only
	// its labels field reveals the wildcard.
	expanded, expandedSig := wildA, wildSig
	expanded.Name, expandedSig.Name = "a.wild.test", "a.wild.test"
	set("a.wild.test/A", answer{answer: []RR{expanded, expandedSig}, authority: sign(test, nsecWild)})
	unproven, unprovenSig := wildA, wildSig
	unproven.Name, unprovenSig.Name = "b.wild.test", "b.wild.test"
	set("b.wild.test/A", answer{answer: []RR{unproven, unprovenSig}}) // no NSEC: bogus
	// n3.test: NSEC3 signed child.
	set("n3.test/DS", answer{answer: sign(test, n3.ds())})
	set("n3.test/DNSKEY", answer{answer: sign(n3, n3.rr)})
	params := &nsec3{hashAlg: 1, iterations: 0}
	h := nsec3Hash("nodata.n3.test", params)
	next := append([]byte(nil), h...)
	next[0]++
	owner := strings.ToLower(base32hex.EncodeToString(h)) + ".n3.test"
	n3data := append([]byte{1, 0, 0, 0, 0, 20}, next...)
	n3data = append(n3data, bitmap(TypeTXT, TypeRRSIG)...)
	nsec3RR := RR{Name: owner, Type: TypeNSEC3, Class: ClassIN, TTL: 300, Data: n3data}
	set("nodata.n3.test/A", answer{authority: append(sign(n3, soaRR("n3.test")), sign(n3, nsec3RR)...)})
	// An NXDOMAIN in n3.test: closest encloser n3.test, next closer and
	// wildcard covered.
	hApex := nsec3Hash("n3.test", params)
	apexNext := append([]byte(nil), hApex...)
	apexNext[0]++
	apexRR := RR{Name: strings.ToLower(base32hex.EncodeToString(hApex)) + ".n3.test", Type: TypeNSEC3, Class: ClassIN, TTL: 300,
		Data: append(append([]byte{1, 0, 0, 0, 0, 20}, apexNext...), bitmap(TypeSOA, TypeNS, TypeDNSKEY, TypeNSEC3PARAM)...)}
	// A record spanning everything else: owner just above apexNext, next wrapping below apex.
	spanOwner := append([]byte(nil), hApex...)
	spanOwner[0] += 2
	spanNext := append([]byte(nil), hApex...)
	spanNext[0]--
	spanRR := RR{Name: strings.ToLower(base32hex.EncodeToString(spanOwner)) + ".n3.test", Type: TypeNSEC3, Class: ClassIN, TTL: 300,
		Data: append(append([]byte{1, 0, 0, 0, 0, 20}, spanNext...), bitmap(TypeA)...)}
	set("gone.n3.test/A", answer{rcode: RcodeNXDomain, authority: append(append(sign(n3, soaRR("n3.test")), sign(n3, apexRR)...), sign(n3, spanRR)...)})
	u.serve()
	return u, v, anchors
}

func TestDNSSECValidation(t *testing.T) {
	_, v, _ := buildHierarchy(t)
	validate := func(name string, typ uint16, do bool, cd bool) (Result, []byte) {
		t.Helper()
		q := mustQuery(t, 42, name, typ)
		if do {
			q = withDO(q)
		}
		if cd {
			binary.BigEndian.PutUint16(q[2:], binary.BigEndian.Uint16(q[2:])|flagCD)
		}
		qh, _ := ParseHeader(q)
		_, qEnd, _ := ParseQuestion(q)
		up := withDO(q)
		uq, uEnd, _ := ParseQuestion(up)
		resp, err := v.resolver.Exchange(context.Background(), up, uEnd, uq, false)
		if err != nil {
			t.Fatal(err)
		}
		return v.Validate(context.Background(), q, qEnd, qh, resp)
	}
	cases := []struct {
		name string
		typ  uint16
		want Result
	}{
		{"www.test", TypeA, Secure},
		{"bad.test", TypeA, Bogus},
		{"plain.test", TypeA, Bogus},
		{"nope.test", TypeA, Secure},   // NXDOMAIN with NSEC
		{"www.test", TypeAAAA, Secure}, // NODATA with NSEC
		{"www.insecure.test", TypeA, Insecure},
		{"a.wild.test", TypeA, Secure},
		{"b.wild.test", TypeA, Bogus},
		{"nodata.n3.test", TypeA, Secure}, // NODATA with NSEC3
		{"gone.n3.test", TypeA, Secure},   // NXDOMAIN with NSEC3
	}
	for _, c := range cases {
		res, resp := validate(c.name, c.typ, true, false)
		if res != c.want {
			t.Errorf("%s/%s: got %s want %s", c.name, TypeName(c.typ), res, c.want)
			continue
		}
		rh, _ := ParseHeader(resp)
		switch res {
		case Secure:
			if rh.Flags&flagAD == 0 {
				t.Errorf("%s: AD not set", c.name)
			}
		case Bogus:
			if rh.Rcode() != RcodeServFail {
				t.Errorf("%s: bogus answer not SERVFAIL", c.name)
			}
		default:
			if rh.Flags&flagAD != 0 {
				t.Errorf("%s: AD set on an insecure answer", c.name)
			}
		}
	}
	// CD passes a bogus answer through unvalidated.
	if res, resp := validate("bad.test", TypeA, true, true); res != Bogus {
		t.Fatalf("cd: %s", res)
	} else if rh, _ := ParseHeader(resp); rh.Rcode() != RcodeNoError || rh.Flags&flagAD != 0 {
		t.Fatalf("cd response %v", rh)
	}
	// The key cache holds the zones; counters moved.
	st := v.Status()
	if st.Secure < 6 || st.Bogus < 3 || st.Insecure < 1 || st.KeyCache < 3 || st.Lookups == 0 {
		t.Fatalf("status %+v", st)
	}
	// An expired signature is bogus: shift the validator clock forward.
	v.now = func() time.Time { return time.Now().Add(3 * time.Hour) }
	v.mu.Lock()
	v.zones = map[string]*zoneState{}
	v.mu.Unlock()
	if res, _ := validate("www.test", TypeA, true, false); res != Bogus {
		t.Fatalf("expired signatures: %s", res)
	}
}

func TestDNSSECHelpers(t *testing.T) {
	// Canonical order (RFC 4034 section 6.1 example).
	order := []string{"example", "a.example", "yljkjljk.a.example", "Z.a.example", "zABC.a.EXAMPLE", "z.example", "\001.z.example", "*.z.example", "\200.z.example"}
	for i := 1; i < len(order); i++ {
		if !canonicalLess(order[i-1], order[i]) {
			t.Errorf("%q should sort before %q", order[i-1], order[i])
		}
	}
	if !nsecCovers("a.example", "z.example", "m.example") || nsecCovers("a.example", "z.example", "zz.example") || !nsecCovers("z.example", "example", "zz.example") {
		t.Fatal("nsecCovers")
	}
	// Trust anchor formats.
	for _, line := range []string{". 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", ". IN DS 20326 8 2 E06D44B8 0B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D", "example.org. DS 1 13 2 aa"} {
		a, err := ParseTrustAnchor(line)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if strings.HasPrefix(line, ".") && (a.Zone != "" || a.KeyTag != 20326 || a.Algorithm != 8 || a.DigestType != 2 || hex.EncodeToString(a.Digest) != strings.ToLower("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")) {
			t.Fatalf("anchor %+v", a)
		}
	}
	for _, bad := range []string{"", ". 1 2", ". x 8 2 aa", ". 1 8 2 zz"} {
		if _, err := ParseTrustAnchor(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// Key tag of a known DNSKEY rdata (RFC 4034 appendix B arithmetic).
	if tag := keyTag([]byte{1, 1, 3, 13, 0, 0}); tag != 0x0101+0x030d {
		t.Fatalf("key tag %d", tag)
	}
	// Strip: RRSIG and OPT vanish for a client without DO or OPT.
	q := mustQuery(t, 1, "www.test", TypeA)
	qm, _ := ParseMessage(q)
	resp := &Message{Header: Header{ID: 1, Flags: flagQR | flagAD}, Question: qm.Question,
		Answer:     []RR{aRR("www.test", 1), {Name: "www.test", Type: TypeRRSIG, Class: ClassIN, Data: make([]byte, 30)}},
		Additional: []RR{{Type: TypeOPT, Class: 4096, TTL: ednsDO}}}
	stripped, err := ParseMessage(StripDNSSEC(resp.Pack(), qm))
	if err != nil || len(stripped.Answer) != 1 || len(stripped.Additional) != 0 {
		t.Fatalf("strip: %v %+v", err, stripped)
	}
	dq, _ := ParseMessage(withDO(q))
	if do, opt := clientDO(dq); !do || !opt {
		t.Fatal("withDO")
	}
	if same := StripDNSSEC(resp.Pack(), dq); len(same) != len(resp.Pack()) {
		t.Fatal("strip with DO changed the response")
	}
	// A validator without anchors for a zone and no upstream is bogus.
	v := NewValidator(NewResolver(nil, time.Second), nil)
	if len(v.anchors[""]) != 2 {
		t.Fatalf("root anchors %d", len(v.anchors[""]))
	}
	m := &Message{Header: Header{Flags: flagQR}, Question: Question{Name: "x.test", Type: TypeA, Class: ClassIN}, Answer: []RR{aRR("x.test", 1)}}
	if res := v.validate(context.Background(), m); res != Bogus {
		t.Fatalf("no chain: %s", res)
	}
	if res := v.validate(context.Background(), &Message{Header: Header{Flags: flagQR | RcodeRefused}}); res != Indeterminate {
		t.Fatalf("refused: %s", res)
	}
	_ = big.NewInt
}
