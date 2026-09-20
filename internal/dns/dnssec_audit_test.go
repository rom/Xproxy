package dns

import (
	"context"
	"strings"
	"testing"
	"time"
)

// buildDowngradeHierarchy is a signed root with two children, test and
// att, arranged so that an upstream under attacker control can try the
// downgrades the second audit round found: an NSEC3 NODATA-for-DS at an
// ordinary host name, a denial proof borrowed from an unrelated zone, a
// parent-side NSEC used below a delegation, and a positive answer whose
// records belong to another name.
func buildDowngradeHierarchy(t *testing.T) *Validator {
	t.Helper()
	udp, tcp := listenPair(t)
	u := &signedUpstream{t: t, udp: udp, tcp: tcp, answers: map[string]answer{}}
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	res := NewResolver([]string{udp.LocalAddr().String()}, 2*time.Second)
	root, test, att := newSignedZone(t, ""), newSignedZone(t, "test"), newSignedZone(t, "att")
	anchorDS := root.ds()
	anchors := []TrustAnchor{{Zone: "", KeyTag: root.tag, Algorithm: 13, DigestType: 2, Digest: anchorDS.Data[4:]}}
	v := NewValidator(res, anchors)
	u.v = v
	set := func(key string, a answer) { u.answers[key] = a }
	sign := func(z *signedZone, rrs ...RR) []RR {
		return append(rrs, z.sign(t, v, rrs, labelCount(rrs[0].Name), false))
	}
	set("/DNSKEY", answer{answer: sign(root, root.rr)})
	set("test/DS", answer{answer: sign(root, test.ds())})
	set("att/DS", answer{answer: sign(root, att.ds())})
	set("test/DNSKEY", answer{answer: sign(test, test.rr)})
	set("att/DNSKEY", answer{answer: sign(att, att.rr)})
	soaTest := soaRR("test")

	// (1) www.test is an ordinary host in an NSEC3 zone: its genuine NSEC3
	// has A and RRSIG only. The upstream answers the validator's DS lookup
	// with it, then hands out an unsigned A record.
	params := &nsec3{hashAlg: 1, iterations: 0}
	h := nsec3Hash("www.test", params)
	next := append([]byte(nil), h...)
	next[0]++
	owner := strings.ToLower(base32hex.EncodeToString(h)) + ".test"
	data := append([]byte{1, 0, 0, 0, 0, 20}, next...)
	data = append(data, bitmap(TypeA, TypeRRSIG)...)
	nsec3www := RR{Name: owner, Type: TypeNSEC3, Class: ClassIN, TTL: 300, Data: data}
	set("www.test/DS", answer{authority: append(sign(test, soaTest), sign(test, nsec3www)...)})
	set("www.test/A", answer{answer: []RR{aRR("www.test", 66)}})

	// (2) exists.test: NXDOMAIN "proven" with zone att's genuine SOA and
	// its wrapping NSEC (zzz.att -> att), which covers every name that
	// sorts after zzz.att.
	nsecWrap := nsecRR("zzz.att", "att", TypeA, TypeRRSIG, TypeNSEC)
	set("exists.test/A", answer{rcode: RcodeNXDomain, authority: append(sign(att, soaRR("att")), sign(att, nsecWrap)...)})

	// (3) sub.test is a delegation (NS, no SOA). The parent's NSEC at
	// sub.test covers host.sub.test in canonical order but is the parent
	// side of the cut and cannot deny a name inside the child zone.
	nsecDeleg := nsecRR("sub.test", "zz.test", TypeNS, TypeRRSIG, TypeNSEC)
	nsecApex := nsecRR("test", "sub.test", TypeSOA, TypeNS, TypeDNSKEY, TypeRRSIG, TypeNSEC)
	set("host.sub.test/A", answer{rcode: RcodeNXDomain, authority: append(append(sign(test, soaTest), sign(test, nsecDeleg)...), sign(test, nsecApex)...)})

	// (4) other.test: a signed A record of a different name is the whole
	// answer to a question about mail.test.
	set("mail.test/A", answer{answer: sign(test, aRR("other.test", 7))})
	u.serve()
	return v
}

func TestDNSSECDowngradeAttempts(t *testing.T) {
	v := buildDowngradeHierarchy(t)
	validate := func(name string, typ uint16) (Result, Header) {
		t.Helper()
		q := withDO(mustQuery(t, 42, name, typ))
		qh, _ := ParseHeader(q)
		uq, uEnd, _ := ParseQuestion(q)
		resp, err := v.resolver.Exchange(context.Background(), q, uEnd, uq, false)
		if err != nil {
			t.Fatal(err)
		}
		res, out := v.Validate(context.Background(), q, uEnd, qh, resp)
		rh, _ := ParseHeader(out)
		return res, rh
	}
	for _, c := range []struct {
		name string
		what string
	}{
		{"www.test", "unsigned answer after an NSEC3 NODATA-for-DS at a host name"},
		{"exists.test", "NXDOMAIN proven with another zone's NSEC"},
		{"host.sub.test", "NXDOMAIN proven with the parent's NSEC of the delegation"},
		{"mail.test", "positive answer whose records belong to another name"},
	} {
		res, rh := validate(c.name, TypeA)
		if res != Bogus || rh.Rcode() != RcodeServFail || rh.Flags&flagAD != 0 {
			t.Errorf("%s (%s): got %s rcode %d AD=%v, want bogus SERVFAIL", c.name, c.what, res, rh.Rcode(), rh.Flags&flagAD != 0)
		}
	}
}

// TestAnswersQuestion pins the chain rules for positive answers: the
// query name and type, a CNAME chain from it, a DNAME at an ancestor;
// records of unrelated names do not count.
func TestAnswersQuestion(t *testing.T) {
	q := Question{Name: "www.test", Type: TypeA}
	cname := func(owner, target string) RR {
		n, _ := packName(target)
		return RR{Name: owner, Type: TypeCNAME, Class: ClassIN, TTL: 60, Data: n}
	}
	dname := func(owner, target string) RR {
		n, _ := packName(target)
		return RR{Name: owner, Type: TypeDNAME, Class: ClassIN, TTL: 60, Data: n}
	}
	cases := []struct {
		rrs  []RR
		want bool
	}{
		{[]RR{aRR("www.test", 1)}, true},
		{[]RR{aRR("other.test", 1)}, false},
		{[]RR{cname("www.test", "x.other"), aRR("x.other", 1)}, true},
		{[]RR{aRR("x.other", 1), cname("www.test", "x.other")}, true},
		{[]RR{cname("y.test", "x.other"), aRR("x.other", 1)}, false},
		{[]RR{dname("test", "other"), cname("www.test", "www.other"), aRR("www.other", 1)}, true},
		{[]RR{{Name: "www.test", Type: TypeAAAA, Class: ClassIN, TTL: 60, Data: make([]byte, 16)}}, false},
	}
	for i, c := range cases {
		if got := answersQuestion(groupRRsets(c.rrs), q); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}
