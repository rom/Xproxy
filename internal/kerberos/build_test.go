package kerberos

import "time"

// A builder, so the tests read as Kerberos rather than as hexadecimal.
//
// It renders DER because the tests have to: this package encodes only a
// KRB-ERROR and the proxy envelope, so nothing in it can produce a request
// or a reply, and a test that pasted captured octets would be a test
// nobody can change when a case is added.

// req is the request a test builds.
type req struct {
	typ      MsgType
	realm    string
	cname    *Principal
	sname    *Principal
	opts     Options
	etypes   []EType
	padata   []pa
	till     time.Time
	from     time.Time
	hasFrom  bool
	nonce    int64
	addTkts  int
	addrs    int
	omitTill bool
	pvno     int64
}

// pa is one pre-authentication element.
type pa struct {
	typ   PAType
	value []byte
}

// build renders a KDC-REQ.
func (r req) build() []byte {
	pvno := r.pvno
	if pvno == 0 {
		pvno = 5
	}
	var body []byte
	body = append(body, ctxInt(1, pvno)...)
	body = append(body, ctxInt(2, int64(r.typ))...)
	if len(r.padata) > 0 {
		var list []byte
		for _, p := range r.padata {
			inner := append(ctxInt(1, int64(p.typ)),
				derTLV(classContext|constructed, 2,
					derTLV(classUniversal, tagOctetString, p.value))...)
			list = append(list, derTLV(classUniversal|constructed, tagSequence, inner)...)
		}
		body = append(body, derTLV(classContext|constructed, 3,
			derTLV(classUniversal|constructed, tagSequence, list))...)
	}
	body = append(body, derTLV(classContext|constructed, 4,
		derTLV(classUniversal|constructed, tagSequence, r.reqBody()))...)
	seq := derTLV(classUniversal|constructed, tagSequence, body)
	return derTLV(classApplication|constructed, uint32(r.typ), seq)
}

// reqBody renders a KDC-REQ-BODY.
func (r req) reqBody() []byte {
	var b []byte
	b = append(b, ctxBits(0, r.opts)...)
	if r.cname != nil {
		b = append(b, ctxPrincipal(1, *r.cname)...)
	}
	b = append(b, ctxString(2, r.realm)...)
	if r.sname != nil {
		b = append(b, ctxPrincipal(3, *r.sname)...)
	}
	if r.hasFrom {
		b = append(b, ctxTime(4, r.from)...)
	}
	if !r.omitTill {
		till := r.till
		if till.IsZero() {
			till = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
		}
		b = append(b, ctxTime(5, till)...)
	}
	b = append(b, ctxInt(7, r.nonce)...)
	var etypes []byte
	for _, e := range r.etypes {
		etypes = append(etypes, derInt(int64(e))...)
	}
	b = append(b, derTLV(classContext|constructed, 8,
		derTLV(classUniversal|constructed, tagSequence, etypes))...)
	if r.addrs > 0 {
		var list []byte
		for i := 0; i < r.addrs; i++ {
			list = append(list, derTLV(classUniversal|constructed, tagSequence,
				append(ctxInt(0, 2), derTLV(classContext|constructed, 1,
					derTLV(classUniversal, tagOctetString, []byte{10, 0, 0, byte(i)}))...))...)
		}
		b = append(b, derTLV(classContext|constructed, 9,
			derTLV(classUniversal|constructed, tagSequence, list))...)
	}
	if r.addTkts > 0 {
		var list []byte
		for i := 0; i < r.addTkts; i++ {
			list = append(list, ticket("OTHER.EXAMPLE",
				Principal{Type: NTSrvInst, Parts: []string{"krbtgt", "OTHER.EXAMPLE"}},
				ETypeAES256SHA1)...)
		}
		b = append(b, derTLV(classContext|constructed, 11,
			derTLV(classUniversal|constructed, tagSequence, list))...)
	}
	return b
}

// ctxBits renders [tag] EXPLICIT BIT STRING over a 32-bit options word.
func ctxBits(tag uint32, o Options) []byte {
	v := uint32(o)
	bits := []byte{0, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	return derTLV(classContext|constructed, tag, derTLV(classUniversal, tagBitString, bits))
}

// ticket renders a Ticket with its plaintext fields and an EncryptedData
// naming an encryption type.
func ticket(realm string, sname Principal, et EType) []byte {
	var b []byte
	b = append(b, ctxInt(0, 5)...)
	b = append(b, ctxString(1, realm)...)
	b = append(b, ctxPrincipal(2, sname)...)
	b = append(b, derTLV(classContext|constructed, 3, encryptedData(et))...)
	seq := derTLV(classUniversal|constructed, tagSequence, b)
	return derTLV(classApplication|constructed, 1, seq)
}

// encryptedData renders an EncryptedData whose cipher is a stand-in: the
// etype is the only field in it a relay reads.
func encryptedData(et EType) []byte {
	inner := append(ctxInt(0, int64(et)),
		derTLV(classContext|constructed, 2,
			derTLV(classUniversal, tagOctetString, []byte{1, 2, 3, 4}))...)
	return derTLV(classUniversal|constructed, tagSequence, inner)
}

// rep is the reply a test builds.
type rep struct {
	typ         MsgType
	realm       string
	cname       Principal
	sname       Principal
	ticketEType EType
	encEType    EType
	padata      []pa
}

// build renders a KDC-REP.
func (r rep) build() []byte {
	var body []byte
	body = append(body, ctxInt(0, 5)...)
	body = append(body, ctxInt(1, int64(r.typ))...)
	if len(r.padata) > 0 {
		var list []byte
		for _, p := range r.padata {
			inner := append(ctxInt(1, int64(p.typ)),
				derTLV(classContext|constructed, 2,
					derTLV(classUniversal, tagOctetString, p.value))...)
			list = append(list, derTLV(classUniversal|constructed, tagSequence, inner)...)
		}
		body = append(body, derTLV(classContext|constructed, 2,
			derTLV(classUniversal|constructed, tagSequence, list))...)
	}
	body = append(body, ctxString(3, r.realm)...)
	body = append(body, ctxPrincipal(4, r.cname)...)
	body = append(body, derTLV(classContext|constructed, 5,
		ticket(r.realm, r.sname, r.ticketEType))...)
	body = append(body, derTLV(classContext|constructed, 6, encryptedData(r.encEType))...)
	seq := derTLV(classUniversal|constructed, tagSequence, body)
	return derTLV(classApplication|constructed, uint32(r.typ), seq)
}

// apReq renders an AP-REQ, which is what reaches a listener that carries
// password changes.
func apReq(realm string, sname Principal) []byte {
	var body []byte
	body = append(body, ctxInt(0, 5)...)
	body = append(body, ctxInt(1, int64(MsgAPReq))...)
	body = append(body, ctxBits(2, 0)...)
	body = append(body, derTLV(classContext|constructed, 3,
		ticket(realm, sname, ETypeAES256SHA1))...)
	body = append(body, derTLV(classContext|constructed, 4, encryptedData(ETypeAES256SHA1))...)
	seq := derTLV(classUniversal|constructed, tagSequence, body)
	return derTLV(classApplication|constructed, uint32(MsgAPReq), seq)
}

// forUserValue renders a PA-FOR-USER naming the principal an S4U2Self
// request asks to impersonate.
func forUserValue(user Principal, realm string) []byte {
	body := append(ctxPrincipal(0, user), ctxString(1, realm)...)
	return derTLV(classUniversal|constructed, tagSequence, body)
}

// user and svc are the two principals the tests keep naming.
func user(name string) Principal {
	return Principal{Type: NTPrincipal, Parts: []string{name}}
}

func svc(class, host string) Principal {
	return Principal{Type: NTSrvHst, Parts: []string{class, host}}
}
