package kkdcp

import (
	"time"

	wire "github.com/rom/xproxy/internal/kerberos"
)

// A Kerberos message builder, so the tests read as the protocol rather than
// as hexadecimal.
//
// The wire package encodes only a KRB-ERROR and the proxy envelope -- those
// are the two a relay writes itself -- so a test that needs a request or a
// reply has to render one, and the DER here is the smallest writer that will
// do it. It is deliberately not shared with internal/kerberos's own builder:
// a test that borrowed the parser's encoder would prove the two agree with
// each other rather than with the standard.

// The DER class bits and the tags this builder writes.
const (
	cUniversal   = 0x00
	cApplication = 0x40
	cContext     = 0x80
	cons         = 0x20
)

const (
	tInteger   = 0x02
	tBitString = 0x03
	tOctetStr  = 0x04
	tSequence  = 0x10
	tGenString = 0x1b
	tGenTime   = 0x18
)

// tlv writes one element with a definite length in the shortest form.
func tlv(class byte, tag uint32, body ...[]byte) []byte {
	var data []byte
	for _, b := range body {
		data = append(data, b...)
	}
	out := []byte{class | byte(tag)}
	switch n := len(data); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 1<<8:
		out = append(out, 0x81, byte(n))
	case n < 1<<16:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, data...)
}

// derInt renders an INTEGER in the minimal two's-complement form.
func derInt(v int64) []byte {
	var b []byte
	n := v
	for {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
		if n == 0 && b[0]&0x80 == 0 {
			break
		}
		if n == -1 && b[0]&0x80 != 0 {
			break
		}
	}
	return tlv(cUniversal, tInteger, b)
}

func ctxInt(tag uint32, v int64) []byte { return tlv(cContext|cons, tag, derInt(v)) }
func ctxStr(tag uint32, s string) []byte {
	return tlv(cContext|cons, tag, tlv(cUniversal, tGenString, []byte(s)))
}

func ctxTime(tag uint32, t time.Time) []byte {
	return tlv(cContext|cons, tag,
		tlv(cUniversal, tGenTime, []byte(t.UTC().Format("20060102150405Z"))))
}

func ctxBits(tag uint32, o wire.Options) []byte {
	v := uint32(o)
	return tlv(cContext|cons, tag, tlv(cUniversal, tBitString,
		[]byte{0, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}))
}

func ctxPrincipal(tag uint32, p wire.Principal) []byte {
	var parts []byte
	for _, s := range p.Parts {
		parts = append(parts, tlv(cUniversal, tGenString, []byte(s))...)
	}
	body := append(ctxInt(0, int64(p.Type)),
		tlv(cContext|cons, 1, tlv(cUniversal|cons, tSequence, parts))...)
	return tlv(cContext|cons, tag, tlv(cUniversal|cons, tSequence, body))
}

// user, svc and krbtgt are the three principals the tests keep naming.
func user(name string) wire.Principal {
	return wire.Principal{Type: wire.NTPrincipal, Parts: []string{name}}
}

func svc(class, host string) wire.Principal {
	return wire.Principal{Type: wire.NTSrvHst, Parts: []string{class, host}}
}

func krbtgt(realm string) wire.Principal {
	return wire.Principal{Type: wire.NTSrvInst, Parts: []string{"krbtgt", realm}}
}

// req is the request under construction, so an option can be a function.
type req struct {
	padata  [][2]any
	options wire.Options
	addTkts int
}

type reqOpt func(*req)

// withPreauth adds a PA-ENC-TIMESTAMP, which is the client proving it knows
// the password.
func withPreauth() reqOpt {
	return func(r *req) {
		r.padata = append(r.padata, [2]any{wire.PAEncTimestamp, []byte{1, 2, 3, 4}})
	}
}

// withForUser adds a PA-FOR-USER, which is S4U2Self and names the
// impersonated principal in the clear.
func withForUser(p wire.Principal, realm string) reqOpt {
	return func(r *req) {
		body := append(ctxPrincipal(0, p), ctxStr(1, realm)...)
		r.padata = append(r.padata, [2]any{wire.PAForUser,
			tlv(cUniversal|cons, tSequence, body)})
	}
}

func withOptions(o wire.Options) reqOpt {
	return func(r *req) { r.options |= o }
}

// withAdditionalTicket adds one ticket, which is the other half of S4U2Proxy.
func withAdditionalTicket() reqOpt {
	return func(r *req) { r.addTkts++ }
}

// asReq and tgsReq render a KDC-REQ.
func asReq(realm string, cname wire.Principal, etypes []wire.EType, opts ...reqOpt) []byte {
	return kdcReq(wire.MsgASReq, realm, &cname, ptr(krbtgt(realm)), etypes, opts...)
}

func tgsReq(realm string, cname, sname wire.Principal, etypes []wire.EType, opts ...reqOpt) []byte {
	return kdcReq(wire.MsgTGSReq, realm, &cname, &sname, etypes, opts...)
}

func ptr(p wire.Principal) *wire.Principal { return &p }

func kdcReq(typ wire.MsgType, realm string, cname, sname *wire.Principal,
	etypes []wire.EType, opts ...reqOpt) []byte {
	r := &req{}
	for _, o := range opts {
		o(r)
	}
	if typ == wire.MsgTGSReq {
		// A TGS request carries its ticket-granting ticket as padata, which is
		// what makes it one in substance as well as in message type.
		r.padata = append([][2]any{{wire.PATGSReq, []byte{9}}}, r.padata...)
	}
	var body []byte
	body = append(body, ctxInt(1, 5)...)
	body = append(body, ctxInt(2, int64(typ))...)
	if len(r.padata) > 0 {
		var list []byte
		for _, p := range r.padata {
			inner := append(ctxInt(1, int64(p[0].(wire.PAType))),
				tlv(cContext|cons, 2, tlv(cUniversal, tOctetStr, p[1].([]byte)))...)
			list = append(list, tlv(cUniversal|cons, tSequence, inner)...)
		}
		body = append(body, tlv(cContext|cons, 3, tlv(cUniversal|cons, tSequence, list))...)
	}
	body = append(body, tlv(cContext|cons, 4,
		tlv(cUniversal|cons, tSequence, reqBody(realm, cname, sname, etypes, r)))...)
	return tlv(cApplication|cons, uint32(typ), tlv(cUniversal|cons, tSequence, body))
}

func reqBody(realm string, cname, sname *wire.Principal, etypes []wire.EType, r *req) []byte {
	var b []byte
	b = append(b, ctxBits(0, r.options)...)
	if cname != nil {
		b = append(b, ctxPrincipal(1, *cname)...)
	}
	b = append(b, ctxStr(2, realm)...)
	if sname != nil {
		b = append(b, ctxPrincipal(3, *sname)...)
	}
	b = append(b, ctxTime(5, time.Now().Add(10*time.Hour))...)
	b = append(b, ctxInt(7, 12345)...)
	var list []byte
	for _, e := range etypes {
		list = append(list, derInt(int64(e))...)
	}
	b = append(b, tlv(cContext|cons, 8, tlv(cUniversal|cons, tSequence, list))...)
	if r.addTkts > 0 {
		var tickets []byte
		for i := 0; i < r.addTkts; i++ {
			tickets = append(tickets, ticket(realm, krbtgt(realm), wire.ETypeAES256SHA1)...)
		}
		b = append(b, tlv(cContext|cons, 11, tlv(cUniversal|cons, tSequence, tickets))...)
	}
	return b
}

// ticket renders a Ticket, whose plaintext names the service and whose
// EncryptedData names the type its contents are in.
func ticket(realm string, sname wire.Principal, et wire.EType) []byte {
	var b []byte
	b = append(b, ctxInt(0, 5)...)
	b = append(b, ctxStr(1, realm)...)
	b = append(b, ctxPrincipal(2, sname)...)
	b = append(b, tlv(cContext|cons, 3, encryptedData(et))...)
	return tlv(cApplication|cons, 1, tlv(cUniversal|cons, tSequence, b))
}

func encryptedData(et wire.EType) []byte {
	inner := append(ctxInt(0, int64(et)),
		tlv(cContext|cons, 2, tlv(cUniversal, tOctetStr, []byte{1, 2, 3, 4}))...)
	return tlv(cUniversal|cons, tSequence, inner)
}

// asRep and tgsRep render a KDC-REP. padata is what a KDC echoes back, which
// on this protocol it does only sometimes.
func asRep(realm string, cname, sname wire.Principal, ticketEType wire.EType,
	padata []wire.PAType) []byte {
	return kdcRep(wire.MsgASRep, realm, cname, sname, ticketEType, padata)
}

func tgsRep(realm string, cname, sname wire.Principal, ticketEType wire.EType) []byte {
	return kdcRep(wire.MsgTGSRep, realm, cname, sname, ticketEType, nil)
}

func kdcRep(typ wire.MsgType, realm string, cname, sname wire.Principal,
	ticketEType wire.EType, padata []wire.PAType) []byte {
	var body []byte
	body = append(body, ctxInt(0, 5)...)
	body = append(body, ctxInt(1, int64(typ))...)
	if len(padata) > 0 {
		var list []byte
		for _, p := range padata {
			inner := append(ctxInt(1, int64(p)),
				tlv(cContext|cons, 2, tlv(cUniversal, tOctetStr, []byte{1}))...)
			list = append(list, tlv(cUniversal|cons, tSequence, inner)...)
		}
		body = append(body, tlv(cContext|cons, 2, tlv(cUniversal|cons, tSequence, list))...)
	}
	body = append(body, ctxStr(3, realm)...)
	body = append(body, ctxPrincipal(4, cname)...)
	body = append(body, tlv(cContext|cons, 5, ticket(realm, sname, ticketEType))...)
	body = append(body, tlv(cContext|cons, 6, encryptedData(wire.ETypeAES256SHA1))...)
	return tlv(cApplication|cons, uint32(typ), tlv(cUniversal|cons, tSequence, body))
}
