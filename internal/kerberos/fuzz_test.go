package kerberos

import (
	"testing"
	"time"
)

// FuzzParse is the guarantee the listener rests on: whatever a client
// POSTs, reading it neither panics nor reports a field that was not in it.
//
// Past "did not crash", the invariant is that what a request reports is
// consistent with what the policy will be asked about: a message that
// parsed as a request carries a realm and at least one encryption type, a
// reply carries a realm, and nothing reports a principal while saying it
// has none.
func FuzzParse(f *testing.F) {
	cname, sname := user("alice"), Principal{Type: NTSrvInst, Parts: []string{"krbtgt", "CORP"}}
	f.Add(req{typ: MsgASReq, realm: "CORP", cname: &cname, sname: &sname,
		etypes: []EType{ETypeAES256SHA1}}.build())
	f.Add(req{typ: MsgTGSReq, realm: "CORP", cname: &cname, sname: &sname,
		opts: OptConstrainedDelegation, etypes: []EType{ETypeRC4HMAC}, addTkts: 1,
		padata: []pa{{typ: PAForUser, value: forUserValue(user("admin"), "CORP")}}}.build())
	f.Add(rep{typ: MsgASRep, realm: "CORP", cname: cname, sname: sname,
		ticketEType: ETypeAES256SHA1, encEType: ETypeAES256SHA1}.build())
	f.Add(MarshalError(time.Unix(0, 0).UTC(), KDCErrPreauthRequired, "CORP",
		KrbtgtFor("CORP"), "no"))
	f.Add(apReq("CORP", Principal{Type: NTSrvInst, Parts: []string{"kadmin", "changepw"}}))

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := Parse(raw)
		if err != nil {
			return
		}
		if m.Realm == "" {
			t.Fatalf("%s parsed with no realm", m.Type)
		}
		if m.Type.Request() && m.Type != MsgAPReq && len(m.ETypes) == 0 {
			t.Fatalf("%s parsed with no encryption type", m.Type)
		}
		if !m.HasClient && !m.Client.Empty() {
			t.Fatal("a principal was read into a field reported as absent")
		}
		if !m.HasServer && !m.Server.Empty() {
			t.Fatal("a principal was read into a field reported as absent")
		}
		if !m.HasForUser && !m.ForUser.Empty() {
			t.Fatal("a for-user was read into a field reported as absent")
		}
		// Every accessor runs on whatever came through.
		_ = m.Summary()
		_ = m.Options.Names()
		_ = m.Options.String()
		_ = m.WeakETypes()
		_ = m.OnlyWeakETypes()
		_ = m.Preauthenticated()
		_ = m.S4U2Self()
		_ = m.S4U2Proxy()
		_, _ = m.Lifetime(time.Unix(0, 0))
		_ = m.Client.IsKrbtgt()
		_ = m.Server.Service()
		_ = ErrorName(m.ErrorCode)
		for _, p := range m.PAData {
			_ = p.Preauth()
			_ = p.String()
		}
		for _, e := range m.ETypes {
			_ = e.Weak()
			_ = e.String()
		}
	})
}

// FuzzProxyMessage is the same for the envelope, which is the first thing
// an HTTP body becomes and therefore the first thing an unauthenticated
// POST reaches.
func FuzzProxyMessage(f *testing.F) {
	cname := user("alice")
	inner := req{typ: MsgASReq, realm: "CORP", cname: &cname,
		etypes: []EType{ETypeAES256SHA1}}.build()
	f.Add(MarshalProxyMessage(inner, "CORP"))
	f.Add(MarshalProxyMessage(inner, ""))
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := ParseProxyMessage(raw, 1<<16)
		if err != nil {
			return
		}
		if len(m.Inner) == 0 {
			t.Fatal("an envelope parsed with an empty inner message")
		}
		if len(m.Inner) > 1<<16 {
			t.Fatalf("inner message of %d octets past the bound", len(m.Inner))
		}
		// Re-wrapping and re-reading gives the same inner message back,
		// which is what the relay does on the reply leg.
		again, err := ParseProxyMessage(MarshalProxyMessage(m.Inner, m.TargetDomain), 1<<16)
		if err != nil {
			t.Fatalf("re-wrapped envelope would not parse: %v", err)
		}
		if string(again.Inner) != string(m.Inner) {
			t.Fatal("the inner message changed on a round trip")
		}
		_, _ = Parse(m.Inner)
	})
}
