package kerberos

import (
	"testing"
	"time"
)

// What this reader does with input nobody meant it to read.
//
// The listener in front of a KDC reads every message before the KDC does, so
// this parser is what stands between a domain controller and whatever can
// reach the proxy's port. The fuzz target states the invariant; these are the
// two systematic sweeps a run without the fuzzer still performs, so a change
// that breaks one of them fails an ordinary `go test`.

// seeds are well formed messages of each kind the relay reads.
func seeds() map[string][]byte {
	cname := user("alice")
	sname := Principal{Type: NTSrvInst, Parts: []string{"krbtgt", "CORP.EXAMPLE"}}
	svc := Principal{Type: NTSrvInst, Parts: []string{"cifs", "files.corp.example"}}
	till := time.Date(2026, 10, 2, 22, 0, 0, 0, time.UTC)
	return map[string][]byte{
		"an AS-REQ": req{typ: MsgASReq, realm: "CORP.EXAMPLE", cname: &cname, sname: &sname,
			opts: OptForwardable | OptRenewableOK, till: till, nonce: 12345,
			etypes: []EType{ETypeAES256SHA1, ETypeRC4HMAC},
			padata: []pa{{typ: PAEncTimestamp, value: []byte{9, 9}}}}.build(),
		"a TGS-REQ": req{typ: MsgTGSReq, realm: "CORP.EXAMPLE", cname: &cname, sname: &svc,
			opts: OptConstrainedDelegation, etypes: []EType{ETypeAES256SHA1}, addTkts: 1,
			till: till, nonce: 7,
			padata: []pa{{typ: PAForUser, value: forUserValue(user("admin"), "CORP.EXAMPLE")}}}.build(),
		"an AS-REP": rep{typ: MsgASRep, realm: "CORP.EXAMPLE", cname: cname, sname: sname,
			ticketEType: ETypeAES256SHA1, encEType: ETypeAES256SHA1}.build(),
		"a KRB-ERROR": MarshalError(time.Unix(0, 0).UTC(), KDCErrPreauthRequired,
			"CORP.EXAMPLE", KrbtgtFor("CORP.EXAMPLE"), "pre-authentication required"),
		"an AP-REQ": apReq("CORP.EXAMPLE", svc),
	}
}

// consistent is the fuzz target's invariant: a message that parsed reports
// only fields that were in it. It is the part that matters past "did not
// crash" -- the policy is asked about these fields, so a field invented by a
// parse is a rule applied to something nobody sent.
func consistent(t *testing.T, what string, m Message) {
	t.Helper()
	if m.Realm == "" {
		t.Fatalf("%s: %s parsed with no realm", what, m.Type)
	}
	if m.Type.Request() && m.Type != MsgAPReq && len(m.ETypes) == 0 {
		t.Fatalf("%s: %s parsed with no encryption type", what, m.Type)
	}
	if !m.HasClient && !m.Client.Empty() {
		t.Fatalf("%s: a principal was read into a field reported as absent", what)
	}
	if !m.HasServer && !m.Server.Empty() {
		t.Fatalf("%s: a principal was read into a field reported as absent", what)
	}
	if !m.HasForUser && !m.ForUser.Empty() {
		t.Fatalf("%s: a for-user was read into a field reported as absent", what)
	}
	// Every accessor the listener calls runs on whatever came through, because
	// a policy that panicked on an odd message would be a refusal nobody
	// configured.
	_ = m.Summary()
	_ = m.Options.Names()
	_ = m.WeakETypes()
	_ = m.OnlyWeakETypes()
	_ = m.Preauthenticated()
	_ = m.S4U2Self()
	_ = m.S4U2Proxy()
	_, _ = m.Lifetime(time.Unix(0, 0))
	_ = m.Server.Service()
}

// A message cut short is not a message. Every DER element says its own
// length, so a prefix is either an element whose content is missing or a
// sequence that ends inside a field -- and a reader that answered about the
// fields it did manage to read would be answering about a message the KDC
// will never see.
func TestAMessageCutShortIsNeverAMessage(t *testing.T) {
	t.Parallel()
	for what, raw := range seeds() {
		if _, err := Parse(raw); err != nil {
			t.Fatalf("%s: the whole message did not parse: %v", what, err)
		}
		for n := range len(raw) {
			if m, err := Parse(raw[:n]); err == nil {
				t.Errorf("%s: the first %d of %d octets parsed as %s", what, n, len(raw), m.Type)
			}
		}
	}
}

// Every one-octet change to a well formed message, which is the shape of a
// tampered or a truncated-and-patched request. Each one is read or refused,
// and what is read is consistent with what the policy will be asked about.
//
// The values are the ones that break an encoding: a zero tag or length, the
// long-form length bit, a maximal octet, and a low value that is a different
// tag. Between them they move every field's boundary.
func TestEverySingleOctetChangeIsReadOrRefused(t *testing.T) {
	t.Parallel()
	for what, raw := range seeds() {
		for i := range raw {
			for _, v := range []byte{0x00, 0x01, 0x05, 0x7f, 0x80, 0xa0, 0xff} {
				if raw[i] == v {
					continue
				}
				b := append([]byte(nil), raw...)
				b[i] = v
				m, err := Parse(b)
				if err != nil {
					continue
				}
				consistent(t, what, m)
			}
		}
	}
}

// And every octet dropped, which moves everything after it by one and leaves
// the lengths saying what they said.
func TestEveryDroppedOctetIsReadOrRefused(t *testing.T) {
	t.Parallel()
	for what, raw := range seeds() {
		for i := range raw {
			b := make([]byte, 0, len(raw)-1)
			b = append(b, raw[:i]...)
			b = append(b, raw[i+1:]...)
			m, err := Parse(b)
			if err != nil {
				continue
			}
			consistent(t, what, m)
		}
	}
}

// The same two sweeps over the KKDCP envelope, which is the outer message
// and the one a client reaches over HTTP. A proxy that read a tampered
// envelope as a shorter one would be forwarding the tail of it to the KDC as
// a message of its own.
func TestTheEnvelopeSurvivesTheSameSweeps(t *testing.T) {
	t.Parallel()
	cname := user("alice")
	sname := Principal{Type: NTSrvInst, Parts: []string{"krbtgt", "CORP.EXAMPLE"}}
	inner := req{typ: MsgASReq, realm: "CORP.EXAMPLE", cname: &cname, sname: &sname,
		etypes: []EType{ETypeAES256SHA1}}.build()
	framed := make([]byte, 0, 4+len(inner))
	framed = append(framed, byte(len(inner)>>24), byte(len(inner)>>16),
		byte(len(inner)>>8), byte(len(inner)))
	framed = append(framed, inner...)

	for what, raw := range map[string][]byte{
		"an envelope naming a realm": MarshalProxyMessage(framed, "CORP.EXAMPLE"),
		"an envelope naming none":    MarshalProxyMessage(framed, ""),
	} {
		if _, err := ParseProxyMessage(raw, 1<<16); err != nil {
			t.Fatalf("%s did not parse: %v", what, err)
		}
		for n := range len(raw) {
			if _, err := ParseProxyMessage(raw[:n], 1<<16); err == nil {
				t.Errorf("%s: the first %d of %d octets parsed", what, n, len(raw))
			}
		}
		for i := range raw {
			for _, v := range []byte{0x00, 0x01, 0x04, 0x30, 0x80, 0xa0, 0xff} {
				if raw[i] == v {
					continue
				}
				b := append([]byte(nil), raw...)
				b[i] = v
				m, err := ParseProxyMessage(b, 1<<16)
				if err != nil {
					continue
				}
				// What came through has to round-trip: the envelope this
				// relay writes towards the KDC is built from these fields,
				// so a field read loosely here is a field sent on.
				again, err := ParseProxyMessage(
					MarshalProxyMessage(m.Inner, m.TargetDomain), 1<<16)
				if err != nil {
					t.Fatalf("%s at %d=%#x: re-reading what was built: %v", what, i, v, err)
				}
				if again.TargetDomain != m.TargetDomain || len(again.Inner) != len(m.Inner) {
					t.Errorf("%s at %d=%#x: round trip changed it", what, i, v)
				}
			}
		}
	}
}

// The encryption type names a rule is written with, including the short
// spellings an operator actually types. A name this does not know has to be a
// load error rather than a rule about a type number nothing uses: the rules
// here are what refuse RC4, and one that silently matched nothing would be a
// weak-crypto policy that is not there.
func TestTheEncryptionTypeNamesARuleIsWrittenWith(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		want EType
	}{
		{"aes128", ETypeAES128SHA1},
		{"aes256", ETypeAES256SHA1},
		{"AES256", ETypeAES256SHA1},
		{"rc4", ETypeRC4HMAC},
		{"arcfour", ETypeRC4HMAC},
		{"arcfour_hmac_md5", ETypeRC4HMAC},
		{" rc4 ", ETypeRC4HMAC},
	} {
		got, ok := ETypeOf(c.name)
		if !ok || got != c.want {
			t.Errorf("%q read as %v, %v; want %v", c.name, got, ok, c.want)
		}
	}
	for _, name := range []string{"", "aes", "aes512", "des", "three-des", "aes-256"} {
		if got, ok := ETypeOf(name); ok {
			t.Errorf("%q read as %v, which is not a name this knows", name, got)
		}
	}
}
