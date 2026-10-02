package radius

import "testing"

// FuzzParse is the guarantee the relay rests on: whatever arrives on UDP
// 1812, reading it neither panics nor reports more than it read.
//
// The invariant checked past "did not crash" is that a parse never looks
// outside the length field. Every attribute's value has to lie inside
// Raw, which is the packet truncated to that field -- because an
// attribute whose value came from the padding is an attribute the server
// will not see, and a policy that decided on one would be deciding about
// a different packet than the one the server answers.
func FuzzParse(f *testing.F) {
	f.Add(packet(CodeAccessRequest, 1, auth16(1), attr(AttrUserName, 'b', 'o', 'b')))
	f.Add(packet(CodeAccessRequest, 2, auth16(2),
		attr(AttrUserName, 'a', '@', 'r'), attr(AttrUserPassword, make([]byte, 16)...)))
	f.Add(packet(CodeAccessAccept, 3, auth16(3), vsa(VendorCisco, 1, []byte("shell:priv-lvl=15")...)))
	f.Add(packet(CodeAccessRequest, 4, auth16(4), attr(AttrEAPMessage, 2, 1, 0, 6, 1, 'x')))
	f.Add(packet(CodeAccessRequest, 5, auth16(5), attr(AttrMessageAuthenticator, make([]byte, 16)...)))
	f.Add(packet(CodeCoARequest, 6, auth16(6), attr(AttrState, 1, 2, 3)))
	f.Add(packet(CodeAccessRequest, 7, auth16(7), attr(241, 7, 'x')))
	f.Add(packet(CodeAccountingRequest, 8, auth16(0), attr(AttrAcctStatusType, 0, 0, 0, 1)))

	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := Parse(raw)
		if err != nil {
			return
		}
		if len(p.Raw) != p.Length || p.Length > len(raw) {
			t.Fatalf("Raw is %d octets for a length of %d from %d", len(p.Raw), p.Length, len(raw))
		}
		for _, a := range p.Attrs {
			if a.Offset < HeaderBytes || a.Offset > len(p.Raw) {
				t.Fatalf("attribute %v starts at %d, outside the packet", a.Type, a.Offset)
			}
			if a.Offset+len(a.Value) > len(p.Raw) {
				t.Fatalf("attribute %v runs to %d past a packet of %d",
					a.Type, a.Offset+len(a.Value), len(p.Raw))
			}
		}
		// Every accessor runs on whatever came through, because the relay
		// calls them on exactly this input and a panic in one is a panic a
		// datagram can cause.
		_ = p.UserName()
		_, _ = p.PasswordBytes()
		_ = p.AuthType()
		_, _ = p.PrivilegeLevel()
		_ = p.Administrative()
		_ = p.Summary()
		_ = p.String()
		_ = p.Count(AttrProxyState)
		if e, err := p.EAP(); err == nil {
			_ = e.Method()
			_ = e.Type.Weak()
			_ = e.Type.Tunnelled()
		}
		secret := []byte("k")
		var ra [AuthenticatorBytes]byte
		_ = p.VerifyMessageAuthenticator(secret, ra)
		_ = p.VerifyResponseAuthenticator(secret, ra)
		_ = p.ResponseAuthenticator(secret, ra)
		for _, a := range p.Attrs {
			_, _ = a.Text()
			_, _ = a.Uint32()
			_ = a.Name()
		}
		_, _ = Realm(p.UserName())
	})
}
