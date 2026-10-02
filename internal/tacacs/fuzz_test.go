package tacacs

import "testing"

// FuzzHeader is the guarantee that a twelve-octet header from a network
// device cannot make this reader allocate or slice out of proportion to
// it: a parsed header's length is within the bound, and a header writes
// back to the octets it was read from.
func FuzzHeader(f *testing.F) {
	f.Add(header(TypeAuthen, 1, 0, 1, 24).Marshal())
	f.Add(header(TypeAuthor, 3, FlagSingleConnect, 0xdeadbeef, 64).Marshal())
	f.Add(header(TypeAcct, 2, FlagUnencrypted, 7, 0).Marshal())
	f.Add(make([]byte, 12))

	f.Fuzz(func(t *testing.T, raw []byte) {
		h, err := ParseHeader(raw)
		if err != nil {
			return
		}
		if h.Length < 0 || h.Length > MaxBody {
			t.Fatalf("length %d is outside the bound", h.Length)
		}
		out := h.Marshal()
		for i := range out {
			if out[i] != raw[i] {
				t.Fatalf("header %x wrote back as %x", raw[:HeaderBytes], out)
			}
		}
		_ = h.Unencrypted()
		_ = h.SingleConnect()
		_ = h.FromClient()
		_ = h.Type.String()
	})
}

// FuzzBodies is the same guarantee for the six bodies. Each is read with
// the parser for its own exchange, because a relay knows the type from the
// header before it reads the body -- and a body that parses must have
// accounted for every octet, which is what the length arithmetic in each
// parser is for.
func FuzzBodies(f *testing.F) {
	lens, strs := lens3("alice", "tty0", "10.0.0.9")
	start := append([]byte{byte(ActionLogin), 15, byte(AuthenPAP), byte(ServiceLogin)}, lens...)
	start = append(start, 0)
	f.Add(append(start, strs...))
	f.Add(MarshalAuthenReply(AuthenReply{Status: AuthenGetPass, ServerMsg: "Password: "}))
	f.Add([]byte{0, 6, 0, 0, 0, 's', 'e', 'c', 'r', 'e', 't'})
	alens, abody := argBody("service=shell", "cmd=show", "cmd-arg=version")
	author := append([]byte{byte(MethodTACACSPlus), 15, byte(AuthenASCII), byte(ServiceLogin)}, lens...)
	author = append(author, byte(len(alens)))
	author = append(author, alens...)
	author = append(author, strs...)
	f.Add(append(author, abody...))
	f.Add(MarshalAuthorResponse(AuthorResponse{Status: AuthorPassAdd,
		Args: Args{{Name: "priv-lvl", Value: "15", Mandatory: true}}}))
	f.Add(MarshalAcctReply(AcctReply{Status: AcctSuccess}))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if s, err := ParseAuthenStart(raw); err == nil {
			if s.DataBytes < 0 || s.DataBytes > len(raw) {
				t.Fatalf("data bytes %d from a body of %d", s.DataBytes, len(raw))
			}
			_ = s.Action.String()
			_ = s.Type.Plaintext()
		}
		if r, err := ParseAuthenReply(raw); err == nil {
			_ = r.Status.String()
			if len(r.ServerMsg)+r.DataBytes+6 != len(raw) {
				t.Fatalf("reply fields do not account for %d octets", len(raw))
			}
		}
		if c, err := ParseAuthenContinue(raw); err == nil {
			if c.UserMsgBytes+c.DataBytes+5 != len(raw) {
				t.Fatalf("continue fields do not account for %d octets", len(raw))
			}
		}
		if r, err := ParseAuthorRequest(raw); err == nil {
			_ = r.Args.Command()
			_ = r.Args.Service()
			_, _ = r.Args.PrivLvl()
			_ = r.Args.Names()
			_ = r.Method.Unauthenticated()
			for _, a := range r.Args {
				_ = a.String()
			}
		}
		if r, err := ParseAuthorResponse(raw); err == nil {
			_ = r.Status.Pass()
			_, _ = r.Args.PrivLvl()
		}
		if r, err := ParseAcctRequest(raw); err == nil {
			_ = AcctRecord(r.Flags)
			_ = r.Args.Command()
		}
		if r, err := ParseAcctReply(raw); err == nil {
			_ = r.Status.String()
		}
	})
}
