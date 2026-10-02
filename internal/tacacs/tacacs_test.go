package tacacs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// A builder, so the tests read as TACACS+ rather than as hexadecimal.

func header(typ Type, seq, flags uint8, session uint32, n int) Header {
	return Header{VersionMajor: VersionMajor, VersionMinor: 0, Type: typ,
		Seq: seq, Flags: flags, SessionID: session, Length: n}
}

// strs renders the three length-prefixed strings every request body has.
func lens3(user, port, rem string) ([]byte, []byte) {
	return []byte{byte(len(user)), byte(len(port)), byte(len(rem))},
		[]byte(user + port + rem)
}

// argBody renders an argument list: the lengths, then the strings.
func argBody(args ...string) (lens, body []byte) {
	for _, a := range args {
		lens = append(lens, byte(len(a)))
		body = append(body, a...)
	}
	return lens, body
}

func TestAHeaderIsRefusedBeforeAnythingIsAllocatedForIt(t *testing.T) {
	t.Parallel()
	ok := header(TypeAuthen, 1, 0, 0xdeadbeef, 24).Marshal()
	t.Run("a good one reads back", func(t *testing.T) {
		t.Parallel()
		h, err := ParseHeader(ok)
		if err != nil {
			t.Fatalf("ParseHeader: %v", err)
		}
		if h.Type != TypeAuthen || h.Seq != 1 || h.SessionID != 0xdeadbeef || h.Length != 24 {
			t.Fatalf("header = %+v", h)
		}
		if !h.FromClient() {
			t.Error("sequence 1 is not reported as the client's")
		}
		if h2 := header(TypeAuthen, 2, 0, 1, 0); h2.FromClient() {
			t.Error("sequence 2 is reported as the client's")
		}
	})
	t.Run("a major version that is not 0xc is refused", func(t *testing.T) {
		t.Parallel()
		b := bytes.Clone(ok)
		b[0] = 0xb0
		if _, err := ParseHeader(b); !errors.Is(err, ErrVersion) {
			t.Fatalf("err = %v, want ErrVersion", err)
		}
	})
	t.Run("sequence number zero is refused", func(t *testing.T) {
		t.Parallel()
		b := bytes.Clone(ok)
		b[2] = 0
		if _, err := ParseHeader(b); !errors.Is(err, ErrZeroSeq) {
			t.Fatalf("err = %v, want ErrZeroSeq", err)
		}
	})
	t.Run("a length past the bound is refused", func(t *testing.T) {
		t.Parallel()
		b := bytes.Clone(ok)
		binary.BigEndian.PutUint32(b[8:12], MaxBody+1)
		if _, err := ParseHeader(b); !errors.Is(err, ErrLength) {
			t.Fatalf("err = %v, want ErrLength", err)
		}
		// And the whole width of the field, which is the number this
		// check exists for: four gigabytes must not reach a make().
		binary.BigEndian.PutUint32(b[8:12], 0xffffffff)
		if _, err := ParseHeader(b); !errors.Is(err, ErrLength) {
			t.Fatalf("err = %v, want ErrLength", err)
		}
	})
	t.Run("shorter than a header is refused", func(t *testing.T) {
		t.Parallel()
		if _, err := ParseHeader(ok[:11]); !errors.Is(err, ErrShort) {
			t.Fatalf("err = %v, want ErrShort", err)
		}
	})
	t.Run("the flags read back", func(t *testing.T) {
		t.Parallel()
		h, err := ParseHeader(header(TypeAuthor, 1, FlagUnencrypted|FlagSingleConnect, 1, 0).Marshal())
		if err != nil {
			t.Fatalf("ParseHeader: %v", err)
		}
		if !h.Unencrypted() || !h.SingleConnect() {
			t.Fatalf("flags = %#x", h.Flags)
		}
	})
}

func TestTheObfuscationIsItsOwnInverseAndIsKeyedBySequence(t *testing.T) {
	t.Parallel()
	key := []byte("sharedkey")
	h := header(TypeAuthen, 1, 0, 0x01020304, 0)
	plain := []byte("a body long enough to span more than one md5 block of pad")
	// Symmetry: obfuscating twice gives the plaintext back, which is the
	// whole of RFC 8907 §4.5's construction.
	enc := Obfuscate(h, key, bytes.Clone(plain))
	if bytes.Equal(enc, plain) {
		t.Fatal("the pad did nothing")
	}
	if got := Obfuscate(h, key, bytes.Clone(enc)); !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %q", got)
	}
	// The pad depends on the sequence number, so the same plaintext at the
	// same offset in the next packet does not give the same ciphertext.
	next := h
	next.Seq = 3
	if bytes.Equal(Obfuscate(next, key, bytes.Clone(plain)), enc) {
		t.Error("the pad is the same for two sequence numbers")
	}
	// And on the session identifier.
	other := h
	other.SessionID = 0x01020305
	if bytes.Equal(Obfuscate(other, key, bytes.Clone(plain)), enc) {
		t.Error("the pad is the same for two session identifiers")
	}
	// A different key gives a different pad.
	if bytes.Equal(Obfuscate(h, []byte("otherkey"), bytes.Clone(plain)), enc) {
		t.Error("the pad is the same for two keys")
	}
	// No key is a no-op, which is what a listener configured without a
	// secret relies on: it reads headers and forwards bodies untouched.
	if got := Obfuscate(h, nil, bytes.Clone(plain)); !bytes.Equal(got, plain) {
		t.Error("an empty key changed the body")
	}
}

func TestDeobfuscatedNeverWritesOnTheBufferItWasGiven(t *testing.T) {
	t.Parallel()
	// The relay forwards the octets it received, so the parse must happen
	// somewhere else. A reader that de-obfuscated in place would forward
	// plaintext to the server.
	key := []byte("k")
	h := header(TypeAuthen, 1, 0, 7, 0)
	enc := Obfuscate(h, key, []byte("secret body"))
	keep := bytes.Clone(enc)
	got := Deobfuscated(h, key, enc)
	if !bytes.Equal(enc, keep) {
		t.Fatal("the input buffer was modified")
	}
	if string(got) != "secret body" {
		t.Fatalf("got %q", got)
	}
	// With the unencrypted flag the body is already readable, and the copy
	// still has to be a copy.
	clear := header(TypeAuthen, 1, FlagUnencrypted, 7, 0)
	plain := []byte("in the clear")
	out := Deobfuscated(clear, key, plain)
	if string(out) != "in the clear" {
		t.Fatalf("got %q", out)
	}
	out[0] = 'X'
	if plain[0] != 'i' {
		t.Fatal("the returned slice aliases the input")
	}
}

func TestAnAuthenticationStartIsReadAndItsPasswordIsNotKept(t *testing.T) {
	t.Parallel()
	lens, strs := lens3("alice", "tty0", "10.0.0.9")
	body := append([]byte{byte(ActionLogin), 15, byte(AuthenPAP), byte(ServiceLogin)}, lens...)
	body = append(body, 8) // data_len: the password
	body = append(body, strs...)
	body = append(body, []byte("hunter22")...)
	s, err := ParseAuthenStart(body)
	if err != nil {
		t.Fatalf("ParseAuthenStart: %v", err)
	}
	if s.Action != ActionLogin || s.PrivLvl != 15 || s.Type != AuthenPAP ||
		s.Service != ServiceLogin {
		t.Fatalf("start = %+v", s)
	}
	if s.User != "alice" || s.Port != "tty0" || s.RemAddr != "10.0.0.9" {
		t.Fatalf("fields = %q %q %q", s.User, s.Port, s.RemAddr)
	}
	if s.DataBytes != 8 {
		t.Errorf("data bytes = %d, want 8", s.DataBytes)
	}
	// The struct has no field that could hold the password, which is the
	// point: there is nowhere for it to be kept.
	if strings.Contains(fmtStart(s), "hunter22") {
		t.Fatal("the password reached the parsed body")
	}
	if !s.Type.Plaintext() {
		t.Error("PAP is not reported as a plaintext method")
	}
	if AuthenCHAP.Plaintext() {
		t.Error("CHAP is reported as a plaintext method")
	}
}

// fmtStart renders a parsed start the way a %+v in a log or a test failure
// would, so the test above can assert the password is not in it.
func fmtStart(s AuthenStart) string {
	return s.Action.String() + s.Type.String() + s.Service.String() +
		s.User + s.Port + s.RemAddr
}

func TestABodyWhoseFieldsDoNotAddUpIsRefused(t *testing.T) {
	t.Parallel()
	lens, strs := lens3("bob", "tty", "")
	base := append([]byte{byte(ActionLogin), 1, byte(AuthenASCII), byte(ServiceLogin)}, lens...)
	base = append(base, 0)
	t.Run("one octet short", func(t *testing.T) {
		t.Parallel()
		b := append(bytes.Clone(base), strs[:len(strs)-1]...)
		if _, err := ParseAuthenStart(b); !errors.Is(err, ErrBodyFields) {
			t.Fatalf("err = %v, want ErrBodyFields", err)
		}
	})
	t.Run("one octet long", func(t *testing.T) {
		t.Parallel()
		// Trailing octets are refused rather than ignored: they are
		// either a field this reader mis-sized or something put there for
		// the server to read and the relay not to.
		b := append(bytes.Clone(base), strs...)
		b = append(b, 'x')
		if _, err := ParseAuthenStart(b); !errors.Is(err, ErrBodyFields) {
			t.Fatalf("err = %v, want ErrBodyFields", err)
		}
	})
	t.Run("shorter than the fixed fields", func(t *testing.T) {
		t.Parallel()
		if _, err := ParseAuthenStart(base[:7]); !errors.Is(err, ErrBodyShort) {
			t.Fatalf("err = %v, want ErrBodyShort", err)
		}
	})
	t.Run("a control character in a field", func(t *testing.T) {
		t.Parallel()
		lens, strs := lens3("bo\nb", "tty", "")
		b := append([]byte{byte(ActionLogin), 1, byte(AuthenASCII), byte(ServiceLogin)}, lens...)
		b = append(b, 0)
		b = append(b, strs...)
		if _, err := ParseAuthenStart(b); !errors.Is(err, ErrText) {
			t.Fatalf("err = %v, want ErrText", err)
		}
	})
}

func TestAReplyAndAContinueRoundTrip(t *testing.T) {
	t.Parallel()
	body := MarshalAuthenReply(AuthenReply{Status: AuthenFail, ServerMsg: "refused by xproxy"})
	r, err := ParseAuthenReply(body)
	if err != nil {
		t.Fatalf("ParseAuthenReply: %v", err)
	}
	if r.Status != AuthenFail || r.ServerMsg != "refused by xproxy" || r.DataBytes != 0 {
		t.Fatalf("reply = %+v", r)
	}
	// A continue keeps only lengths. The typed text is a password on a
	// getpass prompt, and there is no field for it.
	cont := []byte{0, 6, 0, 0, 0}
	cont = append(cont, []byte("secret")...)
	c, err := ParseAuthenContinue(cont)
	if err != nil {
		t.Fatalf("ParseAuthenContinue: %v", err)
	}
	if c.UserMsgBytes != 6 || c.DataBytes != 0 || c.Abort {
		t.Fatalf("continue = %+v", c)
	}
	abort := []byte{0, 0, 0, 0, 1}
	if c, err = ParseAuthenContinue(abort); err != nil || !c.Abort {
		t.Fatalf("abort: %+v, %v", c, err)
	}
	if _, err := ParseAuthenContinue([]byte{0, 9, 0, 0, 0}); !errors.Is(err, ErrBodyFields) {
		t.Fatal("a continue whose lengths do not add up was accepted")
	}
}

func TestAnAuthorizationRequestReadsTheCommandItIsAbout(t *testing.T) {
	t.Parallel()
	lens, strs := lens3("alice", "tty0", "10.0.0.9")
	alens, abody := argBody("service=shell", "cmd=configure", "cmd-arg=terminal", "cmd-arg=<cr>")
	body := append([]byte{byte(MethodTACACSPlus), 15, byte(AuthenASCII), byte(ServiceLogin)}, lens...)
	body = append(body, byte(len(alens)))
	body = append(body, alens...)
	body = append(body, strs...)
	body = append(body, abody...)
	r, err := ParseAuthorRequest(body)
	if err != nil {
		t.Fatalf("ParseAuthorRequest: %v", err)
	}
	if r.User != "alice" || r.PrivLvl != 15 || r.Method != MethodTACACSPlus {
		t.Fatalf("request = %+v", r)
	}
	// The command exists in no single field: it is `cmd` plus every
	// `cmd-arg` in order, with the carriage return dropped.
	if got := r.Args.Command(); got != "configure terminal" {
		t.Fatalf("command = %q, want %q", got, "configure terminal")
	}
	if got := r.Args.Service(); got != "shell" {
		t.Errorf("service = %q", got)
	}
	if n, ok := r.Args.PrivLvl(); ok {
		t.Errorf("priv-lvl read as %d from a request that has none", n)
	}
	if got := strings.Join(r.Args.Names(), ","); got != "service,cmd,cmd-arg" {
		t.Errorf("names = %q", got)
	}
}

func TestAnArgumentIsSplitOnItsFirstSeparator(t *testing.T) {
	t.Parallel()
	// RFC 8907 §6.1: a value may contain either character, so the first
	// separator decides. A reader that took the last one would read
	// `cmd-arg=a*b` as an optional `cmd-arg=a` with value `b` -- a command
	// argument no rule would match.
	cases := []struct {
		in        string
		name, val string
		mandatory bool
	}{
		{"service=shell", "service", "shell", true},
		{"priv-lvl*15", "priv-lvl", "15", false},
		{"cmd-arg=a*b", "cmd-arg", "a*b", true},
		{"cmd-arg*a=b", "cmd-arg", "a=b", false},
		{"idletime=", "idletime", "", true},
	}
	for _, c := range cases {
		a, err := parseArg(c.in)
		if err != nil {
			t.Fatalf("parseArg(%q): %v", c.in, err)
		}
		if a.Name != c.name || a.Value != c.val || a.Mandatory != c.mandatory {
			t.Errorf("parseArg(%q) = %+v", c.in, a)
		}
		if got := a.String(); got != c.in {
			t.Errorf("round trip of %q gave %q", c.in, got)
		}
	}
	if _, err := parseArg("noseparator"); !errors.Is(err, ErrArgSeparator) {
		t.Fatalf("err = %v, want ErrArgSeparator", err)
	}
}

func TestAnEmptyArgumentIsRefused(t *testing.T) {
	t.Parallel()
	lens, strs := lens3("b", "", "")
	body := append([]byte{byte(MethodTACACSPlus), 1, byte(AuthenASCII), byte(ServiceLogin)}, lens...)
	body = append(body, 1, 0) // one argument, of length zero
	body = append(body, strs...)
	if _, err := ParseAuthorRequest(body); !errors.Is(err, ErrArgEmpty) {
		t.Fatalf("err = %v, want ErrArgEmpty", err)
	}
}

func TestAnArgumentCountPastTheBodyIsRefused(t *testing.T) {
	t.Parallel()
	// arg_cnt says there are twenty arguments and the body has room for
	// none of their lengths. A reader that sliced on the count would read
	// past the body.
	lens, _ := lens3("", "", "")
	body := append([]byte{byte(MethodTACACSPlus), 1, byte(AuthenASCII), byte(ServiceLogin)}, lens...)
	body = append(body, 20)
	if _, err := ParseAuthorRequest(body); !errors.Is(err, ErrBodyShort) {
		t.Fatalf("err = %v, want ErrBodyShort", err)
	}
}

func TestAnAuthorizationResponseReadsWhatTheServerGranted(t *testing.T) {
	t.Parallel()
	in := AuthorResponse{
		Status:    AuthorPassReplace,
		ServerMsg: "ok",
		Args:      Args{{Name: "priv-lvl", Value: "15", Mandatory: true}},
	}
	r, err := ParseAuthorResponse(MarshalAuthorResponse(in))
	if err != nil {
		t.Fatalf("ParseAuthorResponse: %v", err)
	}
	if r.Status != AuthorPassReplace || !r.Status.Pass() {
		t.Fatalf("status = %v", r.Status)
	}
	if r.ServerMsg != "ok" {
		t.Errorf("message = %q", r.ServerMsg)
	}
	n, ok := r.Args.PrivLvl()
	if !ok || n != 15 {
		t.Fatalf("priv-lvl = (%d, %v), want (15, true)", n, ok)
	}
	if AuthorFail.Pass() || AuthorError.Pass() || AuthorFollow.Pass() {
		t.Error("a failing status reports Pass")
	}
	// A level outside the ladder is not a level.
	bad := Args{{Name: "priv-lvl", Value: "99", Mandatory: true}}
	if _, ok := bad.PrivLvl(); ok {
		t.Error("priv-lvl=99 was accepted")
	}
}

func TestAnAccountingRecordIsReadAndNamed(t *testing.T) {
	t.Parallel()
	lens, strs := lens3("alice", "tty0", "10.0.0.9")
	alens, abody := argBody("task_id=3", "service=shell", "cmd=reload")
	body := append([]byte{AcctFlagStop, byte(MethodTACACSPlus), 15,
		byte(AuthenASCII), byte(ServiceLogin)}, lens...)
	body = append(body, byte(len(alens)))
	body = append(body, alens...)
	body = append(body, strs...)
	body = append(body, abody...)
	r, err := ParseAcctRequest(body)
	if err != nil {
		t.Fatalf("ParseAcctRequest: %v", err)
	}
	if r.User != "alice" || r.Args.Command() != "reload" {
		t.Fatalf("record = %+v", r)
	}
	if got := AcctRecord(r.Flags); got != "stop" {
		t.Errorf("record name = %q, want stop", got)
	}
	for _, c := range []struct {
		flags uint8
		want  string
	}{
		{AcctFlagStart, "start"},
		{AcctFlagWatchdog, "watchdog"},
		{AcctFlagWatchdog | AcctFlagStart, "watchdog-update"},
		{0, "flags(0)"},
	} {
		if got := AcctRecord(c.flags); got != c.want {
			t.Errorf("AcctRecord(%#x) = %q, want %q", c.flags, got, c.want)
		}
	}
	reply, err := ParseAcctReply(MarshalAcctReply(AcctReply{Status: AcctSuccess, ServerMsg: "logged"}))
	if err != nil {
		t.Fatalf("ParseAcctReply: %v", err)
	}
	if reply.Status != AcctSuccess || reply.ServerMsg != "logged" {
		t.Fatalf("reply = %+v", reply)
	}
}

func TestAnUnauthenticatedMethodIsNamedAsOne(t *testing.T) {
	t.Parallel()
	for _, m := range []AuthenMethod{MethodNotSet, MethodNone, MethodGuest, MethodLine} {
		if !m.Unauthenticated() {
			t.Errorf("%v is not reported as unauthenticated", m)
		}
	}
	for _, m := range []AuthenMethod{MethodTACACSPlus, MethodRADIUS, MethodKRB5,
		MethodLocal, MethodEnable} {
		if m.Unauthenticated() {
			t.Errorf("%v is reported as unauthenticated", m)
		}
	}
}

func TestTheNamesARuleIsWrittenWithRoundTrip(t *testing.T) {
	t.Parallel()
	for _, n := range TypeNames() {
		tp, ok := TypeOf(n)
		if !ok || tp.String() != n {
			t.Errorf("TypeOf(%q) = (%v, %v)", n, tp, ok)
		}
	}
	for _, n := range AuthenTypeNames() {
		a, ok := AuthenTypeOf(n)
		if !ok || a.String() != n {
			t.Errorf("AuthenTypeOf(%q) = (%v, %v)", n, a, ok)
		}
	}
	for _, n := range ServiceNames() {
		s, ok := ServiceOf(n)
		if !ok || s.String() != n {
			t.Errorf("ServiceOf(%q) = (%v, %v)", n, s, ok)
		}
	}
	for _, n := range MethodNames() {
		m, ok := MethodOf(n)
		if !ok || m.String() != n {
			t.Errorf("MethodOf(%q) = (%v, %v)", n, m, ok)
		}
	}
	// The spellings an operator writes.
	for _, s := range []string{"authen", "author", "acct", "authorisation"} {
		if _, ok := TypeOf(s); !ok {
			t.Errorf("TypeOf(%q) was not accepted", s)
		}
	}
	if m, ok := MethodOf("tacacs+"); !ok || m != MethodTACACSPlus {
		t.Errorf(`MethodOf("tacacs+") = (%v, %v)`, m, ok)
	}
	if _, ok := TypeOf("nonsense"); ok {
		t.Error("a nonsense exchange name was accepted")
	}
	// An unknown number renders rather than panicking, which is what a log
	// line about a packet from strange equipment needs.
	if got := Type(9).String(); got != "type(9)" {
		t.Errorf("Type(9) = %q", got)
	}
	if Type(9).Known() || AuthenType(9).Known() || AuthenService(99).Known() ||
		AuthenAction(9).Known() || AuthenMethod(99).Known() {
		t.Error("an unknown value reports Known")
	}
	if got := AuthenStatus(9).String(); got != "authen-status(9)" {
		t.Errorf("AuthenStatus(9) = %q", got)
	}
	if got := AuthorStatus(9).String(); got != "author-status(9)" {
		t.Errorf("AuthorStatus(9) = %q", got)
	}
	if got := AcctStatus(9).String(); got != "acct-status(9)" {
		t.Errorf("AcctStatus(9) = %q", got)
	}
}
