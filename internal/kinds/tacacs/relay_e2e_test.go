package tacacs

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/tacacs"
)

// End to end: a network device, this relay, and a TACACS+ server.
//
// The device below is deliberately a real client of the protocol rather than
// a byte stream: it obfuscates its bodies with the key, numbers its sequence
// numbers, and reads the reply back through the same pad. A test that wrote
// plaintext bodies would pass against a relay that never de-obfuscated
// anything, which is most of what this kind does.

const theKey = "tacacs-shared-key"

const tacacsYAML = `
version: 1
server:
  listeners:
    - name: admin
      address: "127.0.0.1:0"
      kind: tacacs
%[2]s
      tacacs:
        upstream: servers
        secret_file: %[3]q
%[1]s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %[4]q}]}
`

func keyFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tacacs.key")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func relay(t *testing.T, section, extra, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(tacacsYAML, section, extra, keyFile(t, theKey), serverAddr))
	return s, proxytest.Addr(t, s, "admin")
}

// fakeServer answers whatever arrives, through the pad.
type fakeServer struct {
	ln net.Listener
	// author decides an authorization request. nil passes everything with
	// no arguments added.
	author func(wire.AuthorRequest) wire.AuthorResponse
	// authen decides an authentication start. nil passes.
	authen func(wire.AuthenStart) wire.AuthenReply
	// continueReply is the status a CONTINUE packet gets, for the tests that
	// need a session that stays open across more than one exchange. Zero
	// means pass, which ends it.
	continueReply wire.AuthenStatus

	mu       sync.Mutex
	commands []string
	records  []string
	users    []string
}

func startServer(t *testing.T, f *fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go f.serve()
	return f
}

func (f *fakeServer) addr() string { return f.ln.Addr().String() }

func (f *fakeServer) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.session(c)
	}
}

func (f *fakeServer) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	for {
		h, body, err := readPacket(c, wire.MaxBody)
		if err != nil {
			return
		}
		plain := wire.Deobfuscated(h, []byte(theKey), body)
		out := h
		out.Seq = h.Seq + 1
		var reply []byte
		switch h.Type {
		case wire.TypeAuthen:
			r := wire.AuthenReply{Status: wire.AuthenPass, ServerMsg: "ok"}
			switch {
			case h.Seq == 1:
				if st, perr := wire.ParseAuthenStart(plain); perr == nil {
					f.record(&f.users, st.User)
					if f.authen != nil {
						r = f.authen(st)
					}
				}
			case f.continueReply != 0:
				r = wire.AuthenReply{Status: f.continueReply}
			}
			reply = wire.MarshalAuthenReply(r)
		case wire.TypeAuthor:
			ar, perr := wire.ParseAuthorRequest(plain)
			r := wire.AuthorResponse{Status: wire.AuthorPassAdd}
			if perr == nil {
				f.record(&f.commands, ar.Args.Command())
				if f.author != nil {
					r = f.author(ar)
				}
			}
			reply = wire.MarshalAuthorResponse(r)
		case wire.TypeAcct:
			ac, perr := wire.ParseAcctRequest(plain)
			if perr == nil {
				f.record(&f.records, wire.AcctRecord(ac.Flags)+" "+ac.Args.Command())
			}
			reply = wire.MarshalAcctReply(wire.AcctReply{Status: wire.AcctSuccess})
		default:
			return
		}
		out.Length = len(reply)
		if _, err := c.Write(writePacket(out, wire.Obfuscate(out, []byte(theKey), reply))); err != nil {
			return
		}
	}
}

func (f *fakeServer) record(into *[]string, s string) {
	f.mu.Lock()
	*into = append(*into, s)
	f.mu.Unlock()
}

func (f *fakeServer) seen(which *[]string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(*which))
	copy(out, *which)
	return out
}

// device is a router speaking TACACS+.
type device struct {
	t    *testing.T
	c    net.Conn
	key  string
	sess uint32
}

func connect(t *testing.T, addr string) *device {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &device{t: t, c: c, key: theKey, sess: 0x1000}
}

// ask sends one packet and reads the answer, returning the header and the
// de-obfuscated body. A nil body means the relay closed instead of
// answering, which is what a refusal with deny_response: drop looks like.
func (d *device) ask(typ wire.Type, session uint32, seq uint8, flags uint8, body []byte) (wire.Header, []byte) {
	d.t.Helper()
	h := wire.Header{VersionMajor: wire.VersionMajor, Type: typ, Seq: seq,
		Flags: flags, SessionID: session, Length: len(body)}
	out := body
	if flags&wire.FlagUnencrypted == 0 && d.key != "" {
		out = wire.Obfuscate(h, []byte(d.key), append([]byte(nil), body...))
	}
	if err := d.c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		d.t.Fatal(err)
	}
	if _, err := d.c.Write(writePacket(h, out)); err != nil {
		return wire.Header{}, nil
	}
	rh, rbody, err := readPacket(d.c, wire.MaxBody)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			var ne net.Error
			if !errors.As(err, &ne) {
				d.t.Logf("read: %v", err)
			}
		}
		return wire.Header{}, nil
	}
	return rh, wire.Deobfuscated(rh, []byte(d.key), rbody)
}

// authorize asks whether a command may run.
func (d *device) authorize(session uint32, user string, priv uint8, args ...string) (wire.AuthorResponse, bool) {
	d.t.Helper()
	body := authorBody(user, priv, args...)
	h, plain := d.ask(wire.TypeAuthor, session, 1, 0, body)
	if plain == nil {
		return wire.AuthorResponse{}, false
	}
	if h.Type != wire.TypeAuthor {
		d.t.Fatalf("answer type = %v", h.Type)
	}
	r, err := wire.ParseAuthorResponse(plain)
	if err != nil {
		d.t.Fatalf("the answer did not parse: %v", err)
	}
	return r, true
}

// authorBody renders an authorization request body.
func authorBody(user string, priv uint8, args ...string) []byte {
	const port, rem = "tty0", "10.0.0.9"
	var lens, strs []byte
	lens = append(lens, byte(len(user)), byte(len(port)), byte(len(rem)))
	strs = append(strs, user...)
	strs = append(strs, port...)
	strs = append(strs, rem...)
	alens, abody := make([]byte, 0, len(args)), []byte{}
	for _, a := range args {
		alens = append(alens, byte(len(a)))
		abody = append(abody, a...)
	}
	out := append([]byte{byte(wire.MethodTACACSPlus), priv,
		byte(wire.AuthenASCII), byte(wire.ServiceLogin)}, lens...)
	out = append(out, byte(len(alens)))
	out = append(out, alens...)
	out = append(out, strs...)
	return append(out, abody...)
}

// authenBody renders an authentication start body with no data field.
func authenBody(action wire.AuthenAction, typ wire.AuthenType, svc wire.AuthenService,
	user string, priv uint8) []byte {
	const port, rem = "tty0", "10.0.0.9"
	out := []byte{byte(action), priv, byte(typ), byte(svc),
		byte(len(user)), byte(len(port)), byte(len(rem)), 0}
	out = append(out, user...)
	out = append(out, port...)
	return append(out, rem...)
}

// acctBody renders an accounting record.
func acctBody(flags uint8, user string, args ...string) []byte {
	const port, rem = "tty0", "10.0.0.9"
	alens, abody := make([]byte, 0, len(args)), []byte{}
	for _, a := range args {
		alens = append(alens, byte(len(a)))
		abody = append(abody, a...)
	}
	out := []byte{flags, byte(wire.MethodTACACSPlus), 15, byte(wire.AuthenASCII),
		byte(wire.ServiceLogin), byte(len(user)), byte(len(port)), byte(len(rem)),
		byte(len(alens))}
	out = append(out, alens...)
	out = append(out, user...)
	out = append(out, port...)
	out = append(out, rem...)
	return append(out, abody...)
}

func refusals(s *proxy.Server, reason string) uint64 {
	return s.Stats().Refusals["tacacs"][reason]
}

func TestACommandIsAllowedOrRefusedByItsWholeLine(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        commands: [\"show ...\", \"ping ...\"]\n" +
		"        deny_commands: [\"show running-config\"]\n" +
		"        default_action: allow\n"
	s, addr := relay(t, section, "", srv.addr())
	d := connect(t, addr)

	// The command exists in no single field: it is `cmd` plus every
	// `cmd-arg`, and the pattern is written the way it is typed.
	r, ok := d.authorize(1, "alice", 1, "service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>")
	if !ok || !r.Status.Pass() {
		t.Fatalf("`show version` was refused: %+v ok=%v", r, ok)
	}
	if got := srv.seen(&srv.commands); len(got) != 1 || got[0] != "show version" {
		t.Fatalf("the server saw %q", got)
	}

	// The deny list is checked first and no rule overrides it, which is how
	// an exception inside an allowed set is written.
	r, ok = d.authorize(2, "alice", 1, "service=shell", "cmd=show", "cmd-arg=running-config")
	if ok && r.Status.Pass() {
		t.Fatal("`show running-config` was allowed by the `show ...` pattern")
	}
	if refusals(s, "command_not_allowed") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["tacacs"])
	}
	if len(srv.seen(&srv.commands)) != 1 {
		t.Fatal("the refused command reached the server")
	}

	// And a command the allow list does not cover.
	d2 := connect(t, addr)
	if r, ok := d2.authorize(3, "alice", 1, "service=shell", "cmd=configure", "cmd-arg=terminal"); ok && r.Status.Pass() {
		t.Fatal("`configure terminal` was allowed")
	}
}

func TestARefusalIsAnAnswerAnEngineerCanRead(t *testing.T) {
	t.Parallel()
	// The person refused is at a terminal, so the refusal says which proxy
	// refused and why -- which is the difference between a policy they can
	// work with and a router they report as broken.
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        commands: [\"show ...\"]\n        default_action: allow\n"
	_, addr := relay(t, section, "", srv.addr())
	r, ok := connect(t, addr).authorize(1, "alice", 1, "service=shell", "cmd=reload")
	if !ok {
		t.Fatal("the relay closed instead of answering")
	}
	if r.Status != wire.AuthorFail {
		t.Fatalf("status = %v, want fail", r.Status)
	}
	if r.ServerMsg == "" {
		t.Fatal("the refusal carried no message")
	}
	for _, want := range []string{"xproxy", "command_not_allowed"} {
		if !strings.Contains(r.ServerMsg, want) {
			t.Errorf("the message %q does not mention %q", r.ServerMsg, want)
		}
	}
}

func TestAPrivilegeGrantAboveTheBoundIsRefusedOnTheReply(t *testing.T) {
	t.Parallel()
	// priv-lvl in an authorization response is a mandatory argument and the
	// device must apply it, so the bound has to be checked on the server's
	// answer. A relay that checked only the request would let one
	// compromised server hand out enable on every router behind it.
	srv := startServer(t, &fakeServer{
		author: func(wire.AuthorRequest) wire.AuthorResponse {
			return wire.AuthorResponse{
				Status: wire.AuthorPassReplace,
				Args:   wire.Args{{Name: "priv-lvl", Value: "15", Mandatory: true}},
			}
		},
	})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        max_privilege_level: 1\n        default_action: allow\n"
	s, addr := relay(t, section, "", srv.addr())
	r, ok := connect(t, addr).authorize(1, "alice", 1, "service=shell", "cmd=show", "cmd-arg=version")
	if ok && r.Status.Pass() {
		t.Fatalf("a priv-lvl 15 grant crossed a listener bounded at 1: %+v", r)
	}
	if refusals(s, "privilege_grant_too_high") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["tacacs"])
	}
	if s.Stats().TACACSPrivilegeGrants != 0 {
		t.Fatal("a refused grant was counted as a grant")
	}
}

func TestAFollowReplyIsNotCarriedEvenInShadowMode(t *testing.T) {
	t.Parallel()
	// A FOLLOW carries another server's address, port and key, and a client
	// that follows one sends its next credential there. Carrying it to see
	// what the policy would have said is the thing being prevented.
	srv := startServer(t, &fakeServer{
		authen: func(wire.AuthenStart) wire.AuthenReply {
			return wire.AuthenReply{Status: wire.AuthenFollow, ServerMsg: "10.9.9.9 49 otherkey"}
		},
	})
	section := "        allow_clients: [127.0.0.1/32]\n        default_action: allow\n"
	s, addr := relay(t, section, "      policy: {mode: shadow}\n", srv.addr())
	d := connect(t, addr)
	_, plain := d.ask(wire.TypeAuthen, 1, 1, 0,
		authenBody(wire.ActionLogin, wire.AuthenASCII, wire.ServiceLogin, "alice", 1))
	if plain != nil {
		r, err := wire.ParseAuthenReply(plain)
		if err == nil && r.Status == wire.AuthenFollow {
			t.Fatal("a FOLLOW reply was carried to the device")
		}
	}
	if refusals(s, "follow_not_allowed") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["tacacs"])
	}
}

func TestABodyInTheClearIsRefused(t *testing.T) {
	t.Parallel()
	// On bare TCP the unencrypted flag means an administrative login's user
	// name and password are on the wire. RFC 8907 §4.5 allows it only on a
	// secured transport.
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n        default_action: allow\n"
	s, addr := relay(t, section, "", srv.addr())
	d := connect(t, addr)
	_, plain := d.ask(wire.TypeAuthen, 1, 1, wire.FlagUnencrypted,
		authenBody(wire.ActionLogin, wire.AuthenASCII, wire.ServiceLogin, "alice", 1))
	if plain != nil {
		if r, err := wire.ParseAuthenReply(plain); err == nil && r.Status == wire.AuthenPass {
			t.Fatal("a cleartext body was carried")
		}
	}
	if refusals(s, "unencrypted_body") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["tacacs"])
	}
}

func TestAnUnauthenticatedAuthorizationIsRefused(t *testing.T) {
	t.Parallel()
	// A device asking whether an unnamed user may run a command, and being
	// told yes, has authorised it for whoever is on the port.
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n        default_action: allow\n"
	s, addr := relay(t, section, "", srv.addr())
	body := authorBody("", 15, "service=shell", "cmd=configure", "cmd-arg=terminal")
	body[0] = byte(wire.MethodNone)
	_, plain := connect(t, addr).ask(wire.TypeAuthor, 1, 1, 0, body)
	if plain != nil {
		if r, err := wire.ParseAuthorResponse(plain); err == nil && r.Status.Pass() {
			t.Fatal("an unauthenticated authorization was carried")
		}
	}
	if refusals(s, "unauthenticated_authorization") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["tacacs"])
	}
}

func TestAccountingIsCarriedAndCounted(t *testing.T) {
	t.Parallel()
	// The accounting record is the audit trail, and it is the one exchange
	// worth carrying even on a listener that refuses everything else: the
	// record of what was run is what an estate is asked for afterwards.
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        commands: [\"show ...\"]\n        default_action: allow\n"
	s, addr := relay(t, section, "", srv.addr())
	d := connect(t, addr)
	_, plain := d.ask(wire.TypeAcct, 1, 1, 0,
		acctBody(wire.AcctFlagStop, "alice", "service=shell", "cmd=show", "cmd-arg=version",
			"task_id=7", "elapsed_time=3"))
	if plain == nil {
		t.Fatal("the accounting record was not answered")
	}
	if r, err := wire.ParseAcctReply(plain); err != nil || r.Status != wire.AcctSuccess {
		t.Fatalf("reply = %+v, err %v", r, err)
	}
	if got := srv.seen(&srv.records); len(got) != 1 || got[0] != "stop show version" {
		t.Fatalf("the server saw %q", got)
	}
	if s.Stats().TACACSAccounting != 1 {
		t.Fatalf("tacacs_accounting = %d, want 1", s.Stats().TACACSAccounting)
	}
}

func TestTwoSessionsOnOneConnectionAreKeptApart(t *testing.T) {
	t.Parallel()
	// Both ends may set TAC_PLUS_SINGLE_CONNECT_FLAG and multiplex, which
	// every modern device does. The session identifier is what tells them
	// apart, and a relay that paired answers by anything else would deliver
	// one session's answer to the other.
	srv := startServer(t, &fakeServer{
		author: func(r wire.AuthorRequest) wire.AuthorResponse {
			return wire.AuthorResponse{Status: wire.AuthorPassAdd, ServerMsg: r.User}
		},
	})
	section := "        allow_clients: [127.0.0.1/32]\n        default_action: allow\n"
	_, addr := relay(t, section, "", srv.addr())
	d := connect(t, addr)
	for _, c := range []struct {
		session uint32
		user    string
	}{{0x1111, "alice"}, {0x2222, "bob"}} {
		r, ok := d.authorize(c.session, c.user, 1, "service=shell", "cmd=show", "cmd-arg=version")
		if !ok {
			t.Fatalf("%s got no answer", c.user)
		}
		if r.ServerMsg != c.user {
			t.Fatalf("%s got %q's answer", c.user, r.ServerMsg)
		}
	}
}

func TestASequenceNumberThatRepeatsIsRefused(t *testing.T) {
	t.Parallel()
	// The sequence number is this protocol's own replay guard and it only
	// goes up. A relay that decided a repeat twice would have the policy see
	// one command as two; one that forwarded it would hand the server a
	// replay.
	//
	// The server keeps the session open -- GETDATA rather than PASS -- so
	// that the repeat below lands on a session that exists, which is the
	// only case where the sequence number has anything to say.
	srv := startServer(t, &fakeServer{
		authen: func(wire.AuthenStart) wire.AuthenReply {
			return wire.AuthenReply{Status: wire.AuthenGetData, ServerMsg: "Password: "}
		},
		continueReply: wire.AuthenGetData,
	})
	section := "        allow_clients: [127.0.0.1/32]\n        default_action: allow\n"
	s, addr := relay(t, section, "", srv.addr())
	d := connect(t, addr)
	start := authenBody(wire.ActionLogin, wire.AuthenASCII, wire.ServiceLogin, "alice", 1)
	if _, plain := d.ask(wire.TypeAuthen, 7, 1, 0, start); plain == nil {
		t.Fatal("the start was not answered")
	}
	// A CONTINUE at sequence 3, which is the client's next packet.
	cont := []byte{0, 0, 0, 0, 0}
	if _, plain := d.ask(wire.TypeAuthen, 7, 3, 0, cont); plain == nil {
		t.Fatal("the continue was not answered")
	}
	// The same sequence number again on the same session.
	if _, plain := d.ask(wire.TypeAuthen, 7, 3, 0, cont); plain != nil {
		if r, err := wire.ParseAuthenReply(plain); err == nil && r.Status != wire.AuthenFail {
			t.Fatalf("a repeated sequence number was carried: %v", r.Status)
		}
	}
	if refusals(s, "sequence_out_of_order") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["tacacs"])
	}
}

func TestAListenerWithNoKeyReadsHeadersOnly(t *testing.T) {
	t.Parallel()
	// Without the key this relay cannot read a body, so it bounds and counts
	// and forwards. That is worth having and worth being able to see: the
	// counter is what says a command policy would be deciding nothing.
	srv := startServer(t, &fakeServer{})
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: admin
      address: "127.0.0.1:0"
      kind: tacacs
      tacacs:
        upstream: servers
        allow_clients: [127.0.0.1/32]
        default_action: allow
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`, srv.addr())
	s := proxytest.Start(t, yaml)
	addr := proxytest.Addr(t, s, "admin")
	d := connect(t, addr)
	r, ok := d.authorize(1, "alice", 1, "service=shell", "cmd=configure", "cmd-arg=terminal")
	if !ok || !r.Status.Pass() {
		t.Fatalf("a header-only listener refused: %+v ok=%v", r, ok)
	}
	if s.Stats().TACACSHeaderOnly == 0 {
		t.Fatal("tacacs_header_only was not counted")
	}
	if s.Stats().TACACSCommands != 0 {
		t.Fatal("a command was counted on a listener that cannot read one")
	}
}
