package tacacs

import (
	"encoding/binary"
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

// continueBody renders an authentication CONTINUE carrying typed text, which
// is what a person answering a prompt sends.
func continueBody(userMsg string) []byte {
	out := []byte{0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(out[0:2], uint16(len(userMsg)))
	return append(out, userMsg...)
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

// The ASCII login that names nobody. RFC 8907 §5.4.2 lets a START leave the
// user field empty: the server answers GETUSER, the device prompts, and the
// name arrives in the typed text of a CONTINUE. That is the ordinary shape of
// `telnet` to a router, and it used to be the way past every control keyed on a
// name -- the user lists, and the estate's own authorization rules -- because
// the only name this relay read was the one in the START.
func TestANameTypedAtTheServersPromptIsStillDecidedAbout(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{
		authen: func(st wire.AuthenStart) wire.AuthenReply {
			if st.User == "" {
				return wire.AuthenReply{Status: wire.AuthenGetUser, ServerMsg: "Username: "}
			}
			return wire.AuthenReply{Status: wire.AuthenPass, ServerMsg: "ok"}
		},
		continueReply: wire.AuthenPass,
	})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        deny_users: [mallory]\n        default_action: allow\n"
	s, addr := relay(t, section, "", srv.addr())

	// A name the list admits, typed at the prompt, still logs in.
	d := connect(t, addr)
	if _, plain := d.ask(wire.TypeAuthen, 1, 1, 0,
		authenBody(wire.ActionLogin, wire.AuthenASCII, wire.ServiceLogin, "", 1)); plain == nil {
		t.Fatal("the login with no name in its START was refused outright")
	}
	if _, plain := d.ask(wire.TypeAuthen, 1, 3, 0, continueBody("dana")); plain == nil {
		t.Fatal("a name the policy admits was refused when typed at the prompt")
	}

	// And the one the list names is refused, at the packet that carries it.
	d2 := connect(t, addr)
	if _, plain := d2.ask(wire.TypeAuthen, 2, 1, 0,
		authenBody(wire.ActionLogin, wire.AuthenASCII, wire.ServiceLogin, "", 1)); plain == nil {
		t.Fatal("the second login was refused at its START")
	}
	_, plain := d2.ask(wire.TypeAuthen, 2, 3, 0, continueBody("mallory"))
	if plain != nil {
		if r, err := wire.ParseAuthenReply(plain); err == nil && r.Status == wire.AuthenPass {
			t.Fatalf("a denied user logged in by typing the name at the prompt: %+v", r)
		}
	}
	if refusals(s, "user_not_allowed") == 0 {
		t.Errorf("the refusal was not counted: %+v", s.Stats().Refusals["tacacs"])
	}

	// And the reading follows the question the server actually asked. An
	// exchange that has moved on to GETPASS must leave the typed text alone:
	// reading it there would make a password a user name -- decided about as
	// one, and written to a log as one.
	pw := startServer(t, &fakeServer{
		authen: func(st wire.AuthenStart) wire.AuthenReply {
			if st.User == "" {
				return wire.AuthenReply{Status: wire.AuthenGetUser, ServerMsg: "Username: "}
			}
			return wire.AuthenReply{Status: wire.AuthenPass}
		},
		// The second answer in the exchange, which is the password prompt.
		continueReply: wire.AuthenGetPass,
	})
	s2, addr2 := relay(t, section, "", pw.addr())
	d3 := connect(t, addr2)
	if _, plain := d3.ask(wire.TypeAuthen, 3, 1, 0,
		authenBody(wire.ActionLogin, wire.AuthenASCII, wire.ServiceLogin, "", 1)); plain == nil {
		t.Fatal("the login was refused at its START")
	}
	// An empty answer to GETUSER -- a bare return at the prompt -- after which
	// the server asks for the password instead.
	if _, plain := d3.ask(wire.TypeAuthen, 3, 3, 0, continueBody("")); plain == nil {
		t.Fatal("an empty answer to the prompt was refused")
	}
	// The password, answering GETPASS -- and it happens to be a name the
	// policy denies, which is how this test can tell whether it was read as
	// one.
	if _, plain := d3.ask(wire.TypeAuthen, 3, 5, 0, continueBody("mallory")); plain == nil {
		t.Fatal("the password's packet was refused, so it was read as a name")
	}
	if n := refusals(s2, "user_not_allowed"); n != 0 {
		t.Errorf("the typed password was decided about as a user name: %+v",
			s2.Stats().Refusals["tacacs"])
	}
}

// A rule's deny list adds to the listener's rather than standing in for it.
// The listener-wide list is the sentence "no router behind this relay accepts
// `write erase`", and a list a rule could replace would not be that sentence:
// an estate that gave its network team a deny of its own would have handed that
// team everything the estate denied, by writing a deny.
func TestARulesDenyListAddsToTheListenersRatherThanReplacingIt(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        deny_commands: [\"write erase\", \"reload\"]\n" +
		"        default_action: allow\n" +
		"        rules:\n" +
		"          - {name: netops, users: [nina], deny_commands: [\"debug all\"], action: allow}\n"
	s, addr := relay(t, section, "", srv.addr())

	// The rule's own deny works.
	if r, ok := connect(t, addr).authorize(1, "nina", 15, "service=shell", "cmd=debug", "cmd-arg=all"); ok && r.Status.Pass() {
		t.Fatal("the rule's own deny_commands did not refuse `debug all`")
	}
	// And the listener's still does, for the traffic that rule covers.
	if r, ok := connect(t, addr).authorize(2, "nina", 15, "service=shell", "cmd=write", "cmd-arg=erase"); ok && r.Status.Pass() {
		t.Fatal("a rule with a deny list of its own disarmed the listener's")
	}
	if got := srv.seen(&srv.commands); len(got) != 0 {
		t.Errorf("the server saw %q, want nothing", got)
	}
	if refusals(s, "command_not_allowed") < 2 {
		t.Errorf("refusals: %+v", s.Stats().Refusals["tacacs"])
	}
}

// A deny covers the command it names and whatever follows it. A device's
// command line takes suffixes -- a filter, a redirect, an argument -- and under
// an exact reading a deny of `show running-config` matched the spelling an
// operator would type and missed every spelling an attacker would.
func TestADenyCoversTheCommandAndWhatIsAppendedToIt(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        commands: [\"show ...\", \"copy ...\"]\n" +
		"        deny_commands: [\"show running-config\", \"copy running-config\"]\n" +
		"        default_action: allow\n"
	s, addr := relay(t, section, "", srv.addr())

	for i, args := range [][]string{
		// The pipe filter, which is the one that reads the credentials out.
		{"service=shell", "cmd=show", "cmd-arg=running-config", "cmd-arg=|",
			"cmd-arg=include", "cmd-arg=password"},
		// The redirect, which writes them somewhere.
		{"service=shell", "cmd=copy", "cmd-arg=running-config", "cmd-arg=tftp://10.9.9.9/cfg"},
		// And the bare command the operator had in mind.
		{"service=shell", "cmd=show", "cmd-arg=running-config"},
	} {
		if r, ok := connect(t, addr).authorize(uint32(10+i), "alice", 15, args...); ok && r.Status.Pass() {
			t.Errorf("%q was allowed", args)
		}
	}
	if got := srv.seen(&srv.commands); len(got) != 0 {
		t.Errorf("the server saw %q, want nothing", got)
	}

	// An allow list is still read exactly, because allowing more than was
	// asked is the unsafe direction: `show version` does not cover `show
	// version | redirect`, and the `show ...` pattern above is what covers it.
	section = "        allow_clients: [127.0.0.1/32]\n" +
		"        commands: [\"show version\"]\n        default_action: allow\n"
	s2, addr2 := relay(t, section, "", srv.addr())
	if r, ok := connect(t, addr2).authorize(20, "alice", 1, "service=shell", "cmd=show",
		"cmd-arg=version", "cmd-arg=|", "cmd-arg=include", "cmd-arg=serial"); ok && r.Status.Pass() {
		t.Error("an exact allow pattern covered a longer command")
	}
	if refusals(s, "command_not_allowed") < 3 || refusals(s2, "command_not_allowed") == 0 {
		t.Errorf("refusals: %+v %+v", s.Stats().Refusals["tacacs"], s2.Stats().Refusals["tacacs"])
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

// The behavioural models get a user, a device and a command, which is more
// than any other kind in this project gives them. With settle at zero and the
// symbols model on, the first command a user runs is novel by construction --
// which is what makes this testable without a day of history behind it.
func TestTheBehaviouralModelsSeeTheUserAndTheCommand(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        default_action: allow\n" +
		"        anomaly:\n          enabled: true\n          action: alert\n" +
		"          settle: 0s\n          novelty: {symbols: true}\n"
	s, addr := relay(t, section, "", srv.addr())
	d := connect(t, addr)

	// A look, then a change. `show` is one of the four verbs every platform
	// spells the same way, so the first is a read and the second is not --
	// which is what the write-rate model is counting.
	if r, ok := d.authorize(1, "alice", 1, "service=shell", "cmd=show", "cmd-arg=version"); !ok || !r.Status.Pass() {
		t.Fatalf("`show version` with the models on: %+v ok=%v", r, ok)
	}
	if r, ok := d.authorize(2, "alice", 15, "service=shell", "cmd=configure", "cmd-arg=terminal"); !ok || !r.Status.Pass() {
		t.Fatalf("`configure terminal` with action: alert: %+v ok=%v", r, ok)
	}

	// action: alert carries the command and reports it. The finding counts as
	// a refusal reason because that is where every kind's findings land; what
	// it does *not* do on this kind is reach the ban ladder.
	if counts := s.Counters().RefusalCounts()["tacacs"]; len(counts) == 0 {
		t.Errorf("the models reported nothing with settle: 0s and novelty on: %+v", s.Stats().Refusals)
	}
	if got := srv.seen(&srv.commands); len(got) != 2 {
		t.Errorf("the server saw %q, want both commands carried", got)
	}
}

// A `configure terminal` on a core router is the same kind of change as a
// download to a PLC, so it is reported as engineering activity with a class of
// its own -- and a `show` is not, because a class that included those is a
// class nobody reads.
func TestAConfigurationCommandIsEngineeringActivityAndAShowIsNot(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	// The ledger is what makes "outside every approved window" a thing that
	// can be counted: with no ledger there are no windows to be outside of,
	// and the report is all there is.
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: admin
      address: "127.0.0.1:0"
      kind: tacacs
      tacacs:
        upstream: servers
        secret_file: %q
        allow_clients: [127.0.0.1/32]
        default_action: allow
        engineering:
          enabled: true
logging: {access: {enabled: false}}
access:
  ledger: %q
  approvals: 1
  max_duration: 2h
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`, keyFile(t, theKey), filepath.Join(t.TempDir(), "access.jsonl"), srv.addr())
	s := proxytest.Start(t, yaml)
	addr := proxytest.Addr(t, s, "admin")
	d := connect(t, addr)

	if r, ok := d.authorize(1, "alice", 1, "service=shell", "cmd=show", "cmd-arg=version"); !ok || !r.Status.Pass() {
		t.Fatalf("`show version`: %+v ok=%v", r, ok)
	}
	if got := s.Stats().EngineeringOps["tacacs/configuration"]; got != 0 {
		t.Errorf("a `show` was reported as a configuration change (%d)", got)
	}

	// The change. It is carried -- require_grant is off here -- and it is
	// reported, with the command as the detail and the user as the subject.
	if r, ok := d.authorize(2, "alice", 15, "service=shell", "cmd=configure", "cmd-arg=terminal"); !ok || !r.Status.Pass() {
		t.Fatalf("`configure terminal` on a listener that only reports: %+v ok=%v", r, ok)
	}
	sn := s.Stats()
	if got := sn.EngineeringOps["tacacs/configuration"]; got != 1 {
		t.Errorf("engineering_configuration = %d, want 1 (ops %+v)", got, sn.EngineeringOps)
	}
	// Nobody had a grant open, which on a listener that requires none is not a
	// refusal -- it is the line an estate wants counted.
	if len(sn.EngineeringOutside) == 0 {
		t.Errorf("an unapproved change was not counted as outside: %+v", sn.EngineeringOutside)
	}
	if got := srv.seen(&srv.commands); len(got) != 2 {
		t.Errorf("the server saw %q, want both commands carried", got)
	}
}

// A restart and a firmware load are their own classes, because "somebody
// reloaded the core router" and "somebody changed a VLAN description" are not
// the same line in a report.
func TestARestartAndAFirmwareLoadAreTheirOwnClasses(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        default_action: allow\n" +
		"        engineering:\n          enabled: true\n"
	s, addr := relay(t, section, "", srv.addr())

	for i, c := range [][]string{
		{"cmd=reload"},
		{"cmd=copy", "cmd-arg=running-config", "cmd-arg=tftp:"},
		{"cmd=copy", "cmd-arg=tftp:", "cmd-arg=flash:"},
	} {
		d := connect(t, addr)
		args := append([]string{"service=shell"}, c...)
		if r, ok := d.authorize(uint32(i+1), "bob", 15, args...); !ok || !r.Status.Pass() {
			t.Fatalf("%v: %+v ok=%v", c, r, ok)
		}
	}
	sn := s.Stats()
	for _, want := range []string{"tacacs/restart", "tacacs/file_transfer", "tacacs/firmware"} {
		if sn.EngineeringOps[want] == 0 {
			t.Errorf("%s was not reported: %+v", want, sn.EngineeringOps)
		}
	}
}

// A rule decides only the commands it names. Without that, a rule written to
// allow `show ...` for the help desk would also be the rule that decided
// `reload` for them -- and would allow it, which is the opposite of what its
// author wrote.
func TestARuleDecidesOnlyTheCommandsItNames(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        default_action: deny\n" +
		"        rules:\n" +
		"          - {name: helpdesk, users: [dana], commands: [\"show ...\"], action: allow}\n" +
		"          - {name: engineers, users: [erin], action: allow}\n"
	s, addr := relay(t, section, "", srv.addr())

	// The rule covers dana's `show`, so it decides it, and it allows.
	if r, ok := connect(t, addr).authorize(1, "dana", 1, "service=shell", "cmd=show", "cmd-arg=version"); !ok || !r.Status.Pass() {
		t.Fatalf("the helpdesk rule refused `show version`: %+v ok=%v", r, ok)
	}

	// `reload` is dana's too, but it is not a command that rule names, so the
	// rule does not decide it and the default does. The default is deny.
	if r, ok := connect(t, addr).authorize(2, "dana", 1, "service=shell", "cmd=reload"); ok && r.Status.Pass() {
		t.Fatal("the `show ...` rule allowed `reload`")
	}
	if refusals(s, "no_rule_matched") == 0 {
		t.Errorf("no refusal was counted: %+v", s.Stats().Refusals["tacacs"])
	}

	// A rule that names no commands covers all of them, which is how "these
	// people may do anything" is written.
	if r, ok := connect(t, addr).authorize(3, "erin", 15, "service=shell", "cmd=reload"); !ok || !r.Status.Pass() {
		t.Fatalf("the engineers rule refused `reload`: %+v ok=%v", r, ok)
	}

	// And a user no rule names gets the default.
	if r, ok := connect(t, addr).authorize(4, "frank", 1, "service=shell", "cmd=show", "cmd-arg=version"); ok && r.Status.Pass() {
		t.Fatal("a user no rule names was allowed by default_action: deny")
	}
	if got := srv.seen(&srv.commands); len(got) != 2 {
		t.Errorf("the server saw %q, want only the two allowed commands", got)
	}
}

// The estate-wide identity rules apply to the user a TACACS+ exchange claims,
// the same as they do to an SSH principal or an LDAP bind DN -- and they are
// asked twice, which is the shape this protocol forces. The connection is asked
// about first, when there is no name at all: TACACS+ begins with the device's
// first packet and the user is inside a body this relay may not be able to
// read. So an estate policy that named only users would refuse every device at
// the point of connecting, and the rule that admits the devices has to be
// there too. The action asked about is `connect` rather than `session` because
// the authenticated session is the one thing this relay never sees: the server
// proves the password and says only pass or fail.
// An observe rule records what it would have covered and decides nothing. A
// rule that decided -- by allowing -- would make trying a rule out the way to
// turn off every deny rule below it, which is the opposite of trying it out.
func TestAnObserveRuleIsRecordedAndDecidesNothing(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        default_action: allow\n" +
		"        rules:\n" +
		"          - {name: trial, action: observe, clients: [127.0.0.1/32]}\n" +
		"          - {name: lockdown, action: deny, commands: [\"reload\"]}\n"
	s, addr := relay(t, section, "", srv.addr())

	// trial covers every command from this address and is listed first. The
	// deny below it still decides.
	if r, ok := connect(t, addr).authorize(1, "alice", 15, "service=shell", "cmd=reload"); ok && r.Status.Pass() {
		t.Fatal("a trial rule above the deny rule carried `reload`")
	}
	if refusals(s, "rule_denied") == 0 {
		t.Errorf("refusals: %+v", s.Stats().Refusals["tacacs"])
	}
	// And a command no deny rule names is carried, because an observe rule
	// refusing things would be no better than one allowing them.
	if r, ok := connect(t, addr).authorize(2, "alice", 15, "service=shell", "cmd=show", "cmd-arg=version"); !ok || !r.Status.Pass() {
		t.Fatalf("the trial rule refused a command nothing denies: %+v ok=%v", r, ok)
	}
	if got := srv.seen(&srv.commands); len(got) != 1 || got[0] != "show version" {
		t.Errorf("the server saw %q", got)
	}
}

func TestTheEstateWideIdentityRulesApplyToTheClaimedUser(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n        default_action: allow\n"
	policy := "authorization:\n  rules:\n" +
		"    - {name: engineers, allow: true, users: [erin]}\n" +
		"    - {name: devices, allow: true, networks: [127.0.0.1/32], not_users: [dana]}\n"
	yaml := fmt.Sprintf(tacacsYAML, section, "", keyFile(t, theKey), srv.addr()) + policy
	s := proxytest.Start(t, yaml)
	addr := proxytest.Addr(t, s, "admin")

	if r, ok := connect(t, addr).authorize(1, "erin", 15, "service=shell", "cmd=show", "cmd-arg=version"); !ok || !r.Status.Pass() {
		t.Fatalf("a user the estate policy names was refused: %+v ok=%v refusals=%+v", r, ok, s.Stats().Refusals["tacacs"])
	}
	// dana's device connects -- the devices rule admits the connection, because
	// at that point nobody has claimed to be dana -- and then the name is
	// refused as soon as a packet carries it.
	if r, ok := connect(t, addr).authorize(2, "dana", 1, "service=shell", "cmd=show", "cmd-arg=version"); ok && r.Status.Pass() {
		t.Fatalf("a user the estate policy excludes reached the server: %+v refusals=%+v", r, s.Stats().Refusals["tacacs"])
	}
	if refusals(s, "authorization") == 0 {
		t.Errorf("the authorization refusal was not counted: %+v", s.Stats().Refusals["tacacs"])
	}
	if got := srv.seen(&srv.commands); len(got) != 1 {
		t.Errorf("the server saw %q, want only erin's command", got)
	}
}

// The argument-count bound. An authorization body carries one argument per word
// of the command, so a long command line is a long argument list -- and the
// bound is what stops a device being made to allocate for one that is not a
// command at all.
func TestAnArgumentListLongerThanTheBoundIsRefused(t *testing.T) {
	t.Parallel()
	srv := startServer(t, &fakeServer{})
	section := "        allow_clients: [127.0.0.1/32]\n" +
		"        default_action: allow\n        max_args: 4\n"
	s, addr := relay(t, section, "", srv.addr())

	args := []string{"service=shell", "cmd=show"}
	for i := 0; i < 8; i++ {
		args = append(args, "cmd-arg=interface")
	}
	if r, ok := connect(t, addr).authorize(1, "alice", 1, args...); ok && r.Status.Pass() {
		t.Fatal("an argument list past max_args was carried")
	}
	if refusals(s, "too_many_arguments") == 0 {
		t.Errorf("too_many_arguments was not counted: %+v", s.Stats().Refusals["tacacs"])
	}
	if got := srv.seen(&srv.commands); len(got) != 0 {
		t.Errorf("the server saw %q", got)
	}

	// And a list inside the bound still goes through, so the bound is a bound
	// and not a refusal of every command.
	if r, ok := connect(t, addr).authorize(2, "alice", 1, "service=shell", "cmd=show", "cmd-arg=version"); !ok || !r.Status.Pass() {
		t.Fatalf("a short command was refused by max_args: %+v ok=%v", r, ok)
	}
}
