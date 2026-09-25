package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// directory is a fake LDAP server. It records every message that reached it,
// which is the assertion that matters on a security relay: not what the
// client was told, but what got through to the directory.
type directory struct {
	ln net.Listener

	mu  sync.Mutex
	got []*wire.Message
	// password is the one credential it accepts; empty accepts any
	// non-empty one.
	password string
	// entries is how many results a search answers with, and attrs what
	// each carries.
	entries int
	attrs   []string
	// serverTLS makes it an LDAPS server, expecting TLS from the first
	// octet.
	serverTLS *tls.Config
	// startTLS makes it answer the StartTLS extended operation and upgrade.
	startTLS bool
	// mute answers nothing at all, which is a directory that is reachable
	// and not talking.
	mute bool
	// stray sends an entry against a message identifier nobody used.
	stray int
	// reply replaces the answer entirely, for a test about what the relay
	// does with something a directory should not have sent.
	reply func(*wire.Message) []byte
}

func startDirectory(t *testing.T, d *directory) *directory {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.ln = ln
	if d.attrs == nil {
		d.attrs = []string{"cn", "mail", "userPassword"}
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(t, c)
		}
	}()
	return d
}

func (d *directory) addr() string { return d.ln.Addr().String() }

func (d *directory) serve(t *testing.T, c net.Conn) {
	t.Helper()
	defer func() { _ = c.Close() }()
	if d.serverTLS != nil {
		tc := tls.Server(c, d.serverTLS)
		if err := tc.Handshake(); err != nil {
			return
		}
		c = tc
	}
	rd := wire.NewReader(c, wire.MaxMessage)
	for {
		raw, err := rd.Next()
		if err != nil {
			return
		}
		m, err := wire.Parse(raw)
		d.mu.Lock()
		d.got = append(d.got, m)
		mute, pass, entries := d.mute, d.password, d.entries
		attrs, startTLS, stray, reply := d.attrs, d.startTLS, d.stray, d.reply
		d.mu.Unlock()
		if err != nil {
			return
		}
		if mute {
			// A directory that is reachable and says nothing, which is what
			// a request left outstanding looks like from the relay's side.
			continue
		}
		if reply != nil {
			if out := reply(m); out != nil {
				if _, err := c.Write(out); err != nil {
					return
				}
			}
			continue
		}
		switch {
		case m.Op == wire.OpUnbindRequest:
			return
		case m.Op == wire.OpBindRequest:
			// A directory with no password configured answers every bind
			// with success, which is exactly what a real one does to an
			// unauthenticated bind and is the behaviour the relay exists to
			// stand in front of.
			code := wire.ResultSuccess
			if pass != "" && passwordOf(raw) != pass {
				code = wire.ResultInvalidCredentials
			}
			_, _ = c.Write(bindResult(m.ID, code))
		case m.Op == wire.OpSearchRequest:
			id := m.ID
			if stray != 0 {
				id = stray
			}
			for i := 0; i < entries; i++ {
				name := fmt.Sprintf("cn=person%d,ou=people,dc=example,dc=com", i)
				if _, err := c.Write(entry(id, name, attrs...)); err != nil {
					return
				}
			}
			_, _ = c.Write(searchDone(m.ID, wire.ResultSuccess))
		case m.Op == wire.OpExtendedRequest && m.Extended.OID == wire.OIDStartTLS:
			if !startTLS {
				_, _ = c.Write(wire.StartTLSResponse(m.ID, wire.ResultProtocolError, "no"))
				continue
			}
			_, _ = c.Write(wire.StartTLSResponse(m.ID, wire.ResultSuccess, ""))
			tc := tls.Server(c, d.serverTLS)
			if err := tc.Handshake(); err != nil {
				return
			}
			c = tc
			rd = wire.NewReader(c, wire.MaxMessage)
		default:
			if out := wire.Answer(m.ID, m.Op, wire.ResultSuccess, ""); out != nil {
				_, _ = c.Write(out)
			}
		}
	}
}

// passwordOf digs the simple-bind password out of the raw request, which the
// parsed message deliberately does not keep. Only a test does this.
func passwordOf(raw []byte) string {
	// The password is the last field of the bind: a context-primitive [0]
	// whose contents run to the end of the message.
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] == 0x80 && i+2+int(raw[i+1]) == len(raw) {
			return string(raw[i+2:])
		}
	}
	return ""
}

func (d *directory) seen() []*wire.Message {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*wire.Message, len(d.got))
	copy(out, d.got)
	return out
}

func (d *directory) await(t *testing.T, n int, what string) []*wire.Message {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := d.seen(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the directory saw %d messages", what, len(d.seen()))
	return nil
}

const ldapYAML = `
version: 1
server:
  listeners:
    - name: dir
      address: "127.0.0.1:0"
      kind: ldap
      ldap:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: directories, endpoints: [{address: %q}]}
`

func ldapServer(t *testing.T, section, addr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(ldapYAML, section, addr))
	return s, proxytest.Addr(t, s, "dir")
}

// client is a management application: it writes requests and reads whatever
// comes back.
type client struct {
	c  net.Conn
	rd *wire.Reader
	t  *testing.T
}

func dialLDAP(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &client{c: c, rd: wire.NewReader(c, wire.MaxMessage), t: t}
}

func dialLDAPS(t *testing.T, addr string, ca *testutil.CA) *client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool,
		ServerName: "relay.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &client{c: c, rd: wire.NewReader(c, wire.MaxMessage), t: t}
}

func (cl *client) send(raw []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(raw); err != nil {
		cl.t.Fatal(err)
	}
}

// next reads one response, or reports that none came within the window. A
// refusal that is an error and a refusal that is a hang are different things
// to a client, so a test has to be able to tell them apart.
func (cl *client) next(within time.Duration) *wire.Message {
	cl.t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(within))
	raw, err := cl.rd.Next()
	if err != nil {
		return nil
	}
	m, err := wire.Parse(raw)
	if err != nil {
		cl.t.Fatalf("the relay sent something unparseable: %v", err)
	}
	return m
}

// upgrade completes a StartTLS handshake the relay has just agreed to.
func (cl *client) upgrade(ca *testutil.CA) {
	cl.t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	tc := tls.Client(cl.c, &tls.Config{RootCAs: pool, ServerName: "relay.test",
		MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		cl.t.Fatalf("starttls handshake: %v", err)
	}
	cl.c, cl.rd = tc, wire.NewReader(tc, wire.MaxMessage)
}

func awaitCounter(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the counters never said so: %+v", what, s.Stats().Refusals["ldap"])
}

// certs writes a CA and a certificate for the relay.
func certs(t *testing.T) (*testutil.CA, string, string) {
	t.Helper()
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	cert, key := ca.Issue(t, dir, "relay.test")
	return ca, cert, key
}

func tlsSection(cert, key string) string {
	return fmt.Sprintf(`
      tls:
        certificates: [{cert_file: %s, key_file: %s}]`, cert, key)
}

// The relay in its ordinary shape: an application binds over TLS and searches
// the subtree it is allowed to.
func TestLDAPRelaysTheSearchItWasConfiguredFor(t *testing.T) {
	d := startDirectory(t, &directory{entries: 2, attrs: []string{"cn", "mail"}})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        base_dns: ["dc=example,dc=com"]
        read_only: true
        rules:
          - {name: bind, action: allow, operations: [bind]}
          - name: people
            action: allow
            bind_dns: ["ou=services,dc=example,dc=com"]
            access: [read]
            base_dns: ["ou=people,dc=example,dc=com"]`+tlsSection(cert, key), d.addr())

	cl := dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=app1,ou=services,dc=example,dc=com", "s3cret"))
	if got := cl.next(3 * time.Second); got == nil || got.Result.Code != wire.ResultSuccess {
		t.Fatalf("the bind was not answered with success: %+v", got)
	}
	cl.send(search(2, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	entries := 0
	for {
		got := cl.next(3 * time.Second)
		if got == nil {
			t.Fatalf("the search never completed after %d entries", entries)
		}
		if got.Op == wire.OpSearchResultDone {
			break
		}
		entries++
	}
	if entries != 2 {
		t.Errorf("the client got %d entries", entries)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.LDAPBinds >= 1 && sn.LDAPSearches >= 1 && sn.LDAPEntries >= 2
	}, "the traffic was not counted")
}

// The refusal this relay exists for: a bind with a name and an empty password
// never reaches the directory, and the client is told the credential was
// wrong rather than being told success.
func TestABindWithAnEmptyPasswordNeverReachesTheDirectory(t *testing.T) {
	d := startDirectory(t, &directory{})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        default_action: allow`+tlsSection(cert, key), d.addr())

	cl := dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=alice,ou=people,dc=example,dc=com", ""))
	got := cl.next(3 * time.Second)
	if got == nil {
		t.Fatal("the refusal was a hang, not an answer")
	}
	if got.Op != wire.OpBindResponse || got.Result.Code != wire.ResultInvalidCredentials {
		t.Fatalf("the answer was %s %+v", got.Op, got.Result)
	}
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("the bind reached the directory: %+v", seen[0].Op)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["unauthenticated_bind"] >= 1 && sn.LDAPBindFailures >= 1
	}, "the refusal was not counted")
}

// A password in the clear: refused before it can be forwarded, and not
// shadowable, because by the time a policy could be consulted it has already
// gone past.
func TestAPasswordInTheClearIsRefusedEvenInShadowMode(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        default_action: allow
      policy: {mode: shadow}`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send(bind(1, "cn=alice,dc=example,dc=com", "s3cret"))
	got := cl.next(3 * time.Second)
	if got == nil || got.Result.Code != wire.ResultInvalidCredentials {
		t.Fatalf("the answer was %+v", got)
	}
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("a cleartext password reached the directory: %+v", seen[0].Op)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["bind_in_clear"] >= 1
	}, "the cleartext bind was not refused")
	if sn := s.Stats(); sn.LDAPWouldDeny != 0 {
		t.Errorf("a confidentiality bound was shadowed: %d", sn.LDAPWouldDeny)
	}
}

// The attribute policy on the answer, which is the half a request-side access
// list cannot do: the search asked for everything and never named a password.
func TestAPasswordHashIsRemovedFromAnAnswerThatCarriesIt(t *testing.T) {
	d := startDirectory(t, &directory{entries: 1, attrs: []string{"cn", "mail", "userPassword"}})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        read_only: true
        default_action: allow`+tlsSection(cert, key), d.addr())

	cl := dialLDAPS(t, addr, ca)
	cl.send(search(1, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "*"))
	got := cl.next(3 * time.Second)
	if got == nil || got.Op != wire.OpSearchResultEntry {
		t.Fatalf("the first answer was %+v", got)
	}
	for _, a := range got.Entry.Attributes {
		if baseAttr(a) == "userpassword" {
			t.Error("the password hash reached the client")
		}
	}
	if len(got.Entry.Attributes) != 2 {
		t.Errorf("the entry carries %v", got.Entry.Attributes)
	}
	if got.Entry.Name != "cn=person0,ou=people,dc=example,dc=com" {
		t.Errorf("the entry's name changed: %q", got.Entry.Name)
	}
	// The directory did send it: the relay removed it rather than the
	// directory withholding it.
	seen := d.await(t, 1, "the search did not reach the directory")
	if seen[0].Search == nil {
		t.Fatalf("the directory saw %s", seen[0].Op)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.LDAPStripped >= 1 },
		"the removal was not counted")
	// And the search still completes.
	if done := cl.next(3 * time.Second); done == nil || done.Op != wire.OpSearchResultDone {
		t.Errorf("the search did not complete: %+v", done)
	}
}

// Asking for a password by name is refused rather than answered with a
// silence the client cannot tell from an empty directory.
func TestAskingForAPasswordByNameIsRefused(t *testing.T) {
	d := startDirectory(t, &directory{entries: 1})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        read_only: true
        default_action: allow`+tlsSection(cert, key), d.addr())

	cl := dialLDAPS(t, addr, ca)
	cl.send(search(1, "ou=people,dc=example,dc=com", wire.ScopeSub,
		present("objectClass"), "cn", "userPassword"))
	got := cl.next(3 * time.Second)
	if got == nil || got.Op != wire.OpSearchResultDone {
		t.Fatalf("the answer was %+v", got)
	}
	if got.Result.Code != wire.ResultInsufficientAccess {
		t.Errorf("result %s", got.Result.Code)
	}
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("the search reached the directory: %+v", seen[0].Op)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["attribute"] >= 1
	}, "the named attribute was not refused")
}

// The entry bound: this protocol's amplification bound, reached rather than
// refused, so the client gets what it has plus the directory's own
// sizeLimitExceeded.
func TestASearchIsCutAtTheEntryBound(t *testing.T) {
	d := startDirectory(t, &directory{entries: 20, attrs: []string{"cn"}})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        read_only: true
        max_entries: 3
        default_action: allow`+tlsSection(cert, key), d.addr())

	cl := dialLDAPS(t, addr, ca)
	cl.send(search(1, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	entries := 0
	var done *wire.Message
	for {
		got := cl.next(3 * time.Second)
		if got == nil {
			t.Fatalf("the search never completed after %d entries", entries)
		}
		if got.Op == wire.OpSearchResultDone {
			done = got
			break
		}
		entries++
	}
	if entries != 3 {
		t.Errorf("the client got %d entries, wanted 3", entries)
	}
	if done.Result.Code != wire.ResultSizeLimitExceeded {
		t.Errorf("the search completed with %s", done.Result.Code)
	}
	// And nothing after it: the directory's own Done is dropped, or the
	// client would have two answers to one request.
	if extra := cl.next(300 * time.Millisecond); extra != nil {
		t.Errorf("a second answer arrived: %s", extra.Op)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.LDAPTruncated >= 1 },
		"the cut was not counted")
}

// The identity is the directory's to grant. A relay that believed the request
// would let anyone be anybody by binding with the wrong password.
func TestTheIdentityIsAdoptedOnlyWhenTheDirectoryAgrees(t *testing.T) {
	d := startDirectory(t, &directory{entries: 1, attrs: []string{"cn"}, password: "s3cret"})
	ca, cert, key := certs(t)
	_, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        read_only: true
        rules:
          - {name: bind, action: allow, operations: [bind]}
          - name: services
            action: allow
            bind_dns: ["ou=services,dc=example,dc=com"]
            access: [read]`+tlsSection(cert, key), d.addr())

	// The wrong password: the directory refuses, so the relay does not adopt
	// the identity, and the search that identity would have allowed is
	// refused.
	cl := dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=app1,ou=services,dc=example,dc=com", "wrong"))
	if got := cl.next(3 * time.Second); got == nil || got.Result.Code != wire.ResultInvalidCredentials {
		t.Fatalf("the wrong password was answered %+v", got)
	}
	cl.send(search(2, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	got := cl.next(3 * time.Second)
	if got == nil || got.Op != wire.OpSearchResultDone || got.Result.Code == wire.ResultSuccess {
		t.Fatalf("a search after a failed bind was answered %+v", got)
	}

	// The right password: the identity is adopted and the same search passes.
	cl = dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=app1,ou=services,dc=example,dc=com", "s3cret"))
	if got := cl.next(3 * time.Second); got == nil || got.Result.Code != wire.ResultSuccess {
		t.Fatalf("the right password was answered %+v", got)
	}
	cl.send(search(2, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	if got := cl.next(3 * time.Second); got == nil || got.Op != wire.OpSearchResultEntry {
		t.Fatalf("a search after a successful bind was answered %+v", got)
	}
}

// StartTLS, which this relay terminates rather than forwards -- and which
// discards the identity, because RFC 4513 §5.1.7 says so and because keeping
// it would let a client bind in the clear and then hide behind TLS with what
// that bind gave it.
//
// require_tls is off here, which is what makes the attack reachable at all:
// the client establishes a real identity on an unprotected connection and
// then upgrades. The relay has to forget it.
func TestStartTLSIsTerminatedHereAndDiscardsTheIdentity(t *testing.T) {
	d := startDirectory(t, &directory{entries: 1, attrs: []string{"cn"}})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: starttls
        require_tls: false
        read_only: true
        rules:
          - {name: bind, action: allow, operations: [bind, extended]}
          - name: bound
            action: allow
            bind_dns: ["ou=services,dc=example,dc=com"]
            access: [read]`+tlsSection(cert, key), d.addr())

	cl := dialLDAP(t, addr)
	// A real identity, in the clear, because this listener allows it.
	cl.send(bind(1, "cn=app1,ou=services,dc=example,dc=com", "s3cret"))
	if got := cl.next(3 * time.Second); got == nil || got.Result.Code != wire.ResultSuccess {
		t.Fatalf("the bind was answered %+v", got)
	}
	// It works, so the identity is established and the rule keyed on it
	// applies.
	cl.send(search(2, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	if got := cl.next(3 * time.Second); got == nil || got.Op != wire.OpSearchResultEntry {
		t.Fatalf("a search on the established identity: %+v", got)
	}
	if done := cl.next(3 * time.Second); done == nil || done.Op != wire.OpSearchResultDone {
		t.Fatalf("the search did not complete: %+v", done)
	}

	cl.send(extended(3, wire.OIDStartTLS))
	got := cl.next(3 * time.Second)
	if got == nil || got.Op != wire.OpExtendedResponse || got.Result.Code != wire.ResultSuccess {
		t.Fatalf("StartTLS was answered %+v", got)
	}
	cl.upgrade(ca)
	// The directory never saw the StartTLS: the relay answered it.
	for _, m := range d.seen() {
		if m.Op == wire.OpExtendedRequest {
			t.Error("the StartTLS request was forwarded to the directory")
		}
	}
	// And the identity is gone: the same search that worked a moment ago is
	// refused, because the connection is nobody again.
	cl.send(search(4, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	got = cl.next(3 * time.Second)
	if got == nil || got.Op != wire.OpSearchResultDone {
		t.Fatalf("a search after the upgrade: %+v", got)
	}
	if got.Result.Code == wire.ResultSuccess {
		t.Error("the identity survived a StartTLS upgrade")
	}
	// Binding again inside TLS establishes it again.
	cl.send(bind(5, "cn=app1,ou=services,dc=example,dc=com", "s3cret"))
	if got := cl.next(3 * time.Second); got == nil || got.Result.Code != wire.ResultSuccess {
		t.Fatalf("the bind inside TLS was answered %+v", got)
	}
	cl.send(search(6, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	if got := cl.next(3 * time.Second); got == nil || got.Op != wire.OpSearchResultEntry {
		t.Fatalf("a search after the bind inside TLS: %+v", got)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.LDAPStartTLS >= 1 },
		"the upgrade was not counted")
}

// StartTLS with an operation in flight is refused. RFC 4511 §4.14.1 requires
// the client to have none, and a relay that upgraded anyway would be changing
// the transport under an answer already on its way.
func TestStartTLSWithAnOperationOutstandingIsRefused(t *testing.T) {
	// A directory that answers nothing, so the search stays outstanding.
	d := startDirectory(t, &directory{mute: true})
	_, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: starttls
        read_only: true
        default_action: allow`+tlsSection(cert, key), d.addr())

	cl := dialLDAP(t, addr)
	cl.send(search(1, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	d.await(t, 1, "the search did not reach the directory")
	cl.send(extended(2, wire.OIDStartTLS))
	got := cl.next(3 * time.Second)
	if got == nil || got.Result.Code != wire.ResultOperationsError {
		t.Fatalf("StartTLS with a search outstanding was answered %+v", got)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["starttls_outstanding"] >= 1
	}, "the outstanding operation was not the reason")
}

// The outstanding table is bounded, and a full one refuses the request rather
// than forwarding a search whose entries would then arrive with no attribute
// policy and no count against them.
func TestAFullOutstandingTableRefusesRatherThanForwards(t *testing.T) {
	d := startDirectory(t, &directory{mute: true})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        read_only: true
        max_outstanding: 2
        request_timeout: 60s
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	for i := 1; i <= 2; i++ {
		cl.send(search(i, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	}
	d.await(t, 2, "the searches did not reach the directory")
	cl.send(search(3, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	got := cl.next(3 * time.Second)
	if got == nil || got.Op != wire.OpSearchResultDone || got.Result.Code != wire.ResultBusy {
		t.Fatalf("the third search was answered %+v", got)
	}
	if seen := d.seen(); len(seen) != 2 {
		t.Errorf("the directory saw %d searches", len(seen))
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["too_many_outstanding"] >= 1
	}, "the table bound was not the reason")
}

// A listener with no TLS to offer says so in the protocol's own terms rather
// than forwarding the request to a directory whose answer would apply to the
// wrong leg of the connection.
func TestStartTLSOnAListenerThatHasNoneIsAnsweredNotForwarded(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send(extended(1, wire.OIDStartTLS))
	got := cl.next(3 * time.Second)
	if got == nil || got.Result.Code != wire.ResultProtocolError {
		t.Fatalf("the answer was %+v", got)
	}
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("the request was forwarded: %s", seen[0].Op)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["starttls_unavailable"] >= 1
	}, "the unavailable upgrade was not counted")
}

// A malformed message is never forwarded and never shadowed: the directory
// behind this relay would read those octets somehow.
func TestAMalformedMessageEndsTheSession(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        default_action: allow
      policy: {mode: shadow}`, d.addr())

	cl := dialLDAP(t, addr)
	// A message whose operation is not one RFC 4511 defines.
	cl.send(msg(1, appC(30, octets("x"))))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.LDAPMalformed >= 1 && sn.Refusals["ldap"]["malformed"] >= 1
	}, "the malformed message was not refused")
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("a malformed message reached the directory: %s", seen[0].Op)
	}
}

// Message identifier zero is reserved for the server's unsolicited
// notification. A client sending it is either broken or trying to have the
// relay pair an answer with a request nobody made.
func TestMessageIdentifierZeroIsRefused(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send(bind(0, "", ""))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["message_id_zero"] >= 1
	}, "message identifier zero was not refused")
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("it reached the directory: %s", seen[0].Op)
	}
}

// An entry against a message identifier nobody used. The client is not
// waiting for it, and forwarding it would be handing it somebody else's
// answer.
func TestAnEntryForASearchNobodyMadeIsDropped(t *testing.T) {
	d := startDirectory(t, &directory{entries: 1, attrs: []string{"cn"}, stray: 4242})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        read_only: true
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send(search(1, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	// The Done still arrives, against the right identifier.
	got := cl.next(3 * time.Second)
	if got == nil || got.Op != wire.OpSearchResultDone {
		t.Fatalf("the first answer was %+v", got)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["unsolicited_entry"] >= 1
	}, "the stray entry was not refused")
}

// The bind rate limit, which is separate from the request rate because a rate
// loose enough for an application's searches says nothing about somebody
// working through a password list.
func TestTheBindRateIsBoundedSeparately(t *testing.T) {
	d := startDirectory(t, &directory{})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        bind_rate_limit: 1
        bind_rate_burst: 2
        default_action: allow`+tlsSection(cert, key), d.addr())

	cl := dialLDAPS(t, addr, ca)
	for i := 0; i < 20; i++ {
		cl.send(bind(i+1, fmt.Sprintf("cn=user%d,dc=example,dc=com", i), "guess"))
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.LDAPRateLimited >= 1 && sn.Refusals["ldap"]["bind_rate_limited"] >= 1
	}, "the bind rate did not hold")
}

// Shadow mode: the policy is evaluated, the refusal is recorded, and the
// request goes on. The bounds are not part of it.
func TestShadowModeRecordsTheRefusalAndForwardsTheRequest(t *testing.T) {
	d := startDirectory(t, &directory{})
	ca, cert, key := certs(t)
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: implicit
        rules:
          - {name: reads-only, action: allow, access: [read, bind]}
      policy: {mode: shadow}`+tlsSection(cert, key), d.addr())

	cl := dialLDAPS(t, addr, ca)
	cl.send(bind(1, "cn=admin,dc=example,dc=com", "s3cret"))
	if got := cl.next(3 * time.Second); got == nil || got.Result.Code != wire.ResultSuccess {
		t.Fatalf("the bind was answered %+v", got)
	}
	cl.send(modify(2, "cn=alice,dc=example,dc=com", change(2, "cn", "alice2")))
	seen := d.await(t, 2, "the modify did not reach the directory in shadow mode")
	if seen[1].Op != wire.OpModifyRequest {
		t.Fatalf("the directory saw %s", seen[1].Op)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.LDAPWouldDeny >= 1 },
		"the shadow refusal was not counted")
	if sn := s.Stats(); sn.LDAPDenied != 0 {
		t.Errorf("shadow mode refused something: %d", sn.LDAPDenied)
	}
	report := s.Shadow().Report()
	if len(report) == 0 {
		t.Fatal("the shadow ledger recorded nothing")
	}
	if report[0].Reason != "ldap_default_deny" {
		t.Errorf("the ledger says %q", report[0].Reason)
	}
}

// A client outside the list is refused before anything is read, and that
// refusal is not shadowed.
func TestAClientOutsideTheListIsRefusedEvenInShadowMode(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["192.0.2.0/24"]
        tls_mode: none
        default_action: allow
      policy: {mode: shadow}`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send(bind(1, "", ""))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.LDAPRejected >= 1 && sn.Refusals["ldap"]["client_not_allowed"] >= 1
	}, "the unlisted client was not refused")
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("an unlisted client reached the directory: %s", seen[0].Op)
	}
}

// A message past the bound is refused unread: reading it to find out what it
// asked for is the work the bound exists to avoid.
func TestAMessagePastTheBoundIsRefusedUnread(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        max_message_bytes: 2048
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	// A SEQUENCE claiming sixty thousand octets, with none of them sent.
	cl.send([]byte{0x30, 0x82, 0xea, 0x60})
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["message_too_large"] >= 1
	}, "the oversize message was not refused")
}

// A stream whose framing is wrong is a stream whose next octet is unknown.
func TestAStreamWithTheWrongFramingEnds(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["framing"] >= 1
	}, "the framing error was not refused")
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("an HTTP request reached the directory: %s", seen[0].Op)
	}
}

// The subtree boundary, end to end: the request a string suffix test would
// have let through.
func TestASearchOutsideTheNamingContextNeverReachesTheDirectory(t *testing.T) {
	d := startDirectory(t, &directory{entries: 1})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        read_only: true
        base_dns: ["dc=example,dc=com"]
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send(search(1, "dc=notexample,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	got := cl.next(3 * time.Second)
	if got == nil || got.Op != wire.OpSearchResultDone ||
		got.Result.Code != wire.ResultInsufficientAccess {
		t.Fatalf("the answer was %+v", got)
	}
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("it reached the directory: %s", seen[0].Op)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["base_dn"] >= 1
	}, "the boundary was not counted")
}

// The request rate limit, which refuses the one request and keeps the
// connection. LDAP clients hold pooled connections, so killing one on a rate
// spike makes the application reconnect and retry -- more load rather than
// less. The bind rate is the one that ends a session, because that rate is a
// credential attack.
func TestTheRequestRateRefusesTheRequestAndKeepsTheConnection(t *testing.T) {
	d := startDirectory(t, &directory{entries: 1, attrs: []string{"cn"}})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        read_only: true
        rate_limit: 1
        rate_burst: 2
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	busy := false
	for i := 1; i <= 25 && !busy; i++ {
		cl.send(search(i, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
		for {
			got := cl.next(2 * time.Second)
			if got == nil {
				t.Fatalf("no answer to search %d", i)
			}
			if got.Op == wire.OpSearchResultEntry {
				continue
			}
			if got.Result != nil && got.Result.Code == wire.ResultBusy {
				busy = true
			}
			break
		}
	}
	if !busy {
		t.Fatal("the rate limit never refused a request")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.LDAPRateLimited >= 1 && sn.Refusals["ldap"]["rate_limited"] >= 1
	}, "the rate limit was not counted")
	// The connection is still there: the next second's allowance carries a
	// request, which is the whole point of refusing rather than closing.
	time.Sleep(1200 * time.Millisecond)
	cl.send(search(99, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	got := cl.next(3 * time.Second)
	if got == nil {
		t.Fatal("the connection did not survive the rate limit")
	}
	if got.Result != nil && got.Result.Code == wire.ResultBusy {
		t.Error("the allowance did not refill")
	}
}

// A response arriving from the client. This side asks and the directory
// answers, so a response from here is traffic going the wrong way -- and on a
// relay that pairs answers with requests by message identifier, it is an
// attempt to have one paired with a request nobody made.
func TestAResponseFromTheClientIsRefused(t *testing.T) {
	d := startDirectory(t, &directory{})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send(bindResult(1, wire.ResultSuccess))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["wrong_direction"] >= 1
	}, "a response from the client was not refused")
	if seen := d.seen(); len(seen) != 0 {
		t.Errorf("it reached the directory: %s", seen[0].Op)
	}
}

// And a request arriving from the directory, which answers questions and does
// not ask them.
func TestARequestFromTheDirectoryIsRefused(t *testing.T) {
	d := startDirectory(t, &directory{reply: func(m *wire.Message) []byte {
		// A directory that answers a search with a search.
		return search(m.ID, "dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn")
	}})
	s, addr := ldapServer(t, `        upstream: directories
        allow_clients: ["127.0.0.0/8"]
        tls_mode: none
        read_only: true
        default_action: allow`, d.addr())

	cl := dialLDAP(t, addr)
	cl.send(search(1, "ou=people,dc=example,dc=com", wire.ScopeSub, present("objectClass"), "cn"))
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ldap"]["wrong_direction_response"] >= 1
	}, "a request from the directory was not refused")
	if got := cl.next(500 * time.Millisecond); got != nil && got.Op == wire.OpSearchRequest {
		t.Error("a search request was forwarded to the client")
	}
}
