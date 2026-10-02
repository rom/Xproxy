package kkdcp

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/kerberos"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// End to end: a Kerberos client, this proxy, and a KDC.
//
// The KDC below speaks the real framing -- four octets of length, then a DER
// message -- and answers with messages this package's own parser reads back,
// which is what makes the assertions about encryption types and
// pre-authentication mean anything.

const kkdcpYAML = `
version: 1
server:
  listeners:
    - name: kdcproxy
      address: "127.0.0.1:0"
      kind: kkdcp
%[2]s
      tls:
        certificates:
          - cert_file: %[3]q
            key_file: %[4]q
      kkdcp:
        upstream: kdcs
%[1]s
logging: {access: {enabled: false}}
upstreams:
  - {name: kdcs, endpoints: [{address: %[5]q}]}
`

func relay(t *testing.T, section, extra, kdcAddr string) (*proxy.Server, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "kdcproxy.test")
	s := proxytest.Start(t, fmt.Sprintf(kkdcpYAML, section, extra, cert, key, kdcAddr))
	_ = filepath.Dir(cert)
	return s, proxytest.Addr(t, s, "kdcproxy")
}

// client posts an envelope and reads the answer.
type client struct {
	t    *testing.T
	http *http.Client
	url  string
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	tr := &http.Transport{
		// The certificate is this test's own, written a moment ago into a
		// temporary directory: there is no name to verify it against that
		// would prove anything the test does not already know.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // a self-signed certificate this test just wrote
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &client{t: t, http: &http.Client{Transport: tr, Timeout: 5 * time.Second},
		url: "https://" + addr + "/KdcProxy"}
}

// post sends one Kerberos message wrapped in the envelope and returns the
// status and, where the answer was a Kerberos message, the parsed message.
func (c *client) post(msg []byte, realm string) (int, *wire.Message) {
	c.t.Helper()
	body := wire.MarshalProxyMessage(msg, realm)
	resp, err := c.http.Post(c.url, "application/kerberos", bytes.NewReader(body))
	if err != nil {
		c.t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(raw) == 0 {
		return resp.StatusCode, nil
	}
	env, err := wire.ParseProxyMessage(raw, 1<<20)
	if err != nil {
		c.t.Fatalf("the answer is not an envelope: %v", err)
	}
	m, err := wire.Parse(env.Inner)
	if err != nil {
		c.t.Fatalf("the answer's message did not parse: %v", err)
	}
	return resp.StatusCode, &m
}

// fakeKDC answers one message per connection.
type fakeKDC struct {
	ln    net.Listener
	reply func(wire.Message) []byte

	mu   sync.Mutex
	seen []wire.Message
}

func startKDC(t *testing.T, k *fakeKDC) *fakeKDC {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	k.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go k.serve()
	return k
}

func (k *fakeKDC) addr() string { return k.ln.Addr().String() }

func (k *fakeKDC) serve() {
	for {
		c, err := k.ln.Accept()
		if err != nil {
			return
		}
		go k.exchange(c)
	}
}

func (k *fakeKDC) exchange(c net.Conn) {
	defer func() { _ = c.Close() }()
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 1<<20 {
		return
	}
	in := make([]byte, n)
	if _, err := io.ReadFull(c, in); err != nil {
		return
	}
	m, err := wire.Parse(in)
	if err != nil {
		return
	}
	k.mu.Lock()
	k.seen = append(k.seen, m)
	k.mu.Unlock()
	out := k.reply(m)
	_, _ = c.Write(wire.Frame(out))
}

func (k *fakeKDC) requests() []wire.Message {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]wire.Message, len(k.seen))
	copy(out, k.seen)
	return out
}

func refusals(s *proxy.Server, reason string) uint64 {
	return s.Stats().Refusals["kkdcp"][reason]
}

func TestAnASRequestReachesTheKDCAndItsReplyComesBack(t *testing.T) {
	t.Parallel()
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return asRep(m.Realm, user("alice"), krbtgt(m.Realm), wire.ETypeAES256SHA1, nil)
	}})
	s, addr := relay(t, "        realms: [CORP.EXAMPLE]\n        default_action: allow\n",
		"", kdc.addr())
	code, m := dial(t, addr).post(asReq("CORP.EXAMPLE", user("alice"),
		[]wire.EType{wire.ETypeAES256SHA1}, withPreauth()), "CORP.EXAMPLE")
	if code != http.StatusOK || m == nil {
		t.Fatalf("status %d, message %v", code, m)
	}
	if m.Type != wire.MsgASRep {
		t.Fatalf("reply type = %v", m.Type)
	}
	if got := kdc.requests(); len(got) != 1 || got[0].Realm != "CORP.EXAMPLE" {
		t.Fatalf("the KDC saw %+v", got)
	}
	if s.Stats().KKDCPRequests != 1 {
		t.Fatalf("kkdcp_requests = %d, want 1", s.Stats().KKDCPRequests)
	}
}

func TestARealmThisProxyDoesNotServeIsRefused(t *testing.T) {
	t.Parallel()
	// A KDC proxy with no realm policy is an open relay, and this is the
	// refusal that makes the policy mean something. It is never shadowed.
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return asRep(m.Realm, user("alice"), krbtgt(m.Realm), wire.ETypeAES256SHA1, nil)
	}})
	s, addr := relay(t, "        realms: [CORP.EXAMPLE]\n        default_action: allow\n",
		"      policy: {mode: shadow}\n", kdc.addr())
	_, m := dial(t, addr).post(asReq("OTHER.EXAMPLE", user("alice"),
		[]wire.EType{wire.ETypeAES256SHA1}, withPreauth()), "OTHER.EXAMPLE")
	if m == nil {
		t.Fatal("no answer: a refusal should be a KRB-ERROR the client reads")
	}
	if m.Type != wire.MsgError || m.ErrorCode != wire.KDCErrPolicy {
		t.Fatalf("answer = %s", m.Summary())
	}
	if len(kdc.requests()) != 0 {
		t.Fatal("it reached the KDC")
	}
	if refusals(s, "realm_not_allowed") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}
}

func TestTheTwoRealmsHaveToAgree(t *testing.T) {
	t.Parallel()
	// The envelope's realm is what the proxy routes by and the inner one is
	// what the KDC decides on. A client that sends two different ones is
	// asking the two to disagree, and both are in the allow list here, so
	// nothing but the mismatch itself refuses it.
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return asRep(m.Realm, user("alice"), krbtgt(m.Realm), wire.ETypeAES256SHA1, nil)
	}})
	s, addr := relay(t, "        realms: [CORP.EXAMPLE, MFG.EXAMPLE]\n        default_action: allow\n",
		"", kdc.addr())
	_, m := dial(t, addr).post(asReq("MFG.EXAMPLE", user("alice"),
		[]wire.EType{wire.ETypeAES256SHA1}, withPreauth()), "CORP.EXAMPLE")
	if m == nil || m.Type != wire.MsgError {
		t.Fatalf("answer = %v", m)
	}
	if refusals(s, "realm_mismatch") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}
	if s.Stats().KKDCPRealmMismatch == 0 {
		t.Fatal("kkdcp_realm_mismatch was not counted")
	}
}

func TestARequestOfferingNothingButRC4IsRefusedAndAMixedOneIsNot(t *testing.T) {
	t.Parallel()
	// "Nothing but" rather than "any" is the whole setting: a Windows client
	// lists aes256, aes128 and rc4 and the KDC takes the first it can, so
	// refusing a request that mentions RC4 would refuse the estate.
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return tgsRep(m.Realm, user("svc"), svc("MSSQLSvc", "db.corp.example"),
			wire.ETypeAES256SHA1)
	}})
	s, addr := relay(t, "        realms: [CORP.EXAMPLE]\n        default_action: allow\n",
		"", kdc.addr())
	c := dial(t, addr)

	mixed := tgsReq("CORP.EXAMPLE", user("svc"), svc("MSSQLSvc", "db.corp.example"),
		[]wire.EType{wire.ETypeAES256SHA1, wire.ETypeRC4HMAC})
	if _, m := c.post(mixed, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgTGSRep {
		t.Fatalf("a mixed encryption-type list was refused: %v", m)
	}

	only := tgsReq("CORP.EXAMPLE", user("svc"), svc("MSSQLSvc", "db.corp.example"),
		[]wire.EType{wire.ETypeRC4HMAC})
	if _, m := c.post(only, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgError {
		t.Fatalf("an RC4-only request was carried: %v", m)
	}
	if refusals(s, "weak_etype_only") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}
	if n := len(kdc.requests()); n != 1 {
		t.Fatalf("the KDC saw %d requests, want only the mixed one", n)
	}
}

func TestAnASReplyToARequestWithNoPreauthenticationIsRefused(t *testing.T) {
	t.Parallel()
	// AS-REP roasting. The check is on the reply because it cannot be
	// answered on the request: a bare AS-REQ is the first message of every
	// normal exchange, and a KDC answers one with KDC_ERR_PREAUTH_REQUIRED.
	// A KDC that answers it with a *ticket* has said the account is exempt.
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return asRep(m.Realm, user("svcacct"), krbtgt(m.Realm), wire.ETypeAES256SHA1, nil)
	}})
	s, addr := relay(t, "        realms: [CORP.EXAMPLE]\n        default_action: allow\n",
		"", kdc.addr())
	c := dial(t, addr)

	// The bare request itself is carried: refusing it would break every
	// client's first message.
	bare := asReq("CORP.EXAMPLE", user("svcacct"), []wire.EType{wire.ETypeAES256SHA1})
	_, m := c.post(bare, "CORP.EXAMPLE")
	if m == nil || m.Type != wire.MsgError {
		t.Fatalf("the reply was not refused: %v", m)
	}
	if len(kdc.requests()) != 1 {
		t.Fatal("the bare request did not reach the KDC, so the check was on the wrong leg")
	}
	if refusals(s, "preauth_not_required") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}
	if s.Stats().KKDCPPreauthExempt == 0 {
		t.Fatal("kkdcp_preauth_exempt was not counted")
	}

	// And a request that did bring pre-authentication is answered.
	good := asReq("CORP.EXAMPLE", user("alice"), []wire.EType{wire.ETypeAES256SHA1}, withPreauth())
	if _, m := c.post(good, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgASRep {
		t.Fatalf("a pre-authenticated exchange was refused: %v", m)
	}
}

func TestDelegationIsRefusedUnlessBothHalvesAreAllowed(t *testing.T) {
	t.Parallel()
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return tgsRep(m.Realm, user("websvc"), svc("cifs", "files.corp.example"),
			wire.ETypeAES256SHA1)
	}})
	s, addr := relay(t, "        realms: [CORP.EXAMPLE]\n        default_action: allow\n",
		"", kdc.addr())
	c := dial(t, addr)

	// S4U2Self: PA-FOR-USER names the impersonated user in the clear.
	self := tgsReq("CORP.EXAMPLE", user("websvc"), user("websvc"),
		[]wire.EType{wire.ETypeAES256SHA1}, withForUser(user("administrator"), "CORP.EXAMPLE"))
	if _, m := c.post(self, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgError {
		t.Fatalf("S4U2Self was carried: %v", m)
	}
	if refusals(s, "s4u2self_not_allowed") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}

	// S4U2Proxy needs the option *and* a ticket. The option alone is a
	// client setting a reserved bit.
	optOnly := tgsReq("CORP.EXAMPLE", user("websvc"), svc("cifs", "files.corp.example"),
		[]wire.EType{wire.ETypeAES256SHA1}, withOptions(wire.OptConstrainedDelegation))
	if _, m := c.post(optOnly, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgTGSRep {
		t.Fatalf("the option alone was read as a delegation: %v", m)
	}
	both := tgsReq("CORP.EXAMPLE", user("websvc"), svc("cifs", "files.corp.example"),
		[]wire.EType{wire.ETypeAES256SHA1}, withOptions(wire.OptConstrainedDelegation),
		withAdditionalTicket())
	if _, m := c.post(both, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgError {
		t.Fatalf("S4U2Proxy was carried: %v", m)
	}
	if refusals(s, "s4u2proxy_not_allowed") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}
	if s.Stats().KKDCPDelegations < 2 {
		t.Fatalf("kkdcp_delegations = %d", s.Stats().KKDCPDelegations)
	}
}

func TestEnumeratingServiceTicketsTripsTheBound(t *testing.T) {
	t.Parallel()
	// The behavioural half of the Kerberoasting control: it counts
	// *different* service principals, which is what enumeration looks like,
	// and it catches a client that asked for all of them in aes256.
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return tgsRep(m.Realm, user("svc"), m.Server, wire.ETypeAES256SHA1)
	}})
	section := "        realms: [CORP.EXAMPLE]\n        default_action: allow\n" +
		"        max_distinct_services: 3\n        service_window: 1m\n"
	s, addr := relay(t, section, "", kdc.addr())
	c := dial(t, addr)
	refused := 0
	for i := 0; i < 6; i++ {
		req := tgsReq("CORP.EXAMPLE", user("svc"),
			svc("MSSQLSvc", fmt.Sprintf("db%d.corp.example", i)),
			[]wire.EType{wire.ETypeAES256SHA1})
		_, m := c.post(req, "CORP.EXAMPLE")
		if m != nil && m.Type == wire.MsgError {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("six different services were all carried under a bound of three")
	}
	if refusals(s, "service_ticket_enumeration") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}
	// The same service asked for repeatedly is not enumeration, so the bound
	// counts distinct names rather than requests.
	s2, addr2 := relay(t, section, "", kdc.addr())
	c2 := dial(t, addr2)
	for i := 0; i < 6; i++ {
		req := tgsReq("CORP.EXAMPLE", user("svc"), svc("MSSQLSvc", "db.corp.example"),
			[]wire.EType{wire.ETypeAES256SHA1})
		if _, m := c2.post(req, "CORP.EXAMPLE"); m == nil || m.Type != wire.MsgTGSRep {
			t.Fatalf("request %d for one service was refused: %v", i, m)
		}
	}
	if refusals(s2, "service_ticket_enumeration") != 0 {
		t.Fatal("asking for one service six times counted as enumeration")
	}
}

func TestAPreauthenticationFailureBurstStopsTheClient(t *testing.T) {
	t.Parallel()
	// Password spraying, seen from the one place it is visible. The bound is
	// per address because a sprayer tries one password against many
	// accounts, and the per-account bound is the KDC's own lockout.
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return wire.MarshalError(time.Now(), wire.KDCErrPreauthFailed, m.Realm,
			krbtgt(m.Realm), "no")
	}})
	section := "        realms: [CORP.EXAMPLE]\n        default_action: allow\n" +
		"        max_preauth_failures: 3\n        failure_window: 1m\n"
	s, addr := relay(t, section, "", kdc.addr())
	c := dial(t, addr)
	for i := 0; i < 6; i++ {
		req := asReq("CORP.EXAMPLE", user(fmt.Sprintf("user%d", i)),
			[]wire.EType{wire.ETypeAES256SHA1}, withPreauth())
		c.post(req, "CORP.EXAMPLE")
	}
	if s.Stats().KKDCPPreauthFailures == 0 {
		t.Fatal("kkdcp_preauth_failures was not counted")
	}
	if refusals(s, "preauth_failure_burst") == 0 {
		t.Fatalf("refusals: %v", s.Stats().Refusals["kkdcp"])
	}
	// Past the bound the requests stop reaching the KDC, which is the point:
	// the burst is the finding and the next request is the next attempt in
	// it.
	if n := len(kdc.requests()); n >= 6 {
		t.Fatalf("the KDC saw %d of 6 requests; the bound stopped nothing", n)
	}
}

func TestTheHTTPSurfaceIsOnePathAndOneMethod(t *testing.T) {
	t.Parallel()
	kdc := startKDC(t, &fakeKDC{reply: func(m wire.Message) []byte {
		return asRep(m.Realm, user("alice"), krbtgt(m.Realm), wire.ETypeAES256SHA1, nil)
	}})
	_, addr := relay(t, "        realms: [CORP.EXAMPLE]\n        default_action: allow\n",
		"", kdc.addr())
	c := dial(t, addr)
	// A GET on the right path.
	resp, err := c.http.Get(c.url)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", resp.StatusCode)
	}
	// A POST on the wrong one. The 404 carries no body: a proxy that
	// described itself here would be telling a scanner what it is.
	resp, err = c.http.Post("https://"+addr+"/", "application/kerberos", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST / = %d, want 404", resp.StatusCode)
	}
	if bytes.Contains(body, []byte("kkdcp")) || bytes.Contains(body, []byte("xproxy")) {
		t.Fatalf("the 404 body names the product: %q", body)
	}
	// And a body that is not an envelope.
	resp, err = c.http.Post(c.url, "application/kerberos", bytes.NewReader([]byte{0x04, 0x01, 0x00}))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a malformed envelope = %d, want 400", resp.StatusCode)
	}
}

func TestAListenerWithNoRealmsIsRefusedAtLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "kdcproxy.test")
	yaml := fmt.Sprintf(kkdcpYAML, "        default_action: allow\n", "", cert, key, "127.0.0.1:1")
	err := proxytest.StartError(t, yaml)
	if err == nil {
		t.Fatal("a KDC proxy with no realm list loaded")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("realms")) {
		t.Fatalf("the error does not name realms: %v", err)
	}
}
