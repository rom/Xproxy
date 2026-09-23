package rdp

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // the protocol specifies MD5
	"crypto/rc4" //nolint:gosec // the protocol specifies RC4
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // the protocol specifies MD4

	"github.com/rom/xproxy/internal/ntlm"
	"github.com/rom/xproxy/internal/testutil"
)

// The whole exchange, against a stand-in for the Windows side. The
// stand-in does the server half of NTLM in test code rather than in
// the package, because the package deliberately has no server half:
// checking a credential means holding a password hash, which a gateway
// should not do. What is being tested is that this end produces
// something the other end accepts, and that it refuses a far end that
// cannot prove it saw the same tunnel.

// windows is enough of the server side to answer one exchange.
type windows struct {
	t *testing.T
	// password is what it expects to be proved, and domain and user
	// who it expects to prove it.
	domain, user, password string
	// challenge is the eight bytes it answers with.
	challenge []byte
	// wrongBinding makes it answer with a binding over another key,
	// which is what a relayed exchange looks like from this end.
	wrongBinding bool
	// got is the credential it ended up with.
	got *tsPasswordCreds
}

// serve answers one exchange. It does not close its end: the pipe is
// unbuffered, so a TLS close alert nobody is reading would hold this
// goroutine for the five seconds the standard library gives one.
func (w *windows) serve(conn *tls.Conn, pubKey []byte) {
	// A deadline on this end too, so a stalled exchange fails the test
	// rather than holding it until the whole run gives up.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.HandshakeContext(w.t.Context()); err != nil {
		return
	}
	req, err := readTSRequest(conn)
	if err != nil || len(req.NegoTokens) == 0 {
		return
	}
	// The challenge, with extended session security and a key
	// exchange, which is what this package insists on.
	const flags = ntlm.NegotiateUnicode | ntlm.NegotiateExtendedSessionSec |
		ntlm.NegotiateKeyExch | ntlm.Negotiate128 | ntlm.NegotiateTargetInfo
	targetInfo := avPair(2, w.domain)
	targetInfo = append(targetInfo, avPair(1, "DESKTOP")...)
	targetInfo = append(targetInfo, 0, 0, 0, 0)
	if err := writeTSRequest(conn, tsRequest{Version: credSSPVersion,
		NegoTokens: []negoToken{{Token: challengeMessage(w.challenge, flags, targetInfo)}}}); err != nil {
		return
	}

	req, err = readTSRequest(conn)
	if err != nil || len(req.NegoTokens) == 0 {
		return
	}
	exported, err := w.recoverKey(req.NegoTokens[0].Token)
	if err != nil {
		w.t.Errorf("the session key could not be recovered: %v", err)
		return
	}
	peer, err := ntlm.NewSession(exported, ntlm.RoleServer)
	if err != nil {
		return
	}
	// What this end sent must be the binding for this tunnel.
	opened, err := peer.Unseal(req.PubKeyAuth[ntlm.SignatureSize:], req.PubKeyAuth[:ntlm.SignatureSize])
	if err != nil {
		w.t.Errorf("the client's binding did not authenticate: %v", err)
		return
	}
	want := bindingValue(credSSPVersion, clientToServerBinding, req.ClientNonce, pubKey)
	if string(opened) != string(want) {
		w.t.Error("the client's binding is not over this connection's key")
		return
	}

	answerKey := pubKey
	if w.wrongBinding {
		answerKey = append([]byte{0xFF}, pubKey[1:]...)
	}
	sealed, sig := peer.Seal(bindingValue(credSSPVersion, serverToClientBinding, req.ClientNonce, answerKey))
	if err := writeTSRequest(conn, tsRequest{Version: credSSPVersion,
		PubKeyAuth: append(append([]byte(nil), sig...), sealed...)}); err != nil {
		return
	}

	req, err = readTSRequest(conn)
	if err != nil || len(req.AuthInfo) <= ntlm.SignatureSize {
		return
	}
	creds, err := peer.Unseal(req.AuthInfo[ntlm.SignatureSize:], req.AuthInfo[:ntlm.SignatureSize])
	if err != nil {
		w.t.Errorf("the credential did not authenticate: %v", err)
		return
	}
	var outer tsCredentials
	if _, err := asn1.Unmarshal(creds, &outer); err != nil {
		w.t.Errorf("the credential did not parse: %v", err)
		return
	}
	var inner tsPasswordCreds
	if _, err := asn1.Unmarshal(outer.Credentials, &inner); err != nil {
		w.t.Errorf("the password credential did not parse: %v", err)
		return
	}
	w.got = &inner
}

// recoverKey does what a Windows server does with the third message:
// derive the key from the password it holds, and unwrap the session
// key the client chose.
func (w *windows) recoverKey(auth []byte) ([]byte, error) {
	ntowf := testNTOWFv2(w.user, w.domain, w.password)
	nt, err := ntlmField(auth, 20)
	if err != nil {
		return nil, err
	}
	if len(nt) < 16 {
		return nil, errShort
	}
	base := testHMAC(ntowf, nt[:16])
	sealedKey, err := ntlmField(auth, 52)
	if err != nil {
		return nil, err
	}
	c, err := rc4.NewCipher(base) //nolint:gosec // the protocol specifies RC4
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(sealedKey))
	c.XORKeyStream(out, sealedKey)
	return out, nil
}

var errShort = &asn1.SyntaxError{Msg: "short"}

// ntlmField reads one of NTLM's length-and-offset descriptors.
func ntlmField(b []byte, at int) ([]byte, error) {
	if at+8 > len(b) {
		return nil, errShort
	}
	n := int(binary.LittleEndian.Uint16(b[at : at+2]))
	off := int(binary.LittleEndian.Uint32(b[at+4 : at+8]))
	if off+n > len(b) {
		return nil, errShort
	}
	return b[off : off+n], nil
}

// challengeMessage renders the server's second message.
func challengeMessage(challenge []byte, flags uint32, targetInfo []byte) []byte {
	name := testUTF16("DESKTOP")
	out := append([]byte("NTLMSSP\x00"), 2, 0, 0, 0)
	const fixed = 48
	desc := func(n, off int) []byte {
		d := make([]byte, 8)
		binary.LittleEndian.PutUint16(d[0:2], uint16(n)) //nolint:gosec // test sizes
		binary.LittleEndian.PutUint16(d[2:4], uint16(n)) //nolint:gosec // the same
		binary.LittleEndian.PutUint32(d[4:8], uint32(off))
		return d
	}
	out = append(out, desc(len(name), fixed)...)
	out = binary.LittleEndian.AppendUint32(out, flags)
	out = append(out, challenge...)
	out = append(out, make([]byte, 8)...)
	out = append(out, desc(len(targetInfo), fixed+len(name))...)
	out = append(out, name...)
	return append(out, targetInfo...)
}

func avPair(id uint16, value string) []byte {
	v := testUTF16(value)
	out := binary.LittleEndian.AppendUint16(nil, id)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(v))) //nolint:gosec // test sizes
	return append(out, v...)
}

func testUTF16(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}

func testHMAC(key, data []byte) []byte {
	h := hmac.New(md5.New, key) //nolint:gosec // the protocol specifies MD5
	h.Write(data)
	return h.Sum(nil)
}

func testNTOWFv2(user, domain, password string) []byte {
	h := md4.New()
	h.Write(testUTF16(password))
	return testHMAC(h.Sum(nil), testUTF16(strings.ToUpper(user)+domain))
}

// tlsPair sets up a TLS connection over a pipe and returns both ends
// with the public key the binding is over.
func tlsPair(t *testing.T) (client, server *tls.Conn, pubKey []byte) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile := testutil.WriteCert(t, dir, "desktop.test")
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	client = tls.Client(c1, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // a pipe to a certificate this test wrote
	server = tls.Server(c2, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})

	var spki struct {
		Algo      pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	leaf, err := parseLeaf(pair)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(leaf, &spki); err != nil {
		t.Fatal(err)
	}
	return client, server, spki.PublicKey.RightAlign()
}

func parseLeaf(pair tls.Certificate) ([]byte, error) {
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	return leaf.RawSubjectPublicKeyInfo, nil
}

// The exchange completes and the credential arrives, sealed.
func TestNetworkLevelAuthenticationCompletes(t *testing.T) {
	client, server, pubKey := tlsPair(t)
	w := &windows{t: t, domain: "LAB", user: "svc", password: "s3cret",
		challenge: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	done := make(chan struct{})
	go func() { defer close(done); w.serve(server, pubKey) }()

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := Authenticate(t.Context(), client, ntlm.Credential{
		Domain: "LAB", User: "svc", Password: "s3cret", Workstation: "GATE",
	}); err != nil {
		t.Fatalf("the exchange failed: %v", err)
	}
	<-done
	if w.got == nil {
		t.Fatal("the desktop got no credential")
	}
	if string(w.got.User) != string(utf16Bytes("svc")) ||
		string(w.got.Password) != string(utf16Bytes("s3cret")) ||
		string(w.got.Domain) != string(utf16Bytes("LAB")) {
		t.Errorf("the desktop got %q/%q/%q", w.got.Domain, w.got.User, w.got.Password)
	}
}

// A far end that cannot prove it saw this tunnel's key does not get
// the credential, which is what the binding step is for.
func TestARelayedExchangeGetsNoCredential(t *testing.T) {
	client, server, pubKey := tlsPair(t)
	w := &windows{t: t, domain: "LAB", user: "svc", password: "s3cret",
		challenge: []byte{1, 2, 3, 4, 5, 6, 7, 8}, wrongBinding: true}
	done := make(chan struct{})
	go func() { defer close(done); w.serve(server, pubKey) }()

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	err := Authenticate(t.Context(), client, ntlm.Credential{Domain: "LAB", User: "svc", Password: "s3cret"})
	if err == nil {
		t.Fatal("a far end with the wrong binding was accepted")
	}
	if !strings.Contains(err.Error(), "binding") {
		t.Errorf("error %q does not name the binding", err)
	}
	// Closing this end lets the stand-in's read return, rather than
	// holding it until its deadline.
	_ = client.Close()
	<-done
	if w.got != nil {
		t.Error("the credential was sent anyway")
	}
}
