package rdp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"github.com/rom/xproxy/internal/ntlm"
)

// CredSSP, which RDP calls network level authentication: the
// credential is proved inside the TLS tunnel before the connection
// sequence starts. MS-CSSP specifies it; the tokens it carries are
// NTLM, from internal/ntlm.
//
// This is the client half only. A gateway proves its own credential to
// a desktop with it; it never checks one, because checking would mean
// holding the password of whoever is connecting.
//
// The exchange binds itself to the tunnel it runs in: each end sends
// the other a value derived from the server's public key, sealed with
// the session keys. Someone relaying the tokens between two different
// tunnels therefore fails, which is the whole point of the step.

// ErrCredSSP is a failure in the exchange.
var ErrCredSSP = errors.New("rdp: credssp")

// The version this gateway offers. From five onwards the binding is a
// hash over a nonce rather than the public key itself, which is what
// closes the relay the earlier versions allowed.
const (
	credSSPVersion    = 6
	credSSPHashFrom   = 5
	credSSPNonceBytes = 32
)

// The two binding labels of MS-CSSP 3.1.5.
var (
	clientToServerBinding = []byte("CredSSP Client-To-Server Binding Hash\x00")
	serverToClientBinding = []byte("CredSSP Server-To-Client Binding Hash\x00")
)

// maxTSRequest bounds one message from the server.
const maxTSRequest = 64 << 10

type negoToken struct {
	Token []byte `asn1:"explicit,tag:0"`
}

type tsRequest struct {
	Version     int         `asn1:"explicit,tag:0"`
	NegoTokens  []negoToken `asn1:"optional,explicit,tag:1"`
	AuthInfo    []byte      `asn1:"optional,explicit,tag:2"`
	PubKeyAuth  []byte      `asn1:"optional,explicit,tag:3"`
	ErrorCode   int         `asn1:"optional,explicit,tag:4"`
	ClientNonce []byte      `asn1:"optional,explicit,tag:5"`
}

type tsPasswordCreds struct {
	Domain   []byte `asn1:"explicit,tag:0"`
	User     []byte `asn1:"explicit,tag:1"`
	Password []byte `asn1:"explicit,tag:2"`
}

type tsCredentials struct {
	CredType    int    `asn1:"explicit,tag:0"`
	Credentials []byte `asn1:"explicit,tag:1"`
}

// Authenticate proves a credential to a desktop over an established
// TLS connection.
func Authenticate(ctx context.Context, conn *tls.Conn, cred ntlm.Credential) error {
	// The binding is over the certificate the tunnel was built with,
	// so the tunnel has to exist first. A caller that has already
	// completed the handshake loses nothing by this: it is idempotent.
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrCredSSP, err)
	}
	pubKey, err := tlsPublicKey(conn)
	if err != nil {
		return err
	}
	// The first token.
	if err := writeTSRequest(conn, tsRequest{
		Version:    credSSPVersion,
		NegoTokens: []negoToken{{Token: ntlm.Negotiate()}},
	}); err != nil {
		return err
	}
	resp, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if resp.ErrorCode != 0 {
		return fmt.Errorf("%w: the desktop answered with error %#x", ErrCredSSP, resp.ErrorCode)
	}
	if len(resp.NegoTokens) == 0 {
		return fmt.Errorf("%w: the desktop sent no challenge", ErrCredSSP)
	}
	version := min(resp.Version, credSSPVersion)

	challenge, err := ntlm.ParseChallenge(resp.NegoTokens[0].Token)
	if err != nil {
		return err
	}
	auth, session, err := ntlm.Authenticate(challenge, cred)
	if err != nil {
		return err
	}

	// The binding, which ties this exchange to this tunnel.
	var nonce []byte
	if version >= credSSPHashFrom {
		nonce = make([]byte, credSSPNonceBytes)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
	}
	sealed, sig := session.Seal(bindingValue(version, clientToServerBinding, nonce, pubKey))
	pubKeyAuth := append(append([]byte(nil), sig...), sealed...)
	if err := writeTSRequest(conn, tsRequest{
		Version:     version,
		NegoTokens:  []negoToken{{Token: auth}},
		PubKeyAuth:  pubKeyAuth,
		ClientNonce: nonce,
	}); err != nil {
		return err
	}

	resp, err = readTSRequest(conn)
	if err != nil {
		return err
	}
	if resp.ErrorCode != 0 {
		return fmt.Errorf("%w: the desktop refused the credential, error %#x", ErrCredSSP, resp.ErrorCode)
	}
	if err := checkBinding(session, resp.PubKeyAuth, version, nonce, pubKey); err != nil {
		return err
	}

	// Only now does the credential itself travel.
	creds, err := encodeCredentials(cred)
	if err != nil {
		return err
	}
	sealed, sig = session.Seal(creds)
	authInfo := append(append([]byte(nil), sig...), sealed...)
	return writeTSRequest(conn, tsRequest{Version: version, AuthInfo: authInfo})
}

// bindingValue is what each end proves it saw: the public key itself
// in the older versions, and a hash over a nonce and the key from
// version five, which is what stops the tokens being relayed into
// another tunnel.
func bindingValue(version int, label, nonce, pubKey []byte) []byte {
	if version < credSSPHashFrom {
		return pubKey
	}
	h := sha256.New()
	h.Write(label)
	h.Write(nonce)
	h.Write(pubKey)
	return h.Sum(nil)
}

// checkBinding verifies the desktop's half of it.
func checkBinding(s *ntlm.Session, got []byte, version int, nonce, pubKey []byte) error {
	if len(got) <= ntlm.SignatureSize {
		return fmt.Errorf("%w: the desktop sent no public key binding", ErrCredSSP)
	}
	opened, err := s.Unseal(got[ntlm.SignatureSize:], got[:ntlm.SignatureSize])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCredSSP, err)
	}
	want := bindingValue(version, serverToClientBinding, nonce, pubKey)
	if version < credSSPHashFrom {
		// The older versions answer with the key itself, with its
		// first byte incremented so the two directions differ.
		want = append([]byte(nil), pubKey...)
		want[0]++
	}
	if subtle.ConstantTimeCompare(opened, want) != 1 {
		return fmt.Errorf("%w: the desktop's public key binding does not match this connection", ErrCredSSP)
	}
	return nil
}

// encodeCredentials renders the credential the desktop logs in with.
func encodeCredentials(cred ntlm.Credential) ([]byte, error) {
	pw, err := asn1.Marshal(tsPasswordCreds{
		Domain:   utf16Bytes(cred.Domain),
		User:     utf16Bytes(cred.User),
		Password: utf16Bytes(cred.Password),
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(tsCredentials{CredType: 1, Credentials: pw})
}

// utf16Bytes renders a credential field the way the protocol carries
// it.
func utf16Bytes(s string) []byte { return encodeText(s, true) }

// tlsPublicKey is the server's public key as MS-CSSP means it: the
// contents of the certificate's public key bit string, without the
// algorithm wrapper around it.
func tlsPublicKey(conn *tls.Conn) ([]byte, error) {
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: the desktop presented no certificate", ErrCredSSP)
	}
	var spki struct {
		Algo      pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(certs[0].RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("%w: the desktop's public key did not parse: %w", ErrCredSSP, err)
	}
	return spki.PublicKey.RightAlign(), nil
}

// writeTSRequest sends one message.
func writeTSRequest(w io.Writer, req tsRequest) error {
	b, err := asn1.Marshal(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCredSSP, err)
	}
	_, err = w.Write(b)
	return err
}

// readTSRequest reads one. The messages are self-delimiting rather
// than length-prefixed, so the tag and length are read first and the
// body behind them, and the whole thing is kept because that is what
// the decoder takes.
func readTSRequest(r io.Reader) (tsRequest, error) {
	var req tsRequest
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return req, err
	}
	size := int(head[1])
	if head[1] >= 0x80 {
		n := int(head[1] & 0x7F)
		// An indefinite length has no place in DER, and a length of a
		// length over three bytes is past what this message can be.
		if n == 0 || n > 3 {
			return req, fmt.Errorf("%w: a length of %d bytes", ErrCredSSP, n)
		}
		rest := make([]byte, n)
		if _, err := io.ReadFull(r, rest); err != nil {
			return req, err
		}
		size = 0
		for _, b := range rest {
			size = size<<8 | int(b)
		}
		head = append(head, rest...)
	}
	if size > maxTSRequest {
		return req, fmt.Errorf("%w: a message of %d bytes, over the %d bound", ErrCredSSP, size, maxTSRequest)
	}
	whole := make([]byte, len(head)+size)
	copy(whole, head)
	if _, err := io.ReadFull(r, whole[len(head):]); err != nil {
		return req, err
	}
	if _, err := asn1.Unmarshal(whole, &req); err != nil {
		return req, fmt.Errorf("%w: %w", ErrCredSSP, err)
	}
	return req, nil
}
