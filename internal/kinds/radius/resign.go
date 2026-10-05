package radius

import (
	"crypto/md5" //nolint:gosec // RFC 2865 specifies MD5 for both authenticators and for the password obfuscation
	"crypto/rand"
	"errors"

	wire "github.com/rom/xproxy/internal/radius"
)

// Re-signing a packet, which is what a relay that translates identifiers
// has to do.
//
// Changing one octet of a RADIUS packet invalidates both of its integrity
// values: the Message-Authenticator is an HMAC over the whole thing, and
// the Response and Accounting-Request authenticators are MD5 over the whole
// thing with the secret appended. So a relay that renumbers a request --
// which it must, because eight bits of identifier are not enough to
// multiplex two switches -- has to recompute them, and that is only
// possible with the secret.
//
// The order the two are computed in is not a detail. RFC 2866's
// Accounting-Request authenticator is MD5 over the packet *including* its
// attributes, and the Message-Authenticator is one of those attributes, so
// the HMAC has to be written first and the MD5 second. Getting it the other
// way round produces a packet every server rejects, and it is the mistake
// this file exists to not make.
//
// One more thing happens here, and it is the only place in this project
// that recovers a credential: when the two legs have different secrets, the
// obfuscated User-Password has to be re-obfuscated under the new one, which
// means XORing it back to plaintext and XORing it forward again. It is done
// in a buffer that is used and dropped inside one call, it is reached only
// on a listener that was configured with two secrets, and a listener with
// one never calls it.

// errPasswordLength is returned for a User-Password whose length the
// obfuscation cannot have produced. It is refused rather than padded: a
// server decoding a short final block reads past it or truncates, and which
// it does is an implementation's choice -- so a packet like this is a
// request two servers may read differently.
var errPasswordLength = errors.New("radius: User-Password length is not a multiple of 16")

// forward builds the packet to send to the server: a new identifier, a new
// request authenticator where the code has one, the password re-obfuscated
// if the secrets differ, and both digests recomputed.
//
// It returns the authenticator it used, because the reply's digests are
// computed over that value and the caller has to remember it.
func forward(p *wire.Packet, id uint8, oldSecret, newSecret []byte) ([]byte, [wire.AuthenticatorBytes]byte, error) {
	out := make([]byte, len(p.Raw))
	copy(out, p.Raw)
	out[1] = id
	var auth [wire.AuthenticatorBytes]byte
	switch p.Code {
	case wire.CodeAccessRequest, wire.CodeStatusServer, wire.CodeStatusClient:
		// The Request Authenticator is a nonce the client chose. A relay
		// that reused it would be handing the server a value this relay
		// does not control, and the password obfuscation is keyed on it --
		// so a new one is drawn, and the password is re-obfuscated to match
		// even when the secret has not changed.
		if _, err := rand.Read(auth[:]); err != nil {
			return nil, auth, err
		}
		copy(out[4:wire.HeaderBytes], auth[:])
		if err := reobfuscate(p, out, oldSecret, p.Authenticator, newSecret, auth); err != nil {
			return nil, auth, err
		}
	default:
		// Accounting-Request, and RFC 5176's dynamic authorization codes:
		// the authenticator is MD5 over the packet with sixteen zeroes in
		// its place and the secret appended, so it is zeroed now and
		// computed last.
		for i := 4; i < wire.HeaderBytes; i++ {
			out[i] = 0
		}
	}
	signMAC(p, out, newSecret, auth)
	if p.Code != wire.CodeAccessRequest && p.Code != wire.CodeStatusServer &&
		p.Code != wire.CodeStatusClient {
		sum := md5.New() //nolint:gosec // RFC 2866 specifies MD5
		sum.Write(out)
		sum.Write(newSecret)
		copy(out[4:wire.HeaderBytes], sum.Sum(nil))
		copy(auth[:], out[4:wire.HeaderBytes])
	}
	return out, auth, nil
}

// backward builds the reply to send to the client: the client's identifier
// back, and both digests recomputed over the client's own request
// authenticator.
func backward(p *wire.Packet, e *exchange, secret []byte) []byte {
	out := make([]byte, len(p.Raw))
	copy(out, p.Raw)
	out[1] = e.clientID
	// The computation substitutes the request's authenticator into the
	// field, so the field is set to it before the HMAC and overwritten by
	// the MD5 afterwards.
	copy(out[4:wire.HeaderBytes], e.clientAuth[:])
	signMAC(p, out, secret, e.clientAuth)
	sum := md5.New() //nolint:gosec // RFC 2865 specifies MD5
	sum.Write(out[:4])
	sum.Write(e.clientAuth[:])
	sum.Write(out[wire.HeaderBytes:])
	sum.Write(secret)
	copy(out[4:wire.HeaderBytes], sum.Sum(nil))
	return out
}

// signMAC recomputes the Message-Authenticator in place, where the packet
// carries one.
//
// A packet with no such attribute is left alone: adding one would be adding
// an attribute the client did not send, which changes what the server sees
// a request as carrying -- and on a protocol where the attribute's presence
// is itself policy, inventing one would be answering the question the
// policy asks.
func signMAC(p *wire.Packet, out, secret []byte, auth [wire.AuthenticatorBytes]byte) {
	a, ok := p.First(wire.AttrMessageAuthenticator)
	if !ok || len(a.Value) != wire.AuthenticatorBytes {
		return
	}
	at := a.Offset
	if at < wire.HeaderBytes || at+wire.AuthenticatorBytes > len(out) {
		return
	}
	for i := 0; i < wire.AuthenticatorBytes; i++ {
		out[at+i] = 0
	}
	// The digest is over the packet with the *request's* authenticator in
	// the field, which for a request this relay is forwarding is the one it
	// just drew, and for a reply is the client's.
	keep := make([]byte, wire.AuthenticatorBytes)
	copy(keep, out[4:wire.HeaderBytes])
	copy(out[4:wire.HeaderBytes], auth[:])
	mac := hmacMD5(secret, out)
	copy(out[4:wire.HeaderBytes], keep)
	copy(out[at:], mac)
}

// reobfuscate rewrites a User-Password under a new secret and a new request
// authenticator.
//
// RFC 2865 §5.2: the password is XORed with a chain of MD5 digests, the
// first over secret || authenticator and each one after over secret ||
// previous ciphertext block. Decoding and encoding are the same walk with
// the roles of the blocks swapped, which is why both directions are here
// rather than in two functions that could drift apart.
func reobfuscate(p *wire.Packet, out, oldSecret []byte, oldAuth [wire.AuthenticatorBytes]byte,
	newSecret []byte, newAuth [wire.AuthenticatorBytes]byte) error {
	a, ok := p.First(wire.AttrUserPassword)
	if !ok {
		return nil
	}
	n := len(a.Value)
	if n == 0 || n%md5.Size != 0 || n > wire.MaxPassword {
		return errPasswordLength
	}
	at := a.Offset
	if at < wire.HeaderBytes || at+n > len(out) {
		return errPasswordLength
	}
	// The cipher blocks are read from the packet as it arrived, because the
	// chain is over the *ciphertext* and the output buffer is about to hold
	// different ciphertext.
	cipher := make([]byte, n)
	copy(cipher, a.Value)
	plain := make([]byte, n)
	prev := oldAuth[:]
	for off := 0; off < n; off += md5.Size {
		pad := md5.Sum(append(append([]byte{}, oldSecret...), prev...)) //nolint:gosec // RFC 2865 specifies MD5
		for i := 0; i < md5.Size; i++ {
			plain[off+i] = cipher[off+i] ^ pad[i]
		}
		prev = cipher[off : off+md5.Size]
	}
	prev = newAuth[:]
	for off := 0; off < n; off += md5.Size {
		pad := md5.Sum(append(append([]byte{}, newSecret...), prev...)) //nolint:gosec // RFC 2865 specifies MD5
		for i := 0; i < md5.Size; i++ {
			out[at+off+i] = plain[off+i] ^ pad[i]
		}
		prev = out[at+off : at+off+md5.Size]
	}
	// The plaintext existed for the length of this call and is cleared
	// before it returns. It is not a strong guarantee -- the garbage
	// collector may have copied it -- and it costs nothing, and the
	// alternative is leaving every administrative password this relay
	// re-keys lying in a buffer on the heap.
	for i := range plain {
		plain[i] = 0
	}
	return nil
}
