package vnc

import (
	"net"

	"github.com/rom/xproxy/internal/rfb"
	"github.com/rom/xproxy/internal/textsafe"
)

// RealVNC's RSA-AES types, 129, 130 and 133, on both legs.
//
// The shape is the same on each: a public key each way, a random each
// way sealed under the other's key, session keys hashed out of the two
// randoms, and then a channel of AES-EAX boxes carrying a transcript
// hash and the credential. internal/rfb holds the wire format and says
// what is specified and what is reconstructed; this file is the
// policy around it.
//
// The policy is the usual one here, and it is the reason to terminate
// rather than relay: what a person proves to the gateway is checked by
// the gateway, and the credential that opens the desktop is the one an
// operator configured. The peer's key is pinned rather than shown to
// somebody to accept, because there is nobody at a proxy to ask.

// clientRSAAES plays the RSA-AES server.
func (se *session) clientRSAAES() string {
	t := se.t
	sec := se.clientSec
	if t.rsaKey == nil {
		// Validation requires the key, so this is only reachable if
		// that ever stops being true.
		return "security_unsupported"
	}
	ownKey, err := rfb.OwnRSAAESKey(&t.rsaKey.PublicKey)
	if err != nil {
		return "auth"
	}
	if _, err := se.client.Write(ownKey.Encode()); err != nil {
		return "write"
	}
	peer, peerPub, err := rfb.ReadRSAAESKey(se.client)
	if err != nil {
		t.deny(se.ip, "vnc_rsaaes_key", err.Error())
		return "client_auth"
	}
	// The client's random comes first, then this end's.
	clientRandom, err := rfb.OpenRSAAESRandom(se.client, t.rsaKey, sec)
	if err != nil {
		t.deny(se.ip, "vnc_rsaaes_random", err.Error())
		return "client_auth"
	}
	serverRandom, err := rfb.RSAAESRandom(sec)
	if err != nil {
		return "rand"
	}
	sealed, err := rfb.SealRSAAESRandom(peerPub, serverRandom)
	if err != nil {
		return "auth"
	}
	if _, err := se.client.Write(sealed); err != nil {
		return "write"
	}
	clientKey, serverKey := rfb.RSAAESSessionKeys(sec, clientRandom, serverRandom)
	// This end writes with the server key and reads with the client's.
	ch, err := rfb.NewAESConn(se.client, serverKey, clientKey)
	if err != nil {
		return "auth"
	}
	se.client = ch

	// Each end hashes its own key first, so the two transcripts differ
	// and one cannot be replayed as the other.
	if _, err := ch.Write(rfb.RSAAESTranscript(sec, ownKey, peer)); err != nil {
		return "write"
	}
	want := rfb.RSAAESTranscript(sec, peer, ownKey)
	got, err := ch.ReadFull(len(want))
	if err != nil {
		return "client_auth"
	}
	if !rfb.RSAAESTranscriptMatches(got, want) {
		// The two ends did not see the same pair of keys, which is
		// what someone in the middle swapping them looks like.
		t.deny(se.ip, "vnc_rsaaes_transcript", "")
		return "client_auth"
	}
	if _, err := ch.Write([]byte{rfb.RSAAESSubtypeUserPassword}); err != nil {
		return "write"
	}
	user, secret, err := rfb.ReadRSAAESCredential(ch)
	if err != nil {
		return "client_auth"
	}
	// The security result goes inside the channel on both legs; the
	// "ne" type leaves it afterwards, in leaveChannel.
	return se.namedCredential(user, secret)
}

// upstreamRSAAES plays the RSA-AES client towards a target, with the
// target's key pinned.
func (se *session) upstreamRSAAES() string {
	t := se.t
	sec := se.upSec
	peer, peerPub, err := rfb.ReadRSAAESKey(se.up)
	if err != nil {
		return "upstream_auth"
	}
	fp := rfb.RSAAESFingerprint(peer)
	if want := t.v.UpstreamRSAFingerprint; want == "" || !rfb.FingerprintMatches(want, fp) {
		// Nothing authenticates the far end of this exchange but its
		// key, so an unpinned one is not a target to hand a credential
		// to. The log prints what was offered, which is how an
		// operator fills the setting in.
		t.engine.Logs().Error.Warn("vnc target's rsa-aes key is not the pinned one",
			"listener", t.cfg.Name, "target", se.target,
			"offered", fp, "pinned", textsafe.Clip256(want))
		return "upstream_key_unpinned"
	}
	if t.rsaKey == nil {
		return "upstream_security_unusable"
	}
	ownKey, err := rfb.OwnRSAAESKey(&t.rsaKey.PublicKey)
	if err != nil {
		return "upstream_auth"
	}
	if _, err := se.up.Write(ownKey.Encode()); err != nil {
		return "upstream_write"
	}
	clientRandom, err := rfb.RSAAESRandom(sec)
	if err != nil {
		return "rand"
	}
	sealed, err := rfb.SealRSAAESRandom(peerPub, clientRandom)
	if err != nil {
		return "upstream_auth"
	}
	if _, err := se.up.Write(sealed); err != nil {
		return "upstream_write"
	}
	serverRandom, err := rfb.OpenRSAAESRandom(se.up, t.rsaKey, sec)
	if err != nil {
		return "upstream_auth"
	}
	clientKey, serverKey := rfb.RSAAESSessionKeys(sec, clientRandom, serverRandom)
	// The other way round from the server's side.
	ch, err := rfb.NewAESConn(se.up, clientKey, serverKey)
	if err != nil {
		return "upstream_auth"
	}
	se.up = ch

	want := rfb.RSAAESTranscript(sec, peer, ownKey)
	got, err := ch.ReadFull(len(want))
	if err != nil {
		return "upstream_auth"
	}
	if !rfb.RSAAESTranscriptMatches(got, want) {
		return "upstream_auth"
	}
	if _, err := ch.Write(rfb.RSAAESTranscript(sec, ownKey, peer)); err != nil {
		return "upstream_write"
	}
	if _, err := ch.ReadFull(1); err != nil {
		return "upstream_auth"
	}
	cred, err := rfb.RSAAESCredential(t.v.UpstreamUser, t.upPassword)
	if err != nil {
		return "upstream_auth"
	}
	if _, err := ch.Write(cred); err != nil {
		return "upstream_write"
	}
	return ""
}

// leaveChannel puts a leg back on its cleartext socket, which is what
// the "ne" type does once the security result is in. Which of the
// three types encrypts the session is the one thing about this family
// an operator is most likely to get wrong, so the access log names the
// security type of both legs and CONFIG.md spells it out.
func leaveChannel(c net.Conn, sec uint8) (net.Conn, error) {
	ch, ok := c.(*rfb.AESConn)
	if !ok || rfb.RSAAESEncrypted(sec) {
		return c, nil
	}
	return ch.Unwrap()
}
