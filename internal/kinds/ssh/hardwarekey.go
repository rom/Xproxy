package ssh

import (
	"fmt"

	cssh "golang.org/x/crypto/ssh"
)

// Keys held in a security token: sk-ssh-ed25519@openssh.com and
// sk-ecdsa-sha2-nistp256@openssh.com, the FIDO2 key types OpenSSH writes when
// a key is generated on a token rather than in a file.
//
// The distinction this gateway can act on is narrow and worth being exact
// about. It cannot tell a good passphrase from a bad one, a laptop with full
// disk encryption from one without, or an agent forwarded carefully from one
// forwarded to a host that keeps it. What it can tell is whether the private
// key is a file at all: a token's key never leaves the token, so what crosses
// the wire is a signature the token made, and there is no copy of the
// credential to steal, back up or leak.
//
// The second half is the touch. A signature from a token carries a flag saying
// the user was present when it was made, and x/crypto refuses one without it
// unless the credential opts out -- by a no-touch-required option on the
// authorized_keys line, or by an extension of that name in a certificate.
// Without presence the key cannot be copied but can be used by anything
// running on the machine it is plugged into, which is most of what the token
// was bought to prevent, so the opt-outs are refused unless the listener says
// otherwise.

// noTouchRequired is the option and extension name OpenSSH uses for the
// presence opt-out. It is spelt here rather than imported because x/crypto
// keeps its own copy unexported.
const noTouchRequired = "no-touch-required"

// hardwareAlgos are the key types a token holds.
var hardwareAlgos = map[string]bool{
	cssh.KeyAlgoSKED25519:  true,
	cssh.KeyAlgoSKECDSA256: true,
}

// hardwareBacked reports whether a key is held in a token. For a certificate
// it is the certificate's own key that decides: the authority signed a
// statement about a key, and where that key lives is what matters here, not
// what the authority's key is.
func hardwareBacked(key cssh.PublicKey) bool {
	if cert, ok := key.(*cssh.Certificate); ok {
		if cert.Key == nil {
			return false
		}
		return hardwareAlgos[cert.Key.Type()]
	}
	return hardwareAlgos[key.Type()]
}

// waivesTouch reports whether a certificate asks for the presence check to be
// skipped. An authorized_keys line asks for it too, and that is answered at
// load (see loadCredentials) because the file is read there.
func waivesTouch(key cssh.PublicKey) bool {
	cert, ok := key.(*cssh.Certificate)
	if !ok || cert.Extensions == nil {
		return false
	}
	_, waived := cert.Extensions[noTouchRequired]
	return waived
}

// checkHardwareKey applies the token policy to a key that has already been
// accepted as a credential: the listener's requirement, or this principal's
// own, and the presence opt-out a certificate may carry.
//
// It runs after the principal is known, because the exemption is per principal:
// an estate moving to tokens moves one person at a time, and a service account
// has no hands.
func (t *server) checkHardwareKey(key cssh.PublicKey, pr *sshPrincipal) error {
	h := t.h
	required := h.RequireHardwareKey
	if pr != nil && pr.hardware != nil {
		required = *pr.hardware
	}
	hardware := hardwareBacked(key)
	if required && !hardware {
		// The message names the key type on purpose: an operator reading it
		// has to know whether the client offered the wrong key or has not
		// enrolled a token at all.
		return fmt.Errorf("this listener accepts only a key held in a security token, and %s is a key in a file", key.Type())
	}
	if hardware && h.Touch() && waivesTouch(key) {
		// The certificate asks for the presence check to be skipped. Refused
		// rather than honoured: the authority can hand out a credential that
		// needs no touch, and this listener's answer to that is no.
		return fmt.Errorf("the certificate carries %s, and this listener requires user presence", noTouchRequired)
	}
	return nil
}
