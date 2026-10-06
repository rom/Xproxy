package vnc

import (
	"encoding/binary"
	"io"

	"github.com/rom/xproxy/internal/rfb"
)

// MS-Logon II, UltraVNC's security type 113, on both legs.
//
// It is here for one reason: the desktops exist. An estate whose
// machines speak only this is better reached through a gateway that
// records the session, asks for a factor and holds the policy than
// reached directly. The type itself protects the credential with a 64
// bit key exchange and DES, which is to say with nothing, and both the
// validation warning and docs/CONFIG.md say so.
//
// What that means for the two legs is not symmetrical. Towards a
// client the credential is a name and a password like any other, so a
// factor can be asked for and the desktop's own password is never
// involved. Towards a target the gateway sends the credential an
// operator configured, which is the same arrangement as everywhere
// else here: what a person proves to the gateway is not what opens the
// desktop.

// clientMSLogon plays the MS-Logon II server: the parameters, then the
// client's public value and the credential encrypted under the secret
// they agree on.
func (se *session) clientMSLogon() string {
	t := se.t
	params, priv, err := rfb.NewMSLogonParams()
	if err != nil {
		return "rand"
	}
	if _, err := se.client.Write(params.Encode()); err != nil {
		return "write"
	}
	var pub [rfb.MSLogonDHSize]byte
	if _, err := io.ReadFull(se.client, pub[:]); err != nil {
		return "client_auth"
	}
	shared, err := rfb.MSLogonShared(binary.BigEndian.Uint64(pub[:]), priv, params.Mod)
	if err != nil {
		// A public value that fixes the secret is a client trying
		// something, not one that is confused.
		t.deny(se, "vnc_mslogon_parameters", err.Error())
		return "client_auth"
	}
	user, secret, err := rfb.ReadMSLogonCredential(se.client, shared)
	if err != nil {
		return "client_auth"
	}
	return se.namedCredential(user, secret)
}

// upstreamMSLogon plays the MS-Logon II client, with the credential an
// operator configured for this listener.
func (se *session) upstreamMSLogon() string {
	t := se.t
	params, err := rfb.ReadMSLogonParams(se.up)
	if err != nil {
		return "upstream_auth"
	}
	pub, priv, err := rfb.MSLogonPublic(params)
	if err != nil {
		return "upstream_auth"
	}
	shared, err := rfb.MSLogonShared(params.Pub, priv, params.Mod)
	if err != nil {
		// The target chose parameters that fix the secret. That is a
		// target worth not authenticating to.
		t.engine.Logs().Error.Warn("vnc target sent unusable mslogon2 parameters",
			"listener", t.cfg.Name, "target", se.target, "err", err.Error())
		return "upstream_auth"
	}
	cred, err := rfb.MSLogonSeal(shared, t.v.UpstreamUser, t.upPassword)
	if err != nil {
		return "upstream_auth"
	}
	out := binary.BigEndian.AppendUint64(nil, pub)
	if _, err := se.up.Write(append(out, cred...)); err != nil {
		return "upstream_write"
	}
	return ""
}
