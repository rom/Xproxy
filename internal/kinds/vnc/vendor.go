package vnc

import (
	"fmt"
	"io"

	"github.com/rom/xproxy/internal/rfb"
)

// TightVNC's security type 16 and Apple Remote Desktop's 30, on both
// legs. internal/rfb holds each one's wire format and says where it
// comes from; this file is the policy around them.

// clientTight plays the Tight server: no tunnel, then whichever of the
// two authentications this gateway can complete.
func (se *session) clientTight() string {
	t := se.t
	// No tunnels. A tunnel is another protocol wrapped around this
	// one, which is exactly what a gateway must not accept: it would
	// be a session it cannot read or record.
	if _, err := se.client.Write(rfb.TightCapabilities(nil)); err != nil {
		return "write"
	}
	auths := []rfb.TightCapability{rfb.TightAuthNone}
	if t.password != "" {
		auths = []rfb.TightCapability{rfb.TightAuthVNC, rfb.TightAuthNone}
	}
	if _, err := se.client.Write(rfb.TightCapabilities(auths)); err != nil {
		return "write"
	}
	code, err := rfb.ReadTightChoice(se.client)
	if err != nil {
		return "client_auth"
	}
	if !rfb.TightHasCapability(auths, code) {
		// A Tight authentication code is not a security type, so it
		// is logged as the number it is rather than named as one.
		t.deny(se.ip, "vnc_tight_auth_not_offered", fmt.Sprintf("auth %d", code))
		se.securityResult(false, "that authentication was not offered")
		return "security_not_offered"
	}
	// The gateway remembers what the client settled on, so the
	// interaction block after ServerInit goes to the right leg.
	se.clientTightAuth = code
	if code == rfb.TightAuthVNC.Code {
		return se.clientVNCAuth()
	}
	return se.finishClientAuth(true, "")
}

// upstreamTight plays the Tight client towards a target.
func (se *session) upstreamTight() string {
	t := se.t
	tunnels, err := rfb.ReadTightCapabilities(se.up)
	if err != nil {
		return "upstream_auth"
	}
	if len(tunnels) > 0 {
		if !rfb.TightHasCapability(tunnels, rfb.TightTunnelNone.Code) {
			// Every tunnel this target offers would wrap the session
			// in something the gateway cannot read.
			t.engine.Logs().Error.Warn("vnc target offers only tunnelled tight connections",
				"listener", t.cfg.Name, "target", se.target)
			return "upstream_security_unusable"
		}
		if _, err := se.up.Write(rfb.TightChoice(rfb.TightTunnelNone.Code)); err != nil {
			return "upstream_write"
		}
	}
	auths, err := rfb.ReadTightCapabilities(se.up)
	if err != nil {
		return "upstream_auth"
	}
	if len(auths) == 0 {
		// The target asks for nothing, and by this type's own rules
		// sends no security result either.
		se.upNoResult = true
		return ""
	}
	pick := uint32(0)
	switch {
	case rfb.TightHasCapability(auths, rfb.TightAuthVNC.Code) && t.upPassword != "":
		pick = rfb.TightAuthVNC.Code
	case rfb.TightHasCapability(auths, rfb.TightAuthNone.Code):
		pick = rfb.TightAuthNone.Code
	default:
		return "upstream_security_unusable"
	}
	if _, err := se.up.Write(rfb.TightChoice(pick)); err != nil {
		return "upstream_write"
	}
	se.upTight = true
	if pick == rfb.TightAuthVNC.Code {
		return se.upstreamVNCChallenge()
	}
	return ""
}

// clientARD plays the ARD server.
func (se *session) clientARD() string {
	t := se.t
	params, priv, err := rfb.NewARDParams()
	if err != nil {
		return "rand"
	}
	if _, err := se.client.Write(params.Encode()); err != nil {
		return "write"
	}
	// The client answers with the credential and then its public
	// value, in that order.
	blob := make([]byte, rfb.ARDCredentialSize)
	if _, err := io.ReadFull(se.client, blob); err != nil {
		return "client_auth"
	}
	pub := make([]byte, len(params.Prime))
	if _, err := io.ReadFull(se.client, pub); err != nil {
		return "client_auth"
	}
	key, err := rfb.ARDKey(pub, params.Prime, priv)
	if err != nil {
		t.deny(se.ip, "vnc_ard_parameters", err.Error())
		return "client_auth"
	}
	user, secret, err := rfb.ARDOpen(key, blob)
	if err != nil {
		return "client_auth"
	}
	return se.namedCredential(user, secret)
}

// upstreamARD plays the ARD client towards a target.
func (se *session) upstreamARD() string {
	t := se.t
	params, err := rfb.ReadARDParams(se.up)
	if err != nil {
		return "upstream_auth"
	}
	pub, priv, err := rfb.ARDPublic(params)
	if err != nil {
		return "upstream_auth"
	}
	key, err := rfb.ARDKey(params.Pub, params.Prime, priv)
	if err != nil {
		t.engine.Logs().Error.Warn("vnc target sent unusable ard parameters",
			"listener", t.cfg.Name, "target", se.target, "err", err.Error())
		return "upstream_auth"
	}
	blob, err := rfb.ARDSeal(key, t.v.UpstreamUser, t.upPassword)
	if err != nil {
		return "upstream_auth"
	}
	if _, err := se.up.Write(append(blob, pub...)); err != nil {
		return "upstream_write"
	}
	return ""
}

// upstreamVNCChallenge answers a DES challenge from the target, which
// two of the types reach by different routes.
func (se *session) upstreamVNCChallenge() string {
	challenge := make([]byte, rfb.ChallengeSize)
	if _, err := io.ReadFull(se.up, challenge); err != nil {
		return "upstream_auth"
	}
	resp, err := rfb.VNCAuthResponse(challenge, se.t.upPassword)
	if err != nil {
		return "upstream_auth"
	}
	if _, err := se.up.Write(resp); err != nil {
		return "upstream_write"
	}
	return ""
}

// tightInteraction handles the block a Tight server sends after
// ServerInit. A target's is read and dropped, and a client that
// negotiated Tight is told there are no extensions: the capabilities
// advertised there are things like file transfer, which a gateway that
// cannot see inside them has no business passing through.
func (se *session) tightInteraction() string {
	if se.upTight {
		if _, err := rfb.ReadTightInteraction(se.up); err != nil {
			return "upstream_init"
		}
	}
	if se.clientSec == rfb.SecTight {
		if _, err := se.client.Write(rfb.NoTightInteraction()); err != nil {
			return "write"
		}
	}
	return ""
}
