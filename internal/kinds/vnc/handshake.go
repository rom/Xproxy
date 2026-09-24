package vnc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/rom/xproxy/internal/rfb"
	"github.com/rom/xproxy/internal/textsafe"
)

// The handshake is where every decision is. It happens twice, once
// towards each side, and the two need not agree: a 3.3 client can
// reach a 3.8 server through here, and a client offered only vncauth
// can reach a target the gateway opens with VeNCrypt. That is the
// point of terminating rather than forwarding.

// clientHandshake plays the server to the client: version, security
// type, and whatever that type requires.
func (se *session) clientHandshake() string {
	t := se.t
	// The proxy announces the highest version it speaks and takes
	// whatever the client answers with, down to 3.3.
	if _, err := se.client.Write(rfb.V38.Handshake()); err != nil {
		return "write"
	}
	cv, err := rfb.ReadVersion(se.client)
	if err != nil {
		t.deny(se.ip, "vnc_version", err.Error())
		return "client_version"
	}
	v, ok := rfb.Negotiated(cv, rfb.V38)
	if !ok {
		t.deny(se.ip, "vnc_version", cv.String())
		return "client_version"
	}
	se.clientVersion = v

	// What this proxy will accept from a client, in the order it
	// prefers. A 3.3 client cannot choose, so it is told one.
	offered := se.offerable()
	if len(offered) == 0 {
		se.refuseClient("security_not_usable", "no security type this gateway offers is usable here")
		return "no_security"
	}
	if !v.AtLeast(rfb.V37) {
		return se.client33(offered)
	}
	if _, err := se.client.Write(rfb.SecurityList(offered)); err != nil {
		return "write"
	}
	var chosen [1]byte
	if _, err := io.ReadFull(se.client, chosen[:]); err != nil {
		return "client_security"
	}
	if !slices.Contains(offered, chosen[0]) {
		// A client that picks something outside the list it was given
		// is not confused, it is trying something.
		t.engine.Counters().VNCRefused.Add(1)
		t.deny(se.ip, "vnc_security_not_offered", rfb.SecurityName(chosen[0]))
		se.securityResult(false, "that security type was not offered")
		return "security_not_offered"
	}
	se.clientSec = chosen[0]
	return se.clientAuth()
}

// client33 handles a 3.3 client, which is told one security type
// rather than asked.
func (se *session) client33(offered []uint8) string {
	// 3.3 defines only none and vncauth; anything else cannot be named
	// to such a client.
	pick := uint8(rfb.SecInvalid)
	for _, s := range offered {
		if s == rfb.SecVNCAuth || s == rfb.SecNone {
			pick = s
			break
		}
	}
	if pick == rfb.SecInvalid {
		se.refuseClient("security_not_usable_33", "this gateway offers no security type a 3.3 client can use")
		return "no_security_33"
	}
	if _, err := se.client.Write(rfb.Security33(pick)); err != nil {
		return "write"
	}
	se.clientSec = pick
	return se.clientAuth()
}

// offerable is what this proxy can actually complete with a client:
// vncauth needs a password to check against, and vencrypt needs a
// certificate to present.
func (se *session) offerable() []uint8 {
	t := se.t
	out := make([]uint8, 0, len(t.offered))
	for _, s := range t.offered {
		switch s {
		case rfb.SecVNCAuth:
			// A challenge nobody can answer is not authentication.
			if t.password == "" {
				continue
			}
		case rfb.SecVeNCrypt, rfb.SecTLS:
			// Without a certificate there is nothing to present.
			if t.tlsCfg == nil {
				continue
			}
		case rfb.SecMSLogon2:
			// The credential is a name and a password. Without a
			// password to check it against or a factor to check
			// instead, there is nothing to decide on.
			if t.password == "" && t.mfaGuard == nil {
				continue
			}
		case rfb.SecRSAAES, rfb.SecRSAAESne, rfb.SecRSAAES256:
			// The same, and a key of this gateway's own to be
			// identified by.
			if t.rsaKey == nil || (t.password == "" && t.mfaGuard == nil) {
				continue
			}
		case rfb.SecARD:
			// A name and a password, like the two above.
			if t.password == "" && t.mfaGuard == nil {
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

// clientAuth completes whatever the chosen type requires, and sends
// the security result.
func (se *session) clientAuth() string {
	switch se.clientSec {
	case rfb.SecNone:
		return se.finishClientAuth(true, "")
	case rfb.SecVNCAuth:
		return se.clientVNCAuth()
	case rfb.SecVeNCrypt:
		return se.clientVeNCrypt()
	case rfb.SecTLS:
		return se.clientAnonTLS()
	case rfb.SecMSLogon2:
		return se.clientMSLogon()
	case rfb.SecRSAAES, rfb.SecRSAAESne, rfb.SecRSAAES256:
		return se.clientRSAAES()
	case rfb.SecTight:
		return se.clientTight()
	case rfb.SecARD:
		return se.clientARD()
	}
	se.refuseClient("security_not_mediated", "that security type is not mediated by this gateway")
	return "security_unsupported"
}

// clientVNCAuth runs the DES challenge of RFC 6143 section 7.2.2
// against this gateway's own password. The target's password is never
// the client's to learn: whatever the client proves here, the gateway
// opens the target's leg with its own credential.
func (se *session) clientVNCAuth() string {
	if se.t.password == "" {
		se.t.engine.Counters().VNCRefused.Add(1)
		se.t.deny(se.ip, "vnc_auth_unconfigured", "")
		return se.finishClientAuth(false, "authentication is not configured")
	}
	challenge := make([]byte, rfb.ChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return "rand"
	}
	if _, err := se.client.Write(challenge); err != nil {
		return "write"
	}
	got := make([]byte, rfb.ChallengeSize)
	if _, err := io.ReadFull(se.client, got); err != nil {
		return "client_auth"
	}
	want, err := rfb.VNCAuthResponse(challenge, se.t.password)
	if err != nil {
		return "auth"
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		se.t.engine.Counters().VNCRefused.Add(1)
		se.t.deny(se.ip, "vnc_auth_failed", "")
		return se.finishClientAuth(false, "authentication failed")
	}
	return se.finishClientAuth(true, "")
}

// clientVeNCrypt negotiates VeNCrypt and moves the client's leg into
// TLS where the subtype says to.
func (se *session) clientVeNCrypt() string {
	t := se.t
	if _, err := se.client.Write(rfb.VeNCryptVersion(rfb.VeNCrypt02)); err != nil {
		return "write"
	}
	cv, err := rfb.ReadVeNCryptVersion(se.client)
	if err != nil {
		return "client_vencrypt"
	}
	if cv.Major != 0 || cv.Minor < 2 {
		// 0 means agreed, anything else refuses.
		_, _ = se.client.Write([]byte{1})
		return "vencrypt_version"
	}
	if _, err := se.client.Write([]byte{0}); err != nil {
		return "write"
	}
	if _, err := se.client.Write(rfb.Subtypes(t.subtypes)); err != nil {
		return "write"
	}
	sub, err := rfb.ReadSubtypeChoice(se.client)
	if err != nil {
		return "client_vencrypt"
	}
	if !slices.Contains(t.subtypes, sub) {
		t.deny(se.ip, "vnc_subtype_not_offered", rfb.SubtypeName(sub))
		return "subtype_not_offered"
	}
	se.clientSubtype = sub
	if rfb.UsesTLS(sub) {
		// One byte says the handshake follows, then it does.
		if _, err := se.client.Write([]byte{1}); err != nil {
			return "write"
		}
		tc := tls.Server(se.client, t.tlsCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			t.deny(se.ip, "vnc_tls", err.Error())
			return "client_tls"
		}
		se.client = tc
	}
	switch rfb.AuthAfterTLS(sub) {
	case rfb.SecNone:
		return se.finishClientAuth(true, "")
	case rfb.SecVNCAuth:
		return se.clientVNCAuth()
	case rfb.SecPlain:
		return se.clientPlain()
	}
	se.refuseClient("vencrypt_subtype_not_mediated", "that VeNCrypt subtype is not mediated by this gateway")
	return "subtype_unsupported"
}

// clientPlain reads VeNCrypt's plain credentials: a username and a
// password, sent as two lengths and then the two values, inside the
// TLS tunnel.
//
// This is the only place in RFB where a client sends a name. That is
// why a second factor here requires a plain subtype: a DES challenge
// proves knowledge of one shared desktop password and says nothing
// about who is holding it, so there is nothing to look an enrolment up
// by. With plain there is: the username is the person, and the
// password field carries their one-time code.
func (se *session) clientPlain() string {
	user, secret, err := rfb.ReadPlain(se.client, maxCredential)
	if err != nil {
		return "client_auth"
	}
	return se.namedCredential(user, secret)
}

// namedCredential decides on a credential that carries a name: the
// factor where one is configured, and the gateway's own password
// otherwise. VeNCrypt's plain subtype and MS-Logon II both arrive
// here, because both carry the same two fields.
func (se *session) namedCredential(user, secret string) string {
	t := se.t
	se.factorUser, se.factorCode = user, secret
	if t.mfaGuard != nil {
		// The factor is checked here rather than after the handshake,
		// so that a wrong code is answered with a failed security
		// result: a client told its authentication succeeded and then
		// dropped has no way to know why.
		if reason := se.askFactor(); reason != "" {
			se.securityResult(false, "authentication failed")
			return reason
		}
		se.factorDone = true
		return se.finishClientAuth(true, "")
	}
	// No factor configured, so the plain credentials are checked
	// against the gateway's own password, which is the only thing here
	// to check them against.
	if t.password == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(t.password)) != 1 {
		t.engine.Counters().VNCRefused.Add(1)
		t.deny(se.ip, "vnc_auth_failed", textsafe.Clip64(user))
		return se.finishClientAuth(false, "authentication failed")
	}
	se.user = user
	return se.finishClientAuth(true, "")
}

// maxCredential bounds a username or password a client sends.
const maxCredential = 1024

// clientAnonTLS is the older TLS security type (18): anonymous
// Diffie-Hellman, then a second security type inside it. It is offered
// only where an operator asked for it, because nothing is
// authenticated: it stops a reader and not an active attacker.
func (se *session) clientAnonTLS() string {
	t := se.t
	tc := tls.Server(se.client, t.tlsCfg)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		t.deny(se.ip, "vnc_tls", err.Error())
		return "client_tls"
	}
	se.client = tc
	// Inside the tunnel, a second security negotiation.
	inner := []uint8{rfb.SecNone}
	if t.password != "" {
		inner = []uint8{rfb.SecVNCAuth, rfb.SecNone}
	}
	if _, err := se.client.Write(rfb.SecurityList(inner)); err != nil {
		return "write"
	}
	var chosen [1]byte
	if _, err := io.ReadFull(se.client, chosen[:]); err != nil {
		return "client_security"
	}
	if !slices.Contains(inner, chosen[0]) {
		return "security_not_offered"
	}
	if chosen[0] == rfb.SecVNCAuth {
		return se.clientVNCAuth()
	}
	return se.finishClientAuth(true, "")
}

// finishClientAuth sends the security result and says whether the
// handshake goes on.
func (se *session) finishClientAuth(ok bool, reason string) string {
	se.securityResult(ok, reason)
	if !ok {
		return "client_auth_failed"
	}
	return ""
}

func (se *session) securityResult(ok bool, reason string) {
	// Before 3.8 a successful None carries no result at all, so
	// sending one here would put four bytes in front of the ServerInit
	// that such a viewer never reads.
	if ok && !rfb.SendsResult(se.clientVersion, se.clientSec) {
		return
	}
	_, _ = se.client.Write(rfb.SecurityResult(se.clientVersion, ok, reason))
}

// upstreamHandshake plays the client to the target, and answers the
// waiting client's ClientInit with what the target gives.
func (se *session) upstreamHandshake(ci rfb.ClientInit) string {
	t := se.t
	sv, err := rfb.ReadVersion(se.up)
	if err != nil {
		return "upstream_version"
	}
	v, ok := rfb.Negotiated(rfb.V38, sv)
	if !ok {
		return "upstream_version"
	}
	se.upVersion = v
	if _, err := se.up.Write(v.Handshake()); err != nil {
		return "upstream_write"
	}
	// What the target offers, and what of it this gateway will use.
	var offered []uint8
	if v.AtLeast(rfb.V37) {
		offered, err = rfb.ReadSecurityList(se.up)
		if err != nil {
			return "upstream_security"
		}
	} else {
		one, err := rfb.ReadSecurity33(se.up)
		if err != nil {
			return "upstream_security"
		}
		offered = []uint8{one}
	}
	pick, ok := se.pickUpstream(offered)
	if !ok {
		t.engine.Logs().Error.Warn("vnc target offers no security type this gateway uses",
			"listener", t.cfg.Name, "target", se.target, "offered", names(offered))
		return "upstream_security_unusable"
	}
	se.upSec = pick
	if v.AtLeast(rfb.V37) {
		if _, err := se.up.Write([]byte{pick}); err != nil {
			return "upstream_write"
		}
	}
	if reason := se.upstreamAuth(); reason != "" {
		return reason
	}
	// The same rule in the other direction: a pre-3.8 target that
	// asked for nothing sends no result, and waiting for one would
	// hang the session.
	if rfb.SendsResult(v, pick) && !se.upNoResult {
		good, why, err := rfb.ReadSecurityResult(se.up, v)
		if err != nil {
			return "upstream_security"
		}
		if !good {
			t.engine.Logs().Error.Warn("vnc target refused this gateway's credential",
				"listener", t.cfg.Name, "target", se.target, "reason", textsafe.Clip256(why))
			return "upstream_auth_failed"
		}
	}
	// The "ne" type authenticates inside its channel and hands the
	// session back to a cleartext socket once the result is in.
	up, err := leaveChannel(se.up, se.upSec)
	if err != nil {
		return "upstream_auth"
	}
	se.up = up
	// The client's ClientInit, held until now, and the target's answer.
	if _, err := se.up.Write(ci.Encode()); err != nil {
		return "upstream_write"
	}
	si, err := rfb.ReadServerInit(se.up)
	if err != nil {
		return "upstream_init"
	}
	se.si = si
	se.desktop, se.width, se.height = si.Name, si.Width, si.Height
	// The desktop's own size is the first number a viewer allocates
	// from, so it is bounded before it is forwarded: a client that
	// never sees 65535x65535 never makes room for it.
	if err := se.t.px.limits.CheckFramebuffer(si.Width, si.Height); err != nil {
		se.pixelDeny("framebuffer_too_large", err)
		return "framebuffer_too_large"
	}
	if _, err := se.client.Write(si.Encode()); err != nil {
		return "write"
	}
	// Tight puts one more block after ServerInit, on whichever legs
	// negotiated it.
	return se.tightInteraction()
}

// pickUpstream chooses the security type to use towards the target:
// the one an operator named, or the strongest this gateway mediates.
func (se *session) pickUpstream(offered []uint8) (uint8, bool) {
	t := se.t
	if want := t.v.UpstreamSecurity; want != "" {
		if s, ok := rfb.SecurityByName(want); ok && slices.Contains(offered, s) {
			return s, true
		}
		return 0, false
	}
	// Strongest first: an encrypted negotiation beats a bare password,
	// and a password beats nothing at all.
	for _, want := range []uint8{rfb.SecRSAAES256, rfb.SecRSAAES, rfb.SecVeNCrypt,
		rfb.SecVNCAuth, rfb.SecRSAAESne, rfb.SecARD, rfb.SecMSLogon2,
		rfb.SecTight, rfb.SecNone} {
		if !slices.Contains(offered, want) {
			continue
		}
		if want == rfb.SecVNCAuth && t.upPassword == "" {
			continue
		}
		if want == rfb.SecVeNCrypt && t.v.UpstreamTLSMode != "vencrypt" {
			continue
		}
		// MS-Logon II sends a name as well as a password, so it is
		// only usable where an operator gave both.
		if want == rfb.SecMSLogon2 && (t.v.UpstreamUser == "" || t.upPassword == "") {
			continue
		}
		// ARD sends a name as well, like MS-Logon II.
		if want == rfb.SecARD && (t.v.UpstreamUser == "" || t.upPassword == "") {
			continue
		}
		// rsa-aes needs a key of this gateway's own, a credential, and
		// the target's key pinned: nothing else authenticates the far
		// end of that exchange.
		if rfb.RSAAESFamily[want] &&
			(t.rsaKey == nil || t.upPassword == "" || t.v.UpstreamRSAFingerprint == "") {
			continue
		}
		return want, true
	}
	return 0, false
}

// upstreamAuth answers whatever the target asked for.
func (se *session) upstreamAuth() string {
	switch se.upSec {
	case rfb.SecNone:
		return ""
	case rfb.SecVNCAuth:
		return se.upstreamVNCChallenge()
	case rfb.SecVeNCrypt:
		return se.upstreamVeNCrypt()
	case rfb.SecMSLogon2:
		return se.upstreamMSLogon()
	case rfb.SecRSAAES, rfb.SecRSAAESne, rfb.SecRSAAES256:
		return se.upstreamRSAAES()
	case rfb.SecTight:
		return se.upstreamTight()
	case rfb.SecARD:
		return se.upstreamARD()
	}
	return "upstream_security_unusable"
}

// upstreamVeNCrypt negotiates VeNCrypt towards the target.
func (se *session) upstreamVeNCrypt() string {
	t := se.t
	sv, err := rfb.ReadVeNCryptVersion(se.up)
	if err != nil {
		return "upstream_vencrypt"
	}
	if sv.Major != 0 || sv.Minor < 2 {
		return "upstream_vencrypt"
	}
	if _, err := se.up.Write(rfb.VeNCryptVersion(rfb.VeNCrypt02)); err != nil {
		return "upstream_write"
	}
	var ack [1]byte
	if _, err := io.ReadFull(se.up, ack[:]); err != nil || ack[0] != 0 {
		return "upstream_vencrypt"
	}
	subs, err := rfb.ReadSubtypes(se.up)
	if err != nil {
		return "upstream_vencrypt"
	}
	// Prefer a subtype with a certificate to check, then one without.
	var pick uint32
	for _, want := range []uint32{rfb.VeNCryptX509Vnc, rfb.VeNCryptX509None, rfb.VeNCryptTLSVnc, rfb.VeNCryptTLSNone} {
		if slices.Contains(subs, want) {
			if rfb.AuthAfterTLS(want) == rfb.SecVNCAuth && t.upPassword == "" {
				continue
			}
			pick = want
			break
		}
	}
	if pick == 0 {
		return "upstream_vencrypt"
	}
	if _, err := se.up.Write(binaryU32(pick)); err != nil {
		return "upstream_write"
	}
	if rfb.UsesTLS(pick) {
		var go1 [1]byte
		if _, err := io.ReadFull(se.up, go1[:]); err != nil || go1[0] != 1 {
			return "upstream_vencrypt"
		}
		cfg := t.upTLS
		if cfg == nil {
			return "upstream_vencrypt_no_tls"
		}
		tc := tls.Client(se.up, se.upstreamTLSFor(cfg))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			return "upstream_tls"
		}
		se.up = tc
	}
	if rfb.AuthAfterTLS(pick) == rfb.SecVNCAuth {
		challenge := make([]byte, rfb.ChallengeSize)
		if _, err := io.ReadFull(se.up, challenge); err != nil {
			return "upstream_auth"
		}
		resp, err := rfb.VNCAuthResponse(challenge, t.upPassword)
		if err != nil {
			return "upstream_auth"
		}
		if _, err := se.up.Write(resp); err != nil {
			return "upstream_write"
		}
	}
	return ""
}

func binaryU32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// upstreamTLSFor fills in the server name from the endpoint when the
// configuration did not pin one.
func (se *session) upstreamTLSFor(base *tls.Config) *tls.Config {
	tc := base.Clone()
	if tc.ServerName == "" {
		if host, _, err := net.SplitHostPort(se.target); err == nil {
			tc.ServerName = host
		}
	}
	return tc
}

// names renders a security list for a log line.
func names(types []uint8) string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, rfb.SecurityName(t))
	}
	return strings.Join(out, ",")
}
