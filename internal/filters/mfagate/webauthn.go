package mfagate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/webauthn"
)

// A security key beside the one-time code.
//
// A code is a shared secret typed into whatever page asked for it, so a
// convincing copy of that page collects codes that work. WebAuthn does not
// have that failure: the assertion is bound to the origin the ceremony ran
// on, so a look-alike site gets a signature naming its own origin, which
// this refuses. That is the reason to have it, and it is the only reason
// that matters -- everything else about a key is convenience.
//
// The two live side by side rather than one replacing the other. A code is
// how somebody gets in from a machine with no key attached, and it is how a
// key is registered in the first place: registration here requires a factor
// the user already has, because a registration endpoint that trusts only
// the first factor is a way to add a second factor to an account whose
// password has just been stolen.

// maxCeremonyBody bounds a posted ceremony. An assertion is an
// authenticator data blob, a client data JSON and a signature; a few
// kilobytes is generous.
const maxCeremonyBody = 16 << 10

// ceremony is what the page posts back.
type ceremony struct {
	Challenge         string `json:"challenge_id"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
	AttestationObject string `json:"attestation_object"`
	Label             string `json:"label"`
	Next              string `json:"next"`
}

// options is what the page is given to start a ceremony.
type options struct {
	ChallengeID      string   `json:"challenge_id"`
	Challenge        string   `json:"challenge"`
	RPID             string   `json:"rp_id"`
	RPName           string   `json:"rp_name"`
	User             string   `json:"user"`
	UserID           string   `json:"user_id"`
	Credentials      []string `json:"credentials"`
	UserVerification string   `json:"user_verification"`
}

// webauthnOn reports whether this gate has a key policy.
func (g *gate) webauthnOn() bool { return g.keys != nil }

// assertOptions starts an authentication ceremony.
func (in *instance) assertOptions(user string) filter.Verdict {
	g := in.g
	creds := g.keys.Credentials(user)
	if len(creds) == 0 {
		return jsonVerdict(g.name, http.StatusNotFound, map[string]any{"error": "no_credentials"})
	}
	id, value, err := g.challenges.Issue(user)
	if err != nil {
		return jsonVerdict(g.name, http.StatusServiceUnavailable, map[string]any{"error": "unavailable"})
	}
	// The identifiers are listed so a browser can pick the right key
	// without asking the person which one they have. They are public --
	// this is the list every login page carries -- which is why the store
	// looks a credential up by account as well as by identifier.
	list := make([]string, 0, len(creds))
	for _, c := range creds {
		list = append(list, b64(c.ID))
	}
	return jsonVerdict(g.name, http.StatusOK, options{
		ChallengeID: id, Challenge: b64(value), RPID: g.policy.RPID,
		Credentials: list, UserVerification: g.verification(),
	})
}

// registerOptions starts a registration ceremony. It requires a factor
// already verified, which is what keeps this from being a way to bolt a
// second factor onto a freshly stolen password.
func (in *instance) registerOptions(r *http.Request, user string) filter.Verdict {
	g := in.g
	if !in.cookieValid(r, user) {
		return jsonVerdict(g.name, http.StatusUnauthorized, map[string]any{"error": "verify_first"})
	}
	if len(g.keys.Credentials(user)) >= webauthnMaxPerUser {
		return jsonVerdict(g.name, http.StatusConflict, map[string]any{"error": "too_many"})
	}
	id, value, err := g.challenges.Issue(user)
	if err != nil {
		return jsonVerdict(g.name, http.StatusServiceUnavailable, map[string]any{"error": "unavailable"})
	}
	existing := g.keys.Credentials(user)
	list := make([]string, 0, len(existing))
	for _, c := range existing {
		list = append(list, b64(c.ID))
	}
	return jsonVerdict(g.name, http.StatusOK, options{
		ChallengeID: id, Challenge: b64(value), RPID: g.policy.RPID, RPName: g.cfg.Issuer,
		User: user, UserID: b64([]byte(user)), Credentials: list, UserVerification: g.verification(),
	})
}

// webauthnMaxPerUser mirrors the store's bound, so the page can say no
// before a ceremony that would be refused at the end of it.
const webauthnMaxPerUser = 10

// verification is the string a browser expects.
func (g *gate) verification() string {
	if g.policy.UserVerification {
		return "required"
	}
	return "preferred"
}

// assert finishes an authentication ceremony.
func (in *instance) assert(r *http.Request, user string) filter.Verdict {
	g := in.g
	c, err := readCeremony(r)
	if err != nil {
		in.step = "webauthn_bad_body"
		return jsonVerdict(g.name, http.StatusBadRequest, map[string]any{"error": "bad_request"})
	}
	// The challenge is spent before anything is verified: one that
	// survives a failed attempt is an attacker's retry budget.
	challenge, err := g.challenges.Spend(c.Challenge, user)
	if err != nil {
		return in.keyFailed(user, "challenge", err)
	}
	rawID, err := unb64(c.CredentialID)
	if err != nil {
		return in.keyFailed(user, "credential_id", err)
	}
	cred, ok := g.keys.ByID(user, rawID)
	if !ok {
		// The identifier is not this account's. One message for every
		// failure: telling an unknown key from a wrong signature is how an
		// attacker learns which identifiers are worth trying.
		return in.keyFailed(user, "unknown_credential", errors.New("no such credential"))
	}
	ad, err1 := unb64(c.AuthenticatorData)
	cd, err2 := unb64(c.ClientDataJSON)
	sig, err3 := unb64(c.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		return in.keyFailed(user, "encoding", errors.New("a field is not base64url"))
	}
	count, err := g.policy.Assertion(cred, ad, cd, sig, challenge)
	if err != nil {
		return in.keyFailed(user, "assertion", err)
	}
	// The count is written before the cookie is issued. A count that is
	// not stored is a clone check that passes next time, so a store that
	// cannot be written is a refusal rather than a login.
	if err := g.keys.Touch(cred.ID, count); err != nil {
		g.log.Error("webauthn sign count could not be recorded", "filter", g.name, "user", user, "err", err.Error())
		return jsonVerdict(g.name, http.StatusServiceUnavailable, map[string]any{"error": "unavailable"})
	}
	g.verified.Add(1)
	in.step = "webauthn"
	filter.SetIdentity(r.Context(), "mfa", user)
	next := c.Next
	if !safeNext(next) {
		next = "/"
	}
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	body, _ := json.Marshal(map[string]any{"ok": true, "next": next})
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Add("Set-Cookie", in.cookie(user).String())
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusOK, Reason: g.name,
		Detail: "mfa_verified", Response: resp}
}

// register finishes a registration ceremony.
func (in *instance) register(r *http.Request, user string) filter.Verdict {
	g := in.g
	// Checked again here and not only when the options were handed out: a
	// client can post straight to this endpoint.
	if !in.cookieValid(r, user) {
		return jsonVerdict(g.name, http.StatusUnauthorized, map[string]any{"error": "verify_first"})
	}
	c, err := readCeremony(r)
	if err != nil {
		return jsonVerdict(g.name, http.StatusBadRequest, map[string]any{"error": "bad_request"})
	}
	challenge, err := g.challenges.Spend(c.Challenge, user)
	if err != nil {
		return in.keyFailed(user, "challenge", err)
	}
	att, err1 := unb64(c.AttestationObject)
	cd, err2 := unb64(c.ClientDataJSON)
	if err1 != nil || err2 != nil {
		return in.keyFailed(user, "encoding", errors.New("a field is not base64url"))
	}
	reg, err := g.policy.Register(att, cd, challenge)
	if err != nil {
		return in.keyFailed(user, "registration", err)
	}
	label := strings.TrimSpace(c.Label)
	if len(label) > 64 || strings.ContainsAny(label, ":\r\n") {
		label = ""
	}
	if err := g.keys.Add(webauthn.Credential{User: user, ID: reg.CredentialID,
		PublicKey: reg.PublicKey, SignCount: reg.SignCount, Label: label}); err != nil {
		g.log.Warn("webauthn credential could not be stored", "filter", g.name, "user", user, "err", err.Error())
		return jsonVerdict(g.name, http.StatusConflict, map[string]any{"error": "not_stored"})
	}
	g.log.Info("webauthn credential registered", "filter", g.name, "user", user,
		"credential", b64(reg.CredentialID), "label", label, "user_verified", reg.UserVerified)
	return jsonVerdict(g.name, http.StatusOK, map[string]any{"ok": true})
}

// keyFailed answers a refused ceremony. One message for every cause, and
// the detail only in the log: which step refused a key is exactly what an
// attacker is probing for.
func (in *instance) keyFailed(user, where string, err error) filter.Verdict {
	g := in.g
	g.failed.Add(1)
	in.step = "webauthn_failed"
	g.log.Warn("webauthn ceremony refused", "filter", g.name, "user", user, "step", where, "err", err.Error())
	return jsonVerdict(g.name, http.StatusUnauthorized, map[string]any{"error": "not_accepted"})
}

// readCeremony reads a posted ceremony.
func readCeremony(r *http.Request) (ceremony, error) {
	var c ceremony
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCeremonyBody+1))
	_ = r.Body.Close()
	if err != nil {
		return c, err
	}
	if len(body) > maxCeremonyBody {
		return c, fmt.Errorf("ceremony larger than %d bytes", maxCeremonyBody)
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, err
	}
	return c, nil
}

// jsonVerdict answers with a small JSON document and no security event:
// these are the steps of a login, not refusals of a request.
func jsonVerdict(name string, status int, v any) filter.Verdict {
	body, _ := json.Marshal(v)
	resp := &http.Response{StatusCode: status, Header: http.Header{},
		Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body))}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return filter.Verdict{Deny: true, Silent: true, Status: status, Reason: name,
		Detail: "mfa_webauthn", Response: resp}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64 decodes base64url with or without padding, because browsers and
// libraries disagree about which they produce.
func unb64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// keyScript is the page's half of both ceremonies. It is plain and small
// on purpose: a login page that needs a framework is a login page that
// fails when the framework does not load.
const keyScript = `
<script>
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const raw = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
async function options(kind){
  const r = await fetch('?xproxy_mfa='+kind, {method:'POST', headers:{'Accept':'application/json'}});
  if(!r.ok) throw new Error(kind);
  return r.json();
}
async function useKey(next){
  const o = await options('webauthn-options');
  const a = await navigator.credentials.get({publicKey:{
    challenge: raw(o.challenge), rpId: o.rp_id, timeout: 60000,
    userVerification: o.user_verification,
    allowCredentials: o.credentials.map(id => ({type:'public-key', id: raw(id)}))}});
  const r = await fetch('?xproxy_mfa=webauthn', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({challenge_id:o.challenge_id, credential_id:b64(a.rawId),
      authenticator_data:b64(a.response.authenticatorData), client_data_json:b64(a.response.clientDataJSON),
      signature:b64(a.response.signature), next:next})});
  const out = await r.json();
  if(out.ok){ location.href = out.next; return; }
  throw new Error(out.error||'refused');
}
async function addKey(label){
  const o = await options('webauthn-register-options');
  const c = await navigator.credentials.create({publicKey:{
    challenge: raw(o.challenge), rp:{id:o.rp_id, name:o.rp_name},
    user:{id: raw(o.user_id), name:o.user, displayName:o.user}, timeout: 60000,
    pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-8},{type:'public-key',alg:-257}],
    authenticatorSelection:{userVerification:o.user_verification, residentKey:'discouraged'},
    attestation:'none', excludeCredentials:o.credentials.map(id=>({type:'public-key',id:raw(id)}))}});
  const r = await fetch('?xproxy_mfa=webauthn-register', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({challenge_id:o.challenge_id, attestation_object:b64(c.response.attestationObject),
      client_data_json:b64(c.response.clientDataJSON), label:label})});
  const out = await r.json();
  if(!out.ok) throw new Error(out.error||'refused');
}
</script>`

// keyButton is the part of the challenge page that offers a key.
func keyButton(next string) string {
	return `<p><button type="button" id="usekey">Use a security key</button></p>` + keyScript +
		`<script>document.getElementById('usekey').addEventListener('click', () => ` +
		`useKey(` + jsString(next) + `).catch(e => { document.getElementById('usekey').textContent = 'Key not accepted'; }));</script>`
}

// jsString quotes a value for a script. The value is a path this proxy
// already checked with safeNext, and it is quoted anyway: a page that
// interpolates without quoting is one input away from being somebody
// else's script.
func jsString(s string) string {
	b, _ := json.Marshal(s)
	// A closing script tag inside a JSON string still ends the element,
	// so the slash is escaped as well.
	return strings.ReplaceAll(string(b), "/", `\/`)
}

// webauthnEndpoint names the ceremony a request is asking for, or "".
func webauthnEndpoint(r *http.Request) string {
	switch r.URL.Query().Get("xproxy_mfa") {
	case "webauthn-options":
		return "options"
	case "webauthn":
		return "assert"
	case "webauthn-register-options":
		return "register-options"
	case "webauthn-register":
		return "register"
	}
	return ""
}

// challengeTTL is how long a ceremony may take. A person reaching for a
// key on a lanyard takes a while; an hour is somebody else's session.
const challengeTTL = 3 * time.Minute
