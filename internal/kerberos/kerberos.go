// Package kerberos reads the Kerberos messages a KDC proxy carries (RFC
// 4120) and the envelope that carries them over HTTP (MS-KKDCP, and the
// KDC-PROXY-MESSAGE it defines).
//
// A KDC proxy exists because Kerberos is a UDP and TCP protocol on port
// 88 and the places people work from are not on the network the KDC is
// on. So a client POSTs its AS-REQ to an HTTPS endpoint, the proxy
// unwraps it, speaks TCP to the KDC, and wraps the answer back. Windows
// has shipped the client since 2012 and calls it the Kerberos Key
// Distribution Center Proxy; MIT and Heimdal both speak it.
//
// That makes a KDC proxy an unusual thing to put a policy in front of,
// and an unusually valuable one, for three reasons.
//
// **It is the one place an estate's Kerberos traffic is inspectable.**
// Everything interesting about a Kerberos request is in the clear: which
// realm, which client principal, which service principal, which
// encryption types the client will accept, and which pre-authentication
// it brought. Those are the fields the KDC itself decides on, and they
// are readable because they have to be -- they are how the two ends agree
// what to encrypt. What is encrypted is the ticket and the reply's
// enc-part, and no policy worth writing needs those.
//
// **The interesting attacks on Kerberos are visible in those fields.**
// Asking for an RC4 service ticket is Kerberoasting. An AS-REP that
// arrives for a request that carried no pre-authentication is
// AS-REP-roasting, and the KDC answering one means the account is
// exempt. A TGS-REQ carrying PA-FOR-USER is S4U2Self, and one carrying
// the constrained-delegation option with an additional ticket is
// S4U2Proxy -- the two primitives behind most delegation abuse. A run of
// KDC_ERR_PREAUTH_FAILED is password spraying. None of that needs a
// decrypted packet; it needs a reader.
//
// **A proxy that does not police the realm is an open relay.** The
// envelope carries a target domain and the inner message carries a realm,
// and a proxy that forwards whatever it is handed will relay Kerberos for
// realms that are not the estate's -- to KDCs that are not the estate's,
// from the estate's own address.
//
// What this package does not do is decrypt, mint or verify anything. It
// has no keys. It reads the plaintext fields of the six message types a
// proxy carries and reports what it found; internal/kinds/kkdcp decides.
package kerberos

import (
	"strconv"
	"strings"
)

// MsgType is a Kerberos message type: the application tag and the
// msg-type field, which agree in every well-formed message.
type MsgType int

// The message types a KDC proxy carries. There are more in RFC 4120 --
// the safe and private application messages, the credential forwarding
// message -- but they do not go to a KDC, so a proxy that saw one would
// be carrying something that is not its business.
const (
	MsgASReq  MsgType = 10
	MsgASRep  MsgType = 11
	MsgTGSReq MsgType = 12
	MsgTGSRep MsgType = 13
	// MsgAPReq is not a KDC message, but it reaches a password-changing
	// proxy: the kpasswd protocol of RFC 3244 wraps an AP-REQ, and a
	// listener that carries password changes has to read far enough to
	// know what it is carrying.
	MsgAPReq MsgType = 14
	MsgError MsgType = 30
)

var msgNames = map[MsgType]string{
	MsgASReq: "as-req", MsgASRep: "as-rep", MsgTGSReq: "tgs-req",
	MsgTGSRep: "tgs-rep", MsgAPReq: "ap-req", MsgError: "krb-error",
}

func (m MsgType) String() string {
	if n, ok := msgNames[m]; ok {
		return n
	}
	return "msg-type(" + strconv.Itoa(int(m)) + ")"
}

// Known says whether this is a type this package reads.
func (m MsgType) Known() bool { _, ok := msgNames[m]; return ok }

// Request says whether a client sends this towards a KDC.
func (m MsgType) Request() bool {
	return m == MsgASReq || m == MsgTGSReq || m == MsgAPReq
}

// MsgTypeOf reads a message type from the name a rule is written with.
func MsgTypeOf(s string) (MsgType, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	for m, n := range msgNames {
		if n == k {
			return m, true
		}
	}
	switch k {
	case "as", "asreq":
		return MsgASReq, true
	case "tgs", "tgsreq":
		return MsgTGSReq, true
	case "ap", "apreq", "kpasswd":
		return MsgAPReq, true
	}
	return 0, false
}

// MsgTypeNames are the request types a rule may name, sorted. Only the
// requests: a rule naming a reply would be a rule about something the KDC
// chose, and those are separate settings.
func MsgTypeNames() []string { return []string{"as-req", "ap-req", "tgs-req"} }

// EType is an encryption type number (RFC 3961's etype registry).
type EType int32

// The encryption types an estate's traffic uses, and the ones it should
// not.
const (
	ETypeDESCBCCRC  EType = 1
	ETypeDESCBCMD4  EType = 2
	ETypeDESCBCMD5  EType = 3
	ETypeDES3CBCMD5 EType = 5
	ETypeDES3SHA1   EType = 16
	ETypeAES128SHA1 EType = 17
	ETypeAES256SHA1 EType = 18
	// ETypeAES128SHA256 and ETypeAES256SHA384 are RFC 8009's, which are
	// what a current estate should be issuing.
	ETypeAES128SHA256 EType = 19
	ETypeAES256SHA384 EType = 20
	// ETypeRC4HMAC is RFC 4757's arcfour-hmac-md5. It is the type
	// Kerberoasting asks for, because an RC4 service ticket's encrypted
	// part is crackable offline against the service account's NT hash at
	// a speed an aes256 one is not. Microsoft has disabled it by default
	// since Windows 11 24H2 and it remains configured in most estates.
	ETypeRC4HMAC     EType = 23
	ETypeRC4HMACExp  EType = 24
	ETypeCamellia128 EType = 25
	ETypeCamellia256 EType = 26
)

var etypeNames = map[EType]string{
	ETypeDESCBCCRC: "des-cbc-crc", ETypeDESCBCMD4: "des-cbc-md4",
	ETypeDESCBCMD5: "des-cbc-md5", ETypeDES3CBCMD5: "des3-cbc-md5",
	ETypeDES3SHA1: "des3-cbc-sha1", ETypeAES128SHA1: "aes128-cts-hmac-sha1-96",
	ETypeAES256SHA1:   "aes256-cts-hmac-sha1-96",
	ETypeAES128SHA256: "aes128-cts-hmac-sha256-128",
	ETypeAES256SHA384: "aes256-cts-hmac-sha384-192",
	ETypeRC4HMAC:      "rc4-hmac", ETypeRC4HMACExp: "rc4-hmac-exp",
	ETypeCamellia128: "camellia128-cts-cmac", ETypeCamellia256: "camellia256-cts-cmac",
}

func (e EType) String() string {
	if n, ok := etypeNames[e]; ok {
		return n
	}
	return "etype(" + strconv.FormatInt(int64(e), 10) + ")"
}

// Weak reports whether an encryption type is one no estate should be
// issuing tickets in.
//
// Two groups. Single DES and the triple-DES variants are broken or
// obsolete and nothing has needed them this century. RC4-HMAC is the
// Kerberoasting type: its key is the account's NT hash with no salt and
// no iteration, so a service ticket encrypted in it is an offline
// password-cracking target the moment anybody who can ask for one asks.
func (e EType) Weak() bool {
	switch e {
	case ETypeDESCBCCRC, ETypeDESCBCMD4, ETypeDESCBCMD5, ETypeDES3CBCMD5,
		ETypeDES3SHA1, ETypeRC4HMAC, ETypeRC4HMACExp:
		return true
	}
	return false
}

// ETypeOf reads an encryption type from the name a rule is written with,
// or from its number -- the registry is longer than this list and a policy
// about a type this package has no name for is still a policy.
func ETypeOf(s string) (EType, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	for e, n := range etypeNames {
		if n == k {
			return e, true
		}
	}
	switch k {
	case "aes128":
		return ETypeAES128SHA1, true
	case "aes256":
		return ETypeAES256SHA1, true
	case "rc4", "arcfour", "arcfour-hmac-md5":
		return ETypeRC4HMAC, true
	}
	if n, err := strconv.ParseInt(k, 10, 32); err == nil {
		return EType(n), true
	}
	return 0, false
}

// ETypeNames are the types this package names, sorted.
func ETypeNames() []string {
	out := make([]string, 0, len(etypeNames))
	for _, n := range etypeNames {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// WeakETypes are the weak ones by name, sorted, for the message that says
// what a default refuses.
func WeakETypes() []string {
	out := make([]string, 0, 8)
	for e, n := range etypeNames {
		if e.Weak() {
			out = append(out, n)
		}
	}
	sortStrings(out)
	return out
}

// PAType is a pre-authentication data type.
type PAType int32

// The pre-authentication types a policy is written about.
const (
	// PATGSReq is the ticket-granting ticket a TGS-REQ proves itself
	// with: its presence is what makes a request a TGS request in
	// substance as well as in message type.
	PATGSReq PAType = 1
	// PAEncTimestamp is the encrypted timestamp of RFC 4120 §5.2.7.2: the
	// client proving it knows the password before the KDC hands out
	// anything encrypted in a key derived from it. An AS exchange that
	// completes *without* one is the pre-authentication exemption behind
	// AS-REP roasting.
	PAEncTimestamp PAType = 2
	PAPWSalt       PAType = 3
	PAETypeInfo    PAType = 11
	// PAPKASReq is PKINIT (RFC 4556): a certificate instead of a
	// password. Stronger authentication, and the mechanism behind the
	// certificate-based attacks on AD -- so it is counted rather than
	// refused.
	PAPKASReq    PAType = 16
	PAPKASRep    PAType = 17
	PAETypeInfo2 PAType = 19
	// PAFXFast is RFC 6113's armoured channel, which wraps the whole
	// request. A relay reading one sees the armour and not what is
	// inside; that limit is documented rather than worked around.
	PAFXFast   PAType = 136
	PAFXError  PAType = 137
	PAFXCookie PAType = 133
	// PAEncryptedChallenge is FAST's own pre-authentication, RFC 6113
	// §5.4.6: the armoured equivalent of an encrypted timestamp.
	PAEncryptedChallenge PAType = 138
	// PAPACRequest is MS-KILE's: whether the client wants a PAC in its
	// ticket.
	PAPACRequest PAType = 128
	// PAForUser is S4U2Self (MS-SFU §2.2.1): a service asking the KDC for
	// a ticket to itself *as another user*, naming that user in the
	// clear. It is how a compromised service account becomes any user in
	// the realm where the account has the right to ask.
	PAForUser PAType = 129
	// PAPACOptions carries MS-SFU's resource-based constrained
	// delegation flag, which is the half of S4U2Proxy that does not need
	// the service to be trusted for delegation.
	PAPACOptions PAType = 167
	// PASupportedETypes is MS-KILE's advertisement of what the account
	// supports.
	PASupportedETypes PAType = 165
)

var paNames = map[PAType]string{
	PATGSReq: "tgs-req", PAEncTimestamp: "enc-timestamp", PAPWSalt: "pw-salt",
	PAETypeInfo: "etype-info", PAPKASReq: "pk-as-req", PAPKASRep: "pk-as-rep",
	PAETypeInfo2: "etype-info2", PAFXFast: "fx-fast", PAFXError: "fx-error",
	PAFXCookie: "fx-cookie", PAEncryptedChallenge: "encrypted-challenge",
	PAPACRequest: "pac-request", PAForUser: "for-user",
	PAPACOptions: "pac-options", PASupportedETypes: "supported-etypes",
}

func (p PAType) String() string {
	if n, ok := paNames[p]; ok {
		return n
	}
	return "padata(" + strconv.FormatInt(int64(p), 10) + ")"
}

// Preauth reports whether a pre-authentication type proves the client
// knew a credential.
//
// The three that do: the encrypted timestamp, FAST's encrypted
// challenge, and a PKINIT request. A relay reads this on the *reply* leg
// to decide whether a completed AS exchange was pre-authenticated, which
// is the only place that question can be answered -- a bare AS-REQ is a
// normal first message, and what matters is whether the KDC answered one
// with a ticket.
func (p PAType) Preauth() bool {
	switch p {
	case PAEncTimestamp, PAEncryptedChallenge, PAPKASReq:
		return true
	}
	return false
}

// Options is a KDCOptions bit field, read as a big-endian word with bit 0
// the most significant bit -- which is how RFC 4120 §5.4.1 numbers them.
type Options uint32

// The option bits a policy is written about. Written as shifts from bit 0
// so each line reads the way the standard's table does.
const (
	OptForwardable     Options = 1 << (31 - 1)
	OptForwarded       Options = 1 << (31 - 2)
	OptProxiable       Options = 1 << (31 - 3)
	OptProxy           Options = 1 << (31 - 4)
	OptAllowPostdate   Options = 1 << (31 - 5)
	OptPostdated       Options = 1 << (31 - 6)
	OptRenewable       Options = 1 << (31 - 8)
	OptOptHardwareAuth Options = 1 << (31 - 11)
	// OptConstrainedDelegation is bit 14. RFC 4120 reserves it; MS-SFU
	// §2.2.2 uses it as cname-in-addl-tkt, and a TGS-REQ carrying it with
	// an additional ticket is S4U2Proxy: a service presenting a user's
	// ticket to itself and asking for a ticket to a third service as that
	// user.
	OptConstrainedDelegation Options = 1 << (31 - 14)
	// OptCanonicalize asks the KDC to rewrite the principal name, which
	// is ordinary in a realm with name aliases.
	OptCanonicalize Options = 1 << (31 - 15)
	// OptRequestAnonymous asks for a ticket for the anonymous principal
	// (RFC 8062). A proxy carrying one is carrying authentication with no
	// identity in it.
	OptRequestAnonymous      Options = 1 << (31 - 16)
	OptDisableTransitedCheck Options = 1 << (31 - 26)
	OptRenewableOK           Options = 1 << (31 - 27)
	// OptEncTktInSkey is the user-to-user option: the reply's ticket is
	// encrypted in the session key of a second ticket rather than in a
	// service's long-term key.
	OptEncTktInSkey Options = 1 << (31 - 28)
	OptRenew        Options = 1 << (31 - 30)
	// OptValidate is bit 31, the last of the field, so the shift this
	// list is written with -- 1 << (31 - n) -- is 1 << 0 here, and is
	// written that way because the general form would read as a mistake.
	OptValidate Options = 1 << 0
)

var optionNames = []struct {
	bit  Options
	name string
}{
	{OptForwardable, "forwardable"}, {OptForwarded, "forwarded"},
	{OptProxiable, "proxiable"}, {OptProxy, "proxy"},
	{OptAllowPostdate, "allow-postdate"}, {OptPostdated, "postdated"},
	{OptRenewable, "renewable"}, {OptOptHardwareAuth, "opt-hardware-auth"},
	{OptConstrainedDelegation, "constrained-delegation"},
	{OptCanonicalize, "canonicalize"}, {OptRequestAnonymous, "request-anonymous"},
	{OptDisableTransitedCheck, "disable-transited-check"},
	{OptRenewableOK, "renewable-ok"}, {OptEncTktInSkey, "enc-tkt-in-skey"},
	{OptRenew, "renew"}, {OptValidate, "validate"},
}

// Has reports whether an option is set.
func (o Options) Has(bit Options) bool { return o&bit != 0 }

// Names are the options set, in the standard's own order, for a log line.
func (o Options) Names() []string {
	var out []string
	for _, n := range optionNames {
		if o.Has(n.bit) {
			out = append(out, n.name)
		}
	}
	return out
}

func (o Options) String() string {
	if n := o.Names(); len(n) > 0 {
		return strings.Join(n, ",")
	}
	return "none"
}

// OptionOf reads an option from the name a rule is written with.
func OptionOf(s string) (Options, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	for _, n := range optionNames {
		if n.name == k {
			return n.bit, true
		}
	}
	return 0, false
}

// OptionNames are the options a rule may name, sorted.
func OptionNames() []string {
	out := make([]string, 0, len(optionNames))
	for _, n := range optionNames {
		out = append(out, n.name)
	}
	sortStrings(out)
	return out
}

// Error codes from RFC 4120 §7.5.9, the ones a relay counts.
const (
	KDCErrClientUnknown   int32 = 6
	KDCErrServerUnknown   int32 = 7
	KDCErrPolicy          int32 = 12
	KDCErrClientRevoked   int32 = 18
	KDCErrKeyExpired      int32 = 23
	KDCErrPreauthFailed   int32 = 24
	KDCErrPreauthRequired int32 = 25
	KDCErrTicketExpired   int32 = 32
	KDCErrSkew            int32 = 37
	KDCErrWrongRealm      int32 = 68
	KDCErrETypeNoSupp     int32 = 14
)

var errorNames = map[int32]string{
	KDCErrClientUnknown:   "client-principal-unknown",
	KDCErrServerUnknown:   "server-principal-unknown",
	KDCErrPolicy:          "policy",
	KDCErrClientRevoked:   "client-revoked",
	KDCErrKeyExpired:      "key-expired",
	KDCErrPreauthFailed:   "preauth-failed",
	KDCErrPreauthRequired: "preauth-required",
	KDCErrTicketExpired:   "ticket-expired",
	KDCErrSkew:            "clock-skew",
	KDCErrWrongRealm:      "wrong-realm",
	KDCErrETypeNoSupp:     "etype-not-supported",
}

// ErrorName names an error code, or renders the number.
func ErrorName(code int32) string {
	if n, ok := errorNames[code]; ok {
		return n
	}
	return "krb-err(" + strconv.FormatInt(int64(code), 10) + ")"
}

// Principal name types from RFC 4120 §6.2.
const (
	NTUnknown    int32 = 0
	NTPrincipal  int32 = 1
	NTSrvInst    int32 = 2
	NTSrvHst     int32 = 3
	NTSrvXHst    int32 = 4
	NTEnterprise int32 = 10
)

// Principal is a PrincipalName: a type and its components.
type Principal struct {
	Type  int32
	Parts []string
}

// String renders a principal the way Kerberos tooling writes one:
// components joined by a slash. The realm is not included, because a
// principal name in a message does not carry one -- the realm is a
// separate field, and joining them here would invent a name the message
// does not contain.
func (p Principal) String() string { return strings.Join(p.Parts, "/") }

// Service is the first component, which for a service principal is the
// service class: host, HTTP, MSSQLSvc, cifs, ldap.
func (p Principal) Service() string {
	if len(p.Parts) == 0 {
		return ""
	}
	return p.Parts[0]
}

// Empty says there are no components, which a well-formed name never has.
func (p Principal) Empty() bool { return len(p.Parts) == 0 }

// IsKrbtgt reports whether this names the ticket-granting service, which
// is what an AS exchange asks for and what a TGS-REQ for a *different*
// realm's krbtgt asks for when it is crossing a trust.
func (p Principal) IsKrbtgt() bool {
	return len(p.Parts) > 0 && strings.EqualFold(p.Parts[0], "krbtgt")
}

// sortStrings is an insertion sort, so the name tables here need no
// import of sort.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
