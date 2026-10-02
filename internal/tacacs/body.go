package tacacs

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// The bodies. Each exchange has a request body and a reply body, every
// variable field's length is declared ahead of it, and nothing is
// NUL-terminated -- so every parse here is the same three steps: read the
// fixed octets, check that the declared lengths add up to exactly the
// body, then cut the fields out.
//
// "Exactly" is the part worth stating. A body with octets after its last
// declared field is refused rather than ignored, because two readers that
// disagree about where a body ends disagree about what is in it: the
// trailing octets are either a field this reader has mis-sized or
// something somebody put there for the server to read and the relay not
// to. Neither is forwarded.

// maxArgs bounds the argument count a body may declare. RFC 8907's
// arg_cnt is one octet, so 255 is the protocol's own bound and this is
// the same number stated where the allocation happens.
const maxArgs = 255

// AuthenAction is what an authentication session is for.
type AuthenAction uint8

// RFC 8907 §5.1's three actions.
const (
	ActionLogin AuthenAction = 0x01
	// ActionChangePass changes the user's password on the server. It is
	// a credential operation rather than a login, and an estate that
	// does password changes somewhere else has no reason to carry it.
	ActionChangePass AuthenAction = 0x02
	// ActionSendAuth is the outbound authentication of RFC 8907 §5.4.3:
	// the device asking the server for a credential to send *onwards*,
	// to a peer. It hands a secret to whatever asked, it exists for CHAP
	// and PAP outbound on dial links, and in a modern estate a request
	// for one is either dead configuration or somebody extracting
	// credentials from the TACACS+ server.
	ActionSendAuth AuthenAction = 0x04
)

var actionNames = map[AuthenAction]string{
	ActionLogin: "login", ActionChangePass: "change-password",
	ActionSendAuth: "send-auth",
}

func (a AuthenAction) String() string {
	if n, ok := actionNames[a]; ok {
		return n
	}
	return "action(" + strconv.Itoa(int(a)) + ")"
}

// Known says whether this is an action the standard defines.
func (a AuthenAction) Known() bool { _, ok := actionNames[a]; return ok }

// AuthenType is the credential shape an authentication session uses.
type AuthenType uint8

// RFC 8907 §5.1's authentication types.
const (
	// AuthenASCII is the interactive login: the device prompts, and the
	// password arrives in a CONTINUE packet's user_msg, in the clear
	// inside the obfuscation. Anybody holding the key reads it.
	AuthenASCII AuthenType = 0x01
	// AuthenPAP carries the password in the START packet's data, with the
	// same consequence in one round trip instead of three.
	AuthenPAP AuthenType = 0x02
	// AuthenCHAP is a challenge and an MD5 response, which requires the
	// server to hold the password reversibly.
	AuthenCHAP AuthenType = 0x03
	// AuthenARAP is Apple's, from 1990, and is removed in RFC 8907.
	AuthenARAP AuthenType = 0x04
	// AuthenMSCHAP and AuthenMSCHAPv2 derive from NT hashes; version 1 is
	// broken outright.
	AuthenMSCHAP   AuthenType = 0x05
	AuthenMSCHAPv2 AuthenType = 0x06
)

var authenTypeNames = map[AuthenType]string{
	AuthenASCII: "ascii", AuthenPAP: "pap", AuthenCHAP: "chap",
	AuthenARAP: "arap", AuthenMSCHAP: "mschap", AuthenMSCHAPv2: "mschapv2",
}

func (a AuthenType) String() string {
	if n, ok := authenTypeNames[a]; ok {
		return n
	}
	return "authen-type(" + strconv.Itoa(int(a)) + ")"
}

// Known says whether this is a type the standard defines.
func (a AuthenType) Known() bool { _, ok := authenTypeNames[a]; return ok }

// Plaintext reports whether this type puts the password itself into the
// body, where the key holder reads it. It is true of exactly the two
// interactive forms, and it is the reading behind
// refuse_plaintext_passwords.
func (a AuthenType) Plaintext() bool { return a == AuthenASCII || a == AuthenPAP }

// AuthenTypeOf reads a type from the name a rule is written with.
func AuthenTypeOf(s string) (AuthenType, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	for t, n := range authenTypeNames {
		if n == k {
			return t, true
		}
	}
	switch k {
	case "ms-chap":
		return AuthenMSCHAP, true
	case "ms-chapv2":
		return AuthenMSCHAPv2, true
	}
	return 0, false
}

// AuthenTypeNames are the types a rule may name, sorted.
func AuthenTypeNames() []string {
	out := make([]string, 0, len(authenTypeNames))
	for _, n := range authenTypeNames {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// AuthenService is what the authentication is for: which part of the
// device the user is reaching.
type AuthenService uint8

// RFC 8907 §5.1's services.
const (
	ServiceNone AuthenService = 0x00
	// ServiceLogin is a login to the device: the thing an administrator
	// does.
	ServiceLogin AuthenService = 0x01
	// ServiceEnable is the privilege escalation inside an existing
	// session -- `enable` on a Cisco device -- and it is a separate
	// decision from the login, which is why it is a separate service.
	ServiceEnable AuthenService = 0x02
	ServicePPP    AuthenService = 0x03
	ServicePT     AuthenService = 0x05
	// ServiceRCmd is rcmd: a command run on the device without a login
	// session, which is how scripted configuration reaches a lot of
	// equipment.
	ServiceRCmd    AuthenService = 0x06
	ServiceX25     AuthenService = 0x07
	ServiceNASI    AuthenService = 0x08
	ServiceFWProxy AuthenService = 0x09
)

var serviceNames = map[AuthenService]string{
	ServiceNone: "none", ServiceLogin: "login", ServiceEnable: "enable",
	ServicePPP: "ppp", ServicePT: "pt", ServiceRCmd: "rcmd",
	ServiceX25: "x25", ServiceNASI: "nasi", ServiceFWProxy: "fwproxy",
}

func (s AuthenService) String() string {
	if n, ok := serviceNames[s]; ok {
		return n
	}
	return "service(" + strconv.Itoa(int(s)) + ")"
}

// Known says whether this is a service the standard defines.
func (s AuthenService) Known() bool { _, ok := serviceNames[s]; return ok }

// ServiceOf reads a service from the name a rule is written with.
func ServiceOf(str string) (AuthenService, bool) {
	k := strings.ToLower(strings.TrimSpace(str))
	for s, n := range serviceNames {
		if n == k {
			return s, true
		}
	}
	return 0, false
}

// ServiceNames are the services a rule may name, sorted.
func ServiceNames() []string {
	out := make([]string, 0, len(serviceNames))
	for _, n := range serviceNames {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// AuthenMethod is how the user was authenticated, as an authorization or
// accounting request reports it.
type AuthenMethod uint8

// RFC 8907 §6.1's methods.
const (
	MethodNotSet AuthenMethod = 0x00
	// MethodNone means the device authenticated nobody: the request is
	// authorisation for an unauthenticated user. On a device
	// administration listener that is the whole attack in one octet, and
	// it is why a relay reads this field at all.
	MethodNone       AuthenMethod = 0x01
	MethodKRB5       AuthenMethod = 0x02
	MethodLine       AuthenMethod = 0x03
	MethodEnable     AuthenMethod = 0x04
	MethodLocal      AuthenMethod = 0x05
	MethodTACACSPlus AuthenMethod = 0x06
	MethodGuest      AuthenMethod = 0x08
	MethodRADIUS     AuthenMethod = 0x10
	MethodKRB4       AuthenMethod = 0x11
	MethodRCmd       AuthenMethod = 0x20
)

var methodNames = map[AuthenMethod]string{
	MethodNotSet: "not-set", MethodNone: "none", MethodKRB5: "krb5",
	MethodLine: "line", MethodEnable: "enable", MethodLocal: "local",
	MethodTACACSPlus: "tacacsplus", MethodGuest: "guest",
	MethodRADIUS: "radius", MethodKRB4: "krb4", MethodRCmd: "rcmd",
}

func (m AuthenMethod) String() string {
	if n, ok := methodNames[m]; ok {
		return n
	}
	return "method(" + strconv.Itoa(int(m)) + ")"
}

// Known says whether this is a method the standard defines.
func (m AuthenMethod) Known() bool { _, ok := methodNames[m]; return ok }

// Unauthenticated reports whether a method means the device did not
// establish who the user is: not-set, none, guest, or the line password
// -- which is a password on the port rather than on a person.
func (m AuthenMethod) Unauthenticated() bool {
	switch m {
	case MethodNotSet, MethodNone, MethodGuest, MethodLine:
		return true
	}
	return false
}

// MethodOf reads a method from the name a rule is written with.
func MethodOf(s string) (AuthenMethod, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	for m, n := range methodNames {
		if n == k {
			return m, true
		}
	}
	if k == "tacacs+" || k == "tacacs" {
		return MethodTACACSPlus, true
	}
	return 0, false
}

// MethodNames are the methods a rule may name, sorted.
func MethodNames() []string {
	out := make([]string, 0, len(methodNames))
	for _, n := range methodNames {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}

// AuthenStatus is a reply's status.
type AuthenStatus uint8

// RFC 8907 §5.2's statuses.
const (
	AuthenPass    AuthenStatus = 0x01
	AuthenFail    AuthenStatus = 0x02
	AuthenGetData AuthenStatus = 0x03
	AuthenGetUser AuthenStatus = 0x04
	AuthenGetPass AuthenStatus = 0x05
	AuthenRestart AuthenStatus = 0x06
	AuthenError   AuthenStatus = 0x07
	// AuthenFollow redirects the client to a different server, and the
	// reply's data field carries that server's address, port and *key*.
	// It is a server-chosen redirect to an arbitrary host, authenticated
	// by nothing but the obfuscation, and a client that follows one sends
	// the next credential there. RFC 8907 §5.2 deprecates it and says a
	// client should treat it as a failure.
	AuthenFollow AuthenStatus = 0x21
)

var authenStatusNames = map[AuthenStatus]string{
	AuthenPass: "pass", AuthenFail: "fail", AuthenGetData: "getdata",
	AuthenGetUser: "getuser", AuthenGetPass: "getpass",
	AuthenRestart: "restart", AuthenError: "error", AuthenFollow: "follow",
}

func (s AuthenStatus) String() string {
	if n, ok := authenStatusNames[s]; ok {
		return n
	}
	return "authen-status(" + strconv.Itoa(int(s)) + ")"
}

// AuthorStatus is an authorization response's status.
type AuthorStatus uint8

// RFC 8907 §6.2's statuses.
const (
	// AuthorPassAdd allows the request and adds the response's arguments
	// to the ones the client sent.
	AuthorPassAdd AuthorStatus = 0x01
	// AuthorPassReplace allows it and *replaces* the client's arguments
	// with the server's, which is how a server rewrites what the device
	// is about to do -- including the privilege level it does it at.
	AuthorPassReplace AuthorStatus = 0x02
	AuthorFail        AuthorStatus = 0x10
	AuthorError       AuthorStatus = 0x11
	AuthorFollow      AuthorStatus = 0x21
)

var authorStatusNames = map[AuthorStatus]string{
	AuthorPassAdd: "pass-add", AuthorPassReplace: "pass-replace",
	AuthorFail: "fail", AuthorError: "error", AuthorFollow: "follow",
}

func (s AuthorStatus) String() string {
	if n, ok := authorStatusNames[s]; ok {
		return n
	}
	return "author-status(" + strconv.Itoa(int(s)) + ")"
}

// Pass reports whether an authorization response allowed the request.
func (s AuthorStatus) Pass() bool {
	return s == AuthorPassAdd || s == AuthorPassReplace
}

// AcctStatus is an accounting reply's status.
type AcctStatus uint8

// RFC 8907 §7.2's statuses.
const (
	AcctSuccess AcctStatus = 0x01
	AcctError   AcctStatus = 0x02
	AcctFollow  AcctStatus = 0x21
)

func (s AcctStatus) String() string {
	switch s {
	case AcctSuccess:
		return "success"
	case AcctError:
		return "error"
	case AcctFollow:
		return "follow"
	}
	return "acct-status(" + strconv.Itoa(int(s)) + ")"
}

// The accounting record flags of RFC 8907 §7.1.
const (
	AcctFlagStart    uint8 = 0x02
	AcctFlagStop     uint8 = 0x04
	AcctFlagWatchdog uint8 = 0x08
)

// AcctRecord names the record a flags octet describes, which is what an
// audit line should say rather than a number.
func AcctRecord(flags uint8) string {
	switch {
	case flags&AcctFlagStop != 0:
		return "stop"
	case flags&AcctFlagWatchdog != 0 && flags&AcctFlagStart != 0:
		return "watchdog-update"
	case flags&AcctFlagWatchdog != 0:
		return "watchdog"
	case flags&AcctFlagStart != 0:
		return "start"
	}
	return "flags(" + strconv.Itoa(int(flags)) + ")"
}

// Arg is one authorization or accounting argument.
//
// The protocol's own grammar is `attribute=value` for a mandatory
// argument and `attribute*value` for an optional one, and the difference
// is load-bearing: RFC 8907 §6.1 says a client that cannot honour a
// mandatory argument must refuse the whole request, where an optional one
// it does not understand is dropped. So a server adding `priv-lvl=15`
// means the device must apply it, and `priv-lvl*15` means it may.
type Arg struct {
	Name  string
	Value string
	// Mandatory is true for `=` and false for `*`.
	Mandatory bool
}

// String renders the argument back in the protocol's own grammar.
func (a Arg) String() string {
	if a.Mandatory {
		return a.Name + "=" + a.Value
	}
	return a.Name + "*" + a.Value
}

// parseArg splits one argument.
//
// The *first* separator decides, as RFC 8907 §6.1 requires: a value may
// contain either character, so a reader that split on the last one -- or
// on whichever came first of the two -- would read `cmd-arg=a*b` as the
// optional argument `cmd-arg=a` with value `b`. Which is a command
// argument a rule would not match.
func parseArg(s string) (Arg, error) {
	eq, star := strings.IndexByte(s, '='), strings.IndexByte(s, '*')
	i := eq
	mandatory := true
	if i < 0 || (star >= 0 && star < i) {
		i, mandatory = star, false
	}
	if i < 0 {
		return Arg{}, ErrArgSeparator
	}
	return Arg{Name: s[:i], Value: s[i+1:], Mandatory: mandatory}, nil
}

// Args is the argument list, with the readings a policy needs.
type Args []Arg

// First returns the first argument of a name, which for the names that
// matter is the only one that should be there.
func (as Args) First(name string) (Arg, bool) {
	for _, a := range as {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Arg{}, false
}

// Service is the `service` argument: shell, ppp, slip, or a vendor's own.
// It is what says whether the request is about a command at all.
func (as Args) Service() string {
	a, _ := as.First("service")
	return a.Value
}

// Command reconstructs the command line an authorization request is
// about.
//
// A device sends it split: `cmd=configure` and then one `cmd-arg` per
// word, `cmd-arg=terminal`. So the thing a policy is written about --
// "configure terminal" -- exists in no single field, and a relay that
// matched rules against `cmd` alone could not tell `show running-config`
// from `show interfaces`.
//
// The last argument is conventionally `cmd-arg=<cr>`, the carriage
// return the user pressed. It is dropped here: it is in every command
// line, it is not part of the command, and leaving it in would mean every
// rule had to know about it.
func (as Args) Command() string {
	cmd, ok := as.First("cmd")
	if !ok {
		return ""
	}
	parts := []string{cmd.Value}
	for _, a := range as {
		if !strings.EqualFold(a.Name, "cmd-arg") {
			continue
		}
		if a.Value == "<cr>" {
			continue
		}
		parts = append(parts, a.Value)
	}
	return strings.Join(parts, " ")
}

// PrivLvl reads a `priv-lvl` argument, which on a response is the
// privilege the server is granting.
func (as Args) PrivLvl() (int, bool) {
	a, ok := as.First("priv-lvl")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(a.Value))
	if err != nil || n < 0 || n > 15 {
		return 0, false
	}
	return n, true
}

// Names are the argument names present, for a log line that says what a
// request carried without saying what the values were.
func (as Args) Names() []string {
	out := make([]string, 0, len(as))
	seen := map[string]bool{}
	for _, a := range as {
		k := strings.ToLower(a.Name)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// AuthenStart is the first packet of an authentication session.
//
// DataBytes rather than Data: for ActionLogin with AuthenPAP the data
// field *is* the password, and for a change-password session it is the
// old one. The length is what a policy and a log line need.
type AuthenStart struct {
	Action    AuthenAction
	PrivLvl   uint8
	Type      AuthenType
	Service   AuthenService
	User      string
	Port      string
	RemAddr   string
	DataBytes int
}

// ParseAuthenStart reads it.
func ParseAuthenStart(b []byte) (AuthenStart, error) {
	const fixed = 8
	if len(b) < fixed {
		return AuthenStart{}, ErrBodyShort
	}
	s := AuthenStart{
		Action:  AuthenAction(b[0]),
		PrivLvl: b[1],
		Type:    AuthenType(b[2]),
		Service: AuthenService(b[3]),
	}
	userLen, portLen, remLen, dataLen := int(b[4]), int(b[5]), int(b[6]), int(b[7])
	if fixed+userLen+portLen+remLen+dataLen != len(b) {
		return AuthenStart{}, ErrBodyFields
	}
	var err error
	at := fixed
	if s.User, err = text(b[at : at+userLen]); err != nil {
		return AuthenStart{}, err
	}
	at += userLen
	if s.Port, err = text(b[at : at+portLen]); err != nil {
		return AuthenStart{}, err
	}
	at += portLen
	if s.RemAddr, err = text(b[at : at+remLen]); err != nil {
		return AuthenStart{}, err
	}
	s.DataBytes = dataLen
	return s, nil
}

// AuthenReply is the server's answer in an authentication session.
//
// ServerMsg is kept because it is what the device shows the user and a
// relay writes its own refusals into it. DataBytes is a length for the
// same reason as above: on a Follow the data field carries another
// server's key.
type AuthenReply struct {
	Status    AuthenStatus
	Flags     uint8
	ServerMsg string
	DataBytes int
}

// ParseAuthenReply reads it.
func ParseAuthenReply(b []byte) (AuthenReply, error) {
	const fixed = 6
	if len(b) < fixed {
		return AuthenReply{}, ErrBodyShort
	}
	r := AuthenReply{Status: AuthenStatus(b[0]), Flags: b[1]}
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	dataLen := int(binary.BigEndian.Uint16(b[4:6]))
	if fixed+msgLen+dataLen != len(b) {
		return AuthenReply{}, ErrBodyFields
	}
	var err error
	if r.ServerMsg, err = text(b[fixed : fixed+msgLen]); err != nil {
		return AuthenReply{}, err
	}
	r.DataBytes = dataLen
	return r, nil
}

// MarshalAuthenReply builds a reply body, which is how this relay refuses
// an authentication in the protocol's own terms.
func MarshalAuthenReply(r AuthenReply) []byte {
	msg := []byte(r.ServerMsg)
	b := make([]byte, 6, 6+len(msg))
	b[0], b[1] = byte(r.Status), r.Flags
	binary.BigEndian.PutUint16(b[2:4], uint16(len(msg))) //nolint:gosec // the caller's message, clipped by the kind before it gets here
	binary.BigEndian.PutUint16(b[4:6], 0)
	return append(b, msg...)
}

// AuthenContinue is the client's further packet in an authentication
// session: the user's typed answer, which for a password prompt is the
// password.
//
// Both fields are lengths. There is deliberately no accessor that
// returns the typed text: the only field in this protocol a relay must
// never hold is in here, and the way not to hold it is not to have a way
// to ask for it.
type AuthenContinue struct {
	UserMsgBytes int
	DataBytes    int
	// Abort is the client giving up, which ends the session.
	Abort bool
}

// The continue flag of RFC 8907 §5.3.
const continueFlagAbort uint8 = 0x01

// ParseAuthenContinue reads it.
func ParseAuthenContinue(b []byte) (AuthenContinue, error) {
	const fixed = 5
	if len(b) < fixed {
		return AuthenContinue{}, ErrBodyShort
	}
	c := AuthenContinue{
		UserMsgBytes: int(binary.BigEndian.Uint16(b[0:2])),
		DataBytes:    int(binary.BigEndian.Uint16(b[2:4])),
		Abort:        b[4]&continueFlagAbort != 0,
	}
	if fixed+c.UserMsgBytes+c.DataBytes != len(b) {
		return AuthenContinue{}, ErrBodyFields
	}
	return c, nil
}

// AuthorRequest is an authorization request: the one that names a
// command.
type AuthorRequest struct {
	Method  AuthenMethod
	PrivLvl uint8
	Type    AuthenType
	Service AuthenService
	User    string
	Port    string
	RemAddr string
	Args    Args
}

// ParseAuthorRequest reads it.
func ParseAuthorRequest(b []byte) (AuthorRequest, error) {
	const fixed = 8
	if len(b) < fixed {
		return AuthorRequest{}, ErrBodyShort
	}
	r := AuthorRequest{
		Method:  AuthenMethod(b[0]),
		PrivLvl: b[1],
		Type:    AuthenType(b[2]),
		Service: AuthenService(b[3]),
	}
	userLen, portLen, remLen := int(b[4]), int(b[5]), int(b[6])
	argCnt := int(b[7])
	if argCnt > maxArgs {
		return AuthorRequest{}, ErrArgCount
	}
	if len(b) < fixed+argCnt {
		return AuthorRequest{}, ErrBodyShort
	}
	lens := b[fixed : fixed+argCnt]
	at := fixed + argCnt
	total := at + userLen + portLen + remLen
	for _, l := range lens {
		if l == 0 {
			// A zero-length argument is not `a=` -- that is two octets --
			// it is an argument with no separator and nothing in it, and
			// the standard has no reading for one.
			return AuthorRequest{}, ErrArgEmpty
		}
		total += int(l)
	}
	if total != len(b) {
		return AuthorRequest{}, ErrBodyFields
	}
	var err error
	if r.User, err = text(b[at : at+userLen]); err != nil {
		return AuthorRequest{}, err
	}
	at += userLen
	if r.Port, err = text(b[at : at+portLen]); err != nil {
		return AuthorRequest{}, err
	}
	at += portLen
	if r.RemAddr, err = text(b[at : at+remLen]); err != nil {
		return AuthorRequest{}, err
	}
	at += remLen
	if r.Args, err = readArgs(b, at, lens); err != nil {
		return AuthorRequest{}, err
	}
	return r, nil
}

// readArgs cuts the argument strings out and splits each one.
func readArgs(b []byte, at int, lens []byte) (Args, error) {
	out := make(Args, 0, len(lens))
	for _, l := range lens {
		s, err := text(b[at : at+int(l)])
		if err != nil {
			return nil, err
		}
		a, err := parseArg(s)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
		at += int(l)
	}
	return out, nil
}

// AuthorResponse is the server's answer: whether the command may run,
// and the arguments the device is to apply.
type AuthorResponse struct {
	Status    AuthorStatus
	ServerMsg string
	DataBytes int
	Args      Args
}

// ParseAuthorResponse reads it.
func ParseAuthorResponse(b []byte) (AuthorResponse, error) {
	const fixed = 6
	if len(b) < fixed {
		return AuthorResponse{}, ErrBodyShort
	}
	r := AuthorResponse{Status: AuthorStatus(b[0])}
	argCnt := int(b[1])
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	dataLen := int(binary.BigEndian.Uint16(b[4:6]))
	if argCnt > maxArgs {
		return AuthorResponse{}, ErrArgCount
	}
	if len(b) < fixed+argCnt {
		return AuthorResponse{}, ErrBodyShort
	}
	lens := b[fixed : fixed+argCnt]
	at := fixed + argCnt
	total := at + msgLen + dataLen
	for _, l := range lens {
		if l == 0 {
			return AuthorResponse{}, ErrArgEmpty
		}
		total += int(l)
	}
	if total != len(b) {
		return AuthorResponse{}, ErrBodyFields
	}
	var err error
	if r.ServerMsg, err = text(b[at : at+msgLen]); err != nil {
		return AuthorResponse{}, err
	}
	at += msgLen
	r.DataBytes = dataLen
	at += dataLen
	if r.Args, err = readArgs(b, at, lens); err != nil {
		return AuthorResponse{}, err
	}
	return r, nil
}

// MarshalAuthorResponse builds a response body, for the refusal this
// relay writes itself.
func MarshalAuthorResponse(r AuthorResponse) []byte {
	msg := []byte(r.ServerMsg)
	args := make([][]byte, 0, len(r.Args))
	for _, a := range r.Args {
		args = append(args, []byte(a.String()))
	}
	b := make([]byte, 6, 6+len(args)+len(msg))
	b[0] = byte(r.Status)
	b[1] = byte(len(args))                               //nolint:gosec // the caller builds these; a refusal carries none
	binary.BigEndian.PutUint16(b[2:4], uint16(len(msg))) //nolint:gosec // clipped by the kind
	binary.BigEndian.PutUint16(b[4:6], 0)
	for _, a := range args {
		b = append(b, byte(len(a))) //nolint:gosec // the kind builds short arguments
	}
	b = append(b, msg...)
	for _, a := range args {
		b = append(b, a...)
	}
	return b
}

// AcctRequest is an accounting record: what the device says the user did.
//
// This is the audit trail, and on a TACACS+ estate it is the record of
// every command run on every piece of equipment. A relay that writes it
// into the estate's own log has that record even when the TACACS+
// server's own is lost, rotated or edited.
type AcctRequest struct {
	Flags   uint8
	Method  AuthenMethod
	PrivLvl uint8
	Type    AuthenType
	Service AuthenService
	User    string
	Port    string
	RemAddr string
	Args    Args
}

// ParseAcctRequest reads it.
func ParseAcctRequest(b []byte) (AcctRequest, error) {
	const fixed = 9
	if len(b) < fixed {
		return AcctRequest{}, ErrBodyShort
	}
	r := AcctRequest{
		Flags:   b[0],
		Method:  AuthenMethod(b[1]),
		PrivLvl: b[2],
		Type:    AuthenType(b[3]),
		Service: AuthenService(b[4]),
	}
	userLen, portLen, remLen := int(b[5]), int(b[6]), int(b[7])
	argCnt := int(b[8])
	if argCnt > maxArgs {
		return AcctRequest{}, ErrArgCount
	}
	if len(b) < fixed+argCnt {
		return AcctRequest{}, ErrBodyShort
	}
	lens := b[fixed : fixed+argCnt]
	at := fixed + argCnt
	total := at + userLen + portLen + remLen
	for _, l := range lens {
		if l == 0 {
			return AcctRequest{}, ErrArgEmpty
		}
		total += int(l)
	}
	if total != len(b) {
		return AcctRequest{}, ErrBodyFields
	}
	var err error
	if r.User, err = text(b[at : at+userLen]); err != nil {
		return AcctRequest{}, err
	}
	at += userLen
	if r.Port, err = text(b[at : at+portLen]); err != nil {
		return AcctRequest{}, err
	}
	at += portLen
	if r.RemAddr, err = text(b[at : at+remLen]); err != nil {
		return AcctRequest{}, err
	}
	at += remLen
	if r.Args, err = readArgs(b, at, lens); err != nil {
		return AcctRequest{}, err
	}
	return r, nil
}

// AcctReply is the server's acknowledgement of a record.
type AcctReply struct {
	Status    AcctStatus
	ServerMsg string
	DataBytes int
}

// ParseAcctReply reads it.
func ParseAcctReply(b []byte) (AcctReply, error) {
	const fixed = 5
	if len(b) < fixed {
		return AcctReply{}, ErrBodyShort
	}
	msgLen := int(binary.BigEndian.Uint16(b[0:2]))
	dataLen := int(binary.BigEndian.Uint16(b[2:4]))
	r := AcctReply{Status: AcctStatus(b[4])}
	if fixed+msgLen+dataLen != len(b) {
		return AcctReply{}, ErrBodyFields
	}
	var err error
	if r.ServerMsg, err = text(b[fixed : fixed+msgLen]); err != nil {
		return AcctReply{}, err
	}
	r.DataBytes = dataLen
	return r, nil
}

// MarshalAcctReply builds an accounting reply body.
func MarshalAcctReply(r AcctReply) []byte {
	msg := []byte(r.ServerMsg)
	b := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(msg))) //nolint:gosec // clipped by the kind
	binary.BigEndian.PutUint16(b[2:4], 0)
	b[4] = byte(r.Status)
	return append(b, msg...)
}

// sortStrings is an insertion sort, so the name tables above need no
// import of sort.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
