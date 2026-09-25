package ldap

import (
	"errors"
	"fmt"
	"strings"
)

// The reading layer the ldap relay kind decides about.
//
// This is deliberately separate from the client above it and deliberately in
// the same package: both read LDAP, and two BER implementations in one
// binary would be two readings of the same bytes, which is exactly the class
// of bug a security relay exists to remove.
//
// What is read is the envelope and the shape of each operation -- the
// message identifier, which operation it is, the bind method and credential
// *extent*, the search base, scope, filter shape and attribute list, and a
// result's code. What is not read is any value in a directory entry beyond
// its attribute names: an entry's contents are the estate's data, and a
// relay that decoded them would be a directory server with a second
// schema.

// MaxMessage bounds one LDAPMessage. RFC 4511 sets no limit; a directory
// entry with a photograph in it is real, and so is a client that claims a
// four-gigabyte message to see what happens.
const MaxMessage = 1 << 20

// MaxFilterDepth and MaxFilterTerms bound a search filter as read, above any
// policy an operator sets. A filter is a tree a client chooses the shape of,
// and the reader will not walk one deeper or wider than this whatever a
// listener allows.
const (
	MaxFilterDepth = 32
	MaxFilterTerms = 512
)

// MaxDNLength bounds a distinguished name. Directories have their own
// limits; this one keeps a name a client made up from becoming the work.
const MaxDNLength = 4096

// Op is an LDAP protocol operation: the application tag of the choice
// inside an LDAPMessage.
type Op int

// The operations of RFC 4511 §4, by their application tag.
const (
	OpBindRequest           Op = 0
	OpBindResponse          Op = 1
	OpUnbindRequest         Op = 2
	OpSearchRequest         Op = 3
	OpSearchResultEntry     Op = 4
	OpSearchResultDone      Op = 5
	OpModifyRequest         Op = 6
	OpModifyResponse        Op = 7
	OpAddRequest            Op = 8
	OpAddResponse           Op = 9
	OpDelRequest            Op = 10
	OpDelResponse           Op = 11
	OpModifyDNRequest       Op = 12
	OpModifyDNResponse      Op = 13
	OpCompareRequest        Op = 14
	OpCompareResponse       Op = 15
	OpAbandonRequest        Op = 16
	OpSearchResultReference Op = 19
	OpExtendedRequest       Op = 23
	OpExtendedResponse      Op = 24
	OpIntermediateResponse  Op = 25
)

var opNames = map[Op]string{
	OpBindRequest: "bind", OpBindResponse: "bind_response",
	OpUnbindRequest: "unbind", OpSearchRequest: "search",
	OpSearchResultEntry: "search_entry", OpSearchResultDone: "search_done",
	OpModifyRequest: "modify", OpModifyResponse: "modify_response",
	OpAddRequest: "add", OpAddResponse: "add_response",
	OpDelRequest: "delete", OpDelResponse: "delete_response",
	OpModifyDNRequest: "modify_dn", OpModifyDNResponse: "modify_dn_response",
	OpCompareRequest: "compare", OpCompareResponse: "compare_response",
	OpAbandonRequest: "abandon", OpSearchResultReference: "search_reference",
	OpExtendedRequest: "extended", OpExtendedResponse: "extended_response",
	OpIntermediateResponse: "intermediate_response",
}

// opByName is the reverse, for a policy written in an operator's words.
var opByName = func() map[string]Op {
	out := make(map[string]Op, len(opNames))
	for op, name := range opNames {
		out[name] = op
	}
	// The two spellings an administrator is as likely to write.
	out["del"] = OpDelRequest
	out["moddn"] = OpModifyDNRequest
	return out
}()

func (o Op) String() string {
	if n, ok := opNames[o]; ok {
		return n
	}
	return fmt.Sprintf("op(%d)", int(o))
}

// OpOf names an operation the way a rule is written.
func OpOf(s string) (Op, bool) {
	op, ok := opByName[strings.ToLower(strings.TrimSpace(s))]
	return op, ok
}

// Known says whether this is an operation RFC 4511 defines.
func (o Op) Known() bool { _, ok := opNames[o]; return ok }

// Request says whether a client sends this operation. A server sending a
// request, or a client sending a response, is traffic going the wrong way.
func (o Op) Request() bool {
	switch o {
	case OpBindRequest, OpUnbindRequest, OpSearchRequest, OpModifyRequest,
		OpAddRequest, OpDelRequest, OpModifyDNRequest, OpCompareRequest,
		OpAbandonRequest, OpExtendedRequest:
		return true
	}
	return false
}

// Writes says whether this operation changes the directory. It is the
// durable way to write "nobody writes through this relay", because it does
// not change when a later revision adds an operation.
func (o Op) Writes() bool {
	switch o {
	case OpModifyRequest, OpAddRequest, OpDelRequest, OpModifyDNRequest:
		return true
	}
	return false
}

// Reads says whether this operation reads the directory.
func (o Op) Reads() bool { return o == OpSearchRequest || o == OpCompareRequest }

// Method is how a bind authenticates.
type Method int

// The bind methods. Anonymous and unauthenticated are not choices in the
// protocol -- both are simple binds -- but they are different security
// statements and a policy has to be able to name each.
const (
	// MethodAnonymous is a simple bind with no name and no password: the
	// protocol's way of saying "I am nobody", which is a legitimate thing
	// to say and usually not one a directory should answer.
	MethodAnonymous Method = iota
	// MethodUnauthenticated is a simple bind with a name and an *empty*
	// password. RFC 4513 §5.1.2 says it is an anonymous bind; a great many
	// directories answer it with success, and a great many applications
	// read that success as "the password was right". It is the reason this
	// relay exists on this protocol.
	MethodUnauthenticated
	// MethodSimple is a simple bind with a name and a password, which
	// travels in the clear unless the connection is protected.
	MethodSimple
	// MethodSASL is a SASL bind, whose mechanism is the interesting field.
	MethodSASL
)

var methodNames = map[Method]string{
	MethodAnonymous: "anonymous", MethodUnauthenticated: "unauthenticated",
	MethodSimple: "simple", MethodSASL: "sasl",
}

func (m Method) String() string {
	if n, ok := methodNames[m]; ok {
		return n
	}
	return "method(?)"
}

// MethodOf names a bind method the way a rule is written.
func MethodOf(s string) (Method, bool) {
	for m, n := range methodNames {
		if n == strings.ToLower(strings.TrimSpace(s)) {
			return m, true
		}
	}
	return 0, false
}

// ResultCode is an LDAP result code (RFC 4511 §A.1). Only the ones a relay
// sends or reasons about are named.
type ResultCode int

const (
	ResultSuccess                 ResultCode = 0
	ResultOperationsError         ResultCode = 1
	ResultProtocolError           ResultCode = 2
	ResultTimeLimitExceeded       ResultCode = 3
	ResultSizeLimitExceeded       ResultCode = 4
	ResultAuthMethodNotSupported  ResultCode = 7
	ResultStrongerAuthRequired    ResultCode = 8
	ResultAdminLimitExceeded      ResultCode = 11
	ResultConfidentialityRequired ResultCode = 13
	ResultInvalidCredentials      ResultCode = 49
	ResultInsufficientAccess      ResultCode = 50
	ResultBusy                    ResultCode = 51
	ResultUnwillingToPerform      ResultCode = 53
)

var resultNames = map[ResultCode]string{
	ResultSuccess: "success", ResultOperationsError: "operationsError",
	ResultProtocolError: "protocolError", ResultTimeLimitExceeded: "timeLimitExceeded",
	ResultSizeLimitExceeded:       "sizeLimitExceeded",
	ResultAuthMethodNotSupported:  "authMethodNotSupported",
	ResultStrongerAuthRequired:    "strongerAuthRequired",
	ResultAdminLimitExceeded:      "adminLimitExceeded",
	ResultConfidentialityRequired: "confidentialityRequired",
	ResultInvalidCredentials:      "invalidCredentials",
	ResultInsufficientAccess:      "insufficientAccessRights",
	ResultBusy:                    "busy", ResultUnwillingToPerform: "unwillingToPerform",
}

func (r ResultCode) String() string {
	if n, ok := resultNames[r]; ok {
		return n
	}
	return fmt.Sprintf("result(%d)", int(r))
}

// The extended operations worth naming. StartTLS is the one a relay
// implements rather than forwards; the other two change or reveal an
// identity, which is why a policy names them rather than allowing
// "extended".
const (
	OIDStartTLS       = "1.3.6.1.4.1.1466.20037"
	OIDPasswordModify = "1.3.6.1.4.1.4203.1.11.1"
	OIDWhoAmI         = "1.3.6.1.4.1.4203.1.11.3"
	OIDCancel         = "1.3.6.1.1.8"
	// OIDNoticeOfDisconnection arrives as an ExtendedResponse with message
	// identifier 0: the server saying it is about to close. It is the only
	// unsolicited message the protocol has.
	OIDNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"
)

// Errors a reader returns. They are distinct because a relay answers each
// differently: a malformed message ends a connection, and a message past a
// bound is refused without being read.
var (
	// ErrTruncated is a message that ended inside itself.
	ErrTruncated = errors.New("ldap: truncated message")
	// ErrFraming is a stream that does not begin an LDAPMessage where one
	// was due.
	ErrFraming = errors.New("ldap: not a message")
	// ErrTooLong is a message whose declared length is past the bound.
	ErrTooLong = errors.New("ldap: message past the bound")
	// ErrShape is a message whose fields are not the ones the operation
	// has.
	ErrShape = errors.New("ldap: not the shape of that operation")
	// ErrCount is more of something than a bound allows.
	ErrCount = errors.New("ldap: too many elements")
)

// Bind is a parsed BindRequest.
type Bind struct {
	// Version is the LDAP version the client claims. 3 is the only one this
	// relay carries; 2 is a different protocol wearing the same tag.
	Version int
	// Name is the bind DN as it arrived, and DN its parsed form.
	Name string
	DN   DN
	// Method is what kind of bind this is, including the two that are
	// simple binds by the protocol and anonymous by their effect.
	Method Method
	// Mechanism is the SASL mechanism, empty for a simple bind.
	Mechanism string
	// PasswordLength is the credential's extent. The credential itself is
	// deliberately not kept: a relay that held a directory password in a
	// struct would be a relay that could log one.
	PasswordLength int
}

// Search is a parsed SearchRequest.
type Search struct {
	// Base is the search base as it arrived, and BaseDN its parsed form.
	// An empty base is the root DSE, and a subtree search from it is a
	// request for the whole directory.
	Base   string
	BaseDN DN
	// Scope is base, one level or subtree.
	Scope int
	// DerefAliases, SizeLimit and TimeLimit are the client's own bounds,
	// which a relay can lower and must not trust.
	DerefAliases int
	SizeLimit    int
	TimeLimit    int
	// TypesOnly asks for attribute names without values.
	TypesOnly bool
	// Filter is the filter's shape: what it tests, how deep it nests, how
	// many terms it has and which attributes it names.
	Filter *Filter
	// Attributes are the attributes asked for, in order. "*" is all user
	// attributes and "+" all operational ones, and an empty list means all
	// user attributes -- which is why an attribute policy has to apply to
	// the *answer* as well as to the question.
	Attributes []string
}

// AllAttributes says whether this search will be answered with attributes
// it did not name: an empty list, "*" or "+".
func (s *Search) AllAttributes() bool {
	if len(s.Attributes) == 0 {
		return true
	}
	for _, a := range s.Attributes {
		if a == "*" || a == "+" {
			return true
		}
	}
	return false
}

// ResultEntry is a parsed SearchResultEntry: the object's name and the
// attribute names it carries. The values are not read.
//
// It is not the client's Entry above, which carries values because an
// authentication filter needs them. This one deliberately does not: a relay
// that held a directory's contents in a struct would be a relay that could
// log them.
type ResultEntry struct {
	// Name is the entry's DN.
	Name string
	// Attributes are the attribute descriptions present, in order.
	Attributes []string
}

// Modify is a parsed ModifyRequest: which object, and which attributes are
// being changed how.
type Modify struct {
	// Object is the DN being modified.
	Object   string
	ObjectDN DN
	// Attributes are the attribute descriptions this modification touches.
	Attributes []string
	// Operations are the change types, aligned with Attributes: 0 add, 1
	// delete, 2 replace, 3 increment (RFC 4525).
	Operations []int
}

// Extended is a parsed ExtendedRequest or ExtendedResponse.
type Extended struct {
	// OID names the operation. It is the whole of what a policy can decide
	// about: the value is the operation's own encoding.
	OID string
	// HasValue says a request value was present, and ValueLength its
	// extent.
	HasValue    bool
	ValueLength int
}

// Result is the outcome fields every response carries.
type Result struct {
	Code ResultCode
	// MatchedDN and Message are the server's own words. They are carried so
	// an access log can say what the directory said, and are never parsed.
	MatchedDN string
	Message   string
	// Referral says the response carried a referral, which is a redirection
	// to another server and therefore a decision an operator may want to
	// make.
	Referral bool
}

// Control is an LDAPControl: its OID and whether the client marked it
// critical. The value is the control's own encoding and is not read.
type Control struct {
	OID         string
	Criticality bool
	ValueLength int
}

// Message is one parsed LDAPMessage.
type Message struct {
	// ID is the message identifier, which pairs a response with its
	// request. Zero is reserved for the server's unsolicited notification,
	// so a client sending it is malformed.
	ID int
	Op Op
	// Raw is the message exactly as it arrived, which is what a relay
	// forwards when it forwards something unchanged.
	Raw []byte

	Bind     *Bind
	Search   *Search
	Entry    *ResultEntry
	Modify   *Modify
	Extended *Extended
	Result   *Result
	// Target is the DN a single-object operation names: add, delete,
	// modifyDN, compare. Modify and search keep theirs in their own struct.
	Target   string
	TargetDN DN
	// Abandon is the message identifier an AbandonRequest names.
	Abandon int
	// Controls are the controls attached, in order.
	Controls []Control

	// pkt is the parsed tree, kept so a response can be rewritten -- which
	// is how an attribute the policy does not allow is removed from an
	// entry the directory sent anyway.
	pkt *packet
}
