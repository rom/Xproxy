package opcua

import (
	"fmt"
	"strings"
)

// Attribute is the attribute of a node a Read or a Write names.
//
// It is easy to read past this field as bookkeeping, and it is not: a Write to
// attribute 13 changes a process value, and a Write to attribute 17 changes who may
// change process values. A policy that allowed writes to a node without naming the
// attribute would have allowed both.
type Attribute uint32

// The attributes of IEC 62541-3 s5.9, as far as a policy names them.
const (
	AttrNodeID          Attribute = 1
	AttrNodeClass       Attribute = 2
	AttrBrowseName      Attribute = 3
	AttrDisplayName     Attribute = 4
	AttrDescription     Attribute = 5
	AttrWriteMask       Attribute = 6
	AttrUserWriteMask   Attribute = 7
	AttrValue           Attribute = 13
	AttrDataType        Attribute = 14
	AttrValueRank       Attribute = 15
	AttrArrayDimensions Attribute = 16
	AttrAccessLevel     Attribute = 17
	AttrUserAccessLevel Attribute = 18
	AttrMinSampling     Attribute = 19
	AttrHistorizing     Attribute = 20
	AttrEventNotifier   Attribute = 21
	AttrExecutable      Attribute = 22
	AttrUserExecutable  Attribute = 23
)

var attributeNames = map[Attribute]string{
	AttrNodeID: "node_id", AttrNodeClass: "node_class", AttrBrowseName: "browse_name",
	AttrDisplayName: "display_name", AttrDescription: "description",
	AttrWriteMask: "write_mask", AttrUserWriteMask: "user_write_mask",
	AttrValue: "value", AttrDataType: "data_type", AttrValueRank: "value_rank",
	AttrArrayDimensions: "array_dimensions", AttrAccessLevel: "access_level",
	AttrUserAccessLevel: "user_access_level", AttrMinSampling: "minimum_sampling_interval",
	AttrHistorizing: "historizing", AttrEventNotifier: "event_notifier",
	AttrExecutable: "executable", AttrUserExecutable: "user_executable",
}

func (a Attribute) String() string {
	if n, ok := attributeNames[a]; ok {
		return n
	}
	return fmt.Sprintf("attribute(%d)", uint32(a))
}

// Known says the attribute is one the standard defines.
func (a Attribute) Known() bool { _, ok := attributeNames[a]; return ok }

// Permission says the attribute governs who may do what, rather than holding data.
// A write to one of these is a privilege change however innocuous the node looks.
func (a Attribute) Permission() bool {
	switch a {
	case AttrWriteMask, AttrUserWriteMask, AttrAccessLevel, AttrUserAccessLevel,
		AttrExecutable, AttrUserExecutable, AttrHistorizing:
		return true
	}
	return false
}

// AttributeOf reads an attribute back from its name.
func AttributeOf(name string) (Attribute, bool) {
	l := strings.ToLower(name)
	for a, n := range attributeNames {
		if n == l {
			return a, true
		}
	}
	return 0, false
}

// A ValueID names what a Read reads or a monitored item watches: a node, an
// attribute of it, and optionally a slice of an array-valued attribute.
type ValueID struct {
	Node NodeId
	Attr Attribute
	// Range is an index range like "2:4" into an array value, empty for the
	// whole thing. It is a string on the wire and a string here, because the
	// server parses it and a relay that re-parsed it would be a second opinion
	// about what the client asked for.
	Range string
	// Encoding names a non-default encoding for the value, and is almost always
	// empty.
	Encoding string
}

func (r *reader) valueID() ValueID {
	v := ValueID{}
	v.Node = r.nodeID(false)
	v.Attr = Attribute(r.uint32())
	v.Range = r.str()
	ns := r.uint16()
	if name := r.str(); name != "" {
		v.Encoding = fmt.Sprintf("%d:%s", ns, name)
	}
	return v
}

// A ReadRequest is what a client reads with.
type ReadRequest struct {
	// MaxAge is how stale a cached value the client will accept, in
	// milliseconds. Zero means the server must read the device.
	MaxAge float64
	// Timestamps says which of the source and server timestamps to return.
	Timestamps uint32
	// Nodes is what the client asked for.
	Nodes []ValueID
}

// ParseRead reads a ReadRequest body: what follows the request header.
func ParseRead(body []byte) (*ReadRequest, error) {
	r := &reader{b: body}
	q := &ReadRequest{MaxAge: r.double(), Timestamps: r.uint32()}
	n := r.arrayLen("nodes to read")
	for i := 0; i < n; i++ {
		q.Nodes = append(q.Nodes, r.valueID())
		if r.err != nil {
			break
		}
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return q, nil
}

// A WriteValue is one thing a Write changes.
type WriteValue struct {
	Node NodeId
	Attr Attribute
	// Range is an index range, as in a ValueID.
	Range string
	// Value is what the client wants the attribute to become.
	Value DataValue
}

// A WriteRequest is what a client changes a plant with, and the single most
// consequential message in the protocol for a relay in front of one.
type WriteRequest struct {
	Values []WriteValue
}

// ParseWrite reads a WriteRequest body.
func ParseWrite(body []byte) (*WriteRequest, error) {
	r := &reader{b: body}
	w := &WriteRequest{}
	n := r.arrayLen("nodes to write")
	for i := 0; i < n; i++ {
		v := WriteValue{}
		v.Node = r.nodeID(false)
		v.Attr = Attribute(r.uint32())
		v.Range = r.str()
		v.Value = r.dataValue(1)
		if r.err != nil {
			break
		}
		w.Values = append(w.Values, v)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return w, nil
}

// A MethodCall is one method a Call invokes: the object it is on, the method, and
// its arguments.
//
// Both node ids matter. A method exists on a type and is called on an instance, so
// the pair is what a rule names: allowing Reset on one pump is not allowing it on
// every pump of that model.
type MethodCall struct {
	Object    NodeId
	Method    NodeId
	Arguments []Variant
}

// A CallRequest is how a client makes a plant do something. There is no attribute
// and no value: there is a method, and whatever it does happens.
type CallRequest struct {
	Methods []MethodCall
}

// MaxArguments bounds a method's input arguments.
const MaxArguments = 64

// ParseCallRequest reads a CallRequest body.
func ParseCallRequest(body []byte) (*CallRequest, error) {
	r := &reader{b: body}
	c := &CallRequest{}
	n := r.arrayLen("methods to call")
	for i := 0; i < n; i++ {
		m := MethodCall{}
		m.Object = r.nodeID(false)
		m.Method = r.nodeID(false)
		a := r.arrayLen("input arguments")
		if a > MaxArguments {
			r.fail("%w: %d input arguments", ErrTooLong, a)
			break
		}
		for j := 0; j < a; j++ {
			m.Arguments = append(m.Arguments, r.variant(1))
			if r.err != nil {
				break
			}
		}
		if r.err != nil {
			break
		}
		c.Methods = append(c.Methods, m)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return c, nil
}

// BrowseDirection is which way a Browse follows references.
type BrowseDirection uint32

// The directions of IEC 62541-4 s5.8.2.
const (
	BrowseForward BrowseDirection = 0
	BrowseInverse BrowseDirection = 1
	BrowseBoth    BrowseDirection = 2
	// BrowseInvalid is what a peer naming a fourth direction gets.
	BrowseInvalid BrowseDirection = 3
)

func (d BrowseDirection) String() string {
	switch d {
	case BrowseForward:
		return "forward"
	case BrowseInverse:
		return "inverse"
	case BrowseBoth:
		return "both"
	}
	return fmt.Sprintf("direction(%d)", uint32(d))
}

// A BrowseTarget is one node a Browse starts from.
type BrowseTarget struct {
	Node          NodeId
	Direction     BrowseDirection
	ReferenceType NodeId
	// Subtypes says the browse follows subtypes of the reference type as well.
	Subtypes bool
	// NodeClasses is a bit mask of the node classes to return, and zero means
	// every one.
	NodeClasses uint32
	// Results is a bit mask of the fields to return per reference.
	Results uint32
}

// A BrowseRequest is how a client discovers an address space. It is a read, but it
// is the read that turns "I can reach this server" into "I know what is on it", so
// a listener that bounds enumeration bounds this.
type BrowseRequest struct {
	// View names a view of the address space, and is usually null.
	View NodeId
	// MaxReferences is how many references per node the client will take, and
	// zero means the server decides. A client sending zero and browsing the whole
	// tree is enumerating.
	MaxReferences uint32
	Nodes         []BrowseTarget
}

// ParseBrowse reads a BrowseRequest body.
func ParseBrowse(body []byte) (*BrowseRequest, error) {
	r := &reader{b: body}
	b := &BrowseRequest{}
	b.View = r.nodeID(false)
	r.int64() // the view's timestamp
	r.uint32()
	b.MaxReferences = r.uint32()
	n := r.arrayLen("nodes to browse")
	for i := 0; i < n; i++ {
		t := BrowseTarget{}
		t.Node = r.nodeID(false)
		t.Direction = BrowseDirection(r.uint32())
		t.ReferenceType = r.nodeID(false)
		t.Subtypes = r.boolean()
		t.NodeClasses = r.uint32()
		t.Results = r.uint32()
		if r.err != nil {
			break
		}
		b.Nodes = append(b.Nodes, t)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return b, nil
}

// ChannelRequestType is whether an OpenSecureChannel issues a channel or renews one.
type ChannelRequestType uint32

const (
	// ChannelIssue asks for a new channel.
	ChannelIssue ChannelRequestType = 0
	// ChannelRenew asks for new keys on an existing one.
	ChannelRenew ChannelRequestType = 1
)

func (t ChannelRequestType) String() string {
	switch t {
	case ChannelIssue:
		return "issue"
	case ChannelRenew:
		return "renew"
	}
	return fmt.Sprintf("request(%d)", uint32(t))
}

// An OpenChannelRequest is the body of an OPN message, and it is where the security
// mode is named.
//
// This is the message a relay most needs to read, because the header names the
// policy and only the body names the mode — and the mode is what decides whether
// every message after this one has a readable body. A listener that enforced a
// policy without the mode would allow Basic256Sha256 with mode None, which is a
// channel with a strong cipher suite and nothing encrypted.
type OpenChannelRequest struct {
	// ClientProtocolVersion is zero.
	ClientProtocolVersion uint32
	// Type is whether this issues or renews.
	Type ChannelRequestType
	// Mode is the message security mode being asked for.
	Mode MessageSecurityMode
	// Nonce is the client's contribution to the key material. Under mode None it
	// is null, and a non-null one there is a client that thinks it is securing
	// something.
	Nonce []byte
	// Lifetime is how long the client asks the token to live, in milliseconds. A
	// very long one is a client asking not to rotate its keys.
	Lifetime uint32
}

// ParseOpenChannel reads an OpenSecureChannel request body.
func ParseOpenChannel(body []byte) (*OpenChannelRequest, error) {
	r := &reader{b: body}
	o := &OpenChannelRequest{
		ClientProtocolVersion: r.uint32(),
		Type:                  ChannelRequestType(r.uint32()),
		Mode:                  MessageSecurityMode(r.uint32()),
	}
	o.Nonce = r.byteString()
	o.Lifetime = r.uint32()
	if err := r.done(); err != nil {
		return nil, err
	}
	if !o.Mode.Known() {
		return nil, fmt.Errorf("%w: a message security mode of %d", ErrEncoding, uint32(o.Mode))
	}
	return o, nil
}

// A CreateSessionRequest names the application on the other end and how long the
// session should live.
//
// The client's application URI and certificate are here, and they are what an estate
// has an allow-list of. The URI in the certificate's subjectAltName must equal the
// one in this message — a server checks it, and so can a relay, which is the cheapest
// identity check in the protocol.
type CreateSessionRequest struct {
	// ApplicationURI is the client's own identity, which its certificate must
	// also carry.
	ApplicationURI string
	// ProductURI names the software.
	ProductURI string
	// ApplicationName is the human-readable name.
	ApplicationName string
	// ApplicationType is 0 server, 1 client, 2 both, 3 discovery server. A
	// CreateSession from something calling itself a server is worth noticing.
	ApplicationType uint32
	// EndpointURL is the endpoint the client believes it reached.
	EndpointURL string
	// SessionName is a name the client chose, echoed in the server's own audit
	// log.
	SessionName string
	// Nonce and Certificate are the client's key agreement contribution and its
	// instance certificate.
	Nonce       []byte
	Certificate []byte
	// Timeout is the session timeout the client asks for, in milliseconds.
	Timeout float64
	// MaxResponseSize is the largest response the client will accept, and zero
	// means no limit of its own.
	MaxResponseSize uint32
}

// ParseCreateSession reads a CreateSessionRequest body.
func ParseCreateSession(body []byte) (*CreateSessionRequest, error) {
	r := &reader{b: body}
	c := &CreateSessionRequest{}
	c.ApplicationURI = r.str()
	c.ProductURI = r.str()
	c.ApplicationName = r.localizedText()
	c.ApplicationType = r.uint32()
	r.str() // the gateway server uri
	r.str() // the discovery profile uri
	if n := r.arrayLen("discovery urls"); n > 0 {
		for i := 0; i < n; i++ {
			r.str()
			if r.err != nil {
				break
			}
		}
	}
	// The server URI names a server behind a gateway server, and is empty in
	// every direct connection. It is read and discarded rather than skipped,
	// because there is no skipping a length-prefixed field without reading it.
	r.str()
	c.EndpointURL = r.str()
	c.SessionName = r.str()
	c.Nonce = r.byteString()
	c.Certificate = r.byteString()
	c.Timeout = r.double()
	c.MaxResponseSize = r.uint32()
	if err := r.done(); err != nil {
		return nil, err
	}
	return c, nil
}

// TokenKind is which kind of user identity token an ActivateSession carried.
type TokenKind uint32

// The identity token encodings of IEC 62541-4 s7.36, by their binary encoding ids.
const (
	// TokenAnonymous is no user at all: the session's rights are whatever the
	// endpoint grants an anonymous client.
	TokenAnonymous TokenKind = 321
	// TokenUserName is a username and a password.
	TokenUserName TokenKind = 324
	// TokenX509 is a user certificate.
	TokenX509 TokenKind = 327
	// TokenIssued is a token from somewhere else: a JWT, a Kerberos ticket.
	TokenIssued TokenKind = 940
)

func (k TokenKind) String() string {
	switch k {
	case TokenAnonymous:
		return "anonymous"
	case TokenUserName:
		return "username"
	case TokenX509:
		return "x509"
	case TokenIssued:
		return "issued"
	}
	return fmt.Sprintf("token(%d)", uint32(k))
}

// Known says the token kind is one of the four.
func (k TokenKind) Known() bool {
	return k == TokenAnonymous || k == TokenUserName || k == TokenX509 || k == TokenIssued
}

// TokenOf reads a token kind back from its name.
func TokenOf(name string) (TokenKind, bool) {
	switch strings.ToLower(name) {
	case "anonymous":
		return TokenAnonymous, true
	case "username":
		return TokenUserName, true
	case "x509":
		return TokenX509, true
	case "issued":
		return TokenIssued, true
	}
	return 0, false
}

// An ActivateSessionRequest is where the user appears. Everything before it is
// application identity; this is the human or the service account.
type ActivateSessionRequest struct {
	// Kind is which sort of identity token was presented.
	Kind TokenKind
	// TokenType is the token's type identifier as it arrived, for a kind this
	// package does not name.
	TokenType NodeId
	// PolicyID is the identity token policy the token answers, which the server
	// published in its endpoint description.
	PolicyID string
	// User is the user name, for a username token. It is empty for every other
	// kind, and an empty one on a username token is a client authenticating as
	// nobody.
	User string
	// Password is the password field, kept only as its length. The value is not
	// retained: a relay has no use for it and a relay that held it would be a
	// relay whose memory is worth stealing. The length is what says whether one
	// was sent at all.
	PasswordLen int
	// PasswordAlgorithm is the URI of the algorithm the password was encrypted
	// with. Empty with a password present means the password crossed the wire as
	// the client typed it, which under mode None means it crossed in the clear.
	PasswordAlgorithm string
	// Locales is what the client asked for its text in.
	Locales []string
	// SoftwareCertificates counts the signed software certificates presented,
	// which is nearly always zero.
	SoftwareCertificates int
}

// PlaintextPassword says a username token carried a password with no encryption
// algorithm named. Under a channel with mode None that is a credential on the wire;
// under Sign it is a credential readable by anything on the path, this relay
// included.
func (a *ActivateSessionRequest) PlaintextPassword() bool {
	return a.Kind == TokenUserName && a.PasswordLen > 0 && a.PasswordAlgorithm == ""
}

// MaxLocales bounds the locale identifiers an ActivateSession may name.
const MaxLocales = 32

// ParseActivateSession reads an ActivateSessionRequest body.
func ParseActivateSession(body []byte) (*ActivateSessionRequest, error) {
	r := &reader{b: body}
	a := &ActivateSessionRequest{}
	r.str()        // the client signature's algorithm
	r.byteString() // and the signature
	if n := r.arrayLen("software certificates"); n > 0 {
		a.SoftwareCertificates = n
		for i := 0; i < n; i++ {
			r.byteString()
			r.byteString()
			if r.err != nil {
				break
			}
		}
	}
	if n, ok := r.length("locale ids", MaxLocales); ok {
		for i := 0; i < n; i++ {
			a.Locales = append(a.Locales, r.str())
			if r.err != nil {
				break
			}
		}
	}
	// The identity token is an ExtensionObject whose type identifier says which
	// of the four kinds it is, and whose body this package reads for the one kind
	// that carries a name worth policing.
	a.TokenType = r.nodeID(true)
	enc := r.byte()
	var token []byte
	switch enc {
	case extNone:
	case extByteString, extXML:
		token = r.byteString()
	default:
		r.fail("%w: an identity token body encoding of %d", ErrEncoding, enc)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	if a.TokenType.Namespace == 0 {
		a.Kind = TokenKind(a.TokenType.Numeric)
	}
	// The token body is read with its own cursor. A malformed one is reported as
	// an error on the whole message rather than left as a half-filled structure,
	// because "the user is unknown" and "there is no user" must not look alike.
	tr := &reader{b: token}
	switch a.Kind {
	case TokenAnonymous:
		a.PolicyID = tr.str()
	case TokenUserName:
		a.PolicyID = tr.str()
		a.User = tr.str()
		a.PasswordLen = len(tr.byteString())
		a.PasswordAlgorithm = tr.str()
	case TokenX509:
		a.PolicyID = tr.str()
		tr.byteString() // the user's certificate
	case TokenIssued:
		a.PolicyID = tr.str()
		tr.byteString() // the token data
		tr.str()        // and its encryption algorithm
	}
	if err := tr.done(); err != nil {
		return nil, fmt.Errorf("identity token: %w", err)
	}
	return a, nil
}

// A SubscriptionRequest is a CreateSubscription: how often the server should
// publish, and how much.
//
// The interval is the field a relay bounds. A subscription with a one-millisecond
// publishing interval over a thousand monitored items is a server asked to send a
// thousand values a millisecond, which is a denial of service written in valid
// protocol — and unlike a flood it comes from one legitimate session.
type SubscriptionRequest struct {
	// Interval is the publishing interval the client asks for, in milliseconds.
	// Zero means as fast as the server can.
	Interval float64
	// Lifetime and KeepAlive are counts of publishing intervals.
	Lifetime  uint32
	KeepAlive uint32
	// MaxNotifications bounds the notifications in one publish, and zero means
	// the client sets no bound.
	MaxNotifications uint32
	// Enabled says publishing starts immediately.
	Enabled bool
	// Priority is 0 to 255, and a client setting 255 is asking to be served
	// before every other session on the server.
	Priority byte
}

// ParseSubscription reads a CreateSubscriptionRequest body.
func ParseSubscription(body []byte) (*SubscriptionRequest, error) {
	r := &reader{b: body}
	s := &SubscriptionRequest{
		Interval:         r.double(),
		Lifetime:         r.uint32(),
		KeepAlive:        r.uint32(),
		MaxNotifications: r.uint32(),
		Enabled:          r.boolean(),
		Priority:         r.byte(),
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return s, nil
}

// A MonitoredItem is one thing a subscription watches.
type MonitoredItem struct {
	// Item is the node and attribute being watched.
	Item ValueID
	// Mode is 0 disabled, 1 sampling, 2 reporting.
	Mode uint32
	// Sampling is the sampling interval in milliseconds; -1 means the
	// subscription's publishing interval and 0 means as fast as possible.
	Sampling float64
	// Filter is the type identifier of the filter, if any: a data change filter,
	// an event filter, an aggregate filter.
	Filter NodeId
	// Queue is how many samples the server should hold per item.
	Queue uint32
	// DiscardOldest says which end of a full queue to drop.
	DiscardOldest bool
}

// A MonitoredItemsRequest is a CreateMonitoredItems: the items added to a
// subscription, which is where the fan-out of a subscription is decided.
type MonitoredItemsRequest struct {
	Subscription uint32
	Timestamps   uint32
	Items        []MonitoredItem
}

// ParseMonitoredItems reads a CreateMonitoredItemsRequest body.
func ParseMonitoredItems(body []byte) (*MonitoredItemsRequest, error) {
	r := &reader{b: body}
	m := &MonitoredItemsRequest{Subscription: r.uint32(), Timestamps: r.uint32()}
	n := r.arrayLen("items to create")
	for i := 0; i < n; i++ {
		it := MonitoredItem{}
		it.Item = r.valueID()
		it.Mode = r.uint32()
		r.uint32() // the client handle
		it.Sampling = r.double()
		it.Filter = r.extensionObject(1)
		it.Queue = r.uint32()
		it.DiscardOldest = r.boolean()
		if r.err != nil {
			break
		}
		m.Items = append(m.Items, it)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return m, nil
}
