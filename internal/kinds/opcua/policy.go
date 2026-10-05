package opcua

import (
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/numrange"
	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy, in the terms a plant's own drawings use.
//
// OPC UA is the first industrial protocol in this tree that was designed with
// security in it, and the policy is shaped around what that leaves a relay to do.
// It decides in four places, in the order a connection reaches them.
//
// **The transport.** A Hello names an endpoint and proposes four sizes, and the
// sizes are a negotiation whose answer is the minimum of the two ends' proposals —
// so a relay that passed both directions through unchanged would have let the ends
// agree on a chunk larger than its own buffer, after which every large request is
// one it has to refuse in the middle. Refusing here is cheap: nothing has been
// dialled and nothing has been agreed.
//
// **The channel.** An OpenSecureChannel names a security policy in its header and
// a message security mode in its body, and between them they decide both how strong
// the cryptography is and whether there is a readable body at all. This is where
// most of the value is, because the fields are in the clear by construction and a
// listener that admits one policy in one mode from named applications has excluded
// most of what goes wrong without naming a single node.
//
// **The session.** CreateSession names an application and carries its certificate;
// ActivateSession names a user. The application URI must also be in the
// certificate — a server checks that and so does this, which is the cheapest
// identity check the protocol has.
//
// **The service call.** Which service, which nodes, which attributes, which
// methods, and how many operations in one request. This layer applies where the
// channel left the body readable, which is modes none and sign and not
// sign_and_encrypt — and that is a property of the channel rather than a gap in the
// policy, stated here and warned about at load rather than discovered in the field.

// Decision is what the policy says about one thing a client did.
type Decision struct {
	Allow          bool
	Reason, Detail string
	// Hard says the refusal stands even in monitor or shadow mode. It is set for
	// the decisions that are not opinions: a client the lists refuse, a message
	// the relay could not read, a bound, and every service that changes the
	// plant — because a Write forwarded so that it could be written down is a
	// moved actuator.
	Hard bool
	Rule string
	// Comment is the matched rule's own note, carried into the log for the change
	// record a plant keeps.
	Comment string
	// Status is the OPC UA status code a refusal answers with, so the client's own
	// library reports the refusal a server would have given rather than a
	// timeout.
	Status uint32
}

func hard(reason, detail string, status uint32) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true, Status: status}
}

func refuse(reason, detail string, status uint32) Decision {
	return Decision{Reason: reason, Detail: detail, Status: status}
}

func allowed() Decision { return Decision{Allow: true} }

// Session is what the policy knows about a connection, built up as the handshake
// goes and then fixed.
//
// It is a value rather than a pointer into the connection's own state because the
// policy must decide about a snapshot: a request is decided against the session as
// it was when the request arrived, and a session that changed underneath a decision
// would be a decision about something else.
type Session struct {
	IP netip.Addr
	// Endpoint is the URL the client named in its Hello, and Hello says whether
	// one arrived: a rule about endpoints must not match a session that named
	// none.
	Endpoint string
	Hello    bool
	// Policy and Mode are what secures the channel. Secured says whether an
	// OpenSecureChannel has been read — before it has, Mode is invalid rather
	// than none, which is the distinction between "no protection" and "not yet
	// agreed".
	Policy  wire.SecurityPolicy
	Mode    wire.MessageSecurityMode
	Secured bool
	// Channel and Token identify the key material in force.
	Channel, Token uint32
	// ApplicationURI, SessionName and CertURIs come from CreateSession.
	// CertURIs are the URIs in the certificate it presented, which is what the
	// application URI is checked against.
	ApplicationURI string
	SessionName    string
	CertURIs       []string
	HasCert        bool
	Created        bool
	// User, TokenKind and Activated come from ActivateSession.
	User      string
	TokenKind wire.TokenKind
	Activated bool
	// Subscriptions is how many this session holds.
	Subscriptions int
	At            time.Time
}

// Readable says the channel leaves a body this relay can parse, which is the
// question every service-level rule depends on.
func (s Session) Readable() bool { return s.Secured && s.Mode.Readable() }

type policy struct {
	allowIPs, denyIPs []netip.Prefix
	endpoints         []string
	reverseHello      bool

	policies, denyPolicies map[wire.SecurityPolicy]bool
	deprecated             bool
	modes                  map[wire.MessageSecurityMode]bool
	readableOnly           bool
	maxLifetime            time.Duration

	appURIs     []string
	certURI     bool
	needCert    bool
	tokenKinds  map[wire.TokenKind]bool
	users       []string
	denyUsers   []string
	noPlaintext bool

	readOnly               bool
	services, denyServices map[wire.Service]bool
	namespaces             numrange.Set
	nodes, writeNodes      []string
	denyNodes              []string
	methods, denyMethods   []string
	attrs, writeAttrs      map[wire.Attribute]bool

	maxOps, maxWriteOps   int
	maxMonitored          int
	minPublish, minSample time.Duration
	maxSubs               int

	rules []*rule

	allowByDef bool
	respond    string
	now        func() time.Time
}

type rule struct {
	name    string
	comment string
	action  string
	observe bool

	clients    []netip.Prefix
	appURIs    []string
	users      []string
	tokenKinds map[wire.TokenKind]bool
	policies   map[wire.SecurityPolicy]bool
	modes      map[wire.MessageSecurityMode]bool
	sched      *schedule.Window

	services, denyServices map[wire.Service]bool
	namespaces             numrange.Set
	nodes, writeNodes      []string
	denyNodes              []string
	methods, denyMethods   []string
	attrs, writeAttrs      map[wire.Attribute]bool
	maxOps                 int
}

// The defaults, which are what an HMI does.
//
// The list is a positive one and it is deliberately not "everything that does not
// write": it is the services a client that reads a plant and subscribes to it
// actually calls. A service nobody named is refused, which is what makes adding a
// service to a deployment a decision somebody wrote down.
var hmiServices = []wire.Service{
	// Discovery and the session, without which nothing else happens.
	wire.SvcFindServers, wire.SvcGetEndpoints,
	wire.SvcOpenChannel, wire.SvcCloseChannel,
	wire.SvcCreateSession, wire.SvcActivateSession, wire.SvcCloseSession,
	wire.SvcCancel,
	// Reading and navigating.
	wire.SvcRead, wire.SvcHistoryRead, wire.SvcBrowse, wire.SvcBrowseNext,
	wire.SvcTranslatePaths, wire.SvcRegisterNodes, wire.SvcUnregisterNodes,
	// Subscribing, which is how an HMI gets its values and is the reason a
	// read-only listener still has to allow something that changes server state.
	wire.SvcCreateSubscription, wire.SvcModifySubscription,
	wire.SvcSetPublishingMode, wire.SvcDeleteSubscriptions,
	wire.SvcCreateMonitored, wire.SvcModifyMonitored,
	wire.SvcSetMonitoringMode, wire.SvcDeleteMonitored,
	wire.SvcPublish, wire.SvcRepublish,
}

// currentPolicies are the three IEC 62541 has not withdrawn, and the default.
var currentPolicies = []wire.SecurityPolicy{
	wire.PolicyBasic256Sha256, wire.PolicyAes128Sha256RsaOaep, wire.PolicyAes256Sha256RsaPss,
}

func compile(m *config.OPCUAListener, now func() time.Time) (*policy, error) {
	if now == nil {
		now = time.Now
	}
	p := &policy{
		reverseHello: m.AllowReverseHello,
		deprecated:   m.AllowDeprecatedPolicies,
		readableOnly: m.RequireReadableBodies,
		maxLifetime:  m.MaxTokenLifetime.D(),
		certURI:      m.RequireCertificateURI == nil || *m.RequireCertificateURI,
		needCert:     m.RequireClientCertificate == nil || *m.RequireClientCertificate,
		noPlaintext:  m.RefusePlaintextPasswords == nil || *m.RefusePlaintextPasswords,
		readOnly:     m.ReadOnly,
		maxOps:       m.MaxOperations,
		maxWriteOps:  m.MaxWriteOperations,
		maxMonitored: m.MaxMonitoredItems,
		minPublish:   m.MinPublishingInterval.D(),
		minSample:    m.MinSamplingInterval.D(),
		maxSubs:      m.MaxSubscriptions,
		allowByDef:   m.DefaultAction == "allow",
		respond:      m.DenyResponse,
		now:          now,
		endpoints:    m.Endpoints,
		appURIs:      m.ApplicationURIs,
		users:        m.Users,
		denyUsers:    m.DenyUsers,
		nodes:        m.Nodes,
		writeNodes:   m.WriteNodes,
		denyNodes:    m.DenyNodes,
		methods:      m.Methods,
		denyMethods:  m.DenyMethods,
	}
	if p.respond == "" {
		p.respond = "fault"
	}
	p.allowIPs = netutil.ParsePrefixes(m.AllowClients)
	p.denyIPs = netutil.ParsePrefixes(m.DenyClients)
	var err error
	if p.policies, err = policySet(m.SecurityPolicies, currentPolicies); err != nil {
		return nil, fmt.Errorf("security_policies: %w", err)
	}
	if p.denyPolicies, err = policySet(m.DenySecurityPolicies, nil); err != nil {
		return nil, fmt.Errorf("deny_security_policies: %w", err)
	}
	if p.modes, err = modeSet(m.SecurityModes,
		[]wire.MessageSecurityMode{wire.ModeSign, wire.ModeSignAndEncrypt}); err != nil {
		return nil, fmt.Errorf("security_modes: %w", err)
	}
	if p.tokenKinds, err = tokenSet(m.TokenKinds,
		[]wire.TokenKind{wire.TokenUserName, wire.TokenX509, wire.TokenIssued}); err != nil {
		return nil, fmt.Errorf("token_kinds: %w", err)
	}
	if p.services, err = serviceSet(m.Services, hmiServices); err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	if p.denyServices, err = serviceSet(m.DenyServices, nil); err != nil {
		return nil, fmt.Errorf("deny_services: %w", err)
	}
	if p.namespaces, err = namespaceSet(m.Namespaces); err != nil {
		return nil, fmt.Errorf("namespaces: %w", err)
	}
	if p.attrs, err = attrSet(m.Attributes, nil); err != nil {
		return nil, fmt.Errorf("attributes: %w", err)
	}
	if p.writeAttrs, err = attrSet(m.WriteAttributes,
		[]wire.Attribute{wire.AttrValue}); err != nil {
		return nil, fmt.Errorf("write_attributes: %w", err)
	}
	for i := range m.Rules {
		r, err := compileRule(&m.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(rc *config.OPCUARule) (*rule, error) {
	r := &rule{
		name: rc.Name, comment: rc.Comment, action: rc.Action,
		observe:     rc.Action == "observe",
		appURIs:     rc.ApplicationURIs,
		users:       rc.Users,
		nodes:       rc.Nodes,
		writeNodes:  rc.WriteNodes,
		denyNodes:   rc.DenyNodes,
		methods:     rc.Methods,
		denyMethods: rc.DenyMethods,
		maxOps:      rc.MaxOperations,
	}
	if r.action == "" {
		r.action = "allow"
	}
	r.clients = netutil.ParsePrefixes(rc.Clients)
	var err error
	if r.tokenKinds, err = tokenSet(rc.TokenKinds, nil); err != nil {
		return nil, fmt.Errorf("token_kinds: %w", err)
	}
	if r.policies, err = policySet(rc.SecurityPolicies, nil); err != nil {
		return nil, fmt.Errorf("security_policies: %w", err)
	}
	if r.modes, err = modeSet(rc.SecurityModes, nil); err != nil {
		return nil, fmt.Errorf("security_modes: %w", err)
	}
	if r.services, err = serviceSet(rc.Services, nil); err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	if r.denyServices, err = serviceSet(rc.DenyServices, nil); err != nil {
		return nil, fmt.Errorf("deny_services: %w", err)
	}
	if r.namespaces, err = namespaceSet(rc.Namespaces); err != nil {
		return nil, fmt.Errorf("namespaces: %w", err)
	}
	if r.attrs, err = attrSet(rc.Attributes, nil); err != nil {
		return nil, fmt.Errorf("attributes: %w", err)
	}
	if r.writeAttrs, err = attrSet(rc.WriteAttributes, nil); err != nil {
		return nil, fmt.Errorf("write_attributes: %w", err)
	}
	if rc.Schedule != nil {
		w, err := schedule.Compile(rc.Schedule)
		if err != nil {
			return nil, fmt.Errorf("schedule: %w", err)
		}
		r.sched = w
	}
	return r, nil
}

// The set builders. Each returns nil for "no opinion" when the list and the
// default are both empty, because a nil map and an empty one mean different things
// here: nil is "any", and empty would be "none", which is not a configuration
// anybody writes on purpose.

func policySet(names []string, def []wire.SecurityPolicy) (map[wire.SecurityPolicy]bool, error) {
	if len(names) == 0 {
		if len(def) == 0 {
			return nil, nil
		}
		m := make(map[wire.SecurityPolicy]bool, len(def))
		for _, p := range def {
			m[p] = true
		}
		return m, nil
	}
	m := make(map[wire.SecurityPolicy]bool, len(names))
	for _, n := range names {
		p, ok := wire.PolicyOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a security policy", n)
		}
		m[p] = true
	}
	return m, nil
}

func modeSet(names []string, def []wire.MessageSecurityMode) (map[wire.MessageSecurityMode]bool, error) {
	if len(names) == 0 {
		if len(def) == 0 {
			return nil, nil
		}
		m := make(map[wire.MessageSecurityMode]bool, len(def))
		for _, x := range def {
			m[x] = true
		}
		return m, nil
	}
	m := make(map[wire.MessageSecurityMode]bool, len(names))
	for _, n := range names {
		x, ok := wire.ModeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a message security mode", n)
		}
		m[x] = true
	}
	return m, nil
}

func tokenSet(names []string, def []wire.TokenKind) (map[wire.TokenKind]bool, error) {
	if len(names) == 0 {
		if len(def) == 0 {
			return nil, nil
		}
		m := make(map[wire.TokenKind]bool, len(def))
		for _, k := range def {
			m[k] = true
		}
		return m, nil
	}
	m := make(map[wire.TokenKind]bool, len(names))
	for _, n := range names {
		k, ok := wire.TokenOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not an identity token kind", n)
		}
		m[k] = true
	}
	return m, nil
}

func serviceSet(names []string, def []wire.Service) (map[wire.Service]bool, error) {
	if len(names) == 0 {
		if len(def) == 0 {
			return nil, nil
		}
		m := make(map[wire.Service]bool, len(def))
		for _, s := range def {
			m[s] = true
		}
		return m, nil
	}
	m := make(map[wire.Service]bool, len(names))
	for _, n := range names {
		s, ok := wire.ServiceOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a service", n)
		}
		m[s] = true
	}
	return m, nil
}

func attrSet(names []string, def []wire.Attribute) (map[wire.Attribute]bool, error) {
	if len(names) == 0 {
		if len(def) == 0 {
			return nil, nil
		}
		m := make(map[wire.Attribute]bool, len(def))
		for _, a := range def {
			m[a] = true
		}
		return m, nil
	}
	m := make(map[wire.Attribute]bool, len(names))
	for _, n := range names {
		a, ok := wire.AttributeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a node attribute", n)
		}
		m[a] = true
	}
	return m, nil
}

// namespaceSet compiles a namespace list, which is indices and ranges.
//
// **Not URIs**, and that is worth stating because the portable form would be the
// better one and the protocol does not offer it here. A namespace URI can only
// appear in an *ExpandedNodeId*, and the node a Read, a Write, a Browse or a Call
// names is a plain NodeId — so on the wire a request identifies its namespace by
// index and by nothing else. A relay cannot translate: the index-to-URI mapping is
// the server's own NamespaceArray (ns=0;i=2255), which this relay would have to read
// and keep, and that is learning rather than policy.
//
// What follows from it is a real caveat rather than a hidden one: an index is
// meaningful only against the table it came from, and a firmware update can reorder
// that table. A namespace list is a list to review after one.
func namespaceSet(list []string) (numrange.Set, error) {
	if len(list) == 0 {
		return nil, nil
	}
	return numrange.Parse("namespace", list, wire.MaxNamespaces-1)
}

// matchGlob is the pattern match every name-shaped list here uses.
//
// The brackets are made literal first, for the same reason the DHCPv6 kind does
// it: path.Match reads "[" as the start of a character class, and a node
// identifier like "ns=4;s=Tank[1]/Level" is a perfectly ordinary one that would
// otherwise match nothing while looking like it should.
func matchGlob(patterns []string, got string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, err := path.Match(literalBrackets(p), got); err == nil && ok {
			return true
		}
		if p == got {
			return true
		}
	}
	return false
}

// matchedGlob is matchGlob for a deny list, where an empty list must match
// nothing rather than everything.
func matchedGlob(patterns []string, got string) bool {
	if len(patterns) == 0 {
		return false
	}
	return matchGlob(patterns, got)
}

func literalBrackets(pat string) string {
	if !strings.ContainsAny(pat, "[]") {
		return pat
	}
	var b strings.Builder
	b.Grow(len(pat) + 8)
	for _, r := range pat {
		switch r {
		case '[', ']':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Connect decides about a client before anything has been read from it.
func (p *policy) Connect(s Session) Decision {
	if netutil.Contains(p.denyIPs, s.IP) {
		return hard("client_denied", s.IP.String(), wire.StatusBadSecurityChecksFailed)
	}
	if len(p.allowIPs) > 0 && !netutil.Contains(p.allowIPs, s.IP) {
		return hard("client_not_allowed", s.IP.String(), wire.StatusBadSecurityChecksFailed)
	}
	return allowed()
}

// Hello decides about the transport handshake.
//
// The sizes are checked here rather than left to the two ends, because the answer
// to the negotiation is the minimum of the proposals: a relay that forwarded both
// directions unchanged would find the ends had agreed on a chunk larger than its
// own buffer, and would then be refusing large requests in the middle of a plant's
// working day rather than at the point where refusing costs nothing.
func (p *policy) Hello(s Session, h *wire.HelloBody) Decision {
	if err := h.Acceptable(); err != nil {
		return hard("hello_unacceptable", err.Error(), wire.StatusBadTCPMessageTooLarge)
	}
	if !matchGlob(p.endpoints, h.EndpointURL) {
		return refuse("endpoint_not_allowed", h.EndpointURL, wire.StatusBadTCPEndpointURLInvalid)
	}
	return allowed()
}

// ReverseHello decides about a server dialling outward.
func (p *policy) ReverseHello(h *wire.ReverseHelloBody) Decision {
	if !p.reverseHello {
		return hard("reverse_hello", h.ServerURI, wire.StatusBadTCPMessageTypeInvalid)
	}
	if !matchGlob(p.endpoints, h.EndpointURL) {
		return refuse("endpoint_not_allowed", h.EndpointURL, wire.StatusBadTCPEndpointURLInvalid)
	}
	return allowed()
}

// Channel decides about an OpenSecureChannel: the policy from the header and the
// mode from the body.
//
// The two are decided together because neither is enough on its own. A listener
// that checked only the policy would allow Basic256Sha256 with mode none, which is
// a channel with a strong cipher suite and nothing encrypted; one that checked only
// the mode would allow sign_and_encrypt over SHA-1.
func (p *policy) Channel(s Session, pol wire.SecurityPolicy, o *wire.OpenChannelRequest) Decision {
	if !pol.Known() {
		return hard("security_policy_unknown", pol.Short(), wire.StatusBadSecurityPolicyRejected)
	}
	if p.denyPolicies[pol] {
		return hard("security_policy_denied", pol.Short(), wire.StatusBadSecurityPolicyRejected)
	}
	if pol.Deprecated() && !p.deprecated {
		// Named separately from the allow list so that the log line says what is
		// wrong with it rather than only that it was not named: these two are
		// SHA-1 based and withdrawn, and an operator reading the refusal should
		// be told that rather than left to look it up.
		return refuse("security_policy_deprecated", pol.Short(), wire.StatusBadSecurityPolicyRejected)
	}
	if p.policies != nil && !p.policies[pol] {
		return refuse("security_policy_not_allowed", pol.Short(), wire.StatusBadSecurityPolicyRejected)
	}
	if !o.Mode.Known() {
		return hard("security_mode_unknown", o.Mode.String(), wire.StatusBadSecurityModeRejected)
	}
	if p.modes != nil && !p.modes[o.Mode] {
		return refuse("security_mode_not_allowed", o.Mode.String(), wire.StatusBadSecurityModeRejected)
	}
	if p.readableOnly && !o.Mode.Readable() {
		// The listener said its service rules must apply, and this mode makes
		// them inert. Refusing is the honest outcome: the alternative is a
		// channel this relay carries while enforcing none of what it was
		// configured to enforce.
		return refuse("body_not_readable", o.Mode.String(), wire.StatusBadSecurityModeRejected)
	}
	// A policy of None with a nonce is a client that thinks it is securing
	// something. It is worth refusing rather than passing, because the client's
	// own operator believes the channel is protected.
	if pol == wire.PolicyNone && len(o.Nonce) > 0 {
		return refuse("nonce_without_policy", fmt.Sprintf("%d octets", len(o.Nonce)),
			wire.StatusBadSecurityChecksFailed)
	}
	if p.maxLifetime > 0 && time.Duration(o.Lifetime)*time.Millisecond > p.maxLifetime {
		return refuse("token_lifetime",
			fmt.Sprintf("%dms, past %s", o.Lifetime, p.maxLifetime),
			wire.StatusBadSecurityChecksFailed)
	}
	return allowed()
}

// CreateSession decides about the application on the other end.
func (p *policy) CreateSession(s Session, c *wire.CreateSessionRequest) Decision {
	if p.needCert && len(c.Certificate) == 0 {
		return refuse("no_client_certificate", c.ApplicationURI,
			wire.StatusBadCertificateUseNotAllowed)
	}
	if !matchGlob(p.appURIs, c.ApplicationURI) {
		return refuse("application_not_allowed", c.ApplicationURI,
			wire.StatusBadSecurityChecksFailed)
	}
	// The application type: 0 server, 1 client, 2 both, 3 discovery server. A
	// CreateSession from something calling itself a server is a peer describing
	// itself as the thing on the other side of this relay.
	if c.ApplicationType == 0 {
		return refuse("application_type", "server", wire.StatusBadSecurityChecksFailed)
	}
	return allowed()
}

// CertificateURI checks the application URI against the certificate that carried
// it, which is the cheapest identity check in the protocol.
//
// It is separate from CreateSession because the certificate has to be parsed to do
// it, and parsing a peer's certificate is the relay's business rather than the
// policy's: the policy is handed the URIs that were in it.
func (p *policy) CertificateURI(s Session) Decision {
	if !p.certURI || !s.HasCert || s.ApplicationURI == "" {
		return allowed()
	}
	for _, u := range s.CertURIs {
		if u == s.ApplicationURI {
			return allowed()
		}
	}
	return refuse("certificate_uri_mismatch", s.ApplicationURI,
		wire.StatusBadCertificateUseNotAllowed)
}

// ActivateSession decides about the user.
func (p *policy) ActivateSession(s Session, a *wire.ActivateSessionRequest) Decision {
	if !a.Kind.Known() {
		return hard("token_kind_unknown", a.TokenType.Key(), wire.StatusBadUserAccessDenied)
	}
	if p.tokenKinds != nil && !p.tokenKinds[a.Kind] {
		return refuse("token_kind_not_allowed", a.Kind.String(), wire.StatusBadUserAccessDenied)
	}
	if p.noPlaintext && a.PlaintextPassword() {
		// Under mode none this password is on the wire as the operator typed it;
		// under sign it is readable by anything on the path, this relay
		// included. Both are worth refusing by default, and the second is the
		// reason it is not left to the mode.
		return refuse("plaintext_password", a.User, wire.StatusBadUserAccessDenied)
	}
	if a.Kind == wire.TokenUserName {
		if matchedGlob(p.denyUsers, a.User) {
			return hard("user_denied", a.User, wire.StatusBadUserAccessDenied)
		}
		if !matchGlob(p.users, a.User) {
			return refuse("user_not_allowed", a.User, wire.StatusBadUserAccessDenied)
		}
		if a.User == "" {
			// A username token with no name is a client authenticating as
			// nobody, which is not the same as an anonymous token: it claims a
			// policy that names users and then names none.
			return refuse("empty_user", a.PolicyID, wire.StatusBadUserAccessDenied)
		}
	}
	return allowed()
}

// Request decides about one service message whose body was readable.
//
// The order is: the deny lists, which no rule can override; then read_only, which
// is the same; then the matching rule or the default. That order is what makes
// `read_only` and the deny lists mean what they say — a listener whose read-only
// promise one rule could write through is not a read-only listener.
func (p *policy) Request(s Session, c *wire.ServiceCall) Decision {
	svc := c.Service
	if !svc.Known() {
		// A service this relay has not classified. Forwarding it would be
		// forwarding something to a plant with no policy applied to it at all,
		// and the identifier is in the message so the refusal can name it.
		return hard("service_unknown", c.TypeID.Key(), wire.StatusBadServiceUnsupported)
	}
	if p.denyServices[svc] {
		return hard("service_denied", svc.String(), wire.StatusBadServiceUnsupported)
	}
	if p.readOnly && svc.Writes() {
		return hard("read_only", svc.String(), wire.StatusBadNotWritable)
	}
	r := p.match(s, svc)
	if r != nil && r.action == "deny" {
		return p.hardenChange(svc, Decision{Reason: "rule_denied", Detail: svc.String(), Rule: r.name,
			Comment: r.comment, Status: wire.StatusBadServiceUnsupported})
	}
	if d := p.serviceAllowed(r, svc); !d.Allow {
		return p.hardenChange(svc, d)
	}
	if r == nil && !p.allowByDef {
		return p.hardenChange(svc, Decision{Reason: "no_rule", Detail: svc.String(),
			Status: wire.StatusBadServiceUnsupported})
	}
	d := allowed()
	if r != nil {
		d.Rule, d.Comment = r.name, r.comment
	}
	return d
}

// serviceAllowed checks the service against the listener's list and the rule's.
func (p *policy) serviceAllowed(r *rule, svc wire.Service) Decision {
	if r != nil && r.denyServices[svc] {
		return Decision{Reason: "service_denied", Detail: svc.String(), Rule: r.name,
			Comment: r.comment, Hard: true, Status: wire.StatusBadServiceUnsupported}
	}
	if p.services != nil && !p.services[svc] {
		return refuse("service_not_allowed", svc.String(), wire.StatusBadServiceUnsupported)
	}
	if r != nil && r.services != nil && !r.services[svc] {
		return Decision{Reason: "service_not_allowed", Detail: svc.String(), Rule: r.name,
			Comment: r.comment, Status: wire.StatusBadServiceUnsupported}
	}
	return allowed()
}

// match finds the first rule that selects this session and service.
func (p *policy) match(s Session, svc wire.Service) *rule {
	for _, r := range p.rules {
		if !r.selects(s, svc, p.now()) {
			continue
		}
		if r.observe {
			// An observe rule logs and counts and then keeps looking, which is
			// how a rule is tried on live traffic before it decides anything.
			continue
		}
		return r
	}
	return nil
}

func (r *rule) selects(s Session, svc wire.Service, at time.Time) bool {
	if len(r.clients) > 0 && !netutil.Contains(r.clients, s.IP) {
		return false
	}
	if len(r.appURIs) > 0 && !matchGlob(r.appURIs, s.ApplicationURI) {
		return false
	}
	// The Activated and Secured guards, and which of them are load-bearing.
	//
	// For the *user* the guard does work: a rule written `users: ["*"]` matches an
	// empty name, so without it such a rule would decide about every message sent
	// before any session existed. For the three enum sets it is belt-and-braces —
	// an unactivated session's token kind is zero and an unsecured one's policy is
	// empty and its mode is invalid, none of which any configured set contains.
	// They are written the same way on purpose: a reader should not have to work
	// out which of four similar lines is the one that matters.
	if len(r.users) > 0 {
		if !s.Activated || !matchGlob(r.users, s.User) {
			return false
		}
	}
	if r.tokenKinds != nil && (!s.Activated || !r.tokenKinds[s.TokenKind]) {
		return false
	}
	if r.policies != nil && (!s.Secured || !r.policies[s.Policy]) {
		return false
	}
	if r.modes != nil && (!s.Secured || !r.modes[s.Mode]) {
		return false
	}
	if r.services != nil && !r.services[svc] && !r.denyServices[svc] {
		// A rule that names services selects only those, so a rule about writes
		// does not decide about reads.
		return false
	}
	if r.sched != nil && !r.sched.InForce(at) {
		return false
	}
	return true
}

// ObserveRule finds an observe rule that selects this traffic, for the log line
// that says a rule would have matched.
func (p *policy) ObserveRule(s Session, svc wire.Service) *rule {
	for _, r := range p.rules {
		if r.observe && r.selects(s, svc, p.now()) {
			return r
		}
	}
	return nil
}

// Name and Comment let the relay log an observe rule without reaching inside it.
func (r *rule) Name() string    { return r.name }
func (r *rule) Comment() string { return r.comment }

// Nodes decides about the nodes and attributes one request names.
//
// It takes the operations as a list rather than per node because the bound on the
// count is part of the same decision: a Read naming ten thousand nodes is one
// request and ten thousand operations, and refusing the eleventh node while
// forwarding the first ten thousand would be worse than refusing the request.
type Operation struct {
	Node NodeRef
	Attr wire.Attribute
	// Write says this operation changes the attribute rather than reading it,
	// which is what selects the write lists.
	Write bool
	// Method is the method a Call names, which is checked separately from the
	// object it is on.
	Method *NodeRef
}

// NodeRef is a node as the policy compares it: the canonical key and the namespace
// index a rule may name on its own.
type NodeRef struct {
	Key       string
	Namespace uint16
}

// RefOf makes a NodeRef from a parsed node id.
func RefOf(n wire.NodeId) NodeRef {
	return NodeRef{Key: n.Key(), Namespace: n.Namespace}
}

// Operations decides about the operations one request carries.
func (p *policy) Operations(s Session, svc wire.Service, ops []Operation) Decision {
	r := p.match(s, svc)
	if n := p.opBound(r, svc); n > 0 && len(ops) > n {
		return hard("too_many_operations", fmt.Sprintf("%d, past %d", len(ops), n),
			wire.StatusBadTooManyOperations)
	}
	for _, op := range ops {
		if d := p.operation(r, op); !d.Allow {
			return p.hardenChange(svc, d)
		}
	}
	return allowed()
}

// hardenChange makes a refusal hard when the service it refuses would change
// something, so that the refusal holds in monitor_only and shadow mode.
//
// That is the documented contract: monitor_only "evaluates and enforces nothing,
// except the hard decisions: the client list, a message the relay could not read,
// the bounds, and every service that changes anything -- because a Write
// forwarded so it could be written down is a moved actuator." The node,
// attribute, method and service allow-lists all produced soft refusals, so a
// Write to a node outside them was counted as a would-be refusal and sent to the
// server anyway. read_only was hard and so did hold; the allow-lists, which are
// the normal way an OPC UA policy is written, did not.
//
// It is applied where the decision is made rather than where it is acted on,
// because whether a refusal stands depends on what the service does and only the
// policy has both in hand. The sibling kinds do the same: mms in decideTarget's
// caller, s7 in harden.
func (p *policy) hardenChange(svc wire.Service, d Decision) Decision {
	if !d.Allow && (svc.Writes() || svc.Control()) {
		d.Hard = true
	}
	return d
}

// opBound is the operation bound in force: the rule's when it names one, the
// listener's write bound for a writing service, and the listener's own otherwise.
func (p *policy) opBound(r *rule, svc wire.Service) int {
	if r != nil && r.maxOps > 0 {
		return r.maxOps
	}
	if svc.Writes() && p.maxWriteOps > 0 {
		return p.maxWriteOps
	}
	return p.maxOps
}

func (p *policy) operation(r *rule, op Operation) Decision {
	if matchedGlob(p.denyNodes, op.Node.Key) {
		return hard("node_denied", op.Node.Key, wire.StatusBadNodeIDUnknown)
	}
	if r != nil && matchedGlob(r.denyNodes, op.Node.Key) {
		return Decision{Reason: "node_denied", Detail: op.Node.Key, Rule: r.name,
			Comment: r.comment, Hard: true, Status: wire.StatusBadNodeIDUnknown}
	}
	if !p.namespaceAllowed(r, op.Node) {
		return refuse("namespace_not_allowed", op.Node.Key, wire.StatusBadNodeIDUnknown)
	}
	nodes := p.nodes
	if op.Write && len(p.writeNodes) > 0 {
		nodes = p.writeNodes
	}
	if !matchGlob(nodes, op.Node.Key) {
		return refuse("node_not_allowed", op.Node.Key, wire.StatusBadNodeIDUnknown)
	}
	if r != nil {
		rn := r.nodes
		if op.Write && len(r.writeNodes) > 0 {
			rn = r.writeNodes
		}
		if !matchGlob(rn, op.Node.Key) {
			return Decision{Reason: "node_not_allowed", Detail: op.Node.Key, Rule: r.name,
				Comment: r.comment, Status: wire.StatusBadNodeIDUnknown}
		}
	}
	if d := p.attrAllowed(r, op); !d.Allow {
		return d
	}
	if op.Method != nil {
		return p.methodAllowed(r, *op.Method)
	}
	return allowed()
}

// attrAllowed checks the attribute, which is where reading a process value parts
// company with changing who may write it.
func (p *policy) attrAllowed(r *rule, op Operation) Decision {
	if op.Attr == 0 {
		// No attribute in this operation: a Call names an object and a method and
		// no attribute at all.
		return allowed()
	}
	if !op.Attr.Known() {
		return hard("attribute_unknown", op.Attr.String(), wire.StatusBadNodeIDUnknown)
	}
	set, rset := p.attrs, map[wire.Attribute]bool(nil)
	if op.Write {
		set = p.writeAttrs
	}
	if r != nil {
		rset = r.attrs
		if op.Write {
			rset = r.writeAttrs
		}
	}
	if set != nil && !set[op.Attr] {
		reason := "attribute_not_allowed"
		if op.Write && op.Attr.Permission() {
			// Named for what it is. A write to access_level is a privilege
			// change however ordinary the node looks, and a refusal reading
			// "attribute_not_allowed" would not tell an operator that.
			reason = "permission_write"
		}
		return refuse(reason, op.Attr.String(), wire.StatusBadNotWritable)
	}
	if rset != nil && !rset[op.Attr] {
		return Decision{Reason: "attribute_not_allowed", Detail: op.Attr.String(),
			Rule: r.name, Comment: r.comment, Status: wire.StatusBadNotWritable}
	}
	return allowed()
}

func (p *policy) methodAllowed(r *rule, m NodeRef) Decision {
	if matchedGlob(p.denyMethods, m.Key) {
		return hard("method_denied", m.Key, wire.StatusBadUserAccessDenied)
	}
	if r != nil && matchedGlob(r.denyMethods, m.Key) {
		return Decision{Reason: "method_denied", Detail: m.Key, Rule: r.name,
			Comment: r.comment, Hard: true, Status: wire.StatusBadUserAccessDenied}
	}
	if !matchGlob(p.methods, m.Key) {
		return refuse("method_not_allowed", m.Key, wire.StatusBadUserAccessDenied)
	}
	if r != nil && !matchGlob(r.methods, m.Key) {
		return Decision{Reason: "method_not_allowed", Detail: m.Key, Rule: r.name,
			Comment: r.comment, Status: wire.StatusBadUserAccessDenied}
	}
	return allowed()
}

// namespaceAllowed checks the namespace index against the listener's list and the
// rule's.
func (p *policy) namespaceAllowed(r *rule, n NodeRef) bool {
	if p.namespaces != nil && !p.namespaces.Has(int(n.Namespace)) {
		return false
	}
	if r == nil || r.namespaces == nil {
		return true
	}
	return r.namespaces.Has(int(n.Namespace))
}

// Subscription decides about a CreateSubscription.
//
// The publishing interval is the bound that matters most on this protocol, because
// the amplification is arithmetic rather than accidental: a one-millisecond
// interval over a thousand monitored items is a server asked to send a thousand
// values a millisecond, from one legitimate session, in valid protocol.
func (p *policy) Subscription(s Session, q *wire.SubscriptionRequest) Decision {
	if p.maxSubs > 0 && s.Subscriptions >= p.maxSubs {
		return hard("too_many_subscriptions",
			fmt.Sprintf("%d, past %d", s.Subscriptions, p.maxSubs),
			wire.StatusBadTooManyOperations)
	}
	if p.minPublish > 0 {
		// Zero means "as fast as the server can", and it needs no case of its
		// own: zero milliseconds is under every positive bound, so the
		// comparison below refuses it — which is the right answer rather than a
		// coincidence, because "as fast as possible" is faster than any interval
		// a listener would name.
		d := time.Duration(q.Interval) * time.Millisecond
		if d < p.minPublish {
			return refuse("publishing_interval",
				fmt.Sprintf("%.0fms, under %s", q.Interval, p.minPublish),
				wire.StatusBadTooManyOperations)
		}
	}
	return allowed()
}

// MonitoredItems decides about a CreateMonitoredItems.
func (p *policy) MonitoredItems(s Session, m *wire.MonitoredItemsRequest) Decision {
	if p.maxMonitored > 0 && len(m.Items) > p.maxMonitored {
		return hard("too_many_monitored_items",
			fmt.Sprintf("%d, past %d", len(m.Items), p.maxMonitored),
			wire.StatusBadTooManyOperations)
	}
	if p.minSample > 0 {
		for _, it := range m.Items {
			// Minus one means the subscription's own publishing interval, which
			// is already bounded. Zero means as fast as the device will answer,
			// and like a publishing interval of zero it needs no case of its
			// own: it is under every positive bound.
			if it.Sampling < 0 {
				continue
			}
			d := time.Duration(it.Sampling) * time.Millisecond
			if d < p.minSample {
				return refuse("sampling_interval",
					fmt.Sprintf("%.0fms, under %s", it.Sampling, p.minSample),
					wire.StatusBadTooManyOperations)
			}
		}
	}
	return allowed()
}

// respondWith says how a refusal is expressed.
func (p *policy) respondWith() string { return p.respond }

// describeSizes renders a Hello's proposal for a log line.
func describeSizes(h *wire.HelloBody) string {
	return "recv=" + strconv.FormatUint(uint64(h.ReceiveBufferSize), 10) +
		" send=" + strconv.FormatUint(uint64(h.SendBufferSize), 10) +
		" max=" + strconv.FormatUint(uint64(h.MaxMessageSize), 10) +
		" chunks=" + strconv.FormatUint(uint64(h.MaxChunkCount), 10)
}
