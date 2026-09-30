package coap

import (
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"

	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy.
//
// A CoAP request says what is about to happen in three fields a relay can read:
// the method, the path and the content format. That makes this the one OT-adjacent
// protocol where a positive security model is natural rather than aspirational --
// "GET anything under /3303, PUT only /3311/0/5850" is a sentence an estate can
// actually write about its own devices, because the paths are the object model.
//
// So the request side is where most of this policy lives, which is the opposite of
// the DHCP kinds. The answer side still matters, and for one reason: the size of
// an answer relative to the question. CoAP over UDP is a reflection amplifier, and
// the bound on that is never shadowed -- a listener whose policy was being trialled
// would otherwise be a working amplifier with logging.

// Decision is what the policy says about one message.
type Decision struct {
	Allow bool
	// Rule is the rule that decided, empty for the default.
	Rule string
	// Reason and Detail name the refusal for the log and the counter.
	Reason, Detail string
	// Hard is a refusal a shadow-mode listener still enforces: a bound, an
	// amplification factor, a message two parsers would read differently, or a
	// path whose rendering would not mean what it looks like. None of those is
	// an opinion an operator can try out, because carrying one is the harm
	// rather than a note about it.
	Hard bool
	// Answer is the response code to send instead of dropping the message, and
	// zero when the right thing is silence.
	//
	// Answering matters more here than on most protocols. A Confirmable request
	// is retransmitted until something answers, so a refusal that dropped the
	// datagram would turn one refused request into four or five -- and leave the
	// device's own logs showing a timeout rather than a refusal.
	Answer wire.Code
}

func deny(reason, detail string, answer wire.Code) Decision {
	return Decision{Reason: reason, Detail: detail, Answer: answer}
}

func hard(reason, detail string, answer wire.Code) Decision {
	return Decision{Reason: reason, Detail: detail, Answer: answer, Hard: true}
}

// request is one message to decide about.
type request struct {
	from netip.Addr
	msg  *wire.Message
	// secure says the message arrived inside a DTLS session rather than in the
	// clear, which is the weakest identity this protocol offers.
	secure bool
	// identity is the security name the session's peer maps to: the name of
	// its pre-shared key identity, or of the public key this listener pinned.
	// Empty on a NoSec client and on a session that mapped to nothing.
	//
	// named is separate rather than derived, because "this listener has no
	// tables and therefore nobody has a name" and "this peer has no name"
	// are the same empty string and different facts.
	identity string
	named    bool
	at       time.Time
}

// Policy is the compiled listener policy.
type Policy struct {
	clients, notClients []netip.Prefix
	servers             []netip.Prefix

	types   map[wire.Type]bool
	methods map[wire.Code]bool

	allowPaths, denyPaths []string
	allowQueries          []string

	formats       map[uint16]bool
	unknownFormat bool

	proxying   bool
	observe    bool
	discovery  bool
	suspicious bool
	unknownOpt bool
	repeated   bool
	needToken  bool

	maxPayload  int
	maxTransfer int64
	maxBlock    int64
	maxResponse int
	factor      int

	rules        []*rule
	defaultAllow bool
	// needName refuses a message from a session that mapped to no security
	// name, which is what require_security_name decides.
	needName bool
	now      func() time.Time
}

type rule struct {
	name    string
	action  string
	clients []netip.Prefix

	methods map[wire.Code]bool
	paths   []string
	queries []string
	formats map[uint16]bool

	secureOnly bool
	// names are the security names this rule covers. A rule naming them
	// covers no message from a session without one, which is the point: a
	// rule written about an authenticated device must not apply to an
	// unauthenticated one at the same address.
	names    map[string]bool
	proxying bool
	observe  bool

	maxPayload int
	sched      *schedule.Window
}

// compile builds the policy from the configuration.
func compile(m *config.CoAPListener, now func() time.Time) (*Policy, error) {
	p := &Policy{
		allowPaths:    m.AllowPaths,
		denyPaths:     m.DenyPaths,
		allowQueries:  m.AllowQueries,
		proxying:      m.AllowProxying,
		observe:       on(m.AllowObserve),
		discovery:     on(m.AllowDiscovery),
		suspicious:    on(m.RefuseSuspiciousPaths),
		unknownOpt:    on(m.RefuseUnknownOptions),
		repeated:      on(m.RefuseRepeatedOptions),
		needToken:     m.RequireToken,
		unknownFormat: on(m.AllowUnknownContentFormats),
		maxPayload:    intOr(m.MaxPayloadBytes, 1024),
		maxTransfer:   int64(intOr(m.MaxTransferBytes, 65536)),
		maxBlock:      int64(intOr(m.MaxBlockBytes, 1024)),
		maxResponse:   intOr(m.MaxResponseBytes, wire.MaxMessage),
		factor:        m.AmplificationFactor,
		defaultAllow:  m.DefaultAction == "allow",
		needName:      m.RequiresSecurityName(),
		now:           now,
	}
	var err error
	if p.clients, err = prefixes(m.AllowClients); err != nil {
		return nil, fmt.Errorf("coap allow_clients: %w", err)
	}
	if p.notClients, err = prefixes(m.DenyClients); err != nil {
		return nil, fmt.Errorf("coap deny_clients: %w", err)
	}
	if p.servers, err = prefixes(m.AllowServers); err != nil {
		return nil, fmt.Errorf("coap allow_servers: %w", err)
	}
	if p.types, err = types(m.MessageTypes); err != nil {
		return nil, err
	}
	if p.methods, err = methods(m.Methods, defaultMethods()); err != nil {
		return nil, err
	}
	if p.formats, err = formats(m.ContentFormats); err != nil {
		return nil, err
	}
	for i := range m.Rules {
		r, err := compileRule(&m.Rules[i])
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(c *config.CoAPRule) (*rule, error) {
	r := &rule{
		name: c.Name, action: c.Action,
		paths: c.Paths, queries: c.Queries,
		secureOnly: c.SecureOnly, proxying: c.AllowProxying,
		observe:    on(c.AllowObserve),
		maxPayload: c.MaxPayloadBytes,
	}
	if len(c.SecurityNames) > 0 {
		r.names = make(map[string]bool, len(c.SecurityNames))
		for _, n := range c.SecurityNames {
			r.names[n] = true
		}
	}
	var err error
	if r.clients, err = prefixes(c.Clients); err != nil {
		return nil, fmt.Errorf("coap rule %s clients: %w", c.Name, err)
	}
	if r.methods, err = methods(c.Methods, nil); err != nil {
		return nil, fmt.Errorf("coap rule %s: %w", c.Name, err)
	}
	if r.formats, err = formats(c.ContentFormats); err != nil {
		return nil, fmt.Errorf("coap rule %s: %w", c.Name, err)
	}
	if c.Schedule != nil {
		w, err := schedule.Compile(c.Schedule)
		if err != nil {
			return nil, fmt.Errorf("coap rule %s schedule: %w", c.Name, err)
		}
		r.sched = w
	}
	return r, nil
}

// defaultMethods are the four of RFC 7252 and not the three of RFC 8132.
//
// FETCH, PATCH and iPATCH are left out of the default because each is a method
// most deployments do not use and two of them write. FETCH is the one worth
// naming: RFC 8132 puts its selector in the *payload*, so a path policy sees less
// of a FETCH than it sees of a GET, and an estate should say so on purpose rather
// than inherit it.
func defaultMethods() map[wire.Code]bool {
	return map[wire.Code]bool{wire.GET: true, wire.POST: true, wire.PUT: true, wire.DELETE: true}
}

// Client is this listener's own address policy, deny evaluated first.
func (p *Policy) Client(ip netip.Addr) bool {
	if contains(p.notClients, ip) {
		return false
	}
	if len(p.clients) == 0 {
		return true
	}
	return contains(p.clients, ip)
}

// Server says the address may answer. Empty means the endpoints of the upstream
// pool, filled in at start: an operator who wrote nothing meant the devices they
// configured, and a relay that read an empty list as "anybody" would carry an
// answer from whatever got there first.
func (p *Policy) Server(ip netip.Addr) bool {
	for _, n := range p.servers {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Decide is the policy on a message from the client side.
func (p *Policy) Decide(req request) Decision {
	m := req.msg
	switch {
	case m.Code.IsEmpty():
		// A bare acknowledgement or a reset. It carries no request, so there is
		// nothing to have a policy about, and it has to travel: a reset is how a
		// device says "stop sending me that", and a relay that swallowed one
		// would leave a notification running that the client asked to end.
		return Decision{Allow: true}
	case m.Code.IsSignalling():
		// RFC 8323's signalling belongs to CoAP over TCP, TLS and WebSockets.
		// Over UDP it is a code nothing should send and nothing will answer.
		return hard("signalling_over_datagram", m.Code.String(), 0)
	case m.Code.IsResponse():
		// A response arriving on the client side. On this protocol that is what a
		// device answering into the segment looks like from here, or something
		// aiming answers at the relay, and the two look the same.
		return hard("response_from_client_side", m.Code.String(), 0)
	case !m.Code.Known():
		return hard("unknown_method", m.Code.String(), wire.NotImplemented)
	}
	if !p.types[m.Type] {
		return deny("message_type_not_allowed", m.Type.String(), 0)
	}
	if p.needName && !req.named {
		// The listener holds a table that turns a peer into a name, and this
		// message came from one that mapped to none: a NoSec client, or a
		// session that authenticated some other way. Refused before the rules,
		// because every rule naming a security name is unmatchable for it and
		// what is left would be a policy about addresses -- which is the thing
		// putting this listener inside DTLS was meant to stop being.
		return deny("no_security_name", "", wire.Unauthorized)
	}
	if p.repeated {
		if rep := m.Repeated(); len(rep) > 0 {
			return hard("repeated_option", wire.OptionName(rep[0]), wire.BadOption)
		}
	}
	if err := m.ValidateOptions(); err != nil {
		return hard("malformed_option", err.Error(), wire.BadOption)
	}
	if p.needToken && len(m.Token) == 0 {
		// A request with no token can only be paired by its message identifier,
		// which a separate response does not carry. RFC 7252 s5.3.1 lets a
		// client send an empty token; requiring one is a decision an estate makes
		// when it wants every answer traceable to the question.
		return deny("no_token", "", wire.BadRequest)
	}
	if p.suspicious {
		if why := m.SuspiciousPath(); why != "" {
			// Refused rather than normalised. Normalising would mean deciding
			// what the device would have done with the original, and the guess is
			// the whole bug: one segment containing a slash renders as two, so a
			// rule about /sensors/* would be satisfied by a request to /config.
			return hard("suspicious_path", why, wire.BadRequest)
		}
	}
	if d, refused := p.optionRules(m); refused {
		return d
	}
	if !p.proxying && m.Proxying() {
		// The option pair that turns the far end into a forward proxy. Both are
		// checked, because Proxy-Scheme is the same request written the other way
		// and a relay that refused only Proxy-Uri would have refused nothing.
		return deny("proxying_not_allowed", proxyDetail(m), wire.ProxyingNotSupported)
	}
	if !p.observe && m.Registering() {
		return deny("observe_not_allowed", "", wire.BadOption)
	}
	if !p.discovery && m.IsWellKnownCore() {
		// The resource whose purpose is to list every other resource: the largest
		// answer on the device for the smallest question.
		return deny("discovery_not_allowed", m.Path(), wire.Forbidden)
	}
	if d, refused := p.bounds(m); refused {
		return d
	}
	if !p.methods[m.Code] {
		return deny("method_not_allowed", wire.MethodName(m.Code), wire.MethodNotAllowed)
	}
	if why := p.pathAllowed(m); why != "" {
		return deny("path_not_allowed", why, wire.Forbidden)
	}
	if why := p.queryAllowed(m, nil); why != "" {
		return deny("query_not_allowed", why, wire.BadOption)
	}
	if why := p.formatAllowed(m, nil); why != "" {
		return deny("content_format_not_allowed", why, wire.UnsupportedContentFormat)
	}
	return p.match(req)
}

// optionRules is what RFC 7252 says a proxy does with an option it cannot name,
// which is one of the few places a standard hands a relay the answer instead of a
// judgement call.
//
// The unsafe case is checked first because its answer is the stronger one: an
// option can be both, and 5.02 says "this hop will not forward your request" where
// 4.02 says "your request named something I do not support".
func (p *Policy) optionRules(m *wire.Message) (Decision, bool) {
	if !p.unknownOpt {
		return Decision{}, false
	}
	if un := m.UnknownUnSafe(); len(un) > 0 {
		return hard("unknown_unsafe_option", wire.OptionName(un[0]), wire.BadGateway), true
	}
	if un := m.UnknownCritical(); len(un) > 0 {
		return hard("unknown_critical_option", wire.OptionName(un[0]), wire.BadOption), true
	}
	return Decision{}, false
}

// bounds are the sizes, and none of them is ever shadowed.
func (p *Policy) bounds(m *wire.Message) (Decision, bool) {
	if p.maxPayload > 0 && len(m.Payload) > p.maxPayload {
		return hard("payload_too_large",
			fmt.Sprintf("%d octets", len(m.Payload)), wire.RequestEntityTooLarge), true
	}
	for _, n := range []uint16{wire.OptionBlock1, wire.OptionBlock2} {
		v, ok := m.Get(n)
		if !ok {
			continue
		}
		b, err := wire.ParseBlock(v)
		if err != nil {
			return hard("malformed_option", err.Error(), wire.BadOption), true
		}
		if p.maxBlock > 0 && b.Size() > p.maxBlock {
			return hard("block_too_large",
				fmt.Sprintf("%s of %d octets", wire.OptionName(n), b.Size()),
				wire.RequestEntityTooLarge), true
		}
	}
	// The whole transfer, which is the number that matters: a bound on one
	// datagram bounds nothing when a client can walk a device through sixty-four
	// thousand of them. Size1 and Size2 are declarations, so this refuses the
	// intent at the first block rather than the sixty-fourth thousandth.
	if p.maxTransfer > 0 {
		if n := m.TransferSize(); n > p.maxTransfer {
			return hard("transfer_too_large",
				fmt.Sprintf("%d octets", n), wire.RequestEntityTooLarge), true
		}
	}
	return Decision{}, false
}

// pathAllowed checks the path against the listener's own lists, deny first. The
// patterns are shell patterns over the whole rendered path.
//
// A rule's paths are not applied here. They select the rule (see matches), so by
// the time a rule is deciding, its paths have already matched -- and applying them
// twice would be a second check that no input could fail once the first had passed.
func (p *Policy) pathAllowed(m *wire.Message) string {
	got := m.Path()
	for _, pat := range p.denyPaths {
		if matchPath(pat, got) {
			return got + " matches " + pat
		}
	}
	if len(p.allowPaths) == 0 {
		return ""
	}
	for _, pat := range p.allowPaths {
		if matchPath(pat, got) {
			return ""
		}
	}
	return got
}

func (p *Policy) queryAllowed(m *wire.Message, r *rule) string {
	pats := p.allowQueries
	if r != nil && len(r.queries) > 0 {
		pats = r.queries
	}
	if len(pats) == 0 {
		return ""
	}
	for _, part := range m.All(wire.OptionURIQuery) {
		s := string(part)
		ok := false
		for _, pat := range pats {
			if matchPath(pat, s) {
				ok = true
				break
			}
		}
		if !ok {
			return s
		}
	}
	return ""
}

// formatAllowed checks the content format a payload declares. The option's
// absence is not a format: a request with no payload declares nothing.
func (p *Policy) formatAllowed(m *wire.Message, r *rule) string {
	set := p.formats
	if r != nil && len(r.formats) > 0 {
		set = r.formats
	}
	n, ok := m.ContentFormat()
	if !ok {
		return ""
	}
	if !p.unknownFormat && !wire.KnownContentFormat(n) {
		return wire.ContentFormatName(n)
	}
	if len(set) == 0 {
		return ""
	}
	if !set[n] {
		return wire.ContentFormatName(n)
	}
	return ""
}

// match runs the rules.
func (p *Policy) match(req request) Decision {
	for _, r := range p.rules {
		if !r.matches(req, p.now()) {
			continue
		}
		switch r.action {
		case "deny":
			return Decision{Rule: r.name, Reason: "rule", Detail: r.name, Answer: wire.Forbidden}
		case "observe":
			// Recorded and then still looking, which is how a rule is tried on
			// live traffic before it decides anything.
			continue
		}
		// An allow rule's own narrowing is checked here rather than in matches,
		// so that a request the rule is *about* is refused by the rule rather
		// than falling through to the default and being refused by nothing.
		if r.secureOnly && !req.secure {
			return Decision{Rule: r.name, Reason: "insecure_not_allowed",
				Detail: r.name, Answer: wire.Unauthorized}
		}
		if !r.proxying && req.msg.Proxying() {
			return Decision{Rule: r.name, Reason: "proxying_not_allowed",
				Detail: proxyDetail(req.msg), Answer: wire.ProxyingNotSupported}
		}
		if !r.observe && req.msg.Registering() {
			return Decision{Rule: r.name, Reason: "observe_not_allowed",
				Detail: r.name, Answer: wire.BadOption}
		}
		if r.maxPayload > 0 && len(req.msg.Payload) > r.maxPayload {
			return Decision{Rule: r.name, Reason: "payload_too_large", Hard: true,
				Detail: fmt.Sprintf("%d octets", len(req.msg.Payload)),
				Answer: wire.RequestEntityTooLarge}
		}
		// The rule's own paths are not re-checked here: matches above required
		// the path to match one of them for the rule to be selected at all, and
		// the listener's lists were applied before match was called. The query
		// and the content format below are different -- they narrow without
		// selecting, so this is the only place they are applied.
		if why := p.queryAllowed(req.msg, r); why != "" {
			return Decision{Rule: r.name, Reason: "query_not_allowed",
				Detail: why, Answer: wire.BadOption}
		}
		if why := p.formatAllowed(req.msg, r); why != "" {
			return Decision{Rule: r.name, Reason: "content_format_not_allowed",
				Detail: why, Answer: wire.UnsupportedContentFormat}
		}
		return Decision{Allow: true, Rule: r.name}
	}
	if !p.defaultAllow {
		return deny("default_deny", "", wire.Forbidden)
	}
	return Decision{Allow: true}
}

// matches says whether the rule covers this message. It is deliberately only
// about *selecting* the rule: what the rule then permits is applied by match
// above, so that a rule about a request cannot be sidestepped by making the
// request not match it.
func (r *rule) matches(req request, now time.Time) bool {
	m := req.msg
	if len(r.clients) > 0 && !contains(r.clients, req.from) {
		return false
	}
	// The identity selects the rule, and an unnamed peer matches no rule that
	// names one -- including a NoSec client, which has no identity at all.
	// Falling through to the default is what should happen to a message this
	// rule is not about.
	if len(r.names) > 0 && (!req.named || !r.names[req.identity]) {
		return false
	}
	if len(r.methods) > 0 && !r.methods[m.Code] {
		return false
	}
	if r.sched != nil && !r.sched.InForce(now) {
		return false
	}
	// The path selects the rule as well as being checked by it, so that a rule
	// about one subtree does not decide about another.
	if len(r.paths) > 0 {
		got := m.Path()
		hit := false
		for _, pat := range r.paths {
			if matchPath(pat, got) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// Answer is the policy on a message coming back from a device.
//
// The size checks here are the amplification bound, and they are the reason this
// side exists at all: a four-octet GET that returns a kilobyte is a reflection
// amplifier, and the number worth bounding is the answer's size relative to the
// question's.
func (p *Policy) Answer(m *wire.Message, reqSize int, reqRule string) Decision {
	d := Decision{Allow: true, Rule: reqRule}
	switch {
	case m.Code.IsEmpty():
		return d
	case m.Code.IsSignalling():
		return hard("signalling_over_datagram", m.Code.String(), 0)
	case m.Code.IsRequest():
		// A method arriving from the device side. Either a device is confused or
		// something is bouncing requests off the relay.
		return hard("request_from_server_side", m.Code.String(), 0)
	}
	if p.repeated {
		if rep := m.Repeated(); len(rep) > 0 {
			return hard("repeated_option", wire.OptionName(rep[0]), 0)
		}
	}
	if err := m.ValidateOptions(); err != nil {
		return hard("malformed_option", err.Error(), 0)
	}
	if p.maxResponse > 0 && len(m.Raw) > p.maxResponse {
		return hard("response_too_large", fmt.Sprintf("%d octets", len(m.Raw)), 0)
	}
	if p.factor > 0 && reqSize > 0 && len(m.Raw) > reqSize*p.factor {
		// The amplification factor, which is the check a per-datagram bound
		// cannot make: a kilobyte answer is unremarkable on its own and is a
		// hundred and fifty times the four-octet question that asked for it.
		return hard("amplified", fmt.Sprintf("%d octets for %d", len(m.Raw), reqSize), 0)
	}
	if p.maxTransfer > 0 {
		if n := m.TransferSize(); n > p.maxTransfer {
			return hard("transfer_too_large", fmt.Sprintf("%d octets", n), 0)
		}
	}
	if p.maxBlock > 0 {
		if b, ok, err := m.Block2(); err == nil && ok && b.Size() > p.maxBlock {
			return hard("block_too_large", fmt.Sprintf("%d octets", b.Size()), 0)
		}
	}
	if why := p.formatAllowed(m, p.ruleFor(reqRule)); why != "" {
		return deny("content_format_not_allowed", why, 0)
	}
	return d
}

func (p *Policy) ruleFor(name string) *rule {
	if name == "" {
		return nil
	}
	for _, r := range p.rules {
		if r.name == name {
			return r
		}
	}
	return nil
}

// Observing says whether the listener carries Observe at all, for the registration
// table's own bound.
func (p *Policy) Observing() bool { return p.observe }

// proxyDetail names which of the two options asked the far end to fetch.
func proxyDetail(m *wire.Message) string {
	if u := m.ProxyURI(); u != "" {
		return "proxy_uri " + u
	}
	if s := m.ProxyScheme(); s != "" {
		return "proxy_scheme " + s
	}
	return "proxy_uri"
}

// matchPath matches a shell pattern against a path.
//
// A pattern with no slash in it after the first matches one segment, because
// path.Match's * does not cross a separator -- so "/sensors/*" is one level and
// "/sensors/**" is not a thing. A pattern ending in "/..." matches the subtree,
// which is the shape an estate actually wants and which path.Match has no
// spelling for.
func matchPath(pattern, got string) bool {
	if pattern == got {
		return true
	}
	if sub, ok := strings.CutSuffix(pattern, "/..."); ok {
		return got == sub || strings.HasPrefix(got, sub+"/")
	}
	ok, err := path.Match(pattern, got)
	return err == nil && ok
}

func prefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if n, err := netip.ParsePrefix(s); err == nil {
			out = append(out, n)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or a network", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.BitLen()))
	}
	return out, nil
}

func contains(ns []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, n := range ns {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func types(in []string) (map[wire.Type]bool, error) {
	if len(in) == 0 {
		// Confirmable and Non-confirmable, which are the two a client sends. An
		// acknowledgement and a reset are not in the list because they are not a
		// request and are decided before it is consulted.
		return map[wire.Type]bool{wire.Confirmable: true, wire.NonConfirmable: true}, nil
	}
	out := map[wire.Type]bool{}
	for _, s := range in {
		t, ok := wire.TypeOf(s)
		if !ok {
			return nil, fmt.Errorf("coap message_types: %q is not a CoAP message type", s)
		}
		out[t] = true
	}
	return out, nil
}

func methods(in []string, def map[wire.Code]bool) (map[wire.Code]bool, error) {
	if len(in) == 0 {
		return def, nil
	}
	out := map[wire.Code]bool{}
	for _, s := range in {
		c, ok := wire.MethodOf(s)
		if !ok {
			return nil, fmt.Errorf("coap methods: %q is not a CoAP method", s)
		}
		out[c] = true
	}
	return out, nil
}

func formats(in []string) (map[uint16]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[uint16]bool{}
	for _, s := range in {
		if n, ok := wire.ContentFormatOf(s); ok {
			out[n] = true
			continue
		}
		var n uint16
		if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
			return nil, fmt.Errorf("coap content_formats: %q is not a media type or a number", s)
		}
		out[n] = true
	}
	return out, nil
}

// on reads a switch whose default is on. Every switch on this kind that takes a
// pointer defaults to on, so there is one helper rather than a parameter nothing
// ever varies.
func on(p *bool) bool { return p == nil || *p }

func intOr(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
