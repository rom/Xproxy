package mqtt

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mqtt"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server serves a kind: mqtt listener: every control packet is read
// and the ones carrying a policy question are decided before they reach
// the broker.
//
// The reason this is not a layer 4 listener is that an MQTT broker's
// authorisation is per topic, and a topic is a string inside a packet.
// Without reading the packets there is nowhere to say that a device may
// publish its own telemetry and nothing else.
type server struct {
	host     proxy.Host
	cfg      config.Listener
	m        *config.MQTTListener
	ln       net.Listener
	tlsCfg   *tls.Config
	upTLS    *tls.Config
	allow    []netip.Prefix
	versions map[byte]bool
	clientID *regexp.Regexp

	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	once sync.Once
	cons map[net.Conn]struct{}
	done chan struct{}
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tc *tls.Config) (*server, error) {
	m := cfg.MQTT
	t := &server{host: host, cfg: cfg, m: m, ln: ln, tlsCfg: tc,
		versions: map[byte]bool{}, cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	for _, v := range m.Versions {
		switch v {
		case "3.1.1":
			t.versions[wire.V311] = true
		case "5.0":
			t.versions[wire.V5] = true
		}
	}
	for _, c := range m.AllowClients {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("mqtt allow_clients: %w", err)
		}
		t.allow = append(t.allow, p)
	}
	if m.ClientIDPattern != "" {
		re, err := regexp.Compile(m.ClientIDPattern)
		if err != nil {
			return nil, fmt.Errorf("mqtt client_id_pattern: %w", err)
		}
		t.clientID = re
	}
	if m.UpstreamTLSMode != "none" {
		uc, _, err := tlsconf.Client(m.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("mqtt upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	return t, nil
}

func (t *server) serve() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			var opErr *net.OpError
			if errors.As(err, &opErr) && strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if t.open.Add(1) > int64(t.m.MaxConnections) {
			t.open.Add(-1)
			t.host.Counters().MQTTRejected.Add(1)
			// MQTT has no reply before CONNECT, so the only honest
			// answer to a connection over the bound is to close it.
			_ = c.Close()
			continue
		}
		if !t.admit(c) {
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.wg.Done()
			defer t.open.Add(-1)
			defer t.untrack(c)
			defer safe.Guard("mqtt session")
			t.handle(c)
		}()
	}
}

func (t *server) admit(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return false
	default:
	}
	t.cons[c] = struct{}{}
	t.wg.Add(1)
	return true
}

func (t *server) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

func (t *server) shutdown(ctx context.Context) {
	t.once.Do(func() {
		t.mu.Lock()
		close(t.done)
		t.mu.Unlock()
		_ = t.ln.Close()
	})
	finished := make(chan struct{})
	go func() { t.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
		t.mu.Lock()
		for c := range t.cons {
			_ = c.Close()
		}
		t.mu.Unlock()
		<-finished
	}
}

// session is one client connection and the broker connection that
// serves it.
type session struct {
	t      *server
	client net.Conn
	up     net.Conn
	pool   *upstream.Pool
	ep     *upstream.Endpoint

	ip       netip.Addr
	secure   bool
	version  byte
	clientID string
	username string
	subs     map[string]bool
	// refusedQoS2 holds the packet ids of QoS 2 publications this proxy
	// refused, so the client's PUBREL is answered here instead of
	// reaching a broker that never saw the PUBLISH. Bounded by
	// max_subscriptions, which is the only bound in this file that is
	// about memory rather than policy.
	refusedQoS2 map[uint16]bool

	published atomic.Uint64
	upFailed  bool
}

func (t *server) handle(client net.Conn) {
	s := t.host
	start := time.Now()
	s.Counters().MQTTSessions.Add(1)
	s.Counters().MQTTSessionsOpen.Add(1)
	defer s.Counters().MQTTSessionsOpen.Add(-1)
	ip := netutil.AddrOf(client.RemoteAddr().String())
	se := &session{t: t, client: client, ip: ip,
		subs: map[string]bool{}, refusedQoS2: map[uint16]bool{}}
	defer func() {
		if se.up != nil {
			_ = se.up.Close()
			if se.ep != nil && se.pool != nil {
				se.pool.End(se.ep, se.upFailed, 0)
			}
		}
		_ = se.client.Close()
	}()

	if !t.allowed(ip) {
		s.Counters().MQTTRejected.Add(1)
		t.deny(ip, "client_not_allowed", "")
		t.log(se, start, "client_not_allowed")
		return
	}
	if t.m.TLSMode == "implicit" {
		tc := tls.Server(client, t.tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(t.m.ConnectTimeout.D()))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			t.log(se, start, "tls_handshake")
			return
		}
		_ = tc.SetDeadline(time.Time{})
		se.client = tc
		se.secure = true
	}
	reason := se.run(start)
	t.log(se, start, reason)
}

func (t *server) allowed(ip netip.Addr) bool {
	if len(t.allow) == 0 {
		return true
	}
	if !ip.IsValid() {
		return false
	}
	for _, p := range t.allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (t *server) deny(ip netip.Addr, what, detail string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "proto", "mqtt"}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	t.host.Logs().SecurityEvent(context.Background(), "deny", "mqtt_"+what, attrs...)
	if bl := t.host.Bans(); bl != nil && ip.IsValid() {
		bl.Observe(ip, "mqtt_denied")
	}
}

func (t *server) log(se *session, start time.Time, reason string) {
	attrs := []any{"listener", t.cfg.Name, "client_ip", se.ip.String(), "tls", se.secure,
		"client_id", se.clientID, "username", se.username, "version", mqttVersionName(se.version),
		"subscriptions", len(se.subs), "published", se.published.Load(),
		"duration_ms", float64(time.Since(start).Microseconds()) / 1000}
	if se.ep != nil {
		attrs = append(attrs, "endpoint", se.ep.Address)
	}
	if reason != "" {
		attrs = append(attrs, "closed", reason)
	}
	t.host.Logs().Access.Info("mqtt", attrs...)
}

func mqttVersionName(v byte) string {
	switch v {
	case wire.V311:
		return "3.1.1"
	case wire.V5:
		return "5.0"
	case 0:
		return ""
	default:
		return fmt.Sprintf("level %d", v)
	}
}

// run reads the CONNECT, decides on it, opens the broker session and
// then relays in both directions.
func (se *session) run(time.Time) string {
	t := se.t
	_ = se.client.SetReadDeadline(time.Now().Add(t.m.ConnectTimeout.D()))
	first, err := wire.ReadPacket(se.client, t.m.MaxPacketSize)
	if err != nil {
		return se.badPacket(err, "connect")
	}
	if first.Type != wire.CONNECT {
		// Every session begins with CONNECT (3.1.1 section 3.1). A
		// first packet of any other type is either a confused client
		// or an attempt to reach the broker without one.
		t.deny(se.ip, "not_connect", first.Name())
		return "not_connect"
	}
	c, err := wire.ParseConnect(first)
	if err != nil {
		return se.badPacket(err, "connect")
	}
	se.version, se.clientID, se.username = c.Version, c.ClientID, c.Username
	if reason, code := se.checkConnect(c); reason != "" {
		se.refuseConnect(code)
		t.deny(se.ip, reason, "")
		return reason
	}
	if err := se.connect(); err != nil {
		t.host.Logs().Error.Warn("mqtt broker unavailable", "listener", t.cfg.Name, "err", err.Error())
		se.refuseConnect(mqttServerUnavailable(c.Version))
		return "upstream_unavailable"
	}
	if _, err := se.up.Write(first.Encode()); err != nil {
		se.upFailed = true
		return "upstream_write"
	}
	return se.relay()
}

// checkConnect applies the policy that can be decided from the CONNECT
// alone. It returns a log reason and the CONNACK code to answer with.
func (se *session) checkConnect(c wire.Connect) (string, byte) {
	m := se.t.m
	if !se.t.versions[c.Version] {
		return "version_refused", mqttBadVersion(c.Version)
	}
	if c.ClientID == "" && (m.AllowEmptyClientID == nil || !*m.AllowEmptyClientID) {
		return "empty_client_id", mqttBadClientID(c.Version)
	}
	if len(c.ClientID) > m.MaxClientID {
		return "client_id_too_long", mqttBadClientID(c.Version)
	}
	if se.t.clientID != nil && c.ClientID != "" && !se.t.clientID.MatchString(c.ClientID) {
		return "client_id_refused", mqttBadClientID(c.Version)
	}
	if m.RequireAuth && (!c.HasUser || c.Username == "") {
		return "no_username", mqttNotAuthorized(c.Version)
	}
	if m.KeepAliveMax > 0 && (c.KeepAlive == 0 || time.Duration(c.KeepAlive)*time.Second > m.KeepAliveMax.D()) {
		// A keep alive of 0 asks the broker never to time the session
		// out, which is the same problem as one that is too long.
		return "keep_alive_refused", mqttNotAuthorized(c.Version)
	}
	// The will is a message the broker publishes on the client's behalf
	// after it is gone, so it is checked exactly like a publication.
	if c.WillTopic != "" {
		if c.WillRetain && m.AllowRetain != nil && !*m.AllowRetain {
			return "will_retain_refused", mqttNotAuthorized(c.Version)
		}
		if !se.topicAllowed(c.WillTopic) {
			return "will_topic_refused", mqttNotAuthorized(c.Version)
		}
	}
	return "", 0
}

// topicAllowed applies the publish policy to a concrete topic name.
func (se *session) topicAllowed(topic string) bool {
	m := se.t.m
	if err := wire.ValidTopic(topic); err != nil {
		return false
	}
	if len(topic) > m.MaxTopicLength || wire.Levels(topic) > m.MaxTopicLevels {
		return false
	}
	for _, f := range m.PublishDeny {
		if wire.Match(f, topic) {
			return false
		}
	}
	if len(m.PublishAllow) == 0 {
		return true
	}
	for _, f := range m.PublishAllow {
		if wire.Match(f, topic) {
			return true
		}
	}
	return false
}

// filterAllowed applies the subscribe policy to a filter. A filter is
// not a topic: the allow list must cover everything the filter could
// deliver, and the deny list refuses anything it could reach.
func (se *session) filterAllowed(filter string) bool {
	m := se.t.m
	if err := wire.ValidFilter(filter); err != nil {
		return false
	}
	if len(filter) > m.MaxTopicLength || wire.Levels(filter) > m.MaxTopicLevels {
		return false
	}
	if m.AllowWildcardSubscribe != nil && !*m.AllowWildcardSubscribe && strings.ContainsAny(filter, "+#") {
		return false
	}
	for _, f := range m.SubscribeDeny {
		if wire.Overlaps(f, filter) {
			return false
		}
	}
	if len(m.SubscribeAllow) == 0 {
		return true
	}
	for _, f := range m.SubscribeAllow {
		if wire.Subsumes(f, filter) {
			return true
		}
	}
	return false
}

// connect opens the broker connection.
func (se *session) connect() error {
	t := se.t
	pool := t.host.Pool(t.m.Upstream)
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", t.m.Upstream)
	}
	se.pool = pool
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(se.ip.String(), "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: pool.Cfg.Timeouts.Connect.D()}
		c, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			t.host.Logs().Error.Warn("mqtt broker dial failed", "listener", t.cfg.Name, "endpoint", e.Address, "err", err.Error())
			continue
		}
		se.up, se.ep = c, e
		break
	}
	if se.up == nil {
		return errors.New("no reachable endpoint")
	}
	se.upFailed = true
	if t.m.ProxyProtocol {
		if _, err := se.up.Write(netutil.ProxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
			return err
		}
	}
	if t.m.UpstreamTLSMode == "implicit" {
		c := t.upTLS.Clone()
		if c.ServerName == "" && !c.InsecureSkipVerify {
			host, _, err := net.SplitHostPort(se.ep.Address)
			if err != nil {
				host = se.ep.Address
			}
			c.ServerName = host
		}
		tc := tls.Client(se.up, c)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			return err
		}
		se.up = tc
	}
	se.upFailed = false
	return nil
}

// relay runs both directions. The client side is read packet by packet
// and decided on; the broker side is read packet by packet too, because
// a packet that does not parse is one the client and the proxy would
// read differently, and its framing decides where the next one starts.
func (se *session) relay() string {
	reasons := make(chan string, 2)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = se.client.Close()
			_ = se.up.Close()
		})
	}
	go func() {
		defer safe.Guard("mqtt broker direction")
		reasons <- se.fromBroker()
		stop()
	}()
	go func() {
		defer safe.Guard("mqtt client direction")
		reasons <- se.fromClient()
		stop()
	}()
	first := <-reasons
	<-reasons
	return first
}

func (se *session) fromClient() string {
	t := se.t
	for {
		_ = se.client.SetReadDeadline(time.Now().Add(t.m.IdleTimeout.D()))
		p, err := wire.ReadPacket(se.client, t.m.MaxPacketSize)
		if err != nil {
			return se.badPacket(err, "client")
		}
		reason, forward := se.decide(p)
		if reason != "" {
			return reason
		}
		if !forward {
			continue
		}
		_ = se.up.SetWriteDeadline(time.Now().Add(t.m.IdleTimeout.D()))
		if _, err := se.up.Write(p.Encode()); err != nil {
			se.upFailed = true
			return "upstream_write"
		}
	}
}

// decide applies the policy to one client packet. It returns a reason
// when the session must end, and whether the packet is forwarded.
func (se *session) decide(p wire.Packet) (string, bool) {
	t := se.t
	switch p.Type {
	case wire.CONNECT:
		// A second CONNECT on one session is a protocol error in both
		// versions, and a broker that accepted it would be taking a new
		// identity from a session already authorised as another.
		t.deny(se.ip, "second_connect", "")
		return "second_connect", false
	case wire.PUBLISH:
		return se.decidePublish(p)
	case wire.SUBSCRIBE, wire.UNSUBSCRIBE:
		return se.decideSubscribe(p)
	case wire.PUBREL:
		// A PUBREL for a publication this proxy refused is answered
		// here: the broker never saw the PUBLISH, so it has no state to
		// complete and would treat the id as unknown.
		if id, ok := mqttPacketID(p); ok && se.refusedQoS2[id] {
			delete(se.refusedQoS2, id)
			_ = se.writeClient(wire.Packet{Type: wire.PUBCOMP, Body: mqttIDBody(id, se.version, 0x92)})
			return "", false
		}
		return "", true
	default:
		return "", true
	}
}

func (se *session) decidePublish(p wire.Packet) (string, bool) {
	t := se.t
	pub, err := wire.ParsePublish(p)
	if err != nil {
		return se.badPacket(err, "publish"), false
	}
	bad := ""
	switch {
	case pub.Retain && t.m.AllowRetain != nil && !*t.m.AllowRetain:
		bad = "retain_refused"
	case !se.topicAllowed(pub.Topic):
		bad = "publish_topic_refused"
	}
	if bad == "" {
		se.published.Add(1)
		t.host.Counters().MQTTPublished.Add(1)
		return "", true
	}
	t.host.Counters().MQTTRefused.Add(1)
	t.deny(se.ip, bad, mqttClipTopic(pub.Topic))
	if t.m.Action == "disconnect" {
		se.disconnectClient(mqttNotAuthorized(se.version))
		return bad, false
	}
	// drop: the publication is refused and the session continues. A QoS
	// above 0 still needs its acknowledgement, or the client retries
	// the same message until it gives up.
	switch pub.QoS {
	case 1:
		_ = se.writeClient(wire.Packet{Type: wire.PUBACK, Body: mqttIDBody(pub.PacketID, se.version, 0x87)})
	case 2:
		if len(se.refusedQoS2) < t.m.MaxSubscriptions {
			se.refusedQoS2[pub.PacketID] = true
		}
		_ = se.writeClient(wire.Packet{Type: wire.PUBREC, Body: mqttIDBody(pub.PacketID, se.version, 0x87)})
	}
	return "", false
}

func (se *session) decideSubscribe(p wire.Packet) (string, bool) {
	t := se.t
	sub, err := wire.ParseSubscribe(p, se.version)
	if err != nil {
		return se.badPacket(err, "subscribe"), false
	}
	if p.Type == wire.UNSUBSCRIBE {
		for _, f := range sub.Filters {
			delete(se.subs, f.Filter)
		}
		return "", true
	}
	refused := ""
	for _, f := range sub.Filters {
		if !se.filterAllowed(f.Filter) {
			refused = f.Filter
			break
		}
	}
	if refused == "" && len(se.subs)+len(sub.Filters) > t.m.MaxSubscriptions {
		refused = "(too many subscriptions)"
	}
	if refused == "" {
		for _, f := range sub.Filters {
			se.subs[f.Filter] = true
		}
		t.host.Counters().MQTTSubscribed.Add(1)
		return "", true
	}
	t.host.Counters().MQTTRefused.Add(1)
	t.deny(se.ip, "subscribe_refused", mqttClipTopic(refused))
	if t.m.Action == "disconnect" {
		se.disconnectClient(mqttNotAuthorized(se.version))
		return "subscribe_refused", false
	}
	// drop: SUBACK is answered here, with a failure code for every
	// filter. Refusing the packet as a whole rather than per filter
	// keeps one answer for one request; a partial grant would leave the
	// proxy's idea of the session and the broker's out of step.
	body := make([]byte, 2, 2+len(sub.Filters)+1)
	binary.BigEndian.PutUint16(body, sub.PacketID)
	if se.version >= wire.V5 {
		body = append(body, 0) // empty property block
	}
	for range sub.Filters {
		body = append(body, 0x80) // unspecified failure in both versions
	}
	_ = se.writeClient(wire.Packet{Type: wire.SUBACK, Body: body})
	return "", false
}

func (se *session) fromBroker() string {
	t := se.t
	for {
		_ = se.up.SetReadDeadline(time.Now().Add(t.m.IdleTimeout.D()))
		p, err := wire.ReadPacket(se.up, t.m.MaxPacketSize)
		if err != nil {
			if errors.Is(err, wire.ErrMalformed) || errors.Is(err, wire.ErrPacketTooLarge) || errors.Is(err, wire.ErrVarintTooLong) {
				t.host.Counters().MQTTProtocolErrors.Add(1)
				t.host.Logs().Error.Warn("mqtt broker packet refused", "listener", t.cfg.Name, "err", err.Error())
				se.upFailed = true
				return "upstream_protocol"
			}
			se.upFailed = !errors.Is(err, io.EOF)
			return "upstream_closed"
		}
		if err := se.writeClient(p); err != nil {
			return "client_write"
		}
	}
}

func (se *session) writeClient(p wire.Packet) error {
	_ = se.client.SetWriteDeadline(time.Now().Add(se.t.m.IdleTimeout.D()))
	_, err := se.client.Write(p.Encode())
	return err
}

// badPacket ends a session on a framing or parse failure. Nothing is
// forwarded: a packet the proxy could not read is one whose length it
// cannot trust, and every packet after it would start in the wrong
// place.
func (se *session) badPacket(err error, where string) string {
	t := se.t
	switch {
	case errors.Is(err, wire.ErrPacketTooLarge):
		t.host.Counters().MQTTRefused.Add(1)
		t.deny(se.ip, "packet_too_large", where)
		se.disconnectClient(0x95)
		return "packet_too_large"
	case errors.Is(err, wire.ErrMalformed), errors.Is(err, wire.ErrVarintTooLong),
		errors.Is(err, wire.ErrBadTopic), errors.Is(err, wire.ErrBadFilter):
		t.host.Counters().MQTTProtocolErrors.Add(1)
		t.deny(se.ip, "malformed", where+": "+err.Error())
		se.disconnectClient(0x81)
		return "malformed"
	default:
		return "client_closed"
	}
}

// disconnectClient says why before closing, where the protocol has a
// way to. 3.1.1 has no server DISCONNECT and no reason codes, so there
// the close is the whole message.
func (se *session) disconnectClient(reason byte) {
	if se.version >= wire.V5 {
		_ = se.writeClient(wire.Packet{Type: wire.DISCONNECT, Body: []byte{reason, 0}})
	}
}

// refuseConnect answers a CONNECT the policy refused. The session flag
// is 0: nothing was resumed, because nothing was accepted.
func (se *session) refuseConnect(code byte) {
	body := []byte{0, code}
	if se.version >= wire.V5 {
		body = append(body, 0) // empty property block
	}
	_ = se.writeClient(wire.Packet{Type: wire.CONNACK, Body: body})
}

// The CONNACK codes differ between the versions: 3.1.1 has a short list
// of its own (section 3.2.2.3) and 5.0 uses the shared reason codes.
func mqttBadVersion(v byte) byte {
	if v >= wire.V5 {
		return 0x84
	}
	return 0x01
}

func mqttBadClientID(v byte) byte {
	if v >= wire.V5 {
		return 0x85
	}
	return 0x02
}

func mqttNotAuthorized(v byte) byte {
	if v >= wire.V5 {
		return 0x87
	}
	return 0x05
}

func mqttServerUnavailable(v byte) byte {
	if v >= wire.V5 {
		return 0x88
	}
	return 0x03
}

// mqttIDBody builds an acknowledgement body: the packet id, and in 5.0
// a reason code and an empty property block.
func mqttIDBody(id uint16, version, reason byte) []byte {
	b := make([]byte, 2, 4)
	binary.BigEndian.PutUint16(b, id)
	if version >= wire.V5 {
		b = append(b, reason, 0)
	}
	return b
}

// mqttPacketID reads the leading packet id of an acknowledgement.
func mqttPacketID(p wire.Packet) (uint16, bool) {
	if len(p.Body) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(p.Body), true
}

// mqttClipTopic bounds what a topic contributes to a log line.
func mqttClipTopic(t string) string {
	if len(t) <= 64 {
		return t
	}
	return t[:64] + "..."
}
