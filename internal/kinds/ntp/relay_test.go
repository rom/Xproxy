package ntp_test

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/ntp"
	wire "github.com/rom/xproxy/internal/ntp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// timeServer is a time server: it answers what it is told to answer and
// records every packet it was sent, so a test can say what did and did
// not reach it.
type timeServer struct {
	pc *net.UDPConn

	mu   sync.Mutex
	got  []*wire.Packet
	raws [][]byte

	// The shape of its answers. They are read and written under the
	// mutex, so a test can change what this server is halfway through --
	// which is what a replaced or re-pointed time source looks like.
	stratum        byte
	refid          [4]byte
	leap           wire.Leap
	offset         time.Duration
	rootDelay      time.Duration
	rootDispersion time.Duration
	kiss           string
	// silent reads and never answers.
	silent bool
	// echo copies the request's extension fields into the answer, which
	// is what an NTS server's answer carries; strip leaves them out,
	// which is the downgrade a relay must never pass on.
	echo  bool
	strip bool
	// interleave answers with the server's own previous transmit
	// timestamp rather than the client's, which is interleaved mode.
	interleave   bool
	lastTransmit wire.Timestamp
	// unsolicited sends a second, unasked-for packet after each answer.
	unsolicited bool
	// signWith signs the answer, which a real server answering an
	// authenticated request does: an answer that dropped the
	// authentication would be a downgrade.
	signWith *wire.Key
	// garbage answers with these bytes instead of a packet, which is
	// what a broken or hostile server on the other side sends.
	garbage []byte
}

func startTimeServer(t *testing.T, s *timeServer) *timeServer {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s.pc = pc
	if s.stratum == 0 && s.kiss == "" {
		s.stratum = 2
	}
	if s.refid == ([4]byte{}) {
		s.refid = [4]byte{10, 0, 0, 1}
	}
	t.Cleanup(func() { _ = pc.Close() })
	go s.run()
	return s
}

func (s *timeServer) addr() string { return s.pc.LocalAddr().String() }

func (s *timeServer) packets() []*wire.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*wire.Packet(nil), s.got...)
}

// bytes are the datagrams as they arrived, which is the only way to say
// whether the relay forwarded what the client wrote or something it
// rendered itself.
func (s *timeServer) bytes() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.raws...)
}

// asked is how many packets a client (rather than the relay's own
// monitor) sent this server. A probe carries no extension fields and a
// poll of 6, so the two are told apart by the client's own transmit
// timestamp being echoed: every request here is counted.
func (s *timeServer) asked() int { return len(s.packets()) }

func (s *timeServer) run() {
	buf := make([]byte, 2048)
	for {
		n, from, err := s.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		pkt, err := wire.Parse(raw)
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.got = append(s.got, pkt)
		s.raws = append(s.raws, raw)
		silent := s.silent
		s.mu.Unlock()
		if silent {
			continue
		}
		if s.garbage != nil {
			_, _ = s.pc.WriteToUDP(s.garbage, from)
			continue
		}
		out := s.answer(pkt)
		if _, err := s.pc.WriteToUDP(out, from); err != nil {
			return
		}
		if s.unsolicited {
			// A packet nobody asked for, from the right address: the
			// relay has to drop it rather than hand it to whoever asked
			// last.
			spont := &wire.Packet{Version: 4, Mode: wire.ModeServer, Stratum: 1,
				Transmit: wire.TimestampOf(time.Now())}
			_, _ = s.pc.WriteToUDP(spont.Bytes(), from)
		}
	}
}

// set changes what this server answers, under the lock the answers are
// built with.
func (s *timeServer) set(edit func(*timeServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	edit(s)
}

func (s *timeServer) answer(req *wire.Packet) []byte {
	s.mu.Lock()
	shape := struct {
		stratum                       byte
		refid                         [4]byte
		leap                          wire.Leap
		offset, rootDelay, rootDisper time.Duration
		kiss                          string
		echo, strip                   bool
	}{s.stratum, s.refid, s.leap, s.offset, s.rootDelay, s.rootDispersion, s.kiss, s.echo, s.strip}
	origin := req.Transmit
	if s.interleave && s.lastTransmit != 0 {
		origin = s.lastTransmit
	}
	s.mu.Unlock()
	now := time.Now().Add(shape.offset)
	out := &wire.Packet{
		Leap: shape.leap, Version: req.Version, Mode: wire.ModeServer,
		Stratum: shape.stratum, Poll: req.Poll, Precision: -20,
		RootDelay:      wire.ShortOf(shape.rootDelay),
		RootDispersion: wire.ShortOf(shape.rootDisper),
		Reference:      wire.TimestampOf(now.Add(-time.Minute)),
		Origin:         origin,
		Receive:        wire.TimestampOf(now),
		Transmit:       wire.TimestampOf(now.Add(time.Millisecond)),
	}
	if shape.kiss != "" {
		out.Stratum = 0
		out.Leap = wire.LeapUnsynchronised
		copy(out.ReferenceID[:], shape.kiss)
	} else {
		out.ReferenceID = shape.refid
	}
	if shape.echo && !shape.strip {
		out.Extensions = append(out.Extensions, req.Extensions...)
	}
	s.mu.Lock()
	s.lastTransmit = out.Transmit
	s.mu.Unlock()
	raw := out.Bytes()
	if s.signWith != nil {
		if signed, err := s.signWith.Sign(raw); err == nil {
			return signed
		}
	}
	return raw
}

// client is the test's side: one socket, one request at a time.
type client struct {
	t    *testing.T
	conn *net.UDPConn
}

func dialNTP(t *testing.T, addr string) *client {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &client{t: t, conn: c}
}

// request is a client-mode packet with a transmit timestamp of its own,
// which is the only thing tying the answer to it.
func request(version uint8, mode wire.Mode) *wire.Packet {
	return &wire.Packet{Version: version, Mode: mode, Poll: 6, Precision: -20,
		Transmit: wire.TimestampOf(time.Now())}
}

func (c *client) send(p *wire.Packet) { c.raw(p.Bytes()) }

func (c *client) raw(b []byte) {
	c.t.Helper()
	_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// read waits for one answer.
func (c *client) read(d time.Duration) (*wire.Packet, []byte, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 2048)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	pkt, err := wire.Parse(buf[:n])
	return pkt, buf[:n], err
}

// ask sends a request and returns the answer, failing the test if none
// arrives.
func (c *client) ask(p *wire.Packet) (*wire.Packet, []byte) {
	c.t.Helper()
	c.send(p)
	got, raw, err := c.read(3 * time.Second)
	if err != nil {
		c.t.Fatalf("no answer: %v", err)
	}
	return got, raw
}

// expectSilence checks that nothing comes back, which is how a datagram
// relay refuses: there is no reply that means "no".
func (c *client) expectSilence(what string) {
	c.t.Helper()
	if p, _, err := c.read(400 * time.Millisecond); err == nil {
		c.t.Fatalf("%s: answered with %+v", what, p)
	}
}

const ntpYAML = `
version: 1
server:
  listeners:
    - name: time
      address: "127.0.0.1:0"
      kind: ntp
      ntp:
%s
logging: {access: {enabled: false}}
upstreams:
%s
`

// ntpServer starts a listener whose ntp section is the indented block
// given, with one upstream per time server.
func ntpServer(t *testing.T, section string, servers ...*timeServer) (*proxy.Server, string) {
	t.Helper()
	var pool strings.Builder
	pool.WriteString("  - name: clocks\n    endpoints:\n")
	for _, s := range servers {
		fmt.Fprintf(&pool, "      - {address: %q}\n", s.addr())
	}
	srv := proxytest.Start(t, fmt.Sprintf(ntpYAML, section, pool.String()))
	return srv, proxytest.Addr(t, srv, "time")
}

// The floor: a client asks, the server answers, and the answer is the
// server's own bytes with the client's own transmit timestamp echoed --
// which is what makes it verifiable by the client and by nothing else.
func TestNTPRelay(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        allow_clients: ["127.0.0.0/8"]
        rate_limit: 100
        quality: {compare_sources: false}`, up)

	c := dialNTP(t, addr)
	req := request(4, wire.ModeClient)
	got, raw := c.ask(req)
	if got.Mode != wire.ModeServer {
		t.Fatalf("mode %s", got.Mode)
	}
	if !got.AnswersRequest(req.Transmit) {
		t.Fatalf("the answer does not echo this request's transmit timestamp")
	}
	if got.Stratum != 2 {
		t.Errorf("stratum %d", got.Stratum)
	}
	// The relay forwarded the client's packet as it arrived, so the
	// server saw the client's own timestamp rather than one of the
	// relay's.
	sent := up.packets()
	if len(sent) != 1 || sent[0].Transmit != req.Transmit {
		t.Fatalf("the server saw %d packets, and the transmit timestamp did not survive", len(sent))
	}
	// And the answer reached the client as the server wrote it.
	if len(raw) != wire.HeaderLen {
		t.Errorf("the answer is %d octets, want the header's %d", len(raw), wire.HeaderLen)
	}
	// The counters, once they have caught up: "forwarded" is counted
	// after the packet is on its way, so a server on the same host can
	// answer -- and the answer can reach this client -- before that
	// counter is incremented. Waiting for it is the test's job rather
	// than the data path's; a counter that had to be raised before the
	// send would be counting a forward that may still fail.
	sn := awaitCounters(t, s, func(sn proxy.Snapshot) bool {
		return sn.NTPRequests == 1 && sn.NTPForwarded == 1 && sn.NTPAnswered == 1
	}, "one request forwarded and answered")
	if sn.NTPDenied != 0 {
		t.Errorf("denied %d", sn.NTPDenied)
	}
	if sn.NTPAssociations != 1 {
		t.Errorf("associations %d", sn.NTPAssociations)
	}
}

// awaitCounters waits for the counters to satisfy a condition, because a
// counter written after the packet it describes is not readable the
// instant the packet arrives somewhere else.
func awaitCounters(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) proxy.Snapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		sn := s.Stats()
		if ok(sn) {
			return sn
		}
		if time.Now().After(deadline) {
			t.Fatalf("counters never showed %s: requests %d forwarded %d answered %d denied %d dropped %d",
				what, sn.NTPRequests, sn.NTPForwarded, sn.NTPAnswered, sn.NTPDenied, sn.NTPDropped)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Mode 6 and mode 7 are not time. Mode 7 carries monlist, which is the
// amplification this port is famous for, and neither has the header this
// relay parses -- so both are refused from the first octet, before any
// field of the body is read, and neither reaches a server.
func TestNTPManagementModesNeverReachTheServer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   wire.Mode
		reason string
	}{
		{"the control protocol", wire.ModeControl, "control_mode"},
		{"the private protocol monlist belongs to", wire.ModePrivate, "private_mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := startTimeServer(t, &timeServer{})
			s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false}`, up)
			c := dialNTP(t, addr)
			c.send(request(4, tc.mode))
			c.expectSilence("a management mode")
			if n := up.asked(); n != 0 {
				t.Fatalf("%d packets reached the server", n)
			}
			if got := s.Stats().Refusals["ntp"][tc.reason]; got != 1 {
				t.Fatalf("the refusal was not counted as %s: %+v", tc.reason, s.Stats().Refusals["ntp"])
			}
		})
	}
}

// The version profile. Version 4 is the protocol, version 3 is the
// legacy profile a plant still has devices on, versions 1 and 2 are
// named or refused, and version 5 is a different layout that is never
// parsed with this parser.
func TestNTPVersionPolicy(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	for _, v := range []uint8{4, 3} {
		if got, _ := c.ask(request(v, wire.ModeClient)); got.Version != v {
			t.Errorf("version %d came back as %d", v, got.Version)
		}
	}
	// Version 2 is not in the default profile.
	c.send(request(2, wire.ModeClient))
	c.expectSilence("version 2 by default")
	if got := s.Stats().Refusals["ntp"]["version_not_allowed"]; got != 1 {
		t.Errorf("version 2: %+v", s.Stats().Refusals["ntp"])
	}
	// Version 5 is refused by name, because its packet is not this one.
	c.send(request(5, wire.ModeClient))
	c.expectSilence("version 5")
	if got := s.Stats().Refusals["ntp"]["version5"]; got != 1 {
		t.Errorf("version 5: %+v", s.Stats().Refusals["ntp"])
	}

	// A listener that names the legacy versions accepts them.
	up2 := startTimeServer(t, &timeServer{})
	_, addr2 := ntpServer(t, `        upstream: clocks
        versions: [2, 3, 4]
        rate_limit: 100
        quality: {compare_sources: false}`, up2)
	c2 := dialNTP(t, addr2)
	if got, _ := c2.ask(request(2, wire.ModeClient)); got.Version != 2 {
		t.Errorf("a named version 2 came back as %d", got.Version)
	}
}

// Version 5 is forwarded as opaque bytes when a listener says so, on a
// transaction socket of its own, because correlating its answer would
// mean reading fields whose meaning is not settled.
func TestNTPVersion5IsForwardedWithoutBeingParsed(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        allow_version5: true
        rate_limit: 100
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	p := request(5, wire.ModeClient)
	c.send(p)
	// The fake server parses it as version 5 and will not answer, so
	// what is asserted here is that it arrived: the relay forwarded a
	// packet it did not read.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.Stats().NTPVersion5 == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Stats().NTPVersion5 != 1 {
		t.Fatalf("the version 5 packet was not counted: %d", s.Stats().NTPVersion5)
	}
}

// The client list decides before anything else.
func TestNTPClientList(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	c.send(request(4, wire.ModeClient))
	c.expectSilence("a client outside the allow list")
	if got := s.Stats().Refusals["ntp"]["client_not_allowed"]; got != 1 {
		t.Fatalf("the refusal was not counted: %+v", s.Stats().Refusals["ntp"])
	}
	if n := up.asked(); n != 0 {
		t.Fatalf("%d packets reached the server", n)
	}
}

// A client asking too often is told to slow down in the protocol's own
// words: a stratum-0 answer whose reference identifier is RATE. A drop
// teaches it nothing and it asks again.
func TestNTPRateLimitAnswersAKiss(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 1
        rate_burst: 1
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	c.ask(request(4, wire.ModeClient))
	var kiss *wire.Packet
	for i := 0; i < 5 && kiss == nil; i++ {
		c.send(request(4, wire.ModeClient))
		if p, _, err := c.read(500 * time.Millisecond); err == nil && p.KissOfDeath() {
			kiss = p
		}
	}
	if kiss == nil {
		t.Fatal("the rate limit did not answer with a kiss-o'-death")
	}
	if kiss.KissCode() != "RATE" {
		t.Errorf("kiss code %q", kiss.KissCode())
	}
	// The kiss is counted after it is sent, so the client can hold it
	// before the counter moves.
	awaitCounters(t, s, func(sn proxy.Snapshot) bool {
		return sn.NTPKissSent > 0 && sn.NTPRateLimited > 0
	}, "a kiss sent and a rate limit counted")
}

// The server-quality rules, which are about answers and not about
// requests: a client's stratum and dispersion mean nothing, and a
// server's are its whole statement about the time it is handing out.
func TestNTPServerQualityRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server *timeServer
		reason string
	}{
		{"a server that says its clock is not synchronised",
			&timeServer{leap: wire.LeapUnsynchronised}, "unsynchronised"},
		{"a server at the protocol's own unsynchronised stratum",
			&timeServer{stratum: 16}, "unsynchronised_stratum"},
		{"a server too far down the tree",
			&timeServer{stratum: 9}, "stratum_too_high"},
		{"a server whose own dispersion says not to trust it",
			&timeServer{rootDispersion: 2 * time.Second}, "root_dispersion"},
		{"a server whose root delay is past the bound",
			&timeServer{rootDelay: 3 * time.Second}, "root_delay"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := startTimeServer(t, tc.server)
			s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality:
          compare_sources: false
          max_stratum: 8
          max_root_dispersion: 1s
          max_root_delay: 1s`, up)
			c := dialNTP(t, addr)
			c.send(request(4, wire.ModeClient))
			c.expectSilence("an answer the quality rules refuse")
			if got := s.Stats().Refusals["ntp"][tc.reason]; got != 1 {
				t.Fatalf("want the refusal %s, got %+v", tc.reason, s.Stats().Refusals["ntp"])
			}
			if s.Stats().NTPDenied != 1 {
				t.Errorf("denied %d", s.Stats().NTPDenied)
			}
		})
	}
	// And a good answer passes the same rules.
	up := startTimeServer(t, &timeServer{stratum: 3, rootDispersion: 10 * time.Millisecond})
	_, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false, max_stratum: 8, max_root_dispersion: 1s}`, up)
	if got, _ := dialNTP(t, addr).ask(request(4, wire.ModeClient)); got.Stratum != 3 {
		t.Errorf("a sound answer was changed: %+v", got)
	}
}

// A kiss-o'-death from the server is a message to the client, not time.
// Forwarding it lets the client back off; refusing it hides a rate limit
// the estate should know about. Either way it is a counter.
func TestNTPTheServersKissIsAChoice(t *testing.T) {
	for _, tc := range []struct {
		name    string
		section string
		forward bool
	}{
		{"forwarded by default", `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false}`, true},
		{"refused when the listener says so", `        upstream: clocks
        rate_limit: 100
        kod: {forward: false}
        quality: {compare_sources: false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := startTimeServer(t, &timeServer{kiss: "DENY"})
			s, addr := ntpServer(t, tc.section, up)
			c := dialNTP(t, addr)
			c.send(request(4, wire.ModeClient))
			if tc.forward {
				got, _, err := c.read(2 * time.Second)
				if err != nil {
					t.Fatalf("the kiss was not forwarded: %v", err)
				}
				if !got.KissOfDeath() || got.KissCode() != "DENY" {
					t.Fatalf("answer %+v", got)
				}
				return
			}
			c.expectSilence("a kiss the listener refuses")
			if got := s.Stats().Refusals["ntp"]["kiss_of_death"]; got != 1 {
				t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
			}
		})
	}
}

// An answer nobody asked for is dropped, however right its source
// address looks: the origin timestamp is the only thing tying an answer
// to a question, and a relay that forwarded whatever arrived would be
// handing its clients somebody else's time.
func TestNTPUnsolicitedAnswerIsDropped(t *testing.T) {
	up := startTimeServer(t, &timeServer{unsolicited: true})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	req := request(4, wire.ModeClient)
	got, _ := c.ask(req)
	if !got.AnswersRequest(req.Transmit) {
		t.Fatal("the answer to the request did not come back")
	}
	// The second, unasked-for packet must not reach the client.
	if p, _, err := c.read(400 * time.Millisecond); err == nil {
		t.Fatalf("an unsolicited answer reached the client: %+v", p)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.Stats().NTPUnsolicited == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Stats().NTPUnsolicited == 0 {
		t.Fatal("the unsolicited answer was not counted")
	}
}

// Interleaved mode: the answer echoes the server's own previous transmit
// timestamp rather than the client's, which is how a server hands out a
// hardware-quality transmit timestamp. It is supported, and it is a
// switch rather than an assumption.
func TestNTPInterleaved(t *testing.T) {
	up := startTimeServer(t, &timeServer{interleave: true})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	// The first exchange is ordinary: the server has no previous
	// transmit timestamp yet.
	c.ask(request(4, wire.ModeClient))
	// The second answer is interleaved, and it is still forwarded.
	c.send(request(4, wire.ModeClient))
	if _, _, err := c.read(2 * time.Second); err != nil {
		t.Fatalf("an interleaved answer was not forwarded: %v", err)
	}
	if s.Stats().NTPInterleaved == 0 {
		t.Fatal("the interleaved answer was not counted as one")
	}

	// A listener that turns it off drops the same answer as
	// unsolicited, because that is what it cannot tell it from.
	up2 := startTimeServer(t, &timeServer{interleave: true})
	s2, addr2 := ntpServer(t, `        upstream: clocks
        interleaved: false
        rate_limit: 100
        quality: {compare_sources: false}`, up2)
	c2 := dialNTP(t, addr2)
	c2.ask(request(4, wire.ModeClient))
	c2.send(request(4, wire.ModeClient))
	c2.expectSilence("an interleaved answer on a listener that refuses them")
	if s2.Stats().NTPUnsolicited == 0 {
		t.Error("the refused interleaved answer was not counted")
	}
}

// NTS pass-through: the protected packet is forwarded whole, the fields
// reach the server, and an answer that comes back without them is a
// downgrade the relay refuses rather than passes on.
func TestNTPNTSPassthroughAndNoDowngrade(t *testing.T) {
	withNTS := func(p *wire.Packet) *wire.Packet {
		p.Extensions = []wire.Extension{
			{Type: wire.EFUniqueIdentifier, Body: make([]byte, 32)},
			{Type: wire.EFNTSCookie, Body: make([]byte, 100)},
			{Type: wire.EFNTSAuthenticator, Body: make([]byte, 64)},
		}
		return p
	}
	up := startTimeServer(t, &timeServer{echo: true})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        nts: {mode: passthrough}
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	got, _ := c.ask(withNTS(request(4, wire.ModeClient)))
	if n := got.NTS(); !n.Present || !n.Authenticator {
		t.Fatalf("the protected answer lost its fields: %+v", n)
	}
	// The server saw the fields: the relay did not strip or rewrite
	// them, which it could not do without breaking the authentication
	// it cannot check.
	sent := up.packets()
	if len(sent) == 0 || len(sent[0].Extensions) != 3 {
		t.Fatalf("the server saw %d fields", len(sent[0].Extensions))
	}
	if s.Stats().NTPNTSForwarded == 0 {
		t.Error("the protected packet was not counted")
	}

	// A server that answers a protected request without the fields is a
	// downgrade to plain NTP, and that is never passed on silently.
	strip := startTimeServer(t, &timeServer{echo: true, strip: true})
	s2, addr2 := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        nts: {mode: passthrough}
        quality: {compare_sources: false}`, strip)
	c2 := dialNTP(t, addr2)
	c2.send(withNTS(request(4, wire.ModeClient)))
	c2.expectSilence("an answer that dropped the NTS fields")
	if got := s2.Stats().Refusals["ntp"]["nts_stripped"]; got != 1 {
		t.Fatalf("refusals: %+v", s2.Stats().Refusals["ntp"])
	}
}

// A listener that says the estate is NTS only refuses a plain packet.
func TestNTPRequireNTS(t *testing.T) {
	up := startTimeServer(t, &timeServer{echo: true})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        nts: {mode: passthrough, require: true}
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	c.send(request(4, wire.ModeClient))
	c.expectSilence("a plain packet where NTS is required")
	if got := s.Stats().Refusals["ntp"]["nts_required"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
	if n := up.asked(); n != 0 {
		t.Fatalf("%d packets reached the server", n)
	}
}

// A symmetric association is a relationship in which each end accepts
// the other's time, so it is only ever between named peers.
func TestNTPSymmetricModeNeedsAPeer(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        modes: [client, server, symmetric_active]
        peers: ["10.9.9.9/32"]
        rate_limit: 100
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	c.send(request(4, wire.ModeSymActive))
	c.expectSilence("a symmetric packet from something that is not a peer")
	if got := s.Stats().Refusals["ntp"]["not_a_peer"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
}

// The extension field policy: a field this relay cannot read is a field
// it cannot decide about, and that includes every field Autokey defined.
func TestNTPExtensionPolicy(t *testing.T) {
	unknown := func() *wire.Packet {
		p := request(4, wire.ModeClient)
		p.Extensions = []wire.Extension{{Type: 0x0002, Body: make([]byte, 32)}}
		return p
	}
	up := startTimeServer(t, &timeServer{echo: true})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	c.send(unknown())
	c.expectSilence("a field this relay does not know")
	if got := s.Stats().Refusals["ntp"]["unknown_extension"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}

	// A listener that says so forwards it anyway, having said in
	// validation that it is doing that.
	up2 := startTimeServer(t, &timeServer{echo: true})
	_, addr2 := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        extensions: {allow_unknown: true}
        quality: {compare_sources: false}`, up2)
	if _, _ = dialNTP(t, addr2).ask(unknown()); len(up2.packets()) == 0 {
		t.Error("the field was not forwarded where the listener allows it")
	}

	// Too many fields, and the tail whose meaning depends on which way
	// it is read.
	up3 := startTimeServer(t, &timeServer{echo: true})
	s3, addr3 := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        extensions: {max: 2}
        quality: {compare_sources: false}`, up3)
	c3 := dialNTP(t, addr3)
	many := request(4, wire.ModeClient)
	for i := 0; i < 3; i++ {
		// Each field is longer than a MAC could be, so the tail cannot
		// be read as one and the count is what decides.
		many.Extensions = append(many.Extensions, wire.Extension{Type: wire.EFNTSCookie, Body: make([]byte, 100)})
	}
	c3.send(many)
	c3.expectSilence("more fields than the listener allows")
	if got := s3.Stats().Refusals["ntp"]["too_many_extensions"]; got != 1 {
		t.Fatalf("refusals: %+v", s3.Stats().Refusals["ntp"])
	}
	// The RFC 7822 ambiguity: a tail that is both a MAC and a valid
	// field. The relay reads it as a MAC and refuses it, because the
	// server behind it may read it the other way.
	tail := make([]byte, 24)
	tail[0], tail[1], tail[2], tail[3] = 0x01, 0x04, 0x00, 0x18
	c3.raw(append(request(4, wire.ModeClient).Bytes(), tail...))
	c3.expectSilence("an ambiguous tail")
	if got := s3.Stats().Refusals["ntp"]["ambiguous_mac"]; got != 1 {
		t.Fatalf("refusals: %+v", s3.Stats().Refusals["ntp"])
	}
}

// Symmetric authentication: the key the packet names, the digest the
// algorithm produces, and a refusal for every way of getting it wrong.
func TestNTPAuthentication(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "ntp.key")
	if err := os.WriteFile(keyFile, []byte("2b7e151628aed2a6abf7158809cf4f3c"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := wire.Key{ID: 7, Algorithm: wire.AlgAESCMAC,
		Secret: []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}}
	up := startTimeServer(t, &timeServer{signWith: &key})
	s, addr := ntpServer(t, fmt.Sprintf(`        upstream: clocks
        rate_limit: 100
        auth:
          require: true
          keys: [{id: 7, algorithm: aes-cmac, key_file: %s}]
        quality: {compare_sources: false}`, keyFile), up)
	c := dialNTP(t, addr)

	// Signed with the key the listener holds.
	signed, err := key.Sign(request(4, wire.ModeClient).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	c.raw(signed)
	if _, _, err := c.read(2 * time.Second); err != nil {
		t.Fatalf("an authenticated request was not answered: %v", err)
	}
	// A digest with a bit flipped.
	bad := append([]byte(nil), signed...)
	bad[len(bad)-1] ^= 1
	c.raw(bad)
	c.expectSilence("a MAC that does not verify")
	if got := s.Stats().Refusals["ntp"]["auth_failed"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
	// No authentication at all, where it is required.
	c.send(request(4, wire.ModeClient))
	c.expectSilence("no MAC where one is required")
	if got := s.Stats().Refusals["ntp"]["auth_required"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
}

// The monitor is the half a client could not do for itself: three
// sources, one of them wrong, and the relay says which.
func TestNTPTheMonitorFindsTheSourceThatDisagrees(t *testing.T) {
	good1 := startTimeServer(t, &timeServer{})
	good2 := startTimeServer(t, &timeServer{})
	liar := startTimeServer(t, &timeServer{offset: 5 * time.Second})
	s, _ := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality:
          compare_sources: true
          probe_interval: 1s
          max_disagreement: 250ms
          healthy_after: 1
          unhealthy_after: 1`, good1, good2, liar)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().NTPDisagreements > 0 && s.Stats().NTPSourceUnhealthy > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	sn := s.Stats()
	if sn.NTPDisagreements == 0 {
		t.Fatalf("the disagreement was not reported: probes %d failures %d", sn.NTPProbes, sn.NTPProbeFailed)
	}
	if sn.NTPSourceUnhealthy == 0 {
		t.Fatal("no source was marked unhealthy")
	}
	if liar.asked() == 0 || good1.asked() == 0 {
		t.Fatal("the monitor did not probe every source")
	}
}

// An unreachable source is a different state from a wrong one, and the
// monitor says so rather than folding them together.
func TestNTPTheMonitorSeparatesUnreachableFromWrong(t *testing.T) {
	silent := startTimeServer(t, &timeServer{silent: true})
	good := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        request_timeout: 300ms
        quality:
          compare_sources: true
          probe_interval: 1s
          healthy_after: 1
          unhealthy_after: 1`, silent, good)
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) && s.Stats().NTPProbeFailed == 0 {
		time.Sleep(100 * time.Millisecond)
	}
	if s.Stats().NTPProbeFailed == 0 {
		t.Fatal("the silent source was not recorded as a failed probe")
	}
	// And a client still gets the time, from the source that answers.
	c := dialNTP(t, addr)
	for i := 0; i < 4; i++ {
		c.send(request(4, wire.ModeClient))
		if _, _, err := c.read(time.Second); err == nil {
			return
		}
	}
	t.Fatal("no answer while one source of two was unreachable")
}

// Learning mode records what asks for the time and writes out the lists
// a policy is made of, and decides nothing while it does.
func TestNTPLearningMode(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	report := filepath.Join(t.TempDir(), "learned.yaml")
	s, addr := ntpServer(t, fmt.Sprintf(`        upstream: clocks
        allow_clients: ["10.0.0.0/8"]
        rate_limit: 100
        learn: {enabled: true, file: %s, interval: 10s}
        quality: {compare_sources: false}`, report), up)
	c := dialNTP(t, addr)
	// The client is outside the allow list, and learning is
	// observe-only, so the packet goes through anyway and the refusal
	// that did not happen is counted.
	if _, _ = c.ask(request(4, wire.ModeClient)); up.asked() == 0 {
		t.Fatal("learning mode refused a packet it was only meant to record")
	}
	if s.Stats().NTPWouldDeny == 0 {
		t.Error("the refusal that did not happen was not counted")
	}
	// The same for a packet the policy itself refuses rather than the
	// client list: a field this relay does not know. A learning run that
	// enforced this one would be finding out what the plant's traffic is
	// by dropping the half of it that is interesting.
	unknown := request(4, wire.ModeClient)
	unknown.Extensions = []wire.Extension{{Type: 0x0002, Body: make([]byte, 32)}}
	before := s.Stats().NTPWouldDeny
	c.send(unknown)
	if _, _, err := c.read(3 * time.Second); err != nil {
		t.Fatalf("learning mode refused a packet the policy would deny: %v", err)
	}
	if s.Stats().NTPWouldDeny <= before {
		t.Error("the policy refusal that did not happen was not counted")
	}
	if got := s.Stats().Refusals["ntp"]["unknown_extension"]; got != 0 {
		t.Errorf("a learning run counted %d enforced refusals", got)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("the learning report was not written: %v", err)
	}
	body := string(b)
	for _, want := range []string{"observed:", "client: 127.0.0.1", "version: 4", "mode: client",
		"allow_clients: [127.0.0.1/32]", "versions: [4]", "modes: [client]"} {
		if !strings.Contains(body, want) {
			t.Errorf("the report does not carry %q:\n%s", want, body)
		}
	}
}

// The trace is one JSON object per packet, in both directions.
func TestNTPTrace(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	_, addr := ntpServer(t, fmt.Sprintf(`        upstream: clocks
        rate_limit: 100
        trace: {file: %s}
        quality: {compare_sources: false}`, path), up)
	dialNTP(t, addr).ask(request(4, wire.ModeClient))
	var body string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && strings.Count(string(b), "\n") >= 2 {
			body = string(b)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if body == "" {
		t.Fatal("the trace was not written")
	}
	for _, want := range []string{`"direction":"request"`, `"direction":"response"`,
		`"mode":"client"`, `"mode":"server"`, `"decision":"allow"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the trace does not carry %s:\n%s", want, body)
		}
	}
}

// Many clients behind one address: each source port is its own
// association, and all of them are answered. It is the shape a plant
// behind a NAT actually has, and the shape an association table keyed
// only by address would get wrong.
func TestNTPManyClientsBehindOneAddress(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 1000
        rate_burst: 1000
        quality: {compare_sources: false}`, up)
	const n = 8
	for i := 0; i < n; i++ {
		c := dialNTP(t, addr)
		req := request(4, wire.ModeClient)
		got, _ := c.ask(req)
		if !got.AnswersRequest(req.Transmit) {
			t.Fatalf("client %d got an answer to somebody else's question", i)
		}
	}
	if got := s.Stats().NTPAssociations; got != n {
		t.Errorf("associations %d, want %d", got, n)
	}
	// And the same client asking twice from the same port is one
	// association, not two.
	c := dialNTP(t, addr)
	c.ask(request(4, wire.ModeClient))
	c.ask(request(4, wire.ModeClient))
	if got := s.Stats().NTPAssociations; got != n+1 {
		t.Errorf("associations %d, want %d", got, n+1)
	}
}

// A packet the relay cannot read is a packet it cannot decide about.
func TestNTPMalformedPacketsAreDropped(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        max_packet_bytes: 200
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"a packet shorter than the header", make([]byte, 20)},
		{"a tail that is neither a field nor a MAC", append(request(4, wire.ModeClient).Bytes(), 1, 2, 3, 4, 5, 6)},
		{"a field whose length runs past the packet",
			append(request(4, wire.ModeClient).Bytes(), 0x01, 0x04, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := append([]byte(nil), tc.raw...)
			if len(raw) > 0 {
				raw[0] = byte(4<<3) | byte(wire.ModeClient)
			}
			c.raw(raw)
			c.expectSilence("a malformed packet")
		})
	}
	// A packet past the listener's bound.
	big := request(4, wire.ModeClient)
	big.Extensions = []wire.Extension{{Type: wire.EFNTSCookie, Body: make([]byte, 200)}}
	c.raw(big.Bytes())
	c.expectSilence("a packet past the bound")
	if got := s.Stats().Refusals["ntp"]["packet_too_large"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
	if n := up.asked(); n != 0 {
		t.Fatalf("%d malformed packets reached the server", n)
	}
	if s.Stats().NTPMalformed == 0 && s.Stats().NTPDropped == 0 {
		t.Error("nothing was counted")
	}
}

// The bytes that arrive are the bytes forwarded, in both directions.
//
// A relay that re-rendered the packet would strip whatever it did not
// model -- a MAC, a cookie, a field it has no field for -- and the two
// ends would then be authenticating different octets. So the request the
// server reads is the client's own datagram, and the answer the client
// reads is the server's own, tail and all.
func TestNTPTheBytesThatArriveAreTheBytesForwarded(t *testing.T) {
	key := wire.Key{ID: 7, Algorithm: wire.AlgAESCMAC,
		Secret: []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}}
	up := startTimeServer(t, &timeServer{signWith: &key})
	// No auth section: the listener neither holds the key nor checks it,
	// which is exactly the case where a relay that rewrote the packet
	// would silently destroy somebody else's authentication.
	_, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	signed, err := key.Sign(request(4, wire.ModeClient).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) <= wire.HeaderLen {
		t.Fatalf("the signed request is %d octets", len(signed))
	}
	c.raw(signed)
	got, raw, err := c.read(3 * time.Second)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	arrived := up.bytes()
	if len(arrived) != 1 {
		t.Fatalf("the server saw %d datagrams", len(arrived))
	}
	if !bytes.Equal(arrived[0], signed) {
		t.Fatalf("the server saw %d octets and the client sent %d: the MAC did not survive the relay",
			len(arrived[0]), len(signed))
	}
	// And back: the answer carries the server's own digest, which the
	// relay cannot have recomputed and must not have dropped.
	if !got.HasMAC || got.KeyID != 7 {
		t.Fatalf("the answer reached the client without its authentication: mac %v key %d", got.HasMAC, got.KeyID)
	}
	if len(raw) != wire.HeaderLen+4+16 {
		t.Fatalf("the answer is %d octets, want the header, a key identifier and a digest", len(raw))
	}
	if err := got.Verify(wire.Keys{7: key}); err != nil {
		t.Fatalf("the answer's own MAC no longer verifies after the relay: %v", err)
	}
}

// An answer the relay cannot read is an answer it will not pass on. The
// client would read those bytes differently from the relay, and that gap
// is the whole class of bug this listener exists to close.
func TestNTPAServersUnreadableAnswerIsNotPassedOn(t *testing.T) {
	up := startTimeServer(t, &timeServer{garbage: []byte{0x00, 0x01, 0x02, 0x03, 0x04}})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	c.send(request(4, wire.ModeClient))
	c.expectSilence("a server's unreadable answer")
	if n := up.asked(); n != 1 {
		t.Fatalf("the request did not reach the server (%d)", n)
	}
	if got := s.Stats().NTPMalformed; got == 0 {
		t.Error("the unreadable answer was not counted as malformed")
	}
	if got := s.Stats().Refusals["ntp"]["malformed_response"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
	if got := s.Stats().NTPAnswered; got != 0 {
		t.Errorf("%d answers reached a client", got)
	}
}

// The association table is bounded, and the bound is what stops a flood
// of forged sources filling it: an association is an address and a port,
// so the table is exactly as long as an attacker cares to make it.
func TestNTPTheAssociationTableIsBounded(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 1000
        rate_burst: 1000
        max_associations: 16
        quality: {compare_sources: false}`, up)
	// Sixteen clients, each its own source port and so its own
	// association, are all answered.
	clients := make([]*client, 0, 16)
	for i := 0; i < 16; i++ {
		c := dialNTP(t, addr)
		clients = append(clients, c)
		c.ask(request(4, wire.ModeClient))
	}
	if got := s.Stats().NTPAssociations; got != 16 {
		t.Fatalf("associations %d, want the bound's 16", got)
	}
	// The seventeenth is dropped, with the bound as the reason, and the
	// sixteen that were already there keep working.
	extra := dialNTP(t, addr)
	extra.send(request(4, wire.ModeClient))
	extra.expectSilence("a client past the association bound")
	if got := s.Stats().Refusals["ntp"]["max_associations"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
	if got := s.Stats().NTPAssociations; got != 16 {
		t.Errorf("associations %d after the bound was reached", got)
	}
	clients[0].ask(request(4, wire.ModeClient))
	if s.Stats().NTPAssociations != 16 {
		t.Error("an established client was charged a new association")
	}
}

// The egress list is what stops a pool whose name starts resolving
// somewhere new from quietly becoming a new destination for the estate's
// time. It is checked when the socket is opened, before a single packet
// is sent, because by then the destination is already chosen.
func TestNTPTheEgressListBoundsTheServers(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, addr := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        allow_servers: ["10.0.0.0/8"]
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	c.send(request(4, wire.ModeClient))
	c.expectSilence("a server outside the egress list")
	if n := up.asked(); n != 0 {
		t.Fatalf("%d packets went to a server outside allow_servers", n)
	}
	if got := s.Stats().Refusals["ntp"]["server_not_allowed"]; got == 0 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
	if got := s.Stats().Refusals["ntp"]["no_server"]; got == 0 {
		t.Errorf("the client was not told there was no server: %+v", s.Stats().Refusals["ntp"])
	}

	// The same listener with the server's own network named works, so
	// what the test above proves is the list and not the plumbing.
	up2 := startTimeServer(t, &timeServer{})
	_, addr2 := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        allow_servers: ["127.0.0.0/8"]
        quality: {compare_sources: false}`, up2)
	if got, _ := dialNTP(t, addr2).ask(request(4, wire.ModeClient)); got.Stratum != 2 {
		t.Errorf("a server inside the egress list: stratum %d", got.Stratum)
	}
}

// A source that says its own clock is not synchronised is a state of its
// own -- not an outage, not a wrong answer -- and it takes as many probes
// to change a source's state as the listener asked for. One slow answer
// on a busy network is not a fault, and a relay that moved every clock in
// a plant on one sample would be an outage generator with a health check
// attached.
func TestNTPTheMonitorWaitsBeforeItChangesASourcesState(t *testing.T) {
	up := startTimeServer(t, &timeServer{leap: wire.LeapUnsynchronised})
	s, _ := ntpServer(t, `        upstream: clocks
        rate_limit: 100
        quality:
          compare_sources: true
          probe_interval: 1s
          healthy_after: 1
          unhealthy_after: 3`, up)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && s.Stats().NTPProbeFailed == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	failed := s.Stats().NTPProbeFailed
	if failed == 0 {
		t.Fatal("a source whose leap indicator says it is not synchronised was taken as a good probe")
	}
	// The hysteresis: one bad probe of the three this listener asked for
	// does not move the source's state.
	if failed == 1 {
		time.Sleep(50 * time.Millisecond)
		if n := s.Stats().NTPSourceUnhealthy; n != 0 {
			t.Fatalf("one bad probe of three moved the source's state (%d)", n)
		}
	}
	for time.Now().Before(deadline) && s.Stats().NTPSourceUnhealthy == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if s.Stats().NTPSourceUnhealthy == 0 {
		t.Fatalf("the source was never marked: %d probes, %d failed", s.Stats().NTPProbes, s.Stats().NTPProbeFailed)
	}
	if got := s.Stats().NTPProbeFailed; got < 3 {
		t.Errorf("the source was marked after %d failed probes, and the listener asked for 3", got)
	}
	if got := s.Stats().NTPSourceHealthy; got != 0 {
		t.Errorf("a source that says not to use its time was called healthy %d time(s)", got)
	}
}

// A source that changes what it is, through a real relay. Every static
// bound here is generous on purpose: the point is that a stratum jump and
// a new reference identifier are caught by the watcher and not by any
// threshold, because that is the case an estate cannot write a threshold
// for.
func TestNTPASourceThatChangesIsSaidOutLoud(t *testing.T) {
	up := startTimeServer(t, &timeServer{stratum: 2, refid: [4]byte{10, 0, 0, 1}})
	s, addr := ntpServer(t, `        upstream: clocks
        allow_clients: ["127.0.0.0/8"]
        quality: {compare_sources: false, max_stratum: 15}
        change_detection: {enabled: true}`, up)

	c := dialNTP(t, addr)
	c.ask(request(4, wire.ModeClient))

	// The same server, now answering as something else from further down
	// the tree: what a replaced or re-pointed clock looks like.
	up.set(func(ts *timeServer) {
		ts.stratum = 9
		ts.refid = [4]byte{192, 0, 2, 9}
	})
	got, _ := c.ask(request(4, wire.ModeClient))
	if got.Stratum != 9 {
		t.Fatalf("the second answer did not come from the changed server: stratum %d", got.Stratum)
	}
	// The answers reached the client and the change was counted. Both are
	// polled together, because the answered counter is incremented after
	// the datagram is written.
	awaitCounters(t, s, func(sn proxy.Snapshot) bool {
		return sn.NTPSourceChanged >= 1 && sn.NTPStratumJumped >= 1 && sn.NTPAnswered >= 2
	}, "the source change, the stratum jump and both answers")
}

// And the same change where the estate said to refuse: the answer does
// not reach the client at all, which is the choice with an outage in it
// and therefore not the default.
func TestNTPASourceThatChangesCanBeRefused(t *testing.T) {
	up := startTimeServer(t, &timeServer{stratum: 2, refid: [4]byte{10, 0, 0, 1}})
	s, addr := ntpServer(t, `        upstream: clocks
        allow_clients: ["127.0.0.0/8"]
        quality: {compare_sources: false, max_stratum: 15}
        change_detection: {enabled: true, action: refuse}`, up)

	c := dialNTP(t, addr)
	c.ask(request(4, wire.ModeClient))
	up.set(func(ts *timeServer) { ts.refid = [4]byte{192, 0, 2, 9} })
	c.send(request(4, wire.ModeClient))
	c.expectSilence("an answer from a source that changed")
	awaitCounters(t, s, func(sn proxy.Snapshot) bool {
		return sn.NTPSourceChanged >= 1 && sn.Refusals["ntp"]["source_changed"] >= 1
	}, "the source change refused")
	// The next poll is answered again: the baseline moved to what the
	// server is now, so this is not a permanent outage from one change.
	// The counter is read by polling, because it is incremented after the
	// answer is written.
	c.ask(request(4, wire.ModeClient))
	awaitCounters(t, s, func(sn proxy.Snapshot) bool { return sn.NTPAnswered >= 2 },
		"the relay answering again after the change became the new normal")
}

// A leap second announced in a month the IERS never uses, forwarded and
// said: the client hears the announcement from every other server too, so
// hiding it would lose the estate the one event worth reading.
func TestNTPALeapSecondOutOfSeasonIsSaid(t *testing.T) {
	up := startTimeServer(t, &timeServer{stratum: 2, leap: wire.LeapAddSecond})
	s, addr := ntpServer(t, `        upstream: clocks
        allow_clients: ["127.0.0.0/8"]
        quality: {compare_sources: false, leap_policy: alert, leap_window: 1h}`, up)

	c := dialNTP(t, addr)
	got, _ := c.ask(request(4, wire.ModeClient))
	if got.Leap != wire.LeapAddSecond {
		t.Fatalf("the announcement did not reach the client: leap %s", got.Leap)
	}
	awaitCounters(t, s, func(sn proxy.Snapshot) bool {
		return sn.NTPLeapUnexpected >= 1 || sn.NTPLeapAnnounced >= 1
	}, "the leap announcement")
}

// The answer whose own timestamps cannot describe an exchange: the
// cheapest forgery there is, and the client would compute an offset from
// it.
func TestNTPAnAnswerWithImpossibleTimestampsIsRefused(t *testing.T) {
	up := startTimeServer(t, &timeServer{stratum: 2})
	// A server whose answer says it was transmitted before the request
	// arrived. The test server builds a sound answer, so this is done by
	// hand: the garbage hook sends exact bytes.
	bad := &wire.Packet{Version: 4, Mode: wire.ModeServer, Stratum: 2,
		ReferenceID: [4]byte{10, 0, 0, 1},
		Receive:     wire.TimestampOf(time.Now().Add(time.Hour)),
		Transmit:    wire.TimestampOf(time.Now())}
	s, addr := ntpServer(t, `        upstream: clocks
        allow_clients: ["127.0.0.0/8"]
        quality: {compare_sources: false}`, up)
	c := dialNTP(t, addr)
	// The origin timestamp has to be this request's, or the answer is
	// unsolicited and refused earlier for another reason.
	req := request(4, wire.ModeClient)
	bad.Origin = req.Transmit
	up.set(func(ts *timeServer) { ts.garbage = bad.Bytes() })
	c.send(req)
	c.expectSilence("an answer whose timestamps cannot describe an exchange")
	// And refused for that reason rather than for being unsolicited,
	// which is what an answer with the wrong origin timestamp would be.
	awaitCounters(t, s, func(sn proxy.Snapshot) bool {
		return sn.Refusals["ntp"]["bogus_timestamps"] >= 1
	}, "the refusal naming the timestamps")
}
