package ntp

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/ntp"
)

func ptr[T any](v T) *T { return &v }

func policy(t *testing.T, l *config.NTPListener, keys wire.Keys) *Policy {
	t.Helper()
	p, err := compile(l, keys)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func client(t *testing.T, addr string) netip.AddrPort {
	t.Helper()
	return netip.AddrPortFrom(netip.MustParseAddr(addr), 45123)
}

// req builds a parsed request the way the listener does, so a policy test
// decides about the same thing the relay decides about.
func req(t *testing.T, from string, p *wire.Packet) request {
	t.Helper()
	raw := p.Bytes()
	k, err := wire.Classify(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wire.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return request{client: client(t, from), kind: k, pkt: parsed, size: len(raw)}
}

func clientPacket() *wire.Packet {
	return &wire.Packet{Version: 4, Mode: wire.ModeClient, Poll: 6, Precision: -20,
		Transmit: wire.TimestampOf(time.Now())}
}

// The dispatch decides from the first octet, and what it refuses it
// refuses before the parser is reached.
func TestTheDispatchRefusesWhatIsNotThisProtocol(t *testing.T) {
	p := policy(t, &config.NTPListener{Upstream: "clocks"}, nil)
	for _, tc := range []struct {
		name   string
		kind   wire.Kind
		reason string
	}{
		{"the control protocol", wire.Kind{Version: 4, Mode: wire.ModeControl}, "control_mode"},
		{"the private protocol", wire.Kind{Version: 4, Mode: wire.ModePrivate}, "private_mode"},
		{"version 5", wire.Kind{Version: 5, Mode: wire.ModeClient}, "version5"},
		{"version 0", wire.Kind{Version: 0, Mode: wire.ModeClient}, "version"},
		{"a version the profile does not name", wire.Kind{Version: 2, Mode: wire.ModeClient}, "version_not_allowed"},
		{"a mode the profile does not name", wire.Kind{Version: 4, Mode: wire.ModeBroadcast}, "mode_not_allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := p.Dispatch(tc.kind)
			if d.Allow || d.Reason != tc.reason {
				t.Fatalf("decision %+v, want %s", d, tc.reason)
			}
		})
	}
	// The two the default profile does allow.
	for _, k := range []wire.Kind{{Version: 4, Mode: wire.ModeClient}, {Version: 3, Mode: wire.ModeServer}} {
		if d := p.Dispatch(k); !d.Allow {
			t.Errorf("version %d mode %s: %+v", k.Version, k.Mode, d)
		}
	}
	// Version 1 has no mode field, and the dispatch decides about the
	// mode it effectively is rather than about a reserved value nobody
	// can write down.
	legacy := policy(t, &config.NTPListener{Upstream: "clocks", Versions: []int{1, 4}}, nil)
	if d := legacy.Dispatch(wire.Kind{Version: 1, Mode: wire.ModeReserved}); !d.Allow {
		t.Errorf("a version 1 packet with the mode bits zero: %+v", d)
	}
	// Version 5 passes through only where a listener says so, and it is
	// still not parsed.
	five := policy(t, &config.NTPListener{Upstream: "clocks", AllowVersion5: true}, nil)
	if d := five.Dispatch(wire.Kind{Version: 5, Mode: wire.ModeClient}); !d.Allow || d.Reason != "version5_passthrough" {
		t.Errorf("version 5 pass-through: %+v", d)
	}
}

// The request policy: the association shapes, the bounds on what a packet
// may carry, and the two identities a listener can demand.
func TestTheRequestPolicy(t *testing.T) {
	base := &config.NTPListener{Upstream: "clocks", MaxPacketBytes: 200,
		Modes: []string{"client", "server", "symmetric_active"}, Peers: []string{"10.9.9.9/32"}}
	p := policy(t, base, nil)
	if d := p.Request(req(t, "10.0.0.5", clientPacket())); !d.Allow {
		t.Fatalf("an ordinary client: %+v", d)
	}
	// A symmetric association is a relationship between named peers.
	sym := clientPacket()
	sym.Mode = wire.ModeSymActive
	if d := p.Request(req(t, "10.0.0.5", sym)); d.Allow || d.Reason != "not_a_peer" {
		t.Errorf("a symmetric packet from a stranger: %+v", d)
	}
	if d := p.Request(req(t, "10.9.9.9", sym)); !d.Allow {
		t.Errorf("a symmetric packet from the named peer: %+v", d)
	}
	// Broadcast is confined the same way, and to the same list.
	bc := clientPacket()
	bc.Mode = wire.ModeBroadcast
	if d := p.Request(req(t, "10.0.0.5", bc)); d.Allow || d.Reason != "broadcast_not_allowed" {
		t.Errorf("a broadcast from a stranger: %+v", d)
	}
	// The packet bound, counted on the bytes that arrived.
	big := clientPacket()
	big.Extensions = []wire.Extension{{Type: wire.EFNTSCookie, Body: make([]byte, 200)}}
	if d := p.Request(req(t, "10.0.0.5", big)); d.Allow || d.Reason != "packet_too_large" {
		t.Errorf("a packet past the bound: %+v", d)
	}
	// An unknown field, and the same field where the listener allows it.
	unknown := clientPacket()
	// The body is long enough that the field cannot be read as a MAC:
	// a single trailing field of twenty or twenty-four octets is the
	// ambiguity below rather than this case.
	unknown.Extensions = []wire.Extension{{Type: 0x0002, Body: make([]byte, 100)}}
	if d := p.Request(req(t, "10.0.0.5", unknown)); d.Allow || d.Reason != "unknown_extension" {
		t.Errorf("a field this relay cannot read: %+v", d)
	}
	allowUnknown := policy(t, &config.NTPListener{Upstream: "clocks",
		Extensions: &config.NTPExtensions{AllowUnknown: true}}, nil)
	if d := allowUnknown.Request(req(t, "10.0.0.5", unknown)); !d.Allow {
		t.Errorf("a field the listener allows: %+v", d)
	}
	// More fields than the listener allows.
	bounded := policy(t, &config.NTPListener{Upstream: "clocks",
		Extensions: &config.NTPExtensions{Max: 1}}, nil)
	two := clientPacket()
	two.Extensions = []wire.Extension{
		{Type: wire.EFUniqueIdentifier, Body: make([]byte, 32)},
		{Type: wire.EFNTSCookie, Body: make([]byte, 100)},
	}
	if d := bounded.Request(req(t, "10.0.0.5", two)); d.Allow || d.Reason != "too_many_extensions" {
		t.Errorf("two fields where one is allowed: %+v", d)
	}
	// NTS required, and satisfied.
	needNTS := policy(t, &config.NTPListener{Upstream: "clocks", NTS: &config.NTPNTS{Require: true}}, nil)
	if d := needNTS.Request(req(t, "10.0.0.5", clientPacket())); d.Allow || d.Reason != "nts_required" {
		t.Errorf("a plain packet where NTS is required: %+v", d)
	}
	protected := clientPacket()
	protected.Extensions = []wire.Extension{
		{Type: wire.EFUniqueIdentifier, Body: make([]byte, 32)},
		{Type: wire.EFNTSAuthenticator, Body: make([]byte, 64)},
	}
	if d := needNTS.Request(req(t, "10.0.0.5", protected)); !d.Allow {
		t.Errorf("a protected packet where NTS is required: %+v", d)
	}
	// Authentication required: NTS counts, a MAC counts if it verifies,
	// and a crypto-NAK is not authentication.
	secret := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	key := wire.Key{ID: 7, Algorithm: wire.AlgAESCMAC, Secret: secret}
	keys := wire.Keys{7: key}
	needAuth := policy(t, &config.NTPListener{Upstream: "clocks",
		Auth: &config.NTPAuth{Require: true}}, keys)
	if d := needAuth.Request(req(t, "10.0.0.5", clientPacket())); d.Allow || d.Reason != "auth_required" {
		t.Errorf("no authentication where it is required: %+v", d)
	}
	if d := needAuth.Request(req(t, "10.0.0.5", protected)); !d.Allow {
		t.Errorf("NTS counts as the authentication this relay cannot itself check: %+v", d)
	}
	signed, err := key.Sign(clientPacket().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := wire.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := wire.Classify(signed)
	good := request{client: client(t, "10.0.0.5"), kind: k, pkt: parsed, size: len(signed)}
	if d := needAuth.Request(good); !d.Allow {
		t.Errorf("a MAC this listener can verify: %+v", d)
	}
	bad := append([]byte(nil), signed...)
	bad[len(bad)-1] ^= 1
	parsedBad, err := wire.Parse(bad)
	if err != nil {
		t.Fatal(err)
	}
	if d := needAuth.Request(request{client: client(t, "10.0.0.5"), kind: k, pkt: parsedBad, size: len(bad)}); d.Allow || d.Reason != "auth_failed" {
		t.Errorf("a MAC that does not verify: %+v", d)
	}
	nak := append(clientPacket().Bytes(), 0, 0, 0, 7)
	parsedNAK, err := wire.Parse(nak)
	if err != nil {
		t.Fatal(err)
	}
	if d := needAuth.Request(request{client: client(t, "10.0.0.5"), kind: k, pkt: parsedNAK, size: len(nak)}); d.Allow {
		t.Errorf("a crypto-NAK is not authentication: %+v", d)
	}
	// A MAC the listener did not demand is still checked when it can be:
	// a packet whose own authentication fails is not one to pass on
	// because nobody insisted on it.
	optional := policy(t, &config.NTPListener{Upstream: "clocks"}, keys)
	if d := optional.Request(request{client: client(t, "10.0.0.5"), kind: k, pkt: parsedBad, size: len(bad)}); d.Allow {
		t.Errorf("an unrequired MAC that fails: %+v", d)
	}
	// The ambiguity of RFC 7822, read as a MAC and refused by default.
	tail := make([]byte, 24)
	tail[0], tail[1], tail[2], tail[3] = 0x01, 0x04, 0x00, 0x18
	amb := append(clientPacket().Bytes(), tail...)
	parsedAmb, err := wire.Parse(amb)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedAmb.MACAmbiguous {
		t.Fatal("the parser did not report the ambiguity")
	}
	if d := p.Request(request{client: client(t, "10.0.0.5"), kind: k, pkt: parsedAmb, size: len(amb)}); d.Allow || d.Reason != "ambiguous_mac" {
		t.Errorf("an ambiguous tail: %+v", d)
	}
	lenient := policy(t, &config.NTPListener{Upstream: "clocks", MaxPacketBytes: 200,
		Extensions: &config.NTPExtensions{RefuseAmbiguousMAC: ptr(false)}}, nil)
	if d := lenient.Request(request{client: client(t, "10.0.0.5"), kind: k, pkt: parsedAmb, size: len(amb)}); !d.Allow {
		t.Errorf("an ambiguous tail where the listener allows it: %+v", d)
	}
}

// The response policy: the server-quality rules, which are about answers
// and not about requests.
func TestTheResponsePolicy(t *testing.T) {
	l := &config.NTPListener{Upstream: "clocks", Quality: &config.NTPQuality{
		MaxStratum: 8, MaxRootDispersion: config.Duration(time.Second),
		MaxRootDelay: config.Duration(time.Second), MaxDelay: config.Duration(500 * time.Millisecond),
		MaxOffset: config.Duration(time.Second)}}
	p := policy(t, l, nil)
	answer := func(edit func(*wire.Packet)) *wire.Packet {
		// A sound answer carries a reference identifier: at stratum 2
		// that is the upstream it synchronises to, and an answer with
		// none is a server claiming a place in the tree while naming
		// nothing above it.
		a := &wire.Packet{Version: 4, Mode: wire.ModeServer, Stratum: 2,
			ReferenceID: [4]byte{10, 30, 10, 1},
			Reference:   wire.TimestampOf(time.Now().Add(-time.Minute)),
			Receive:     wire.TimestampOf(time.Now()), Transmit: wire.TimestampOf(time.Now())}
		if edit != nil {
			edit(a)
		}
		parsed, err := wire.Parse(a.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	if d := p.Response(response{pkt: answer(nil)}); !d.Allow {
		t.Fatalf("a sound answer: %+v", d)
	}
	for _, tc := range []struct {
		name   string
		edit   func(*wire.Packet)
		resp   response
		reason string
	}{
		{"a client-mode packet arriving as an answer",
			func(a *wire.Packet) { a.Mode = wire.ModeClient }, response{}, "response_mode"},
		{"a server that says it is not synchronised",
			func(a *wire.Packet) { a.Leap = wire.LeapUnsynchronised }, response{}, "unsynchronised"},
		{"the protocol's own unsynchronised stratum",
			func(a *wire.Packet) { a.Stratum = 16 }, response{}, "unsynchronised_stratum"},
		{"a stratum past the bound",
			func(a *wire.Packet) { a.Stratum = 9 }, response{}, "stratum_too_high"},
		{"a dispersion past the bound",
			func(a *wire.Packet) { a.RootDispersion = wire.ShortOf(2 * time.Second) }, response{}, "root_dispersion"},
		{"a root delay past the bound",
			func(a *wire.Packet) { a.RootDelay = wire.ShortOf(2 * time.Second) }, response{}, "root_delay"},
		{"a round trip past the bound", nil,
			response{delay: 2 * time.Second}, "delay"},
		{"an offset past the bound", nil,
			response{offset: 2 * time.Second}, "offset"},
		{"an offset past the bound the other way", nil,
			response{offset: -2 * time.Second}, "offset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.resp
			r.pkt = answer(tc.edit)
			d := p.Response(r)
			if d.Allow || d.Reason != tc.reason {
				t.Fatalf("decision %+v, want %s", d, tc.reason)
			}
		})
	}
	// A kiss-o'-death is a message rather than time, and forwarding it is
	// a choice either way.
	kiss := answer(func(a *wire.Packet) {
		a.Stratum = 0
		copy(a.ReferenceID[:], "RATE")
	})
	if d := p.Response(response{pkt: kiss}); !d.Allow || !strings.HasPrefix(d.Reason, "kiss_") {
		t.Errorf("a kiss forwarded by default: %+v", d)
	}
	noKiss := policy(t, &config.NTPListener{Upstream: "clocks", KoD: &config.NTPKoD{Forward: ptr(false)}}, nil)
	if d := noKiss.Response(response{pkt: kiss}); d.Allow || d.Reason != "kiss_of_death" {
		t.Errorf("a kiss the listener refuses: %+v", d)
	}
	// The downgrades: NTS asked for and not answered, and the same for a
	// MAC. Both are refusals rather than a quieter answer.
	if d := p.Response(response{pkt: answer(nil), ntsAsked: true}); d.Allow || d.Reason != "nts_stripped" {
		t.Errorf("a protected request answered in the clear: %+v", d)
	}
	if d := p.Response(response{pkt: answer(nil), authAsked: true}); d.Allow || d.Reason != "auth_stripped" {
		t.Errorf("an authenticated request answered without one: %+v", d)
	}
	// A listener that says so passes an unsynchronised server's answer on
	// to the clients, which is what the warning at validation is about.
	lenient := policy(t, &config.NTPListener{Upstream: "clocks",
		Quality: &config.NTPQuality{RefuseUnsynchronised: ptr(false)}}, nil)
	if d := lenient.Response(response{pkt: answer(func(a *wire.Packet) { a.Leap = wire.LeapUnsynchronised })}); !d.Allow {
		t.Errorf("an unsynchronised answer where the listener allows it: %+v", d)
	}
}

// The client and server lists.
func TestTheClientAndServerLists(t *testing.T) {
	p := policy(t, &config.NTPListener{Upstream: "clocks",
		AllowClients: []string{"10.0.0.0/8"}, DenyClients: []string{"10.9.0.0/16"},
		AllowServers: []string{"10.30.10.0/24"}}, nil)
	for _, tc := range []struct {
		addr string
		ok   bool
	}{{"10.0.0.5", true}, {"10.9.0.5", false}, {"192.0.2.1", false}} {
		if got := p.ClientAllowed(netip.MustParseAddr(tc.addr)); got != tc.ok {
			t.Errorf("client %s: %v", tc.addr, got)
		}
	}
	for _, tc := range []struct {
		addr string
		ok   bool
	}{{"10.30.10.21", true}, {"192.0.2.1", false}} {
		if got := p.ServerAllowed(netip.MustParseAddr(tc.addr)); got != tc.ok {
			t.Errorf("server %s: %v", tc.addr, got)
		}
	}
	// An empty list allows what the deny list does not refuse.
	open := policy(t, &config.NTPListener{Upstream: "clocks"}, nil)
	if !open.ClientAllowed(netip.MustParseAddr("192.0.2.1")) || !open.ServerAllowed(netip.MustParseAddr("192.0.2.1")) {
		t.Error("an empty list should allow")
	}
}

// A policy the configuration cannot express is refused at compile rather
// than at the first packet.
func TestABrokenPolicyIsRefusedAtCompile(t *testing.T) {
	for _, tc := range []struct {
		name string
		l    *config.NTPListener
	}{
		{"a client network that is not one", &config.NTPListener{AllowClients: []string{"10.0.0.1"}}},
		{"a peer network that is not one", &config.NTPListener{Peers: []string{"nope"}}},
		{"a version this parser does not read", &config.NTPListener{Versions: []int{9}}},
		{"a mode nobody defined", &config.NTPListener{Modes: []string{"gossip"}}},
		{"a management mode named as a mode", &config.NTPListener{Modes: []string{"control"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compile(tc.l, nil); err == nil {
				t.Fatal("compiled")
			}
		})
	}
}

// The learning report is the three lists a policy is made of, with the
// traffic they came from written above them.
func TestTheLearningReportIsThePolicyLists(t *testing.T) {
	l := NewLearner("time", "", time.Minute, 64)
	now := time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	r := req(t, "10.0.0.9", clientPacket())
	l.Observe(r, Decision{Allow: true}, now)
	l.Observe(r, Decision{Allow: true}, now.Add(64*time.Second))
	l.Observe(r, Decision{Reason: "client_not_allowed"}, now.Add(128*time.Second))
	v3 := clientPacket()
	v3.Version = 3
	l.Observe(req(t, "10.0.0.10", v3), Decision{Allow: true}, now)
	out := l.Report()
	for _, want := range []string{
		"observed:", "client: 10.0.0.9", "version: 4", "mode: client", "packets: 3",
		"denied_by_policy: 1", "poll_seconds: [64, 64]", "nts_fields: false",
		"allow_clients: [10.0.0.10/32, 10.0.0.9/32]", "versions: [3, 4]", "modes: [client]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not carry %q:\n%s", want, out)
		}
	}
	if l.Subjects() != 2 {
		t.Errorf("subjects %d, want 2", l.Subjects())
	}
	// The bound drops the oldest and says so in the report.
	small := NewLearner("time", "", time.Minute, 2)
	for _, addr := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		small.Observe(req(t, addr, clientPacket()), Decision{Allow: true}, now)
	}
	if small.Subjects() != 2 || small.Dropped() != 1 {
		t.Errorf("subjects %d dropped %d", small.Subjects(), small.Dropped())
	}
	if !strings.Contains(small.Report(), "1 subjects dropped at the bound") {
		t.Error("the report does not say the bound was reached")
	}
	// The file is replaced atomically and owner readable only.
	dir := t.TempDir()
	path := filepath.Join(dir, "learned.yaml")
	onDisk := NewLearner("time", path, time.Minute, 64)
	onDisk.Observe(r, Decision{Allow: true}, now)
	if err := onDisk.Write(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("%d files, want only the report", len(entries))
	}
	// A learner that is not there is every call a no-op, because that is
	// what a listener with learning off is.
	var absent *Learner
	absent.Observe(r, Decision{Allow: true}, now)
	absent.Start(nil)
	if err := absent.Write(); err != nil {
		t.Error(err)
	}
	if err := absent.Stop(); err != nil {
		t.Error(err)
	}
	if absent.Subjects() != 0 {
		t.Error("a learner that is not there holds nothing")
	}
}

// The trace stops at its bound and says so in the file.
func TestTheTraceStopsAtItsBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	tr, err := NewTracer("time", path, 400, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := wire.Parse(clientPacket().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		tr.Request("time", client(t, "10.0.0.9"), pkt, Decision{Allow: true})
	}
	if !tr.Full() || tr.Dropped.Load() == 0 {
		t.Fatalf("full %v dropped %d", tr.Full(), tr.Dropped.Load())
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) > 400+256 {
		t.Fatalf("%d bytes past a bound of 400", len(b))
	}
	for _, want := range []string{`"direction":"request"`, `"mode":"client"`, "trace_full"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the trace does not carry %s:\n%s", want, b)
		}
	}
	// The directions are selectable, because the responses double the
	// file and the requests are usually the question.
	only := filepath.Join(t.TempDir(), "requests.jsonl")
	tr2, err := NewTracer("time", only, 1<<20, ptr(true), ptr(false))
	if err != nil {
		t.Fatal(err)
	}
	tr2.Request("time", client(t, "10.0.0.9"), pkt, Decision{Allow: true})
	tr2.Response("time", client(t, "10.0.0.9"), client(t, "10.0.0.1"), pkt, Decision{Allow: true})
	if err := tr2.Close(); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(only)
	if strings.Contains(string(b2), `"direction":"response"`) {
		t.Errorf("a response was traced on a request-only trace:\n%s", b2)
	}
	if strings.Count(string(b2), "\n") != 1 {
		t.Errorf("want one line:\n%s", b2)
	}
	// A tracer that is not there is every call a no-op.
	var absent *Tracer
	absent.Request("time", client(t, "10.0.0.9"), pkt, Decision{})
	absent.Response("time", client(t, "10.0.0.9"), client(t, "10.0.0.1"), pkt, Decision{})
	if absent.Full() {
		t.Error("a tracer that is not there is not full")
	}
	if err := absent.Close(); err != nil {
		t.Error(err)
	}
}

// The smoothing is what stops one slow answer moving a source's state,
// and it has to reach a new value rather than crawl towards it for ever.
func TestTheMeasurementSmoothing(t *testing.T) {
	if got := smooth(0, 100*time.Millisecond); got != 100*time.Millisecond {
		t.Fatalf("the first sample is the value, got %v", got)
	}
	v := time.Duration(0)
	v = smooth(v, 80*time.Millisecond)
	for i := 0; i < 40; i++ {
		v = smooth(v, 120*time.Millisecond)
	}
	if v < 115*time.Millisecond || v > 120*time.Millisecond {
		t.Fatalf("after forty samples of 120ms the average is %v", v)
	}
	// One outlier moves it a little and not a lot.
	before := v
	v = smooth(v, time.Second)
	if v > before+150*time.Millisecond {
		t.Fatalf("one outlier moved the average from %v to %v", before, v)
	}
	if abs(-time.Second) != time.Second || abs(time.Second) != time.Second {
		t.Error("abs")
	}
}

// The checks that read a server's answer against itself rather than
// against a bound: the timestamps, the reference identifier, the
// synchronisation distance, the stratum list and the leap announcement.
// Each of these is a forgery that passes every threshold an estate would
// set, which is why each has a rule of its own.
func TestAnAnswerIsReadAgainstItself(t *testing.T) {
	sound := func(edit func(*wire.Packet)) *wire.Packet {
		a := &wire.Packet{Version: 4, Mode: wire.ModeServer, Stratum: 2,
			ReferenceID: [4]byte{10, 30, 10, 1},
			Reference:   wire.TimestampOf(time.Now().Add(-time.Minute)),
			Receive:     wire.TimestampOf(time.Now()), Transmit: wire.TimestampOf(time.Now())}
		if edit != nil {
			edit(a)
		}
		parsed, err := wire.Parse(a.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	p := policy(t, &config.NTPListener{Upstream: "clocks"}, nil)
	for _, tc := range []struct {
		name   string
		edit   func(*wire.Packet)
		reason string
	}{
		{"no transmit timestamp, so the answer says nothing about when it was sent",
			func(a *wire.Packet) { a.Transmit = 0 }, "bogus_timestamps"},
		{"no receive timestamp",
			func(a *wire.Packet) { a.Receive = 0 }, "bogus_timestamps"},
		{"an answer sent before the request reached it",
			func(a *wire.Packet) { a.Receive = wire.TimestampOf(time.Now().Add(time.Second)) },
			"bogus_timestamps"},
		{"a last synchronisation later than the request",
			func(a *wire.Packet) { a.Reference = wire.TimestampOf(time.Now().Add(time.Hour)) },
			"bogus_timestamps"},
		{"a stratum 1 answer that names no reference clock",
			func(a *wire.Packet) { a.Stratum = 1; a.ReferenceID = [4]byte{0, 1, 2, 3} }, "bogus_refid"},
		{"a stratum 2 answer that names no upstream",
			func(a *wire.Packet) { a.ReferenceID = [4]byte{} }, "bogus_refid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if d := p.Response(response{pkt: sound(tc.edit)}); d.Allow || d.Reason != tc.reason {
				t.Fatalf("decision %+v, want %s", d, tc.reason)
			}
		})
	}
	// A stratum 1 answer whose identifier is a reference clock's name is
	// the normal case and must pass, or the check above would be a check
	// on every stratum 1 server.
	if d := p.Response(response{pkt: sound(func(a *wire.Packet) {
		a.Stratum = 1
		a.ReferenceID = [4]byte{}
		copy(a.ReferenceID[:], "GPS")
	})}); !d.Allow {
		t.Errorf("a real stratum 1 answer: %+v", d)
	}
	// An interleaved answer's transmit timestamp is the server's own
	// previous one on purpose, so it is older than this request's
	// arrival. Applying the order check to it would refuse the most
	// accurate exchange the protocol has.
	late := sound(func(a *wire.Packet) { a.Receive = wire.TimestampOf(time.Now().Add(time.Second)) })
	if d := p.Response(response{pkt: late, interleaved: true}); !d.Allow {
		t.Errorf("an interleaved answer: %+v", d)
	}
	// A listener that says so turns each check off, which is what the
	// warnings at validation are about.
	lenient := policy(t, &config.NTPListener{Upstream: "clocks", Quality: &config.NTPQuality{
		RefuseBogusTimestamps: ptr(false), RefuseBogusRefID: ptr(false)}}, nil)
	if d := lenient.Response(response{pkt: sound(func(a *wire.Packet) { a.Transmit = 0 })}); !d.Allow {
		t.Errorf("bogus timestamps where the listener allows them: %+v", d)
	}
	if d := lenient.Response(response{pkt: sound(func(a *wire.Packet) { a.ReferenceID = [4]byte{} })}); !d.Allow {
		t.Errorf("a missing reference identifier where the listener allows it: %+v", d)
	}

	// The synchronisation distance: half the root delay plus the root
	// dispersion. Each half is inside its own bound and the sum is not,
	// which is the answer this rule exists for.
	dist := policy(t, &config.NTPListener{Upstream: "clocks", Quality: &config.NTPQuality{
		MaxRootDelay: config.Duration(time.Second), MaxRootDispersion: config.Duration(time.Second),
		MaxRootDistance: config.Duration(600 * time.Millisecond)}}, nil)
	far := sound(func(a *wire.Packet) {
		a.RootDelay = wire.ShortOf(900 * time.Millisecond)
		a.RootDispersion = wire.ShortOf(900 * time.Millisecond)
	})
	if d := dist.Response(response{pkt: far}); d.Allow || d.Reason != "root_distance" {
		t.Errorf("a distant answer inside both halves: %+v", d)
	}
	near := sound(func(a *wire.Packet) {
		a.RootDelay = wire.ShortOf(200 * time.Millisecond)
		a.RootDispersion = wire.ShortOf(200 * time.Millisecond)
	})
	if d := dist.Response(response{pkt: near}); !d.Allow {
		t.Errorf("an answer inside the distance: %+v", d)
	}

	// The stratum list, which is not the bound: a list admits what it
	// names and a bound admits everything below it.
	list := policy(t, &config.NTPListener{Upstream: "clocks",
		Quality: &config.NTPQuality{AllowStrata: []int{1, 2}}}, nil)
	if d := list.Response(response{pkt: sound(nil)}); !d.Allow {
		t.Errorf("a stratum named in the list: %+v", d)
	}
	if d := list.Response(response{pkt: sound(func(a *wire.Packet) { a.Stratum = 3 })}); d.Allow ||
		d.Reason != "stratum_not_allowed" {
		t.Errorf("a stratum the list does not name: %+v", d)
	}

	// Server identity, as far as the protocol allows it without a key:
	// the reference identifier the estate expects.
	named := policy(t, &config.NTPListener{Upstream: "clocks",
		Quality: &config.NTPQuality{ExpectRefID: []string{"GPS", "10.30.10.1"}}}, nil)
	if d := named.Response(response{pkt: sound(nil)}); !d.Allow {
		t.Errorf("the identifier the estate expects: %+v", d)
	}
	if d := named.Response(response{pkt: sound(func(a *wire.Packet) {
		a.ReferenceID = [4]byte{192, 0, 2, 9}
	})}); d.Allow || d.Reason != "refid_not_allowed" {
		t.Errorf("an identifier the estate does not expect: %+v", d)
	}
}

// The leap-second policy. An announcement is not a fault: it tells every
// client that hears it to plan to move its clock, which is why one in a
// month the IERS never uses is worth saying and worth being able to
// refuse.
func TestTheLeapSecondPolicy(t *testing.T) {
	answer := func(l wire.Leap) *wire.Packet {
		a := &wire.Packet{Version: 4, Mode: wire.ModeServer, Stratum: 2, Leap: l,
			ReferenceID: [4]byte{10, 30, 10, 1},
			Receive:     wire.TimestampOf(time.Now()), Transmit: wire.TimestampOf(time.Now())}
		parsed, err := wire.Parse(a.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	// The end of June, where a leap second really happens, and the
	// middle of August, where one does not.
	inSeason := time.Date(2026, time.June, 30, 12, 0, 0, 0, time.UTC)
	outOfSeason := time.Date(2026, time.August, 14, 12, 0, 0, 0, time.UTC)

	alert := policy(t, &config.NTPListener{Upstream: "clocks"}, nil) // the default
	if d := alert.Response(response{pkt: answer(wire.LeapAddSecond), now: inSeason}); !d.Allow || d.Reason != "" {
		t.Errorf("an announcement in season: %+v", d)
	}
	d := alert.Response(response{pkt: answer(wire.LeapAddSecond), now: outOfSeason})
	if !d.Allow || d.Reason != "leap_unexpected" {
		t.Errorf("an announcement out of season is forwarded and said: %+v", d)
	}
	quiet := policy(t, &config.NTPListener{Upstream: "clocks",
		Quality: &config.NTPQuality{LeapPolicy: "allow"}}, nil)
	if d := quiet.Response(response{pkt: answer(wire.LeapDeleteSecond), now: outOfSeason}); !d.Allow || d.Reason != "" {
		t.Errorf("an announcement where the listener says nothing: %+v", d)
	}
	window := policy(t, &config.NTPListener{Upstream: "clocks",
		Quality: &config.NTPQuality{LeapPolicy: "window"}}, nil)
	if d := window.Response(response{pkt: answer(wire.LeapAddSecond), now: outOfSeason}); d.Allow ||
		d.Reason != "leap_unexpected" {
		t.Errorf("an announcement out of season where the listener refuses it: %+v", d)
	}
	if d := window.Response(response{pkt: answer(wire.LeapAddSecond), now: inSeason}); !d.Allow {
		t.Errorf("an announcement in season where the listener refuses only the others: %+v", d)
	}
	never := policy(t, &config.NTPListener{Upstream: "clocks",
		Quality: &config.NTPQuality{LeapPolicy: "refuse"}}, nil)
	if d := never.Response(response{pkt: answer(wire.LeapAddSecond), now: inSeason}); d.Allow ||
		d.Reason != "leap_announced" {
		t.Errorf("an announcement where the listener refuses every one: %+v", d)
	}
	// And an answer that announces nothing is never touched by any of
	// these, whatever the month.
	for _, p := range []*Policy{alert, quiet, window, never} {
		if d := p.Response(response{pkt: answer(wire.LeapNone), now: outOfSeason}); !d.Allow || d.Reason != "" {
			t.Errorf("an ordinary answer: %+v", d)
		}
	}
	// A listener with no clock in the response still decides, because a
	// zero time means now rather than the epoch.
	if d := window.Response(response{pkt: answer(wire.LeapNone)}); !d.Allow {
		t.Errorf("an ordinary answer with no clock given: %+v", d)
	}
}

// Rendering a report while packets are still arriving.
//
// The report is rendered outside the learner's lock, from a snapshot taken under
// it. A snapshot that copied the observations by value would share their maps of
// key identifiers and strata, and a map written while it is being ranged over is
// not a race the runtime tolerates: it is a fatal "concurrent map iteration and
// map write" that takes the process down. For a relay in front of a plant's clocks
// that would be an outage caused by writing a report.
func TestAnNTPReportRenderedWhilePacketsArrive(t *testing.T) {
	l := NewLearner("time", "", time.Minute, 512)
	now := time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			p := clientPacket()
			// Authenticated, with a different key identifier each time: the map
			// of key identifiers is the one the report ranges over, so it has to
			// be the one that keeps being written.
			p.HasMAC = true
			p.KeyID = uint32(i)      //nolint:gosec // a test key identifier
			p.MAC = make([]byte, 16) //nolint:gosec // a MAC of a legal length; its value is not checked here
			l.Observe(req(t, "10.0.0.9", p), Decision{Allow: true}, now.Add(time.Duration(i)*time.Second))
		}
	}()
	for i := 0; i < 200; i++ {
		if r := l.Report(); r == "" {
			t.Fatal("the report came back empty")
		}
	}
	<-done
	if r := l.Report(); !strings.Contains(r, "key_ids: [") {
		t.Errorf("the report does not carry the key identifiers it ranged over:\n%s", r)
	}
}
