package amqpwire

import (
	"bytes"
	"testing"
)

// Fuzzing is the primary bug-finder for this package, because everything
// in it is a length or a count that came off the network. The properties
// asserted are the two that matter to a relay: nothing panics, and nothing
// is reported as read when it was not.

// FuzzFrames drives the frame reader with whatever the fuzzer produces,
// starting from a real protocol header so the framing is in force.
func FuzzFrames(f *testing.F) {
	f.Add(join(header091(), frame091(FrameMethod, 1, method(ClassQueue, 10,
		short(0), shortstr("work"), bits(false, true, false, false, false), table()))))
	f.Add(join(header091(), frame091(FrameHeader, 1,
		contentHeader(ClassBasic, 100, 1<<propContentType, shortstr("text/plain")))))
	f.Add(join(header091(), frame091(FrameBody, 1, []byte("hello"))))
	f.Add(join(header10(ProtoSASL), frame10(FrameSASL, 0,
		perf10(uint8(PerfSASLInit), sym10("PLAIN"), bin10([]byte("\x00u\x00p"))))))
	f.Add(join(header10(ProtoAMQP), frame10(FrameAMQP, 0,
		perf10(uint8(PerfAttach), str10("l"), uint10(1), bool10(false), null10(), null10(),
			source10("/queue/work", false), target10("", false)))))

	f.Fuzz(func(t *testing.T, in []byte) {
		r := NewReader(bytes.NewReader(in), MinFrameMax091)
		h, err := r.Header()
		if err != nil {
			return
		}
		// A header that parsed is eight octets of the input, and the
		// octets it hands back are those octets: a relay forwards them.
		if !bytes.Equal(h.Bytes(), in[:HeaderSize]) {
			t.Fatalf("the header was rewritten: %q became %q", in[:HeaderSize], h.Bytes())
		}
		if h.Version() == Unknown {
			return
		}
		for i := 0; i < 64; i++ {
			fr, err := r.Next()
			if err != nil {
				return
			}
			// Every frame's payload is inside its own octets, and its own
			// octets are no larger than the bound.
			if len(fr.Raw) > r.Max()+8 {
				t.Fatalf("a frame of %d octets passed a bound of %d", len(fr.Raw), r.Max())
			}
			if len(fr.Payload) > len(fr.Raw) {
				t.Fatalf("a payload of %d octets in a frame of %d", len(fr.Payload), len(fr.Raw))
			}
			readFrame(t, fr)
		}
	})
}

// readFrame does to a frame what the relay does: whatever the version and
// the type say it holds.
func readFrame(t *testing.T, fr *Frame) {
	t.Helper()
	if fr.Version == V10 {
		if len(fr.Payload) == 0 {
			return
		}
		p, err := ParsePerformative(fr.Payload)
		if err != nil {
			return
		}
		// Every accessor, on every performative: an accessor that
		// answered about a performative it is not for would be a policy
		// reading one field as another.
		p.Open()
		p.Attach()
		p.Transfer()
		p.Dynamic()
		p.Handle()
		p.SASLInit()
		p.SASLMechanisms()
		p.SASLOutcome()
		p.CloseError()
		if p.Known() && p.Name() == "" {
			t.Fatal("a known performative has no name")
		}
		return
	}
	switch fr.Type {
	case FrameMethod:
		m, err := ParseMethod(fr.Payload)
		if err != nil {
			return
		}
		targets, known := m.Targets()
		if !known && len(targets) != 0 {
			t.Fatalf("%s: targets were returned with known false", m.Name())
		}
		for _, tg := range targets {
			switch tg.Kind {
			case KindExchange, KindQueue, KindRoutingKey:
			default:
				t.Fatalf("%s: target kind %q", m.Name(), tg.Kind)
			}
		}
		if _, user, ok := m.Mechanism(); ok && user != "" && m.Name() != "connection.start-ok" {
			t.Fatalf("%s answered as a start-ok", m.Name())
		}
		m.VirtualHost()
		m.Tune()
		m.Mechanisms()
		m.Consumer()
		m.Queue()
		m.Exchange()
		m.CloseReason()
	case FrameHeader:
		h, err := ParseContentHeader(fr.Payload)
		if err != nil {
			return
		}
		if h.Set == nil {
			t.Fatal("a content header came back with no property set")
		}
	}
}

// FuzzMethod drives the 0-9-1 argument layouts directly, which is where the
// field table and the packed bits are.
func FuzzMethod(f *testing.F) {
	f.Add(method(ClassQueue, 20, short(0), shortstr("work"), shortstr("events"),
		shortstr("key"), bits(false), table(entryS("x-dead-letter-exchange", "dlx"))))
	f.Add(method(ClassConnection, 11, table(), shortstr("PLAIN"),
		longstr([]byte("\x00user\x00pass")), shortstr("en_US")))
	f.Add(method(ClassBasic, 40, short(0), shortstr("events"), shortstr("k"), bits(true, false)))
	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := ParseMethod(in)
		if err != nil {
			return
		}
		_, user, ok := m.Mechanism()
		if ok && len(user) > len(in) {
			t.Fatalf("an identity of %d octets came out of %d", len(user), len(in))
		}
		targets, known := m.Targets()
		if !known && len(targets) != 0 {
			t.Fatal("targets with known false")
		}
		for _, tg := range targets {
			if len(tg.Name) > len(in) {
				t.Fatalf("a name of %d octets came out of %d", len(tg.Name), len(in))
			}
		}
	})
}

// FuzzPerformative drives the 1.0 type reader, which is the largest
// attack surface here: constructors, sizes, counts and nesting.
func FuzzPerformative(f *testing.F) {
	f.Add(perf10(uint8(PerfOpen), str10("client"), str10("/"), uint10(4096)))
	f.Add(perf10(uint8(PerfAttach), str10("l"), uint10(1), bool10(true), null10(), null10(),
		source10("/exchange/events/k", false), target10("", true)))
	f.Add(perf10(uint8(PerfTransfer), uint10(1), uint10(1), bin10([]byte{9}), uint10(0),
		bool10(false), bool10(true)))
	f.Add(described10(0x10, bigList10([][]byte{null10()}, [][]byte{str10("x")})))
	f.Fuzz(func(t *testing.T, in []byte) {
		p, err := ParsePerformative(in)
		if err != nil {
			return
		}
		if len(p.Fields) > maxValues {
			t.Fatalf("%d fields out of %d octets", len(p.Fields), len(in))
		}
		_, host, _, _, _, _ := p.Open()
		if len(host) > len(in) {
			t.Fatalf("a hostname of %d octets came out of %d", len(host), len(in))
		}
		name, _, role, source, target, ok := p.Attach()
		if ok {
			if role != RoleSender && role != RoleReceiver {
				t.Fatalf("role %q", role)
			}
			for _, s := range []string{name, source, target} {
				if len(s) > len(in) {
					t.Fatalf("a field of %d octets came out of %d", len(s), len(in))
				}
			}
			for _, tg := range SplitAddress(target) {
				if len(tg.Name) > len(target)+len("amq.topic") {
					t.Fatalf("an address split into %q", tg.Name)
				}
			}
		}
		p.Transfer()
		p.Handle()
		p.Dynamic()
		p.SASLInit()
		p.SASLMechanisms()
		p.SASLOutcome()
		p.CloseError()
	})
}
