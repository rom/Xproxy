package opcua

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzParseChunk checks the framing against arbitrary octets. The invariant is not
// that everything parses: it is that a chunk which parses reports a body that is
// exactly the octets after the header, and that nothing panics on the way.
func FuzzParseChunk(f *testing.F) {
	f.Add([]byte("HELF\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff"))
	f.Add([]byte("MSGF\x10\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00"))
	f.Add([]byte("OPNF\x08\x00\x00\x00"))
	f.Add([]byte("ERRF\x08\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := ParseChunk(raw)
		if err != nil {
			return
		}
		if len(c.Raw) != len(raw) || !bytes.Equal(c.Raw, raw) {
			t.Fatalf("Raw is not the octets that arrived")
		}
		if len(c.Body) != len(raw)-HeaderLen {
			t.Fatalf("body %d octets of %d", len(c.Body), len(raw))
		}
		if !c.Type.Known() || !c.Chunk.Known() {
			t.Fatalf("a chunk parsed with an unknown type %s/%s", c.Type, c.Chunk)
		}
		// Whatever the type, reading its body must not panic and must not report
		// success on octets that mean nothing.
		switch c.Type {
		case Hello:
			if h, err := ParseHello(c.Body); err == nil {
				_ = h.Acceptable()
			}
		case Acknowledge:
			_, _ = ParseAcknowledge(c.Body)
		case Error:
			if e, err := ParseError(c.Body); err == nil {
				_ = e.Bad()
				_ = StatusName(e.Code)
			}
		case ReverseHello:
			_, _ = ParseReverseHello(c.Body)
		case OpenSecureChannel:
			if h, off, err := ParseAsymmetric(c.Body); err == nil {
				_ = h.Policy.Known()
				_, _, _ = ParseSequence(c.Raw, off)
			}
		case CloseSecureChannel, Message:
			if _, off, err := ParseSymmetric(c.Body); err == nil {
				_, _, _ = ParseSequence(c.Raw, off)
			}
		}
	})
}

// FuzzAssemble drives the assembler with arbitrary chunk bodies in both security
// modes. The invariants are the bounds: no matter what arrives, the open-message
// table never passes MaxPartial, and a returned message never carries more than
// MaxAssembled octets.
func FuzzAssemble(f *testing.F) {
	f.Add([]byte("MSGF\x10\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00"), uint32(1), false)
	f.Add([]byte("MSGC\x14\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00"), uint32(2), true)
	f.Fuzz(func(t *testing.T, raw []byte, requests uint32, encrypted bool) {
		mode := ModeSign
		if encrypted {
			mode = ModeSignAndEncrypt
		}
		a := NewAssembler()
		// The same octets are offered repeatedly with rotating request
		// identifiers, which is the shape that exercises the table's bounds.
		for i := uint32(0); i < requests%64; i++ {
			b := append([]byte(nil), raw...)
			if len(b) >= HeaderLen+16 {
				binary.LittleEndian.PutUint32(b[HeaderLen+12:], i)
			}
			c, err := ParseChunk(b)
			if err != nil {
				continue
			}
			m, err := a.Add(c, mode)
			if err != nil {
				continue
			}
			if a.Open() > MaxPartial {
				t.Fatalf("%d partial messages, past the %d bound", a.Open(), MaxPartial)
			}
			if m == nil {
				continue
			}
			if len(m.Body) > MaxAssembled {
				t.Fatalf("a message of %d octets, past the %d bound", len(m.Body), MaxAssembled)
			}
			if m.Encrypted && m.Body != nil {
				t.Fatal("an encrypted message carried a body")
			}
			if m.Chunks > MaxChunks {
				t.Fatalf("%d chunks, past the %d bound", m.Chunks, MaxChunks)
			}
		}
		if a.Open() > MaxPartial {
			t.Fatalf("%d partial messages left", a.Open())
		}
	})
}

// FuzzParseCall drives the service reader over arbitrary bodies in both directions.
// The invariant is that a call which parses reports a body that lies inside the
// octets it was given — a slice past the end would be a reader that had walked off
// its own input.
func FuzzParseCall(f *testing.F) {
	f.Add(call(SvcRead, build().f64(0).u32(0).array(0)), true)
	f.Add(build().numeric(0, uint32(SvcFault)).i64(0).u32(0).u32(0).noDiag().array(0).emptyExt().b, false)
	f.Fuzz(func(t *testing.T, body []byte, request bool) {
		c, err := ParseCall(body, request)
		if err != nil {
			return
		}
		if len(c.Body) > len(body) {
			t.Fatalf("a body of %d octets from a message of %d", len(c.Body), len(body))
		}
		_ = c.Service.Writes()
		_ = c.Service.Control()
		_ = c.TypeID.Key()
		// Each service's own parser is then offered the remainder. None of them
		// may panic, and each must either refuse or return a structure whose
		// counts are inside the bounds.
		switch c.Service {
		case SvcRead:
			if q, err := ParseRead(c.Body); err == nil && len(q.Nodes) > MaxArray {
				t.Fatalf("%d nodes to read", len(q.Nodes))
			}
		case SvcWrite:
			if w, err := ParseWrite(c.Body); err == nil && len(w.Values) > MaxArray {
				t.Fatalf("%d values to write", len(w.Values))
			}
		case SvcCall:
			if k, err := ParseCallRequest(c.Body); err == nil {
				for _, m := range k.Methods {
					if len(m.Arguments) > MaxArguments {
						t.Fatalf("%d arguments", len(m.Arguments))
					}
				}
			}
		case SvcBrowse:
			if b, err := ParseBrowse(c.Body); err == nil && len(b.Nodes) > MaxArray {
				t.Fatalf("%d nodes to browse", len(b.Nodes))
			}
		case SvcOpenChannel:
			if o, err := ParseOpenChannel(c.Body); err == nil && !o.Mode.Known() {
				t.Fatalf("an unknown mode %d was accepted", uint32(o.Mode))
			}
		case SvcCreateSession:
			_, _ = ParseCreateSession(c.Body)
		case SvcActivateSession:
			if a, err := ParseActivateSession(c.Body); err == nil {
				_ = a.PlaintextPassword()
				if len(a.Locales) > MaxLocales {
					t.Fatalf("%d locales", len(a.Locales))
				}
			}
		case SvcCreateSubscription:
			_, _ = ParseSubscription(c.Body)
		case SvcCreateMonitored:
			if m, err := ParseMonitoredItems(c.Body); err == nil && len(m.Items) > MaxArray {
				t.Fatalf("%d monitored items", len(m.Items))
			}
		}
	})
}

// FuzzParseNodeId checks that the text form and the wire form agree. A node id that
// renders to a key must parse back from that key to the same key, because a rule is
// written in one form and matched in the other.
func FuzzParseNodeId(f *testing.F) {
	f.Add("ns=3;i=1001")
	f.Add("nsu=urn:x;s=a/b")
	f.Add("svr=1;ns=0;g=00000000-0000-0000-0000-000000000000")
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseNodeId(s)
		if err != nil {
			return
		}
		key := n.Key()
		back, err := ParseNodeId(key)
		if err != nil {
			t.Fatalf("%q rendered to %q, which does not parse: %v", s, key, err)
		}
		if back.Key() != key {
			t.Fatalf("%q rendered to %q and back to %q", s, key, back.Key())
		}
	})
}
