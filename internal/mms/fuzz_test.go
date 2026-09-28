package mms

import (
	"bytes"
	"testing"
)

// Fuzzing, because every layer here parses octets from a peer and the shapes that
// break a nested encoding are not the shapes a person thinks to write down.
//
// Each target asserts the same two things: nothing panics, and nothing that comes
// back out claims more than the input could hold. The second is the one that matters
// -- a parser that returned a name longer than the buffer, or a count of values
// larger than the octets, would have a policy decided about something that is not
// there.

func FuzzBER(f *testing.F) {
	f.Add(seq(integer(1), visible("x")))
	f.Add(set(ctx(2, oid(1, 3, 6, 1))))
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Add([]byte{0xBF, 0xFF, 0x7F, 0x01, 0x02})
	f.Fuzz(func(t *testing.T, b []byte) {
		walk(t, NewBER(b), 0, len(b))
	})
}

// walk reads every element at a level and descends, which is what exercises the depth
// bound as well as the length checks.
func walk(t *testing.T, r *BER, depth, limit int) {
	if depth > MaxDepth+2 {
		t.Fatalf("descended %d levels, past the bound of %d", depth, MaxDepth)
	}
	for n := 0; !r.Empty() && n < 64; n++ {
		e, err := r.Next()
		if err != nil {
			return
		}
		if len(e.Data) > limit {
			t.Fatalf("an element of %d octets came out of %d", len(e.Data), limit)
		}
		if e.Tag > MaxTag {
			t.Fatalf("a tag of %d came back, past the bound of %d", e.Tag, MaxTag)
		}
		if !e.Cons {
			continue
		}
		sub, err := r.Sub(e)
		if err != nil {
			continue
		}
		walk(t, sub, depth+1, len(e.Data))
	}
}

func FuzzParseCOTP(f *testing.F) {
	f.Add(cotpData([]byte{1, 2, 3}))
	f.Add([]byte{0x11, CR, 0, 0, 0, 1, 0x00, paramCalled, 2, 0, 1})
	f.Add([]byte{0x02, DR, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseCOTP(b)
		if err != nil {
			return
		}
		if len(c.Called) > MaxSelector || len(c.Calling) > MaxSelector {
			t.Fatalf("a selector of %d/%d octets came back, past %d",
				len(c.Called), len(c.Calling), MaxSelector)
		}
		if len(c.Data) > len(b) {
			t.Fatalf("%d octets of data came out of %d", len(c.Data), len(b))
		}
	})
}

func FuzzParseSession(f *testing.F) {
	f.Add(sessionData([]byte{0x61, 0x00}))
	f.Add([]byte{SPDUConnect, 4, pgiUserData, 2, 0x61, 0x00})
	f.Add([]byte{SPDUGiveTokens, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseSession(b)
		if err != nil {
			return
		}
		if len(s.UserData) > len(b) {
			t.Fatalf("%d octets of user data came out of %d", len(s.UserData), len(b))
		}
	})
}

func FuzzParseCP(f *testing.F) {
	f.Add(set(ctx(cpNormalMode,
		ctx(cpContextList, seq(integer(3), oid(1, 0, 9506, 2, 1))),
		app(1, seq(integer(3), ctx(0, []byte{0xA0, 0x00}))))))
	f.Add(set())
	f.Fuzz(func(t *testing.T, b []byte) {
		ctxs, vals, err := ParseCP(b)
		if err != nil {
			return
		}
		if len(ctxs) > MaxContexts {
			t.Fatalf("%d contexts came back, past the bound of %d", len(ctxs), MaxContexts)
		}
		for _, o := range ctxs {
			if len(o) > MaxOIDArcs {
				t.Fatalf("an identifier of %d arcs came back", len(o))
			}
		}
		if len(vals) > MaxPDVs {
			t.Fatalf("%d values came back, past the bound of %d", len(vals), MaxPDVs)
		}
		for _, v := range vals {
			if len(v.Data) > len(b) {
				t.Fatalf("%d octets of value came out of %d", len(v.Data), len(b))
			}
		}
	})
}

func FuzzParseAssociate(f *testing.F) {
	f.Add(app(AARQ, ctx(aarqAppContext, oid(1, 0, 9506, 2, 3)),
		ctx(aarqCallingAPName, oid(1, 1, 999, 1)),
		ctx(aarqAuthValue, ctxp(0, []byte("secret")))))
	f.Add(app(AARE, ctx(aareResult, integer(1))))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ParseAssociate(b)
		if err != nil {
			return
		}
		if a.AuthLength > len(b) {
			t.Fatalf("an authentication value of %d octets came out of %d", a.AuthLength, len(b))
		}
		// The parsed association must never carry the value itself, whatever the
		// input was: that is the invariant the whole layer is written around.
		if a.Auth == AuthPassword && bytes.Contains([]byte(sprintAll(a)), []byte("secret")) {
			t.Fatal("a password survived into the parsed association")
		}
	})
}

func FuzzParsePDU(f *testing.F) {
	f.Add(readRequest(1, objectName("LD0", "X1$ST$V$stVal")))
	f.Add(writeRequest(2, objectName("LD0", "X1$CO$Pos$Oper")))
	f.Add(ctx(uint32(ConfirmedRequest), integer(3),
		ctx(uint32(SvcFileOpen), seq(visible("a"), visible("b")), integer(0))))
	f.Add(ctx(uint32(ConfirmedRequest), integer(4), ctx(uint32(SvcGetNameList),
		ctx(0, integer(9)), ctx(1, ctxp(1, []byte("LD0"))))))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParsePDU(b)
		if err != nil {
			return
		}
		if len(m.Names) > MaxNames {
			t.Fatalf("%d names came back, past the bound of %d", len(m.Names), MaxNames)
		}
		for _, n := range m.Names {
			if len(n.Domain) > MaxIdentifier || len(n.Item) > MaxIdentifier {
				t.Fatalf("a name of %d/%d octets came back, past %d",
					len(n.Domain), len(n.Item), MaxIdentifier)
			}
			// A parsed name's segments have to come from its item, or a rule
			// matching the item and a rule matching the constraint would be
			// deciding about different things.
			if n.Parsed && !bytes.Contains([]byte(n.Item), []byte(n.FC)) {
				t.Fatalf("the constraint %q is not in the item %q", n.FC, n.Item)
			}
		}
		if len(m.Domain) > MaxIdentifier || len(m.FileName) > MaxIdentifier {
			t.Fatalf("a domain or file name past the bound came back: %q %q",
				m.Domain, m.FileName)
		}
		if m.Values > MaxElements {
			t.Fatalf("%d values came back, past the bound of %d", m.Values, MaxElements)
		}
	})
}

func FuzzParseItem(f *testing.F) {
	f.Add("XCBR1$CO$Pos$Oper")
	f.Add("$$$$")
	f.Add("LastApplError")
	f.Fuzz(func(t *testing.T, s string) {
		n := ParseItem(s)
		if n.Item != s {
			t.Fatalf("the item came back as %q from %q", n.Item, s)
		}
		if !n.Parsed {
			if n.FC != "" || n.LogicalNode != "" {
				t.Fatalf("an unparsed name carries %q/%q", n.LogicalNode, n.FC)
			}
			return
		}
		if !n.FC.Known() {
			t.Fatalf("a parsed name carries the unknown constraint %q", n.FC)
		}
	})
}
