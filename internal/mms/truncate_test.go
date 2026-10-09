package mms

import (
	"bytes"
	"strings"
	"testing"
)

// A frame that stops in the middle.
//
// Every layer here reads a peer's octets and a message can end anywhere: a
// short read on the connection, a device power-cycled mid-send, or somebody
// cutting one deliberately to see which half of it this relay acts on. So the
// encodings below are cut at every length from nothing to one octet short of
// whole, and each cut has to come back as an error or as a value no larger
// than what arrived.
//
// The invariant the cuts are checked against is the one that matters for a
// relay in front of a substation: every name that comes out has to be in the
// octets that went in. A parser that read a domain, an item or a file path out
// of octets that were not there would hand the policy a name no rule was
// written about -- and the policy would then decide about it as though the
// client had asked for it.

// inOctets reports whether every component of a name read out of a frame is
// present in the frame. Names are joined for display -- a domain and an item
// with a slash, a file path with slashes, an item's own parts with dollars --
// so each component is looked for rather than the whole string.
func inOctets(in []byte, name string) bool {
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '$' }) {
		if part == "" {
			continue
		}
		if !bytes.Contains(in, []byte(part)) {
			return false
		}
	}
	return true
}

// checkPDU parses one (possibly truncated) APDU and asserts the invariant.
func checkPDU(t *testing.T, in []byte) {
	t.Helper()
	m, err := ParsePDU(in)
	if err != nil || m == nil {
		return
	}
	for what, s := range map[string]string{
		"the domain":    m.Domain,
		"the file name": m.FileName,
		"the list name": m.ListName,
	} {
		if s != "" && !inOctets(in, s) {
			t.Fatalf("%s came back as %q, which is not in the %d octets given", what, s, len(in))
		}
	}
	for i, n := range m.Names {
		if !inOctets(in, n.Key()) {
			t.Fatalf("name %d came back as %q, which is not in the %d octets given", i, n.Key(), len(in))
		}
	}
}

// TestAnAPDUCutAnywhereIsRefusedOrReadHonestly walks the services whose bodies
// this package reads, because each has its own reader and its own way of
// running out of octets.
func TestAnAPDUCutAnywhereIsRefusedOrReadHonestly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		whole []byte
	}{
		{"a read of a vmd name", readRequest(1, vmdName("TotW"))},
		{"a read of a domain name", readRequest(2, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f"))},
		{"a write", writeRequest(3, objectName("AA1J1Q01A1LD0", "CSWI1$CO$Pos$Oper"))},
		// A read addressed by named variable list rather than by name: the
		// list is a name of its own, and the objects behind it are the
		// device's business rather than the request's.
		{"a read of a named variable list", ctx(uint32(ConfirmedRequest), integer(4),
			ctx(uint32(SvcRead), ctx(1, ctx(1, objectName("LD0", "MeasList")))))},
		{"a define of a named variable list", ctx(uint32(ConfirmedRequest), integer(5),
			ctx(uint32(SvcDefineNamedVariableList),
				vmdName("NewList"),
				ctx(0, seq(ctx(0, vmdName("TotW"))), seq(ctx(0, vmdName("TotVAr"))))))},
		{"an enumeration of a domain", ctx(uint32(ConfirmedRequest), integer(6),
			ctx(uint32(SvcGetNameList), ctxp(0, []byte{0x00}), ctx(1, ctxp(1, []byte("AA1J1Q01A1LD0")))))},
		{"a domain download", ctx(uint32(ConfirmedRequest), integer(7),
			ctx(uint32(SvcInitiateDownloadSequence), visible("AA1J1Q01A1LD0")))},
		{"a file open", ctx(uint32(ConfirmedRequest), integer(8),
			ctx(uint32(SvcFileOpen), seq(visible("COMTRADE"), visible("fault-0001.cfg")), integer(0)))},
		{"an attribute read", ctx(uint32(ConfirmedRequest), integer(9),
			ctx(uint32(SvcGetVariableAccessAttributes), vmdName("TotW")))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The whole thing has to parse, or the cuts below prove nothing.
			if _, err := ParsePDU(tc.whole); err != nil {
				t.Fatalf("the whole encoding did not parse: %v", err)
			}
			checkPDU(t, tc.whole)
			for n := range tc.whole {
				checkPDU(t, tc.whole[:n:n])
			}
		})
	}
}

// TestTheLowerLayersCutAnywhereAreRefused: the four layers under MMS, each of
// which frames the one above and so each of which can be the one that was cut.
func TestTheLowerLayersCutAnywhereAreRefused(t *testing.T) {
	apdu := readRequest(1, vmdName("TotW"))
	cp := set(ctx(cpNormalMode,
		ctx(cpContextList,
			seq(integer(1), oid(2, 2, 1, 0, 1), seq(oid(2, 1, 1))),
			seq(integer(3), oid(1, 0, 9506, 2, 1), seq(oid(2, 1, 1)))),
		app(1, seq(integer(1), ctx(0, []byte{0x60, 0x00})))))
	aarq := app(AARQ,
		ctx(aarqAppContext, oid(1, 0, 9506, 2, 3)),
		ctx(aarqCalledAPTitle, oid(1, 1, 999, 1)),
		ctx(aarqCallingAPName, oid(1, 1, 999, 2)),
		ctx(aarqAuthValue, ctxp(0, []byte("substationsecret"))))

	for _, tc := range []struct {
		name  string
		whole []byte
		parse func(*testing.T, []byte)
	}{
		{"a COTP data unit", cotpData(apdu), func(t *testing.T, b []byte) {
			c, err := ParseCOTP(b)
			if err == nil && len(c.Data) > len(b) {
				t.Fatalf("a payload of %d octets came out of %d", len(c.Data), len(b))
			}
		}},
		{"a session unit pair", sessionData(apdu), func(t *testing.T, b []byte) {
			s, err := ParseSession(b)
			if err == nil && len(s.UserData) > len(b) {
				t.Fatalf("user data of %d octets came out of %d", len(s.UserData), len(b))
			}
		}},
		{"a presentation connect", cp, func(t *testing.T, b []byte) {
			ctxs, vals, err := ParseCP(b)
			if err != nil {
				return
			}
			if len(ctxs) > len(b) {
				t.Fatalf("%d contexts came out of %d octets", len(ctxs), len(b))
			}
			for _, v := range vals {
				if len(v.Data) > len(b) {
					t.Fatalf("a value of %d octets came out of %d", len(v.Data), len(b))
				}
			}
		}},
		{"a presentation data value", pdv(3, apdu), func(t *testing.T, b []byte) {
			vals, err := ParsePDVs(b, Contexts{3: OIDMMSAbstract})
			if err != nil {
				return
			}
			for _, v := range vals {
				if len(v.Data) > len(b) {
					t.Fatalf("a value of %d octets came out of %d", len(v.Data), len(b))
				}
			}
		}},
		{"an association request", aarq, func(t *testing.T, b []byte) {
			a, err := ParseAssociate(b)
			if err != nil || a == nil {
				return
			}
			// The password is seen and not kept, however short the frame: a
			// length is recorded and the octets are not.
			if a.AuthLength > len(b) {
				t.Fatalf("an authentication value of %d octets came out of %d", a.AuthLength, len(b))
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.parse(t, tc.whole)
			for n := range tc.whole {
				tc.parse(t, tc.whole[:n:n])
			}
		})
	}
}
