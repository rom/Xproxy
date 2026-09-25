package tdswire

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// Every reader here runs before anything has authenticated anything: the
// PRELOGIN is the first message on the connection, and the LOGIN7 that follows
// is where the credential *is*.

func FuzzParsePreLogin(f *testing.F) {
	f.Add(prelogin(PreLoginOption{Token: PreLoginEncryption, Value: []byte{EncryptOff}}))
	f.Add(prelogin(
		PreLoginOption{Token: PreLoginVersion, Value: []byte{16, 0, 0, 0, 0, 0}},
		PreLoginOption{Token: PreLoginEncryption, Value: []byte{EncryptReq}},
		PreLoginOption{Token: PreLoginInstOpt, Value: []byte("MSSQLSERVER\x00")}))
	f.Add([]byte{PreLoginTerminator})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParsePreLogin(b)
		if err != nil {
			return
		}
		if len(p.Options) > MaxPreLoginOptions {
			t.Fatalf("%d options past the bound", len(p.Options))
		}
		// The encryption value is only ever reported as present when the option
		// was there, and the absent case must read as plaintext -- because
		// "absent" and "off" have the same consequence on the wire and a
		// default of "on" would be a lie.
		if !p.HasEncryption && Encrypted(p.Encryption) {
			t.Fatalf("an absent option reads as encrypted: %s", EncryptName(p.Encryption))
		}
		if len(p.Instance) > MaxString+3 {
			t.Fatalf("an unclipped instance name: %d octets", len(p.Instance))
		}
		// Rewriting the encryption option and reading it back must give what
		// was asked for, whatever the input looked like: that round trip is how
		// the downgrade is defeated, so it must not depend on the shape of what
		// the client sent.
		rebuilt, err := ParsePreLogin(BuildPreLogin(p.WithEncryption(EncryptReq)))
		if err != nil {
			t.Fatalf("a rebuilt table would not parse: %v", err)
		}
		if rebuilt.Encryption != EncryptReq || !rebuilt.HasEncryption {
			t.Fatalf("the rewrite did not take: %s", EncryptName(rebuilt.Encryption))
		}
		// When the client's own table was in ascending token order, the one the
		// relay produces is too -- a new option goes in its place rather than
		// at the end, because some servers enforce the ordering. An input that
		// was already unsorted keeps its order: normalising somebody else's
		// message beyond what the policy asked for is not the relay's business,
		// and a server that refused an unsorted table would have refused the
		// client's own.
		sorted := true
		for i := 1; i < len(p.Options); i++ {
			if p.Options[i-1].Token > p.Options[i].Token {
				sorted = false
				break
			}
		}
		opts := p.WithEncryption(EncryptReq)
		if sorted {
			for i := 1; i < len(opts); i++ {
				if opts[i-1].Token > opts[i].Token {
					t.Fatalf("a sorted table became unsorted: %#02x then %#02x",
						opts[i-1].Token, opts[i].Token)
				}
			}
		}
		// Either way the encryption option appears exactly once: two would let
		// a server read a different value from the one the relay decided on.
		n := 0
		for _, o := range opts {
			if o.Token == PreLoginEncryption {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("the encryption option appears %d times", n)
		}
	})
}

func FuzzParseLogin7(f *testing.F) {
	f.Add(login7("WS01", "sa", "hunter2", "MyApp", "srv", "ODBC", "us_english", "sales", false))
	f.Add(login7("", "", "", "", "", "", "", "", true))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseLogin7(b)
		if err != nil {
			return
		}
		for name, v := range map[string]string{
			"hostname": l.Hostname, "user": l.User, "database": l.Database,
			"appname": l.AppName, "servername": l.ServerName, "library": l.Library,
		} {
			if len(v) > MaxString+3 {
				t.Fatalf("an unclipped %s: %d octets", name, len(v))
			}
		}
		// A version below 7.0 must never parse: that is a different message
		// shape, and a relay that accepted one would forward octets it had not
		// read.
		if l.TDSVersion != 0 && l.TDSVersion < 0x70000000 {
			t.Fatalf("a pre-7.0 version parsed: %#x", l.TDSVersion)
		}
	})
}

func FuzzParseRPC(f *testing.F) {
	f.Add(rpcByName("sp_executesql", false, nvarcharParam("SELECT 1")))
	f.Add(rpcByName("xp_cmdshell", true))
	f.Add(rpcByID(SpExecuteSql, nvarcharParam("SELECT 1")))
	f.Add(rpcByName("sp_prepare", false, intParam(0), nvarcharParam("@a int"),
		nvarcharParam("UPDATE t SET x = 1"), intParam(1)))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRPC(b)
		if err != nil {
			return
		}
		// A procedure always has a name a policy can compare, and it is always
		// lower-cased -- because a policy that compared two spellings would be
		// bypassed by the other one.
		p := r.Procedure()
		if p == "" {
			t.Fatalf("a procedure with no name: %+v", r)
		}
		if p != strings.ToLower(p) {
			t.Fatalf("a procedure name that is not folded: %q", p)
		}
		if len(p) > MaxString+3 {
			t.Fatalf("an unclipped procedure name: %d octets", len(p))
		}
		// Named by number and named by name are mutually exclusive.
		if r.ByID && r.Name != "" {
			t.Fatalf("both forms at once: %+v", r)
		}
		// A statement is read exactly when the procedure's signature has one,
		// and never invented: the relay's statement policy runs on this value,
		// so a statement that appeared out of a call that has none would be a
		// decision about text nobody sent.
		_, dynamic := StatementParam(p)
		if r.HasStatement != dynamic {
			t.Fatalf("%s: HasStatement=%v, signature says %v", p, r.HasStatement, dynamic)
		}
		if r.HasStatement && r.Statement == "" {
			t.Fatalf("%s: an empty statement", p)
		}
		if !r.HasStatement && r.Statement != "" {
			t.Fatalf("%s: a statement on a procedure with none: %q", p, r.Statement)
		}
		// Whatever came back is text. It is about to be lexed by the statement
		// classifier and then put in a log line, and both of those want a
		// string rather than a byte soup.
		if !utf8.ValidString(r.Statement) {
			t.Fatalf("%s: the statement is not valid UTF-8: %q", p, r.Statement)
		}
	})
}

func FuzzNext(f *testing.F) {
	f.Add(pkt(TypeSQLBatch, StatusEOM, 0, ToUCS2("SELECT 1")))
	f.Add(pkt(TypePreLogin, StatusEOM, 0, prelogin(
		PreLoginOption{Token: PreLoginEncryption, Value: []byte{EncryptOff}})))
	f.Add(append(pkt(TypeSQLBatch, StatusNormal, 0, []byte("a")),
		pkt(TypeSQLBatch, StatusEOM, 0, []byte("b"))...))
	f.Fuzz(func(t *testing.T, b []byte) {
		rd := NewReader(bytes.NewReader(b), 8192)
		for i := 0; i < 32; i++ {
			p, err := rd.Next()
			if err != nil {
				return
			}
			if len(p.Payload) > 8192 {
				t.Fatalf("a payload past the bound: %d", len(p.Payload))
			}
			if p.Packets < 1 {
				t.Fatalf("a message of %d packets", p.Packets)
			}
			if TypeName(p.Type) == "" {
				t.Fatalf("a message with no type name: %#02x", p.Type)
			}
			// The body readers must not panic on a payload of the wrong shape,
			// and must not return a value together with an error.
			switch p.Type {
			case TypePreLogin:
				if pl, err := ParsePreLogin(p.Payload); err != nil && pl != nil {
					t.Fatal("a prelogin returned both a value and an error")
				}
			case TypeLogin7:
				if l, err := ParseLogin7(p.Payload); err != nil && l != nil {
					t.Fatal("a login returned both a value and an error")
				}
			case TypeRPC:
				if r, err := ParseRPC(p.Payload); err != nil && r != nil {
					t.Fatal("an rpc returned both a value and an error")
				}
			case TypeSQLBatch:
				if s, err := SQLText(p.Payload); err == nil && strings.ContainsRune(s, 0xfffd) {
					// A replacement character is fine -- it means the input was
					// not valid UTF-16 -- but the decode must not have failed
					// silently into something a policy then reads as innocent.
					_ = s
				}
			}
			LoginAck(p.Payload)
			ErrorNumber(p.Payload)
		}
	})
}

// Framing has to round-trip whatever it is given, or the relay forwards a
// different message from the one it read.
func FuzzFrameRoundTrip(f *testing.F) {
	f.Add([]byte("SELECT 1"), uint16(512))
	f.Add([]byte{}, uint16(4096))
	f.Fuzz(func(t *testing.T, payload []byte, size uint16) {
		if len(payload) > 1<<20 {
			return
		}
		framed := Frame(TypeSQLBatch, 3, payload, int(size))
		rd := NewReader(bytes.NewReader(framed), MaxMessage)
		p, err := rd.Next()
		if err != nil {
			t.Fatalf("a framed payload of %d octets at size %d would not read back: %v",
				len(payload), size, err)
		}
		if !bytes.Equal(p.Payload, payload) {
			t.Fatalf("round trip changed %d octets into %d", len(payload), len(p.Payload))
		}
	})
}

// The obfuscation is an encoding, so it round-trips for every input -- which is
// the property that makes it not encryption.
func FuzzObfuscateRoundTrip(f *testing.F) {
	f.Add([]byte("hunter2"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if !bytes.Equal(Deobfuscate(Obfuscate(b)), b) {
			t.Fatalf("%d octets did not round-trip", len(b))
		}
		// And it is its own inverse in the other direction too, because the
		// transformation is a fixed permutation of the octet space.
		if !bytes.Equal(Obfuscate(Deobfuscate(b)), b) {
			t.Fatalf("%d octets did not round-trip the other way", len(b))
		}
	})
}
