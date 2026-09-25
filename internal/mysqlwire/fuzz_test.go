package mysqlwire

import (
	"bytes"
	"strings"
	"testing"
)

// The greeting reader runs on the first octets a server sends, and the login
// reader on the first a client sends -- before anything has authenticated
// anything, in both directions.

func FuzzParseGreeting(f *testing.F) {
	f.Add(greeting(baseCaps|CapSSL, AuthCachingSHA2))
	f.Add(greeting(baseCaps, AuthNative))
	f.Add(greeting(baseCaps|CapSSL|CapLocalFiles|CapMultiStatements, AuthCachingSHA2))
	f.Fuzz(func(t *testing.T, b []byte) {
		g, err := ParseGreeting(b)
		if err != nil {
			return
		}
		// Only version 10 parses: 9 is a different shape and anything else is
		// not a handshake, so a relay that accepted one would be forwarding
		// octets it had not read.
		if g.Protocol != 10 {
			t.Fatalf("protocol %d parsed", g.Protocol)
		}
		// Every peer-chosen string is bounded, because it goes in a log line
		// and into the device inventory.
		if len(g.Version) > MaxString+3 || len(g.Plugin) > MaxString+3 {
			t.Fatalf("an unclipped string: version %d plugin %d", len(g.Version), len(g.Plugin))
		}
		// A plugin name is only read when the capability says there is one.
		if g.Plugin != "" && !g.Offers(CapPluginAuth) {
			t.Fatalf("a plugin name without the capability: %q", g.Plugin)
		}
	})
}

func FuzzParseLogin(f *testing.F) {
	f.Add(login(baseCaps|CapConnectWithDB, "alice", "sales", AuthCachingSHA2, nil))
	f.Add(login(baseCaps|CapSSL, "", "", "", nil))
	f.Add(login(baseCaps|CapConnectAttrs, "alice", "", AuthNative,
		map[string]string{"_client_name": "libmysql"}))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseLogin(b)
		if err != nil {
			return
		}
		// Protocol 4.1 is required, because the older response is a different
		// shape and reading it as this one decides about fields that are not
		// there.
		if !l.Wants(CapProtocol41) {
			t.Fatal("a pre-4.1 response parsed")
		}
		// The short form is only ever the short form when TLS was asked for.
		if l.SSLOnly && !l.Wants(CapSSL) {
			t.Fatal("the short form without the ssl capability")
		}
		if l.SSLOnly && (l.User != "" || l.Database != "" || l.Plugin != "") {
			t.Fatalf("the short form carried an identity: %+v", l)
		}
		for name, v := range map[string]string{
			"user": l.User, "database": l.Database, "plugin": l.Plugin,
		} {
			if len(v) > MaxString+3 {
				t.Fatalf("an unclipped %s: %d octets", name, len(v))
			}
			if strings.ContainsRune(v, 0) {
				t.Fatalf("a NUL inside %s: %q", name, v)
			}
		}
		if len(l.Attrs) > MaxAttrs {
			t.Fatalf("%d attributes past the bound", len(l.Attrs))
		}
		// A database is only read when the capability says there is one, and
		// likewise a plugin and the attributes.
		if l.Database != "" && !l.Wants(CapConnectWithDB) {
			t.Fatalf("a database without the capability: %q", l.Database)
		}
		if l.Attrs != nil && !l.Wants(CapConnectAttrs) {
			t.Fatal("attributes without the capability")
		}
	})
}

// The framing reader is the other thing that runs on unauthenticated octets, and
// its two traps -- the continuation chain and the sequence number -- are exactly
// the kind of arithmetic a fuzzer finds.
func FuzzNext(f *testing.F) {
	f.Add(Frame(0, []byte{ComQuery, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'}))
	f.Add(Frame(0, nil))
	f.Add(append(Frame(0, []byte{ComPing}), Frame(1, []byte{ComQuit})...))
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
			// A command is only produced when there is an octet to produce it
			// from, and it always names itself so a refusal can say what it
			// refused.
			c, rest, ok := p.Command()
			if ok {
				if len(rest) != len(p.Payload)-1 {
					t.Fatalf("the rest is %d of %d", len(rest), len(p.Payload))
				}
				if CommandName(c) == "" {
					t.Fatalf("a command with no name: %#02x", c)
				}
			} else if len(p.Payload) != 0 {
				t.Fatalf("no command from a %d-octet payload", len(p.Payload))
			}
			// The readers must not panic on a payload of the wrong shape, and
			// must not return a value together with an error.
			if ok {
				switch c {
				case ComChangeUser:
					if cu, err := ReadChangeUser(rest, baseCaps); err != nil && cu != nil {
						t.Fatal("a change-user returned both a value and an error")
					}
				case ComSetOption:
					SetOptionMultiStatements(rest)
				}
			}
			if e, err := ReadError(p.Payload, CapProtocol41); err != nil && e != nil {
				t.Fatal("an error packet returned both a value and an error")
			}
			LocalInfilePath(p.Payload)
		}
	})
}

// Framing has to round-trip, or the relay forwards a different message from the
// one it read.
func FuzzFrameRoundTrip(f *testing.F) {
	f.Add([]byte("SELECT 1"), uint8(0))
	f.Add([]byte{}, uint8(3))
	f.Fuzz(func(t *testing.T, payload []byte, seq uint8) {
		if len(payload) > 4<<20 {
			return
		}
		framed := Frame(seq, payload)
		rd := NewReader(bytes.NewReader(framed), MaxMessage)
		rd.SetSeq(seq)
		p, err := rd.Next()
		if err != nil {
			t.Fatalf("a framed payload of %d octets would not read back: %v", len(payload), err)
		}
		if !bytes.Equal(p.Payload, payload) {
			t.Fatalf("round trip changed %d octets into %d", len(payload), len(p.Payload))
		}
	})
}
