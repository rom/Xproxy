package pgwire

import (
	"bytes"
	"strings"
	"testing"
)

// Both of these run before anything has authenticated anything.
//
// A PostgreSQL relay reads the startup packet from a connection that has
// presented no credential at all -- the credential is inside the packet, and on
// an SSLRequest there is not even a user name yet. So the reader is the most
// exposed code in the kind, and the classifier runs on a string the client
// chose.

func FuzzParseStartup(f *testing.F) {
	f.Add([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f})
	f.Add(startup(Version3, "user", "alice"))
	f.Add(startup(Version3, "user", "alice", "replication", "true"))
	f.Add([]byte{0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0x30, 0x39, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseStartup(b)
		if err != nil {
			return
		}
		// Whatever parsed must have a code this relay speaks, and the four
		// shapes must not be confusable: a packet that parsed as a cancel
		// request must not also carry parameters, because a relay that read
		// both would be deciding about one message and forwarding another.
		switch s.Code {
		case Version3:
			if s.PID != 0 || s.Secret != 0 {
				t.Fatalf("a startup packet with cancel fields: %+v", s)
			}
			for _, p := range s.Params {
				if strings.ContainsRune(p.Key, 0) || strings.ContainsRune(p.Value, 0) {
					t.Fatalf("a NUL inside a parameter: %q=%q", p.Key, p.Value)
				}
			}
			if len(s.Params) > MaxStartupParams {
				t.Fatalf("%d parameters past the bound", len(s.Params))
			}
			// Database falls back to the user, so it is empty only when the
			// user is -- and a startup packet with no user is one the server
			// will refuse, which the policy has to be able to see.
			if s.Database() == "" && s.User() != "" {
				t.Fatalf("a user with no database: %+v", s)
			}
		case SSLRequest, GSSEncRequest, CancelRequest:
			if len(s.Params) != 0 {
				t.Fatalf("a %d packet with parameters: %+v", s.Code, s)
			}
		default:
			t.Fatalf("an unspoken version parsed: %d", s.Code)
		}
	})
}

func FuzzNext(f *testing.F) {
	f.Add(msg(MsgQuery, 'S', 'E', 'L', 'E', 'C', 'T', 0))
	f.Add(msg(MsgSync))
	f.Add(append(msg(MsgParse, 's', 0, 'S', 'E', 'L', 'E', 'C', 'T', 0, 0, 0), msg(MsgSync)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		rd := NewReader(bytes.NewReader(b), FromClient, 4096)
		for i := 0; i < 64; i++ {
			m, err := rd.Next()
			if err != nil {
				return
			}
			if len(m.Body) > 4096 {
				t.Fatalf("a body past the bound: %d", len(m.Body))
			}
			// Every message must name itself, because a refusal has to say
			// what it refused.
			if m.Name() == "" {
				t.Fatalf("a message with no name: %q", m.Type)
			}
			// Round-tripping must be exact: the relay forwards what it read.
			raw := m.Raw()
			if len(raw) != len(m.Body)+5 || raw[0] != m.Type {
				t.Fatalf("raw is not the message: %q", raw)
			}
			// The readers must not panic on a body of the wrong shape, and
			// must not return a value together with an error.
			switch m.Type {
			case MsgParse:
				if p, err := m.ReadParse(); err != nil && p != nil {
					t.Fatal("a parse returned both a value and an error")
				}
			case MsgBind:
				if bm, err := m.ReadBind(); err != nil && bm != nil {
					t.Fatal("a bind returned both a value and an error")
				}
			case MsgQuery:
				if s, err := m.QueryText(); err == nil && strings.ContainsRune(s, 0) {
					t.Fatalf("a NUL inside a query: %q", s)
				}
			}
		}
	})
}

// The classifier has to answer for every string, and must never answer with a
// kind that is less restricted than the truth.
func FuzzStatements(f *testing.F) {
	f.Add("SELECT 1")
	f.Add("SELECT 1; DROP TABLE t")
	f.Add("WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x")
	f.Add("COPY t FROM PROGRAM 'id'")
	f.Add("DO $$ BEGIN PERFORM 1; END $$")
	f.Add("/* /* nested */ */ SELECT 1")
	f.Fuzz(func(t *testing.T, sql string) {
		got, ok := Statements(sql, 64)
		if !ok {
			return
		}
		if len(got) == 0 {
			t.Fatal("a lexed statement list is empty")
		}
		for _, s := range got {
			// Every statement gets a kind, and unknown is the one that means
			// "this code could not read it". It must count as a write, because
			// that is what makes an allow list of kinds and read_only both
			// refuse it without an operator thinking about the unknown case.
			if s.Kind == "" {
				t.Fatalf("a statement with no kind: %q", sql)
			}
			if s.Kind == KindUnknown && !s.Writes {
				t.Fatalf("an unreadable statement that does not count as a write: %q", sql)
			}
			// A COPY always says which of the three it is, and nothing else
			// ever claims to be a copy.
			if (s.Kind == KindCopy) != (s.Copy != CopyNone) {
				t.Fatalf("copy target %q on kind %s: %q", s.Copy, s.Kind, sql)
			}
			if len(s.Verb) > MaxString+3 {
				t.Fatalf("an unclipped verb: %d octets", len(s.Verb))
			}
		}
	})
}
