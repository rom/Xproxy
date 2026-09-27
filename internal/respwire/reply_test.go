package respwire

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// The replies, read back by this package's own reader where it can read them,
// and byte for byte where it cannot.
//
// A fabricated server's replies have to be the octets a client library expects,
// and the one way to be sure of that is to write the bytes out in the test:
// asserting that the builder agrees with itself would say nothing.
func TestTheRepliesAreTheOctetsRedisSends(t *testing.T) {
	for _, tc := range []struct {
		what string
		got  []byte
		want string
	}{
		{"a simple string", Simple("OK"), "+OK\r\n"},
		{"an integer", Int(1), ":1\r\n"},
		{"a negative integer", Int(-1), ":-1\r\n"},
		{"zero", Int(0), ":0\r\n"},
		{"a bulk string", BulkString("foo"), "$3\r\nfoo\r\n"},
		{"an empty bulk string", BulkString(""), "$0\r\n\r\n"},
		{"the null bulk string, which is not an empty one", NilBulk(), "$-1\r\n"},
		{"the null array", NilArray(), "*-1\r\n"},
		{"an empty array", Array(), "*0\r\n"},
		{"an array of bulk strings", Strings("a", "bb"), "*2\r\n$1\r\na\r\n$2\r\nbb\r\n"},
		{"a nested array", Array(Int(1), Strings("x")), "*2\r\n:1\r\n*1\r\n$1\r\nx\r\n"},
		// A map header counts pairs, not elements, which is the one place
		// RESP3 counts differently from RESP2 and the one that breaks a client
		// if it is wrong.
		{"a map of one pair", Map(BulkString("k"), Int(2)), "%1\r\n$1\r\nk\r\n:2\r\n"},
		{"an empty map", Map(), "%0\r\n"},
	} {
		if string(tc.got) != tc.want {
			t.Errorf("%s: %q, want %q", tc.what, tc.got, tc.want)
		}
	}
}

// A bulk string is length-delimited, so it carries any octets at all. That is
// what makes it the reply for anything a client reads as a value -- and what a
// fabricated INFO, whose whole body is newline-separated, depends on.
func TestABulkStringCarriesWhateverItIsGiven(t *testing.T) {
	body := "# Server\r\nredis_version:7.2.4\r\n\x00\xff"
	got := Bulk([]byte(body))
	want := "$" + itoaTest(len(body)) + "\r\n" + body + "\r\n"
	if string(got) != want {
		t.Errorf("%q, want %q", got, want)
	}
	// And the length is the *octet* count, not the rune count, so a value with
	// multi-byte characters in it is framed correctly.
	multi := "påse"
	if got := Bulk([]byte(multi)); string(got) != "$5\r\npåse\r\n" {
		t.Errorf("a multi-byte value framed as %q", got)
	}
}

// A simple string is line-delimited, so a newline inside one would end the reply
// early and everything after it would be read as another reply: a reply the
// fabrication did not mean to send, built out of a string somebody else chose.
func TestASimpleStringCannotBeSplit(t *testing.T) {
	for _, tc := range []struct{ what, in string }{
		{"a line feed", "OK\ninjected"},
		{"a carriage return", "OK\rinjected"},
		{"both", "OK\r\n+injected"},
		{"a null", "OK\x00here"},
	} {
		got := Simple(tc.in)
		if n := bytes.Count(got, []byte("\r\n")); n != 1 {
			t.Errorf("%s: %q has %d terminators", tc.what, got, n)
		}
		if i := bytes.IndexAny(got[1:len(got)-2], "\r\n"); i >= 0 {
			t.Errorf("%s: %q still has a line ending in its text", tc.what, got)
		}
	}
	// The same for an error reply, which is the other line-delimited type. It
	// already sanitised; this is the assertion that it stays that way.
	if got := Error("ERR", "no\r\n+PONG"); bytes.Count(got, []byte("\r\n")) != 1 {
		t.Errorf("an error reply split: %q", got)
	}
}

// Every reply this package builds is one the reader beside it can read as a
// reply, which is the round trip that says the framing is right.
func TestTheRepliesReadBackAsOneMessageEach(t *testing.T) {
	// A pipeline of every reply type, read back as a stream: if any one of them
	// framed its length wrongly, the next would start mid-reply and the count
	// would come out wrong.
	replies := [][]byte{
		Simple("PONG"), Int(42), BulkString("value"), NilBulk(),
		Strings("one", "two"), Array(), Error("WRONGTYPE", "not a list"),
		Bulk([]byte("a\r\nb")),
	}
	var stream []byte
	for _, r := range replies {
		stream = append(stream, r...)
	}
	br := bufio.NewReader(bytes.NewReader(stream))
	for i := range replies {
		got, err := readOneReply(br)
		if err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
		if !bytes.Equal(got, replies[i]) {
			t.Errorf("reply %d read back as %q, want %q", i, got, replies[i])
		}
	}
	if _, err := br.Peek(1); err == nil {
		t.Error("octets were left over after the last reply")
	}
}

// readOneReply is a minimal RESP reply reader, written here rather than reused
// so that the assertion is against a second implementation of the framing
// rather than against the one under test.
func readOneReply(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), line...)
	if len(line) < 3 {
		return out, nil
	}
	switch line[0] {
	case TypeBulkString:
		n, err := atoiTest(string(bytes.TrimRight(line[1:], "\r\n")))
		if err != nil || n < 0 {
			return out, nil
		}
		body := make([]byte, n+2)
		if _, err := readFull(br, body); err != nil {
			return nil, err
		}
		return append(out, body...), nil
	case TypeArray, TypeMap:
		n, err := atoiTest(string(bytes.TrimRight(line[1:], "\r\n")))
		if err != nil || n <= 0 {
			return out, nil
		}
		if line[0] == TypeMap {
			n *= 2
		}
		for i := 0; i < n; i++ {
			el, err := readOneReply(br)
			if err != nil {
				return nil, err
			}
			out = append(out, el...)
		}
	}
	return out, nil
}

func readFull(br *bufio.Reader, into []byte) (int, error) {
	at := 0
	for at < len(into) {
		n, err := br.Read(into[at:])
		at += n
		if err != nil {
			return at, err
		}
	}
	return at, nil
}

func atoiTest(s string) (int, error) {
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	if s == "" {
		return 0, errTestAtoi
	}
	v := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errTestAtoi
		}
		v = v*10 + int(s[i]-'0')
	}
	if neg {
		return -v, nil
	}
	return v, nil
}

var errTestAtoi = errTest("not a number")

type errTest string

func (e errTest) Error() string { return string(e) }

func itoaTest(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}
