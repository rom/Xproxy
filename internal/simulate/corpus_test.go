package simulate

import (
	"strings"
	"testing"
)

func TestParsingARequestCorpus(t *testing.T) {
	in, err := ParseRequests(strings.NewReader(`# a comment before everything
>>> listener=edge name="the injection" client=203.0.113.9
GET /?id=1%27 HTTP/1.1
Host: shop.example.com

>>>
POST /checkout HTTP/1.1
Host: shop.example.com
Content-Length: 9

qty=99999
>>> raw
GET /
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 3 {
		t.Fatalf("items %d", len(in))
	}
	if in[0].Name != "the injection" || in[0].Listener != "edge" || in[0].Client != "203.0.113.9" {
		t.Errorf("directives: %+v", in[0])
	}
	// A head with no body gets its terminator; a head with a body keeps the
	// body exactly.
	if got := string(in[0].Bytes); !strings.HasSuffix(got, "\r\n\r\n") {
		t.Errorf("first item %q is not a terminated head", got)
	}
	if got := string(in[1].Bytes); !strings.HasSuffix(got, "\r\n\r\nqty=99999") {
		t.Errorf("second item %q lost its body", got)
	}
	if in[1].Name != "item 2" {
		t.Errorf("an unnamed item is numbered so the report can point at it: %q", in[1].Name)
	}
	// raw is byte for byte, which is how to send something malformed.
	if got := string(in[2].Bytes); got != "GET /" {
		t.Errorf("raw item %q was rewritten", got)
	}
}

func TestParsingAFrameCorpus(t *testing.T) {
	in, err := ParseFrames(strings.NewReader(`>>> listener=plant name="write single register"
# the MBAP header, then the PDU
0001 0000 0006
01 10 0000 0001
>>> listener=plant
00:02:00:00:00:06_01_03_00_00_00_01
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(in) != 2 {
		t.Fatalf("items %d", len(in))
	}
	want := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x10, 0x00, 0x00, 0x00, 0x01}
	if string(in[0].Bytes) != string(want) {
		t.Errorf("frame % x, want % x", in[0].Bytes, want)
	}
	if len(in[1].Bytes) != 12 {
		t.Errorf("a frame written with separators: % x", in[1].Bytes)
	}
}

// What a corpus file gets wrong, and what it is told.
func TestACorpusFileWithMistakesInIt(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		frames         bool
	}{
		{name: "nothing at all", in: "", want: "no items"},
		{name: "only comments", in: "# nothing here\n", want: "no items"},
		{name: "text before the first item", in: "GET / HTTP/1.1\n", want: "before the first >>>"},
		{name: "an empty item", in: ">>>\n>>>\nGET / HTTP/1.1\n", want: "an item with nothing in it"},
		{name: "a directive nobody knows", in: ">>> route=shop\nGET / HTTP/1.1\n", want: "listener, name, client or raw"},
		{name: "a directive with no value", in: ">>> listener\nGET / HTTP/1.1\n", want: "expected key=value"},
		{name: "half a byte", in: ">>>\n0001 000\n", want: "odd number of hex digits", frames: true},
		{name: "not hex", in: ">>>\nzz01\n", want: "not hex", frames: true},
	} {
		var err error
		if tc.frames {
			_, err = ParseFrames(strings.NewReader(tc.in))
		} else {
			_, err = ParseRequests(strings.NewReader(tc.in))
		}
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say %q", tc.name, err, tc.want)
		}
	}
}
