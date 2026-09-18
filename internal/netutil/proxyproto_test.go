package netutil

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func v2(cmd, fam byte, body []byte) []byte {
	h := append([]byte{}, proxyV2Sig...)
	h = append(h, 0x20|cmd, fam<<4|1)
	h = binary.BigEndian.AppendUint16(h, uint16(len(body)))
	return append(h, body...)
}

func TestProxyHeader(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("PROXY TCP4 203.0.113.9 10.0.0.1 40000 443\r\nGET / HTTP/1.1\r\n"))
	h, err := ReadProxyHeader(br)
	if err != nil || h.Version != 1 || h.Src.String() != "203.0.113.9:40000" || h.Dst.Port() != 443 || h.Local {
		t.Fatalf("v1: %+v %v", h, err)
	}
	rest, _ := br.Peek(5)
	if string(rest) != "GET /" {
		t.Fatalf("v1 consumed too much: %q", rest)
	}
	if h, err := ReadProxyHeader(bufio.NewReader(strings.NewReader("PROXY UNKNOWN\r\n"))); err != nil || !h.Local {
		t.Fatalf("v1 unknown: %+v %v", h, err)
	}
	body4 := append([]byte{203, 0, 113, 9, 10, 0, 0, 1}, 0x9c, 0x40, 0x01, 0xbb)
	br = bufio.NewReader(bytes.NewReader(append(v2(1, 1, body4), "GET"...)))
	h, err = ReadProxyHeader(br)
	if err != nil || h.Version != 2 || h.Src.String() != "203.0.113.9:40000" || h.Dst.String() != "10.0.0.1:443" {
		t.Fatalf("v2 ipv4: %+v %v", h, err)
	}
	if rest, _ := br.Peek(3); string(rest) != "GET" {
		t.Fatal("v2 consumed too much")
	}
	body6 := make([]byte, 36)
	body6[15] = 1 // ::1
	body6[31] = 2 // ::2
	binary.BigEndian.PutUint16(body6[32:], 5000)
	binary.BigEndian.PutUint16(body6[34:], 853)
	if h, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(v2(1, 2, body6)))); err != nil || h.Src.String() != "[::1]:5000" || h.Dst.String() != "[::2]:853" {
		t.Fatalf("v2 ipv6: %+v %v", h, err)
	}
	if h, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(v2(0, 1, body4)))); err != nil || !h.Local {
		t.Fatalf("v2 local: %+v %v", h, err)
	}
	// TLVs after the addresses are skipped.
	withTLV := v2(1, 1, append(body4, 0x01, 0x00, 0x02, 'h', '2'))
	if h, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(append(withTLV, 'X')))); err != nil || h.Src.Port() != 40000 {
		t.Fatalf("v2 tlv: %+v %v", h, err)
	}
	for _, in := range []string{"GET / HTTP/1.1\r\n", "", "PROX"} {
		if _, err := ReadProxyHeader(bufio.NewReader(strings.NewReader(in))); !errors.Is(err, ErrNoProxyHeader) {
			t.Fatalf("%q: %v", in, err)
		}
	}
	for _, in := range []string{"PROXY TCP4 1.2.3.4\r\n", "PROXY TCP9 1.2.3.4 5.6.7.8 1 2\r\n", "PROXY TCP4 ::1 ::2 1 2\r\n", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n", "PROXY " + strings.Repeat("x", 200) + "\r\n"} {
		if _, err := ReadProxyHeader(bufio.NewReader(strings.NewReader(in))); !errors.Is(err, ErrBadProxyHeader) {
			t.Fatalf("%q: %v", in, err)
		}
	}
	short := v2(1, 1, body4[:5])
	if _, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(short))); !errors.Is(err, ErrBadProxyHeader) {
		t.Fatalf("short v2: %v", err)
	}
	if _, err := ReadProxyHeader(bufio.NewReader(bytes.NewReader(v2(1, 1, body4)[:20]))); !errors.Is(err, ErrBadProxyHeader) {
		t.Fatal("truncated v2 accepted")
	}
}
