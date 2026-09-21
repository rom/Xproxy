package capture

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ap
}

// writeFlowTo runs one whole conversation and returns its segments.
func writeFlowTo(t *testing.T, client, server netip.AddrPort, req, resp []byte) []segment {
	t.Helper()
	var buf capBuffer
	p := &writer{w: &buf}
	f := newFlow(client, server, "request_id=test")
	when := time.Date(2026, 9, 21, 9, 30, 0, 0, time.UTC)
	for _, step := range []func() error{
		func() error { return f.open(p, when) },
		func() error { return f.send(p, when, true, req) },
		func() error { return f.send(p, when, false, resp) },
		func() error { return f.close(p, when) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	return segments(t, readPackets(t, readBlocks(t, buf.b)), client)
}

func TestFlowIsAConversationADissectorAccepts(t *testing.T) {
	client := mustAddrPort(t, "198.51.100.7:44321")
	server := mustAddrPort(t, "203.0.113.9:443")
	req := []byte("GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	segs := writeFlowTo(t, client, server, req, resp)

	var shape []string
	for _, s := range segs {
		dir := "->"
		if !s.fromClient {
			dir = "<-"
		}
		shape = append(shape, dir+flagString(s.flags))
		if !s.ipSumOK {
			t.Errorf("segment %s has a bad IPv4 header checksum", dir+flagString(s.flags))
		}
		if !s.tcpSumOK {
			t.Errorf("segment %s has a bad TCP checksum; Wireshark would flag every frame", dir+flagString(s.flags))
		}
		if !s.totalLenConsistent {
			t.Errorf("segment %s: the IP length field disagrees with the frame", dir+flagString(s.flags))
		}
	}
	want := "->S <-SA ->A ->PA <-PA ->FA <-FA ->A"
	if got := strings.Join(shape, " "); got != want {
		t.Errorf("conversation is\n  %s\nwant\n  %s", got, want)
	}

	// Sequence numbers: the handshake costs one each way, then the data
	// advances by its own length. Without that a dissector calls every
	// later segment out of order and reassembles nothing.
	if segs[3].seq != 1 {
		t.Errorf("first client data segment starts at seq %d, want 1 (the SYN consumed one)", segs[3].seq)
	}
	if !bytes.Equal(segs[3].payload, req) {
		t.Errorf("client payload %q, want %q", segs[3].payload, req)
	}
	if segs[4].seq != 1 {
		t.Errorf("first server data segment starts at seq %d, want 1", segs[4].seq)
	}
	if !bytes.Equal(segs[4].payload, resp) {
		t.Errorf("server payload %q, want %q", segs[4].payload, resp)
	}
	if want := uint32(1 + len(req)); segs[5].seq != want {
		t.Errorf("client FIN at seq %d, want %d (one for the SYN plus the data)", segs[5].seq, want)
	}
	if want := uint32(1 + len(resp)); segs[6].seq != want {
		t.Errorf("server FIN at seq %d, want %d", segs[6].seq, want)
	}
	if segs[0].src != client || segs[0].dst != server {
		t.Errorf("SYN is %s -> %s, want %s -> %s", segs[0].src, segs[0].dst, client, server)
	}
}

func TestFlowSplitsAtTheMTU(t *testing.T) {
	client := mustAddrPort(t, "198.51.100.7:44321")
	server := mustAddrPort(t, "203.0.113.9:443")
	body := bytes.Repeat([]byte("x"), defaultMTU*2+7)
	segs := writeFlowTo(t, client, server, body, nil)

	var data []segment
	for _, s := range segs {
		if len(s.payload) > 0 {
			data = append(data, s)
		}
	}
	if len(data) != 3 {
		t.Fatalf("%d data segments for %d bytes, want 3 at a %d byte MTU", len(data), len(body), defaultMTU)
	}
	var seen []byte
	for i, s := range data {
		if len(s.payload) > defaultMTU {
			t.Errorf("segment %d carries %d bytes, over the %d byte MTU", i, len(s.payload), defaultMTU)
		}
		if want := uint32(1 + len(seen)); s.seq != want {
			t.Errorf("segment %d starts at seq %d, want %d: a gap makes the stream unreassemblable", i, s.seq, want)
		}
		seen = append(seen, s.payload...)
	}
	if !bytes.Equal(seen, body) {
		t.Errorf("the segments reassemble to %d bytes, want the %d written", len(seen), len(body))
	}
}

func TestFlowEmptyDirectionWritesNothing(t *testing.T) {
	client := mustAddrPort(t, "198.51.100.7:44321")
	server := mustAddrPort(t, "203.0.113.9:443")
	segs := writeFlowTo(t, client, server, nil, nil)
	if len(segs) != 6 {
		t.Fatalf("%d segments, want the handshake and close only", len(segs))
	}
	for _, s := range segs {
		if len(s.payload) != 0 {
			t.Errorf("a side that said nothing produced a %d byte segment", len(s.payload))
		}
	}
}

func TestFlowIPv6(t *testing.T) {
	client := mustAddrPort(t, "[2001:db8::7]:44321")
	server := mustAddrPort(t, "[2001:db8::9]:443")
	segs := writeFlowTo(t, client, server, []byte("GET / HTTP/1.1\r\n\r\n"), nil)
	for i, s := range segs {
		if !s.v6 {
			t.Fatalf("segment %d is IPv4; an IPv6 conversation must be written as one", i)
		}
		if !s.tcpSumOK {
			t.Errorf("segment %d has a bad TCP checksum over the IPv6 pseudo-header", i)
		}
		if !s.totalLenConsistent {
			t.Errorf("segment %d: the IPv6 payload length disagrees with the frame", i)
		}
	}
	if segs[0].src != client {
		t.Errorf("SYN from %s, want %s", segs[0].src, client)
	}
}

// A client on one family reaching a listener on the other is what a
// dual-stack deployment produces. The frame has one ethertype and one
// address length, so the flow has to settle on a family rather than
// write a header that disagrees with itself.
func TestFlowMixedFamiliesAreCoherent(t *testing.T) {
	client := mustAddrPort(t, "[2001:db8::7]:44321")
	server := mustAddrPort(t, "203.0.113.9:443")
	segs := writeFlowTo(t, client, server, []byte("GET / HTTP/1.1\r\n\r\n"), nil)
	for i, s := range segs {
		if !s.v6 {
			t.Fatalf("segment %d is IPv4 although the client is IPv6", i)
		}
		if !s.tcpSumOK || !s.totalLenConsistent {
			t.Errorf("segment %d is malformed: checksum ok=%v, length ok=%v", i, s.tcpSumOK, s.totalLenConsistent)
		}
	}
	if got := segs[0].dst.Addr(); !got.Is4In6() || got.Unmap() != server.Addr() {
		t.Errorf("IPv4 listener written as %s, want the mapped form of %s", got, server.Addr())
	}
}

func TestChecksumRFC1071(t *testing.T) {
	// The worked example from RFC 1071 section 3.
	b := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got, want := checksum(b), uint16(0x220d); got != want {
		t.Errorf("checksum = %#04x, want %#04x", got, want)
	}
	// An odd-length buffer must not read past the end.
	_ = checksum([]byte{1, 2, 3})
}
