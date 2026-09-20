package geoip

import (
	"testing"
	"time"
)

// Nesting depth alone does not bound the decoder's work: an array of two
// pointers into the next array costs 2^k decodes for a chain of k
// arrays, six bytes per level, so a couple of hundred bytes reach 2^32
// values. The metadata uses the same decoder, so the whole file can be
// that small — and geoip.Open runs at start-up and again on every
// reload, with a database most deployments fetch from a third party.
func TestDecoderBombIsRefused(t *testing.T) {
	// k arrays, each of size 2, whose two elements are pointers to the
	// next array. Six bytes per level: a two-byte extended-type header
	// and two two-byte pointers.
	const k = 32
	var data []byte
	for i := 0; i < k; i++ {
		next := (i + 1) * 6
		data = append(data, 0x02, 0x04) // extended type 11 (array), size 2
		for j := 0; j < 2; j++ {
			data = append(data, 0x20|byte(next>>8)&7, byte(next)) // pointer, one-byte form
		}
	}
	data = append(data, 0x00, 0x04) // an empty array to land on
	done := make(chan struct{})
	go func() {
		defer close(done)
		d := newDecoder(data)
		if _, _, err := d.decode(0, 0); err == nil {
			t.Error("a decoder bomb decoded cleanly")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%d bytes did not come back: the work budget is not doing its job", len(data))
	}
}

// A container whose declared size the remaining bytes cannot hold is a
// lie; allocating for it turns a handful of bytes into megabytes.
func TestOversizedContainerIsRefused(t *testing.T) {
	for _, b := range [][]byte{
		{0x1d, 0x04, 0xff}, // array of 284 elements in three bytes
		{0xfd, 0xff},       // map of 284 entries in two bytes
	} {
		d := newDecoder(b)
		if _, _, err := d.decode(0, 0); err == nil {
			t.Fatalf("%v decoded cleanly", b)
		}
	}
}
