package snmp

import (
	"bytes"
	"testing"
)

// The encoder. Every field this relay writes is one an agent will read, so
// the encoding has to be the one every other manager writes: BER integers
// in the fewest octets, and lengths in the short form until they cannot be.

func TestAnIntegerIsEncodedInTheFewestOctetsThatKeepItsSign(t *testing.T) {
	for _, c := range []struct {
		in   int64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		// 128 needs a leading zero, or the high bit would make it -128.
		{128, []byte{0x00, 0x80}},
		{255, []byte{0x00, 0xff}},
		{256, []byte{0x01, 0x00}},
		{-1, []byte{0xff}},
		{-128, []byte{0x80}},
		{-129, []byte{0xff, 0x7f}},
		{100000, []byte{0x01, 0x86, 0xa0}},
	} {
		got := encodeInt(c.in)
		if !bytes.Equal(got, c.want) {
			t.Errorf("%d encoded as % x, wanted % x", c.in, got, c.want)
		}
		// And it reads back, which is the property that matters: the
		// reader in this package is the one an agent's reader stands in
		// for.
		back, err := readInt(element{tag: TagInteger, body: got})
		if err != nil || back != c.in {
			t.Errorf("%d read back as %d (%v)", c.in, back, err)
		}
	}
}

func TestALengthTakesTheShortFormUntilItCannot(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, 65535, 65536} {
		out := encodeTLV(TagOctetStr, make([]byte, n))
		r := &reader{b: out}
		e, err := r.next()
		if err != nil {
			t.Fatalf("%d octets: %v", n, err)
		}
		if len(e.body) != n || !r.empty() {
			t.Errorf("%d octets encoded to a body of %d", n, len(e.body))
		}
		// The short form is used exactly where it fits, so a rewritten
		// message is byte-identical in shape to one nobody touched.
		wantShort := n < 0x80
		if got := out[1] < 0x80; got != wantShort {
			t.Errorf("%d octets: short form %v", n, got)
		}
	}
}

// The secure downgrade: a v3 request leaves here as v2c, in a community
// string the manager never saw, carrying the PDU that arrived.
func TestAnEnvelopeCarriesThePDUIntoAnotherVersion(t *testing.T) {
	get := pdu(TagGetRequest, 4242, 0, 0, varbind(oid(1, 3, 6, 1, 2, 1, 1, 5, 0), tlv(TagNull)))
	in, err := Parse(v3msg(9, 0x05, 3, usm("engine-a", 1, 2, "monitor", "0123456789ab", ""),
		scopedPDU("engine-a", "", get)))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Envelope(V2c, "s3cret-upstream", in.PDU.Raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(out)
	if err != nil {
		t.Fatalf("the rewritten message does not parse: %v", err)
	}
	if got.Version != V2c || got.Community != "s3cret-upstream" {
		t.Fatalf("version %s community %q", got.Version, got.Community)
	}
	if got.PDU.Type != GetRequest || got.PDU.RequestID != 4242 {
		t.Fatalf("pdu %+v", got.PDU)
	}
	// What was asked for is unchanged, to the octet. A relay that rewrote
	// a binding while rewriting an envelope would be answering a different
	// question from the one the manager asked.
	if !bytes.Equal(got.PDU.Bindings, in.PDU.Bindings) {
		t.Errorf("bindings changed: % x became % x", in.PDU.Bindings, got.PDU.Bindings)
	}
	if got.PDU.VarBinds[0].OID.String() != "1.3.6.1.2.1.1.5.0" {
		t.Errorf("oid %s", got.PDU.VarBinds[0].OID)
	}
}

func TestAnEnvelopeRefusesWhatItCannotHold(t *testing.T) {
	get := pdu(TagGetRequest, 1, 0, 0)
	if _, err := Envelope(V3, "public", get); err == nil {
		t.Error("a v3 envelope with a community string was built")
	}
	if _, err := Envelope(V2c, string(make([]byte, MaxCommunity+1)), get); err == nil {
		t.Error("a community string past the bound was accepted")
	}
	if _, err := Envelope(V2c, "public", nil); err == nil {
		t.Error("an envelope with no PDU was built")
	}
}

// The amplification bound: the repetition count is lowered and nothing else
// about the request moves.
func TestTheRepetitionCountIsLoweredAndNothingElseMoves(t *testing.T) {
	bulk := pdu(TagGetBulkRequest, 77, 0, 10000,
		varbind(oid(1, 3, 6, 1, 2, 1), tlv(TagNull)),
		varbind(oid(1, 3, 6, 1, 2, 2), tlv(TagNull)))
	in, err := Parse(v2c("public", bulk))
	if err != nil {
		t.Fatal(err)
	}
	lowered, err := WithMaxRepetitions(in.PDU.Raw, 25)
	if err != nil {
		t.Fatal(err)
	}
	full, err := Envelope(V2c, "public", lowered)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(full)
	if err != nil {
		t.Fatalf("the lowered request does not parse: %v", err)
	}
	if got.PDU.MaxRepetitions != 25 {
		t.Errorf("max-repetitions is %d", got.PDU.MaxRepetitions)
	}
	if got.PDU.RequestID != 77 || got.PDU.NonRepeaters != 0 {
		t.Errorf("request id %d non-repeaters %d", got.PDU.RequestID, got.PDU.NonRepeaters)
	}
	if !bytes.Equal(got.PDU.Bindings, in.PDU.Bindings) {
		t.Errorf("bindings changed while lowering a count")
	}
}

func TestOnlyAGetBulkHasARepetitionCountToLower(t *testing.T) {
	get := pdu(TagGetRequest, 1, 0, 0, varbind(oid(1, 3, 6, 1), tlv(TagNull)))
	m, err := Parse(v2c("public", get))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithMaxRepetitions(m.PDU.Raw, 10); err == nil {
		t.Error("a GET was rewritten as though it had a repetition count")
	}
	bulk := pdu(TagGetBulkRequest, 1, 0, 5, varbind(oid(1, 3, 6, 1), tlv(TagNull)))
	m, err = Parse(v2c("public", bulk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithMaxRepetitions(m.PDU.Raw, -1); err == nil {
		t.Error("a negative repetition count was written")
	}
	// Trailing octets after the PDU are not a PDU this relay will rebuild:
	// it would be choosing which of two readings to forward.
	if _, err := WithMaxRepetitions(append(append([]byte{}, m.PDU.Raw...), 0x05, 0x00), 5); err == nil {
		t.Error("a PDU with trailing octets was rewritten")
	}
}

// The refusal. A manager that gets an error knows it was refused; a manager
// that gets nothing knows only that something timed out, which is what a
// dead device looks like.
func TestARefusalIsTheErrorTheVersionHasAWordFor(t *testing.T) {
	binds := varbind(oid(1, 3, 6, 1, 2, 1, 1, 5, 0), octets(TagOctetStr, "newname"))
	set := pdu(TagSetRequest, 31337, 0, 0, binds)

	m, err := Parse(v2c("private", set))
	if err != nil {
		t.Fatal(err)
	}
	answer, err := Parse(Refusal(m))
	if err != nil {
		t.Fatalf("the refusal does not parse: %v", err)
	}
	if answer.Version != V2c || answer.Community != "private" {
		t.Fatalf("version %s community %q", answer.Version, answer.Community)
	}
	if answer.PDU.Type != Response || answer.PDU.RequestID != 31337 {
		t.Fatalf("pdu %+v", answer.PDU)
	}
	if answer.PDU.ErrorStatus != StatusNoAccess {
		t.Errorf("error status %d, wanted noAccess", answer.PDU.ErrorStatus)
	}
	if len(answer.PDU.VarBinds) != 1 {
		t.Errorf("the refusal did not echo the bindings: %+v", answer.PDU.VarBinds)
	}

	// Version 1 has no noAccess, so it says the only thing it can.
	m, err = Parse(v1msg("private", set))
	if err != nil {
		t.Fatal(err)
	}
	answer, err = Parse(Refusal(m))
	if err != nil {
		t.Fatalf("the v1 refusal does not parse: %v", err)
	}
	if answer.PDU.ErrorStatus != StatusNoSuchName || answer.PDU.ErrorIndex != 1 {
		t.Errorf("v1 refusal: status %d index %d", answer.PDU.ErrorStatus, answer.PDU.ErrorIndex)
	}
}

func TestThereIsNoRefusalToSendForAMessageThatIsNotAsking(t *testing.T) {
	get := pdu(TagGetRequest, 1, 0, 0, varbind(oid(1, 3, 6, 1), tlv(TagNull)))
	// A v3 request: a response would have to carry an authentication digest
	// this relay has no key to compute.
	m, err := Parse(v3msg(1, 0x05, 3, usm("e", 1, 1, "monitor", "0123456789ab", ""),
		scopedPDU("e", "", get)))
	if err != nil {
		t.Fatal(err)
	}
	if answer := Refusal(m); answer != nil {
		t.Error("a v3 request was answered with an unauthenticated response")
	}
	// A trap: nobody is waiting on an answer.
	trap := pdu(TagTrapV2, 5, 0, 0, varbind(oid(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), oid(1, 3, 6, 1)))
	m, err = Parse(v2c("public", trap))
	if err != nil {
		t.Fatal(err)
	}
	if answer := Refusal(m); answer != nil {
		t.Error("a trap was answered")
	}
	// And a response, which is not a request.
	resp := pdu(TagResponse, 5, 0, 0, varbind(oid(1, 3, 6, 1), tlv(TagNull)))
	m, err = Parse(v2c("public", resp))
	if err != nil {
		t.Fatal(err)
	}
	if answer := Refusal(m); answer != nil {
		t.Error("a response was answered")
	}
	if answer := Refusal(nil); answer != nil {
		t.Error("nothing was answered")
	}
}
