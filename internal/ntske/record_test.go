package ntske

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// request builds a client request out of records, so that a test can send a
// malformed one without the encoder refusing to make it.
func request(recs ...Record) []byte {
	var out []byte
	for _, r := range recs {
		out = r.AppendTo(out)
	}
	return Record{Critical: true, Type: RecEndOfMessage}.AppendTo(out)
}

func offer(protos, aeads []uint16) []byte {
	return request(
		Record{Critical: true, Type: RecNextProtocol, Body: uint16List(protos...)},
		Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(aeads...)},
	)
}

func TestARecordRoundTripsThroughTheWire(t *testing.T) {
	in := []Record{
		{Critical: true, Type: RecNextProtocol, Body: uint16List(0)},
		{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15, 17)},
		{Type: RecNewCookie, Body: []byte("cookie")},
		{Type: RecServer, Body: []byte("time.example")},
		{Critical: true, Type: RecEndOfMessage},
	}
	var wire []byte
	for _, r := range in {
		wire = r.AppendTo(wire)
	}
	out, err := ParseRecords(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("parsed %d records of %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Critical != in[i].Critical || out[i].Type != in[i].Type || !bytes.Equal(out[i].Body, in[i].Body) {
			t.Errorf("record %d: got %+v want %+v", i, out[i], in[i])
		}
	}
}

// The critical bit lives in the same field as the type, so a type with the high
// bit set would be indistinguishable from a critical record of a lower type.
// AppendTo masks it, and the parser separates them.
func TestTheCriticalBitIsNotPartOfTheType(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       Record
		wantCrit bool
		wantType uint16
	}{
		{"plain", Record{Type: 7}, false, 7},
		{"critical", Record{Critical: true, Type: 7}, true, 7},
		{"type with the bit set", Record{Type: 0x8007}, false, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.in.AppendTo(nil)
			wire = Record{Critical: true, Type: RecEndOfMessage}.AppendTo(wire)
			out, err := ParseRecords(wire)
			if err != nil {
				t.Fatal(err)
			}
			if out[0].Critical != tc.wantCrit || out[0].Type != tc.wantType {
				t.Fatalf("got critical=%v type=%d want critical=%v type=%d",
					out[0].Critical, out[0].Type, tc.wantCrit, tc.wantType)
			}
		})
	}
}

func TestAMalformedMessageIsRefused(t *testing.T) {
	end := Record{Critical: true, Type: RecEndOfMessage}.AppendTo(nil)
	// A message past the whole-message bound that is otherwise valid: records
	// within their own bound, few enough of them, and an End of Message at the
	// end. A bound that only caught malformed messages would not be a bound.
	var long []byte
	for len(long) <= MaxMessage {
		long = Record{Type: RecNewCookie, Body: make([]byte, MaxRecordBody)}.AppendTo(long)
	}
	long = Record{Critical: true, Type: RecEndOfMessage}.AppendTo(long)
	manyBody := Record{Type: RecNewCookie, Body: []byte("x")}.AppendTo(nil)
	var many []byte
	for i := 0; i <= MaxRecords; i++ {
		many = append(many, manyBody...)
	}
	// A body length the sender promised and did not send.
	lying := []byte{0x00, 0x05, 0x00, 0x20, 'a', 'b'}
	// A record whose body is past the per-record bound, promised but not sent:
	// the bound has to be checked before the body is waited for, or a single
	// header would reserve as much as the length field can say.
	big := binary.BigEndian.AppendUint16(nil, RecNewCookie)
	big = binary.BigEndian.AppendUint16(big, MaxRecordBody+1)

	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"a header cut in half", []byte{0x00, 0x00, 0x00}, ErrTruncated},
		{"a body cut short", lying, ErrTruncated},
		{"no end of message at all", Record{Type: RecNewCookie}.AppendTo(nil), ErrNoEnd},
		{"octets after the end", append(append([]byte(nil), end...), 0x00), ErrTooLong},
		{"a whole message past the bound", long, ErrTooLong},
		{"a record body past the bound", big, ErrTooLong},
		{"more records than the bound", many, ErrTooLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseRecords(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// An empty message is a message with no End of Message record. It is refused
// for the same reason a short one is: nothing in it says the sender is finished.
func TestAnEmptyMessageIsNotAnEmptyRequest(t *testing.T) {
	if _, err := ParseRecords(nil); !errors.Is(err, ErrNoEnd) {
		t.Fatalf("got %v, want %v", err, ErrNoEnd)
	}
}

func TestARequestIsReadFromItsRecords(t *testing.T) {
	in := request(
		Record{Critical: true, Type: RecNextProtocol, Body: uint16List(0)},
		Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15)},
		Record{Type: RecServer, Body: []byte("time.example")},
		Record{Type: RecPort, Body: uint16List(1230)},
	)
	q, err := ParseRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.NextProtocols) != 1 || q.NextProtocols[0] != NextProtoNTPv4 {
		t.Errorf("next protocols %v", q.NextProtocols)
	}
	if len(q.AEADs) != 1 || q.AEADs[0] != AEADAESSIVCMAC256 {
		t.Errorf("aeads %v", q.AEADs)
	}
	if q.Server != "time.example" || !q.HasPort || q.Port != 1230 {
		t.Errorf("server %q port %d has %v", q.Server, q.Port, q.HasPort)
	}
}

// A port the client did not ask for must not read as port zero: the caller
// decides what to answer from whether it was asked at all.
func TestAnAbsentPortIsNotPortZero(t *testing.T) {
	q, err := ParseRequest(offer([]uint16{0}, []uint16{15}))
	if err != nil {
		t.Fatal(err)
	}
	if q.HasPort {
		t.Fatalf("a request with no port record reports port %d", q.Port)
	}
	withZero, err := ParseRequest(request(
		Record{Critical: true, Type: RecNextProtocol, Body: uint16List(0)},
		Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15)},
		Record{Type: RecPort, Body: uint16List(0)},
	))
	if err != nil {
		t.Fatal(err)
	}
	if !withZero.HasPort {
		t.Fatal("a request that asked for port 0 reads as one that asked for nothing")
	}
}

func TestARequestIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{
			"an unknown critical record",
			request(
				Record{Critical: true, Type: RecNextProtocol, Body: uint16List(0)},
				Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15)},
				Record{Critical: true, Type: 900, Body: []byte("?")},
			),
			ErrCritical,
		},
		{
			"an odd number of octets where a list of numbers belongs",
			request(
				Record{Critical: true, Type: RecNextProtocol, Body: []byte{0, 0, 0}},
				Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15)},
			),
			ErrTruncated,
		},
		{
			"an odd AEAD list",
			request(
				Record{Critical: true, Type: RecNextProtocol, Body: uint16List(0)},
				Record{Critical: true, Type: RecAEADAlgorithm, Body: []byte{0}},
			),
			ErrTruncated,
		},
		{
			"a port that is not two octets",
			request(
				Record{Critical: true, Type: RecNextProtocol, Body: uint16List(0)},
				Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15)},
				Record{Type: RecPort, Body: []byte{1, 2, 3}},
			),
			ErrTruncated,
		},
		{
			"no next protocol offered",
			request(Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15)}),
			ErrRequest,
		},
		{
			"no algorithm offered",
			request(Record{Critical: true, Type: RecNextProtocol, Body: uint16List(0)}),
			ErrRequest,
		},
		{
			"an empty next protocol record, which offers nothing",
			request(
				Record{Critical: true, Type: RecNextProtocol},
				Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15)},
			),
			ErrRequest,
		},
		{"not a message at all", []byte{0x00}, ErrTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseRequest(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// An unknown record that is not critical is the extension point of the format.
// Refusing it would make this relay the reason a client could not adopt a later
// revision of the standard.
func TestAnUnknownRecordThatIsNotCriticalIsIgnored(t *testing.T) {
	q, err := ParseRequest(request(
		Record{Type: 900, Body: []byte("later")},
		Record{Critical: true, Type: RecNextProtocol, Body: uint16List(0)},
		Record{Type: 901},
		Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(15)},
		Record{Type: RecWarning, Body: uint16List(1)},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(q.NextProtocols) != 1 || len(q.AEADs) != 1 {
		t.Fatalf("the records around the unknown ones were not read: %+v", q)
	}
}

func TestNegotiationTakesWhatBothSidesHave(t *testing.T) {
	for _, tc := range []struct {
		name          string
		protos, aeads []uint16
		wantOK        bool
	}{
		{"exactly what is supported", []uint16{0}, []uint16{15}, true},
		{"among others", []uint16{7, 0}, []uint16{30, 15, 17}, true},
		{"no protocol in common", []uint16{1, 2}, []uint16{15}, false},
		{"no algorithm in common", []uint16{0}, []uint16{16, 17}, false},
		{"neither", []uint16{1}, []uint16{16}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := ParseRequest(offer(tc.protos, tc.aeads))
			if err != nil {
				t.Fatal(err)
			}
			proto, aead, ok := Negotiate(q)
			if ok != tc.wantOK {
				t.Fatalf("negotiated %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if proto != NextProtoNTPv4 || aead != AEADAESSIVCMAC256 {
				t.Fatalf("negotiated protocol %d algorithm %d", proto, aead)
			}
		})
	}
}

// A negotiation that succeeded on the protocol and failed on the algorithm must
// report failure, not a protocol with algorithm zero: zero is a real AEAD
// number and a caller that took it would seal cookies under an algorithm nobody
// agreed to.
func TestAFailedNegotiationReturnsNothingUsable(t *testing.T) {
	q, err := ParseRequest(offer([]uint16{0}, []uint16{16}))
	if err != nil {
		t.Fatal(err)
	}
	proto, aead, ok := Negotiate(q)
	if ok || proto != 0 || aead != 0 {
		t.Fatalf("got protocol %d algorithm %d ok %v", proto, aead, ok)
	}
}

func TestAResponseIsReadableByAClient(t *testing.T) {
	r := &Response{
		NextProtocol: NextProtoNTPv4,
		AEAD:         AEADAESSIVCMAC256,
		Cookies:      [][]byte{[]byte("one"), []byte("two")},
		Server:       "time.example",
		Port:         1230,
		HasPort:      true,
	}
	recs, err := ParseRecords(r.AppendTo(nil))
	if err != nil {
		t.Fatal(err)
	}
	var cookies [][]byte
	var proto, aead []uint16
	var server string
	var port uint16
	for _, rec := range recs {
		switch rec.Type {
		case RecNextProtocol:
			proto, _ = uint16s(rec.Body)
		case RecAEADAlgorithm:
			aead, _ = uint16s(rec.Body)
		case RecNewCookie:
			cookies = append(cookies, rec.Body)
		case RecServer:
			server = string(rec.Body)
		case RecPort:
			port = binary.BigEndian.Uint16(rec.Body)
		}
	}
	if len(proto) != 1 || proto[0] != NextProtoNTPv4 || len(aead) != 1 || aead[0] != AEADAESSIVCMAC256 {
		t.Errorf("protocol %v algorithm %v", proto, aead)
	}
	if len(cookies) != 2 || string(cookies[0]) != "one" || string(cookies[1]) != "two" {
		t.Errorf("cookies %q", cookies)
	}
	if server != "time.example" || port != 1230 {
		t.Errorf("server %q port %d", server, port)
	}
	if recs[len(recs)-1].Type != RecEndOfMessage {
		t.Errorf("the response does not end with end of message: %+v", recs[len(recs)-1])
	}
	// The negotiated terms come before the cookies, so a client reading in
	// order knows what the cookies are for by the time it reaches them.
	if recs[0].Type != RecNextProtocol || recs[1].Type != RecAEADAlgorithm {
		t.Errorf("the response opens with %d then %d", recs[0].Type, recs[1].Type)
	}
	// Everything the client must act on is critical.
	for _, rec := range recs {
		if rec.Type != RecNewCookie && !rec.Critical {
			t.Errorf("record %d is not critical", rec.Type)
		}
	}
}

// A server that is where the client already thinks it is says nothing about it,
// because a response that repeated the connection's own address would be a
// response a client had to compare rather than ignore.
func TestAResponseOmitsWhatItDoesNotRedirect(t *testing.T) {
	recs, err := ParseRecords((&Response{NextProtocol: NextProtoNTPv4, AEAD: AEADAESSIVCMAC256}).AppendTo(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if rec.Type == RecServer || rec.Type == RecPort {
			t.Errorf("record %d is present with nothing to say", rec.Type)
		}
	}
}

func TestAnErrorMessageIsAWholeMessage(t *testing.T) {
	recs, err := ParseRecords(ErrorMessage(ErrBadRequest))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("%d records: %+v", len(recs), recs)
	}
	if !recs[0].Critical || recs[0].Type != RecError || len(recs[0].Body) != 2 {
		t.Fatalf("error record %+v", recs[0])
	}
	if got := binary.BigEndian.Uint16(recs[0].Body); got != ErrBadRequest {
		t.Fatalf("code %d, want %d", got, ErrBadRequest)
	}
	if recs[1].Type != RecEndOfMessage {
		t.Fatalf("second record %+v", recs[1])
	}
}
