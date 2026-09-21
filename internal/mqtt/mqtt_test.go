package mqtt_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/mqtt"
)

// connect builds a CONNECT packet body for a version, so the tests
// exercise the wire format rather than a helper that mirrors the parser.
func connect(version byte, clientID string, opts func(flags *byte, payload *[]byte)) mqtt.Packet {
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', version}
	var flags byte = 0x02 // clean session
	payload := []byte{}
	if opts != nil {
		opts(&flags, &payload)
	}
	body = append(body, flags, 0, 60) // keep alive 60
	if version >= mqtt.V5 {
		body = append(body, 0) // no properties
	}
	body = append(body, byte(len(clientID)>>8), byte(len(clientID)))
	body = append(body, clientID...)
	body = append(body, payload...)
	return mqtt.Packet{Type: mqtt.CONNECT, Body: body}
}

func str(s string) []byte {
	return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...)
}

func TestPacketRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 127, 128, 16383, 16384} {
		p := mqtt.Packet{Type: mqtt.PUBLISH, Flags: 0, Body: bytes.Repeat([]byte{'x'}, size)}
		got, err := mqtt.ReadPacket(bytes.NewReader(p.Encode()), 1<<20)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if got.Type != p.Type || len(got.Body) != size {
			t.Fatalf("size %d: got type %d len %d", size, got.Type, len(got.Body))
		}
	}
}

// Two spellings of one length would be two readings of one packet.
func TestRemainingLengthShortestForm(t *testing.T) {
	raw := []byte{mqtt.PUBLISH << 4, 0x80, 0x00}
	if _, err := mqtt.ReadPacket(bytes.NewReader(raw), 1<<20); !errors.Is(err, mqtt.ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
	long := []byte{mqtt.PUBLISH << 4, 0x80, 0x80, 0x80, 0x80, 0x01}
	if _, err := mqtt.ReadPacket(bytes.NewReader(long), 1<<20); !errors.Is(err, mqtt.ErrVarintTooLong) {
		t.Fatalf("want ErrVarintTooLong, got %v", err)
	}
}

func TestPacketTooLarge(t *testing.T) {
	p := mqtt.Packet{Type: mqtt.PUBLISH, Body: bytes.Repeat([]byte{'x'}, 5000)}
	if _, err := mqtt.ReadPacket(bytes.NewReader(p.Encode()), 1024); !errors.Is(err, mqtt.ErrPacketTooLarge) {
		t.Fatalf("want ErrPacketTooLarge, got %v", err)
	}
	// Reserved type 0 is never legal.
	if _, err := mqtt.ReadPacket(bytes.NewReader([]byte{0, 0}), 1024); !errors.Is(err, mqtt.ErrMalformed) {
		t.Fatalf("type 0: want ErrMalformed, got %v", err)
	}
}

func TestParseConnect(t *testing.T) {
	p := connect(mqtt.V311, "device-1", func(flags *byte, payload *[]byte) {
		*flags |= 0x80 | 0x40 | 0x04 | (1 << 3) // user, pass, will at QoS 1
		*payload = append(*payload, str("devices/1/will")...)
		*payload = append(*payload, 0, 3, 'b', 'y', 'e')
		*payload = append(*payload, str("device-1")...)
		*payload = append(*payload, 0, 6, 's', 'e', 'c', 'r', 'e', 't')
	})
	c, err := mqtt.ParseConnect(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != mqtt.V311 || c.ClientID != "device-1" || c.Username != "device-1" {
		t.Fatalf("got %+v", c)
	}
	if c.WillTopic != "devices/1/will" || c.WillQoS != 1 || !c.HasPass || c.KeepAlive != 60 {
		t.Fatalf("got %+v", c)
	}
}

func TestParseConnectV5Properties(t *testing.T) {
	c, err := mqtt.ParseConnect(connect(mqtt.V5, "d", nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != mqtt.V5 || c.ClientID != "d" {
		t.Fatalf("got %+v", c)
	}
}

func TestParseConnectMalformed(t *testing.T) {
	cases := map[string]mqtt.Packet{
		"wrong protocol name": {Type: mqtt.CONNECT, Body: append(str("MQIsdp"), 3, 2, 0, 60, 0, 0)},
		"reserved flag set":   {Type: mqtt.CONNECT, Body: append(str("MQTT"), mqtt.V311, 0x03, 0, 60, 0, 0)},
		"will QoS 3":          {Type: mqtt.CONNECT, Body: append(str("MQTT"), mqtt.V311, 0x04|0x18, 0, 60, 0, 0)},
		"QoS without will":    {Type: mqtt.CONNECT, Body: append(str("MQTT"), mqtt.V311, 0x08, 0, 60, 0, 0)},
		"truncated":           {Type: mqtt.CONNECT, Body: append(str("MQTT"), mqtt.V311, 0x02)},
		"trailing bytes":      {Type: mqtt.CONNECT, Body: append(append(str("MQTT"), mqtt.V311, 0x02, 0, 60), 0, 0, 'x')},
		"flags in header":     {Type: mqtt.CONNECT, Flags: 1, Body: append(str("MQTT"), mqtt.V311, 0x02, 0, 60, 0, 0)},
	}
	for name, p := range cases {
		if _, err := mqtt.ParseConnect(p); err == nil {
			t.Errorf("%s: should not parse", name)
		}
	}
}

// A client id that is not UTF-8, or carries NUL or a surrogate, is
// refused rather than passed to a broker that may read it differently.
func TestParseConnectBadString(t *testing.T) {
	for _, bad := range []string{"\xff\xfe", "a\x00b", "\xed\xa0\x80"} {
		if _, err := mqtt.ParseConnect(connect(mqtt.V311, bad, nil)); !errors.Is(err, mqtt.ErrMalformed) {
			t.Errorf("%q: want ErrMalformed, got %v", bad, err)
		}
	}
}

func TestParsePublish(t *testing.T) {
	body := append(str("sensors/1/temp"), 0, 7)
	body = append(body, "21.5C"...)
	p := mqtt.Packet{Type: mqtt.PUBLISH, Flags: 0x02 | 0x01, Body: body} // QoS 1, retain
	pub, err := mqtt.ParsePublish(p)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Topic != "sensors/1/temp" || pub.QoS != 1 || !pub.Retain || pub.PacketID != 7 {
		t.Fatalf("got %+v", pub)
	}
	bad := map[string]mqtt.Packet{
		"QoS 3":          {Type: mqtt.PUBLISH, Flags: 0x06, Body: str("a")},
		"DUP at QoS 0":   {Type: mqtt.PUBLISH, Flags: 0x08, Body: str("a")},
		"packet id zero": {Type: mqtt.PUBLISH, Flags: 0x02, Body: append(str("a"), 0, 0)},
		"no packet id":   {Type: mqtt.PUBLISH, Flags: 0x02, Body: str("a")},
		"truncated":      {Type: mqtt.PUBLISH, Body: []byte{0, 5, 'a'}},
	}
	for name, p := range bad {
		if _, err := mqtt.ParsePublish(p); err == nil {
			t.Errorf("%s: should not parse", name)
		}
	}
}

func TestParseSubscribe(t *testing.T) {
	body := []byte{0, 1}
	body = append(body, str("sensors/+/temp")...)
	body = append(body, 1)
	body = append(body, str("alerts/#")...)
	body = append(body, 0)
	s, err := mqtt.ParseSubscribe(mqtt.Packet{Type: mqtt.SUBSCRIBE, Flags: 0x02, Body: body}, mqtt.V311)
	if err != nil {
		t.Fatal(err)
	}
	if s.PacketID != 1 || len(s.Filters) != 2 || s.Filters[0].Filter != "sensors/+/temp" || s.Filters[1].Options != 0 {
		t.Fatalf("got %+v", s)
	}
	bad := map[string]mqtt.Packet{
		"no flags":       {Type: mqtt.SUBSCRIBE, Body: body},
		"packet id zero": {Type: mqtt.SUBSCRIBE, Flags: 0x02, Body: append([]byte{0, 0}, body[2:]...)},
		"no filters":     {Type: mqtt.SUBSCRIBE, Flags: 0x02, Body: []byte{0, 1}},
		"QoS 3":          {Type: mqtt.SUBSCRIBE, Flags: 0x02, Body: append(append([]byte{0, 1}, str("a")...), 3)},
		"reserved bits":  {Type: mqtt.SUBSCRIBE, Flags: 0x02, Body: append(append([]byte{0, 1}, str("a")...), 0x40)},
	}
	for name, p := range bad {
		if _, err := mqtt.ParseSubscribe(p, mqtt.V311); err == nil {
			t.Errorf("%s: should not parse", name)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		filter, topic string
		want          bool
	}{
		{"sport/tennis/player1", "sport/tennis/player1", true},
		{"sport/+/player1", "sport/tennis/player1", true},
		{"sport/+", "sport/tennis/player1", false},
		{"sport/#", "sport/tennis/player1", true},
		{"sport/#", "sport", true},
		{"#", "a/b/c", true},
		{"+/b", "a/b", true},
		{"+/b", "/b", true},
		// The $ rule: a wildcard at the first level never reaches the
		// broker's own tree, which is why "#" does not quietly hand a
		// client $SYS.
		{"#", "$SYS/broker/version", false},
		{"+/broker/#", "$SYS/broker/version", false},
		{"$SYS/#", "$SYS/broker/version", true},
	}
	for _, c := range cases {
		if got := mqtt.Match(c.filter, c.topic); got != c.want {
			t.Errorf("Match(%q, %q) = %v want %v", c.filter, c.topic, got, c.want)
		}
	}
}

// Subsumes is the question an allow list asks: a filter is not a topic,
// and matching it as one would let the broadest request through.
func TestSubsumes(t *testing.T) {
	cases := []struct {
		allowed, want string
		ok            bool
	}{
		{"sensors/+/temp", "sensors/1/temp", true},
		{"sensors/+/temp", "sensors/+/temp", true},
		{"sensors/+/temp", "sensors/#", false},
		{"sensors/#", "sensors/1/temp", true},
		{"sensors/#", "#", false},
		{"sensors/#", "sensors/#", true},
		{"#", "#", true},
		{"#", "anything/at/all", true},
		{"sensors/1/#", "sensors/+/temp", false},
		{"sensors/+", "sensors", false},
	}
	for _, c := range cases {
		if got := mqtt.Subsumes(c.allowed, c.want); got != c.ok {
			t.Errorf("Subsumes(%q, %q) = %v want %v", c.allowed, c.want, got, c.ok)
		}
	}
}

// Overlaps is the question a deny list asks: a subscription is refused
// when it could reach anything denied, not only when it names it.
func TestOverlaps(t *testing.T) {
	cases := []struct {
		a, b string
		ok   bool
	}{
		{"$SYS/#", "#", true},
		{"$SYS/#", "+/broker", true},
		{"secret/+/key", "secret/1/key", true},
		{"secret/+/key", "secret/1/value", false},
		{"secret/#", "public/#", false},
		{"a/b", "a/b/c", false},
		{"a/#", "a/b/c", true},
		{"a", "a/#", true},
	}
	for _, c := range cases {
		if got := mqtt.Overlaps(c.a, c.b); got != c.ok {
			t.Errorf("Overlaps(%q, %q) = %v want %v", c.a, c.b, got, c.ok)
		}
	}
}

func TestValidTopicAndFilter(t *testing.T) {
	for _, bad := range []string{"", "a/+/b", "a/#"} {
		if err := mqtt.ValidTopic(bad); err == nil {
			t.Errorf("ValidTopic(%q) should fail", bad)
		}
	}
	if err := mqtt.ValidTopic("a/b/c"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "a/#/b", "a/b#", "a/+b"} {
		if err := mqtt.ValidFilter(bad); err == nil {
			t.Errorf("ValidFilter(%q) should fail", bad)
		}
	}
	for _, ok := range []string{"#", "a/#", "a/+/c", "+"} {
		if err := mqtt.ValidFilter(ok); err != nil {
			t.Errorf("ValidFilter(%q): %v", ok, err)
		}
	}
}

func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{mqtt.PINGREQ << 4, 0})
	f.Add(connect(mqtt.V311, "d", nil).Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := mqtt.ReadPacket(bytes.NewReader(b), 1<<16)
		if err != nil {
			return
		}
		if p.Type == 0 {
			t.Fatal("accepted the reserved packet type")
		}
		// Whatever parses must re-encode to something that parses the
		// same way: the framing is what the session's next read depends
		// on.
		again, err := mqtt.ReadPacket(bytes.NewReader(p.Encode()), 1<<16)
		if err != nil || again.Type != p.Type || !bytes.Equal(again.Body, p.Body) {
			t.Fatalf("round trip changed the packet: %v", err)
		}
	})
}

func FuzzParseConnect(f *testing.F) {
	f.Add(connect(mqtt.V311, "d", nil).Body)
	f.Add(connect(mqtt.V5, "d", nil).Body)
	f.Fuzz(func(t *testing.T, body []byte) {
		c, err := mqtt.ParseConnect(mqtt.Packet{Type: mqtt.CONNECT, Body: body})
		if err != nil {
			return
		}
		if strings.ContainsRune(c.ClientID, 0) || strings.ContainsRune(c.Username, 0) {
			t.Fatal("accepted a NUL in a string")
		}
		if c.WillQoS > 2 {
			t.Fatalf("accepted will QoS %d", c.WillQoS)
		}
	})
}

func FuzzParseSubscribe(f *testing.F) {
	f.Add([]byte{0, 1, 0, 1, 'a', 0})
	f.Fuzz(func(t *testing.T, body []byte) {
		s, err := mqtt.ParseSubscribe(mqtt.Packet{Type: mqtt.SUBSCRIBE, Flags: 0x02, Body: body}, mqtt.V311)
		if err != nil {
			return
		}
		if len(s.Filters) == 0 || s.PacketID == 0 {
			t.Fatal("accepted a subscribe with no filters or no packet id")
		}
	})
}
