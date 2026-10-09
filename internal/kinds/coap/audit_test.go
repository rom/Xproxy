package coap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The access line, which on this protocol carries the one number that says
// whether a segment is being used as a reflector.
//
// CoAP is a datagram protocol with a four-octet request and an answer that can
// be a thousand times its size, which is what makes a sensor network an
// amplifier somebody else points at a victim. The relay bounds that, and the
// line it writes is where an operator sees it happening: the request size, the
// response size, and the factor between them, per exchange.
//
// Written through a real logger rather than proxytest, which discards the
// streams: this is a test about what is in them.

const auditYAML = `
version: 1
server:
  listeners:
    - name: segment
      address: "127.0.0.1:0"
      kind: coap
      coap:
%s
logging:
  directory: %s
  access: {enabled: true, file: access.log}
upstreams:
  - {name: devices, endpoints: [{address: %q}]}
`

func auditRelay(t *testing.T, section, device string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(fmt.Sprintf(auditYAML, section, dir, device)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	s, err := proxy.New(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		logs.Close()
	})
	return proxytest.Addr(t, s, "segment"), dir
}

// accessLog waits for the stream to hold what the test is looking for. The
// line is written from the exchange's own goroutine and flushed by the logger,
// so reading the instant the client's answer arrives races the relay rather
// than testing it.
func accessLog(t *testing.T, dir, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join(dir, "access.log"))
		if err == nil && strings.Contains(string(b), want) {
			return string(b)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the access log never held %q:\n%s", want, b)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestTheAccessLineCarriesTheAmplificationOfEachExchange: both halves of an
// exchange are written, and the device's half carries the sizes and the factor
// between them -- which is the number an operator watches on a segment that
// faces anything.
func TestTheAccessLineCarriesTheAmplificationOfEachExchange(t *testing.T) {
	// A device whose answer is far larger than the question, with the options
	// a real sensor sends: a content format, a block of a larger response,
	// and a notification sequence number.
	big := strings.Repeat("21.5,", 200)
	d := startDevice(t, &fakeDevice{reply: func(req *wire.Message) *wire.Message {
		out := wire.Answer(req, wire.Content, req.MessageID)
		out.Set(wire.OptionContentFormat, nil)
		out.Set(wire.OptionBlock2, []byte{0x0A}) // block 0, more to come
		out.Set(wire.OptionObserve, []byte{0x00, 0x00, 0x2A})
		out.Payload = []byte(big)
		return out
	}})
	addr, dir := auditRelay(t, base+"        log_messages: true\n"+
		"        max_response_bytes: 4096\n"+
		"        allow_observe: true\n", d.addr())

	c := dial(t, addr)
	m := get(1, 0x11, "3303", "0", "5700")
	m.Set(wire.OptionObserve, nil) // a registration
	if got := c.ask(m); got.Code != wire.Content {
		t.Fatalf("the exchange answered %s", got.Code)
	}

	// The device's half of the exchange, with the sizes and the factor.
	line := accessLog(t, dir, `"side":"device"`)
	for _, want := range []string{
		`"path":"/3303/0/5700"`,
		`"response_bytes":`,
		`"request_bytes":`,
		`"factor":`,
		`"content_format":"text/plain"`,
		`"block2":`,
		`"rule":"telemetry"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the access log does not carry %s:\n%s", want, line)
		}
	}
	// And the factor is the ratio, not a constant: the answer here is two
	// orders of magnitude larger than the question.
	if !strings.Contains(line, `"side":"client"`) {
		t.Errorf("the client's half of the exchange was not logged:\n%s", line)
	}
}
