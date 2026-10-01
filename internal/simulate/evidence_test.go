package simulate

import (
	"encoding/hex"
	"strings"
	"testing"

	_ "github.com/rom/xproxy/internal/kinds/modbus" // a kind that speaks bytes, not HTTP
)

// A Modbus relay in front of a PLC, with one rule: reads anywhere, writes only
// into the window the process engineer signed off.
const modbusYAML = `version: 1
server:
  listeners:
    - name: line1
      address: "10.20.0.4:502"
      kind: modbus
      daemon: xot
      modbus:
        upstream: plc
        units: ["1-8"]
        rules:
          - {name: reads, action: allow, access: [read], addresses: ["0-1999"]}
          - {name: setpoints, action: allow, functions: [write_multiple_registers], write_addresses: ["400-499"]}
upstreams:
  - {name: plc, endpoints: [{address: "10.20.0.9:502"}]}
`

func frame(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The fail-open case, which is the one that matters.
//
// A listener that speaks bytes rather than HTTP answers only when it has
// something from the device, so absence of a refusal is not evidence of an
// allow: a frame the listener could not finish reading produces no reply and no
// event at all. Reporting that as "allowed" would put a hole in the report
// exactly where an operator would rely on it, so the simulation asserts an
// allow only on evidence -- the input reached the sink, or the listener answered
// -- and says "error" where it has neither.
func TestAnAllowIsAssertedOnlyOnEvidence(t *testing.T) {
	r, err := Start(parse(t, modbusYAML), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()

	// A read the rules allow: relayed, and the relay reaching the sink is what
	// makes the allow an observation rather than an assumption.
	read := r.Ask(Input{Name: "read holding registers",
		Bytes: frame(t, "0001 0000 0006 01 03 0000 0001")})
	if read.Decision != Allowed {
		t.Errorf("a read the rules allow: %+v", read)
	}
	if !read.Relayed {
		t.Error("an allowed frame did not reach the sink: the allow rests on nothing")
	}

	// A write outside the window: refused, with the reason the security log uses,
	// and nothing reached the far side.
	write := r.Ask(Input{Name: "write outside the window",
		Bytes: frame(t, "0002 0000 0009 01 10 0000 0001 02 0064")})
	if write.Decision != Refused {
		t.Fatalf("a write outside the window was not refused: %+v", write)
	}
	if write.Relayed {
		t.Error("a refused frame reached the sink")
	}

	// A frame whose length field claims two more bytes than it carries. The
	// listener is still waiting for the rest of it when the connection ends: no
	// decision was taken, and the report has to say so.
	short := r.Ask(Input{Name: "a frame with a wrong length",
		Bytes: frame(t, "0003 0000 000b 01 10 0000 0001 02 0064")})
	if short.Decision != Errored {
		t.Errorf("an unfinished frame was reported as a decision: %+v", short)
	}
	if short.Relayed {
		t.Error("an unfinished frame reached the sink")
	}
	if !strings.Contains(short.Err, "nothing was relayed") {
		t.Errorf("error %q does not say what happened", short.Err)
	}
}

// A Modbus listener whose rules name the clients that may write, in front of
// the same PLC. It parses a PROXY protocol header, which is how an estate
// behind a load balancer gets the real client address, and how a simulation
// gets to ask a question about one.
const clientYAML = `version: 1
trusted_proxies: ["10.20.0.0/16"]
server:
  listeners:
    - name: line1
      address: "10.20.0.4:502"
      kind: modbus
      daemon: xot
      proxy_protocol: true
      modbus:
        upstream: plc
        units: ["1-8"]
        rules:
          - {name: masters, action: allow, clients: ["10.30.2.0/24"], functions: [write_multiple_registers]}
          - {name: reads, action: allow, access: [read]}
upstreams:
  - {name: plc, endpoints: [{address: "10.20.0.9:502"}]}
`

// The question an OT policy is mostly made of: may *this* address do this?
//
// A simulation connects from loopback, so without the PROXY protocol header the
// answer to every address-based rule would be the same one, and an operator
// reading it would conclude their allow list did not work. The corpus's
// client= is delivered where the listener parses a header, and where it does
// not the run says so by name rather than answering as though it had.
func TestAClientAddressDecidesWhereTheListenerParsesOne(t *testing.T) {
	r, err := Start(parse(t, clientYAML), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	write := frame(t, "0001 0000 0009 01 10 0000 0001 02 0064")

	master := r.Ask(Input{Name: "a master writing", Client: "10.30.2.14", Bytes: write})
	if master.Decision != Allowed {
		t.Errorf("a write from an address the rule names: %+v", master)
	}
	if master.Client != "10.30.2.14" {
		t.Errorf("the outcome does not carry the address: %+v", master)
	}

	stranger := r.Ask(Input{Name: "somebody else writing", Client: "10.30.9.9", Bytes: write})
	if stranger.Decision != Refused {
		t.Fatalf("a write from an address no rule names was not refused: %+v", stranger)
	}

	// And the loopback address this program really connects from is not what
	// decided either of them: without the header both would have been the same.
	if master.Decision == stranger.Decision {
		t.Error("the two addresses decided the same, so the header did not arrive")
	}
	for _, n := range r.Report().Notes {
		if strings.Contains(n, "trusted_proxies") {
			return
		}
	}
	t.Errorf("the report does not say loopback was added to trusted_proxies: %v", r.Report().Notes)
}

// And where the listener does not parse a header, the address is reported as
// not delivered instead of quietly deciding nothing.
func TestAClientAddressThatCouldNotBeDeliveredIsSaidSo(t *testing.T) {
	r, err := Start(parse(t, modbusYAML), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	out := r.Ask(Input{Name: "a read from somewhere", Client: "10.30.2.14",
		Bytes: frame(t, "0001 0000 0006 01 03 0000 0001")})
	if out.Decision != Allowed {
		t.Errorf("the read was not decided: %+v", out)
	}
	var said bool
	for _, n := range r.Report().Notes {
		if strings.Contains(n, "line1") && strings.Contains(n, "PROXY protocol") {
			said = true
		}
	}
	if !said {
		t.Errorf("the report does not say the client address could not be delivered: %v",
			r.Report().Notes)
	}
}
