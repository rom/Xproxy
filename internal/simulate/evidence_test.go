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
