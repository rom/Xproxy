package modbus

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/rom/xproxy/internal/modbus"
)

// A trace is the engineer's tool, and it is a different thing from the
// audit log.
//
// The audit log answers "who was refused and why", keeps forever and is
// shipped off the machine. A trace answers "what is this master actually
// doing", is turned on for an afternoon during a commissioning or an
// incident, and is read with grep. Mixing them gives an audit log nobody
// can afford to keep and a trace nobody can find anything in.
//
// So the trace is its own file, its own bound and its own switch, and it
// stops at the bound rather than filling the disk the plant's historian
// is also on.

// TraceEntry is one line of the trace.
type TraceEntry struct {
	Time        string `json:"time"`
	Listener    string `json:"listener"`
	Direction   string `json:"direction"`
	Client      string `json:"client"`
	Role        string `json:"role,omitempty"`
	Upstream    string `json:"upstream,omitempty"`
	Transaction uint16 `json:"transaction"`
	Unit        uint8  `json:"unit"`
	Function    string `json:"function"`
	Access      string `json:"access,omitempty"`
	// SubFunction and Effect are the second code a frame carries where it
	// has one -- a diagnostic sub-function, a UMAS command -- and what it
	// does. They are in the trace because "function: diagnostic" is the
	// line an engineer would have had to decode by hand, and it is the
	// line that says whether a device was polled or taken off the bus.
	SubFunction string `json:"sub_function,omitempty"`
	Effect      string `json:"effect,omitempty"`
	// Session is the UMAS pairing key, when there is one.
	Session   *int   `json:"umas_session,omitempty"`
	Address   *int   `json:"address,omitempty"`
	Quantity  *int   `json:"quantity,omitempty"`
	Exception string `json:"exception,omitempty"`
	Decision  string `json:"decision,omitempty"`
	Rule      string `json:"rule,omitempty"`
	Data      string `json:"data,omitempty"`
	Bytes     int    `json:"bytes"`
}

// Tracer writes the trace file.
type Tracer struct {
	listener  string
	max       int64
	data      bool
	requests  bool
	responses bool

	mu      sync.Mutex
	f       *os.File
	written int64
	full    bool

	// Lines counts what was written and Dropped what the bound refused.
	Lines, Dropped atomic.Uint64
}

// NewTracer opens the trace file, appending to it.
func NewTracer(listener, path string, max int64, data, requests, responses bool) (*Tracer, error) {
	if max <= 0 {
		max = 100 << 20
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // the path is the operator's own configuration
	if err != nil {
		return nil, fmt.Errorf("modbus trace: %w", err)
	}
	t := &Tracer{listener: listener, max: max, data: data,
		requests: requests, responses: responses, f: f}
	if info, err := f.Stat(); err == nil {
		t.written = info.Size()
	}
	return t, nil
}

// Close closes the file.
func (t *Tracer) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil {
		return nil
	}
	f := t.f
	t.f = nil
	return f.Close()
}

// Full says the bound was reached, so the status can say the trace
// stopped rather than leaving an operator to notice the file stopped
// growing.
func (t *Tracer) Full() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.full
}

// Request traces a request frame.
func (t *Tracer) Request(e TraceEntry, pdu *wire.PDU, raw []byte) {
	if t == nil || !t.requests {
		return
	}
	t.write(e, pdu, raw, "request")
}

// Response traces a response frame.
func (t *Tracer) Response(e TraceEntry, pdu *wire.PDU, raw []byte) {
	if t == nil || !t.responses {
		return
	}
	t.write(e, pdu, raw, "response")
}

func (t *Tracer) write(e TraceEntry, pdu *wire.PDU, raw []byte, dir string) {
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	e.Listener = t.listener
	e.Direction = dir
	e.Bytes = len(raw)
	if pdu != nil {
		e.Function = wire.FunctionName(pdu.Function)
		e.Access = string(pdu.Access)
		if pdu.HasSubFunction {
			e.SubFunction = pdu.SubName()
			if eff, ok := pdu.SubEffect(); ok {
				e.Effect = string(eff)
			}
		}
		if pdu.HasSession {
			sess := int(pdu.Session)
			e.Session = &sess
		}
		if pdu.HasRange {
			addr, qty := int(pdu.Address), int(pdu.Quantity)
			e.Address, e.Quantity = &addr, &qty
		}
		if pdu.IsException {
			e.Exception = wire.ExceptionName(pdu.Exception)
		}
	}
	if t.data && len(raw) > 0 {
		e.Data = hex.EncodeToString(raw)
	}
	line, err := json.Marshal(e)
	if err != nil {
		t.Dropped.Add(1)
		return
	}
	line = append(line, '\n')
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f == nil || t.full {
		t.Dropped.Add(1)
		return
	}
	if t.written+int64(len(line)) > t.max {
		// The bound is what keeps a trace somebody left on from taking
		// the disk down with it. It stops, and the fact that it stopped
		// is counted, reported, and written into the file itself: a
		// trace that ends in the middle of an exchange reads as the
		// exchange ending, which is the wrong conclusion to hand an
		// engineer looking for one.
		t.full = true
		t.Dropped.Add(1)
		mark := fmt.Sprintf(
			"{\"time\":%q,\"listener\":%q,\"direction\":\"trace_full\","+
				"\"note\":\"the trace reached max_bytes and stopped\"}\n", e.Time, t.listener)
		n, _ := t.f.WriteString(mark)
		t.written += int64(n)
		return
	}
	n, err := t.f.Write(line)
	t.written += int64(n)
	if err != nil {
		t.Dropped.Add(1)
		return
	}
	t.Lines.Add(1)
}
