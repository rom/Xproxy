package ntp

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/rom/xproxy/internal/ntp"
)

// A trace is the engineer's tool, and a different thing from the audit
// log: it answers "what is this device actually asking, and what is it
// being told", it is turned on for an afternoon, and it is read with grep.
// It has its own file, its own bound, and it stops at the bound rather
// than filling the disk.

// TraceEntry is one line of the trace.
type TraceEntry struct {
	Time      string `json:"time"`
	Listener  string `json:"listener"`
	Direction string `json:"direction"`
	Client    string `json:"client"`
	Server    string `json:"server,omitempty"`

	Version   uint8  `json:"version"`
	Mode      string `json:"mode"`
	Leap      string `json:"leap"`
	Stratum   uint8  `json:"stratum"`
	RefID     string `json:"refid,omitempty"`
	Poll      int8   `json:"poll"`
	Precision int8   `json:"precision"`

	RootDelayMS      float64 `json:"root_delay_ms"`
	RootDispersionMS float64 `json:"root_dispersion_ms"`
	OffsetMS         float64 `json:"offset_ms,omitempty"`
	DelayMS          float64 `json:"delay_ms,omitempty"`

	Extensions []string `json:"extensions,omitempty"`
	NTSFields  bool     `json:"nts_fields,omitempty"`
	KeyID      uint32   `json:"key_id,omitempty"`
	CryptoNAK  bool     `json:"crypto_nak,omitempty"`

	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Bytes    int    `json:"bytes"`
}

// Tracer writes the trace file.
type Tracer struct {
	listener  string
	max       int64
	requests  bool
	responses bool

	mu      sync.Mutex
	f       *os.File
	written int64
	full    bool

	Lines, Dropped atomic.Uint64
}

// NewTracer opens the trace file, appending to it.
func NewTracer(listener, path string, max int64, requests, responses *bool) (*Tracer, error) {
	if max <= 0 {
		max = 100 << 20
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // the path is the operator's own configuration
	if err != nil {
		return nil, fmt.Errorf("ntp trace: %w", err)
	}
	t := &Tracer{listener: listener, max: max, f: f,
		requests: requests == nil || *requests, responses: responses == nil || *responses}
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
	err := t.f.Close()
	t.f = nil
	return err
}

// Full says the bound was reached.
func (t *Tracer) Full() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.full
}

// Request traces a packet from a client.
func (t *Tracer) Request(listener string, client netip.AddrPort, pkt *wire.Packet, d Decision) {
	if t == nil || !t.requests {
		return
	}
	e := entry(pkt, d)
	e.Client = client.Addr().String()
	t.write(e, "request")
}

// Response traces a packet from a server.
func (t *Tracer) Response(listener string, client, server netip.AddrPort, pkt *wire.Packet, d Decision) {
	if t == nil || !t.responses {
		return
	}
	e := entry(pkt, d)
	e.Client = client.Addr().String()
	e.Server = server.String()
	t.write(e, "response")
}

func entry(pkt *wire.Packet, d Decision) TraceEntry {
	e := TraceEntry{
		Version: pkt.Version, Mode: pkt.Mode.String(), Leap: pkt.Leap.String(),
		Stratum: pkt.Stratum, RefID: pkt.RefID(), Poll: pkt.Poll, Precision: pkt.Precision,
		RootDelayMS:      float64(pkt.RootDelay.Duration().Microseconds()) / 1000,
		RootDispersionMS: float64(pkt.RootDispersion.Duration().Microseconds()) / 1000,
		KeyID:            pkt.KeyID, CryptoNAK: pkt.CryptoNAK,
		Decision: decisionName(d), Reason: d.Reason, Bytes: len(pkt.Raw),
	}
	for _, x := range pkt.Extensions {
		e.Extensions = append(e.Extensions, wire.ExtensionName(x.Type))
	}
	e.NTSFields = pkt.NTS().Present
	return e
}

func (t *Tracer) write(e TraceEntry, dir string) {
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	e.Listener = t.listener
	e.Direction = dir
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
		t.full = true
		t.Dropped.Add(1)
		mark := fmt.Sprintf("{\"time\":%q,\"listener\":%q,\"direction\":\"trace_full\","+
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
